// Package check evaluates a received HTTP response against a target's expectations
// (plan §6.4, steps 2–7).
package check

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/antchfx/xmlquery"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/redact"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/soap"
)

// Response is a received response with its body already decoded to UTF-8.
type Response struct {
	Status int
	Header http.Header
	// Text is the decoded body (soap.DecodeBody).
	Text string
}

// Evaluate runs the checks in the order of plan §6.4 and returns every outcome. reason and
// message come from the first failing check (ReasonNone and "" if all passed):
//
//  2. SOAP Fault, unless expect.allow_soap_fault → soap_fault (code and text in the message)
//  3. status not in expect.status → auth for 401/407, otherwise status
//  4. not an envelope of the target's SOAP version (an empty body passes only with 202)
//     → invalid_envelope
//  5. expect.headers → header; values of headers that can carry credentials, cookies or
//     tokens are quoted with those hidden (redact.HeaderValue), so messages are safe to log
//  6. expect.regex / expect.not_regex → regex
//  7. expect.xpath / expect.not_xpath, converted with XPath boolean() → xpath
//
// The body is parsed once (soap.ParseXML) and shared by steps 2, 4 and 7. Evaluate never
// panics on arbitrary input.
func Evaluate(t *config.Target, r *Response) (outcomes []result.CheckOutcome, reason result.Reason, message string) {
	b := parseBody(r.Text)
	e := &t.Expect
	outcomes = make([]result.CheckOutcome, 0, 3+2*len(e.Headers)+
		len(e.Regex)+len(e.NotRegex)+len(e.XPath)+len(e.NotXPath))
	outcomes = append(outcomes,
		checkFault(e.AllowSOAPFault, b),
		checkStatus(e.Status, r.Status),
		checkEnvelope(t.SOAP.Version, r.Status, b))
	outcomes = checkHeaders(outcomes, e.Headers, r.Header)
	outcomes = checkRegexes(outcomes, e.Regex, e.NotRegex, r.Text)
	outcomes = checkXPaths(outcomes, t, b)
	for _, o := range outcomes {
		if !o.Passed {
			return outcomes, o.Reason, o.Message
		}
	}
	return outcomes, result.ReasonNone, ""
}

// body is the response body parsed once for the fault, envelope and XPath checks.
type body struct {
	empty bool           // the text is empty or whitespace only
	doc   *xmlquery.Node // nil if the body is empty or not well-formed XML
	env   *soap.Envelope // nil if doc is nil or not a SOAP envelope
	err   error          // why a non-empty body has no doc or no env
}

func parseBody(text string) *body {
	if strings.TrimSpace(text) == "" {
		return &body{empty: true}
	}
	doc, err := soap.ParseXML(text)
	if err != nil {
		return &body{err: err}
	}
	env, err := soap.ParseEnvelope(doc)
	return &body{doc: doc, env: env, err: err}
}

func checkFault(allow bool, b *body) result.CheckOutcome {
	o := result.CheckOutcome{Name: "soap_fault", Reason: result.ReasonSOAPFault, Passed: true}
	if b.env == nil || b.env.Fault == nil {
		return o
	}
	o.Message = describeFault(b.env.Fault)
	if allow {
		o.Message += " (allowed)"
	} else {
		o.Passed = false
	}
	return o
}

// describeFault formats a fault as "SOAP fault <code>: <reason>" on one line. The reason
// often carries a whole server stack trace, so it is shortened.
func describeFault(f *soap.Fault) string {
	code, reason := oneLine(f.Code), oneLine(f.Reason)
	switch {
	case code == "" && reason == "":
		return "SOAP fault without code and reason"
	case reason == "":
		return "SOAP fault " + code
	case code == "":
		return "SOAP fault: " + reason
	}
	return "SOAP fault " + code + ": " + reason
}

func checkStatus(want []int, got int) result.CheckOutcome {
	o := result.CheckOutcome{Name: "status", Reason: result.ReasonStatus}
	if got == http.StatusUnauthorized || got == http.StatusProxyAuthRequired {
		o.Reason = result.ReasonAuth
	}
	if slices.Contains(want, got) {
		o.Passed = true
		o.Message = fmt.Sprintf("got %d", got)
	} else {
		o.Message = fmt.Sprintf("got %d, want %v", got, want)
	}
	return o
}

func checkEnvelope(want soap.Version, status int, b *body) result.CheckOutcome {
	o := result.CheckOutcome{Name: "envelope", Reason: result.ReasonInvalidEnvelope}
	switch {
	case b.empty && status == http.StatusAccepted:
		o.Passed = true
		o.Message = "empty body with status 202"
	case b.empty:
		o.Message = "empty body (allowed only with status 202)"
	case b.err != nil:
		// Parser messages may quote names and namespaces from the response.
		o.Message = oneLine(b.err.Error())
	case b.env.Version != want:
		o.Message = fmt.Sprintf("got a SOAP %s envelope, want SOAP %s", b.env.Version, want)
	default:
		o.Passed = true
		o.Message = fmt.Sprintf("SOAP %s envelope", want)
	}
	return o
}

func checkHeaders(outcomes []result.CheckOutcome, checks []config.HeaderCheck, h http.Header) []result.CheckOutcome {
	for _, hc := range checks {
		name := quote(hc.Name)
		values := h.Values(hc.Name)
		if hc.Regex != nil {
			re := quote(hc.Regex.String())
			o := result.CheckOutcome{Name: "header " + name + " regex", Reason: result.ReasonHeader}
			switch {
			case len(values) == 0:
				o.Message = "header " + name + " is missing"
			case slices.ContainsFunc(values, hc.Regex.MatchString):
				o.Passed = true
			default:
				o.Message = fmt.Sprintf("header %s does not match %s: got %s", name, re, quoteValues(hc.Name, values))
			}
			outcomes = append(outcomes, o)
		}
		if hc.NotRegex != nil {
			re := quote(hc.NotRegex.String())
			o := result.CheckOutcome{Name: "header " + name + " not_regex", Reason: result.ReasonHeader}
			if i := slices.IndexFunc(values, hc.NotRegex.MatchString); i >= 0 {
				o.Message = fmt.Sprintf("header %s matches not_regex %s: got %s", name, re, quoteHeaderValue(hc.Name, values[i]))
			} else {
				o.Passed = true
			}
			outcomes = append(outcomes, o)
		}
	}
	return outcomes
}

func checkRegexes(outcomes []result.CheckOutcome, match, notMatch []config.Regexp, text string) []result.CheckOutcome {
	for _, re := range match {
		name := "regex " + quote(re.String())
		o := result.CheckOutcome{Name: name, Reason: result.ReasonRegex, Passed: re.MatchString(text)}
		if !o.Passed {
			o.Message = name + " does not match the body"
		}
		outcomes = append(outcomes, o)
	}
	for _, re := range notMatch {
		name := "not_regex " + quote(re.String())
		o := result.CheckOutcome{Name: name, Reason: result.ReasonRegex}
		if m := re.FindStringIndex(text); m != nil {
			o.Message = name + " matches " + quoteValue(text[m[0]:m[1]])
		} else {
			o.Passed = true
		}
		outcomes = append(outcomes, o)
	}
	return outcomes
}

// maxValueLen bounds the length in bytes of a value from the response quoted in a message.
const maxValueLen = 200

// clip shortens s to at most maxValueLen bytes plus an ellipsis, on a rune boundary.
func clip(s string) string {
	if len(s) <= maxValueLen {
		return s
	}
	cut := maxValueLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// oneLine prepares text from the response for a message: runs of white space become single
// spaces, the result is clipped, and the control characters left are escaped.
func oneLine(s string) string {
	return escape(clip(strings.Join(strings.Fields(s), " ")))
}

// quoteValue quotes a value from the response as a Go string literal, clipped.
func quoteValue(s string) string {
	return strconv.Quote(clip(s))
}

// maxValues bounds the number of header values quoted in a message.
const maxValues = 3

// quoteHeaderValue quotes a value of the response header name like quoteValue, with
// credentials, cookies and tokens redacted first, so that clipping cannot keep part of one.
func quoteHeaderValue(name, value string) string {
	return quoteValue(redact.HeaderValue(name, value))
}

// quoteValues quotes a list of values of the response header name: "a", "b".
func quoteValues(name string, values []string) string {
	q := make([]string, 0, min(len(values), maxValues))
	for _, v := range values[:min(len(values), maxValues)] {
		q = append(q, quoteHeaderValue(name, v))
	}
	s := strings.Join(q, ", ")
	if n := len(values) - maxValues; n > 0 {
		s += fmt.Sprintf(" and %d more", n)
	}
	return s
}

// quote puts s, a configured name or expression, in double quotes. Unlike strconv.Quote it
// keeps backslashes and quotes as written, so regular expressions read as in the config;
// only control characters and invalid UTF-8 are escaped.
func quote(s string) string {
	return `"` + escape(s) + `"`
}

// escape escapes control characters and invalid UTF-8 in s as a Go string literal would
// and keeps everything else as is.
func escape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsControl(r):
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
