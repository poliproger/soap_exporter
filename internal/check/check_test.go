package check

import (
	"cmp"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/soap"
)

// loadTarget loads one target of the given SOAP version through config.LoadBytes. expect is
// the YAML of its expect block without indentation; "" keeps the defaults.
func loadTarget(t testing.TB, version, expect string) *config.Target {
	t.Helper()
	ns := soap.NS11
	if version == "1.2" {
		ns = soap.NS12
	}
	var b strings.Builder
	fmt.Fprintf(&b, `targets:
  - name: orders
    url: http://soap.example.com/Orders.asmx
    soap: {version: %q, action: "http://corp.example/GetOrders"}
    body: '<s:Envelope xmlns:s="%s"><s:Body><GetOrders xmlns="http://corp.example/"/></s:Body></s:Envelope>'
`, version, ns)
	if expect != "" {
		b.WriteString("    expect:\n")
		for line := range strings.Lines(expect) {
			b.WriteString("      " + line)
		}
		b.WriteString("\n")
	}
	c, err := config.LoadBytes([]byte(b.String()), t.TempDir())
	if err != nil {
		t.Fatalf("load config: %v\n%s", err, b.String())
	}
	return c.Targets[0]
}

// fixture returns the contents of a file in testdata.
func fixture(t testing.TB, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// summary formats outcomes as name:pass / name:FAIL, one per element.
func summary(outcomes []result.CheckOutcome) []string {
	s := make([]string, len(outcomes))
	for i, o := range outcomes {
		state := "pass"
		if !o.Passed {
			state = "FAIL"
		}
		s[i] = o.Name + ":" + state
	}
	return s
}

// evaluate runs Evaluate and checks the invariants every result must satisfy.
func evaluate(t testing.TB, tgt *config.Target, r *Response) ([]result.CheckOutcome, result.Reason, string) {
	t.Helper()
	outcomes, reason, message := Evaluate(tgt, r)
	if err := checkInvariants(tgt, outcomes, reason, message); err != nil {
		t.Fatalf("%v\noutcomes: %+v", err, outcomes)
	}
	return outcomes, reason, message
}

// checkInvariants verifies the shape of an Evaluate result: one outcome per configured
// check in plan order, and reason and message taken from the first failing outcome.
func checkInvariants(tgt *config.Target, outcomes []result.CheckOutcome, reason result.Reason, message string) error {
	e := tgt.Expect
	want := 3 + len(e.Regex) + len(e.NotRegex) + len(e.XPath) + len(e.NotXPath)
	for _, h := range e.Headers {
		if h.Regex != nil {
			want++
		}
		if h.NotRegex != nil {
			want++
		}
	}
	if len(outcomes) != want {
		return fmt.Errorf("got %d outcomes, want %d", len(outcomes), want)
	}
	if got := []string{outcomes[0].Name, outcomes[1].Name, outcomes[2].Name}; !slices.Equal(got, []string{"soap_fault", "status", "envelope"}) {
		return fmt.Errorf("first outcomes are %q", got)
	}
	i := slices.IndexFunc(outcomes, func(o result.CheckOutcome) bool { return !o.Passed })
	switch {
	case i < 0 && (reason != result.ReasonNone || message != ""):
		return fmt.Errorf("all checks passed, but reason = %q, message = %q", reason, message)
	case i >= 0 && (reason != outcomes[i].Reason || message != outcomes[i].Message):
		return fmt.Errorf("reason, message = %q, %q, want %q, %q from the first failure",
			reason, message, outcomes[i].Reason, outcomes[i].Message)
	case i >= 0 && (reason == result.ReasonNone || message == ""):
		return fmt.Errorf("check %s failed without a reason or a message", outcomes[i].Name)
	}
	return nil
}

func TestEvaluateOrder(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expect      string
		status      int
		body        string
		wantReason  result.Reason
		wantMessage string
		wantChecks  []string // soap_fault, status, envelope
	}{
		{
			name:        "500 with a fault",
			status:      500,
			body:        fixture(t, "fault11.xml"),
			wantReason:  result.ReasonSOAPFault,
			wantMessage: "SOAP fault soap:Server: ORA-01017",
			wantChecks:  []string{"soap_fault:FAIL", "status:FAIL", "envelope:pass"},
		},
		{
			name:        "200 with a fault",
			status:      200,
			body:        fixture(t, "fault11.xml"),
			wantReason:  result.ReasonSOAPFault,
			wantMessage: "SOAP fault soap:Server: ORA-01017",
			wantChecks:  []string{"soap_fault:FAIL", "status:pass", "envelope:pass"},
		},
		{
			name:        "SOAP 1.2 fault with subcodes",
			version:     "1.2",
			status:      400,
			body:        fixture(t, "fault12.xml"),
			wantReason:  result.ReasonSOAPFault,
			wantMessage: "SOAP fault env:Sender / m:MessageTimeout / m:Retry: Sender Timeout",
			wantChecks:  []string{"soap_fault:FAIL", "status:FAIL", "envelope:pass"},
		},
		{
			name:        "fault of the other SOAP version",
			status:      400,
			body:        fixture(t, "fault12.xml"),
			wantReason:  result.ReasonSOAPFault,
			wantMessage: "SOAP fault env:Sender / m:MessageTimeout / m:Retry: Sender Timeout",
			wantChecks:  []string{"soap_fault:FAIL", "status:FAIL", "envelope:FAIL"},
		},
		{
			name:       "allowed fault",
			expect:     "status: [200, 500]\nallow_soap_fault: true",
			status:     500,
			body:       fixture(t, "fault11.xml"),
			wantChecks: []string{"soap_fault:pass", "status:pass", "envelope:pass"},
		},
		{
			name:        "allowed fault with an unexpected status",
			expect:      "allow_soap_fault: true",
			status:      500,
			body:        fixture(t, "fault11.xml"),
			wantReason:  result.ReasonStatus,
			wantMessage: "got 500, want [200]",
			wantChecks:  []string{"soap_fault:pass", "status:FAIL", "envelope:pass"},
		},
		{
			name:        "502 with HTML",
			status:      502,
			body:        fixture(t, "bad-gateway.html"),
			wantReason:  result.ReasonStatus,
			wantMessage: "got 502, want [200]",
			wantChecks:  []string{"soap_fault:pass", "status:FAIL", "envelope:FAIL"},
		},
		{
			name:        "200 with HTML",
			status:      200,
			body:        fixture(t, "bad-gateway.html"),
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "XML syntax error on line 6: element <hr> closed by </body>",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:        "200 with a DOCTYPE",
			status:      200,
			body:        fixture(t, "error-page.html"),
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "DOCTYPE is not allowed",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		// Names and namespaces from the response are kept on one line.
		{
			name:        "envelope namespace with control characters",
			status:      200,
			body:        `<x:Envelope xmlns:x="urn:a&#10;b&#x85;c&#x86;d"><x:Body/></x:Envelope>`,
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: `root element {urn:a b c\u0086d}Envelope is not in a SOAP envelope namespace`,
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:        "200 with well-formed XML that is not an envelope",
			status:      200,
			body:        `<html><body>OK</body></html>`,
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "root element is html, want a SOAP Envelope",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:        "401",
			status:      401,
			wantReason:  result.ReasonAuth,
			wantMessage: "got 401, want [200]",
			wantChecks:  []string{"soap_fault:pass", "status:FAIL", "envelope:FAIL"},
		},
		{
			name:        "401 with HTML",
			status:      401,
			body:        fixture(t, "error-page.html"),
			wantReason:  result.ReasonAuth,
			wantMessage: "got 401, want [200]",
			wantChecks:  []string{"soap_fault:pass", "status:FAIL", "envelope:FAIL"},
		},
		{
			name:        "407",
			status:      407,
			wantReason:  result.ReasonAuth,
			wantMessage: "got 407, want [200]",
			wantChecks:  []string{"soap_fault:pass", "status:FAIL", "envelope:FAIL"},
		},
		{
			name:        "403",
			status:      403,
			wantReason:  result.ReasonStatus,
			wantMessage: "got 403, want [200]",
			wantChecks:  []string{"soap_fault:pass", "status:FAIL", "envelope:FAIL"},
		},
		{
			name:       "202 with an empty body",
			expect:     "status: [200, 202]",
			status:     202,
			wantChecks: []string{"soap_fault:pass", "status:pass", "envelope:pass"},
		},
		{
			name:       "202 with a whitespace body",
			expect:     "status: [202]",
			status:     202,
			body:       "\r\n \t",
			wantChecks: []string{"soap_fault:pass", "status:pass", "envelope:pass"},
		},
		{
			name:        "202 not expected",
			status:      202,
			wantReason:  result.ReasonStatus,
			wantMessage: "got 202, want [200]",
			wantChecks:  []string{"soap_fault:pass", "status:FAIL", "envelope:pass"},
		},
		{
			name:        "202 with HTML",
			expect:      "status: [202]",
			status:      202,
			body:        fixture(t, "error-page.html"),
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "DOCTYPE is not allowed",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:        "200 with an empty body",
			status:      200,
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "empty body (allowed only with status 202)",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:        "SOAP 1.2 envelope for a SOAP 1.1 target",
			status:      200,
			body:        fixture(t, "orders12.xml"),
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "got a SOAP 1.2 envelope, want SOAP 1.1",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:        "SOAP 1.1 envelope for a SOAP 1.2 target",
			version:     "1.2",
			status:      200,
			body:        fixture(t, "orders11.xml"),
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "got a SOAP 1.1 envelope, want SOAP 1.2",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:        "envelope without a Body",
			status:      200,
			body:        `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header/></soap:Envelope>`,
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "SOAP 1.1 Envelope has no Body element in namespace http://schemas.xmlsoap.org/soap/envelope/",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:        "truncated XML",
			status:      200,
			body:        `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>`,
			wantReason:  result.ReasonInvalidEnvelope,
			wantMessage: "XML syntax error on line 1: unexpected EOF: element <soap:Body> is not closed",
			wantChecks:  []string{"soap_fault:pass", "status:pass", "envelope:FAIL"},
		},
		{
			name:       "SOAP 1.1 response",
			status:     200,
			body:       fixture(t, "orders11.xml"),
			wantChecks: []string{"soap_fault:pass", "status:pass", "envelope:pass"},
		},
		{
			name:       "SOAP 1.2 response",
			version:    "1.2",
			status:     200,
			body:       fixture(t, "orders12.xml"),
			wantChecks: []string{"soap_fault:pass", "status:pass", "envelope:pass"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt := loadTarget(t, cmp.Or(tt.version, "1.1"), tt.expect)
			outcomes, reason, message := evaluate(t, tgt, &Response{Status: tt.status, Text: tt.body})
			if reason != tt.wantReason || message != tt.wantMessage {
				t.Errorf("reason, message = %q, %q, want %q, %q", reason, message, tt.wantReason, tt.wantMessage)
			}
			if got := summary(outcomes); !slices.Equal(got, tt.wantChecks) {
				t.Errorf("checks = %q, want %q", got, tt.wantChecks)
			}
		})
	}
}

func TestEvaluateMessages(t *testing.T) {
	stackTrace := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault>
<faultcode>soap:Server</faultcode>
<faultstring>Server was unable to process request. ---&gt; Timeout expired.
   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception)
   at System.Data.SqlClient.TdsParser.Run(RunBehavior runBehavior)` + strings.Repeat("\n   at Frame.Method()", 20) + `
</faultstring></soap:Fault></soap:Body></soap:Envelope>`
	tests := []struct {
		name   string
		expect string
		status int
		body   string
		want   []result.CheckOutcome // the first three outcomes
	}{
		{
			name:   "passing",
			status: 200,
			body:   fixture(t, "orders11.xml"),
			want: []result.CheckOutcome{
				{Name: "soap_fault", Reason: result.ReasonSOAPFault, Passed: true},
				{Name: "status", Reason: result.ReasonStatus, Passed: true, Message: "got 200"},
				{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true, Message: "SOAP 1.1 envelope"},
			},
		},
		{
			name:   "allowed fault keeps the fault text",
			expect: "status: [500]\nallow_soap_fault: true",
			status: 500,
			body:   fixture(t, "fault11.xml"),
			want: []result.CheckOutcome{
				{Name: "soap_fault", Reason: result.ReasonSOAPFault, Passed: true, Message: "SOAP fault soap:Server: ORA-01017 (allowed)"},
				{Name: "status", Reason: result.ReasonStatus, Passed: true, Message: "got 500"},
				{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true, Message: "SOAP 1.1 envelope"},
			},
		},
		{
			name:   "expected 401 passes but still reports auth",
			expect: "status: [401]",
			status: 401,
			body:   fixture(t, "orders11.xml"),
			want: []result.CheckOutcome{
				{Name: "soap_fault", Reason: result.ReasonSOAPFault, Passed: true},
				{Name: "status", Reason: result.ReasonAuth, Passed: true, Message: "got 401"},
				{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true, Message: "SOAP 1.1 envelope"},
			},
		},
		{
			name:   "empty body with 202",
			expect: "status: [202]",
			status: 202,
			want: []result.CheckOutcome{
				{Name: "soap_fault", Reason: result.ReasonSOAPFault, Passed: true},
				{Name: "status", Reason: result.ReasonStatus, Passed: true, Message: "got 202"},
				{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true, Message: "empty body with status 202"},
			},
		},
		{
			name:   "fault without code and reason",
			status: 500,
			body:   `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault/></soap:Body></soap:Envelope>`,
			want: []result.CheckOutcome{
				{Name: "soap_fault", Reason: result.ReasonSOAPFault, Message: "SOAP fault without code and reason"},
				{Name: "status", Reason: result.ReasonStatus, Message: "got 500, want [200]"},
				{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true, Message: "SOAP 1.1 envelope"},
			},
		},
		{
			name:   "fault without reason",
			status: 500,
			body:   `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Client</faultcode></soap:Fault></soap:Body></soap:Envelope>`,
			want: []result.CheckOutcome{
				{Name: "soap_fault", Reason: result.ReasonSOAPFault, Message: "SOAP fault soap:Client"},
				{Name: "status", Reason: result.ReasonStatus, Message: "got 500, want [200]"},
				{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true, Message: "SOAP 1.1 envelope"},
			},
		},
		{
			name:   "fault with a stack trace is shortened to one line",
			status: 500,
			body:   stackTrace,
			want: []result.CheckOutcome{
				{Name: "soap_fault", Reason: result.ReasonSOAPFault, Message: "SOAP fault soap:Server: " +
					"Server was unable to process request. ---> Timeout expired. " +
					"at System.Data.SqlClient.SqlConnection.OnError(SqlException exception) " +
					"at System.Data.SqlClient.TdsParser.Run(RunBehavior runBehavior) at Fr…"},
				{Name: "status", Reason: result.ReasonStatus, Message: "got 500, want [200]"},
				{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true, Message: "SOAP 1.1 envelope"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt := loadTarget(t, "1.1", tt.expect)
			outcomes, _, _ := evaluate(t, tgt, &Response{Status: tt.status, Text: tt.body})
			if !slices.Equal(outcomes[:3], tt.want) {
				t.Errorf("outcomes:\n got %+v\nwant %+v", outcomes[:3], tt.want)
			}
		})
	}
}

func TestEvaluateHeaders(t *testing.T) {
	const expect = `headers:
  - name: Content-Type
    regex: '^text/xml\b'
  - name: x-request-id
    regex: '^[0-9a-f-]{36}$'
  - name: Server
    not_regex: 'IIS/[1-8]\.'
  - name: X-Powered-By
    not_regex: 'PHP'`
	tests := []struct {
		name        string
		header      http.Header
		wantReason  result.Reason
		wantMessage string
		wantChecks  []string
	}{
		{
			name: "all pass",
			header: http.Header{
				"Content-Type": {"text/xml; charset=utf-8"},
				"X-Request-Id": {"3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
				"Server":       {"Microsoft-IIS/10.0"},
			},
		},
		{
			name: "one of several values matches",
			header: http.Header{
				"Content-Type": {"text/xml; charset=utf-8"},
				"X-Request-Id": {"none", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
			},
		},
		{
			name: "regex does not match",
			header: http.Header{
				"Content-Type": {"text/html; charset=utf-8"},
				"X-Request-Id": {"3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
			},
			wantReason:  result.ReasonHeader,
			wantMessage: `header "Content-Type" does not match "^text/xml\b": got "text/html; charset=utf-8"`,
			wantChecks:  []string{`header "Content-Type" regex:FAIL`},
		},
		{
			name: "regex matches none of several values",
			header: http.Header{
				"Content-Type": {"text/xml"},
				"X-Request-Id": {"a", "b", "c", "d", "e"},
			},
			wantReason:  result.ReasonHeader,
			wantMessage: `header "x-request-id" does not match "^[0-9a-f-]{36}$": got "a", "b", "c" and 2 more`,
			wantChecks:  []string{`header "x-request-id" regex:FAIL`},
		},
		{
			name: "missing header fails regex",
			header: http.Header{
				"X-Request-Id": {"3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
			},
			wantReason:  result.ReasonHeader,
			wantMessage: `header "Content-Type" is missing`,
			wantChecks:  []string{`header "Content-Type" regex:FAIL`},
		},
		{
			name: "not_regex matches",
			header: http.Header{
				"Content-Type": {"text/xml"},
				"X-Request-Id": {"3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
				"Server":       {"Microsoft-IIS/8.5"},
				"X-Powered-By": {"ASP.NET", "PHP/8.3"},
			},
			wantReason:  result.ReasonHeader,
			wantMessage: `header "Server" matches not_regex "IIS/[1-8]\.": got "Microsoft-IIS/8.5"`,
			wantChecks:  []string{`header "Server" not_regex:FAIL`, `header "X-Powered-By" not_regex:FAIL`},
		},
		{
			name:        "nil header",
			wantReason:  result.ReasonHeader,
			wantMessage: `header "Content-Type" is missing`,
			wantChecks:  []string{`header "Content-Type" regex:FAIL`, `header "x-request-id" regex:FAIL`},
		},
	}
	tgt := loadTarget(t, "1.1", expect)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcomes, reason, message := evaluate(t, tgt, &Response{Status: 200, Header: tt.header, Text: fixture(t, "orders11.xml")})
			if reason != tt.wantReason || message != tt.wantMessage {
				t.Errorf("reason, message = %q, %q, want %q, %q", reason, message, tt.wantReason, tt.wantMessage)
			}
			var failed []string
			for _, s := range summary(outcomes) {
				if strings.HasSuffix(s, ":FAIL") {
					failed = append(failed, s)
				}
			}
			if !slices.Equal(failed, tt.wantChecks) {
				t.Errorf("failed checks = %q, want %q", failed, tt.wantChecks)
			}
		})
	}
}

// Messages of header checks end up in logs, so they never quote credentials, cookies or
// authentication tokens; authentication schemes stay visible.
func TestEvaluateSecretHeaders(t *testing.T) {
	const (
		cookie = "ASP.NET_SessionId=s3cret-cookie-value; path=/; HttpOnly"
		token  = "oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
	)
	tests := []struct {
		name        string
		expect      string
		header      http.Header
		wantMessage string
	}{
		{
			name:        "Set-Cookie matches not_regex",
			expect:      "headers: [{name: Set-Cookie, not_regex: SessionId}]",
			header:      http.Header{"Set-Cookie": {cookie}},
			wantMessage: `header "Set-Cookie" matches not_regex "SessionId": got "<redacted>"`,
		},
		{
			name:        "WWW-Authenticate does not match",
			expect:      "headers: [{name: WWW-Authenticate, regex: '^NTLM'}]",
			header:      http.Header{"Www-Authenticate": {"Negotiate " + token, "Basic realm=\"corp.example\""}},
			wantMessage: `header "WWW-Authenticate" does not match "^NTLM": got "Negotiate <redacted>", "Basic realm=\"corp.example\""`,
		},
		{
			// Redacting before clipping: a clipped token would escape the token pattern.
			name:        "long WWW-Authenticate",
			expect:      "headers: [{name: proxy-authenticate, not_regex: Negotiate}]",
			header:      http.Header{"Proxy-Authenticate": {"Negotiate " + strings.Repeat(token, 20)}},
			wantMessage: `header "proxy-authenticate" matches not_regex "Negotiate": got "Negotiate <redacted>"`,
		},
		{
			name:        "Cookie values",
			expect:      "headers: [{name: Cookie, regex: '^lang='}]",
			header:      http.Header{"Cookie": {"a=s3cret", "b=s3cret"}},
			wantMessage: `header "Cookie" does not match "^lang=": got "<redacted>", "<redacted>"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt := loadTarget(t, "1.1", tt.expect)
			outcomes, reason, message := evaluate(t, tgt, &Response{Status: 200, Header: tt.header, Text: fixture(t, "orders11.xml")})
			if reason != result.ReasonHeader || message != tt.wantMessage {
				t.Errorf("reason, message = %q, %q, want header, %q", reason, message, tt.wantMessage)
			}
			for _, o := range outcomes {
				for _, secret := range []string{"s3cret", token[:8]} {
					if strings.Contains(o.Message, secret) {
						t.Errorf("check %s quotes a secret: %q", o.Name, o.Message)
					}
				}
			}
		})
	}
}

func TestEvaluateRegex(t *testing.T) {
	tests := []struct {
		name        string
		expect      string
		body        string
		wantReason  result.Reason
		wantMessage string
	}{
		{
			name:   "regex matches",
			expect: `regex: ['<Id>\d+</Id>', '(?s)<Order>.*Open']`,
			body:   fixture(t, "orders11.xml"),
		},
		{
			name:        "regex does not match",
			expect:      `regex: ['<Id>\d+</Id>', '(?s)<Order>.*Closed']`,
			body:        fixture(t, "orders11.xml"),
			wantReason:  result.ReasonRegex,
			wantMessage: `regex "(?s)<Order>.*Closed" does not match the body`,
		},
		{
			name:   "not_regex does not match",
			expect: `not_regex: ['ORA-\d{5}']`,
			body:   fixture(t, "orders11.xml"),
		},
		{
			name:        "not_regex matches",
			expect:      `not_regex: ['ORA-\d{5}']`,
			body:        fixture(t, "no-orders11.xml"),
			wantReason:  result.ReasonRegex,
			wantMessage: `not_regex "ORA-\d{5}" matches "ORA-12541"`,
		},
		{
			name:        "regex before not_regex",
			expect:      "regex: ['<Order>']\nnot_regex: ['ORA-']",
			body:        fixture(t, "no-orders11.xml"),
			wantReason:  result.ReasonRegex,
			wantMessage: `regex "<Order>" does not match the body`,
		},
		{
			name:        "long match is clipped",
			expect:      `not_regex: ['(?s)<Error>.*</Error>']`,
			body:        strings.Replace(fixture(t, "no-orders11.xml"), "TNS:no listener", strings.Repeat("x", 300), 1),
			wantReason:  result.ReasonRegex,
			wantMessage: `not_regex "(?s)<Error>.*</Error>" matches "<Error>ORA-12541: ` + strings.Repeat("x", 182) + `…"`,
		},
		{
			name:        "control characters in the expression are escaped",
			expect:      `regex: ["Shipped\n\t</Status>"]`,
			body:        fixture(t, "orders11.xml"),
			wantReason:  result.ReasonRegex,
			wantMessage: `regex "Shipped\n\t</Status>" does not match the body`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt := loadTarget(t, "1.1", tt.expect)
			_, reason, message := evaluate(t, tgt, &Response{Status: 200, Text: tt.body})
			if reason != tt.wantReason || message != tt.wantMessage {
				t.Errorf("reason, message = %q, %q, want %q, %q", reason, message, tt.wantReason, tt.wantMessage)
			}
		})
	}
}

// Regexes and XPath run on the text decoded by soap.DecodeBody, not on the raw bytes.
func TestEvaluateDecodedText(t *testing.T) {
	raw := fixture(t, "branch11-windows-1251.xml")
	if strings.Contains(raw, "Главный") {
		t.Fatal("the fixture is not in windows-1251")
	}
	text, charset, err := soap.DecodeBody([]byte(raw), "text/xml")
	if err != nil {
		t.Fatal(err)
	}
	if charset != "windows-1251" {
		t.Fatalf("charset = %q, want windows-1251", charset)
	}
	tgt := loadTarget(t, "1.1", `namespaces: {c: "http://corp.example/"}
regex: ['Главный\s+филиал']
xpath: ["//c:Name = 'Главный филиал'"]`)
	outcomes, reason, message := evaluate(t, tgt, &Response{Status: 200, Text: text})
	if reason != result.ReasonNone {
		t.Errorf("reason, message = %q, %q; outcomes %+v", reason, message, outcomes)
	}
}

// Every check runs and is kept even after an earlier one failed; the first failure wins.
func TestEvaluateKeepsAllOutcomes(t *testing.T) {
	tgt := loadTarget(t, "1.1", `status: [200]
namespaces: {o: "http://corp.example/"}
headers:
  - {name: Content-Type, regex: '^text/xml', not_regex: 'html'}
regex: ['<Order>']
not_regex: ['ORA-\d{5}']
xpath: ['count(//o:Order) > 0']
not_xpath: ['//o:Error']`)
	outcomes, reason, message := evaluate(t, tgt, &Response{
		Status: 500,
		Header: http.Header{"Content-Type": {"text/html"}},
		Text:   fixture(t, "no-orders11.xml"),
	})
	want := []string{
		"soap_fault:pass",
		"status:FAIL",
		"envelope:pass",
		`header "Content-Type" regex:FAIL`,
		`header "Content-Type" not_regex:FAIL`,
		`regex "<Order>":FAIL`,
		`not_regex "ORA-\d{5}":FAIL`,
		`xpath "count(//o:Order) > 0":FAIL`,
		`not_xpath "//o:Error":FAIL`,
	}
	if got := summary(outcomes); !slices.Equal(got, want) {
		t.Errorf("checks:\n got %q\nwant %q", got, want)
	}
	if reason != result.ReasonStatus || message != "got 500, want [200]" {
		t.Errorf("reason, message = %q, %q", reason, message)
	}
	wantReasons := []result.Reason{
		result.ReasonSOAPFault, result.ReasonStatus, result.ReasonInvalidEnvelope,
		result.ReasonHeader, result.ReasonHeader, result.ReasonRegex, result.ReasonRegex,
		result.ReasonXPath, result.ReasonXPath,
	}
	for i, o := range outcomes {
		if o.Reason != wantReasons[i] {
			t.Errorf("%s: reason %q, want %q", o.Name, o.Reason, wantReasons[i])
		}
		if !o.Passed && o.Message == "" {
			t.Errorf("%s failed without a message", o.Name)
		}
	}
}

func TestQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{``, `""`},
		{`ORA-\d{5}`, `"ORA-\d{5}"`},
		{`//a[@b = "c"]`, `"//a[@b = "c"]"`},
		{"a\nb\tc\x00", `"a\nb\tc\x00"`},
		{"\u0085", `"\u0085"`},
		{"Главный", `"Главный"`},
		{"bad\xffutf8", `"bad\xffutf8"`},
	}
	for _, tt := range tests {
		if got := quote(tt.in); got != tt.want {
			t.Errorf("quote(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestOneLine(t *testing.T) {
	long := strings.Repeat("a", maxValueLen)
	tests := []struct{ in, want string }{
		{"", ""},
		{"  a\r\n\tb  c ", "a b c"},
		// NEL and LINE SEPARATOR are white space; other control characters are escaped.
		{"a\u0085b\u2028c", "a b c"},
		{"a\u0086b\x00c\x1bd", `a\u0086b\x00c\x1bd`},
		{"bad\xffutf8", `bad\xffutf8`},
		// Clipped before escaping, so an escape sequence is never cut.
		{"\u0086" + long, `\u0086` + long[:maxValueLen-2] + "…"},
	}
	for _, tt := range tests {
		if got := oneLine(tt.in); got != tt.want {
			t.Errorf("oneLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClip(t *testing.T) {
	ascii := strings.Repeat("a", maxValueLen)
	tests := []struct{ in, want string }{
		{"", ""},
		{ascii, ascii},
		{ascii + "b", ascii + "…"},
		// A two-byte rune across the limit is dropped whole.
		{ascii[1:] + "ж", ascii[1:] + "…"},
		{ascii[2:] + "жж", ascii[2:] + "ж…"},
	}
	for _, tt := range tests {
		if got := clip(tt.in); got != tt.want {
			t.Errorf("clip(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
