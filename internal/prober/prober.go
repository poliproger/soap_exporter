// Package prober performs one SOAP call per Probe and turns it into a result.Result
// (plan §6.1–§6.3): transport, request, httptrace phases, limited body reading, decoding,
// TLS state, error classification, and the checks.
package prober

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"runtime/debug"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/units"
	commoncfg "github.com/prometheus/common/config"

	"github.com/poliproger/soap_exporter/internal/check"
	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/soap"
)

// maxRedirects bounds the redirects followed with follow_redirects, as net/http does.
const maxRedirects = 10

// Options configure a Prober.
type Options struct {
	// UserAgent is the default User-Agent ("soap_exporter/<version>"); a User-Agent in the
	// target's headers overrides it.
	UserAgent string
	Logger    *slog.Logger
}

// Prober probes one target. It is safe for concurrent use; the scheduler never overlaps
// probes of one target, but on-demand debug probes may run concurrently.
type Prober struct {
	target        *config.Target
	rt            http.RoundTripper // the target's chain; every probe wraps it in a transport
	checkRedirect func(*http.Request, []*http.Request) error
	slots         chan struct{} // one per running round trip, see transport
	logger        *slog.Logger

	url    string
	header http.Header // request headers, SOAPAction with its exact spelling
	host   string      // a Host header from the target's headers, "" if none
	limit  int64       // max_response_size
	spn    string
	// tokenStage is the stage of a probe that timed out before its request reached the
	// HTTP transport; "" for a target without a token to acquire.
	tokenStage string
}

// hooks replace parts of the transport in tests.
type hooks struct {
	// resolver replaces the system resolver, so that tests need no real DNS.
	resolver *net.Resolver
	// wrap wraps the target's RoundTripper chain, inside the per-probe transport.
	wrap func(http.RoundTripper) http.RoundTripper
}

// New builds the per-target RoundTripper from the target's HTTP client config (keep-alives
// off unless keep_alive, HTTP/2 only with enable_http2, redirects only with
// follow_redirects) and wraps it with the SPNEGO RoundTripper if cred is not nil.
func New(t *config.Target, cred kerberos.Credential, opts Options) (*Prober, error) {
	return newProber(t, cred, opts, hooks{})
}

func newProber(t *config.Target, cred kerberos.Credential, opts Options, h hooks) (*Prober, error) {
	switch {
	case t.ParsedURL == nil:
		return nil, errors.New("target URL is not parsed")
	case t.Timeout <= 0:
		return nil, errors.New("target timeout must be positive")
	case cred != nil && t.Kerberos == nil:
		return nil, errors.New("kerberos credential given for a target without kerberos settings")
	case cred == nil && t.Kerberos != nil:
		return nil, errors.New("target has kerberos settings, but no kerberos credential was given")
	}
	p := &Prober{
		target:        t,
		checkRedirect: checkRedirect(t.HTTPClientConfig.FollowRedirects),
		slots:         make(chan struct{}, maxRoundTrips),
		logger:        opts.Logger,
		url:           t.ParsedURL.String(),
		header:        make(http.Header, len(t.Headers)+3),
		limit:         int64(t.MaxResponseSize),
	}
	if p.logger == nil {
		p.logger = slog.New(slog.DiscardHandler)
	}
	if p.limit <= 0 {
		p.limit = int64(config.DefaultMaxResponseSize)
	}
	for name, value := range t.Headers {
		if strings.EqualFold(name, "Host") {
			p.host = value // net/http ignores a Host entry in the header map
			continue
		}
		p.header.Set(name, value)
	}
	if _, ok := p.header["User-Agent"]; !ok && opts.UserAgent != "" {
		p.header.Set("User-Agent", opts.UserAgent)
	}
	soap.SetRequestHeaders(p.header, t.SOAP.Version, t.SOAP.Action)

	// The transport dials detached from the request context; the dialer timeout bounds a
	// dial abandoned at the probe deadline.
	dialer := &net.Dialer{Timeout: time.Duration(t.Timeout), Resolver: h.resolver}
	rtOpts := []commoncfg.HTTPClientOption{commoncfg.WithDialContextFunc(dialer.DialContext)}
	if !t.KeepAlive {
		rtOpts = append(rtOpts, commoncfg.WithKeepAlivesDisabled())
	}
	if ua := p.header.Get("User-Agent"); ua != "" {
		// The user agent RoundTripper overwrites User-Agent, so it gets the effective one.
		// It also applies to OAuth2 token requests.
		rtOpts = append(rtOpts, commoncfg.WithUserAgent(ua))
	}
	rt, err := commoncfg.NewRoundTripperFromConfig(t.HTTPClientConfig, "soap_exporter", rtOpts...)
	if err != nil {
		return nil, err
	}
	switch {
	case cred != nil:
		p.spn = t.Kerberos.SPN
		p.tokenStage = kerberosTokenStage
		rt = kerberos.NewRoundTripper(cred, p.spn, rt)
	case t.HTTPClientConfig.OAuth2 != nil:
		p.tokenStage = oauth2TokenStage
	}
	if h.wrap != nil {
		rt = h.wrap(rt)
	}
	p.rt = rt
	return p, nil
}

func checkRedirect(follow bool) func(*http.Request, []*http.Request) error {
	if !follow {
		return func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return func(_ *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return nil
	}
}

// Target returns the probed target.
func (p *Prober) Target() *config.Target {
	return p.target
}

// Probe performs one probe within the target's timeout (a single deadline covering token
// acquisition, DNS, connect, TLS, request and body). It never panics: a recovered panic
// yields reason "internal". ctx cancellation (shutdown) aborts the probe.
//
// End is the time the exchange ended (the body was read or the request failed); the
// response checks that follow do not count towards the probe duration.
func (p *Prober) Probe(ctx context.Context) (r result.Result) {
	tr := newTracer(time.Now)
	r = result.Result{Target: p.target.Name, Start: time.Now(), SPN: p.spn}
	defer func() {
		if v := recover(); v != nil {
			stack := debug.Stack()
			if rp, ok := v.(*roundTripPanic); ok {
				v, stack = rp.value, rp.stack
			}
			p.logger.Error("Probe panicked", "target", p.target.Name, "panic", v, "stack", string(stack))
			r.Success = false
			r.Reason = result.ReasonInternal
			r.Message = oneLine(fmt.Sprintf("panic: %v", v))
		}
		if r.End.IsZero() {
			r.End = time.Now()
		}
		r.Phases = tr.phases()
	}()
	p.probe(ctx, tr, &r)
	return r
}

func (p *Prober) probe(parent context.Context, tr *tracer, r *result.Result) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.target.Timeout))
	defer cancel()
	req, err := p.newRequest(httptrace.WithClientTrace(ctx, tr.clientTrace()))
	if err != nil {
		r.End = time.Now()
		r.Reason, r.Message = result.ReasonInternal, oneLine("build request: "+err.Error())
		return
	}
	client := &http.Client{Transport: &transport{p: p, tr: tr}, CheckRedirect: p.checkRedirect}
	resp, err := client.Do(req)
	if err != nil {
		r.End = time.Now()
		if resp != nil {
			// A failed redirect check returns the last response with its body closed.
			p.setResponse(r, resp)
		}
		r.Reason, r.Message = p.classify(err, ctx.Err(), tr.state())
		return
	}
	defer resp.Body.Close()
	p.setResponse(r, resp)

	body, tooLarge, err := readBody(resp.Body, p.limit)
	tr.bodyDone()
	r.End = time.Now()
	r.BodySize = int64(len(body))
	contentType := resp.Header.Get("Content-Type")
	switch {
	case tooLarge:
		r.Reason = result.ReasonBodyTooLarge
		r.Message = "response body exceeds max_response_size of " + units.Base2Bytes(p.limit).String()
		// Best effort: show the start of the body.
		text, charset, err := soap.DecodeBody(body, contentType)
		if err != nil {
			text, charset = rawText(body), ""
		}
		r.Charset = charset
		r.Body, _ = snippet(text)
		r.BodyTruncated = true
		return
	case err != nil:
		st := tr.state()
		st.stage = "while reading the response body"
		r.Reason, r.Message = p.classify(err, ctx.Err(), st)
		if r.Reason == result.ReasonHTTP {
			r.Message = "read response body: " + r.Message
		}
		return
	}

	text, charset, err := soap.DecodeBody(body, contentType)
	if err != nil {
		r.Reason = result.ReasonInvalidEnvelope
		r.Message = oneLine("decode response body: " + err.Error())
		r.Body, r.BodyTruncated = snippet(rawText(body))
		r.Checks = []result.CheckOutcome{{Name: "envelope", Reason: r.Reason, Message: r.Message}}
		return
	}
	r.Charset = charset
	r.Body, r.BodyTruncated = snippet(text)
	r.Checks, r.Reason, r.Message = check.Evaluate(p.target, &check.Response{
		Status: resp.StatusCode,
		Header: resp.Header,
		Text:   text,
	})
	r.Success = r.Reason == result.ReasonNone
}

// newRequest builds the request with a fresh body reader. The header map is cloned, which
// keeps the SOAPAction key as it is.
func (p *Prober) newRequest(ctx context.Context) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(p.target.RequestBody))
	if err != nil {
		return nil, err
	}
	req.Header = p.header.Clone()
	if p.host != "" {
		req.Host = p.host
	}
	return req, nil
}

func (p *Prober) setResponse(r *result.Result, resp *http.Response) {
	r.GotResponse = true
	r.HTTPStatus = resp.StatusCode
	r.ResponseHeader = resp.Header.Clone()
	r.TLS = tlsInfo(resp.TLS)
}

// readBody reads at most limit bytes of the body; tooLarge reports that there are more.
func readBody(body io.Reader, limit int64) (b []byte, tooLarge bool, err error) {
	n := limit
	if n < math.MaxInt64 {
		n++
	}
	b, err = io.ReadAll(io.LimitReader(body, n))
	if int64(len(b)) > limit {
		return b[:limit], true, nil
	}
	return b, false, err
}

// rawText returns a body that could not be decoded, with invalid UTF-8 replaced by U+FFFD.
func rawText(body []byte) string {
	return strings.ToValidUTF8(string(body), "\uFFFD")
}

// snippet clips text to result.BodySnippetLimit bytes on a rune boundary. A clipped
// snippet is a copy, so that a stored result does not keep the whole body alive.
func snippet(text string) (string, bool) {
	if len(text) <= result.BodySnippetLimit {
		return text, false
	}
	cut := result.BodySnippetLimit
	for i := cut; i > cut-utf8.UTFMax && i > 0; i-- {
		if utf8.RuneStart(text[i]) {
			cut = i
			break
		}
	}
	return strings.Clone(text[:cut]), true
}

// tlsInfo describes the negotiated TLS state and the certificates the server sent.
func tlsInfo(cs *tls.ConnectionState) *result.TLSInfo {
	if cs == nil {
		return nil
	}
	info := &result.TLSInfo{
		Version:     tls.VersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
		ServerName:  cs.ServerName,
		Chain:       make([]result.CertInfo, 0, len(cs.PeerCertificates)),
	}
	for _, c := range cs.PeerCertificates {
		info.Chain = append(info.Chain, result.CertInfo{
			Subject:   c.Subject.String(),
			Issuer:    c.Issuer.String(),
			NotBefore: c.NotBefore,
			NotAfter:  c.NotAfter,
			DNSNames:  slices.Clone(c.DNSNames),
		})
	}
	return info
}

// Close releases idle connections.
func (p *Prober) Close() {
	if c, ok := p.rt.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
