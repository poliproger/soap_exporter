package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/poliproger/soap_exporter/internal/app"
	"github.com/poliproger/soap_exporter/internal/check"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/state"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// t0 is 2026-10-02T12:00:00Z.
var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// Target-controlled text that must never be rendered as markup.
const (
	hostileTarget  = `<script>alert("name")</script>&target=orders` // testdata/config.yml
	hostileMessage = `<script>alert("message")</script>`
	hostileBody    = `</pre><script>alert("body")</script>`
	hostileHeader  = `<img src=x onerror=alert("header")>`
	hostileCheck   = `<b onmouseover=alert("check")>`
	hostileSubject = `CN=<i>evil</i>`
	hostileSPN     = `HTTP/<svg onload=alert("spn")>`
)

// Secrets in response headers that must be redacted.
const (
	negotiateToken = "oYG3MIG0oAMKAQChCwYJKoZIgvcSAQICooGf+/BIGc=="
	sessionCookie  = "s3ssion-cookie-value"
)

// historyResults are the recorded results: two for orders (a success, then a fault) and a
// DNS failure for the hostile target.
func historyResults() []result.Result {
	return []result.Result{tlsSuccess("orders"), hostileFault("orders"), dnsFailure(hostileTarget)}
}

// reportResult is what the fake ProbeNow returns.
func reportResult(target string) result.Result {
	r := hostileFault(target)
	r.Start, r.End = t0.Add(time.Hour), t0.Add(time.Hour+1500*time.Millisecond)
	return r
}

func tlsSuccess(target string) result.Result {
	return result.Result{
		Target: target,
		Start:  t0,
		End:    t0.Add(312 * time.Millisecond),
		Phases: map[result.Phase]time.Duration{
			result.PhaseResolve:    2 * time.Millisecond,
			result.PhaseConnect:    10 * time.Millisecond,
			result.PhaseTLS:        40 * time.Millisecond,
			result.PhaseProcessing: 250 * time.Millisecond,
			result.PhaseTransfer:   10 * time.Millisecond,
		},
		Success:        true,
		GotResponse:    true,
		HTTPStatus:     http.StatusOK,
		ResponseHeader: http.Header{"Content-Type": {"application/soap+xml; charset=utf-8"}},
		BodySize:       1234,
		Charset:        "utf-8",
		Body:           `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`,
		TLS: &result.TLSInfo{
			Version:     "TLS 1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
			ServerName:  "orders.example.com",
			Chain: []result.CertInfo{
				{
					Subject: "CN=orders.example.com", Issuer: "CN=Example Issuing CA",
					NotBefore: t0.AddDate(0, -1, 0), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
					DNSNames: []string{"orders.example.com", "orders2.example.com"},
				},
				{
					Subject: "CN=Example Issuing CA", Issuer: "CN=Example Root CA",
					NotBefore: t0.AddDate(-1, 0, 0), NotAfter: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
				},
			},
		},
		Checks: []result.CheckOutcome{
			{Name: "soap_fault", Reason: result.ReasonSOAPFault, Passed: true},
			{Name: "status", Reason: result.ReasonStatus, Passed: true},
			{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true},
		},
	}
}

// hostileFault is a SOAP fault over TLS with Kerberos whose server-controlled parts are
// hostile, and whose headers carry secrets.
func hostileFault(target string) result.Result {
	r := tlsSuccess(target)
	r.Start, r.End = t0.Add(time.Minute), t0.Add(time.Minute+1500*time.Millisecond)
	r.Success, r.Reason, r.Message = false, result.ReasonSOAPFault, hostileMessage
	r.HTTPStatus = http.StatusInternalServerError
	r.ResponseHeader = http.Header{
		"Content-Type":     {"application/soap+xml; charset=utf-8"},
		"Www-Authenticate": {"Negotiate " + negotiateToken},
		"Set-Cookie":       {"ASP.NET_SessionId=" + sessionCookie + "; path=/; HttpOnly"},
		"X-Evil":           {hostileHeader},
	}
	r.BodySize = int64(len(hostileBody))
	r.Body, r.BodyTruncated = hostileBody, true
	r.SPN = hostileSPN
	r.TLS.Chain[0].Subject = hostileSubject
	r.Checks = []result.CheckOutcome{
		{Name: "soap_fault", Reason: result.ReasonSOAPFault, Message: hostileCheck},
		{Name: "status", Reason: result.ReasonStatus, Message: "got 500, want [200]"},
		{Name: "envelope", Reason: result.ReasonInvalidEnvelope, Passed: true},
	}
	return r
}

func dnsFailure(target string) result.Result {
	start := t0.Add(2 * time.Minute)
	return result.Result{
		Target:  target,
		Start:   start,
		End:     start.Add(3 * time.Millisecond),
		Phases:  map[result.Phase]time.Duration{result.PhaseResolve: 3 * time.Millisecond},
		Reason:  result.ReasonDNS,
		Message: "lookup hostile.example.com: no such host",
	}
}

func compareGolden(t *testing.T, got []byte, golden string) {
	t.Helper()
	path := filepath.Join("testdata", golden)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s (run with -update to rewrite it):\n%s", path, got)
	}
}

// HTML helpers based on a real parser: what it sees as elements and text is what a browser
// would see.

func parseHTML(t *testing.T, body string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func findAll(n *html.Node, tag string) []*html.Node {
	var out []*html.Node
	for d := range n.Descendants() {
		if d.Type == html.ElementNode && d.Data == tag {
			out = append(out, d)
		}
	}
	return out
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func text(n *html.Node) string {
	var b strings.Builder
	for d := range n.Descendants() {
		if d.Type == html.TextNode {
			b.WriteString(d.Data)
		}
	}
	return b.String()
}

func texts(nodes []*html.Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = strings.TrimSpace(text(n))
	}
	return out
}

// queryTarget returns the target parameter of a link or form action.
func queryTarget(t *testing.T, ref string) string {
	t.Helper()
	u, err := url.Parse(ref)
	if err != nil {
		t.Fatalf("parsing %q: %v", ref, err)
	}
	if got := u.Query()["target"]; len(got) != 1 {
		t.Errorf("%q has target parameters %q, want one", ref, got)
	}
	return u.Query().Get("target")
}

// checkInert verifies that the hostile strings are rendered as text and never as markup,
// and that secrets in headers are redacted.
func checkInert(t *testing.T, page string, hostile ...string) {
	t.Helper()
	doc := parseHTML(t, page)
	allowed := []string{
		"html", "head", "meta", "title", "style", "body", "header", "main", "a", "p", "h1", "h2", "h3",
		"section", "dl", "dt", "dd", "code", "span", "form", "button", "table", "thead", "tbody",
		"tr", "th", "td", "details", "summary", "pre",
	}
	for d := range doc.Descendants() {
		if d.Type != html.ElementNode {
			continue
		}
		if !slices.Contains(allowed, d.Data) {
			t.Errorf("page contains a <%s> element", d.Data)
		}
		for _, a := range d.Attr {
			if strings.HasPrefix(a.Key, "on") || a.Key == "style" || a.Key == "src" {
				t.Errorf("<%s> has a %s attribute", d.Data, a.Key)
			}
		}
	}
	content := text(doc)
	for _, h := range hostile {
		if !strings.Contains(content, h) {
			t.Errorf("page text lacks %q", h)
		}
	}
	for _, secret := range []string{negotiateToken, sessionCookie} {
		if strings.Contains(page, secret) {
			t.Errorf("page contains the secret %q", secret)
		}
	}
	for _, want := range []string{"Negotiate <redacted>", "Set-Cookie<redacted>"} {
		if !strings.Contains(content, want) {
			t.Errorf("page text lacks %q", want)
		}
	}
}

func TestProbesHTML(t *testing.T) {
	e := newEnv(t, withLifecycle)
	rec := e.do(http.MethodGet, "/debug/probes", nil)
	checkResponse(t, rec, http.StatusOK, "")
	checkHTMLHeaders(t, rec, debugCSP)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	page := rec.Body.String()
	checkInert(t, page, hostileTarget, hostileMessage, hostileBody, hostileHeader, hostileCheck,
		hostileSubject, hostileSPN)

	doc := parseHTML(t, page)
	sections := findAll(doc, "section")
	if got := texts(findAll(doc, "h2")); !slices.Equal(got, []string{"orders", hostileTarget}) {
		t.Fatalf("targets = %q, want config order", got)
	}
	for i, name := range []string{"orders", hostileTarget} {
		s := sections[i]
		heading := findAll(findAll(s, "h2")[0], "a")[0]
		if got := queryTarget(t, attr(heading, "href")); got != name {
			t.Errorf("heading link of %q targets %q", name, got)
		}
		forms := findAll(s, "form")
		if len(forms) != 1 || attr(forms[0], "method") != "post" {
			t.Fatalf("section %q has forms %v, want one POST form", name, forms)
		}
		action := attr(forms[0], "action")
		if !strings.HasPrefix(action, "/debug/probe?") || queryTarget(t, action) != name {
			t.Errorf("form of %q posts to %q", name, action)
		}
	}

	// Newest first, with the summary columns.
	var rows [][]string
	for tbody := range findAll(sections[0], "table")[0].ChildNodes() {
		if tbody.Type == html.ElementNode && tbody.Data == "tbody" {
			rows = append(rows, texts(findAll(findAll(tbody, "tr")[0], "td")))
		}
	}
	want := [][]string{
		{"2026-10-02T12:01:00.000Z", "1.5s", "soap_fault", "500", "36 B", hostileMessage},
		{"2026-10-02T12:00:00.000Z", "312ms", "success", "200", "1234 B", ""},
	}
	if !slices.EqualFunc(rows, want, slices.Equal) {
		t.Errorf("orders rows = %q, want %q", rows, want)
	}
	dnsRow := texts(findAll(findAll(sections[1], "tr")[1], "td"))
	if !slices.Equal(dnsRow[2:5], []string{"dns", "none", "0 B"}) {
		t.Errorf("DNS failure row = %q", dnsRow)
	}

	// Details: phases in probe order, check outcomes, TLS, SPN, charset, body.
	details := text(findAll(sections[0], "details")[0])
	for _, want := range []string{
		"resolve2ms", "connect10ms", "tls40ms", "processing250ms", "transfer10ms",
		"soap_faultfailsoap_fault" + hostileCheck, "statusfailstatusgot 500, want [200]", "envelopepass",
		"SPN" + hostileSPN, "Charsetutf-8", "TLS 1.3, TLS_AES_128_GCM_SHA256, server name orders.example.com",
		hostileSubject + "CN=Example Issuing CA2026-09-02T12:00:00.000Z2027-01-01T00:00:00.000Z" +
			"orders.example.com, orders2.example.com",
		"Body (truncated)",
	} {
		if !strings.Contains(details, want) {
			t.Errorf("details lack %q:\n%s", want, details)
		}
	}
	phases := texts(findAll(findAll(findAll(sections[0], "details")[0], "table")[0], "th"))
	if !slices.Equal(phases, []string{"resolve", "connect", "tls", "processing", "transfer"}) {
		t.Errorf("phases = %q, want probe order", phases)
	}
	if got := text(findAll(sections[1], "details")[0]); !strings.Contains(got, "resolve3ms") ||
		strings.Contains(got, "Checks") || strings.Contains(got, "Body") {
		t.Errorf("DNS failure details = %q", got)
	}
}

// formOrigin returns the Origin header that a browser sends with the POST of a form on page
// to action when page has the given Referrer-Policy (Fetch standard, "append a request
// Origin header", for a request whose mode is not cors).
func formOrigin(t *testing.T, policy string, page, action *url.URL) string {
	t.Helper()
	switch policy {
	case "no-referrer":
		return "null"
	case "", "no-referrer-when-downgrade", "strict-origin", "strict-origin-when-cross-origin":
		if page.Scheme == "https" && action.Scheme != "https" {
			return "null"
		}
	case "same-origin":
		if page.Scheme != action.Scheme || page.Host != action.Host {
			return "null"
		}
	case "origin", "origin-when-cross-origin", "unsafe-url":
	default:
		t.Fatalf("unknown Referrer-Policy %q", policy)
	}
	return page.Scheme + "://" + page.Host
}

// The "Probe now" form works over plain HTTP, where browsers send no Sec-Fetch-Site and
// CrossOriginProtection decides by the Origin that the page's Referrer-Policy yields.
func TestProbeFormOverPlainHTTP(t *testing.T) {
	e := newEnv(t, withLifecycle)
	page, err := url.Parse(exporterURL + "/debug/probes")
	if err != nil {
		t.Fatal(err)
	}
	rec := e.do(http.MethodGet, page.String(), nil)
	checkResponse(t, rec, http.StatusOK, "")
	forms := findAll(parseHTML(t, rec.Body.String()), "form")
	if len(forms) == 0 {
		t.Fatal("page has no probe form")
	}
	action, err := page.Parse(attr(forms[0], "action"))
	if err != nil {
		t.Fatal(err)
	}
	origin := formOrigin(t, rec.Header().Get("Referrer-Policy"), page, action)
	checkResponse(t, e.do(http.MethodPost, action.String(), nil, "Origin", origin), http.StatusOK, "")
	if !slices.Equal(e.app.probed, []string{"orders"}) {
		t.Errorf("probed %q, want [orders]", e.app.probed)
	}
}

func TestProbesHTMLWithoutLifecycle(t *testing.T) {
	e := newEnv(t)
	rec := e.do(http.MethodGet, "/debug/probes", nil)
	checkResponse(t, rec, http.StatusOK, "")
	if forms := findAll(parseHTML(t, rec.Body.String()), "form"); len(forms) != 0 {
		t.Errorf("page has %d probe forms without lifecycle", len(forms))
	}
}

func TestProbesWithoutHistory(t *testing.T) {
	e := newEnv(t)
	// Nothing recorded yet, and a store that does not know the targets (during a reload).
	empty := state.New(10, true)
	empty.SetTargets(e.app.cfg.Targets[:1])
	e.app.store = empty
	rec := e.do(http.MethodGet, "/debug/probes", nil)
	checkResponse(t, rec, http.StatusOK, "")
	if n := strings.Count(rec.Body.String(), "No probes recorded yet."); n != 2 {
		t.Errorf("%d targets without history, want 2:\n%s", n, rec.Body.String())
	}
	checkResponse(t, e.do(http.MethodGet, "/debug/probes?format=json&target=orders", nil), http.StatusOK, "")

	// With --history.limit=0 the targets are probed, but nothing is kept.
	disabled := state.New(0, false)
	disabled.SetTargets(e.app.cfg.Targets)
	disabled.Record(tlsSuccess("orders"))
	e.app.store = disabled
	rec = e.do(http.MethodGet, "/debug/probes", nil)
	checkResponse(t, rec, http.StatusOK, "")
	body := rec.Body.String()
	if n := strings.Count(body, "Probe history is disabled (--history.limit=0)."); n != 2 || strings.Contains(body, "No probes recorded yet.") {
		t.Errorf("%d targets say the history is disabled, want 2:\n%s", n, body)
	}

	e.app.cfg.Targets = nil
	rec = e.do(http.MethodGet, "/debug/probes", nil)
	if !strings.Contains(rec.Body.String(), "No targets configured.") {
		t.Errorf("page without targets:\n%s", rec.Body.String())
	}
	checkResponse(t, e.do(http.MethodGet, "/debug/probes?format=json", nil), http.StatusOK, "{\n  \"targets\": []\n}\n")
}

func TestProbesFilter(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantCode  int
		wantNames []string
	}{
		{"one target", "?target=orders", http.StatusOK, []string{"orders"}},
		{"hostile target", "?target=" + url.QueryEscape(hostileTarget), http.StatusOK, []string{hostileTarget}},
		{"json", "?format=json&target=orders", http.StatusOK, []string{"orders"}},
		{"explicit html", "?format=html", http.StatusOK, []string{"orders", hostileTarget}},
		{"unknown target", "?target=billing", http.StatusNotFound, nil},
		{"empty target", "?target=", http.StatusNotFound, nil},
		{"unknown format", "?format=xml", http.StatusBadRequest, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			rec := e.do(http.MethodGet, "/debug/probes"+tt.query, nil)
			checkResponse(t, rec, tt.wantCode, "")
			if tt.wantCode != http.StatusOK {
				if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
					t.Errorf("error Content-Type = %q", ct)
				}
				return
			}
			var names []string
			if strings.Contains(tt.query, "format=json") {
				var doc probesJSON
				if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				for _, th := range doc.Targets {
					names = append(names, th.Name)
				}
			} else {
				doc := parseHTML(t, rec.Body.String())
				names = texts(findAll(doc, "h2"))
				if len(tt.wantNames) == 1 {
					// The JSON link keeps the filter.
					var jsonLink string
					for _, a := range findAll(doc, "a") {
						if text(a) == "JSON" {
							jsonLink = attr(a, "href")
						}
					}
					if got := queryTarget(t, jsonLink); got != tt.wantNames[0] {
						t.Errorf("JSON link %q targets %q", jsonLink, got)
					}
				}
			}
			if !slices.Equal(names, tt.wantNames) {
				t.Errorf("targets = %q, want %q", names, tt.wantNames)
			}
		})
	}

	e := newEnv(t)
	e.app.cfg = nil
	checkResponse(t, e.do(http.MethodGet, "/debug/probes", nil), http.StatusServiceUnavailable,
		"No configuration loaded yet\n")
}

func TestProbesJSON(t *testing.T) {
	e := newEnv(t)
	rec := e.do(http.MethodGet, "/debug/probes?format=json", nil)
	checkResponse(t, rec, http.StatusOK, "")
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	checkInertJSON(t, rec.Body.Bytes())
	compareGolden(t, rec.Body.Bytes(), "probes.json")

	var doc struct {
		Targets []struct {
			Name    string           `json:"name"`
			Results []map[string]any `json:"results"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Targets) != 2 || doc.Targets[1].Name != hostileTarget {
		t.Fatalf("targets = %+v", doc.Targets)
	}
	orders := doc.Targets[0].Results
	if len(orders) != 2 || orders[0]["start"] != "2026-10-02T12:01:00Z" || orders[1]["start"] != "2026-10-02T12:00:00Z" {
		t.Errorf("orders results are not newest first: %v", orders)
	}
	if got := orders[0]["duration_seconds"]; got != 1.5 {
		t.Errorf("duration_seconds = %v, want 1.5", got)
	}
	if got := orders[0]["phase_duration_seconds"].(map[string]any)["processing"]; got != 0.25 {
		t.Errorf("processing phase = %v, want 0.25", got)
	}
	if got := orders[0]["message"]; got != hostileMessage {
		t.Errorf("message = %v, want the original text", got)
	}
}

// checkInertJSON verifies that a JSON document is inert in a browser and has its secrets redacted.
func checkInertJSON(t *testing.T, body []byte) {
	t.Helper()
	for _, unwanted := range []string{"<", ">", negotiateToken, sessionCookie} {
		if bytes.Contains(body, []byte(unwanted)) {
			t.Errorf("JSON contains %q", unwanted)
		}
	}
	if !bytes.Contains(body, []byte(`"Negotiate \u003credacted\u003e"`)) {
		t.Errorf("JSON lacks the redacted Negotiate token")
	}
}

func TestProbeReportHTML(t *testing.T) {
	e := newEnv(t, withLifecycle)
	rec := e.do(http.MethodPost, "/debug/probe?target=orders", nil)
	checkResponse(t, rec, http.StatusOK, "")
	checkHTMLHeaders(t, rec, debugCSP)
	if !slices.Equal(e.app.probed, []string{"orders"}) {
		t.Errorf("probed %q, want [orders]", e.app.probed)
	}
	page := rec.Body.String()
	checkInert(t, page, hostileMessage, hostileBody, hostileHeader, hostileCheck, hostileSubject, hostileSPN)

	doc := parseHTML(t, page)
	content := text(doc)
	for _, want := range []string{
		"Probe of orders",
		"URLhttps://orders.example.com/Orders.svc",
		"SOAP1.2, action http://example.com/IOrders/GetStatus",
		"Authbasic", "Interval5m, timeout 30s", `team="payments"`,
		"Resultsoap_fault", "Message" + hostileMessage, "Time2026-10-02T13:00:00.000Z", "Duration1.5s",
		"HTTP status500", "Body size36 B",
		"Content-Typeapplication/soap+xml; charset=utf-8", "X-Evil" + hostileHeader,
		"SPN" + hostileSPN, "Charsetutf-8", "TLS 1.3, TLS_AES_128_GCM_SHA256",
		"Certificate chain", "CN=Example Root CA", "Body (truncated)", hostileBody,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("report lacks %q:\n%s", want, content)
		}
	}
	if forms := findAll(doc, "form"); len(forms) != 0 {
		t.Errorf("report has %d forms", len(forms))
	}

	// The target name appears in the title, the heading and the history link.
	rec = e.do(http.MethodPost, "/debug/probe?target="+url.QueryEscape(hostileTarget), nil)
	checkResponse(t, rec, http.StatusOK, "")
	checkInert(t, rec.Body.String(), hostileTarget)
	doc = parseHTML(t, rec.Body.String())
	if got := text(findAll(doc, "title")[0]); got != "Probe of "+hostileTarget+" - soap_exporter" {
		t.Errorf("title = %q", got)
	}
	if got := text(findAll(doc, "h1")[0]); got != "Probe of "+hostileTarget {
		t.Errorf("heading = %q", got)
	}
	var history string
	for _, a := range findAll(doc, "a") {
		if text(a) == "History of this target" {
			history = attr(a, "href")
		}
	}
	if got := queryTarget(t, history); got != hostileTarget {
		t.Errorf("history link %q targets %q", history, got)
	}
	if got := e.app.probed[len(e.app.probed)-1]; got != hostileTarget {
		t.Errorf("probed %q, want the hostile target", got)
	}
}

func TestProbeReportJSON(t *testing.T) {
	e := newEnv(t, withLifecycle)
	rec := e.do(http.MethodPost, "/debug/probe?target=orders&format=json", nil)
	checkResponse(t, rec, http.StatusOK, "")
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	checkInertJSON(t, rec.Body.Bytes())
	compareGolden(t, rec.Body.Bytes(), "probe.json")
}

// A target removed by a reload while it was probed is reported by name only.
func TestProbeReportRemovedTarget(t *testing.T) {
	e := newEnv(t, withLifecycle)
	rec := e.do(http.MethodPost, "/debug/probe?target=gone&format=json", nil)
	checkResponse(t, rec, http.StatusOK, "")
	var doc map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc["target"]) != 1 || doc["target"]["name"] != "gone" || doc["result"]["reason"] != "soap_fault" {
		t.Errorf("report = %v", doc)
	}

	rec = e.do(http.MethodPost, "/debug/probe?target=gone", nil)
	checkResponse(t, rec, http.StatusOK, "")
	if content := text(parseHTML(t, rec.Body.String())); !strings.Contains(content, "Probe of gone") ||
		strings.Contains(content, "Interval") {
		t.Errorf("report:\n%s", content)
	}
}

func TestProbeErrors(t *testing.T) {
	tests := []struct {
		name           string
		query          string
		err            error
		wantCode       int
		wantBody       string
		wantRetryAfter string
		wantProbed     bool
	}{
		{
			name: "unknown target", query: "?target=billing", err: fmt.Errorf("%w: billing", app.ErrUnknownTarget),
			wantCode: http.StatusNotFound, wantBody: "Unknown target \"billing\"\n", wantProbed: true,
		},
		{
			name: "rate limited", query: "?target=orders&format=json", err: app.ErrRateLimited,
			wantCode: http.StatusTooManyRequests, wantBody: app.ErrRateLimited.Error() + "\n",
			wantRetryAfter: retryAfterSeconds, wantProbed: true,
		},
		{
			name: "rate limited, wrapped", query: "?target=orders", err: fmt.Errorf("orders: %w", app.ErrRateLimited),
			wantCode: http.StatusTooManyRequests, wantRetryAfter: retryAfterSeconds, wantProbed: true,
		},
		{
			name: "other error", query: "?target=orders", err: errors.New("app stopped"),
			wantCode: http.StatusInternalServerError, wantBody: "Probe failed: app stopped\n", wantProbed: true,
		},
		{name: "missing target", query: "", wantCode: http.StatusBadRequest},
		{name: "empty target", query: "?target=", wantCode: http.StatusBadRequest},
		{name: "unknown format", query: "?target=orders&format=yaml", wantCode: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, withLifecycle)
			e.app.probe = func(string) (result.Result, error) { return result.Result{}, tt.err }
			rec := e.do(http.MethodPost, "/debug/probe"+tt.query, nil)
			checkResponse(t, rec, tt.wantCode, tt.wantBody)
			if got := rec.Header().Get("Retry-After"); got != tt.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tt.wantRetryAfter)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Errorf("Content-Type = %q", ct)
			}
			if probed := len(e.app.probed) > 0; probed != tt.wantProbed {
				t.Errorf("probed = %v, want %v", probed, tt.wantProbed)
			}
		})
	}
}

// Header checks quote the values they got; on the pages, as in the headers table, those of
// secret headers carry no secrets.
func TestHeaderCheckMessagesRedacted(t *testing.T) {
	e := newEnv(t, withLifecycle)
	orders := findTarget(e.app.cfg, "orders")
	r := hostileFault("orders")
	r.HTTPStatus, r.Body, r.BodyTruncated = http.StatusOK, tlsSuccess("orders").Body, false
	r.Checks, r.Reason, r.Message = check.Evaluate(orders, &check.Response{
		Status: r.HTTPStatus, Header: r.ResponseHeader, Text: r.Body,
	})
	const (
		cookieMessage = `header "Set-Cookie" matches not_regex "SessionId": got "<redacted>"`
		authMessage   = `header "WWW-Authenticate" does not match "^Basic": got "Negotiate <redacted>"`
		typeMessage   = `header "Content-Type" does not match "^text/xml": got "application/soap+xml; charset=utf-8"`
	)
	if r.Reason != result.ReasonHeader || r.Message != cookieMessage {
		t.Fatalf("check.Evaluate = %s %q, want a header failure", r.Reason, r.Message)
	}
	e.app.probe = func(string) (result.Result, error) { return r, nil }
	e.app.store.Record(r)

	for _, req := range []struct{ method, target string }{
		{http.MethodPost, "/debug/probe?target=orders"},
		{http.MethodPost, "/debug/probe?target=orders&format=json"},
		{http.MethodGet, "/debug/probes?target=orders"},
		{http.MethodGet, "/debug/probes?target=orders&format=json"},
	} {
		t.Run(req.method+" "+req.target, func(t *testing.T) {
			rec := e.do(req.method, req.target, nil)
			checkResponse(t, rec, http.StatusOK, "")
			var messages []string
			if strings.Contains(req.target, "format=json") {
				var doc struct {
					Result  *resultJSON         `json:"result"`
					Targets []targetHistoryJSON `json:"targets"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				res := doc.Result
				if res == nil {
					res = &doc.Targets[0].Results[0]
				}
				messages = append(messages, res.Message)
				for _, c := range res.Checks {
					messages = append(messages, c.Message)
				}
			} else {
				doc := parseHTML(t, rec.Body.String())
				for _, td := range findAll(doc, "td") {
					if attr(td, "class") == "message" {
						messages = append(messages, text(td))
					}
				}
				for _, dd := range findAll(doc, "dd") {
					messages = append(messages, text(dd))
				}
			}
			for _, want := range []string{cookieMessage, authMessage, typeMessage} {
				if !slices.Contains(messages, want) {
					t.Errorf("messages lack %q: %q", want, messages)
				}
			}
			for _, secret := range []string{negotiateToken, sessionCookie} {
				if strings.Contains(rec.Body.String(), secret) {
					t.Errorf("response contains the secret %q", secret)
				}
			}
		})
	}
}

// The style element must match the hash in the CSP, or browsers drop the stylesheet.
func TestDebugCSPMatchesStylesheet(t *testing.T) {
	e := newEnv(t, withLifecycle)
	for _, req := range []struct{ method, target string }{
		{http.MethodGet, "/debug/probes"},
		{http.MethodPost, "/debug/probe?target=orders"},
	} {
		rec := e.do(req.method, req.target, nil)
		styles := findAll(parseHTML(t, rec.Body.String()), "style")
		if len(styles) != 1 {
			t.Fatalf("%s: %d style elements, want 1", req.target, len(styles))
		}
		sum := sha256.Sum256([]byte(text(styles[0])))
		hash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "style-src "+hash+";") {
			t.Errorf("%s: CSP %q does not allow the style element (%s)", req.target, csp, hash)
		}
	}
}
