package web

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/state"
)

// fakeApp implements App. Handlers are called synchronously through httptest recorders,
// so it needs no locking.
type fakeApp struct {
	cfg   *config.Config
	store *state.Store
	ready bool

	reloadErr error
	reloads   int

	// probe answers ProbeNow; probed records the targets asked for.
	probe  func(target string) (result.Result, error)
	probed []string
}

func (a *fakeApp) Reload() error {
	a.reloads++
	return a.reloadErr
}

func (a *fakeApp) Config() *config.Config { return a.cfg }
func (a *fakeApp) Store() *state.Store    { return a.store }
func (a *fakeApp) Ready() bool            { return a.ready }

func (a *fakeApp) ProbeNow(ctx context.Context, target string) (result.Result, error) {
	if ctx == nil {
		return result.Result{}, errors.New("nil context")
	}
	a.probed = append(a.probed, target)
	return a.probe(target)
}

type testEnv struct {
	app     *fakeApp
	level   *promslog.Level
	logs    *bytes.Buffer
	handler http.Handler
}

type envOption func(*Options)

func withLifecycle(o *Options) { o.EnableLifecycle = true }

// newEnv returns a handler over testdata/config.yml with a store that keeps bodies and the
// history of historyResults.
func newEnv(t *testing.T, opts ...envOption) *testEnv {
	t.Helper()
	cfg, err := config.Load(filepath.Join("testdata", "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	store := state.New(10, true)
	store.SetTargets(cfg.Targets)
	for _, r := range historyResults() {
		store.Record(r)
	}
	fake := &fakeApp{
		cfg:   cfg,
		store: store,
		ready: true,
		probe: func(target string) (result.Result, error) { return reportResult(target), nil },
	}

	level := promslog.NewLevel()
	var logs bytes.Buffer
	o := Options{
		App:             fake,
		Gatherer:        prometheus.NewRegistry(),
		LogLevel:        level,
		KerberosBackend: "gokrb5",
		Logger:          promslog.New(&promslog.Config{Level: level, Writer: &logs}),
	}
	for _, opt := range opts {
		opt(&o)
	}
	h, err := NewHandler(o)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{app: fake, level: level, logs: &logs, handler: h}
}

// do serves one request and returns the recorded response.
func (e *testEnv) do(method, target string, body io.Reader, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func checkResponse(t *testing.T, rec *httptest.ResponseRecorder, wantCode int, wantBody string) {
	t.Helper()
	if rec.Code != wantCode {
		t.Errorf("status = %d, want %d (body %q)", rec.Code, wantCode, rec.Body.String())
	}
	if wantBody != "" && rec.Body.String() != wantBody {
		t.Errorf("body = %q, want %q", rec.Body.String(), wantBody)
	}
}

func TestNewHandlerRequiresOptions(t *testing.T) {
	valid := Options{App: &fakeApp{}, Gatherer: prometheus.NewRegistry(), LogLevel: promslog.NewLevel()}
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"no app", func(o *Options) { o.App = nil }},
		{"no gatherer", func(o *Options) { o.Gatherer = nil }},
		{"no log level", func(o *Options) { o.LogLevel = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := valid
			tt.mutate(&o)
			if h, err := NewHandler(o); err == nil {
				t.Errorf("NewHandler = %v, want an error", h)
			}
		})
	}
	if _, err := NewHandler(valid); err != nil {
		t.Errorf("NewHandler without a logger: %v", err)
	}
}

func TestRouting(t *testing.T) {
	e := newEnv(t, withLifecycle)
	tests := []struct {
		method, target string
		wantCode       int
		wantAllow      string
	}{
		{http.MethodGet, "/", http.StatusOK, ""},
		{http.MethodHead, "/", http.StatusOK, ""},
		{http.MethodPost, "/", http.StatusMethodNotAllowed, "GET, HEAD"},
		{http.MethodGet, "/index.html", http.StatusNotFound, ""},
		{http.MethodGet, "/metrics/", http.StatusNotFound, ""},
		{http.MethodGet, "/debug/pprof/heap", http.StatusNotFound, ""},
		{http.MethodHead, "/metrics", http.StatusOK, ""},
		{http.MethodPost, "/metrics", http.StatusMethodNotAllowed, "GET, HEAD"},
		{http.MethodHead, "/-/healthy", http.StatusOK, ""},
		{http.MethodPost, "/-/healthy", http.StatusMethodNotAllowed, "GET, HEAD"},
		{http.MethodHead, "/-/ready", http.StatusOK, ""},
		{http.MethodDelete, "/-/ready", http.StatusMethodNotAllowed, "GET, HEAD"},
		{http.MethodGet, "/-/reload", http.StatusMethodNotAllowed, "POST"},
		{http.MethodPut, "/-/reload", http.StatusMethodNotAllowed, "POST"},
		{http.MethodPost, "/-/log-level", http.StatusMethodNotAllowed, "GET, HEAD, PUT"},
		{http.MethodHead, "/config", http.StatusOK, ""},
		{http.MethodPost, "/config", http.StatusMethodNotAllowed, "GET, HEAD"},
		{http.MethodHead, "/debug/probes", http.StatusOK, ""},
		{http.MethodPost, "/debug/probes", http.StatusMethodNotAllowed, "GET, HEAD"},
		{http.MethodGet, "/debug/probe?target=orders", http.StatusMethodNotAllowed, "POST"},
		{http.MethodHead, "/debug/probe?target=orders", http.StatusMethodNotAllowed, "POST"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.target, func(t *testing.T) {
			rec := e.do(tt.method, tt.target, nil)
			checkResponse(t, rec, tt.wantCode, "")
			if got := rec.Header().Get("Allow"); got != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tt.wantAllow)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
	if len(e.app.probed) != 0 || e.app.reloads != 0 {
		t.Errorf("wrong methods reached the app: probed %q, %d reloads", e.app.probed, e.app.reloads)
	}
}

func TestLandingPage(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.KerberosBackend = `<b>gokrb5</b>` })
	rec := e.do(http.MethodGet, "/", nil)
	checkResponse(t, rec, http.StatusOK, "")
	checkHTMLHeaders(t, rec, landingCSP)
	page := rec.Body.String()
	for _, want := range []string{
		"soap_exporter",
		"Kerberos backend: &lt;b&gt;gokrb5&lt;/b&gt;",
		"Version: ",
		`href="/metrics"`,
		`href="/config"`,
		`href="/debug/probes"`,
		`href="/-/healthy"`,
		`href="/-/ready"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("landing page lacks %q:\n%s", want, page)
		}
	}
	for _, unwanted := range []string{"<b>gokrb5", "debug/pprof"} {
		if strings.Contains(page, unwanted) {
			t.Errorf("landing page contains %q", unwanted)
		}
	}
}

func checkHTMLHeaders(t *testing.T, rec *httptest.ResponseRecorder, csp string) {
	t.Helper()
	for name, want := range map[string]string{
		"Content-Type":            "text/html; charset=",
		"Content-Security-Policy": csp,
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "same-origin",
	} {
		if got := rec.Header().Values(name); len(got) != 1 || !strings.HasPrefix(strings.ToLower(got[0]), strings.ToLower(want)) {
			t.Errorf("%s = %q, want one value starting with %q", name, got, want)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "script-src") {
		t.Errorf("Content-Security-Policy %q is not restrictive", csp)
	}
}

// failingCollector reports one good gauge and one collection error.
type failingCollector struct{}

var (
	goodDesc = prometheus.NewDesc("web_test_good", "A metric that collects.", nil, nil)
	badDesc  = prometheus.NewDesc("web_test_bad", "A metric that fails.", nil, nil)
)

func (failingCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- goodDesc
	ch <- badDesc
}

func (failingCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(goodDesc, prometheus.GaugeValue, 42)
	ch <- prometheus.NewInvalidMetric(badDesc, errors.New("collector exploded"))
}

func TestMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(failingCollector{})
	e := newEnv(t, func(o *Options) { o.Gatherer = reg })

	rec := e.do(http.MethodGet, "/metrics", nil)
	checkResponse(t, rec, http.StatusOK, "")
	if body := rec.Body.String(); !strings.Contains(body, "web_test_good 42") {
		t.Errorf("metrics lack the good gauge despite ContinueOnError:\n%s", body)
	}
	logs := e.logs.String()
	for _, want := range []string{"level=ERROR", `msg="error gathering metrics"`, "collector exploded"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
}

func TestPromhttpLogger(t *testing.T) {
	tests := []struct {
		name string
		args []any
		want []string
	}{
		{"error", []any{"error gathering metrics:", errors.New("boom")}, []string{`msg="error gathering metrics"`, "err=boom"}},
		{"plain", []any{"message", 3}, []string{`msg="message 3"`}},
		{"lone error", []any{errors.New("boom")}, []string{"msg=boom"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			promhttpLogger{promslog.New(&promslog.Config{Writer: &buf})}.Println(tt.args...)
			for _, want := range tt.want {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("log %q lacks %q", buf.String(), want)
				}
			}
		})
	}
}

func TestHealthAndReadiness(t *testing.T) {
	tests := []struct {
		path     string
		ready    bool
		wantCode int
		wantBody string
	}{
		{"/-/healthy", false, http.StatusOK, "Healthy\n"},
		{"/-/healthy", true, http.StatusOK, "Healthy\n"},
		{"/-/ready", true, http.StatusOK, "Ready\n"},
		{"/-/ready", false, http.StatusServiceUnavailable, "Not ready\n"},
	}
	for _, tt := range tests {
		e := newEnv(t)
		e.app.ready = tt.ready
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := e.do(method, tt.path, nil)
			checkResponse(t, rec, tt.wantCode, tt.wantBody)
			if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Errorf("%s %s: Content-Type = %q", method, tt.path, ct)
			}
		}
	}
}

func TestLifecycleDisabled(t *testing.T) {
	e := newEnv(t)
	for _, req := range []struct{ method, target string }{
		{http.MethodPost, "/-/reload"},
		{http.MethodPut, "/-/log-level?level=debug"},
		{http.MethodPost, "/debug/probe?target=orders"},
		{http.MethodPost, "/debug/probe?target=orders&format=json"},
	} {
		rec := e.do(req.method, req.target, strings.NewReader("debug"))
		checkResponse(t, rec, http.StatusForbidden, "")
		if !strings.Contains(rec.Body.String(), "--web.enable-lifecycle") {
			t.Errorf("%s %s: body %q does not name the flag", req.method, req.target, rec.Body.String())
		}
	}
	if e.app.reloads != 0 || len(e.app.probed) != 0 || e.level.String() != "info" {
		t.Errorf("disabled lifecycle endpoints acted: %d reloads, probed %q, level %s",
			e.app.reloads, e.app.probed, e.level)
	}
	// Reading is not a lifecycle action.
	checkResponse(t, e.do(http.MethodGet, "/-/log-level", nil), http.StatusOK, "info\n")
}

func TestReload(t *testing.T) {
	e := newEnv(t, withLifecycle)
	checkResponse(t, e.do(http.MethodPost, "/-/reload", nil), http.StatusOK, "")
	if e.app.reloads != 1 {
		t.Fatalf("reloads = %d, want 1", e.app.reloads)
	}

	e.app.reloadErr = errors.New(`targets[1] "orders": url: required`)
	rec := e.do(http.MethodPost, "/-/reload", nil)
	checkResponse(t, rec, http.StatusInternalServerError,
		"Failed to reload the configuration: targets[1] \"orders\": url: required\n")
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if e.app.reloads != 2 {
		t.Errorf("reloads = %d, want 2", e.app.reloads)
	}
}

// exporterURL is the exporter as browsers reach it by default: plain HTTP, not localhost.
// They send Sec-Fetch-Site only to HTTPS and localhost, so only Origin is checked.
const exporterURL = "http://exporter.example.com:10057"

func TestCrossOriginProtection(t *testing.T) {
	e := newEnv(t, withLifecycle)
	tests := []struct {
		name     string
		header   []string
		wantCode int
	}{
		{"cross-site browser request", []string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"foreign origin", []string{"Origin", "https://attacker.example.com"}, http.StatusForbidden},
		// What browsers send for a POST from a page with Referrer-Policy: no-referrer.
		{"opaque origin", []string{"Origin", "null"}, http.StatusForbidden},
		{"same-origin browser request", []string{"Sec-Fetch-Site", "same-origin"}, http.StatusOK},
		{"same origin over plain HTTP", []string{"Origin", exporterURL}, http.StatusOK},
		{"non-browser client", nil, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := e.app.reloads
			checkResponse(t, e.do(http.MethodPost, exporterURL+"/-/reload", nil, tt.header...), tt.wantCode, "")
			if reloaded := e.app.reloads > before; reloaded != (tt.wantCode == http.StatusOK) {
				t.Errorf("reloaded = %v with status %d", reloaded, tt.wantCode)
			}
		})
	}
	// Safe methods are never blocked.
	checkResponse(t, e.do(http.MethodGet, "/debug/probes", nil, "Sec-Fetch-Site", "cross-site"), http.StatusOK, "")
}

func TestLogLevel(t *testing.T) {
	tests := []struct {
		name        string
		from        string // initial level, default info
		target      string
		body        string
		contentType string
		wantCode    int
		wantBody    string
		wantLevel   string
		// wantLogged is the level of the logged change, "" if none is logged.
		wantLogged string
	}{
		{name: "body", target: "/-/log-level", body: "debug", wantCode: http.StatusOK, wantBody: "debug\n", wantLevel: "debug", wantLogged: "INFO"},
		{name: "body with newline and case", target: "/-/log-level", body: " WARN\n", wantCode: http.StatusOK, wantBody: "warn\n", wantLevel: "warn", wantLogged: "INFO"},
		{name: "query", target: "/-/log-level?level=error", wantCode: http.StatusOK, wantBody: "error\n", wantLevel: "error", wantLogged: "INFO"},
		{name: "query wins over body", target: "/-/log-level?level=warn", body: "debug", wantCode: http.StatusOK, wantBody: "warn\n", wantLevel: "warn", wantLogged: "INFO"},
		{
			name: "form", target: "/-/log-level", body: "level=debug", contentType: "application/x-www-form-urlencoded",
			wantCode: http.StatusOK, wantBody: "debug\n", wantLevel: "debug", wantLogged: "INFO",
		},
		{name: "debug to info", from: "debug", target: "/-/log-level", body: "info", wantCode: http.StatusOK, wantBody: "info\n", wantLevel: "info", wantLogged: "INFO"},
		{name: "warn to error", from: "warn", target: "/-/log-level", body: "error", wantCode: http.StatusOK, wantBody: "error\n", wantLevel: "error", wantLogged: "WARN"},
		{name: "error to warn", from: "error", target: "/-/log-level", body: "warn", wantCode: http.StatusOK, wantBody: "warn\n", wantLevel: "warn", wantLogged: "WARN"},
		{name: "error to debug", from: "error", target: "/-/log-level", body: "debug", wantCode: http.StatusOK, wantBody: "debug\n", wantLevel: "debug", wantLogged: "INFO"},
		{name: "unchanged", target: "/-/log-level", body: "info", wantCode: http.StatusOK, wantBody: "info\n", wantLevel: "info"},
		{name: "unknown", target: "/-/log-level", body: "verbose", wantCode: http.StatusBadRequest,
			wantBody: "Unknown log level \"verbose\", want one of debug, info, warn, error\n", wantLevel: "info"},
		{name: "unknown query", target: "/-/log-level?level=%3Cb%3E", wantCode: http.StatusBadRequest, wantLevel: "info"},
		{name: "missing", target: "/-/log-level", wantCode: http.StatusBadRequest, wantLevel: "info"},
		{name: "blank", target: "/-/log-level?level=", body: "  \n", wantCode: http.StatusBadRequest, wantLevel: "info"},
		{name: "too large", target: "/-/log-level", body: "debug" + strings.Repeat(" ", maxLogLevelBody),
			wantCode: http.StatusRequestEntityTooLarge, wantLevel: "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, withLifecycle)
			from := cmp.Or(tt.from, "info")
			if err := e.level.Set(from); err != nil {
				t.Fatal(err)
			}
			var header []string
			if tt.contentType != "" {
				header = []string{"Content-Type", tt.contentType}
			}
			rec := e.do(http.MethodPut, tt.target, strings.NewReader(tt.body), header...)
			checkResponse(t, rec, tt.wantCode, tt.wantBody)
			if got := e.level.String(); got != tt.wantLevel {
				t.Errorf("level = %s, want %s", got, tt.wantLevel)
			}
			checkResponse(t, e.do(http.MethodGet, "/-/log-level", nil), http.StatusOK, tt.wantLevel+"\n")

			logs := e.logs.String()
			if tt.wantLogged == "" {
				if logs != "" {
					t.Errorf("logs = %q, want none", logs)
				}
				return
			}
			for _, want := range []string{"level=" + tt.wantLogged, `msg="Log level changed" from=` + from + " to=" + tt.wantLevel} {
				if !strings.Contains(logs, want) {
					t.Errorf("logs lack %q:\n%s", want, logs)
				}
			}
		})
	}
}

// The level set over HTTP controls the logger it was created with.
func TestLogLevelControlsLogger(t *testing.T) {
	e := newEnv(t, withLifecycle)
	logger := promslog.New(&promslog.Config{Level: e.level, Writer: e.logs})
	logger.Debug("before")
	checkResponse(t, e.do(http.MethodPut, "/-/log-level", strings.NewReader("debug")), http.StatusOK, "debug\n")
	logger.Debug("after")
	logs := e.logs.String()
	if strings.Contains(logs, "msg=before") || !strings.Contains(logs, "msg=after") {
		t.Errorf("debug logging did not follow the level:\n%s", logs)
	}
}

func TestConfig(t *testing.T) {
	e := newEnv(t)
	rec := e.do(http.MethodGet, "/config", nil)
	checkResponse(t, rec, http.StatusOK, "")
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	text := rec.Body.String()
	redacted, err := e.app.cfg.Redacted()
	if err != nil {
		t.Fatal(err)
	}
	// Config.Redacted, plus the credential headers that config accepts in headers.
	const proxyAuth, cookie = "Basic cHJveHk6cHJveHktczNjcmV0", "session=c00kie-s3cret"
	want := strings.NewReplacer(proxyAuth, "<secret>", cookie, "<secret>").Replace(string(redacted))
	if want == string(redacted) {
		t.Fatalf("testdata/config.yml lacks the credential headers:\n%s", redacted)
	}
	if text != want {
		t.Errorf("body = \n%s\nwant\n%s", text, want)
	}
	for _, want := range []string{"password: <secret>", "Proxy-Authorization: <secret>", "Cookie: <secret>", "X-Client: soap-exporter-test"} {
		if !strings.Contains(text, want) {
			t.Errorf("body lacks %q:\n%s", want, text)
		}
	}
	if h := e.app.cfg.Targets[0].Headers; h["Cookie"] != cookie || h["Proxy-Authorization"] != proxyAuth {
		t.Errorf("rendering modified the configuration: headers %q", h)
	}

	e.app.cfg = nil
	checkResponse(t, e.do(http.MethodGet, "/config", nil), http.StatusServiceUnavailable, "No configuration loaded yet\n")
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{250*time.Microsecond + 400, "250µs"},
		{1234567 * time.Nanosecond, "1.23ms"},
		{312 * time.Millisecond, "312ms"},
		{1500 * time.Millisecond, "1.5s"},
		{2345678 * time.Microsecond, "2.346s"},
	}
	for _, tt := range tests {
		if got := formatDuration(tt.d); got != tt.want {
			t.Errorf("formatDuration(%d) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
