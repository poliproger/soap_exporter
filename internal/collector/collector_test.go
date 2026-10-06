package collector

import (
	"errors"
	"flag"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil/promlint"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/soap"
	"github.com/poliproger/soap_exporter/internal/state"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// t0 is 2026-10-02T12:00:00Z, Unix time 1790942400.
var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// ordersTarget is an HTTPS SOAP 1.2 target with basic auth and credentials in its URL.
func ordersTarget(t *testing.T) *config.Target {
	const raw = "https://monitor:s3cret@orders.corp.example/Orders.svc?wsdl=0"
	return &config.Target{
		Name:      "orders",
		URL:       raw,
		ParsedURL: mustParseURL(t, raw),
		Interval:  model.Duration(5 * time.Minute),
		Timeout:   model.Duration(30 * time.Second),
		Labels:    map[string]string{"team": "payments"},
		SOAP:      config.SOAP{Version: soap.V12, Action: "http://corp.example/IOrders/GetStatus"},
		HTTPClientConfig: commoncfg.HTTPClientConfig{
			BasicAuth: &commoncfg.BasicAuth{Username: "monitor", Password: "s3cret"},
		},
		Fingerprint: "orders-1",
	}
}

// coreTarget is a plain HTTP SOAP 1.1 target with Kerberos.
func coreTarget(t *testing.T, labels map[string]string) *config.Target {
	const raw = "http://core.corp.example/CoreService.asmx"
	return &config.Target{
		Name:        "core",
		URL:         raw,
		ParsedURL:   mustParseURL(t, raw),
		Interval:    model.Duration(time.Minute),
		Timeout:     model.Duration(10 * time.Second),
		Labels:      labels,
		SOAP:        config.SOAP{Version: soap.V11},
		Kerberos:    &config.Kerberos{Principal: "monitor@CORP.EXAMPLE", Keytab: "monitor.keytab", SPN: "HTTP/core.corp.example"},
		Fingerprint: "core-1",
	}
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
		Body:           "<Envelope/>",
		TLS: &result.TLSInfo{
			Version:     "TLS 1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
			Chain: []result.CertInfo{
				{Subject: "CN=orders.corp.example", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
				{Subject: "CN=Corp Issuing CA", NotAfter: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)},
				{Subject: "CN=Corp Root CA", NotAfter: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)},
			},
		},
	}
}

func faultFailure(target string) result.Result {
	start := t0.Add(time.Minute)
	return result.Result{
		Target: target,
		Start:  start,
		End:    start.Add(1500 * time.Millisecond),
		Phases: map[result.Phase]time.Duration{
			result.PhaseResolve:    time.Millisecond,
			result.PhaseConnect:    4 * time.Millisecond,
			result.PhaseProcessing: 1490 * time.Millisecond,
			result.PhaseTransfer:   5 * time.Millisecond,
		},
		Reason:      result.ReasonSOAPFault,
		Message:     "soap:Server: Object reference not set to an instance of an object.",
		GotResponse: true,
		HTTPStatus:  http.StatusInternalServerError,
		BodySize:    420,
	}
}

func timeoutFailure(target string, start time.Time) result.Result {
	return result.Result{
		Target:  target,
		Start:   start,
		End:     start.Add(10 * time.Second),
		Phases:  map[result.Phase]time.Duration{result.PhaseResolve: time.Millisecond},
		Reason:  result.ReasonTimeout,
		Message: "no response within 10s",
	}
}

func newCollector(targets []*config.Target, results ...result.Result) *Collector {
	s := state.New(10, false)
	s.SetTargets(targets)
	for _, r := range results {
		s.Record(r)
	}
	return New(s)
}

func TestCollectGolden(t *testing.T) {
	tests := []struct {
		name    string
		golden  string
		targets func(t *testing.T) []*config.Target
		results []result.Result
		// metrics limits the comparison to these metric names; empty compares everything.
		metrics []string
	}{
		{
			name:    "before the first probe",
			golden:  "before_first_probe.prom",
			targets: func(t *testing.T) []*config.Target { return []*config.Target{ordersTarget(t)} },
		},
		{
			name:    "after a success with TLS",
			golden:  "success_tls.prom",
			targets: func(t *testing.T) []*config.Target { return []*config.Target{ordersTarget(t)} },
			results: []result.Result{tlsSuccess("orders")},
		},
		{
			name:   "after a failure",
			golden: "failure.prom",
			targets: func(t *testing.T) []*config.Target {
				return []*config.Target{coreTarget(t, map[string]string{"team": "core-banking"})}
			},
			results: []result.Result{tlsSuccess("core"), faultFailure("core")},
		},
		{
			name:   "two targets with different user labels",
			golden: "two_targets.prom",
			targets: func(t *testing.T) []*config.Target {
				return []*config.Target{
					ordersTarget(t),
					coreTarget(t, map[string]string{"system": "core", "criticality": "high"}),
				}
			},
			results: []result.Result{tlsSuccess("orders"), timeoutFailure("core", t0)},
			metrics: []string{
				"soap_target_info", "soap_probe_interval_seconds", "soap_probe_success",
				"soap_probe_failure_reason", "soap_probe_last_timestamp_seconds",
				"soap_probe_http_status_code", "soap_probe_response_size_bytes",
				"soap_probe_tls_version_info",
			},
		},
		{
			name:    "after a failure without a reason",
			golden:  "no_reason.prom",
			targets: func(t *testing.T) []*config.Target { return []*config.Target{coreTarget(t, nil)} },
			results: []result.Result{withReason(timeoutFailure("core", t0), result.ReasonNone)},
			metrics: []string{
				"soap_probe_success", "soap_probe_failure_reason", "soap_probes_total",
				"soap_probe_http_status_code",
			},
		},
		{
			name:    "histogram buckets",
			golden:  "histogram.prom",
			targets: func(t *testing.T) []*config.Target { return []*config.Target{coreTarget(t, nil)} },
			results: []result.Result{
				withDuration(tlsSuccess("core"), 5*time.Millisecond),
				withDuration(tlsSuccess("core"), 10*time.Millisecond), // on a bound: le is inclusive
				withDuration(tlsSuccess("core"), 300*time.Millisecond),
				withDuration(faultFailure("core"), 2500*time.Millisecond),
				withDuration(tlsSuccess("core"), 75*time.Second), // only in +Inf
				timeoutFailure("core", t0),                       // no response, not observed
			},
			metrics: []string{"soap_probe_duration_seconds", "soap_probes_total"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCollector(tt.targets(t), tt.results...)
			compareGolden(t, c, tt.golden, tt.metrics...)
		})
	}
}

func withDuration(r result.Result, d time.Duration) result.Result {
	r.End = r.Start.Add(d)
	return r
}

func withReason(r result.Result, reason result.Reason) result.Result {
	r.Reason = reason
	return r
}

// compareGolden compares the named metric families of c (all of them when metrics is empty)
// with testdata/golden; -update rewrites the file instead.
func compareGolden(t *testing.T, c prometheus.Collector, golden string, metrics ...string) {
	t.Helper()
	got := mustScrape(t, c, metrics...)
	path := filepath.Join("testdata", golden)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s does not match (-want +got):\n%s", path, lineDiff(string(want), got))
	}
}

// scrape collects c through a pedantic registry and returns the text exposition of the
// named metric families (all of them when names is empty) with the Gather error. Gather
// misses some problems Prometheus rejects a whole scrape for, such as a label name that
// appears twice, so the exposition must also parse back.
func scrape(t *testing.T, c prometheus.Collector, names ...string) (string, error) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatal(err)
	}
	families, gatherErr := reg.Gather()
	var b strings.Builder
	for _, mf := range families {
		if len(names) > 0 && !slices.Contains(names, mf.GetName()) {
			continue
		}
		if _, err := expfmt.MetricFamilyToText(&b, mf); err != nil {
			t.Fatal(err)
		}
	}
	text := b.String()
	parser := expfmt.NewTextParser(model.UTF8Validation)
	if _, err := parser.TextToMetricFamilies(strings.NewReader(text)); err != nil {
		t.Errorf("exposition does not parse: %v\n%s", err, text)
	}
	return text, gatherErr
}

func mustScrape(t *testing.T, c prometheus.Collector, names ...string) string {
	t.Helper()
	text, err := scrape(t, c, names...)
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	return text
}

// countSeries returns the number of series of the metric family name.
func countSeries(t *testing.T, c prometheus.Collector, name string) int {
	t.Helper()
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(mustScrape(t, c, name)))
	if err != nil {
		t.Fatal(err)
	}
	return len(families[name].GetMetric())
}

// lineDiff lists the lines only in want (-) and only in got (+).
func lineDiff(want, got string) string {
	count := map[string]int{}
	for line := range strings.Lines(got) {
		count[line]++
	}
	var b strings.Builder
	for line := range strings.Lines(want) {
		if count[line] > 0 {
			count[line]--
			continue
		}
		b.WriteString("- " + line)
	}
	for line := range strings.Lines(got) {
		if count[line] > 0 {
			count[line]--
			b.WriteString("+ " + line)
		}
	}
	return b.String()
}

func TestCollectEmptyStore(t *testing.T) {
	if got := mustScrape(t, New(state.New(10, false))); got != "" {
		t.Errorf("collected metrics from an empty store:\n%s", got)
	}
}

func TestCollectFollowsReload(t *testing.T) {
	s := state.New(10, false)
	s.SetTargets([]*config.Target{ordersTarget(t), coreTarget(t, map[string]string{"system": "core"})})
	c := New(s)
	if n := countSeries(t, c, "soap_target_info"); n != 2 {
		t.Fatalf("soap_target_info series = %d, want 2", n)
	}

	s.SetTargets([]*config.Target{ordersTarget(t)})
	const want = `# HELP soap_target_info Static information about the probed target; always 1.
# TYPE soap_target_info gauge
soap_target_info{auth="basic",soap_action="http://corp.example/IOrders/GetStatus",soap_version="1.2",target="orders",team="payments",url="https://monitor:xxxxx@orders.corp.example/Orders.svc?wsdl=0"} 1
`
	if got := mustScrape(t, c, "soap_target_info"); got != want {
		t.Errorf("after reload (-want +got):\n%s", lineDiff(want, got))
	}
}

// A user label "le" would appear twice on every histogram bucket, which makes Prometheus
// reject the whole scrape. The histogram is reported as one Gather error instead, and
// everything else is still exposed.
func TestBucketLabelClash(t *testing.T) {
	c := newCollector(
		[]*config.Target{ordersTarget(t), coreTarget(t, map[string]string{"le": "x"})},
		tlsSuccess("orders"), tlsSuccess("core"),
	)
	text, err := scrape(t, c)
	// Gather returns a MultiError only for more than one error.
	var multi prometheus.MultiError
	if err == nil || errors.As(err, &multi) || !strings.Contains(err.Error(), `targets ["core"]: user label "le"`) {
		t.Errorf("Gather error = %v, want one error naming target core and label le", err)
	}
	if strings.Contains(text, "soap_probe_duration_seconds") {
		t.Errorf("histogram exposed despite the clash:\n%s", text)
	}
	const want = `soap_probe_success{le="x",target="core",team=""} 1`
	if !strings.Contains(text, want) {
		t.Errorf("exposition lacks %s:\n%s", want, text)
	}
}

func TestTLSMetricsNeedAChain(t *testing.T) {
	tests := []struct {
		name string
		tls  *result.TLSInfo
		want int
	}{
		{name: "plain HTTP", tls: nil, want: 0},
		{name: "no certificates", tls: &result.TLSInfo{Version: "TLS 1.2"}, want: 0},
		{name: "with a chain", tls: tlsSuccess("orders").TLS, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tlsSuccess("orders")
			r.TLS = tt.tls
			c := newCollector([]*config.Target{ordersTarget(t)}, r)
			for _, name := range []string{"soap_probe_tls_version_info", "soap_probe_tls_cert_expiry_timestamp_seconds"} {
				if got := countSeries(t, c, name); got != tt.want {
					t.Errorf("%s: %d series, want %d", name, got, tt.want)
				}
			}
		})
	}
}

func TestLint(t *testing.T) {
	c := newCollector([]*config.Target{ordersTarget(t)}, faultFailure("orders"), tlsSuccess("orders"))
	problems, err := promlint.New(strings.NewReader(mustScrape(t, c))).Lint()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("%s: %s", p.Metric, p.Text)
	}
}

func TestRedactedURL(t *testing.T) {
	tests := []struct {
		name   string
		target config.Target
		want   string
	}{
		{
			name:   "parsed URL with a password",
			target: config.Target{URL: "https://u:p@a.example.com/x", ParsedURL: mustParseURL(t, "https://u:p@a.example.com/x")},
			want:   "https://u:xxxxx@a.example.com/x",
		},
		{
			name:   "without ParsedURL",
			target: config.Target{URL: "http://u:p@a.example.com:8080/x"},
			want:   "http://u:xxxxx@a.example.com:8080/x",
		},
		{
			name:   "without credentials",
			target: config.Target{URL: "http://a.example.com/x"},
			want:   "http://a.example.com/x",
		},
		{
			name:   "unparsable",
			target: config.Target{URL: "http://u:p@a.example.com:port/x"},
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactedURL(&tt.target); got != tt.want {
				t.Errorf("redactedURL(%q) = %q, want %q", tt.target.URL, got, tt.want)
			}
		})
	}
}

func TestUnixSeconds(t *testing.T) {
	tests := []struct {
		in   time.Time
		want float64
	}{
		{in: t0, want: 1790942400},
		{in: t0.Add(250 * time.Millisecond), want: 1790942400.25},
		{in: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), want: 253402300799},
	}
	for _, tt := range tests {
		if got := unixSeconds(tt.in); got != tt.want {
			t.Errorf("unixSeconds(%s) = %f, want %f", tt.in, got, tt.want)
		}
	}
}
