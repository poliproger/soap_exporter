package app

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/result"
)

const (
	reloadOKMetric   = "soap_exporter_config_last_reload_successful"
	reloadTimeMetric = "soap_exporter_config_last_reload_success_timestamp_seconds"
	targetInfoMetric = "soap_target_info"

	monitor  = "monitor@CORP.EXAMPLE"
	payments = "payments@CORP.EXAMPLE"
	audit    = "audit@CORP.EXAMPLE"
)

// probes returns the number of probes of target counted by soap_probes_total.
func probes(series map[string]float64, target string) float64 {
	var n float64
	for key, v := range series {
		if strings.HasPrefix(key, "soap_probes_total{") && strings.Contains(key, `target="`+target+`"`) {
			n += v
		}
	}
	return n
}

func unix(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}

// checkReloadMetrics checks the reload gauges.
func (e *env) checkReloadMetrics(ok float64, last time.Time) {
	e.t.Helper()
	s := e.series()
	if s[reloadOKMetric] != ok || s[reloadTimeMetric] != unix(last) {
		e.t.Errorf("%s = %v, %s = %v; want %v and %v", reloadOKMetric, s[reloadOKMetric], reloadTimeMetric,
			s[reloadTimeMetric], ok, unix(last))
	}
}

func TestNew(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	a, err := New(Options{Registerer: reg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.opts.DebugProbeInterval != 5*time.Second {
		t.Errorf("DebugProbeInterval = %v, want the default 5s", a.opts.DebugProbeInterval)
	}
	if a.Ready() || a.Config() != nil || a.Store() == nil {
		t.Errorf("new App: Ready() = %v, Config() = %v, Store() = %v; want false, nil and a store",
			a.Ready(), a.Config(), a.Store())
	}
	want := map[string]float64{reloadOKMetric: 0, reloadTimeMetric: 0}
	if got := gatherSeries(t, reg); !maps.Equal(got, want) {
		t.Errorf("series = %v, want %v", got, want)
	}

	// The gauges of a second App collide; the first App's metrics stay.
	if _, err := New(Options{Registerer: reg}); err == nil {
		t.Error("New with already registered metrics: no error")
	}
	if got := gatherSeries(t, reg); !maps.Equal(got, want) {
		t.Errorf("after the failed New: series = %v, want %v", got, want)
	}

	if _, err := New(Options{}); err != nil {
		t.Errorf("New without a registerer: %v", err)
	}
}

func TestNewUnregistersOnError(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	taken := prometheus.NewGauge(prometheus.GaugeOpts{Name: reloadTimeMetric, Help: "Taken."})
	reg.MustRegister(taken)
	if _, err := New(Options{Registerer: reg}); err == nil {
		t.Fatal("New: no error")
	}
	// The first gauge was registered before the collision and must be gone again.
	want := map[string]float64{reloadTimeMetric: 0}
	if got := gatherSeries(t, reg); !maps.Equal(got, want) {
		t.Errorf("series = %v, want %v", got, want)
	}
}

func TestStartAndReady(t *testing.T) {
	e := newEnv(t)
	if e.app.Ready() {
		t.Error("Ready before Start")
	}

	e.writeConfig("invalid.yml")
	err := e.app.Start()
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Start with an invalid config: %v, want a timeout error", err)
	}
	if e.app.Ready() || e.app.Config() != nil {
		t.Errorf("after a failed Start: Ready() = %v, Config() = %v; want false and nil",
			e.app.Ready(), e.app.Config())
	}
	e.checkReloadMetrics(0, time.Unix(0, 0))

	// A failed Start may be retried.
	e.writeConfig("basic.yml")
	if err := e.app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !e.app.Ready() {
		t.Error("not Ready after Start")
	}
	cfg := e.app.Config()
	if cfg == nil || len(cfg.Targets) != 2 || cfg.File != e.file {
		t.Fatalf("Config() = %+v, want the two targets of %s", cfg, e.file)
	}
	e.checkReloadMetrics(1, t0)
	if got, want := targetsOf(e.series(), targetInfoMetric), []string{"branches", "orders"}; !slices.Equal(got, want) {
		t.Errorf("%s targets = %q, want %q", targetInfoMetric, got, want)
	}

	e.app.Stop()
	if e.app.Ready() {
		t.Error("Ready after Stop")
	}
}

func TestReloadBeforeStart(t *testing.T) {
	e := newEnv(t)
	e.writeConfig("basic.yml")
	if err := e.app.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !e.app.Ready() {
		t.Error("not Ready after Reload")
	}
	e.checkReloadMetrics(1, t0)
}

func TestStartErrors(t *testing.T) {
	failingBackend := func(o *Options) {
		o.NewBackend = func() (kerberos.Backend, error) { return nil, errors.New("krb5.conf: no such file") }
	}
	tests := []struct {
		name    string
		fixture string // "" leaves the config file missing
		opts    func(*Options)
		fail    func(target string) error
		wantErr []string
	}{
		{name: "missing file", wantErr: []string{"no such file"}},
		{name: "invalid", fixture: "invalid.yml", wantErr: []string{`target "orders"`, "timeout"}},
		{
			name:    "prober error",
			fixture: "basic.yml",
			fail: func(target string) error {
				if target == "branches" {
					return errors.New("no transport")
				}
				return nil
			},
			wantErr: []string{`target "branches": no transport`},
		},
		{
			name:    "unreadable TLS file",
			fixture: "tls-missing-ca.yml",
			wantErr: []string{`target "tls": unable to read CA cert`, "missing-ca.pem"},
		},
		{
			name:    "no kerberos backend",
			fixture: "kerberos.yml",
			opts:    func(o *Options) { o.NewBackend = nil },
			wantErr: []string{"kerberos: no backend available"},
		},
		{
			name:    "kerberos backend error",
			fixture: "kerberos.yml",
			opts:    failingBackend,
			wantErr: []string{"kerberos backend: krb5.conf: no such file"},
		},
		{
			name:    "credential error",
			fixture: "kerberos-broken.yml",
			wantErr: []string{`target "broken": kerberos: keytab`, "unsupported format"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []func(*Options)
			if tt.opts != nil {
				opts = append(opts, tt.opts)
			}
			e := newEnv(t, opts...)
			e.probers.setFail(tt.fail)
			if tt.fixture != "" {
				e.writeConfig(tt.fixture)
			}

			err := e.app.Start()
			if err == nil {
				t.Fatal("Start: no error")
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, "config file "+e.file+": ") {
				t.Errorf("error %q does not name the config file", msg)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not contain %q", msg, want)
				}
			}
			if e.app.Ready() || e.app.Config() != nil {
				t.Errorf("Ready() = %v, Config() = %v; want false and nil", e.app.Ready(), e.app.Config())
			}
			e.checkReloadMetrics(0, time.Unix(0, 0))
			// Nothing built for the rejected configuration survives.
			for _, p := range e.probers.since(0) {
				if n := p.closes.Load(); n != 1 {
					t.Errorf("prober of %s closed %d times, want once", p.target, n)
				}
			}
			if open := e.backend.open(t); len(open) != 0 {
				t.Errorf("open credentials %q, want none", open)
			}
		})
	}
}

// TestNewBackendRetried: a failed backend creation does not stick, and a created backend
// is kept.
func TestNewBackendRetried(t *testing.T) {
	failures := 1
	e := newEnv(t, func(o *Options) {
		next := o.NewBackend
		o.NewBackend = func() (kerberos.Backend, error) {
			if failures > 0 {
				failures--
				return nil, errors.New("krb5.conf: no such file")
			}
			return next()
		}
	})
	e.writeConfig("kerberos.yml")
	if err := e.app.Start(); err == nil {
		t.Fatal("Start with a failing backend: no error")
	}
	for range 2 {
		if err := e.app.Reload(); err != nil {
			t.Fatalf("Reload: %v", err)
		}
	}
	if !e.app.Ready() {
		t.Error("not Ready")
	}
	if n := e.backends.Load(); n != 1 {
		t.Errorf("backends created: %d, want 1", n)
	}
}

func TestReload(t *testing.T) {
	e := newEnv(t)
	e.writeConfig("reload-before.yml")
	if err := e.app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	eventually(t, 10*time.Second, func() bool {
		s := e.series()
		return probes(s, "stable") >= 3 && probes(s, "changing") >= 1 && probes(s, "removed") >= 1
	}, "targets not probed")

	stable, _ := e.app.sched.Prober("stable")
	stableHistory, _ := e.app.Store().History("stable")
	before := e.series()
	e.clock.Set(t0.Add(time.Minute))
	e.writeConfig("reload-after.yml")
	if err := e.app.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	after := e.series()

	if p, _ := e.app.sched.Prober("stable"); p != stable {
		t.Error("the unchanged target got a new prober")
	}
	if got, want := probes(after, "stable"), probes(before, "stable"); got < want {
		t.Errorf("unchanged target: %v probes after the reload, want at least %v", got, want)
	}
	if h, _ := e.app.Store().History("stable"); len(h) < len(stableHistory) {
		t.Errorf("unchanged target: history of %d results, want at least %d", len(h), len(stableHistory))
	}
	// changing and added only probe /block, which does not answer while the test runs.
	for _, name := range []string{"changing", "added"} {
		if n := probes(after, name); n != 0 {
			t.Errorf("%s: %v probes after the reload, want 0", name, n)
		}
		if h, _ := e.app.Store().History(name); len(h) != 0 {
			t.Errorf("%s: history of %d results, want none", name, len(h))
		}
	}
	if got := after[`soap_probe_interval_seconds{target="changing"}`]; got != 60 {
		t.Errorf("interval of the changed target = %v, want 60", got)
	}
	if got, want := targetsOf(after, targetInfoMetric), []string{"added", "changing", "stable"}; !slices.Equal(got, want) {
		t.Errorf("%s targets = %q, want %q", targetInfoMetric, got, want)
	}
	if got := targetsOf(after, "soap_probes_total"); slices.Contains(got, "removed") {
		t.Error("the removed target still has series")
	}
	if _, err := e.app.ProbeNow(t.Context(), "removed"); !errors.Is(err, ErrUnknownTarget) {
		t.Errorf("ProbeNow of the removed target: %v, want ErrUnknownTarget", err)
	}
	e.checkReloadMetrics(1, t0.Add(time.Minute))

	// An invalid configuration changes nothing but the reload metric.
	cfg := e.app.Config()
	changing, _ := e.app.sched.Prober("changing")
	e.clock.Set(t0.Add(2 * time.Minute))
	e.writeConfig("invalid.yml")
	if err := e.app.Reload(); err == nil {
		t.Fatal("Reload of an invalid config: no error")
	}
	if e.app.Config() != cfg || !e.app.Ready() {
		t.Error("a failed reload replaced the config or stopped the app")
	}
	e.checkReloadMetrics(0, t0.Add(time.Minute))
	n := probes(e.series(), "stable")
	eventually(t, 10*time.Second, func() bool { return probes(e.series(), "stable") > n },
		"the unchanged target stopped probing after a failed reload")

	e.clock.Set(t0.Add(3 * time.Minute))
	e.writeConfig("reload-after.yml")
	if err := e.app.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	e.checkReloadMetrics(1, t0.Add(3*time.Minute))
	if p, _ := e.app.sched.Prober("changing"); p != changing {
		t.Error("reloading the same config restarted a target")
	}
}

func TestProbeNow(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.app.ProbeNow(ctx, "orders"); !errors.Is(err, ErrUnknownTarget) {
		t.Errorf("ProbeNow before Start: %v, want ErrUnknownTarget", err)
	}
	e.writeConfig("basic.yml")
	if err := e.app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := e.app.ProbeNow(ctx, "nonexistent"); !errors.Is(err, ErrUnknownTarget) {
		t.Errorf("ProbeNow of an unknown target: %v, want ErrUnknownTarget", err)
	}

	res, err := e.app.ProbeNow(ctx, "orders")
	if err != nil {
		t.Fatalf("ProbeNow: %v", err)
	}
	if !res.Success || res.Target != "orders" {
		t.Errorf("result: target %q, success %v (%s: %s); want a success of orders", res.Target,
			res.Success, res.Reason, res.Message)
	}
	// Bodies are not captured in the history, but an on-demand report always has one.
	if !strings.Contains(res.Body, "<Seq>") {
		t.Errorf("body %q, want the response", res.Body)
	}
	history, _ := e.app.Store().History("orders")
	for _, h := range history {
		if h.Start.Equal(res.Start) {
			t.Error("the on-demand result was recorded")
		}
	}

	// The first probe of orders was at t0; the window is 5s and moves only with an
	// accepted call.
	steps := []struct {
		at     time.Duration
		target string
		want   error
	}{
		{time.Second, "orders", ErrRateLimited},
		{time.Second, "branches", nil},
		{4999 * time.Millisecond, "orders", ErrRateLimited},
		{5 * time.Second, "orders", nil},
		{9 * time.Second, "orders", ErrRateLimited},
		{10 * time.Second, "orders", nil},
		{10 * time.Second, "nonexistent", ErrUnknownTarget},
	}
	for _, s := range steps {
		e.clock.Set(t0.Add(s.at))
		if _, err := e.app.ProbeNow(ctx, s.target); !errors.Is(err, s.want) {
			t.Errorf("ProbeNow(%s) at t0+%v: %v, want %v", s.target, s.at, err, s.want)
		}
	}

	e.app.Stop()
	e.clock.Set(t0.Add(time.Hour))
	if _, err := e.app.ProbeNow(ctx, "orders"); !errors.Is(err, errStopped) {
		t.Errorf("ProbeNow after Stop: %v, want errStopped", err)
	}
}

func TestKerberos(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	checkCreds := func(wantCreated, wantOpen []string) {
		t.Helper()
		if got := e.backend.created(); !slices.Equal(got, wantCreated) {
			t.Errorf("credentials created: %q, want %q", got, wantCreated)
		}
		if got := e.backend.open(t); !slices.Equal(got, wantOpen) {
			t.Errorf("open credentials: %q, want %q", got, wantOpen)
		}
		if n := e.backends.Load(); n != 1 {
			t.Errorf("backends created: %d, want 1", n)
		}
	}

	e.writeConfig("kerberos.yml")
	if err := e.app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// orders and branches share one credential.
	checkCreds([]string{monitor, payments}, []string{monitor, payments})
	for _, tt := range []struct{ target, spn string }{{"orders", "HTTP/127.0.0.1"}, {"public", ""}} {
		res, err := e.app.ProbeNow(ctx, tt.target)
		if err != nil || !res.Success || res.SPN != tt.spn {
			t.Errorf("ProbeNow(%s): %v, success %v (%s: %s), SPN %q; want a success with SPN %q",
				tt.target, err, res.Success, res.Reason, res.Message, res.SPN, tt.spn)
		}
	}

	n := e.probers.count()
	if err := e.app.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := len(e.probers.since(n)); got != 0 {
		t.Errorf("reloading the same config created %d probers", got)
	}
	checkCreds([]string{monitor, payments}, []string{monitor, payments})

	// billing reuses the credential of orders; the one of payments is no longer used.
	n = e.probers.count()
	e.writeConfig("kerberos-reduced.yml")
	if err := e.app.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := len(e.probers.since(n)); got != 1 {
		t.Errorf("reload created %d probers, want 1 for billing", got)
	}
	checkCreds([]string{monitor, payments}, []string{monitor})
	if res, err := e.app.ProbeNow(ctx, "billing"); err != nil || !res.Success {
		t.Errorf("ProbeNow(billing): %v, success %v (%s: %s)", err, res.Success, res.Reason, res.Message)
	}

	// The credential and the prober built for audit are dropped with the failed reload.
	n = e.probers.count()
	cfg := e.app.Config()
	e.writeConfig("kerberos-broken.yml")
	err := e.app.Reload()
	if err == nil || !strings.Contains(err.Error(), `target "broken"`) {
		t.Fatalf("Reload: %v, want an error for target broken", err)
	}
	checkCreds([]string{monitor, payments, audit}, []string{monitor})
	built := e.probers.since(n)
	if len(built) != 1 || built[0].target != "audit" || built[0].closes.Load() != 1 {
		t.Errorf("the failed reload left probers %+v, want the closed one of audit", built)
	}
	if e.app.Config() != cfg {
		t.Error("the failed reload replaced the config")
	}

	e.app.Stop()
	checkCreds([]string{monitor, payments, audit}, []string{})
}

func TestLoadLogsWarnings(t *testing.T) {
	var logs syncBuffer
	e := newEnv(t, func(o *Options) { o.Logger = textLogger(&logs) })
	e.writeConfig("warnings.yml")
	if err := e.app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cfg := e.app.Config()
	if len(cfg.Warnings) != 1 {
		t.Fatalf("warnings %q, want one", cfg.Warnings)
	}
	for _, want := range []string{
		fmt.Sprintf("level=WARN msg=\"Configuration warning\" file=%s warning=%q", e.file, cfg.Warnings[0]),
		`level=INFO msg="Configuration loaded"`,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs do not contain %s:\n%s", want, logs.String())
		}
	}
}

// TestLoadFailureLoggedOnce: Start leaves logging a failure to its caller, which exits;
// Reload logs it, so that neither SIGHUP nor POST /-/reload logs it twice.
func TestLoadFailureLoggedOnce(t *testing.T) {
	var logs syncBuffer
	e := newEnv(t, func(o *Options) { o.Logger = textLogger(&logs) })
	e.writeConfig("invalid.yml")
	if err := e.app.Start(); err == nil {
		t.Fatal("Start of an invalid config: no error")
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("Start logged its error:\n%s", logs.String())
	}

	// A Reload before a successful Start has no previous configuration to keep.
	if err := e.app.Reload(); err == nil {
		t.Fatal("Reload of an invalid config: no error")
	}
	e.writeConfig("basic.yml")
	if err := e.app.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	e.writeConfig("invalid.yml")
	err := e.app.Reload()
	if err == nil {
		t.Fatal("Reload of an invalid config: no error")
	}
	var lines []string
	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, "level=ERROR") {
			lines = append(lines, line)
		}
	}
	want := []string{
		`msg="Loading configuration failed" err=` + strconv.Quote(err.Error()),
		`msg="Reloading configuration failed, the previous configuration stays in effect" err=` + strconv.Quote(err.Error()),
	}
	if len(lines) != len(want) {
		t.Fatalf("%d error lines, want one per failed Reload:\n%s", len(lines), logs.String())
	}
	for i, w := range want {
		if !strings.Contains(lines[i], w) {
			t.Errorf("error line %d = %q, want %s", i, lines[i], w)
		}
	}
}

func TestStop(t *testing.T) {
	t.Run("before Start", func(t *testing.T) {
		e := newEnv(t)
		e.writeConfig("basic.yml")
		e.app.Stop()
		if err := e.app.Start(); !errors.Is(err, errStopped) {
			t.Errorf("Start after Stop: %v, want errStopped", err)
		}
		if e.app.Ready() || e.probers.count() != 0 {
			t.Errorf("Ready() = %v, %d probers; want false and none", e.app.Ready(), e.probers.count())
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		e := newEnv(t)
		e.writeConfig("kerberos.yml")
		if err := e.app.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		e.app.Stop()
		e.app.Stop()
		if e.app.Ready() {
			t.Error("Ready after Stop")
		}
		if err := e.app.Reload(); !errors.Is(err, errStopped) {
			t.Errorf("Reload after Stop: %v, want errStopped", err)
		}
		if open := e.backend.open(t); len(open) != 0 {
			t.Errorf("open credentials %q, want none", open)
		}
		for _, p := range e.probers.since(0) {
			if n := p.closes.Load(); n != 1 {
				t.Errorf("prober of %s closed %d times, want once", p.target, n)
			}
		}
	})
}

// TestStopDuringLoad stops the app while a load is building credentials: the load fails,
// and Stop closes what it built.
func TestStopDuringLoad(t *testing.T) {
	e := newEnv(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.backend.hook = func() { once.Do(func() { close(entered); <-release }) }
	e.writeConfig("kerberos.yml")

	started := make(chan error, 1)
	go func() { started <- e.app.Start() }()
	<-entered
	stopped := make(chan struct{})
	go func() {
		e.app.Stop()
		close(stopped)
	}()
	eventually(t, 5*time.Second, e.app.stopping.Load, "Stop did not begin")
	select {
	case <-stopped:
		t.Fatal("Stop returned during a load")
	default:
	}
	close(release)

	if err := <-started; !errors.Is(err, errStopped) {
		t.Errorf("Start: %v, want errStopped", err)
	}
	<-stopped
	if e.app.Ready() {
		t.Error("Ready after Stop")
	}
	if got := e.backend.created(); len(got) != 2 {
		t.Errorf("credentials created: %q, want two", got)
	}
	if open := e.backend.open(t); len(open) != 0 {
		t.Errorf("open credentials %q, want none", open)
	}
	for _, p := range e.probers.since(0) {
		if n := p.closes.Load(); n != 1 {
			t.Errorf("prober of %s closed %d times, want once", p.target, n)
		}
	}
}

// TestStopCancelsOnDemandProbe stops the app while an on-demand probe waits for a response:
// Stop cancels the probe and returns only after it, and the probe's credential stays open
// until then.
func TestStopCancelsOnDemandProbe(t *testing.T) {
	e := newEnv(t)
	e.writeConfig("slow.yml")
	if err := e.app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	started := make(chan struct{})
	var finished atomic.Bool
	var openAtFinish []string // written before finished is set
	ctx := withProbeHooks(t.Context(), probeHooks{
		start: func() { close(started) },
		finish: func() {
			openAtFinish = e.backend.open(t)
			finished.Store(true)
		},
	})
	type outcome struct {
		res result.Result
		err error
	}
	probed := make(chan outcome, 1)
	go func() {
		res, err := e.app.ProbeNow(ctx, "slow")
		probed <- outcome{res, err}
	}()
	<-started

	stopped := make(chan struct{})
	go func() {
		e.app.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return")
	}
	if !finished.Load() {
		t.Fatal("Stop returned before the on-demand probe finished")
	}
	if !slices.Equal(openAtFinish, []string{monitor}) {
		t.Errorf("open credentials when the probe finished: %q, want %q", openAtFinish, monitor)
	}
	if open := e.backend.open(t); len(open) != 0 {
		t.Errorf("open credentials after Stop: %q, want none", open)
	}
	o := <-probed
	if o.err != nil || o.res.Reason != result.ReasonHTTP || o.res.Message != "probe cancelled" {
		t.Errorf("ProbeNow: %v, reason %q (%s); want a cancelled probe", o.err, o.res.Reason, o.res.Message)
	}
}

// TestStopConcurrentWithReload reloads alternating configurations, which create and drop
// a credential, and runs on-demand probes while the app stops.
func TestStopConcurrentWithReload(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.DebugProbeInterval = time.Nanosecond })
	// A real clock, so that the rate limit lets on-demand probes through.
	e.app.now = time.Now
	configs := []string{
		renderConfig(t, "kerberos.yml", e.server.URL),
		renderConfig(t, "kerberos-reduced.yml", e.server.URL),
	}
	writeFile(t, e.file, configs[0])
	if err := e.app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var reloads atomic.Int64
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			tmp := filepath.Join(e.dir, fmt.Sprintf("config-%d.tmp", i))
			for n := 0; ; n++ {
				// Rename replaces the file atomically, so that a load never reads half of it.
				if err := os.WriteFile(tmp, []byte(configs[n%2]), 0o600); err != nil {
					t.Error(err)
					return
				}
				if err := os.Rename(tmp, e.file); err != nil {
					t.Error(err)
					return
				}
				err := e.app.Reload()
				if errors.Is(err, errStopped) {
					return
				}
				if err != nil {
					t.Errorf("Reload: %v", err)
					return
				}
				reloads.Add(1)
			}
		})
	}
	// payments is not in every configuration, and its credential is dropped and created
	// again with it.
	var onDemand, inFlight atomic.Int64
	ctx := withProbeHooks(t.Context(), probeHooks{
		start:  func() { inFlight.Add(1) },
		finish: func() { inFlight.Add(-1) },
	})
	for _, target := range []string{"orders", "payments"} {
		wg.Go(func() {
			for {
				_, err := e.app.ProbeNow(ctx, target)
				switch {
				case errors.Is(err, errStopped):
					return
				case err == nil:
					onDemand.Add(1)
				case !errors.Is(err, ErrUnknownTarget) && !errors.Is(err, ErrRateLimited):
					t.Errorf("ProbeNow(%s): %v", target, err)
					return
				}
			}
		})
	}
	eventually(t, 10*time.Second, func() bool { return reloads.Load() >= 20 && onDemand.Load() >= 20 },
		"no reloads or on-demand probes")
	e.app.Stop()
	if n := inFlight.Load(); n != 0 {
		t.Errorf("%d on-demand probes still running after Stop", n)
	}
	wg.Wait()

	if e.app.Ready() {
		t.Error("Ready after Stop")
	}
	if open := e.backend.open(t); len(open) != 0 {
		t.Errorf("open credentials %q, want none", open)
	}
	for _, p := range e.probers.since(0) {
		if n := p.closes.Load(); n != 1 {
			t.Errorf("prober of %s closed %d times, want once", p.target, n)
		}
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		fixture string // "" leaves the config file missing
		backend string // "fake" (default), "none" (nil) or "error"
		wantErr []string
		// wantCfg is the number of targets of the returned config, -1 for none.
		wantCfg      int
		wantWarnings int
		wantBackends int
		wantCreated  []string
	}{
		{name: "plain", fixture: "basic.yml", wantCfg: 2},
		{name: "warnings", fixture: "warnings.yml", wantCfg: 1, wantWarnings: 1},
		{
			name:         "kerberos",
			fixture:      "kerberos.yml",
			wantCfg:      4,
			wantBackends: 1,
			wantCreated:  []string{monitor, payments},
		},
		{
			name:         "credential error",
			fixture:      "kerberos-broken.yml",
			wantErr:      []string{`target "broken": kerberos: keytab`, "unsupported format"},
			wantCfg:      4,
			wantBackends: 1,
			wantCreated:  []string{monitor, audit},
		},
		{
			name:    "no backend",
			fixture: "kerberos.yml",
			backend: "none",
			wantErr: []string{"kerberos: no backend available"},
			wantCfg: 4,
		},
		{
			name:         "backend error",
			fixture:      "kerberos.yml",
			backend:      "error",
			wantErr:      []string{"kerberos backend: krb5.conf: no such file"},
			wantCfg:      4,
			wantBackends: 1,
		},
		{
			name:    "unreadable TLS file",
			fixture: "tls-missing-ca.yml",
			wantErr: []string{`target "tls": unable to read CA cert`, "missing-ca.pem"},
			wantCfg: 2,
		},
		{name: "invalid", fixture: "invalid.yml", wantErr: []string{`target "orders"`, "timeout"}, wantCfg: -1},
		{name: "missing", wantErr: []string{"no such file"}, wantCfg: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := newConfigDir(t)
			file := filepath.Join(dir, "config.yml")
			if tt.fixture != "" {
				writeFile(t, file, renderConfig(t, tt.fixture, "http://127.0.0.1:9"))
			}
			backend := &fakeBackend{}
			var calls int
			var newBackend func() (kerberos.Backend, error)
			switch tt.backend {
			case "", "fake":
				newBackend = func() (kerberos.Backend, error) {
					calls++
					return backend, nil
				}
			case "error":
				newBackend = func() (kerberos.Backend, error) {
					calls++
					return nil, errors.New("krb5.conf: no such file")
				}
			}

			cfg, err := Check(file, newBackend)
			switch {
			case len(tt.wantErr) == 0 && err != nil:
				t.Errorf("Check: %v", err)
			case len(tt.wantErr) > 0 && err == nil:
				t.Error("Check: no error")
			case err != nil && !strings.HasPrefix(err.Error(), "config file "+file+": "):
				t.Errorf("error %q does not name the config file", err)
			}
			for _, want := range tt.wantErr {
				if err != nil && !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			switch {
			case tt.wantCfg < 0 && cfg != nil:
				t.Errorf("config with %d targets, want none", len(cfg.Targets))
			case tt.wantCfg >= 0 && (cfg == nil || len(cfg.Targets) != tt.wantCfg || len(cfg.Warnings) != tt.wantWarnings):
				t.Errorf("config %+v, want %d targets and %d warnings", cfg, tt.wantCfg, tt.wantWarnings)
			}
			if calls != tt.wantBackends {
				t.Errorf("backends created: %d, want %d", calls, tt.wantBackends)
			}
			if got := backend.created(); !slices.Equal(got, tt.wantCreated) {
				t.Errorf("credentials created: %q, want %q", got, tt.wantCreated)
			}
			if open := backend.open(t); len(open) != 0 {
				t.Errorf("open credentials %q, want none", open)
			}
		})
	}
}
