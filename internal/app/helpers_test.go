package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/scheduler"
)

// t0 is the fake time of the first load, 2026-10-02T12:00:00Z (Unix time 1790942400).
var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// keytabs are written to the config directory; the fake backend never parses them, but the
// config loader wants non-empty files.
var keytabs = []string{"monitor.keytab", "payments.keytab", "audit.keytab", "broken.keytab"}

// env is an App on a temporary config file, probing a local SOAP server.
type env struct {
	t        *testing.T
	dir      string
	file     string
	server   *soapServer
	reg      *prometheus.Registry
	backend  *fakeBackend
	backends atomic.Int32 // calls of Options.NewBackend
	clock    *fakeClock
	probers  *proberTracker
	app      *App
}

// newEnv returns an env whose App is not started. opts may change the options first.
func newEnv(t *testing.T, opts ...func(*Options)) *env {
	t.Helper()
	e := &env{
		t:       t,
		dir:     newConfigDir(t),
		server:  newSOAPServer(t),
		reg:     prometheus.NewPedanticRegistry(),
		backend: &fakeBackend{},
		clock:   &fakeClock{now: t0},
	}
	e.file = filepath.Join(e.dir, "config.yml")

	o := Options{
		ConfigFile: e.file,
		NewBackend: func() (kerberos.Backend, error) {
			e.backends.Add(1)
			return e.backend, nil
		},
		UserAgent:    "soap_exporter/test",
		HistoryLimit: 100,
		Registerer:   e.reg,
	}
	for _, f := range opts {
		f(&o)
	}
	a, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.now = e.clock.Now
	e.probers = trackProbers(a)
	e.app = a
	t.Cleanup(a.Stop)
	return e
}

// newConfigDir returns a temporary directory with the files the config fixtures refer to.
func newConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	copyFile(t, filepath.Join("testdata", "request.xml"), filepath.Join(dir, "request.xml"))
	for _, name := range keytabs {
		writeFile(t, filepath.Join(dir, name), "\x05\x02keytab")
	}
	return dir
}

// renderConfig returns the config fixture testdata/name with {{.URL}} set to url.
func renderConfig(t *testing.T, name, url string) string {
	t.Helper()
	tmpl, err := template.ParseFiles(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, struct{ URL string }{url}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// writeConfig writes the fixture testdata/name, probing the SOAP server, as the config
// file.
func (e *env) writeConfig(name string) {
	e.t.Helper()
	writeFile(e.t, e.file, renderConfig(e.t, name, e.server.URL))
}

// series gathers the registry; see gatherSeries.
func (e *env) series() map[string]float64 {
	e.t.Helper()
	return gatherSeries(e.t, e.reg)
}

// gatherSeries returns every series of g by its name and non-empty labels in text format,
// e.g. `soap_probes_total{result="success",target="orders"}`. A histogram contributes its
// _count series only.
func gatherSeries(t *testing.T, g prometheus.Gatherer) map[string]float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			name, v := mf.GetName(), 0.0
			switch {
			case m.GetCounter() != nil:
				v = m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				v = m.GetGauge().GetValue()
			case m.GetHistogram() != nil:
				name += "_count"
				v = float64(m.GetHistogram().GetSampleCount())
			default:
				t.Fatalf("unexpected type %v of %s", mf.GetType(), name)
			}
			var labels []string
			for _, lp := range m.GetLabel() {
				if lp.GetValue() != "" {
					labels = append(labels, fmt.Sprintf("%s=%q", lp.GetName(), lp.GetValue()))
				}
			}
			if len(labels) > 0 {
				name += "{" + strings.Join(labels, ",") + "}"
			}
			out[name] = v
		}
	}
	return out
}

// targetsOf returns the sorted target label values of the series of metric.
func targetsOf(series map[string]float64, metric string) []string {
	var out []string
	for key := range series {
		if !strings.HasPrefix(key, metric+"{") {
			continue
		}
		_, rest, ok := strings.Cut(key, `target="`)
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(rest, `"`)
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, timeout time.Duration, cond func() bool, format string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: "+format, args...)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, to, string(data))
}

// soapServer answers SOAP 1.1 calls:
//
//	/ok         a response carrying the sequence number of the request in <Seq>
//	/negotiate  as /ok, but 401 unless the request carries a token of the fake backend
//	/block      no response until the request is cancelled or the test ends
type soapServer struct {
	*httptest.Server
	response *template.Template
	seq      atomic.Int64
}

func newSOAPServer(t *testing.T) *soapServer {
	t.Helper()
	s := &soapServer{response: template.Must(template.ParseFiles(filepath.Join("testdata", "response.xml")))}
	done := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", s.respond)
	mux.HandleFunc("/negotiate", func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Negotiate ")
		if raw, err := base64.StdEncoding.DecodeString(token); !ok || err != nil || !bytes.HasPrefix(raw, []byte(fakeTokenPrefix)) {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.respond(w, r)
	})
	mux.HandleFunc("/block", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(func() {
		close(done)
		s.Close()
	})
	return s
}

func (s *soapServer) respond(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_ = s.response.Execute(w, struct{ Seq int64 }{s.seq.Add(1)})
}

// fakeTokenPrefix starts every token of a fakeCredential.
const fakeTokenPrefix = "fake-token "

// fakeBackend creates fakeCredentials. NewCredential fails for a keytab named
// broken.keytab.
type fakeBackend struct {
	// hook, if set, runs at the start of NewCredential.
	hook func()

	mu    sync.Mutex
	creds []*fakeCredential
}

func (b *fakeBackend) Name() string { return "fake" }

func (b *fakeBackend) NewCredential(principal, keytab string) (kerberos.Credential, error) {
	if b.hook != nil {
		b.hook()
	}
	if filepath.Base(keytab) == "broken.keytab" {
		return nil, fmt.Errorf("keytab %s: unsupported format", keytab)
	}
	c := &fakeCredential{principal: principal, keytab: keytab}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.creds = append(b.creds, c)
	return c, nil
}

// created returns the principals of all credentials created so far, in creation order.
func (b *fakeBackend) created() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.creds))
	for _, c := range b.creds {
		out = append(out, c.principal)
	}
	return out
}

// open returns the sorted principals of the credentials not closed. It fails the test if
// a credential was closed twice.
func (b *fakeBackend) open(t *testing.T) []string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []string{}
	for _, c := range b.creds {
		switch n := c.closes.Load(); n {
		case 0:
			out = append(out, c.principal)
		case 1:
		default:
			t.Errorf("credential %s closed %d times", c.principal, n)
		}
	}
	slices.Sort(out)
	return out
}

type fakeCredential struct {
	principal, keytab string
	closes            atomic.Int32
}

func (c *fakeCredential) Token(_ context.Context, spn string) ([]byte, error) {
	if c.closes.Load() > 0 {
		return nil, errors.New("credential closed")
	}
	return []byte(fakeTokenPrefix + c.principal + " " + spn), nil
}

func (c *fakeCredential) Reset() {}

func (c *fakeCredential) Close() error {
	c.closes.Add(1)
	return nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// proberTracker wraps the probers an App creates, to see which ones are closed. fail, if
// set, makes the creation for a target fail.
type proberTracker struct {
	mu      sync.Mutex
	probers []*trackedProber
	fail    func(target string) error
}

type trackedProber struct {
	scheduler.Prober
	target string
	closes atomic.Int32
}

func (p *trackedProber) Probe(ctx context.Context) result.Result {
	h, _ := ctx.Value(probeHooksKey{}).(probeHooks)
	if h.start != nil {
		h.start()
	}
	r := p.Prober.Probe(ctx)
	if h.finish != nil {
		h.finish()
	}
	return r
}

func (p *trackedProber) Close() {
	p.closes.Add(1)
	p.Prober.Close()
}

// probeHooks are called by a trackedProber when a probe whose context carries them (see
// withProbeHooks) starts and when it has finished.
type probeHooks struct{ start, finish func() }

type probeHooksKey struct{}

func withProbeHooks(ctx context.Context, h probeHooks) context.Context {
	return context.WithValue(ctx, probeHooksKey{}, h)
}

func trackProbers(a *App) *proberTracker {
	tr := &proberTracker{}
	newProber := a.builder.newProber
	a.builder.newProber = func(t *config.Target, cred kerberos.Credential) (scheduler.Prober, error) {
		tr.mu.Lock()
		fail := tr.fail
		tr.mu.Unlock()
		if fail != nil {
			if err := fail(t.Name); err != nil {
				return nil, err
			}
		}
		p, err := newProber(t, cred)
		if err != nil {
			return nil, err
		}
		tp := &trackedProber{Prober: p, target: t.Name}
		tr.mu.Lock()
		defer tr.mu.Unlock()
		tr.probers = append(tr.probers, tp)
		return tp, nil
	}
	return tr
}

func (tr *proberTracker) setFail(fail func(target string) error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.fail = fail
}

// count returns the number of probers created so far.
func (tr *proberTracker) count() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return len(tr.probers)
}

// since returns the probers created after the first n.
func (tr *proberTracker) since(n int) []*trackedProber {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return slices.Clone(tr.probers[n:])
}

// syncBuffer is a log destination for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func textLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
