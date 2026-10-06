package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// runMainEnv makes the test binary run main instead of the tests (see TestMain), so that
// tests can check the exit code and the signal handling of a real process.
const runMainEnv = "SOAP_EXPORTER_TEST_RUN_MAIN"

// waitTimeout bounds every wait for the exporter: startup, probes, reloads and shutdown.
const waitTimeout = 10 * time.Second

// client is the HTTP client of the tests; a hanging exporter fails a test instead of
// stalling it. Without keep-alive, the transport never dials a connection it then does not
// use: the server's Shutdown would wait up to 5 seconds for such a connection.
var client = &http.Client{
	Timeout:   waitTimeout,
	Transport: &http.Transport{DisableKeepAlives: true},
}

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main() // exits
	}
	os.Exit(m.Run())
}

// syncBuffer is a bytes.Buffer safe for concurrent use; the logger writes from many
// goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// soapServer answers SOAP 1.1 calls: /ok with a response, /fault with a SOAP Fault. /hang
// answers only once the client gives up or the test ends.
type soapServer struct {
	*httptest.Server
	release chan struct{} // closed when the test ends

	mu        sync.Mutex
	userAgent string // of the last request
	hangs     int    // requests to /hang so far
}

func newSOAPServer(t *testing.T) *soapServer {
	t.Helper()
	s := &soapServer{release: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", s.respond(http.StatusOK, readFixture(t, "response.xml")))
	mux.HandleFunc("/fault", s.respond(http.StatusInternalServerError, readFixture(t, "fault.xml")))
	mux.HandleFunc("/hang", s.hang)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	// Runs before Close, which waits for the requests.
	t.Cleanup(func() { close(s.release) })
	return s
}

func (s *soapServer) hang(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hangs++
	s.mu.Unlock()
	select {
	case <-r.Context().Done():
	case <-s.release:
	}
}

// hangCount returns the number of requests to /hang so far.
func (s *soapServer) hangCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hangs
}

func (s *soapServer) respond(code int, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		s.mu.Lock()
		s.userAgent = r.UserAgent()
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}
}

func (s *soapServer) lastUserAgent() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userAgent
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newConfigDir returns the path of config.yml in a temporary directory that also holds
// request.xml. The file is the fixture name rendered with the URL of the SOAP server.
func newConfigDir(t *testing.T, name, url string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "request.xml"), readFixture(t, "request.xml"))
	path := filepath.Join(dir, "config.yml")
	writeConfig(t, path, name, url)
	return path
}

// writeConfig writes the fixture name, rendered with url, to path.
func writeConfig(t *testing.T, path, name, url string) {
	t.Helper()
	tmpl, err := template.ParseFiles(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, struct{ URL string }{url}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, b.Bytes())
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// freeAddr returns a local address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// exporter is run running in a goroutine.
type exporter struct {
	t      *testing.T
	base   string // http://<listen address>
	stderr *syncBuffer
	cancel context.CancelFunc
	done   chan int // receives the exit code
}

// startExporter runs run with args plus a free listen address and waits until the
// exporter is ready. The test fails if it is not.
func startExporter(t *testing.T, args ...string) *exporter {
	t.Helper()
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	e := &exporter{
		t:      t,
		base:   "http://" + addr,
		stderr: &syncBuffer{},
		cancel: cancel,
		done:   make(chan int, 1),
	}
	args = append(args, "--web.listen-address="+addr)
	go func() { e.done <- run(ctx, args, io.Discard, e.stderr) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-e.done:
		case <-time.After(waitTimeout):
			t.Error("the exporter did not stop")
		}
		if t.Failed() {
			t.Logf("exporter log:\n%s", e.stderr)
		}
	})
	waitReady(t, e.base, func() (int, bool) {
		select {
		case code := <-e.done:
			e.done <- code // for the cleanup
			return code, true
		default:
			return 0, false
		}
	})
	return e
}

// stop cancels the exporter's context and returns its exit code.
func (e *exporter) stop() int {
	e.t.Helper()
	e.cancel()
	select {
	case code := <-e.done:
		e.done <- code
		return code
	case <-time.After(waitTimeout):
		e.t.Fatal("the exporter did not stop")
		return 0
	}
}

// waitReady polls base/-/ready until it answers 200. exited reports whether the exporter
// has exited, and with which code.
func waitReady(t *testing.T, base string, exited func() (int, bool)) {
	t.Helper()
	eventually(t, func() bool {
		if code, ok := exited(); ok {
			t.Fatalf("the exporter exited with code %d before it was ready", code)
		}
		resp, err := client.Get(base + "/-/ready")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "the exporter is not ready")
}

// eventually polls cond until it holds or waitTimeout passes.
func eventually(t *testing.T, cond func() bool, format string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: "+format, args...)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// do sends a request and returns the status code and body.
func do(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: reading the body: %v", method, url, err)
	}
	return resp.StatusCode, string(b)
}

// sample is a series of a scrape. A histogram is a sample of its _count series.
type sample struct {
	name   string
	labels map[string]string
	value  float64
}

// scrape returns the samples of base/metrics.
func scrape(t *testing.T, base string) []sample {
	t.Helper()
	code, body := do(t, http.MethodGet, base+"/metrics", "")
	if code != http.StatusOK {
		t.Fatalf("GET /metrics: status %d\n%s", code, body)
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parsing /metrics: %v", err)
	}
	var out []sample
	for name, mf := range families {
		for _, m := range mf.GetMetric() {
			s := sample{name: name, labels: map[string]string{}}
			for _, lp := range m.GetLabel() {
				s.labels[lp.GetName()] = lp.GetValue()
			}
			switch {
			case m.GetGauge() != nil:
				s.value = m.GetGauge().GetValue()
			case m.GetCounter() != nil:
				s.value = m.GetCounter().GetValue()
			case m.GetHistogram() != nil:
				s.name += "_count"
				s.value = float64(m.GetHistogram().GetSampleCount())
			case m.GetSummary() != nil:
				s.name += "_count"
				s.value = float64(m.GetSummary().GetSampleCount())
			case m.GetUntyped() != nil:
				s.value = m.GetUntyped().GetValue()
			}
			out = append(out, s)
		}
	}
	return out
}

// find returns the value of the first sample of name whose labels include labels, given as
// name-value pairs.
func find(samples []sample, name string, labels ...string) (float64, bool) {
next:
	for _, s := range samples {
		if s.name != name {
			continue
		}
		for i := 0; i+1 < len(labels); i += 2 {
			if v, ok := s.labels[labels[i]]; !ok || v != labels[i+1] {
				continue next
			}
		}
		return s.value, true
	}
	return 0, false
}

// targets returns the target label values of the samples of name.
func targets(samples []sample, name string) []string {
	var out []string
	for _, s := range samples {
		if s.name == name {
			out = append(out, s.labels["target"])
		}
	}
	return out
}

// mainCommand returns a command that runs main in a child process of the test binary.
func mainCommand(t *testing.T, args ...string) (*exec.Cmd, *syncBuffer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*waitTimeout)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	stderr := &syncBuffer{}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("exporter log:\n%s", stderr)
		}
	})
	return cmd, stderr
}

// exitCode returns the exit code of a finished command.
func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		t.Fatalf("running the exporter: %v", err)
	}
	if !exitErr.Exited() {
		t.Fatalf("the exporter did not exit normally: %v", err)
	}
	return exitErr.ExitCode()
}

// mustContain fails unless s contains every one of want.
func mustContain(t *testing.T, what, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("%s does not contain %q:\n%s", what, w, s)
		}
	}
}

// errorLines returns the lines of log logged at error level.
func errorLines(log string) []string {
	var lines []string
	for line := range strings.Lines(log) {
		if strings.Contains(line, "level=ERROR") {
			lines = append(lines, line)
		}
	}
	return lines
}

// mustLogErrorOnce fails unless log has exactly one line at error level, and it contains want.
func mustLogErrorOnce(t *testing.T, log, want string) {
	t.Helper()
	if lines := errorLines(log); len(lines) != 1 || !strings.Contains(lines[0], want) {
		t.Errorf("log has %d error lines, want one with %q:\n%s", len(lines), want, log)
	}
}
