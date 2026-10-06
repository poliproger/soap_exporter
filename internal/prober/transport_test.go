package prober

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/poliproger/soap_exporter/internal/result"
)

// stuckRoundTripper returns a wrap hook for a RoundTripper that ignores the request context
// and blocks until release is closed; then it calls then. It counts its calls in entered,
// unless that is nil.
func stuckRoundTripper(release <-chan struct{}, entered *atomic.Int32,
	then func(next http.RoundTripper, req *http.Request) (*http.Response, error),
) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if entered != nil {
				entered.Add(1)
			}
			<-release
			return then(next, req)
		})
	}
}

// probeTimesOut runs a probe that must end at its deadline of 100ms.
func probeTimesOut(t *testing.T, p *Prober) {
	t.Helper()
	r := probe(t, p)
	if want := "timed out (timeout 100ms)"; r.Reason != result.ReasonTimeout || r.Message != want {
		t.Errorf("reason, message = %q, %q; want timeout, %q", r.Reason, r.Message, want)
	}
	if d := r.Duration(); d > 3*time.Second {
		t.Errorf("duration = %v, want the probe to end at its deadline", d)
	}
}

// waitFor polls cond for up to 5s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within 5s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTransportBoundsStuckRoundTrips(t *testing.T) {
	ts := newServer(t, okHandler(t))
	release := make(chan struct{})
	var entered atomic.Int32
	p := newTestProber(t, loadTarget(t, ts.URL, "1.1", "timeout: 100ms"), hooks{
		wrap: stuckRoundTripper(release, &entered, func(next http.RoundTripper, req *http.Request) (*http.Response, error) {
			return next.RoundTrip(req)
		}),
	})

	// The first probes leave their round trips stuck; the rest wait for a free slot.
	for range maxRoundTrips + 2 {
		probeTimesOut(t, p)
	}
	if n := entered.Load(); n != maxRoundTrips {
		t.Errorf("%d round trips started, want %d", n, maxRoundTrips)
	}

	close(release)
	waitFor(t, "stuck round trips end", func() bool { return len(p.slots) == 0 })
	if r := probe(t, p); !r.Success {
		t.Errorf("probe after the round trips ended failed: %s: %s", r.Reason, r.Message)
	}
}

func TestTransportClosesLateResponse(t *testing.T) {
	release := make(chan struct{})
	body := &closeRecorder{Reader: strings.NewReader("late")}
	p := newTestProber(t, loadTarget(t, "http://soap.example.com/Orders.asmx", "1.1", "timeout: 100ms"), hooks{
		wrap: stuckRoundTripper(release, nil, func(http.RoundTripper, *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: body}, nil
		}),
	})

	probeTimesOut(t, p)
	close(release)
	waitFor(t, "late response body closed", body.closed.Load)
}

func TestTransportLogsLatePanic(t *testing.T) {
	release := make(chan struct{})
	var logs syncBuffer
	tgt := loadTarget(t, "http://soap.example.com/Orders.asmx", "1.1", "timeout: 100ms")
	p, err := newProber(tgt, nil, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))}, hooks{
		wrap: stuckRoundTripper(release, nil, func(http.RoundTripper, *http.Request) (*http.Response, error) {
			panic("late boom")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	probeTimesOut(t, p)
	close(release)
	waitFor(t, "late panic logged", func() bool {
		return strings.Contains(logs.String(), "Round trip panicked after its probe ended")
	})
	if out := logs.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "panic=\"late boom\"") ||
		!strings.Contains(out, "stack=") {
		t.Errorf("log = %q, want an error with the panic and the stack", out)
	}
}

// closeRecorder is a response body that records Close.
type closeRecorder struct {
	io.Reader
	closed atomic.Bool
}

func (b *closeRecorder) Close() error {
	b.closed.Store(true)
	return nil
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
