package scheduler

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/common/model"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
)

// rcLog records events from probers and the Reconcile hook in the order they happen.
type rcLog struct {
	mu     sync.Mutex
	events []string
}

func (l *rcLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *rcLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// rcProber blocks in Probe until its loop is cancelled.
type rcProber struct {
	id      string
	log     *rcLog
	started chan struct{}
	once    sync.Once
}

func newRCProber(id string, log *rcLog) *rcProber {
	return &rcProber{id: id, log: log, started: make(chan struct{})}
}

func (p *rcProber) Probe(ctx context.Context) result.Result {
	p.log.add(p.id + " probe")
	p.once.Do(func() { close(p.started) })
	<-ctx.Done()
	return result.Result{Target: p.id}
}

func (p *rcProber) Close() { p.log.add(p.id + " close") }

type rcRecorder struct{}

func (rcRecorder) Record(result.Result) {}

func rcTarget(name, fingerprint string) *config.Target {
	return &config.Target{Name: name, Interval: model.Duration(time.Hour), Fingerprint: fingerprint}
}

func TestReconcileRunsBetweenStopAndStart(t *testing.T) {
	log := &rcLog{}
	s := New(rcRecorder{}, Options{
		InitialDelay: func(time.Duration) time.Duration { return 0 },
		Reconcile: func(targets []*config.Target) {
			names := make([]string, len(targets))
			for i, tg := range targets {
				names[i] = tg.Name
			}
			log.add("reconcile " + strings.Join(names, ","))
		},
	})
	defer s.Stop()

	pa1, pb := newRCProber("a1", log), newRCProber("b", log)
	s.Apply([]Job{{Target: rcTarget("a", "1"), Prober: pa1}, {Target: rcTarget("b", "1"), Prober: pb}})
	<-pa1.started
	<-pb.started

	// a changes, b is unchanged.
	pa2 := newRCProber("a2", log)
	s.Apply([]Job{{Target: rcTarget("a", "2"), Prober: pa2}, {Target: rcTarget("b", "1")}})
	<-pa2.started

	// a is removed.
	s.Apply([]Job{{Target: rcTarget("b", "1")}})

	events := log.list()
	pos := func(e string) int {
		t.Helper()
		i := slices.Index(events, e)
		if i < 0 {
			t.Fatalf("event %q missing from %q", e, events)
		}
		return i
	}
	before := func(a, b int) {
		t.Helper()
		if a >= b {
			t.Errorf("%q must happen before %q; events: %q", events[a], events[b], events)
		}
	}

	first := pos("reconcile a,b")
	before(first, pos("a1 probe"))
	before(first, pos("b probe"))

	second := first + 1 + slices.Index(events[first+1:], "reconcile a,b")
	if second <= first {
		t.Fatalf("second reconcile missing: %q", events)
	}
	before(pos("a1 close"), second)
	before(second, pos("a2 probe"))

	third := pos("reconcile b")
	before(pos("a2 close"), third)
	if slices.Contains(events, "b close") {
		t.Errorf("unchanged prober b was closed: %q", events)
	}
}
