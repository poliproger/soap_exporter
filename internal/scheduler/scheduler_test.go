package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/common/model"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
)

// Most tests run in a synctest bubble: time is fake, so schedules are checked exactly and
// instantly, and the bubble fails the test if a goroutine outlives the scheduler.

const interval = time.Minute

func target(name, fingerprint string) *config.Target {
	return &config.Target{Name: name, Fingerprint: fingerprint, Interval: model.Duration(interval)}
}

// job returns a job for target(name, fingerprint); a nil p yields a job without a prober.
func job(name, fingerprint string, p *fakeProber) Job {
	j := Job{Target: target(name, fingerprint)}
	if p != nil {
		j.Prober = p
	}
	return j
}

type fakeProber struct {
	// probe handles call n (1-based); nil means an immediate success.
	probe  func(ctx context.Context, n int) result.Result
	calls  atomic.Int64
	closes atomic.Int64
}

func newFakeProber(probe func(ctx context.Context, n int) result.Result) *fakeProber {
	return &fakeProber{probe: probe}
}

func (p *fakeProber) Probe(ctx context.Context) result.Result {
	n := int(p.calls.Add(1))
	if p.probe == nil {
		return result.Result{Success: true}
	}
	return p.probe(ctx, n)
}

func (p *fakeProber) Close() { p.closes.Add(1) }

type recorder struct {
	mu      sync.Mutex
	results []result.Result
}

func (r *recorder) Record(res result.Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, res)
}

func (r *recorder) all() []result.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.results)
}

// newScheduler returns a scheduler without initial delay that is stopped at the end of the
// test.
func newScheduler(t *testing.T, rec Recorder, logger *slog.Logger) *Scheduler {
	t.Helper()
	s := New(rec, Options{
		Logger:       logger,
		InitialDelay: func(time.Duration) time.Duration { return 0 },
	})
	t.Cleanup(s.Stop)
	return s
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// logEntry holds the attributes of a log record the tests look at.
type logEntry struct {
	Level   string `json:"level"`
	Msg     string `json:"msg"`
	Target  string `json:"target"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Err     string `json:"err"`
}

func newLogger() (*slog.Logger, *logBuffer) {
	b := &logBuffer{}
	return slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})), b
}

// entries returns the logged records that match keep, decoded into dst.
func entries[T any](t *testing.T, b *logBuffer, keep func(map[string]any) bool) []T {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []T
	dec := json.NewDecoder(bytes.NewReader(b.buf.Bytes()))
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatalf("decoding log: %v", err)
		}
		var attrs map[string]any
		if err := json.Unmarshal(raw, &attrs); err != nil {
			t.Fatalf("decoding log: %v", err)
		}
		if !keep(attrs) {
			continue
		}
		var e T
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("decoding log: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func withMsg(msg string) func(map[string]any) bool {
	return func(a map[string]any) bool { return a["msg"] == msg }
}

func TestDefaultInitialDelay(t *testing.T) {
	tests := []struct {
		interval time.Duration
		limit    time.Duration // the delay is in [0, limit), or 0 if limit is 0
	}{
		{interval: -time.Second, limit: 0},
		{interval: 0, limit: 0},
		{interval: time.Nanosecond, limit: time.Nanosecond},
		{interval: 500 * time.Millisecond, limit: 500 * time.Millisecond},
		{interval: 10 * time.Second, limit: 10 * time.Second},
		{interval: time.Hour, limit: 10 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.interval.String(), func(t *testing.T) {
			var longest time.Duration
			for range 1000 {
				d := defaultInitialDelay(tt.interval)
				if d < 0 || (tt.limit == 0 && d != 0) || (tt.limit > 0 && d >= tt.limit) {
					t.Fatalf("defaultInitialDelay(%v) = %v, want [0, %v)", tt.interval, d, tt.limit)
				}
				longest = max(longest, d)
			}
			// 1000 samples all in the lower half are practically impossible.
			if tt.limit >= time.Second && longest < tt.limit/2 {
				t.Errorf("longest of 1000 delays is %v, want them spread over [0, %v)", longest, tt.limit)
			}
		})
	}
}

func TestSchedule(t *testing.T) {
	tests := []struct {
		name         string
		initialDelay time.Duration
		// probeTime returns how long probe n takes; nil means no time.
		probeTime func(n int) time.Duration
		// want holds the probe start times, relative to Apply.
		want []time.Duration
	}{
		{
			name: "probes at the interval",
			want: []time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute},
		},
		{
			name:         "first probe after the initial delay",
			initialDelay: 25 * time.Second,
			want:         []time.Duration{25 * time.Second, 85 * time.Second, 145 * time.Second},
		},
		{
			name:         "negative initial delay means none",
			initialDelay: -time.Second,
			want:         []time.Duration{0, time.Minute, 2 * time.Minute},
		},
		{
			name:      "slow probes never overlap",
			probeTime: func(int) time.Duration { return 150 * time.Second },
			want:      []time.Duration{0, 150 * time.Second, 300 * time.Second, 450 * time.Second},
		},
		{
			// One missed tick is delivered when the stalled probe ends, the other nine are
			// dropped; then the loop is back on the ticker's grid.
			name: "missed ticks are dropped",
			probeTime: func(n int) time.Duration {
				if n == 1 {
					return 630 * time.Second
				}
				return 0
			},
			want: []time.Duration{0, 630 * time.Second, 660 * time.Second, 720 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var (
					mu                    sync.Mutex
					starts                []time.Duration
					inFlight, maxInFlight int
				)
				start := time.Now()
				p := newFakeProber(func(ctx context.Context, n int) result.Result {
					mu.Lock()
					starts = append(starts, time.Since(start))
					inFlight++
					maxInFlight = max(maxInFlight, inFlight)
					mu.Unlock()
					defer func() {
						mu.Lock()
						inFlight--
						mu.Unlock()
					}()
					if tt.probeTime != nil {
						if d := tt.probeTime(n); d > 0 {
							select {
							case <-ctx.Done():
							case <-time.After(d):
							}
						}
					}
					return result.Result{Success: true}
				})
				var delayArgs []time.Duration
				rec := &recorder{}
				s := New(rec, Options{InitialDelay: func(iv time.Duration) time.Duration {
					delayArgs = append(delayArgs, iv)
					return tt.initialDelay
				}})
				t.Cleanup(s.Stop)

				s.Apply([]Job{job("a", "1", p)})
				time.Sleep(tt.want[len(tt.want)-1] + time.Second)
				synctest.Wait()

				mu.Lock()
				defer mu.Unlock()
				if !slices.Equal(starts, tt.want) {
					t.Errorf("probes started at %v, want %v", starts, tt.want)
				}
				if maxInFlight != 1 {
					t.Errorf("up to %d probes ran at once, want 1", maxInFlight)
				}
				if !slices.Equal(delayArgs, []time.Duration{interval}) {
					t.Errorf("InitialDelay called with %v, want [%v]", delayArgs, interval)
				}
				results := rec.all()
				if len(results) == 0 {
					t.Error("no result recorded")
				}
				for _, r := range results {
					if r.Target != "a" || !r.Success {
						t.Errorf("recorded target %q success %v, want %q true", r.Target, r.Success, "a")
					}
				}
			})
		})
	}
}

func TestApplyReconciles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger, logs := newLogger()
		s := newScheduler(t, &recorder{}, logger)
		pa, pb, pc := newFakeProber(nil), newFakeProber(nil), newFakeProber(nil)
		s.Apply([]Job{job("a", "a1", pa), job("b", "b1", pb), job("c", "c1", pc)})
		synctest.Wait()

		time.Sleep(30 * time.Second)
		a2 := target("a", "a1")
		pb2, pd := newFakeProber(nil), newFakeProber(nil)
		s.Apply([]Job{{Target: a2}, job("b", "b2", pb2), job("d", "d1", pd)})

		// Apply has stopped and closed the loops of the changed and the removed target.
		probers := map[string]*fakeProber{"a": pa, "b1": pb, "c": pc, "b2": pb2, "d": pd}
		wantCloses := map[string]int64{"a": 0, "b1": 1, "c": 1, "b2": 0, "d": 0}
		for name, p := range probers {
			if got := p.closes.Load(); got != wantCloses[name] {
				t.Errorf("after Apply: prober %s closed %d times, want %d", name, got, wantCloses[name])
			}
		}
		wantFps := map[string]string{"a": "a1", "b": "b2", "d": "d1"}
		if got := s.Fingerprints(); !maps.Equal(got, wantFps) {
			t.Errorf("Fingerprints() = %v, want %v", got, wantFps)
		}
		for name, want := range map[string]*fakeProber{"a": pa, "b": pb2, "d": pd, "c": nil} {
			got, ok := s.Prober(name)
			if want == nil {
				if ok || got != nil {
					t.Errorf("Prober(%q) = %v, %v, want nil, false", name, got, ok)
				}
			} else if !ok || got != Prober(want) {
				t.Errorf("Prober(%q) = %v, %v, want %p, true", name, got, ok, want)
			}
		}
		s.mu.Lock()
		gotTarget := s.loops["a"].target
		s.mu.Unlock()
		if gotTarget != a2 {
			t.Error("the kept loop did not get the new *config.Target")
		}

		// The kept loop stays on its schedule (its second probe is due at 60s); the
		// restarted and the new loop probe at once and then at 90s.
		synctest.Wait()
		calls := func() [5]int64 {
			return [5]int64{pa.calls.Load(), pb.calls.Load(), pc.calls.Load(), pb2.calls.Load(), pd.calls.Load()}
		}
		if got, want := calls(), [5]int64{1, 1, 1, 1, 1}; got != want {
			t.Errorf("at 30s: probes of a, b1, c, b2, d = %v, want %v", got, want)
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if got, want := calls(), [5]int64{2, 1, 1, 1, 1}; got != want {
			t.Errorf("at 60s: probes of a, b1, c, b2, d = %v, want %v", got, want)
		}

		type applied struct {
			Added, Changed, Unchanged, Removed int
		}
		wantApplied := []applied{{Added: 3}, {Added: 1, Changed: 1, Unchanged: 1, Removed: 1}}
		if got := entries[applied](t, logs, withMsg("Applied targets")); !slices.Equal(got, wantApplied) {
			t.Errorf("Applied targets logs = %+v, want %+v", got, wantApplied)
		}

		s.Stop()
		for name, p := range probers {
			if got := p.closes.Load(); got != 1 {
				t.Errorf("after Stop: prober %s closed %d times, want 1", name, got)
			}
		}
	})
}

func TestApplyRejectsInvalidJobs(t *testing.T) {
	tests := []struct {
		name    string
		running func(p []*fakeProber) []Job
		jobs    func(p []*fakeProber) []Job
		want    map[string]string // fingerprints after Apply(jobs)
		closed  []int64           // per prober, after Apply(jobs)
	}{
		{
			name: "no prober for a new target",
			jobs: func([]*fakeProber) []Job { return []Job{job("a", "1", nil)} },
			want: map[string]string{},
		},
		{
			name:    "no prober for a changed target",
			running: func(p []*fakeProber) []Job { return []Job{job("a", "1", p[0])} },
			jobs:    func([]*fakeProber) []Job { return []Job{job("a", "2", nil)} },
			want:    map[string]string{},
			closed:  []int64{1},
		},
		{
			name: "duplicate target",
			jobs: func(p []*fakeProber) []Job {
				return []Job{job("a", "1", p[0]), job("a", "2", p[1])}
			},
			want:   map[string]string{"a": "1"},
			closed: []int64{0, 1},
		},
		{
			name: "zero interval",
			jobs: func(p []*fakeProber) []Job {
				return []Job{{Target: &config.Target{Name: "a", Fingerprint: "1"}, Prober: p[0]}}
			},
			want:   map[string]string{},
			closed: []int64{1},
		},
		{
			name:   "no target",
			jobs:   func(p []*fakeProber) []Job { return []Job{{Prober: p[0]}} },
			want:   map[string]string{},
			closed: []int64{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logger, logs := newLogger()
				s := newScheduler(t, &recorder{}, logger)
				p := []*fakeProber{newFakeProber(nil), newFakeProber(nil)}
				if tt.running != nil {
					s.Apply(tt.running(p))
				}
				s.Apply(tt.jobs(p))
				synctest.Wait()

				if got := s.Fingerprints(); !maps.Equal(got, tt.want) {
					t.Errorf("Fingerprints() = %v, want %v", got, tt.want)
				}
				for i := range p {
					var want int64
					if i < len(tt.closed) {
						want = tt.closed[i]
					}
					if got := p[i].closes.Load(); got != want {
						t.Errorf("prober %d closed %d times, want %d", i, got, want)
					}
				}
				if got := entries[logEntry](t, logs, withMsg("Not probing target")); len(got) != 1 || got[0].Level != "ERROR" || got[0].Err == "" {
					t.Errorf("logged %+v, want one error", got)
				}

				s.Stop()
				for i := range p {
					if got := p[i].closes.Load(); got > 1 {
						t.Errorf("prober %d closed %d times", i, got)
					}
				}
			})
		})
	}
}

// blockingProber returns a prober whose first probe closes started and blocks until its
// context is cancelled; it stores the context error in ctxErr.
func blockingProber(started chan<- struct{}, ctxErr *error) *fakeProber {
	return newFakeProber(func(ctx context.Context, n int) result.Result {
		if n == 1 {
			close(started)
		}
		<-ctx.Done()
		*ctxErr = ctx.Err()
		return result.Result{Reason: result.ReasonTimeout, Message: ctx.Err().Error()}
	})
}

func TestApplyCancelsInFlightProbeOfChangedTarget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := &recorder{}
		s := newScheduler(t, rec, nil)
		started := make(chan struct{})
		var ctxErr error
		old := blockingProber(started, &ctxErr)
		s.Apply([]Job{job("a", "1", old)})
		<-started

		var overlapped atomic.Bool
		replacement := newFakeProber(func(context.Context, int) result.Result {
			overlapped.Store(old.closes.Load() == 0)
			return result.Result{Success: true, Message: "new"}
		})
		s.Apply([]Job{job("a", "2", replacement)})
		synctest.Wait()

		if !errors.Is(ctxErr, context.Canceled) {
			t.Errorf("old probe's context error = %v, want %v", ctxErr, context.Canceled)
		}
		if got := old.closes.Load(); got != 1 {
			t.Errorf("old prober closed %d times, want 1", got)
		}
		if got := replacement.calls.Load(); got != 1 {
			t.Errorf("new prober probed %d times, want 1", got)
		}
		if overlapped.Load() {
			t.Error("the new loop probed before the old prober was closed")
		}
		// The cancelled probe's result is dropped; only the new loop's result is recorded.
		if got := rec.all(); len(got) != 1 || got[0].Message != "new" {
			t.Errorf("recorded %+v, want only the new prober's result", got)
		}
	})
}

func TestStopCancelsInFlightProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := &recorder{}
		s := newScheduler(t, rec, nil)
		started := make(chan struct{})
		var ctxErr error
		p := blockingProber(started, &ctxErr)
		start := time.Now()
		s.Apply([]Job{job("a", "1", p)})
		<-started
		s.Stop()

		if elapsed := time.Since(start); elapsed != 0 {
			t.Errorf("Stop took %v, want it to cancel the probe at once", elapsed)
		}
		if !errors.Is(ctxErr, context.Canceled) {
			t.Errorf("probe's context error = %v, want %v", ctxErr, context.Canceled)
		}
		if got := p.closes.Load(); got != 1 {
			t.Errorf("prober closed %d times, want 1", got)
		}
		if got := rec.all(); len(got) != 0 {
			t.Errorf("recorded %+v, want the cancelled probe's result dropped", got)
		}
		if got := s.Fingerprints(); len(got) != 0 {
			t.Errorf("Fingerprints() after Stop = %v, want none", got)
		}
		if _, ok := s.Prober("a"); ok {
			t.Error("Prober(\"a\") found a prober after Stop")
		}

		s.Stop()
		if got := p.closes.Load(); got != 1 {
			t.Errorf("after a second Stop: prober closed %d times, want 1", got)
		}
	})
}

func TestInitialDelayIsCancelled(t *testing.T) {
	tests := []struct {
		name string
		stop func(s *Scheduler)
	}{
		{name: "stop", stop: (*Scheduler).Stop},
		{name: "change", stop: func(s *Scheduler) { s.Apply([]Job{job("a", "2", newFakeProber(nil))}) }},
		{name: "remove", stop: func(s *Scheduler) { s.Apply(nil) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rec := &recorder{}
				s := New(rec, Options{InitialDelay: func(time.Duration) time.Duration { return 30 * time.Second }})
				t.Cleanup(s.Stop)
				p := newFakeProber(nil)
				start := time.Now()
				s.Apply([]Job{job("a", "1", p)})
				tt.stop(s)

				if elapsed := time.Since(start); elapsed != 0 {
					t.Errorf("stopping the loop took %v, want it to cancel the initial delay at once", elapsed)
				}
				if got := p.calls.Load(); got != 0 {
					t.Errorf("prober probed %d times, want 0", got)
				}
				if got := p.closes.Load(); got != 1 {
					t.Errorf("prober closed %d times, want 1", got)
				}
				if got := rec.all(); len(got) != 0 {
					t.Errorf("recorded %+v, want nothing", got)
				}
			})
		})
	}
}

func TestApplyAfterStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newScheduler(t, &recorder{}, nil)
		s.Apply(nil)
		s.Stop()
		p := newFakeProber(nil)
		s.Apply([]Job{job("a", "1", p)})
		synctest.Wait()

		if got := p.calls.Load(); got != 0 {
			t.Errorf("prober probed %d times after Stop, want 0", got)
		}
		if got := p.closes.Load(); got != 1 {
			t.Errorf("prober closed %d times, want 1", got)
		}
		if _, ok := s.Prober("a"); ok {
			t.Error("Prober(\"a\") found a prober applied after Stop")
		}
	})
}

func TestPanicIsRecordedAsInternal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger, logs := newLogger()
		rec := &recorder{}
		s := newScheduler(t, rec, logger)
		p := newFakeProber(func(_ context.Context, n int) result.Result {
			if n == 1 {
				time.Sleep(2 * time.Second)
				panic("boom")
			}
			return result.Result{Success: true}
		})
		start := time.Now()
		s.Apply([]Job{job("a", "1", p)})
		time.Sleep(interval)
		synctest.Wait()

		got := rec.all()
		if len(got) != 2 {
			t.Fatalf("recorded %d results, want 2", len(got))
		}
		r := got[0]
		if r.Target != "a" || r.Success || r.Reason != result.ReasonInternal || r.Message != "panic: boom" {
			t.Errorf("panic recorded as target %q success %v reason %q message %q, want %q false %q %q",
				r.Target, r.Success, r.Reason, r.Message, "a", result.ReasonInternal, "panic: boom")
		}
		if !r.Start.Equal(start) || !r.End.Equal(start.Add(2*time.Second)) {
			t.Errorf("panic recorded from %v to %v, want %v to %v", r.Start, r.End, start, start.Add(2*time.Second))
		}
		if !got[1].Success {
			t.Errorf("probe after the panic: %+v, want success", got[1])
		}
		type panicEntry struct {
			Level, Target, Panic, Stack string
		}
		panics := entries[panicEntry](t, logs, withMsg("Probe panicked"))
		if len(panics) != 1 || panics[0].Level != "ERROR" || panics[0].Target != "a" ||
			panics[0].Panic != "boom" || panics[0].Stack == "" {
			t.Errorf("panic logged as %+v, want one error with the panic and a stack", panics)
		}
	})
}

func TestPanicLogging(t *testing.T) {
	tests := []struct {
		name     string
		outcomes string   // one per probe: p panics, f fails, s succeeds
		want     []string // levels of the "Probe panicked" records; only errors carry the stack
		downs    int      // "Target is down" records
	}{
		{
			name:     "repeated panics",
			outcomes: "pppppppppp",
			want:     []string{"ERROR", "DEBUG", "DEBUG", "DEBUG", "DEBUG", "DEBUG", "DEBUG", "DEBUG", "DEBUG", "DEBUG"},
			downs:    1,
		},
		{
			name:     "streak ended by a success",
			outcomes: "ppspp",
			want:     []string{"ERROR", "DEBUG", "ERROR", "DEBUG"},
			downs:    2,
		},
		{
			name:     "streak ended by a failure",
			outcomes: "pfp",
			want:     []string{"ERROR", "ERROR"},
			downs:    1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logger, logs := newLogger()
				rec := &recorder{}
				s := newScheduler(t, rec, logger)
				p := newFakeProber(func(ctx context.Context, n int) result.Result {
					if n > len(tt.outcomes) {
						<-ctx.Done()
						return result.Result{Reason: result.ReasonTimeout}
					}
					switch tt.outcomes[n-1] {
					case 'p':
						panic(fmt.Sprintf("boom %d", n))
					case 'f':
						return result.Result{Reason: result.ReasonStatus}
					}
					return result.Result{Success: true}
				})
				s.Apply([]Job{job("a", "1", p)})
				time.Sleep(time.Duration(len(tt.outcomes)) * interval)
				synctest.Wait()
				if got := len(rec.all()); got != len(tt.outcomes) {
					t.Fatalf("recorded %d results, want %d", got, len(tt.outcomes))
				}
				s.Stop()

				type panicEntry struct {
					Level, Target, Panic, Stack string
				}
				panics := entries[panicEntry](t, logs, withMsg("Probe panicked"))
				var levels []string
				for _, e := range panics {
					levels = append(levels, e.Level)
					if e.Target != "a" || e.Panic == "" || (e.Stack != "") != (e.Level == "ERROR") {
						t.Errorf("panic logged as %+v, want target, panic value, and a stack only at error level", e)
					}
				}
				if !slices.Equal(levels, tt.want) {
					t.Errorf("panics logged at %v, want %v", levels, tt.want)
				}
				if got := len(entries[logEntry](t, logs, withMsg("Target is down"))); got != tt.downs {
					t.Errorf("logged %d down transitions, want %d", got, tt.downs)
				}
			})
		})
	}
}

func TestTransitionLogging(t *testing.T) {
	ok := result.Result{Success: true}
	fail := func(reason result.Reason, msg string) result.Result {
		return result.Result{Reason: reason, Message: msg}
	}
	down := func(reason result.Reason, msg string) logEntry {
		return logEntry{Level: "WARN", Msg: "Target is down", Target: "a", Reason: string(reason), Message: msg}
	}
	up := logEntry{Level: "INFO", Msg: "Target is up again", Target: "a"}

	tests := []struct {
		name    string
		results []result.Result
		want    []logEntry
	}{
		{
			name:    "first success is not logged",
			results: []result.Result{ok, ok},
		},
		{
			name:    "first failure",
			results: []result.Result{fail(result.ReasonTimeout, "deadline exceeded")},
			want:    []logEntry{down(result.ReasonTimeout, "deadline exceeded")},
		},
		{
			name: "repeated failures are logged once",
			results: []result.Result{
				fail(result.ReasonConnect, "refused"), fail(result.ReasonConnect, "refused"),
				fail(result.ReasonDNS, "no such host"),
			},
			want: []logEntry{down(result.ReasonConnect, "refused")},
		},
		{
			name:    "recovery",
			results: []result.Result{fail(result.ReasonStatus, "got 502, want [200]"), ok, ok},
			want:    []logEntry{down(result.ReasonStatus, "got 502, want [200]"), up},
		},
		{
			name: "flapping",
			results: []result.Result{
				ok, fail(result.ReasonSOAPFault, "soap:Server"), ok, ok,
				fail(result.ReasonXPath, "no match"), fail(result.ReasonXPath, "no match"),
			},
			want: []logEntry{down(result.ReasonSOAPFault, "soap:Server"), up, down(result.ReasonXPath, "no match")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logger, logs := newLogger()
				rec := &recorder{}
				s := newScheduler(t, rec, logger)
				p := newFakeProber(func(ctx context.Context, n int) result.Result {
					if n <= len(tt.results) {
						return tt.results[n-1]
					}
					<-ctx.Done()
					return fail(result.ReasonTimeout, "cancelled")
				})
				s.Apply([]Job{job("a", "1", p)})
				time.Sleep(time.Duration(len(tt.results)) * interval)
				synctest.Wait()
				if got := len(rec.all()); got != len(tt.results) {
					t.Fatalf("recorded %d results, want %d", got, len(tt.results))
				}
				s.Stop()

				transitions := entries[logEntry](t, logs, func(a map[string]any) bool {
					return a["level"] != "DEBUG" && a["msg"] != "Applied targets"
				})
				if !slices.Equal(transitions, tt.want) {
					t.Errorf("logged %+v, want %+v", transitions, tt.want)
				}
				if got := entries[logEntry](t, logs, withMsg("Probe finished")); len(got) != len(tt.results) {
					t.Errorf("logged %d probes, want %d", len(got), len(tt.results))
				} else if got[0].Level != "DEBUG" {
					t.Errorf("probe logged at %s, want DEBUG", got[0].Level)
				}
			})
		})
	}
}

func TestRunning(t *testing.T) {
	tests := []struct {
		name string
		ops  string // a: Apply, s: Stop
		want bool
	}{
		{name: "new", ops: "", want: false},
		{name: "applied", ops: "a", want: true},
		{name: "applied twice", ops: "aa", want: true},
		{name: "stopped", ops: "as", want: false},
		{name: "stopped twice", ops: "ass", want: false},
		{name: "stopped before apply", ops: "s", want: false},
		{name: "applied after stop", ops: "asa", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newScheduler(t, &recorder{}, nil)
				for _, op := range tt.ops {
					switch op {
					case 'a':
						s.Apply([]Job{job("a", "1", newFakeProber(nil))})
					case 's':
						s.Stop()
					}
				}
				if got := s.Running(); got != tt.want {
					t.Errorf("Running() = %v, want %v", got, tt.want)
				}
			})
		})
	}
}

// TestConcurrentUse runs in real time to let the race detector see Apply, Stop and the
// readers interleave with running loops.
func TestConcurrentUse(t *testing.T) {
	s := New(&recorder{}, Options{InitialDelay: func(time.Duration) time.Duration { return 0 }})
	var (
		mu      sync.Mutex
		probers []*fakeProber
	)
	jobs := func(round int) []Job {
		fps := s.Fingerprints()
		var out []Job
		for _, name := range []string{"a", "b", "c"} {
			if fp, ok := fps[name]; ok && round%2 == 0 {
				out = append(out, Job{Target: &config.Target{
					Name: name, Fingerprint: fp, Interval: model.Duration(time.Millisecond),
				}})
				continue
			}
			p := newFakeProber(nil)
			mu.Lock()
			probers = append(probers, p)
			mu.Unlock()
			out = append(out, Job{
				Target: &config.Target{
					Name: name, Fingerprint: fmt.Sprint(round % 3), Interval: model.Duration(time.Millisecond),
				},
				Prober: p,
			})
		}
		return out
	}

	done := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				for name := range s.Fingerprints() {
					s.Prober(name)
				}
				s.Running()
				// Without yielding, the readers starve the appliers when GOMAXPROCS is 1.
				runtime.Gosched()
			}
		})
	}
	var appliers sync.WaitGroup
	for i := range 4 {
		appliers.Go(func() {
			for round := range 25 {
				s.Apply(jobs(i*100 + round))
				if i == 0 && round == 20 {
					s.Stop()
				}
			}
		})
	}
	appliers.Wait()
	s.Stop()
	close(done)
	readers.Wait()

	if s.Running() {
		t.Error("Running() after Stop")
	}
	for i, p := range probers {
		if got := p.closes.Load(); got != 1 {
			t.Errorf("prober %d closed %d times, want 1", i, got)
		}
	}
}
