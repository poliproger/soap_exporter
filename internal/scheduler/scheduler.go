// Package scheduler runs one probe loop per target (plan §9 phase 5, D1, D11).
package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
)

// maxInitialDelay caps the default initial delay, so that targets with long intervals are
// probed soon after a start or reload.
const maxInitialDelay = 10 * time.Second

// Prober probes one target; *prober.Prober implements it.
type Prober interface {
	Probe(ctx context.Context) result.Result
	Close()
}

// Recorder receives scheduled results; *state.Store implements it.
type Recorder interface {
	Record(r result.Result)
}

// Job is one target with its prober.
type Job struct {
	Target *config.Target
	// Prober may be nil only for a target whose name and fingerprint match a running loop
	// (see Scheduler.Fingerprints); that loop then keeps running unchanged.
	Prober Prober
}

// Options configure a Scheduler.
type Options struct {
	Logger *slog.Logger
	// InitialDelay returns the delay before the first probe of a target; the default is a
	// random delay in [0, min(interval, 10s)). Tests override it.
	InitialDelay func(interval time.Duration) time.Duration
	// Reconcile, if set, is called by Apply after obsolete loops have finished and before new
	// loops start, with the targets of the accepted jobs in job order. The app passes
	// state.Store.SetTargets: a result of an old loop then never lands in a reset state, and a
	// result of a new loop never arrives before the store knows its target.
	Reconcile func(targets []*config.Target)
}

// Scheduler is safe for concurrent use.
type Scheduler struct {
	rec          Recorder
	logger       *slog.Logger
	initialDelay func(time.Duration) time.Duration
	reconcile    func([]*config.Target)

	// ctx is the parent of every loop context. Stop cancels it before it waits for a
	// concurrent Apply, so that in-flight probes are aborted right away.
	ctx    context.Context
	cancel context.CancelFunc

	// applyMu serializes Apply and Stop; mu is held only briefly, so that the readers do
	// not wait while loops are being stopped.
	applyMu sync.Mutex
	mu      sync.Mutex
	loops   map[string]*loop
	applied bool
	stopped bool
}

// New returns a scheduler without targets.
func New(rec Recorder, opts Options) *Scheduler {
	s := &Scheduler{
		rec:          rec,
		logger:       opts.Logger,
		initialDelay: opts.InitialDelay,
		reconcile:    opts.Reconcile,
	}
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}
	if s.initialDelay == nil {
		s.initialDelay = defaultInitialDelay
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s
}

// defaultInitialDelay spreads the first probes of all targets over up to 10 seconds.
func defaultInitialDelay(interval time.Duration) time.Duration {
	limit := min(interval, maxInitialDelay)
	if limit <= 0 {
		return 0
	}
	return rand.N(limit)
}

// Fingerprints returns the fingerprint of every running loop by target name.
func (s *Scheduler) Fingerprints() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	fps := make(map[string]string, len(s.loops))
	for name, l := range s.loops {
		fps[name] = l.target.Fingerprint
	}
	return fps
}

// Apply reconciles the running loops with jobs: a job with a nil Prober keeps its running
// loop (it gets the new *config.Target pointer); every other job starts a new loop, after
// stopping and closing a running loop of the same name; loops of targets not in jobs are
// stopped and their probers closed. Each loop probes after the initial delay, then on a
// time.Ticker of the target's interval: missed ticks are dropped and probes of one target
// never overlap. A panic in Probe is recovered and recorded as reason "internal". Up↔down
// transitions are logged (warn when a target goes down, info when it recovers); single
// probes are logged at debug level only.
func (s *Scheduler) Apply(jobs []Job) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		s.logger.Warn("Scheduler is stopped, ignoring targets", "targets", len(jobs))
		for _, j := range jobs {
			if j.Prober != nil {
				j.Prober.Close()
			}
		}
		return
	}
	s.applied = true
	old := s.loops
	next := make(map[string]*loop, len(jobs))
	var started, stopped []*loop
	var accepted []*config.Target
	var added, changed, unchanged int
	for _, j := range jobs {
		var cur *loop
		if j.Target != nil {
			cur = old[j.Target.Name]
		}
		if err := checkJob(j, cur, next); err != nil {
			name := ""
			if j.Target != nil {
				name = j.Target.Name
			}
			// Unless an earlier job of this name was accepted, its running loop is stopped
			// below.
			s.logger.Error("Not probing target", "target", name, "err", err)
			if j.Prober != nil {
				j.Prober.Close()
			}
			continue
		}
		name := j.Target.Name
		accepted = append(accepted, j.Target)
		switch {
		case j.Prober == nil:
			cur.target = j.Target
			next[name] = cur
			unchanged++
			continue
		case cur != nil:
			changed++
		default:
			added++
		}
		l := newLoop(s.ctx, j)
		next[name] = l
		started = append(started, l)
	}
	for name, l := range old {
		if next[name] != l {
			stopped = append(stopped, l)
		}
	}
	s.loops = next
	s.mu.Unlock()

	// A changed target's old loop has finished before its new loop starts, so the two never
	// probe at the same time.
	s.stopLoops(stopped)
	if s.reconcile != nil {
		s.reconcile(accepted)
	}
	for _, l := range started {
		delay := max(s.initialDelay(l.interval), 0)
		s.logger.Debug("Starting probe loop", "target", l.name, "interval", l.interval,
			"initial_delay", delay)
		go s.run(l, delay)
	}
	s.logger.Info("Applied targets", "added", added, "changed", changed,
		"unchanged", unchanged, "removed", len(stopped)-changed)
}

// checkJob reports why a job cannot be scheduled. cur is the running loop of the job's
// target, accepted holds the jobs accepted so far.
func checkJob(j Job, cur *loop, accepted map[string]*loop) error {
	switch {
	case j.Target == nil:
		return errors.New("job without a target")
	case accepted[j.Target.Name] != nil:
		return errors.New("duplicate target name")
	case j.Prober == nil && (cur == nil || cur.target.Fingerprint != j.Target.Fingerprint):
		return errors.New("no prober for a new or changed target")
	case j.Prober != nil && j.Target.Interval <= 0:
		return errors.New("interval must be positive")
	}
	return nil
}

// Prober returns the running prober of a target (for on-demand debug probes).
func (s *Scheduler) Prober(target string) (Prober, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.loops[target]
	if !ok {
		return nil, false
	}
	return l.prober, true
}

// Running reports whether Apply has been called and Stop has not.
func (s *Scheduler) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied && !s.stopped
}

// Stop cancels all loops and in-flight probes, waits for them, and closes the probers.
func (s *Scheduler) Stop() {
	s.cancel()
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	s.mu.Lock()
	loops := make([]*loop, 0, len(s.loops))
	for _, l := range s.loops {
		loops = append(loops, l)
	}
	s.loops = nil
	s.stopped = true
	s.mu.Unlock()

	s.stopLoops(loops)
}

// stopLoops cancels the loops, waits for them to finish and closes their probers.
func (s *Scheduler) stopLoops(loops []*loop) {
	for _, l := range loops {
		l.cancel()
	}
	for _, l := range loops {
		<-l.done
		l.prober.Close()
		s.logger.Debug("Stopped probe loop", "target", l.name)
	}
}
