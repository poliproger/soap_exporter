package scheduler

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
)

// loop is the probe loop of one target. Apply swaps target for an unchanged target, guarded
// by Scheduler.mu; the goroutine never reads it. panicking belongs to the goroutine.
type loop struct {
	name     string
	interval time.Duration
	prober   Prober
	target   *config.Target

	panicking bool // the last probe panicked

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{} // closed when the goroutine has returned
}

func newLoop(parent context.Context, j Job) *loop {
	ctx, cancel := context.WithCancel(parent)
	return &loop{
		name:     j.Target.Name,
		interval: time.Duration(j.Target.Interval),
		prober:   j.Prober,
		target:   j.Target,
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
}

// health is the last known state of a target, for transition logging.
type health int

const (
	healthUnknown health = iota
	healthUp
	healthDown
)

// run is the goroutine of l: the first probe after delay, then one per tick. The ticker
// starts with the first probe, so probes start at a fixed rate; a probe that takes longer
// than the interval makes the ticker drop the ticks it missed.
func (s *Scheduler) run(l *loop, delay time.Duration) {
	defer close(l.done)
	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-l.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	h := s.probe(l, healthUnknown)
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			h = s.probe(l, h)
		}
	}
}

// probe runs one probe, records its result and logs a transition from prev. The result of
// a probe aborted because its loop was stopped is dropped: it says nothing about the target.
func (s *Scheduler) probe(l *loop, prev health) health {
	if l.ctx.Err() != nil {
		return prev
	}
	r := s.safeProbe(l)
	if l.ctx.Err() != nil {
		s.logger.Debug("Dropped result of a cancelled probe", "target", l.name)
		return prev
	}
	r.Target = l.name
	s.rec.Record(r)
	s.logger.Debug("Probe finished", "target", l.name, "success", r.Success,
		"reason", string(r.Reason), "duration", r.Duration())

	if r.Success {
		if prev == healthDown {
			s.logger.Info("Target is up again", "target", l.name)
		}
		return healthUp
	}
	if prev != healthDown {
		s.logger.Warn("Target is down", "target", l.name, "reason", string(r.Reason),
			"message", r.Message)
	}
	return healthDown
}

// safeProbe calls the prober and turns a panic into a failed result. Only the first of
// consecutive panics is logged at error level with the stack (D11); the rest go to debug.
func (s *Scheduler) safeProbe(l *loop) (r result.Result) {
	start := time.Now()
	defer func() {
		v := recover()
		if v == nil {
			l.panicking = false
			return
		}
		if l.panicking {
			s.logger.Debug("Probe panicked", "target", l.name, "panic", v)
		} else {
			s.logger.Error("Probe panicked", "target", l.name, "panic", v,
				"stack", string(debug.Stack()))
		}
		l.panicking = true
		r = result.Result{
			Target:  l.name,
			Start:   start,
			End:     time.Now(),
			Reason:  result.ReasonInternal,
			Message: fmt.Sprintf("panic: %v", v),
		}
	}()
	return l.prober.Probe(l.ctx)
}
