// Package state keeps per-target probe state: the last result, counters, the duration
// histogram and a history ring buffer (plan D7, §7).
package state

import (
	"maps"
	"slices"
	"sort"
	"sync"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
)

// DurationBuckets are the buckets of soap_probe_duration_seconds (plan §7).
var DurationBuckets = []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

// Histogram is a snapshot of the duration histogram in the shape
// prometheus.NewConstHistogram expects.
type Histogram struct {
	Count uint64
	Sum   float64
	// Buckets maps each upper bound of DurationBuckets to its cumulative count.
	Buckets map[float64]uint64
}

// TargetState is a consistent copy of one target's state.
type TargetState struct {
	Target *config.Target
	// Last is the last recorded result, nil before the first probe.
	Last *result.Result
	// Results counts probes by the `result` label of soap_probes_total:
	// result.ResultSuccess or a failure reason.
	Results map[string]uint64
	// Histogram observes the duration of probes with GotResponse.
	Histogram Histogram
}

// Store is safe for concurrent use.
type Store struct {
	historyLimit  int
	captureBodies bool
	// bounds is a private copy of DurationBuckets, fixed at New.
	bounds []float64

	mu      sync.RWMutex
	targets []*targetState // config order
	byName  map[string]*targetState
}

// targetState is the mutable state of one target. Stored results are private copies that
// are never modified after insertion, so readers may clone them outside the lock.
type targetState struct {
	target  *config.Target
	last    *result.Result
	results map[string]uint64
	// buckets holds non-cumulative counts per bound; observations above the last bound
	// only count towards count.
	buckets []uint64
	count   uint64
	sum     float64
	// history is a ring buffer of at most historyLimit results; next is the slot the next
	// result is written to once the buffer is full.
	history []result.Result
	next    int
}

// New returns an empty store. historyLimit is the number of results kept per target
// (--history.limit). Unless captureBodies (--debug.capture-bodies), Body is cleared in the
// stored history (Last keeps it neither).
func New(historyLimit int, captureBodies bool) *Store {
	return &Store{
		historyLimit:  max(historyLimit, 0),
		captureBodies: captureBodies,
		bounds:        slices.Clone(DurationBuckets),
		byName:        map[string]*targetState{},
	}
}

// SetTargets reconciles the store with a new configuration: targets with an unchanged name
// and fingerprint keep their state (and get the new *config.Target pointer), changed
// targets start from zero, removed targets disappear. Snapshot follows the order of
// targets.
func (s *Store) SetTargets(targets []*config.Target) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ordered := make([]*targetState, 0, len(targets))
	byName := make(map[string]*targetState, len(targets))
	for _, t := range targets {
		if t == nil {
			continue
		}
		if _, dup := byName[t.Name]; dup {
			// Names are unique after config validation; keep the first one.
			continue
		}
		ts, ok := s.byName[t.Name]
		if ok && ts.target.Fingerprint == t.Fingerprint {
			ts.target = t
		} else {
			ts = s.newTargetState(t)
		}
		ordered = append(ordered, ts)
		byName[t.Name] = ts
	}
	s.targets, s.byName = ordered, byName
}

func (s *Store) newTargetState(t *config.Target) *targetState {
	return &targetState{
		target:  t,
		results: map[string]uint64{},
		buckets: make([]uint64, len(s.bounds)),
	}
}

// Record stores a scheduled probe result. Results for unknown targets are dropped.
func (s *Store) Record(r result.Result) {
	// Copy outside the lock so the caller may keep using its maps and slices.
	r = cloneResult(r)
	if !s.captureBodies {
		r.Body, r.BodyTruncated = "", false
	}
	label := resultLabel(&r)

	s.mu.Lock()
	defer s.mu.Unlock()

	ts, ok := s.byName[r.Target]
	if !ok {
		return
	}
	ts.last = &r
	ts.results[label]++
	if r.GotResponse {
		ts.observe(r.Duration().Seconds(), s.bounds)
	}
	ts.push(r, s.historyLimit)
}

// resultLabel returns the soap_probes_total `result` label value of r. A failed result
// without a reason is a prober bug; it is counted as internal rather than with an empty
// label value.
func resultLabel(r *result.Result) string {
	switch {
	case r.Success:
		return result.ResultSuccess
	case r.Reason == result.ReasonNone:
		return string(result.ReasonInternal)
	}
	return string(r.Reason)
}

func (ts *targetState) observe(v float64, bounds []float64) {
	ts.count++
	ts.sum += v
	// Bucket upper bounds are inclusive (le).
	if i := sort.SearchFloat64s(bounds, v); i < len(bounds) {
		ts.buckets[i]++
	}
}

func (ts *targetState) push(r result.Result, limit int) {
	switch {
	case limit == 0:
	case len(ts.history) < limit:
		ts.history = append(ts.history, r)
	default:
		ts.history[ts.next] = r
		ts.next = (ts.next + 1) % limit
	}
}

// newestFirst returns the history (sharing the stored results) from newest to oldest.
func (ts *targetState) newestFirst() []result.Result {
	n := len(ts.history)
	out := make([]result.Result, 0, n)
	// Before the buffer is full next is 0, so the newest entry is the last one appended.
	for i := 1; i <= n; i++ {
		out = append(out, ts.history[(ts.next-i+n)%n])
	}
	return out
}

// Snapshot returns a consistent copy of all target states, in config order.
func (s *Store) Snapshot() []TargetState {
	s.mu.RLock()
	out := make([]TargetState, len(s.targets))
	for i, ts := range s.targets {
		h := Histogram{
			Count:   ts.count,
			Sum:     ts.sum,
			Buckets: make(map[float64]uint64, len(s.bounds)),
		}
		var cumulative uint64
		for j, bound := range s.bounds {
			cumulative += ts.buckets[j]
			h.Buckets[bound] = cumulative
		}
		out[i] = TargetState{
			Target:    ts.target,
			Last:      ts.last, // replaced by a deep copy below
			Results:   maps.Clone(ts.results),
			Histogram: h,
		}
	}
	s.mu.RUnlock()

	for i := range out {
		if last := out[i].Last; last != nil {
			c := cloneResult(*last)
			out[i].Last = &c
		}
	}
	return out
}

// HistoryLimit returns the number of results kept per target; 0 means History is always
// empty (--history.limit=0).
func (s *Store) HistoryLimit() int {
	return s.historyLimit
}

// History returns the recorded results of one target, newest first. ok is false for an
// unknown target.
func (s *Store) History(target string) (results []result.Result, ok bool) {
	s.mu.RLock()
	ts, ok := s.byName[target]
	if ok {
		results = ts.newestFirst()
	}
	s.mu.RUnlock()

	if !ok {
		return nil, false
	}
	for i := range results {
		results[i] = cloneResult(results[i])
	}
	return results, true
}

// cloneResult returns a deep copy of r.
func cloneResult(r result.Result) result.Result {
	r.Phases = maps.Clone(r.Phases)
	r.ResponseHeader = r.ResponseHeader.Clone()
	r.Checks = slices.Clone(r.Checks)
	if r.TLS != nil {
		t := *r.TLS
		t.Chain = slices.Clone(t.Chain)
		for i := range t.Chain {
			t.Chain[i].DNSNames = slices.Clone(t.Chain[i].DNSNames)
		}
		r.TLS = &t
	}
	return r
}
