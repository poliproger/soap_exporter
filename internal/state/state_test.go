package state

import (
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func newTarget(name, fingerprint string) *config.Target {
	return &config.Target{Name: name, Fingerprint: fingerprint}
}

func newStore(historyLimit int, captureBodies bool, targets ...*config.Target) *Store {
	s := New(historyLimit, captureBodies)
	s.SetTargets(targets)
	return s
}

// probe returns the n-th result of target: a success with a response that took
// n*100ms. Message identifies it.
func probe(target string, n int) result.Result {
	start := t0.Add(time.Duration(n) * time.Minute)
	return result.Result{
		Target:      target,
		Start:       start,
		End:         start.Add(time.Duration(n) * 100 * time.Millisecond),
		Success:     true,
		GotResponse: true,
		HTTPStatus:  http.StatusOK,
		Message:     fmt.Sprintf("probe %d", n),
	}
}

func failure(target string, reason result.Reason, gotResponse bool) result.Result {
	r := probe(target, 1)
	r.Success, r.Reason, r.GotResponse = false, reason, gotResponse
	return r
}

func messages(results []result.Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.Message
	}
	return out
}

func names(snap []TargetState) []string {
	out := make([]string, len(snap))
	for i, ts := range snap {
		out[i] = ts.Target.Name
	}
	return out
}

func TestRecordCountsByResult(t *testing.T) {
	s := newStore(10, false, newTarget("a", "1"))
	s.Record(probe("a", 1))
	s.Record(probe("a", 2))
	s.Record(failure("a", result.ReasonDNS, false))
	s.Record(failure("a", result.ReasonSOAPFault, true))
	s.Record(failure("a", result.ReasonNone, false)) // a prober bug, counted as internal

	ts := s.Snapshot()[0]
	want := map[string]uint64{"success": 2, "dns": 1, "soap_fault": 1, "internal": 1}
	if !maps.Equal(ts.Results, want) {
		t.Errorf("Results = %v, want %v", ts.Results, want)
	}
	if ts.Last == nil || ts.Last.Reason != result.ReasonNone || ts.Last.Success {
		t.Errorf("Last = %+v, want the last recorded failure", ts.Last)
	}
}

func TestHistogram(t *testing.T) {
	ms := time.Millisecond
	tests := []struct {
		name      string
		durations []time.Duration
		noResp    int // additional failures without a response
		wantCount uint64
		wantSum   float64
		// wantLE maps a bucket bound to its expected cumulative count; unlisted bounds
		// must equal the count of the next listed smaller bound.
		wantLE map[float64]uint64
	}{
		{
			name:   "empty",
			wantLE: map[float64]uint64{.01: 0, 60: 0},
		},
		{
			name:      "bounds are inclusive",
			durations: []time.Duration{10 * ms, 25 * ms},
			wantCount: 2,
			wantSum:   .035,
			wantLE:    map[float64]uint64{.01: 1, .025: 2, 60: 2},
		},
		{
			name:      "spread",
			durations: []time.Duration{5 * ms, 300 * ms, 2500 * ms, 45 * time.Second},
			wantCount: 4,
			wantSum:   47.805,
			wantLE:    map[float64]uint64{.01: 1, .25: 1, .5: 2, 2.5: 3, 30: 3, 60: 4},
		},
		{
			name:      "above the last bound counts only towards count",
			durations: []time.Duration{90 * time.Second},
			wantCount: 1,
			wantSum:   90,
			wantLE:    map[float64]uint64{60: 0},
		},
		{
			name:      "probes without a response are not observed",
			durations: []time.Duration{100 * ms},
			noResp:    3,
			wantCount: 1,
			wantSum:   .1,
			wantLE:    map[float64]uint64{.05: 0, .1: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(10, false, newTarget("a", "1"))
			for _, d := range tt.durations {
				r := probe("a", 1)
				r.End = r.Start.Add(d)
				s.Record(r)
			}
			for range tt.noResp {
				s.Record(failure("a", result.ReasonTimeout, false))
			}

			h := s.Snapshot()[0].Histogram
			if h.Count != tt.wantCount {
				t.Errorf("Count = %d, want %d", h.Count, tt.wantCount)
			}
			if diff := h.Sum - tt.wantSum; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("Sum = %g, want %g", h.Sum, tt.wantSum)
			}
			if got := slices.Sorted(maps.Keys(h.Buckets)); !slices.Equal(got, DurationBuckets) {
				t.Fatalf("bucket bounds = %v, want %v", got, DurationBuckets)
			}
			var want uint64
			for _, bound := range DurationBuckets {
				if v, ok := tt.wantLE[bound]; ok {
					want = v
				}
				if got := h.Buckets[bound]; got != want {
					t.Errorf("bucket le=%g = %d, want %d", bound, got, want)
				}
			}
		})
	}
}

func TestSetTargets(t *testing.T) {
	tests := []struct {
		name string
		next []*config.Target
		// wantProbes is the expected number of recorded probes per target, in snapshot
		// order; 0 means fresh state.
		wantOrder  []string
		wantProbes []int
		wantGone   []string
	}{
		{
			name:       "unchanged targets keep their state",
			next:       []*config.Target{newTarget("a", "a1"), newTarget("b", "b1")},
			wantOrder:  []string{"a", "b"},
			wantProbes: []int{2, 3},
		},
		{
			name:       "a changed fingerprint resets the state",
			next:       []*config.Target{newTarget("a", "a2"), newTarget("b", "b1")},
			wantOrder:  []string{"a", "b"},
			wantProbes: []int{0, 3},
		},
		{
			name:       "removed targets disappear",
			next:       []*config.Target{newTarget("b", "b1")},
			wantOrder:  []string{"b"},
			wantProbes: []int{3},
			wantGone:   []string{"a"},
		},
		{
			name:       "order follows the config",
			next:       []*config.Target{newTarget("c", "c1"), newTarget("b", "b1"), newTarget("a", "a1")},
			wantOrder:  []string{"c", "b", "a"},
			wantProbes: []int{0, 3, 2},
		},
		{
			name:       "duplicate names keep the first target",
			next:       []*config.Target{newTarget("a", "a1"), newTarget("a", "a2")},
			wantOrder:  []string{"a"},
			wantProbes: []int{2},
			wantGone:   []string{"b"},
		},
		{
			name:     "empty config removes everything",
			wantGone: []string{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(10, false, newTarget("a", "a1"), newTarget("b", "b1"))
			for i := range 2 {
				s.Record(probe("a", i))
			}
			for i := range 3 {
				s.Record(probe("b", i))
			}

			s.SetTargets(tt.next)

			snap := s.Snapshot()
			if got := names(snap); !slices.Equal(got, tt.wantOrder) {
				t.Fatalf("snapshot order = %v, want %v", got, tt.wantOrder)
			}
			for i, ts := range snap {
				if !slices.Contains(tt.next, ts.Target) {
					t.Errorf("%s: Target is not the pointer passed to SetTargets", ts.Target.Name)
				}
				want := tt.wantProbes[i]
				if got := ts.Results["success"]; got != uint64(want) {
					t.Errorf("%s: success count = %d, want %d", ts.Target.Name, got, want)
				}
				if got := ts.Histogram.Count; got != uint64(want) {
					t.Errorf("%s: histogram count = %d, want %d", ts.Target.Name, got, want)
				}
				if (ts.Last == nil) != (want == 0) {
					t.Errorf("%s: Last = %v, want nil only for fresh state", ts.Target.Name, ts.Last)
				}
				h, ok := s.History(ts.Target.Name)
				if !ok || len(h) != want {
					t.Errorf("%s: History = %d results, %t; want %d, true", ts.Target.Name, len(h), ok, want)
				}
			}
			for _, name := range tt.wantGone {
				if _, ok := s.History(name); ok {
					t.Errorf("History(%q) ok after removal", name)
				}
				s.Record(probe(name, 9))
				if got := names(s.Snapshot()); slices.Contains(got, name) {
					t.Errorf("Record re-created removed target %q: %v", name, got)
				}
			}
		})
	}
}

func TestHistoryLimitAndOrder(t *testing.T) {
	tests := []struct {
		limit, records int
		want           []string
	}{
		{limit: 3, records: 0, want: []string{}},
		{limit: 3, records: 2, want: []string{"probe 2", "probe 1"}},
		{limit: 3, records: 3, want: []string{"probe 3", "probe 2", "probe 1"}},
		{limit: 3, records: 7, want: []string{"probe 7", "probe 6", "probe 5"}},
		{limit: 1, records: 4, want: []string{"probe 4"}},
		{limit: 0, records: 2, want: []string{}},
		{limit: -1, records: 2, want: []string{}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("limit %d records %d", tt.limit, tt.records), func(t *testing.T) {
			s := newStore(tt.limit, false, newTarget("a", "1"))
			for n := 1; n <= tt.records; n++ {
				s.Record(probe("a", n))
			}
			h, ok := s.History("a")
			if !ok {
				t.Fatal("History not ok for a known target")
			}
			if h == nil {
				t.Error("History returned nil for a known target, want an empty slice")
			}
			if got := messages(h); !slices.Equal(got, tt.want) {
				t.Errorf("History = %v, want %v", got, tt.want)
			}
			if got, want := s.HistoryLimit(), max(tt.limit, 0); got != want {
				t.Errorf("HistoryLimit() = %d, want %d", got, want)
			}
			// Last does not depend on the history limit.
			if last := s.Snapshot()[0].Last; tt.records > 0 && (last == nil || last.Message != fmt.Sprintf("probe %d", tt.records)) {
				t.Errorf("Last = %+v, want probe %d", last, tt.records)
			}
		})
	}
}

func TestBodies(t *testing.T) {
	tests := []struct {
		captureBodies bool
		wantBody      string
		wantTruncated bool
	}{
		{captureBodies: false, wantBody: "", wantTruncated: false},
		{captureBodies: true, wantBody: "<Envelope/>", wantTruncated: true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("captureBodies=%t", tt.captureBodies), func(t *testing.T) {
			s := newStore(5, tt.captureBodies, newTarget("a", "1"))
			r := probe("a", 1)
			r.Body, r.BodyTruncated, r.BodySize = "<Envelope/>", true, 1<<20
			s.Record(r)

			h, _ := s.History("a")
			for what, got := range map[string]*result.Result{"Last": s.Snapshot()[0].Last, "History[0]": &h[0]} {
				if got.Body != tt.wantBody || got.BodyTruncated != tt.wantTruncated {
					t.Errorf("%s: Body %q, BodyTruncated %t; want %q, %t",
						what, got.Body, got.BodyTruncated, tt.wantBody, tt.wantTruncated)
				}
				if got.BodySize != 1<<20 {
					t.Errorf("%s: BodySize = %d, want it kept", what, got.BodySize)
				}
			}
		})
	}
}

func richResult() result.Result {
	r := probe("a", 1)
	r.Phases = map[result.Phase]time.Duration{result.PhaseResolve: time.Millisecond}
	r.ResponseHeader = http.Header{"Content-Type": {"text/xml"}}
	r.TLS = &result.TLSInfo{
		Version: "TLS 1.3",
		Chain:   []result.CertInfo{{Subject: "CN=a.example.com", DNSNames: []string{"a.example.com"}}},
	}
	r.Checks = []result.CheckOutcome{{Name: "status", Reason: result.ReasonStatus, Passed: true}}
	return r
}

func mutate(r *result.Result) {
	r.Phases[result.PhaseResolve] = time.Hour
	r.Phases[result.PhaseTransfer] = time.Hour
	r.ResponseHeader["Content-Type"][0] = "text/html"
	r.ResponseHeader.Set("X-Mutated", "1")
	r.TLS.Version = "SSL 3.0"
	r.TLS.Chain[0].Subject = "CN=mutated"
	r.TLS.Chain[0].DNSNames[0] = "mutated.example.com"
	r.Checks[0].Passed = false
}

func TestCopiesAreDeep(t *testing.T) {
	s := newStore(5, false, newTarget("a", "1"))
	in := richResult()
	s.Record(in)
	mutate(&in)

	snap := s.Snapshot()
	mutate(snap[0].Last)
	snap[0].Results["success"] = 100
	snap[0].Histogram.Buckets[1] = 100
	h, _ := s.History("a")
	mutate(&h[0])

	want := richResult()
	ts := s.Snapshot()[0]
	if !reflect.DeepEqual(*ts.Last, want) {
		t.Errorf("Last changed through a copy:\n got %+v\nwant %+v", *ts.Last, want)
	}
	if ts.Results["success"] != 1 || ts.Histogram.Buckets[1] != 1 {
		t.Errorf("counters changed through a copy: %v, %v", ts.Results, ts.Histogram.Buckets)
	}
	if h, _ := s.History("a"); !reflect.DeepEqual(h[0], want) {
		t.Errorf("History changed through a copy:\n got %+v\nwant %+v", h[0], want)
	}
}

func TestUnknownTargets(t *testing.T) {
	s := New(5, false)
	s.Record(probe("a", 1))
	if snap := s.Snapshot(); len(snap) != 0 {
		t.Errorf("Snapshot of an empty store = %v, want none", names(snap))
	}
	if h, ok := s.History("a"); ok || h != nil {
		t.Errorf("History(unknown) = %v, %t; want nil, false", h, ok)
	}

	s.SetTargets([]*config.Target{newTarget("a", "1")})
	if last := s.Snapshot()[0].Last; last != nil {
		t.Errorf("a result recorded before the target existed was kept: %+v", last)
	}
}

// TestConcurrentAccess is meant for -race.
func TestConcurrentAccess(t *testing.T) {
	s := newStore(4, true, newTarget("a", "1"), newTarget("b", "1"))
	const n = 200
	var wg sync.WaitGroup
	for _, name := range []string{"a", "b"} {
		wg.Go(func() {
			for range n {
				r := richResult()
				r.Target = name
				s.Record(r)
			}
		})
	}
	wg.Go(func() {
		for range n {
			for _, ts := range s.Snapshot() {
				if ts.Last != nil {
					mutate(ts.Last)
				}
				ts.Results["success"]++
				ts.Histogram.Buckets[1]++
			}
		}
	})
	wg.Go(func() {
		for range n {
			h, _ := s.History("a")
			for i := range h {
				mutate(&h[i])
			}
		}
	})
	wg.Go(func() {
		for i := range n {
			s.SetTargets([]*config.Target{newTarget("a", "1"), newTarget("b", fmt.Sprint(i%2))})
		}
	})
	wg.Wait()

	if got := names(s.Snapshot()); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("targets after concurrent use = %v", got)
	}
	if got := s.Snapshot()[0].Results["success"]; got != n {
		t.Errorf("a: success count = %d, want %d", got, n)
	}
}
