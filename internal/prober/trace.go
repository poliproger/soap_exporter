package prober

import (
	"cmp"
	"crypto/tls"
	"errors"
	"net/http/httptrace"
	"net/textproto"
	"sync"
	"time"

	"github.com/poliproger/soap_exporter/internal/result"
)

// maxInformational bounds the 1xx responses accepted before the final response: with a
// Got1xxResponse hook, net/http leaves limiting them to the caller.
const maxInformational = 5

var errTooManyInformational = errors.New("too many 1xx informational responses")

// tracer records the httptrace events of one probe. net/http calls the hooks on its own
// goroutines, and a dial or round trip abandoned at the deadline may still report after
// Probe returned, so all state is guarded by mu.
type tracer struct {
	now func() time.Time

	mu    sync.Mutex
	trips []*trip // one per round trip; a followed redirect or a retry adds one
}

// trip holds the event times of one round trip; a zero time means the event did not happen.
type trip struct {
	dnsStart, dnsDone time.Time
	connStart         time.Time // the first dial attempt started
	connFailed        time.Time // the last failed dial attempt ended
	connOK            time.Time // a dial attempt succeeded
	tlsStart, tlsDone time.Time
	tlsFailed         bool
	gotConn           time.Time
	wrote             time.Time
	firstByte         time.Time // of any response, a 1xx included
	informational     int       // 1xx responses received
	headers           time.Time // the final response headers arrived
	bodyDone          time.Time
}

// responseStart returns when the final response started to arrive, zero if it did not. After
// a 1xx response the first response byte belongs to that; then the arrival of the final
// headers stands in for it.
func (rt *trip) responseStart() time.Time {
	if rt.informational > 0 {
		return rt.headers
	}
	return cmp.Or(rt.firstByte, rt.headers)
}

// traceState is what the trace tells about a failed probe.
type traceState struct {
	stage         string // where the probe was, e.g. "while connecting"; "" if unknown
	tlsFailed     bool   // the TLS handshake failed
	connectFailed bool   // every dial attempt failed
	noRoundTrip   bool   // no round trip reached the HTTP transport, e.g. a token was pending
}

func newTracer(now func() time.Time) *tracer {
	return &tracer{now: now}
}

// update applies fn to the current round trip.
func (t *tracer) update(fn func(rt *trip, now time.Time)) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.trips) == 0 {
		t.trips = append(t.trips, &trip{})
	}
	fn(t.trips[len(t.trips)-1], now)
}

func setOnce(t *time.Time, now time.Time) {
	if t.IsZero() {
		*t = now
	}
}

func (t *tracer) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(string) {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.trips = append(t.trips, &trip{})
		},
		DNSStart: func(httptrace.DNSStartInfo) {
			t.update(func(rt *trip, now time.Time) { setOnce(&rt.dnsStart, now) })
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.update(func(rt *trip, now time.Time) { rt.dnsDone = now })
		},
		ConnectStart: func(string, string) {
			t.update(func(rt *trip, now time.Time) { setOnce(&rt.connStart, now) })
		},
		ConnectDone: func(_, _ string, err error) {
			t.update(func(rt *trip, now time.Time) {
				if err != nil {
					rt.connFailed = now
				} else {
					setOnce(&rt.connOK, now)
				}
			})
		},
		TLSHandshakeStart: func() {
			t.update(func(rt *trip, now time.Time) { setOnce(&rt.tlsStart, now) })
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			t.update(func(rt *trip, now time.Time) {
				rt.tlsDone = now
				rt.tlsFailed = err != nil
			})
		},
		GotConn: func(httptrace.GotConnInfo) {
			t.update(func(rt *trip, now time.Time) { setOnce(&rt.gotConn, now) })
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			t.update(func(rt *trip, now time.Time) { setOnce(&rt.wrote, now) })
		},
		GotFirstResponseByte: func() {
			t.update(func(rt *trip, now time.Time) { setOnce(&rt.firstByte, now) })
		},
		Got1xxResponse: func(int, textproto.MIMEHeader) error {
			var n int
			t.update(func(rt *trip, _ time.Time) {
				rt.informational++
				n = rt.informational
			})
			if n > maxInformational {
				return errTooManyInformational
			}
			return nil
		},
	}
}

// gotResponse records that the final response headers arrived.
func (t *tracer) gotResponse() {
	t.update(func(rt *trip, now time.Time) { setOnce(&rt.headers, now) })
}

// bodyDone records that reading the response body ended.
func (t *tracer) bodyDone() {
	t.update(func(rt *trip, now time.Time) { rt.bodyDone = now })
}

// phases sums the durations of the phases that happened over all round trips; nil if none
// did. A phase counts once it has ended: resolve, connect and tls also when they failed
// (connect from the first attempt to the successful one, or else to the last failure),
// processing when the final response started, transfer when reading the body ended. A
// server may answer before the request is fully written; then processing is zero and
// transfer starts when the request was written. No phase is negative.
func (t *tracer) phases() map[result.Phase]time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	var m map[result.Phase]time.Duration
	add := func(p result.Phase, from, to time.Time) {
		if from.IsZero() || to.IsZero() {
			return
		}
		if m == nil {
			m = make(map[result.Phase]time.Duration, len(result.AllPhases))
		}
		m[p] += max(to.Sub(from), 0)
	}
	for _, rt := range t.trips {
		add(result.PhaseResolve, rt.dnsStart, rt.dnsDone)
		add(result.PhaseConnect, rt.connStart, cmp.Or(rt.connOK, rt.connFailed))
		add(result.PhaseTLS, rt.tlsStart, rt.tlsDone)
		if start := rt.responseStart(); !start.IsZero() {
			add(result.PhaseProcessing, rt.wrote, start)
			add(result.PhaseTransfer, latest(start, rt.wrote), rt.bodyDone)
		}
	}
	return m
}

func latest(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

// state describes the last round trip for a failed probe.
func (t *tracer) state() traceState {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.trips) == 0 {
		return traceState{noRoundTrip: true}
	}
	rt := t.trips[len(t.trips)-1]
	st := traceState{
		tlsFailed:     rt.tlsFailed,
		connectFailed: !rt.connFailed.IsZero() && rt.connOK.IsZero(),
	}
	switch {
	case !rt.bodyDone.IsZero():
		// The exchange is over.
	case !rt.responseStart().IsZero():
		st.stage = "while reading the response"
	case !rt.wrote.IsZero():
		st.stage = "while waiting for the response"
	case !rt.gotConn.IsZero():
		st.stage = "while sending the request"
	case !rt.tlsStart.IsZero() && rt.tlsDone.IsZero():
		st.stage = "during the TLS handshake"
	case !rt.connStart.IsZero() && rt.connOK.IsZero():
		st.stage = "while connecting"
	case !rt.dnsStart.IsZero() && rt.dnsDone.IsZero():
		st.stage = "while resolving the host name"
	}
	return st
}
