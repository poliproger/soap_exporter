package prober

import (
	"crypto/tls"
	"errors"
	"maps"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/poliproger/soap_exporter/internal/result"
)

func TestTracer(t *testing.T) {
	const ms = time.Millisecond
	errDial := errors.New("connection refused")
	tests := []struct {
		name string
		// run fires events; tick advances the clock by n milliseconds.
		run       func(ct *httptrace.ClientTrace, tr *tracer, tick func(n int))
		want      map[result.Phase]time.Duration
		wantState traceState
	}{
		{
			name:      "nothing happened",
			run:       func(*httptrace.ClientTrace, *tracer, func(int)) {},
			wantState: traceState{noRoundTrip: true},
		},
		{
			name: "fresh TLS connection",
			run: func(ct *httptrace.ClientTrace, tr *tracer, tick func(int)) {
				ct.GetConn("example.com:443")
				ct.DNSStart(httptrace.DNSStartInfo{Host: "example.com"})
				tick(1)
				ct.DNSDone(httptrace.DNSDoneInfo{})
				ct.ConnectStart("tcp", "127.0.0.1:443")
				tick(2)
				ct.ConnectDone("tcp", "127.0.0.1:443", nil)
				ct.TLSHandshakeStart()
				tick(3)
				ct.TLSHandshakeDone(tls.ConnectionState{}, nil)
				ct.GotConn(httptrace.GotConnInfo{})
				tick(1)
				ct.WroteRequest(httptrace.WroteRequestInfo{})
				tick(4)
				ct.GotFirstResponseByte()
				tick(5)
				tr.bodyDone()
			},
			want: map[result.Phase]time.Duration{
				result.PhaseResolve: 1 * ms, result.PhaseConnect: 2 * ms, result.PhaseTLS: 3 * ms,
				result.PhaseProcessing: 4 * ms, result.PhaseTransfer: 5 * ms,
			},
		},
		{
			name: "reading the response header",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:443")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				ct.WroteRequest(httptrace.WroteRequestInfo{})
				tick(4)
				ct.GotFirstResponseByte()
				tick(1)
			},
			want:      map[result.Phase]time.Duration{result.PhaseProcessing: 4 * ms},
			wantState: traceState{stage: "while reading the response"},
		},
		{
			name: "second dial attempt succeeds",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.ConnectStart("tcp", "[::1]:80")
				tick(1)
				ct.ConnectDone("tcp", "[::1]:80", errDial)
				ct.ConnectStart("tcp", "127.0.0.1:80")
				tick(2)
				ct.ConnectDone("tcp", "127.0.0.1:80", nil)
			},
			want: map[result.Phase]time.Duration{result.PhaseConnect: 3 * ms},
		},
		{
			name: "parallel attempts, the loser fails later",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.ConnectStart("tcp", "[::1]:80")
				tick(1)
				ct.ConnectStart("tcp", "127.0.0.1:80")
				tick(1)
				ct.ConnectDone("tcp", "127.0.0.1:80", nil)
				tick(1)
				ct.ConnectDone("tcp", "[::1]:80", errDial)
			},
			want: map[result.Phase]time.Duration{result.PhaseConnect: 2 * ms},
		},
		{
			name: "every dial attempt fails",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.ConnectStart("tcp", "[::1]:80")
				tick(1)
				ct.ConnectDone("tcp", "[::1]:80", errDial)
				ct.ConnectStart("tcp", "127.0.0.1:80")
				tick(2)
				ct.ConnectDone("tcp", "127.0.0.1:80", errDial)
			},
			want:      map[result.Phase]time.Duration{result.PhaseConnect: 3 * ms},
			wantState: traceState{stage: "while connecting", connectFailed: true},
		},
		{
			name: "failed TLS handshake",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:443")
				ct.ConnectStart("tcp", "127.0.0.1:443")
				tick(1)
				ct.ConnectDone("tcp", "127.0.0.1:443", nil)
				ct.TLSHandshakeStart()
				tick(2)
				ct.TLSHandshakeDone(tls.ConnectionState{}, errors.New("bad certificate"))
			},
			want:      map[result.Phase]time.Duration{result.PhaseConnect: 1 * ms, result.PhaseTLS: 2 * ms},
			wantState: traceState{tlsFailed: true},
		},
		{
			name: "deadline during the TLS handshake",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:443")
				ct.ConnectStart("tcp", "127.0.0.1:443")
				tick(1)
				ct.ConnectDone("tcp", "127.0.0.1:443", nil)
				ct.TLSHandshakeStart()
				tick(2)
			},
			want:      map[result.Phase]time.Duration{result.PhaseConnect: 1 * ms},
			wantState: traceState{stage: "during the TLS handshake"},
		},
		{
			name: "deadline during DNS",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.DNSStart(httptrace.DNSStartInfo{Host: "example.com"})
				tick(5)
			},
			wantState: traceState{stage: "while resolving the host name"},
		},
		{
			name: "reused connection",
			run: func(ct *httptrace.ClientTrace, tr *tracer, tick func(int)) {
				ct.GetConn("example.com:443")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				ct.WroteRequest(httptrace.WroteRequestInfo{})
				tick(4)
				ct.GotFirstResponseByte()
				tick(5)
				tr.bodyDone()
			},
			want: map[result.Phase]time.Duration{result.PhaseProcessing: 4 * ms, result.PhaseTransfer: 5 * ms},
		},
		{
			name: "waiting for the response",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:443")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				ct.WroteRequest(httptrace.WroteRequestInfo{})
				tick(4)
			},
			wantState: traceState{stage: "while waiting for the response"},
		},
		{
			name: "redirect",
			run: func(ct *httptrace.ClientTrace, tr *tracer, tick func(int)) {
				for range 2 {
					ct.GetConn("example.com:80")
					ct.ConnectStart("tcp", "127.0.0.1:80")
					tick(1)
					ct.ConnectDone("tcp", "127.0.0.1:80", nil)
					ct.GotConn(httptrace.GotConnInfo{})
					ct.WroteRequest(httptrace.WroteRequestInfo{})
					tick(4)
					ct.GotFirstResponseByte()
				}
				tick(5)
				tr.bodyDone() // the body of the redirect is not read
			},
			want: map[result.Phase]time.Duration{
				result.PhaseConnect: 2 * ms, result.PhaseProcessing: 8 * ms, result.PhaseTransfer: 5 * ms,
			},
		},
		{
			name: "100 Continue",
			run: func(ct *httptrace.ClientTrace, tr *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				tick(1)
				ct.GotFirstResponseByte()
				_ = ct.Got1xxResponse(http.StatusContinue, nil)
				tick(1)
				ct.WroteRequest(httptrace.WroteRequestInfo{})
				tick(4)
				tr.gotResponse()
				tick(5)
				tr.bodyDone()
			},
			want: map[result.Phase]time.Duration{result.PhaseProcessing: 4 * ms, result.PhaseTransfer: 5 * ms},
		},
		{
			name: "sending the body after 100 Continue",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				tick(1)
				ct.GotFirstResponseByte()
				_ = ct.Got1xxResponse(http.StatusContinue, nil)
				tick(1)
			},
			wantState: traceState{stage: "while sending the request"},
		},
		{
			name: "unsolicited 1xx",
			run: func(ct *httptrace.ClientTrace, tr *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				ct.WroteRequest(httptrace.WroteRequestInfo{})
				tick(1)
				ct.GotFirstResponseByte()
				_ = ct.Got1xxResponse(http.StatusEarlyHints, nil)
				tick(4)
				tr.gotResponse()
				tick(5)
				tr.bodyDone()
			},
			want: map[result.Phase]time.Duration{result.PhaseProcessing: 5 * ms, result.PhaseTransfer: 5 * ms},
		},
		{
			name: "waiting for the response after a 1xx",
			run: func(ct *httptrace.ClientTrace, _ *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				ct.WroteRequest(httptrace.WroteRequestInfo{})
				tick(1)
				ct.GotFirstResponseByte()
				_ = ct.Got1xxResponse(http.StatusEarlyHints, nil)
				tick(4)
			},
			wantState: traceState{stage: "while waiting for the response"},
		},
		{
			name: "response before the request was written",
			run: func(ct *httptrace.ClientTrace, tr *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				tick(1)
				ct.GotFirstResponseByte()
				tr.gotResponse()
				tick(3)
				ct.WroteRequest(httptrace.WroteRequestInfo{})
				tick(2)
				tr.bodyDone()
			},
			want: map[result.Phase]time.Duration{result.PhaseProcessing: 0, result.PhaseTransfer: 2 * ms},
		},
		{
			name: "request written after the body was read",
			run: func(ct *httptrace.ClientTrace, tr *tracer, tick func(int)) {
				ct.GetConn("example.com:80")
				ct.GotConn(httptrace.GotConnInfo{Reused: true})
				tick(1)
				ct.GotFirstResponseByte()
				tr.gotResponse()
				tick(2)
				tr.bodyDone()
				tick(1)
				ct.WroteRequest(httptrace.WroteRequestInfo{Err: errors.New("broken pipe")})
			},
			want: map[result.Phase]time.Duration{result.PhaseProcessing: 0, result.PhaseTransfer: 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
			tr := newTracer(func() time.Time { return now })
			tt.run(tr.clientTrace(), tr, func(n int) { now = now.Add(time.Duration(n) * ms) })
			if got := tr.phases(); !maps.Equal(got, tt.want) {
				t.Errorf("phases() = %v, want %v", got, tt.want)
			}
			if got := tr.state(); got != tt.wantState {
				t.Errorf("state() = %+v, want %+v", got, tt.wantState)
			}
		})
	}
}

func TestTracerInformationalLimit(t *testing.T) {
	tr := newTracer(time.Now)
	ct := tr.clientTrace()
	ct.GetConn("example.com:80")
	for i := range maxInformational {
		if err := ct.Got1xxResponse(http.StatusEarlyHints, nil); err != nil {
			t.Fatalf("1xx response %d: %v", i+1, err)
		}
	}
	if err := ct.Got1xxResponse(http.StatusEarlyHints, nil); !errors.Is(err, errTooManyInformational) {
		t.Errorf("1xx response %d: error = %v, want %v", maxInformational+1, err, errTooManyInformational)
	}
	// The limit applies per round trip.
	ct.GetConn("example.com:80")
	if err := ct.Got1xxResponse(http.StatusEarlyHints, nil); err != nil {
		t.Errorf("1xx response of the next round trip: %v", err)
	}
}
