package prober

import (
	"net/http"
	"runtime/debug"
)

// maxRoundTrips bounds the round trips of one prober that run at once, including those that
// still run after their probe gave up on them.
const maxRoundTrips = 4

// transport is the RoundTripper of one probe. It runs every round trip on a goroutine of its
// own and returns at the probe deadline even if a RoundTripper of the chain ignores the
// request context: prometheus/common's OAuth2 RoundTripper fetches tokens with
// context.Background() and a client without a timeout. Such a round trip goes on in the
// background and holds one of the prober's slots until it ends; a probe that finds no free
// slot waits for one until its deadline. This bounds the goroutines that a hanging token
// endpoint piles up.
//
// transport also tells the tracer when the final response headers arrived.
type transport struct {
	p  *Prober
	tr *tracer
}

type roundTripResult struct {
	resp  *http.Response
	err   error
	panic *roundTripPanic
}

// roundTripPanic is a panic of a round trip goroutine, raised again on the probe's goroutine.
type roundTripPanic struct {
	value any
	stack []byte
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	select {
	case t.p.slots <- struct{}{}:
	case <-ctx.Done():
		// A RoundTripper must close the request body, even on errors.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, ctx.Err()
	}
	done := make(chan roundTripResult, 1)
	go func() {
		defer func() { <-t.p.slots }()
		done <- t.p.roundTrip(req)
	}()
	select {
	case res := <-done:
		if res.panic != nil {
			panic(res.panic)
		}
		if res.resp != nil {
			t.tr.gotResponse()
		}
		return res.resp, res.err
	case <-ctx.Done():
		go t.p.discard(done)
		return nil, ctx.Err()
	}
}

// roundTrip calls the target's RoundTripper chain and turns a panic into a result.
func (p *Prober) roundTrip(req *http.Request) (res roundTripResult) {
	defer func() {
		if v := recover(); v != nil {
			res = roundTripResult{panic: &roundTripPanic{value: v, stack: debug.Stack()}}
		}
	}()
	res.resp, res.err = p.rt.RoundTrip(req) //nolint:bodyclose // the probe or discard closes it
	return res
}

// discard waits for a round trip that its probe gave up on and releases the response.
func (p *Prober) discard(done <-chan roundTripResult) {
	res := <-done
	switch {
	case res.panic != nil:
		p.logger.Error("Round trip panicked after its probe ended", "target", p.target.Name,
			"panic", res.panic.value, "stack", string(res.panic.stack))
	case res.resp != nil:
		_ = res.resp.Body.Close()
	}
}
