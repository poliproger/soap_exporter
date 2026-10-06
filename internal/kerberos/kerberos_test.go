package kerberos

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeCredential returns token for every SPN, or err.
type fakeCredential struct {
	key   Key
	token []byte
	err   error

	mu     sync.Mutex
	spns   []string
	ctxs   []context.Context
	resets atomic.Int32
	closes atomic.Int32
}

func (c *fakeCredential) Token(ctx context.Context, spn string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.spns = append(c.spns, spn)
	c.ctxs = append(c.ctxs, ctx)
	return c.token, c.err
}

func (c *fakeCredential) Reset() { c.resets.Add(1) }

func (c *fakeCredential) Close() error {
	c.closes.Add(1)
	return nil
}

// fakeBackend creates fakeCredentials; it fails for keytabs in fail.
type fakeBackend struct {
	fail map[string]error

	mu      sync.Mutex
	created []*fakeCredential
}

func (b *fakeBackend) Name() string { return "fake" }

func (b *fakeBackend) NewCredential(principal, keytab string) (Credential, error) {
	if err := b.fail[keytab]; err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c := &fakeCredential{key: Key{principal, keytab}}
	b.created = append(b.created, c)
	return c, nil
}

func (b *fakeBackend) credentials() []*fakeCredential {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.created)
}

var (
	keyA = Key{Principal: "HTTP/a.corp.example@CORP.EXAMPLE", Keytab: "/etc/soap_exporter/a.keytab"}
	keyB = Key{Principal: "HTTP/b.corp.example@CORP.EXAMPLE", Keytab: "/etc/soap_exporter/b.keytab"}
	// keyA's principal with another keytab is another credential.
	keyA2 = Key{Principal: keyA.Principal, Keytab: "/etc/soap_exporter/a2.keytab"}
)

func TestRegistryGet(t *testing.T) {
	b := &fakeBackend{}
	r := NewRegistry(b, nil)
	if r.Backend() != b {
		t.Fatal("Backend() does not return the backend")
	}

	a, err := r.Get(keyA)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := a.(*fakeCredential).key; got != keyA {
		t.Errorf("credential created for %+v, want %+v", got, keyA)
	}
	again, _ := r.Get(keyA)
	if again != a {
		t.Error("Get() created a second credential for the same key")
	}
	other, _ := r.Get(keyA2)
	if other == a {
		t.Error("Get() shared a credential between keytabs")
	}
	if n := len(b.credentials()); n != 2 {
		t.Errorf("backend created %d credentials, want 2", n)
	}
}

func TestRegistryGetConcurrent(t *testing.T) {
	b := &fakeBackend{}
	r := NewRegistry(b, nil)
	const n = 16
	got := make([]Credential, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			c, err := r.Get(keyA)
			if err != nil {
				t.Errorf("Get() error = %v", err)
			}
			got[i] = c
		})
	}
	wg.Wait()
	for _, c := range got {
		if c != got[0] {
			t.Fatal("concurrent Get() calls returned different credentials")
		}
	}
	if n := len(b.credentials()); n != 1 {
		t.Errorf("backend created %d credentials, want 1", n)
	}
}

func TestRegistryGetError(t *testing.T) {
	errKeytab := errors.New("read keytab: permission denied")
	b := &fakeBackend{fail: map[string]error{keyA.Keytab: errKeytab}}
	r := NewRegistry(b, nil)

	if _, err := r.Get(keyA); !errors.Is(err, errKeytab) {
		t.Fatalf("Get() error = %v, want %v", err, errKeytab)
	}
	delete(b.fail, keyA.Keytab)
	if _, err := r.Get(keyA); err != nil {
		t.Fatalf("Get() after the keytab was fixed: error = %v, want the failure not to be cached", err)
	}
}

func TestRegistryRetain(t *testing.T) {
	tests := []struct {
		name       string
		keep       []Key
		wantClosed []Key
	}{
		{name: "keep all", keep: []Key{keyA, keyB, keyA2}},
		{name: "drop one", keep: []Key{keyA, keyB}, wantClosed: []Key{keyA2}},
		{name: "unknown keys", keep: []Key{keyB, {Principal: "x", Keytab: "y"}}, wantClosed: []Key{keyA, keyA2}},
		{name: "drop all", keep: nil, wantClosed: []Key{keyA, keyB, keyA2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &fakeBackend{}
			r := NewRegistry(b, nil)
			creds := make(map[Key]Credential)
			for _, k := range []Key{keyA, keyB, keyA2} {
				c, err := r.Get(k)
				if err != nil {
					t.Fatal(err)
				}
				creds[k] = c
			}

			r.Retain(tt.keep)
			for k, c := range creds {
				fc := c.(*fakeCredential)
				wantClosed := slices.Contains(tt.wantClosed, k)
				if closed := fc.closes.Load() > 0; closed != wantClosed {
					t.Errorf("%v closed = %v, want %v", k, closed, wantClosed)
				}
				again, _ := r.Get(k)
				if reused := again == c; reused == wantClosed {
					t.Errorf("%v: Get() after Retain reused = %v, want %v", k, reused, !wantClosed)
				}
			}
		})
	}
}

func TestRegistryClose(t *testing.T) {
	b := &fakeBackend{}
	r := NewRegistry(b, nil)
	for _, k := range []Key{keyA, keyB} {
		if _, err := r.Get(k); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	for _, c := range b.credentials() {
		if n := c.closes.Load(); n != 1 {
			t.Errorf("%v closed %d times, want 1", c.key, n)
		}
	}
	r.Close()
	for _, c := range b.credentials() {
		if n := c.closes.Load(); n != 1 {
			t.Errorf("%v closed %d times after a second Close, want 1", c.key, n)
		}
	}
}

// server records the requests it receives and answers with status.
type server struct {
	*httptest.Server
	hits atomic.Int32

	mu   sync.Mutex
	reqs []*http.Request
}

func newServer(t *testing.T, status int) *server {
	t.Helper()
	s := &server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		s.reqs = append(s.reqs, r)
		s.mu.Unlock()
		if status == http.StatusUnauthorized {
			w.Header().Add("WWW-Authenticate", "Negotiate")
			w.Header().Add("WWW-Authenticate", "NTLM")
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) lastRequest() *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqs[len(s.reqs)-1]
}

const testSPN = "HTTP/app.corp.example"

type ctxKey struct{}

func newRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	ctx := context.WithValue(t.Context(), ctxKey{}, "probe")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("<Envelope/>"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "vhost.corp.example"
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	return req
}

func TestRoundTripper(t *testing.T) {
	s := newServer(t, http.StatusOK)
	cred := &fakeCredential{token: []byte{0x60, 0x82, 0x01, 0xff}}
	req := newRequest(t, s.URL)

	resp, err := NewRoundTripper(cred, testSPN, s.Client().Transport).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	got := s.lastRequest()
	if want := "Negotiate YIIB/w=="; got.Header.Get("Authorization") != want {
		t.Errorf("Authorization = %q, want %q", got.Header.Get("Authorization"), want)
	}
	if got.Host != "vhost.corp.example" {
		t.Errorf("Host = %q, want it unchanged", got.Host)
	}
	if got.Header.Get("Content-Type") != "text/xml; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the caller's header", got.Header.Get("Content-Type"))
	}
	if cred.spns[0] != testSPN {
		t.Errorf("token requested for %q, want %q", cred.spns[0], testSPN)
	}
	if cred.ctxs[0].Value(ctxKey{}) != "probe" {
		t.Error("the token was not requested with the request context")
	}
	if n := cred.resets.Load(); n != 0 {
		t.Errorf("Reset called %d times, want 0", n)
	}

	// The caller's request is not modified.
	if req.Header.Get("Authorization") != "" {
		t.Error("the caller's request got an Authorization header")
	}
	if req.Host != "vhost.corp.example" || len(req.Header) != 1 {
		t.Errorf("the caller's request changed: Host %q, headers %v", req.Host, req.Header)
	}
}

func TestRoundTripperUnauthorized(t *testing.T) {
	s := newServer(t, http.StatusUnauthorized)
	cred := &fakeCredential{token: []byte("token")}

	resp, err := NewRoundTripper(cred, testSPN, s.Client().Transport).RoundTrip(newRequest(t, s.URL))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if n := s.hits.Load(); n != 1 {
		t.Errorf("server hit %d times, want 1 (no retry)", n)
	}
	if n := cred.resets.Load(); n != 1 {
		t.Errorf("Reset called %d times, want 1", n)
	}
}

func TestRoundTripperStatusWithoutReset(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError} {
		s := newServer(t, status)
		cred := &fakeCredential{token: []byte("token")}
		resp, err := NewRoundTripper(cred, testSPN, s.Client().Transport).RoundTrip(newRequest(t, s.URL))
		if err != nil {
			t.Fatalf("RoundTrip() error = %v", err)
		}
		resp.Body.Close()
		if n := cred.resets.Load(); n != 0 {
			t.Errorf("status %d: Reset called %d times, want 0", status, n)
		}
	}
}

// closeRecorder records whether the request body was closed.
type closeRecorder struct {
	io.Reader
	closed bool
}

func (b *closeRecorder) Close() error {
	b.closed = true
	return nil
}

func TestRoundTripperTokenError(t *testing.T) {
	s := newServer(t, http.StatusOK)
	errKDC := errors.New("KDC_ERR_S_PRINCIPAL_UNKNOWN")
	cred := &fakeCredential{err: errKDC}
	req := newRequest(t, s.URL)
	body := &closeRecorder{Reader: strings.NewReader("<Envelope/>")}
	req.Body = body

	resp, err := NewRoundTripper(cred, testSPN, s.Client().Transport).RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
		t.Error("RoundTrip() returned a response")
	}
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("RoundTrip() error = %v, want *TokenError", err)
	}
	if te.SPN != testSPN || !errors.Is(err, errKDC) {
		t.Errorf("TokenError = %+v, want SPN %q wrapping %v", te, testSPN, errKDC)
	}
	if want := "kerberos: token for " + testSPN + ": " + errKDC.Error(); err.Error() != want {
		t.Errorf("error text = %q, want %q", err, want)
	}
	if n := s.hits.Load(); n != 0 {
		t.Errorf("server hit %d times, want 0", n)
	}
	if !body.closed {
		t.Error("the request body was not closed")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRoundTripperTokenTimeout(t *testing.T) {
	cred := &fakeCredential{err: context.DeadlineExceeded}
	next := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Error("the request was sent without a token")
		return nil, errors.New("unexpected request")
	})
	_, err := NewRoundTripper(cred, testSPN, next).RoundTrip(newRequest(t, "http://app.corp.example/svc.asmx"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RoundTrip() error = %v, want it to wrap context.DeadlineExceeded", err)
	}
}

func TestRoundTripperNilHeader(t *testing.T) {
	s := newServer(t, http.StatusOK)
	req := newRequest(t, s.URL)
	req.Header = nil
	resp, err := NewRoundTripper(&fakeCredential{token: []byte("t")}, testSPN, s.Client().Transport).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	resp.Body.Close()
	if got, want := s.lastRequest().Header.Get("Authorization"), "Negotiate "+base64.StdEncoding.EncodeToString([]byte("t")); got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestRoundTripperRedirect(t *testing.T) {
	tests := []struct {
		name    string
		from    string // URL of the request that got the redirect; "" without its request
		to      string
		wantErr bool
	}{
		{name: "same host", from: "http://app.corp.example/svc.asmx", to: "http://app.corp.example/v2/svc.asmx"},
		{name: "same host, other case", from: "http://App.Corp.Example/svc.asmx", to: "http://app.corp.example/svc.asmx"},
		{name: "same host, other scheme and port", from: "http://app.corp.example/svc.asmx", to: "https://app.corp.example:8443/svc.asmx"},
		{name: "other host", from: "http://app.corp.example/svc.asmx", to: "http://evil.example/svc.asmx", wantErr: true},
		{name: "subdomain", from: "http://corp.example/svc.asmx", to: "http://app.corp.example/svc.asmx", wantErr: true},
		{name: "unknown origin", to: "http://app.corp.example/svc.asmx", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &fakeCredential{token: []byte("t")}
			var sent int
			next := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				sent++
				if r.Header.Get("Authorization") == "" {
					t.Error("the request was sent without a token")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
			})
			req := newRequest(t, tt.to)
			req.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect}
			if tt.from != "" {
				req.Response.Request = newRequest(t, tt.from)
			}

			resp, err := NewRoundTripper(cred, testSPN, next).RoundTrip(req)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("RoundTrip() error = %v", err)
				}
				resp.Body.Close()
				if sent != 1 {
					t.Errorf("sent %d requests, want 1", sent)
				}
				return
			}
			var te *TokenError
			if !errors.As(err, &te) || !errors.Is(err, errRedirect) {
				t.Fatalf("RoundTrip() error = %v, want a *TokenError for the redirect", err)
			}
			if sent != 0 || len(cred.spns) != 0 {
				t.Errorf("sent %d requests and made %d tokens, want none", sent, len(cred.spns))
			}
		})
	}
}

func TestRoundTripperRedirectWithClient(t *testing.T) {
	tests := []struct {
		name       string
		target     func(s *server) string // the Location of the redirect
		wantTokens int
		wantErr    bool
	}{
		{name: "same host", target: func(s *server) string { return s.URL + "/v2" }, wantTokens: 2},
		{
			name: "other host",
			target: func(s *server) string {
				return strings.Replace(s.URL, "127.0.0.1", "localhost", 1) + "/v2"
			},
			wantTokens: 1,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s2 := newServer(t, http.StatusOK)
			s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tt.target(s2), http.StatusTemporaryRedirect)
			}))
			t.Cleanup(s1.Close)
			cred := &fakeCredential{token: []byte("t")}
			client := &http.Client{Transport: NewRoundTripper(cred, testSPN, s1.Client().Transport)}

			resp, err := client.Do(newRequest(t, s1.URL))
			if tt.wantErr {
				if !errors.Is(err, errRedirect) {
					t.Errorf("Do() error = %v, want the redirect refused", err)
				}
				if n := s2.hits.Load(); n != 0 {
					t.Errorf("the redirect target was hit %d times, want 0", n)
				}
			} else {
				if err != nil {
					t.Fatalf("Do() error = %v", err)
				}
				resp.Body.Close()
				if got := s2.lastRequest().Header.Get("Authorization"); got == "" {
					t.Error("the redirect target got no token")
				}
			}
			if n := len(cred.spns); n != tt.wantTokens {
				t.Errorf("made %d tokens, want %d", n, tt.wantTokens)
			}
		})
	}
}

type idleCloser struct {
	http.RoundTripper
	closed atomic.Bool
}

func (c *idleCloser) CloseIdleConnections() { c.closed.Store(true) }

func TestRoundTripperCloseIdleConnections(t *testing.T) {
	next := &idleCloser{RoundTripper: http.DefaultTransport}
	client := &http.Client{Transport: NewRoundTripper(&fakeCredential{}, testSPN, next)}
	client.CloseIdleConnections()
	if !next.closed.Load() {
		t.Error("CloseIdleConnections did not reach the wrapped transport")
	}
}
