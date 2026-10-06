// Package kerberos defines the Kerberos backend interfaces, a registry that shares one
// credential per (principal, keytab), and the SPNEGO RoundTripper (plan §4, §6.2, D5, D6).
package kerberos

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

// Backend creates credentials; implemented by the gokrb5 and gssapi packages.
type Backend interface {
	Name() string
	// NewCredential creates a credential. It reads and parses the keytab eagerly, so a
	// missing or broken keytab is reported at config load; it does not contact the KDC.
	NewCredential(principal, keytab string) (Credential, error)
}

// Credential is one Kerberos identity (principal + keytab), shared by all targets that use
// it. Implementations are safe for concurrent use.
type Credential interface {
	// Token returns an initial SPNEGO token for the service principal spn ("HTTP/host"),
	// sent as "Authorization: Negotiate <base64 token>". It honours ctx cancellation even if
	// the underlying library does not.
	Token(ctx context.Context, spn string) ([]byte, error)
	// Reset drops all cached tickets; the next Token call starts with a fresh TGT.
	Reset()
	Close() error
}

// Key identifies a credential in the registry.
type Key struct {
	Principal string
	Keytab    string
}

// Registry shares one Credential per Key.
type Registry struct {
	backend Backend
	logger  *slog.Logger

	mu    sync.Mutex
	creds map[Key]Credential
}

// NewRegistry returns an empty registry using backend b.
func NewRegistry(b Backend, logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Registry{backend: b, logger: logger, creds: make(map[Key]Credential)}
}

// Backend returns the backend of the registry.
func (r *Registry) Backend() Backend {
	return r.backend
}

// Get returns the credential for k, creating it on first use.
func (r *Registry) Get(k Key) (Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.creds[k]; ok {
		return c, nil
	}
	c, err := r.backend.NewCredential(k.Principal, k.Keytab)
	if err != nil {
		return nil, err
	}
	r.creds[k] = c
	r.logger.Debug("Kerberos credential created", "principal", k.Principal, "keytab", k.Keytab,
		"backend", r.backend.Name())
	return c, nil
}

// Retain closes and forgets every credential whose key is not in keep (after a reload).
func (r *Registry) Retain(keep []Key) {
	want := make(map[Key]struct{}, len(keep))
	for _, k := range keep {
		want[k] = struct{}{}
	}
	r.mu.Lock()
	drop := make(map[Key]Credential)
	for k, c := range r.creds {
		if _, ok := want[k]; !ok {
			drop[k] = c
			delete(r.creds, k)
		}
	}
	r.mu.Unlock()
	r.close(drop)
}

// Close closes all credentials.
func (r *Registry) Close() {
	r.mu.Lock()
	drop := r.creds
	r.creds = make(map[Key]Credential)
	r.mu.Unlock()
	r.close(drop)
}

// close closes creds outside r.mu: a credential may wait for a KDC exchange in progress.
func (r *Registry) close(creds map[Key]Credential) {
	for k, c := range creds {
		if err := c.Close(); err != nil {
			r.logger.Warn("Closing Kerberos credential failed", "principal", k.Principal,
				"keytab", k.Keytab, "err", err)
			continue
		}
		r.logger.Debug("Kerberos credential closed", "principal", k.Principal, "keytab", k.Keytab)
	}
}

// TokenError wraps a failure to obtain a SPNEGO token. The prober classifies it as reason
// "auth" (or "timeout" if the probe deadline expired while waiting).
type TokenError struct {
	SPN string
	Err error
}

func (e *TokenError) Error() string { return "kerberos: token for " + e.SPN + ": " + e.Err.Error() }
func (e *TokenError) Unwrap() error { return e.Err }

// NewRoundTripper returns a RoundTripper that sets "Authorization: Negotiate <token>" on
// every request preemptively, using spn explicitly (no DNS canonicalization, req.Host is
// never changed). A 401 response is returned as is (never retried) and calls cred.Reset(),
// so the next probe starts with fresh tickets (plan §6.2). A redirect (follow_redirects)
// to another host fails without a token: that host could replay it to the service. Token
// failures and such redirects are returned as *TokenError.
func NewRoundTripper(cred Credential, spn string, next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &roundTripper{cred: cred, spn: spn, next: next}
}

type roundTripper struct {
	cred Credential
	spn  string
	next http.RoundTripper
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := rt.token(req)
	if err != nil {
		// A RoundTripper must close the request body, even on errors.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, &TokenError{SPN: rt.spn, Err: err}
	}
	out := req.Clone(req.Context())
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	out.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))
	resp, err := rt.next.RoundTrip(out)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		// The cached tickets may be the cause (e.g. a rotated service key); without a reset
		// they would be reused until they expire.
		rt.cred.Reset()
	}
	return resp, err
}

// errRedirect is returned for a redirect to another host.
var errRedirect = errors.New("redirect to another host")

func (rt *roundTripper) token(req *http.Request) ([]byte, error) {
	// http.Client strips Authorization from a redirect to another domain, but this
	// RoundTripper sees each redirect as a new request. The host is compared, not the domain:
	// the token is meant for one service only.
	if req.Response != nil {
		var from string
		if prev := req.Response.Request; prev != nil && prev.URL != nil {
			from = prev.URL.Hostname()
		}
		if to := req.URL.Hostname(); from == "" || !strings.EqualFold(from, to) {
			return nil, fmt.Errorf("%w (%s to %s), no token sent", errRedirect, cmp.Or(from, "unknown"), to)
		}
	}
	return rt.cred.Token(req.Context(), rt.spn)
}

// CloseIdleConnections forwards to the wrapped transport, so http.Client.CloseIdleConnections
// reaches it.
func (rt *roundTripper) CloseIdleConnections() {
	if c, ok := rt.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
