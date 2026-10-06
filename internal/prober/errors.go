package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/result"
)

// Stages of a probe whose request has not reached the HTTP transport yet.
const (
	kerberosTokenStage = "while acquiring a Kerberos token"
	oauth2TokenStage   = "while acquiring an OAuth2 token"
)

// classify maps an error of the round trip or of the body read to a failure reason and a
// one-line message. ctxErr is the error of the probe context: whatever the error, a probe
// past its deadline failed with "timeout", and a cancelled probe is only reported as such.
func (p *Prober) classify(err, ctxErr error, st traceState) (result.Reason, string) {
	var (
		tokenErr *kerberos.TokenError
		dnsErr   *net.DNSError
	)
	isToken := errors.As(err, &tokenErr)
	switch {
	case errors.Is(ctxErr, context.Canceled):
		return result.ReasonHTTP, "probe cancelled"
	case errors.Is(ctxErr, context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		stage := st.stage
		switch {
		case isToken:
			stage = kerberosTokenStage
		case st.noRoundTrip:
			// The deadline may have cut the round trip short before the token error came back.
			stage = p.tokenStage
		}
		msg := "timed out"
		if stage != "" {
			msg += " " + stage
		}
		return result.ReasonTimeout, msg + " (timeout " + p.target.Timeout.String() + ")"
	case isToken:
		return result.ReasonAuth, oneLine(tokenErr.Error())
	case st.noRoundTrip && p.tokenStage == oauth2TokenStage:
		// prometheus/common acquires the token (reads the client secret, calls the token
		// endpoint) before the request reaches the HTTP transport, and without the probe's
		// trace. An error before any round trip comes from there, like a Kerberos TokenError,
		// also when the token endpoint is unreachable.
		return result.ReasonAuth, message(err)
	case errors.As(err, &dnsErr):
		return result.ReasonDNS, oneLine(dnsErr.Error())
	case st.tlsFailed || isTLSError(err):
		return result.ReasonTLS, message(err)
	case st.connectFailed || hasOpError(err, "dial"):
		return result.ReasonConnect, message(err)
	}
	return result.ReasonHTTP, message(err)
}

// isTLSError reports whether err comes from a TLS handshake or certificate verification.
// Alerts are not exported by crypto/tls for TCP connections; they arrive as a *net.OpError
// with the operation "remote error" or "local error".
func isTLSError(err error) bool {
	var (
		recordErr tls.RecordHeaderError
		alertErr  tls.AlertError
		verifyErr *tls.CertificateVerificationError
		echErr    *tls.ECHRejectionError
		authErr   x509.UnknownAuthorityError
		hostErr   x509.HostnameError
		certErr   x509.CertificateInvalidError
		rootsErr  x509.SystemRootsError
	)
	return errors.As(err, &recordErr) || errors.As(err, &alertErr) || errors.As(err, &verifyErr) ||
		errors.As(err, &echErr) || errors.As(err, &authErr) || errors.As(err, &hostErr) ||
		errors.As(err, &certErr) || errors.As(err, &rootsErr) ||
		hasOpError(err, "remote error", "local error")
}

// hasOpError reports whether err wraps a *net.OpError with one of the operations. Unlike a
// single errors.As it also finds a dial error inside a "proxyconnect" error.
func hasOpError(err error, ops ...string) bool {
	var opErr *net.OpError
	for errors.As(err, &opErr) {
		if slices.Contains(ops, opErr.Op) {
			return true
		}
		err = opErr.Err
	}
	return false
}

// message returns the text of err on one line, without the method and URL that
// *url.Error adds: the target URL is known, and the error is shorter without it.
func message(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return oneLine(err.Error())
}

// maxMessageLen bounds the length in bytes of a message taken from an error. OAuth2 token
// errors, for example, carry the whole response of the token endpoint.
const maxMessageLen = 512

// oneLine collapses runs of white space into single spaces and clips s on a rune boundary.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxMessageLen {
		return s
	}
	cut := maxMessageLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
