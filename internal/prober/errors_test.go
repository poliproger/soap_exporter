package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/common/model"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/result"
)

func TestClassify(t *testing.T) {
	target := &config.Target{Timeout: model.Duration(2 * time.Second)}
	post := func(err error) error {
		return &url.Error{Op: "Post", URL: "https://soap.example.com/Orders.svc", Err: err}
	}
	dial := func(err error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: err} }
	refused := os.NewSyscallError("connect", syscall.ECONNREFUSED)
	tokenErr := &kerberos.TokenError{SPN: "HTTP/soap.example.com", Err: errors.New("KDC has no support for encryption type")}

	tests := []struct {
		name        string
		err         error
		ctxErr      error
		st          traceState
		tokenStage  string
		want        result.Reason
		wantMessage string
	}{
		{
			name:        "unresolvable host",
			err:         post(dial(&net.DNSError{Err: "no such host", Name: "soap.example.com", IsNotFound: true})),
			want:        result.ReasonDNS,
			wantMessage: "lookup soap.example.com: no such host",
		},
		{
			name:        "connection refused",
			err:         post(dial(refused)),
			want:        result.ReasonConnect,
			wantMessage: "dial tcp: connect: connection refused",
		},
		{
			name:        "proxy refuses the connection",
			err:         post(&net.OpError{Op: "proxyconnect", Net: "tcp", Err: dial(refused)}),
			want:        result.ReasonConnect,
			wantMessage: "proxyconnect tcp: dial tcp: connect: connection refused",
		},
		{
			name:        "dial failure seen by the trace",
			err:         post(errors.New("no route")),
			st:          traceState{connectFailed: true},
			want:        result.ReasonConnect,
			wantMessage: "no route",
		},
		{
			name:        "unknown authority",
			err:         post(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
			want:        result.ReasonTLS,
			wantMessage: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},
		{
			name: "expired certificate",
			err:  post(x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}),
			want: result.ReasonTLS,
		},
		{
			name: "host name mismatch",
			err:  post(x509.HostnameError{Certificate: &x509.Certificate{}, Host: "soap.example.com"}),
			want: result.ReasonTLS,
		},
		{
			name:        "not a TLS server",
			err:         post(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}),
			want:        result.ReasonTLS,
			wantMessage: "tls: first record does not look like a TLS handshake",
		},
		{
			name:        "alert from the server",
			err:         post(&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}),
			want:        result.ReasonTLS,
			wantMessage: "remote error: tls: handshake failure",
		},
		{
			name:        "handshake failure seen by the trace",
			err:         post(http.ErrSchemeMismatch),
			st:          traceState{tlsFailed: true},
			want:        result.ReasonTLS,
			wantMessage: "http: server gave HTTP response to HTTPS client",
		},
		{
			name:        "Kerberos token",
			err:         post(tokenErr),
			want:        result.ReasonAuth,
			wantMessage: "kerberos: token for HTTP/soap.example.com: KDC has no support for encryption type",
		},
		{
			name:        "Kerberos token at the deadline",
			err:         post(&kerberos.TokenError{SPN: "HTTP/soap.example.com", Err: context.DeadlineExceeded}),
			ctxErr:      context.DeadlineExceeded,
			want:        result.ReasonTimeout,
			wantMessage: "timed out while acquiring a Kerberos token (timeout 2s)",
		},
		{
			name:        "Kerberos deadline before the token error came back",
			err:         post(context.DeadlineExceeded),
			ctxErr:      context.DeadlineExceeded,
			st:          traceState{noRoundTrip: true},
			tokenStage:  kerberosTokenStage,
			want:        result.ReasonTimeout,
			wantMessage: "timed out while acquiring a Kerberos token (timeout 2s)",
		},
		{
			name:        "OAuth2 deadline before the round trip",
			err:         post(context.DeadlineExceeded),
			ctxErr:      context.DeadlineExceeded,
			st:          traceState{noRoundTrip: true},
			tokenStage:  oauth2TokenStage,
			want:        result.ReasonTimeout,
			wantMessage: "timed out while acquiring an OAuth2 token (timeout 2s)",
		},
		{
			name:        "OAuth2 token rejected",
			err:         post(errors.New(`oauth2: "invalid_client" "bad client credentials"`)),
			st:          traceState{noRoundTrip: true},
			tokenStage:  oauth2TokenStage,
			want:        result.ReasonAuth,
			wantMessage: `oauth2: "invalid_client" "bad client credentials"`,
		},
		{
			name: "OAuth2 token endpoint unreachable",
			err: post(&url.Error{Op: "Post", URL: "https://idp.example.com/token",
				Err: dial(&net.DNSError{Err: "no such host", Name: "idp.example.com", IsNotFound: true})}),
			st:          traceState{noRoundTrip: true},
			tokenStage:  oauth2TokenStage,
			want:        result.ReasonAuth,
			wantMessage: `Post "https://idp.example.com/token": dial tcp: lookup idp.example.com: no such host`,
		},
		{
			name:        "OAuth2 target after the round trip started",
			err:         post(dial(refused)),
			st:          traceState{stage: "while connecting", connectFailed: true},
			tokenStage:  oauth2TokenStage,
			want:        result.ReasonConnect,
			wantMessage: "dial tcp: connect: connection refused",
		},
		{
			name:        "Kerberos target without a round trip and without a TokenError",
			err:         post(errors.New("net/http: invalid header field value")),
			st:          traceState{noRoundTrip: true},
			tokenStage:  kerberosTokenStage,
			want:        result.ReasonHTTP,
			wantMessage: "net/http: invalid header field value",
		},
		{
			name:        "deadline before the round trip without a token",
			err:         post(context.DeadlineExceeded),
			ctxErr:      context.DeadlineExceeded,
			st:          traceState{noRoundTrip: true},
			want:        result.ReasonTimeout,
			wantMessage: "timed out (timeout 2s)",
		},
		{
			name:        "deadline while connecting",
			err:         post(context.DeadlineExceeded),
			ctxErr:      context.DeadlineExceeded,
			st:          traceState{stage: "while connecting"},
			want:        result.ReasonTimeout,
			wantMessage: "timed out while connecting (timeout 2s)",
		},
		{
			name:        "deadline in the error only",
			err:         post(context.DeadlineExceeded),
			want:        result.ReasonTimeout,
			wantMessage: "timed out (timeout 2s)",
		},
		{
			name:        "the deadline explains any error",
			err:         post(dial(errors.New("i/o timeout"))),
			ctxErr:      context.DeadlineExceeded,
			st:          traceState{stage: "while connecting", connectFailed: true},
			want:        result.ReasonTimeout,
			wantMessage: "timed out while connecting (timeout 2s)",
		},
		{
			name:        "cancelled",
			err:         post(context.Canceled),
			ctxErr:      context.Canceled,
			want:        result.ReasonHTTP,
			wantMessage: "probe cancelled",
		},
		{
			name:        "protocol error",
			err:         post(errors.New(`net/http: HTTP/1.x transport connection broken: malformed HTTP response "SOAP/1.1"`)),
			want:        result.ReasonHTTP,
			wantMessage: `net/http: HTTP/1.x transport connection broken: malformed HTTP response "SOAP/1.1"`,
		},
		{
			name:        "multi-line error",
			err:         post(errors.New("oauth2: cannot fetch token: 400 Bad Request\nResponse: {\"error\":\"invalid_client\"}")),
			want:        result.ReasonHTTP,
			wantMessage: `oauth2: cannot fetch token: 400 Bad Request Response: {"error":"invalid_client"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Prober{target: target, tokenStage: tt.tokenStage}
			reason, msg := p.classify(tt.err, tt.ctxErr, tt.st)
			if reason != tt.want {
				t.Errorf("reason = %q, want %q (message %q)", reason, tt.want, msg)
			}
			if tt.wantMessage != "" && msg != tt.wantMessage {
				t.Errorf("message = %q, want %q", msg, tt.wantMessage)
			}
			if msg == "" || strings.Contains(msg, "https://soap.example.com") {
				t.Errorf("message = %q, want the error without the URL", msg)
			}
		})
	}
}

func TestOneLine(t *testing.T) {
	long := strings.Repeat("Ж", maxMessageLen)
	tests := []struct {
		in, want string
	}{
		{in: "a\n\tb  c\r\n", want: "a b c"},
		{in: long, want: long[:maxMessageLen] + "…"},
		{in: "a" + long, want: "a" + long[:maxMessageLen-2] + "…"},
	}
	for _, tt := range tests {
		if got := oneLine(tt.in); got != tt.want {
			t.Errorf("oneLine(%.20q…) = %.20q… (%d bytes), want %d bytes", tt.in, got, len(got), len(tt.want))
		}
	}
}
