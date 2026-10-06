package prober

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
)

func TestProbeRequestOnTheWire(t *testing.T) {
	tests := []struct {
		name    string
		version string
		extra   string
		// want lists header lines that must be sent exactly so, and only once by name.
		want []string
		// absent lists header names (any case) that must not be sent.
		absent []string
	}{
		{
			name:    "SOAP 1.1",
			version: "1.1",
			want: []string{
				`SOAPAction: "http://corp.example/GetOrders"`,
				"Content-Type: text/xml; charset=utf-8",
				"User-Agent: " + testUserAgent,
			},
		},
		{
			name:    "SOAP 1.1 without action",
			version: "1.1",
			extra:   "soap: {action: null}",
			want:    []string{`SOAPAction: ""`, "Content-Type: text/xml; charset=utf-8"},
		},
		{
			name:    "SOAP 1.2",
			version: "1.2",
			want: []string{
				`Content-Type: application/soap+xml; charset=utf-8; action="http://corp.example/GetOrders"`,
				"User-Agent: " + testUserAgent,
			},
			absent: []string{"SOAPAction"},
		},
		{
			name:    "SOAP 1.2 without action",
			version: "1.2",
			extra:   "soap: {action: null}",
			want:    []string{"Content-Type: application/soap+xml; charset=utf-8"},
			absent:  []string{"SOAPAction"},
		},
		{
			name:    "target headers override the User-Agent",
			version: "1.1",
			extra:   "headers: {user-agent: custom-agent/2.0, X-Request-Source: monitoring}",
			want:    []string{"User-Agent: custom-agent/2.0", "X-Request-Source: monitoring"},
		},
		{
			name:    "Host header",
			version: "1.1",
			extra:   "headers: {Host: soap.example.com}",
			want:    []string{"Host: soap.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := rawResponse("200 OK", "text/xml; charset=utf-8", fixture(t, "ok11.xml"))
			if tt.version == "1.2" {
				resp = rawResponse("200 OK", "application/soap+xml; charset=utf-8", fixture(t, "ok12.xml"))
			}
			srv := newRawServer(t, resp)
			tgt := loadTarget(t, srv.url("/Orders.asmx"), tt.version, tt.extra)
			p := newTestProber(t, tgt, hooks{})

			r := probe(t, p)
			if !r.Success {
				t.Errorf("probe failed: %s: %s", r.Reason, r.Message)
			}
			raw := srv.next(t)
			head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
			if !ok {
				t.Fatalf("no end of the header in %q", raw)
			}
			if !bytes.Equal(body, tgt.RequestBody) {
				t.Errorf("body = %q, want %q", body, tgt.RequestBody)
			}
			lines := strings.Split(string(head), "\r\n")
			if want := "POST /Orders.asmx HTTP/1.1"; lines[0] != want {
				t.Errorf("request line = %q, want %q", lines[0], want)
			}
			want := append([]string{
				"Content-Length: " + strconv.Itoa(len(tgt.RequestBody)),
				"Connection: close", // keep-alives are off by default
			}, tt.want...)
			for _, w := range want {
				name, _, _ := strings.Cut(w, ":")
				if !slices.Contains(lines, w) {
					t.Errorf("header line %q missing in\n%s", w, head)
				}
				if n := countHeader(lines, name); n != 1 {
					t.Errorf("header %s sent %d times", name, n)
				}
			}
			for _, name := range tt.absent {
				if countHeader(lines, name) != 0 {
					t.Errorf("header %s sent in\n%s", name, head)
				}
			}
		})
	}
}

// countHeader counts the header lines with the given name, ignoring case.
func countHeader(lines []string, name string) int {
	n := 0
	for _, l := range lines[1:] {
		if k, _, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, name) {
			n++
		}
	}
	return n
}

func TestProbeResponse(t *testing.T) {
	const cyrillic = "Центральный филиал"
	tests := []struct {
		name        string
		version     string
		extra       string
		status      int
		contentType string
		body        string // fixture name; "" is an empty body
		wantReason  result.Reason
		wantMessage string // a substring of the message
		wantCharset string // "" is utf-8
		noCharset   bool   // the body could not be decoded
		wantBody    string // a substring of the body snippet
	}{
		{
			name: "SOAP 1.1", version: "1.1", status: 200, contentType: "text/xml; charset=utf-8",
			body: "ok11.xml", wantBody: "<Status>Closed</Status>",
		},
		{
			name: "SOAP 1.2", version: "1.2", status: 200, contentType: "application/soap+xml; charset=utf-8",
			body: "ok12.xml", wantBody: "<Status>Closed</Status>",
		},
		{
			name: "XPath and regex checks", version: "1.1", status: 200, contentType: "text/xml",
			extra: `expect: {namespaces: {o: "http://corp.example/"}, xpath: ["count(//o:Order) = 2"], ` +
				`regex: ["<Id>2</Id>"]}`,
			body: "ok11.xml",
		},
		{
			name: "SOAP 1.1 fault with 500", version: "1.1", status: 500, contentType: "text/xml; charset=utf-8",
			body: "fault11.xml", wantReason: result.ReasonSOAPFault,
			wantMessage: "SOAP fault soap:Server: Database is unavailable",
		},
		{
			name: "SOAP 1.2 fault with 500", version: "1.2", status: 500, contentType: "application/soap+xml",
			body: "fault12.xml", wantReason: result.ReasonSOAPFault,
			wantMessage: "SOAP fault env:Receiver: Database is unavailable",
		},
		{
			name: "allowed fault with an unexpected status", version: "1.1", status: 500, contentType: "text/xml",
			extra: "expect: {allow_soap_fault: true}", body: "fault11.xml",
			wantReason: result.ReasonStatus, wantMessage: "got 500, want [200]",
		},
		{
			name: "status mismatch", version: "1.1", status: 503, contentType: "text/html",
			body: "error.html", wantReason: result.ReasonStatus, wantMessage: "got 503, want [200]",
		},
		{
			name: "HTML page with 200", version: "1.1", status: 200, contentType: "text/html",
			body: "error.html", wantReason: result.ReasonInvalidEnvelope, wantMessage: "DOCTYPE",
		},
		{
			name: "401", version: "1.1", status: 401, contentType: "text/html",
			wantReason: result.ReasonAuth, wantMessage: "got 401",
		},
		{
			name: "407", version: "1.1", status: 407, contentType: "text/html",
			wantReason: result.ReasonAuth, wantMessage: "got 407",
		},
		{
			name: "SOAP version mismatch", version: "1.1", status: 200, contentType: "text/xml",
			body: "ok12.xml", wantReason: result.ReasonInvalidEnvelope,
			wantMessage: "got a SOAP 1.2 envelope, want SOAP 1.1",
		},
		{
			name: "DOCTYPE", version: "1.1", status: 200, contentType: "text/xml",
			body: "doctype11.xml", wantReason: result.ReasonInvalidEnvelope, wantMessage: "DOCTYPE",
		},
		{
			name: "empty body with 202", version: "1.1", status: 202, extra: "expect: {status: [202]}",
		},
		{
			name: "windows-1251 by Content-Type", version: "1.1", status: 200,
			contentType: "text/xml; charset=windows-1251", extra: `expect: {regex: ["` + cyrillic + `"]}`,
			body: "branch-windows-1251.xml", wantCharset: "windows-1251", wantBody: cyrillic,
		},
		{
			name: "windows-1251 by the XML declaration", version: "1.1", status: 200,
			contentType: "text/xml", extra: `expect: {regex: ["` + cyrillic + `"]}`,
			body: "branch-windows-1251-decl.xml", wantCharset: "windows-1251", wantBody: cyrillic,
		},
		{
			name: "windows-1251 without a charset", version: "1.1", status: 200, contentType: "text/xml",
			body: "branch-windows-1251.xml", wantReason: result.ReasonInvalidEnvelope, wantMessage: "UTF-8",
		},
		{
			name: "BOM wins over Content-Type", version: "1.1", status: 200,
			contentType: "text/xml; charset=windows-1251", extra: `expect: {regex: ["` + cyrillic + `"]}`,
			body: "branch-utf8-bom.xml", wantBody: cyrillic,
		},
		{
			name: "unknown charset", version: "1.1", status: 200, contentType: "text/xml; charset=x-unknown",
			body: "ok11.xml", wantReason: result.ReasonInvalidEnvelope,
			wantMessage: `decode response body: unknown charset "x-unknown" in Content-Type`,
			noCharset:   true, wantBody: "<Status>Closed</Status>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body string
			if tt.body != "" {
				body = fixture(t, tt.body)
			}
			ts := newServer(t, soapHandler(tt.status, tt.contentType, body))
			p := newTestProber(t, loadTarget(t, ts.URL+"/Orders.asmx", tt.version, tt.extra), hooks{})

			r := probe(t, p)
			if r.Reason != tt.wantReason || !strings.Contains(r.Message, tt.wantMessage) {
				t.Errorf("reason, message = %q, %q; want %q, %q", r.Reason, r.Message, tt.wantReason, tt.wantMessage)
			}
			if !r.GotResponse || r.HTTPStatus != tt.status {
				t.Errorf("GotResponse, HTTPStatus = %v, %d; want true, %d", r.GotResponse, r.HTTPStatus, tt.status)
			}
			if got := r.ResponseHeader.Get("Content-Type"); tt.contentType != "" && got != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.contentType)
			}
			if r.BodySize != int64(len(body)) {
				t.Errorf("BodySize = %d, want %d", r.BodySize, len(body))
			}
			wantCharset := cmp.Or(tt.wantCharset, "utf-8")
			if tt.noCharset {
				wantCharset = ""
			}
			if r.Charset != wantCharset {
				t.Errorf("Charset = %q, want %q", r.Charset, wantCharset)
			}
			if !strings.Contains(r.Body, tt.wantBody) || r.BodyTruncated {
				t.Errorf("Body = %q (truncated %v), want it to contain %q", r.Body, r.BodyTruncated, tt.wantBody)
			}
			if len(r.Checks) == 0 {
				t.Error("no check outcomes")
			}
			if r.TLS != nil {
				t.Errorf("TLS = %+v for plain HTTP", r.TLS)
			}
		})
	}
}

func TestProbeBodySize(t *testing.T) {
	const limit = 1024
	tests := []struct {
		name    string
		size    int
		chunked bool
		want    result.Reason
	}{
		{name: "at the limit", size: limit},
		{name: "one byte over the limit", size: limit + 1, want: result.ReasonBodyTooLarge},
		{name: "chunked, at the limit", size: limit, chunked: true},
		{name: "chunked, one byte over the limit", size: limit + 1, chunked: true, want: result.ReasonBodyTooLarge},
		{name: "far over the limit", size: 1 << 20, chunked: true, want: result.ReasonBodyTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := paddedEnvelope(t, tt.size, " ")
			ts := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/xml; charset=utf-8")
				if !tt.chunked {
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				}
				_, _ = io.WriteString(w, body[:len(body)/2])
				if tt.chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, body[len(body)/2:])
			}))
			p := newTestProber(t, loadTarget(t, ts.URL, "1.1", "max_response_size: 1KiB"), hooks{})

			r := probe(t, p)
			if r.Reason != tt.want {
				t.Fatalf("reason = %q (%s), want %q", r.Reason, r.Message, tt.want)
			}
			wantSize := int64(min(tt.size, limit))
			if !r.GotResponse || r.HTTPStatus != http.StatusOK || r.BodySize != wantSize {
				t.Errorf("GotResponse, HTTPStatus, BodySize = %v, %d, %d; want true, 200, %d",
					r.GotResponse, r.HTTPStatus, r.BodySize, wantSize)
			}
			if tt.want != result.ReasonBodyTooLarge {
				return
			}
			if want := "response body exceeds max_response_size of 1KiB"; r.Message != want {
				t.Errorf("message = %q, want %q", r.Message, want)
			}
			if r.Body != body[:limit] || !r.BodyTruncated || r.Charset != "utf-8" {
				t.Errorf("Body = %q (truncated %v, charset %q), want the first %d bytes, truncated",
					r.Body, r.BodyTruncated, r.Charset, limit)
			}
			if len(r.Checks) != 0 {
				t.Errorf("checks ran on an incomplete body: %+v", r.Checks)
			}
		})
	}
}

func TestProbeBodySnippet(t *testing.T) {
	// Two-byte runes, with the snippet limit falling into the middle of one.
	body := paddedEnvelope(t, 100<<10, "Ж")
	if utf8.RuneStart(body[result.BodySnippetLimit]) {
		body = paddedEnvelope(t, 100<<10+1, "Ж") // one more space shifts the runes by a byte
	}
	ts := newServer(t, soapHandler(http.StatusOK, "text/xml; charset=utf-8", body))
	p := newTestProber(t, loadTarget(t, ts.URL, "1.1", ""), hooks{})

	r := probe(t, p)
	if !r.Success {
		t.Fatalf("probe failed: %s: %s", r.Reason, r.Message)
	}
	if r.BodySize != int64(len(body)) {
		t.Errorf("BodySize = %d, want %d", r.BodySize, len(body))
	}
	if !r.BodyTruncated || len(r.Body) != result.BodySnippetLimit-1 || !utf8.ValidString(r.Body) ||
		!strings.HasPrefix(body, r.Body) {
		t.Errorf("Body has %d bytes (truncated %v, valid UTF-8 %v), want the first %d bytes",
			len(r.Body), r.BodyTruncated, utf8.ValidString(r.Body), result.BodySnippetLimit-1)
	}
}

func TestProbeTimeout(t *testing.T) {
	tests := []struct {
		name         string
		handler      http.HandlerFunc
		wantMessage  string
		wantResponse bool
		wantPhases   []result.Phase
	}{
		{
			name:        "waiting for the response",
			handler:     func(_ http.ResponseWriter, r *http.Request) { block(r) },
			wantMessage: "timed out while waiting for the response (timeout 300ms)",
			wantPhases:  []result.Phase{result.PhaseConnect},
		},
		{
			name: "slow body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "text/xml")
				_, _ = io.WriteString(w, "<soap:Envelope")
				w.(http.Flusher).Flush()
				block(r)
			},
			wantMessage:  "timed out while reading the response body (timeout 300ms)",
			wantResponse: true,
			wantPhases:   []result.Phase{result.PhaseConnect, result.PhaseProcessing, result.PhaseTransfer},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newServer(t, tt.handler)
			p := newTestProber(t, loadTarget(t, ts.URL, "1.1", "timeout: 300ms"), hooks{})

			r := probe(t, p)
			if r.Reason != result.ReasonTimeout || r.Message != tt.wantMessage {
				t.Errorf("reason, message = %q, %q; want timeout, %q", r.Reason, r.Message, tt.wantMessage)
			}
			if d := r.Duration(); d < 300*time.Millisecond || d > 3*time.Second {
				t.Errorf("duration = %v, want about 300ms", d)
			}
			if r.GotResponse != tt.wantResponse {
				t.Errorf("GotResponse = %v, want %v", r.GotResponse, tt.wantResponse)
			}
			if tt.wantResponse && (r.HTTPStatus != http.StatusOK || r.BodySize != int64(len("<soap:Envelope"))) {
				t.Errorf("HTTPStatus, BodySize = %d, %d; want 200, %d", r.HTTPStatus, r.BodySize, len("<soap:Envelope"))
			}
			if got := phaseNames(r); !slices.Equal(got, tt.wantPhases) {
				t.Errorf("phases = %v, want %v", got, tt.wantPhases)
			}
		})
	}
}

// TestProbeOAuth2TokenHangs checks that the deadline holds although prometheus/common fetches
// OAuth2 tokens without the request context.
func TestProbeOAuth2TokenHangs(t *testing.T) {
	tests := []struct {
		name        string
		cancel      bool
		wantReason  result.Reason
		wantMessage string
	}{
		{
			name:        "deadline",
			wantReason:  result.ReasonTimeout,
			wantMessage: "timed out while acquiring an OAuth2 token (timeout 300ms)",
		},
		{name: "cancelled", cancel: true, wantReason: result.ReasonHTTP, wantMessage: "probe cancelled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tokenRequests, soapRequests atomic.Int32
			token := newServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				tokenRequests.Add(1)
				block(r)
			}))
			ok := okHandler(t)
			ts := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				soapRequests.Add(1)
				ok(w, r)
			}))
			extra := "timeout: 300ms\noauth2: {client_id: monitor, client_secret: secret, token_url: " +
				token.URL + "/token}"
			p := newTestProber(t, loadTarget(t, ts.URL, "1.1", extra), hooks{})

			ctx := t.Context()
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				time.AfterFunc(100*time.Millisecond, cancel)
			}
			r := probeContext(ctx, t, p)
			if r.Reason != tt.wantReason || r.Message != tt.wantMessage {
				t.Errorf("reason, message = %q, %q; want %q, %q", r.Reason, r.Message, tt.wantReason, tt.wantMessage)
			}
			if d := r.Duration(); d > 3*time.Second {
				t.Errorf("duration = %v, want the probe to end at its deadline", d)
			}
			if n := tokenRequests.Load(); n != 1 {
				t.Errorf("token endpoint got %d requests, want 1", n)
			}
			if n := soapRequests.Load(); n != 0 {
				t.Errorf("service got %d requests without a token", n)
			}
		})
	}
}

// TestProbeOAuth2Token checks that a failed OAuth2 token acquisition is reason auth, like a
// failed Kerberos token acquisition.
func TestProbeOAuth2Token(t *testing.T) {
	closedPort := func(t *testing.T) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return "http://" + addr + "/token"
	}
	tokenEndpoint := func(status int, body string) func(t *testing.T) string {
		return func(t *testing.T) string {
			ts := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			}))
			return ts.URL + "/token"
		}
	}
	tests := []struct {
		name        string
		tokenURL    func(t *testing.T) string
		wantReason  result.Reason
		wantMessage string
		wantSOAP    int32 // requests that reached the service
	}{
		{
			name:       "token issued",
			tokenURL:   tokenEndpoint(http.StatusOK, `{"access_token":"t0ken","token_type":"Bearer","expires_in":3600}`),
			wantReason: result.ReasonNone,
			wantSOAP:   1,
		},
		{
			name:        "client credentials rejected",
			tokenURL:    tokenEndpoint(http.StatusUnauthorized, `{"error":"invalid_client","error_description":"bad client credentials"}`),
			wantReason:  result.ReasonAuth,
			wantMessage: `oauth2: "invalid_client" "bad client credentials"`,
		},
		{
			name:        "token endpoint refuses connections",
			tokenURL:    closedPort,
			wantReason:  result.ReasonAuth,
			wantMessage: "connection refused",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var soapRequests atomic.Int32
			ok := okHandler(t)
			ts := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				soapRequests.Add(1)
				if got := r.Header.Get("Authorization"); got != "Bearer t0ken" {
					t.Errorf("Authorization = %q, want the issued token", got)
				}
				ok(w, r)
			}))
			extra := "oauth2: {client_id: monitor, client_secret: secret, token_url: " + tt.tokenURL(t) + "}"
			p := newTestProber(t, loadTarget(t, ts.URL, "1.1", extra), hooks{})

			r := probe(t, p)
			if r.Reason != tt.wantReason || !strings.Contains(r.Message, tt.wantMessage) {
				t.Errorf("reason, message = %q, %q; want %q, %q", r.Reason, r.Message, tt.wantReason, tt.wantMessage)
			}
			if r.Success != (tt.wantReason == result.ReasonNone) {
				t.Errorf("Success = %v", r.Success)
			}
			if n := soapRequests.Load(); n != tt.wantSOAP {
				t.Errorf("service got %d requests, want %d", n, tt.wantSOAP)
			}
		})
	}
}

// TestProbeResponsePhases checks processing and transfer when the first response byte is not
// the start of the final response.
func TestProbeResponsePhases(t *testing.T) {
	const delay = 200 * time.Millisecond
	ok := okHandler(t)
	tests := []struct {
		name     string
		extra    string
		h2       bool
		bodySize int // of the request; 0 keeps the target's body
		handler  http.HandlerFunc
		// earlyResponse: the server answers before the request is written, so processing is 0.
		earlyResponse bool
	}{
		{
			name:  "Expect: 100-continue",
			extra: "headers: {Expect: 100-continue}",
			handler: func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				time.Sleep(delay)
				ok(w, r)
			},
		},
		{
			name: "103 Early Hints",
			handler: func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.WriteHeader(http.StatusEarlyHints)
				time.Sleep(delay)
				ok(w, r)
			},
		},
		{
			name: "103 Early Hints over HTTP/2",
			h2:   true,
			handler: func(w http.ResponseWriter, r *http.Request) {
				drainBody(r)
				w.WriteHeader(http.StatusEarlyHints)
				time.Sleep(delay)
				ok(w, r)
			},
		},
		{
			name:     "response before the request was written",
			bodySize: 16 << 20, // more than the socket buffers hold
			handler: func(w http.ResponseWriter, r *http.Request) {
				if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", "text/xml; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				time.Sleep(delay)
				drainBody(r)
				_, _ = io.WriteString(w, fixture(t, "ok11.xml"))
			},
			earlyResponse: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tgt *config.Target
			var h hooks
			if tt.h2 {
				ts, caFile := newTLSServer(t, tt.handler, true, nil)
				url := "https://example.com:" + port(t, ts) + "/Orders.svc"
				tgt = loadTarget(t, url, "1.1", "tls_config: {ca_file: "+caFile+"}\nenable_http2: true")
				h.resolver = fakeResolver(map[string]string{"example.com": "127.0.0.1"})
			} else {
				tgt = loadTarget(t, newServer(t, tt.handler).URL, "1.1", tt.extra)
			}
			if tt.bodySize > 0 {
				tgt.RequestBody = bytes.Repeat([]byte(" "), tt.bodySize)
			}
			p := newTestProber(t, tgt, h)

			r := probe(t, p)
			if !r.Success {
				t.Fatalf("probe failed: %s: %s", r.Reason, r.Message)
			}
			processing, okP := r.Phases[result.PhaseProcessing]
			transfer, okT := r.Phases[result.PhaseTransfer]
			if !okP || !okT {
				t.Fatalf("phases = %v, want processing and transfer", r.Phases)
			}
			switch {
			case tt.earlyResponse && processing != 0:
				t.Errorf("processing = %v, want 0", processing)
			case !tt.earlyResponse && processing < delay/2:
				t.Errorf("processing = %v, want about %v", processing, delay)
			}
			if transfer >= delay/2 {
				t.Errorf("transfer = %v, want far less than %v", transfer, delay)
			}
		})
	}
}

func TestProbeTooManyInformational(t *testing.T) {
	ok := okHandler(t)
	ts := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drainBody(r)
		for range maxInformational + 1 {
			w.WriteHeader(http.StatusEarlyHints)
		}
		ok(w, r)
	}))
	p := newTestProber(t, loadTarget(t, ts.URL, "1.1", ""), hooks{})

	r := probe(t, p)
	if want := "too many 1xx informational responses"; r.Reason != result.ReasonHTTP ||
		!strings.Contains(r.Message, want) {
		t.Errorf("reason, message = %q, %q; want http, %q", r.Reason, r.Message, want)
	}
}

// phaseNames returns the phases of r in the order of result.AllPhases.
func phaseNames(r result.Result) []result.Phase {
	var names []result.Phase
	for _, p := range result.AllPhases {
		if _, ok := r.Phases[p]; ok {
			names = append(names, p)
		}
	}
	return names
}

func TestProbeTransportErrors(t *testing.T) {
	closedPort := func(t *testing.T) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return "http://" + addr + "/Orders.asmx"
	}
	tests := []struct {
		name        string
		url         func(t *testing.T) string
		wantReason  result.Reason
		wantMessage string
		wantStatus  int
		wantPhases  []result.Phase
	}{
		{
			name:        "unresolvable host",
			url:         func(*testing.T) string { return "http://nonexistent.invalid/Orders.asmx" },
			wantReason:  result.ReasonDNS,
			wantMessage: "lookup nonexistent.invalid",
			wantPhases:  []result.Phase{result.PhaseResolve},
		},
		{
			name:        "connection refused",
			url:         closedPort,
			wantReason:  result.ReasonConnect,
			wantMessage: "connection refused",
			wantPhases:  []result.Phase{result.PhaseConnect},
		},
		{
			name: "truncated response",
			url: func(t *testing.T) string {
				ts := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					c, buf, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer c.Close()
					_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 1000\r\n\r\n<soap:Envelope")
					_ = buf.Flush()
				}))
				return ts.URL
			},
			wantReason:  result.ReasonHTTP,
			wantMessage: "read response body: unexpected EOF",
			wantStatus:  http.StatusOK,
			wantPhases:  []result.Phase{result.PhaseConnect, result.PhaseProcessing, result.PhaseTransfer},
		},
		{
			name: "malformed response",
			url: func(t *testing.T) string {
				return newRawServer(t, "SOAP/1.1 OK\r\n\r\n").url("/Orders.asmx")
			},
			wantReason:  result.ReasonHTTP,
			wantMessage: "malformed HTTP",
			wantPhases:  []result.Phase{result.PhaseConnect, result.PhaseProcessing},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestProber(t, loadTarget(t, tt.url(t), "1.1", ""), hooks{resolver: fakeResolver(nil)})

			r := probe(t, p)
			if r.Reason != tt.wantReason || !strings.Contains(r.Message, tt.wantMessage) {
				t.Errorf("reason, message = %q, %q; want %q, %q", r.Reason, r.Message, tt.wantReason, tt.wantMessage)
			}
			if r.GotResponse != (tt.wantStatus != 0) || r.HTTPStatus != tt.wantStatus {
				t.Errorf("GotResponse, HTTPStatus = %v, %d; want status %d", r.GotResponse, r.HTTPStatus, tt.wantStatus)
			}
			if len(r.Checks) != 0 {
				t.Errorf("checks ran after a transport error: %+v", r.Checks)
			}
			if got := phaseNames(r); !slices.Equal(got, tt.wantPhases) {
				t.Errorf("phases = %v, want %v", got, tt.wantPhases)
			}
		})
	}
}

func TestProbeTLS(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run("enable_http2="+strconv.FormatBool(h2), func(t *testing.T) {
			var (
				mu    sync.Mutex
				proto string
				state *tls.ConnectionState
			)
			ok := okHandler(t)
			ts, caFile := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				proto, state = r.Proto, r.TLS
				mu.Unlock()
				ok(w, r)
			}), true, nil)
			url := "https://example.com:" + port(t, ts) + "/Orders.svc"
			extra := "tls_config: {ca_file: " + caFile + "}\nenable_http2: " + strconv.FormatBool(h2)
			p := newTestProber(t, loadTarget(t, url, "1.1", extra),
				hooks{resolver: fakeResolver(map[string]string{"example.com": "127.0.0.1"})})

			r := probe(t, p)
			if !r.Success {
				t.Fatalf("probe failed: %s: %s", r.Reason, r.Message)
			}
			mu.Lock()
			defer mu.Unlock()
			wantProto := "HTTP/1.1"
			if h2 {
				wantProto = "HTTP/2.0"
			}
			if proto != wantProto {
				t.Errorf("server saw %s, want %s", proto, wantProto)
			}
			cert := ts.Certificate()
			want := result.TLSInfo{
				Version:     tls.VersionName(state.Version),
				CipherSuite: tls.CipherSuiteName(state.CipherSuite),
				ServerName:  "example.com",
				Chain: []result.CertInfo{{
					Subject:   cert.Subject.String(),
					Issuer:    cert.Issuer.String(),
					NotBefore: cert.NotBefore,
					NotAfter:  cert.NotAfter,
					DNSNames:  cert.DNSNames,
				}},
			}
			if r.TLS == nil || !tlsInfoEqual(*r.TLS, want) {
				t.Errorf("TLS = %+v, want %+v", r.TLS, want)
			}
			if got := phaseNames(r); !slices.Equal(got, result.AllPhases) {
				t.Errorf("phases = %v, want all of %v", got, result.AllPhases)
			}
			for phase, d := range r.Phases {
				if d <= 0 {
					t.Errorf("phase %s = %v, want > 0", phase, d)
				}
			}
		})
	}
}

func tlsInfoEqual(a, b result.TLSInfo) bool {
	return a.Version == b.Version && a.CipherSuite == b.CipherSuite && a.ServerName == b.ServerName &&
		slices.EqualFunc(a.Chain, b.Chain, func(x, y result.CertInfo) bool {
			return x.Subject == y.Subject && x.Issuer == y.Issuer && x.NotBefore.Equal(y.NotBefore) &&
				x.NotAfter.Equal(y.NotAfter) && slices.Equal(x.DNSNames, y.DNSNames)
		})
}

func TestProbeTLSErrors(t *testing.T) {
	tests := []struct {
		name        string
		url         func(ts, plain string) string
		caFile      bool
		wantMessage string
	}{
		{
			name:        "untrusted certificate",
			url:         func(ts, _ string) string { return ts },
			wantMessage: "certificate signed by unknown authority",
		},
		{
			name:        "host name mismatch",
			url:         func(ts, _ string) string { return strings.Replace(ts, "127.0.0.1", "soap.example.org", 1) },
			caFile:      true,
			wantMessage: "not soap.example.org",
		},
		{
			name:        "plain HTTP server",
			url:         func(_, plain string) string { return strings.Replace(plain, "http:", "https:", 1) },
			caFile:      true,
			wantMessage: "server gave HTTP response to HTTPS client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, caFile := newTLSServer(t, okHandler(t), false, nil)
			plain := newServer(t, okHandler(t))
			var extra string
			if tt.caFile {
				extra = "tls_config: {ca_file: " + caFile + "}"
			}
			p := newTestProber(t, loadTarget(t, tt.url(ts.URL, plain.URL), "1.1", extra),
				hooks{resolver: fakeResolver(map[string]string{"soap.example.org": "127.0.0.1"})})

			r := probe(t, p)
			if r.Reason != result.ReasonTLS || !strings.Contains(r.Message, tt.wantMessage) {
				t.Errorf("reason, message = %q, %q; want tls, %q", r.Reason, r.Message, tt.wantMessage)
			}
			if r.GotResponse {
				t.Error("GotResponse = true")
			}
			if _, ok := r.Phases[result.PhaseTLS]; !ok {
				t.Errorf("phases = %v, want a tls phase", r.Phases)
			}
		})
	}
}

func TestProbeKeepAlive(t *testing.T) {
	for _, keepAlive := range []bool{false, true} {
		t.Run("keep_alive="+strconv.FormatBool(keepAlive), func(t *testing.T) {
			var conns atomic.Int32
			closed := make(chan struct{}, 1)
			ts, caFile := newTLSServer(t, okHandler(t), false, func(_ net.Conn, s http.ConnState) {
				switch s {
				case http.StateNew:
					conns.Add(1)
				case http.StateClosed:
					select {
					case closed <- struct{}{}:
					default:
					}
				}
			})
			url := "https://example.com:" + port(t, ts) + "/Orders.svc"
			extra := "tls_config: {ca_file: " + caFile + "}\nkeep_alive: " + strconv.FormatBool(keepAlive)
			p := newTestProber(t, loadTarget(t, url, "1.1", extra),
				hooks{resolver: fakeResolver(map[string]string{"example.com": "127.0.0.1"})})

			first, second := probe(t, p), probe(t, p)
			if !first.Success || !second.Success {
				t.Fatalf("probes failed: %s: %s; %s: %s", first.Reason, first.Message, second.Reason, second.Message)
			}
			wantConns, wantSecond := int32(2), result.AllPhases
			if keepAlive {
				wantConns, wantSecond = 1, []result.Phase{result.PhaseProcessing, result.PhaseTransfer}
			}
			if n := conns.Load(); n != wantConns {
				t.Errorf("server saw %d connections, want %d", n, wantConns)
			}
			if got := phaseNames(first); !slices.Equal(got, result.AllPhases) {
				t.Errorf("first probe phases = %v, want %v", got, result.AllPhases)
			}
			if got := phaseNames(second); !slices.Equal(got, wantSecond) {
				t.Errorf("second probe phases = %v, want %v", got, wantSecond)
			}
			if second.TLS == nil {
				t.Error("no TLS state on a reused connection")
			}
			if keepAlive {
				p.Close()
				select {
				case <-closed:
				case <-time.After(5 * time.Second):
					t.Error("Close() did not close the idle connection")
				}
			}
		})
	}
}

func TestProbeRedirect(t *testing.T) {
	tests := []struct {
		name        string
		follow      bool
		loop        bool
		wantReason  result.Reason
		wantMessage string
		wantStatus  int
	}{
		{name: "not followed", wantReason: result.ReasonStatus, wantMessage: "got 307", wantStatus: 307},
		{name: "followed", follow: true, wantStatus: 200},
		{
			name: "redirect loop", follow: true, loop: true,
			wantReason: result.ReasonHTTP, wantMessage: "stopped after 10 redirects", wantStatus: 307,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var finalBody atomic.Value
			ok := okHandler(t)
			mux := http.NewServeMux()
			mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/new", http.StatusTemporaryRedirect)
			})
			mux.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
				if tt.loop {
					http.Redirect(w, r, "/old", http.StatusTemporaryRedirect)
					return
				}
				b, _ := io.ReadAll(r.Body)
				finalBody.Store(string(b))
				ok(w, r)
			})
			ts := newServer(t, mux)
			tgt := loadTarget(t, ts.URL+"/old", "1.1", "follow_redirects: "+strconv.FormatBool(tt.follow))
			p := newTestProber(t, tgt, hooks{})

			r := probe(t, p)
			if r.Reason != tt.wantReason || !strings.Contains(r.Message, tt.wantMessage) {
				t.Errorf("reason, message = %q, %q; want %q, %q", r.Reason, r.Message, tt.wantReason, tt.wantMessage)
			}
			if r.HTTPStatus != tt.wantStatus {
				t.Errorf("HTTPStatus = %d, want %d", r.HTTPStatus, tt.wantStatus)
			}
			if tt.follow && !tt.loop && finalBody.Load() != string(tgt.RequestBody) {
				t.Errorf("redirected request body = %q, want %q", finalBody.Load(), tgt.RequestBody)
			}
		})
	}
}

func TestProbeKerberos(t *testing.T) {
	tests := []struct {
		name        string
		cred        *fakeCredential
		extra       string
		status      int
		wantReason  result.Reason
		wantMessage string
		wantSPN     string
		wantAuth    string // the Authorization header the server saw
		wantResets  int32
	}{
		{
			name:     "token",
			cred:     &fakeCredential{token: []byte("token")},
			status:   http.StatusOK,
			wantSPN:  "HTTP/127.0.0.1",
			wantAuth: "Negotiate dG9rZW4=",
		},
		{
			name:     "explicit SPN",
			cred:     &fakeCredential{token: []byte("token")},
			extra:    "spn: HTTP/soap.example.com",
			status:   http.StatusOK,
			wantSPN:  "HTTP/soap.example.com",
			wantAuth: "Negotiate dG9rZW4=",
		},
		{
			name:        "401 resets the credential",
			cred:        &fakeCredential{token: []byte("token")},
			status:      http.StatusUnauthorized,
			wantReason:  result.ReasonAuth,
			wantMessage: "got 401, want [200]",
			wantSPN:     "HTTP/127.0.0.1",
			wantAuth:    "Negotiate dG9rZW4=",
			wantResets:  1,
		},
		{
			name:        "token error",
			cred:        &fakeCredential{err: errors.New("KDC_ERR_C_PRINCIPAL_UNKNOWN\nclient not found")},
			wantReason:  result.ReasonAuth,
			wantMessage: "kerberos: token for HTTP/127.0.0.1: KDC_ERR_C_PRINCIPAL_UNKNOWN client not found",
			wantSPN:     "HTTP/127.0.0.1",
		},
		{
			name:        "token timeout",
			cred:        &fakeCredential{block: true},
			wantReason:  result.ReasonTimeout,
			wantMessage: "timed out while acquiring a Kerberos token (timeout 300ms)",
			wantSPN:     "HTTP/127.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var auth atomic.Value
			ts := newServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth.Store(r.Header.Get("Authorization"))
				if tt.status == http.StatusUnauthorized {
					w.Header().Add("WWW-Authenticate", "Negotiate")
					w.Header().Add("WWW-Authenticate", "NTLM")
				}
				soapHandler(tt.status, "text/xml; charset=utf-8", fixture(t, "ok11.xml"))(w, r)
			}))
			extra := "timeout: 300ms\nkerberos:\n  principal: monitor@CORP.EXAMPLE\n  keytab: monitor.keytab\n"
			if tt.extra != "" {
				extra += "  " + tt.extra + "\n"
			}
			p := newTestProberWithCred(t, loadTarget(t, ts.URL, "1.1", extra), tt.cred, hooks{})

			r := probe(t, p)
			if r.Reason != tt.wantReason || r.Message != tt.wantMessage {
				t.Errorf("reason, message = %q, %q; want %q, %q", r.Reason, r.Message, tt.wantReason, tt.wantMessage)
			}
			if r.SPN != tt.wantSPN {
				t.Errorf("SPN = %q, want %q", r.SPN, tt.wantSPN)
			}
			if got := tt.cred.requestedSPNs(); !slices.Equal(got, []string{tt.wantSPN}) {
				t.Errorf("tokens requested for %q, want [%q]", got, tt.wantSPN)
			}
			if got, _ := auth.Load().(string); got != tt.wantAuth {
				t.Errorf("server saw Authorization %q, want %q", got, tt.wantAuth)
			}
			if got := tt.cred.resets.Load(); got != tt.wantResets {
				t.Errorf("credential reset %d times, want %d", got, tt.wantResets)
			}
		})
	}
}

func TestProbePanic(t *testing.T) {
	ts := newServer(t, okHandler(t))
	var logs bytes.Buffer
	tgt := loadTarget(t, ts.URL, "1.1", "")
	p, err := newProber(tgt, nil, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))}, hooks{
		wrap: func(http.RoundTripper) http.RoundTripper {
			return roundTripperFunc(func(*http.Request) (*http.Response, error) { panic("boom") })
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	r := probe(t, p)
	if r.Reason != result.ReasonInternal || r.Message != "panic: boom" {
		t.Errorf("reason, message = %q, %q; want internal, %q", r.Reason, r.Message, "panic: boom")
	}
	if out := logs.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "Probe panicked") ||
		!strings.Contains(out, "stack=") {
		t.Errorf("log = %q, want an error with the stack", out)
	}
}

func TestProbeConcurrent(t *testing.T) {
	ts := newServer(t, okHandler(t))
	p := newTestProber(t, loadTarget(t, ts.URL, "1.1", ""), hooks{})
	const n = 16
	results := make([]result.Result, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { results[i] = p.Probe(t.Context()) })
	}
	wg.Wait()
	for i, r := range results {
		if err := checkInvariants(p, r); err != nil {
			t.Errorf("probe %d: %v", i, err)
		}
		if !r.Success {
			t.Errorf("probe %d failed: %s: %s", i, r.Reason, r.Message)
		}
	}
}

func TestProbeCancelled(t *testing.T) {
	ts := newServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { block(r) }))
	p := newTestProber(t, loadTarget(t, ts.URL, "1.1", ""), hooks{})

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)
	r := probeContext(ctx, t, p)
	if r.Reason != result.ReasonHTTP || r.Message != "probe cancelled" {
		t.Errorf("reason, message = %q, %q; want http, %q", r.Reason, r.Message, "probe cancelled")
	}
	if d := r.Duration(); d > 3*time.Second {
		t.Errorf("cancelled probe took %v", d)
	}
}

func TestNew(t *testing.T) {
	plain := loadTarget(t, "http://soap.example.com/Orders.asmx", "1.1", "")
	krb := loadTarget(t, "http://soap.example.com/Orders.asmx", "1.1",
		"kerberos: {principal: monitor@CORP.EXAMPLE, keytab: monitor.keytab}")
	missingCA := loadTarget(t, "https://soap.example.com/Orders.svc", "1.1", "")
	missingCA.HTTPClientConfig.TLSConfig.CAFile = "/nonexistent/ca.pem"
	noURL := *plain
	noURL.ParsedURL = nil

	tests := []struct {
		name    string
		target  *config.Target
		cred    *fakeCredential
		wantErr string
	}{
		{name: "plain", target: plain},
		{name: "kerberos", target: krb, cred: &fakeCredential{}},
		{name: "credential without kerberos settings", target: plain, cred: &fakeCredential{}, wantErr: "without kerberos settings"},
		{name: "kerberos settings without credential", target: krb, wantErr: "no kerberos credential"},
		{name: "missing CA file", target: missingCA, wantErr: "/nonexistent/ca.pem"},
		{name: "no parsed URL", target: &noURL, wantErr: "URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p *Prober
			var err error
			if tt.cred != nil {
				p, err = New(tt.target, tt.cred, Options{})
			} else {
				p, err = New(tt.target, nil, Options{})
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("New() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer p.Close()
			if p.Target() != tt.target {
				t.Error("Target() does not return the target")
			}
		})
	}
}

func TestSnippet(t *testing.T) {
	limit := result.BodySnippetLimit
	tests := []struct {
		name      string
		text      string
		want      int
		truncated bool
	}{
		{name: "short", text: "<a/>", want: 4},
		{name: "at the limit", text: strings.Repeat("a", limit), want: limit},
		{name: "ASCII over the limit", text: strings.Repeat("a", limit+1), want: limit, truncated: true},
		{name: "cut inside a rune", text: "a" + strings.Repeat("Ж", limit), want: limit - 1, truncated: true},
		{name: "cut before a rune", text: strings.Repeat("Ж", limit), want: limit, truncated: true},
		{name: "four-byte runes", text: "ab" + strings.Repeat("😀", limit), want: limit - 2, truncated: true},
		{name: "invalid UTF-8", text: strings.Repeat("\x80", limit+1), want: limit, truncated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, truncated := snippet(tt.text)
			if len(got) != tt.want || truncated != tt.truncated || !strings.HasPrefix(tt.text, got) {
				t.Errorf("snippet() = %d bytes, %v; want %d bytes, %v", len(got), truncated, tt.want, tt.truncated)
			}
		})
	}
}
