package prober

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/soap"
)

const testUserAgent = "soap_exporter/test"

// loadTarget loads one target named "orders" through config.LoadBytes, so that every
// default applies. version selects the SOAP version of the request; extra holds further
// target fields as unindented YAML. The config directory holds monitor.keytab, a dummy
// keytab for kerberos settings.
func loadTarget(t testing.TB, url, version, extra string) *config.Target {
	t.Helper()
	ns := soap.NS11
	if version == "1.2" {
		ns = soap.NS12
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "monitor.keytab"), []byte("not read by the prober"), 0o600); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `defaults:
  timeout: 5s
  soap: {version: %q, action: "http://corp.example/GetOrders"}
targets:
  - name: orders
    url: %s
    body: '<s:Envelope xmlns:s="%s"><s:Body><GetOrders xmlns="http://corp.example/"/></s:Body></s:Envelope>'
`, version, url, ns)
	for line := range strings.Lines(extra) {
		b.WriteString("    " + line)
	}
	b.WriteString("\n")
	c, err := config.LoadBytes([]byte(b.String()), dir)
	if err != nil {
		t.Fatalf("load config: %v\n%s", err, b.String())
	}
	return c.Targets[0]
}

// newTestProber builds a prober and closes it when the test ends.
func newTestProber(t testing.TB, tgt *config.Target, h hooks) *Prober {
	t.Helper()
	return newTestProberWithCred(t, tgt, nil, h)
}

func newTestProberWithCred(t testing.TB, tgt *config.Target, cred *fakeCredential, h hooks) *Prober {
	t.Helper()
	var p *Prober
	var err error
	if cred != nil {
		p, err = newProber(tgt, cred, Options{UserAgent: testUserAgent}, h)
	} else {
		p, err = newProber(tgt, nil, Options{UserAgent: testUserAgent}, h)
	}
	if err != nil {
		t.Fatalf("newProber() error = %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

// probe runs a probe and checks the invariants every result must satisfy.
func probe(t testing.TB, p *Prober) result.Result {
	t.Helper()
	return probeContext(t.Context(), t, p)
}

func probeContext(ctx context.Context, t testing.TB, p *Prober) result.Result {
	t.Helper()
	r := p.Probe(ctx)
	if err := checkInvariants(p, r); err != nil {
		t.Fatalf("%v\nresult: %+v", err, r)
	}
	return r
}

func checkInvariants(p *Prober, r result.Result) error {
	switch {
	case r.Target != p.target.Name:
		return fmt.Errorf("Target = %q, want %q", r.Target, p.target.Name)
	case r.Start.IsZero() || r.End.Before(r.Start):
		return fmt.Errorf("Start = %v, End = %v", r.Start, r.End)
	case r.Success != (r.Reason == result.ReasonNone):
		return fmt.Errorf("Success = %v with reason %q", r.Success, r.Reason)
	case r.Success && r.Message != "":
		return fmt.Errorf("successful probe with message %q", r.Message)
	case !r.Success && r.Message == "":
		return fmt.Errorf("failed probe (%s) without a message", r.Reason)
	case strings.ContainsAny(r.Message, "\r\n"):
		return fmt.Errorf("message %q spans several lines", r.Message)
	case !r.GotResponse && (r.HTTPStatus != 0 || r.ResponseHeader != nil || r.BodySize != 0 ||
		r.TLS != nil || len(r.Checks) > 0):
		return fmt.Errorf("response fields set without a response")
	case len(r.Body) > result.BodySnippetLimit:
		return fmt.Errorf("body snippet has %d bytes", len(r.Body))
	case r.SPN != p.spn:
		return fmt.Errorf("SPN = %q, want %q", r.SPN, p.spn)
	}
	for phase, d := range r.Phases {
		if d < 0 {
			return fmt.Errorf("phase %s = %v", phase, d)
		}
	}
	return nil
}

// fixture returns the contents of a file in testdata.
func fixture(t testing.TB, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// paddedEnvelope returns a SOAP 1.1 response of exactly size bytes, padded in a comment
// with pad repeated, preceded by spaces if size requires.
func paddedEnvelope(t testing.TB, size int, pad string) string {
	t.Helper()
	const (
		head = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` +
			`<GetOrdersResponse xmlns="http://corp.example/"/><!--`
		tail = `--></soap:Body></soap:Envelope>`
	)
	n := size - len(head) - len(tail)
	if n < 0 {
		t.Fatalf("an envelope cannot be shorter than %d bytes", len(head)+len(tail))
	}
	return head + strings.Repeat(" ", n%len(pad)) + strings.Repeat(pad, n/len(pad)) + tail
}

// soapHandler answers every request with status, contentType and body.
func soapHandler(status int, contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// okHandler answers with the successful SOAP 1.1 response.
func okHandler(t testing.TB) http.HandlerFunc {
	return soapHandler(http.StatusOK, "text/xml; charset=utf-8", fixture(t, "ok11.xml"))
}

// drainBody reads the request body. Only then does the server watch the connection and
// cancel the request context when the client goes away.
func drainBody(r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
}

// block blocks a handler until the client goes away or the server is closed.
func block(r *http.Request) {
	drainBody(r)
	<-r.Context().Done()
}

// newServer starts an httptest server that is closed when the test ends.
func newServer(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(func() { closeServer(ts) })
	return ts
}

// closeServer closes ts and the connections of blocked handlers, which Close would wait for.
func closeServer(ts *httptest.Server) {
	ts.CloseClientConnections()
	ts.Close()
}

// newTLSServer starts an httptest TLS server (with HTTP/2 if h2) and writes its
// certificate to a CA file. Its certificate is valid for example.com and 127.0.0.1.
func newTLSServer(t testing.TB, h http.Handler, h2 bool, connState func(net.Conn, http.ConnState)) (ts *httptest.Server, caFile string) {
	t.Helper()
	ts = httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = h2
	ts.Config.ConnState = connState
	ts.Config.ErrorLog = log.New(io.Discard, "", 0) // failed handshakes are expected
	ts.StartTLS()
	t.Cleanup(func() { closeServer(ts) })
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return ts, caFile
}

// port returns the port of an httptest server.
func port(t testing.TB, ts *httptest.Server) string {
	t.Helper()
	_, p, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeResolver answers from hosts (name → IPv4 address) without network access: the Go
// resolver talks to serveDNS over an in-memory pipe. Other names get NXDOMAIN; AAAA
// queries for known names get no answers.
func fakeResolver(hosts map[string]string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go serveDNS(server, hosts)
			return client, nil
		},
	}
}

// serveDNS answers one query in TCP framing, which the resolver uses for a conn that is not
// a net.PacketConn.
func serveDNS(c net.Conn, hosts map[string]string) {
	defer c.Close()
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, msg); err != nil {
		return
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	addr, known := hosts[strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")]
	rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true}
	if !known {
		rh.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(make([]byte, 2, 512), rh)
	_ = b.StartQuestions()
	_ = b.Question(q)
	if known && q.Type == dnsmessage.TypeA {
		_ = b.StartAnswers()
		_ = b.AResource(
			dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: netip.MustParseAddr(addr).As4()})
	}
	out, err := b.Finish()
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(out, uint16(len(out)-2))
	_, _ = c.Write(out)
}

// rawServer answers every request with a fixed response and records each request exactly
// as it arrived on the wire.
type rawServer struct {
	ln       net.Listener
	response string
	requests chan []byte
}

func newRawServer(t testing.TB, response string) *rawServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rawServer{ln: ln, response: response, requests: make(chan []byte, 16)}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *rawServer) url(path string) string {
	return "http://" + s.ln.Addr().String() + path
}

func (s *rawServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *rawServer) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	var raw bytes.Buffer
	length := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		raw.WriteString(line)
		if line == "\r\n" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "Content-Length") {
			length, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(br, body); err != nil {
		return
	}
	raw.Write(body)
	s.requests <- raw.Bytes()
	_, _ = io.WriteString(c, s.response)
}

// next returns the next recorded request.
func (s *rawServer) next(t testing.TB) []byte {
	t.Helper()
	select {
	case req := <-s.requests:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("no request arrived")
		return nil
	}
}

// rawResponse formats a complete HTTP/1.1 response that closes the connection.
func rawResponse(status, contentType, body string) string {
	return "HTTP/1.1 " + status + "\r\nContent-Type: " + contentType + "\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

// fakeCredential is a kerberos.Credential that returns token, or err. With block, Token
// waits until its context is done and returns the context's error.
type fakeCredential struct {
	token []byte
	err   error
	block bool

	mu     sync.Mutex
	spns   []string
	resets atomic.Int32
}

func (c *fakeCredential) Token(ctx context.Context, spn string) ([]byte, error) {
	c.mu.Lock()
	c.spns = append(c.spns, spn)
	c.mu.Unlock()
	if c.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return c.token, c.err
}

func (c *fakeCredential) Reset() { c.resets.Add(1) }

func (c *fakeCredential) Close() error { return nil }

func (c *fakeCredential) requestedSPNs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.spns...)
}

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
