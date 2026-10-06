// Command mocksoap is the SOAP service of the end-to-end smoke test (test/e2e). It checks
// each request the way a strict SOAP stack does and answers with a fixed envelope. It is not
// part of the exporter.
//
// Endpoints (POST unless noted):
//
//	/soap11    SOAP 1.1 Ping without authentication
//	/kerberos  SOAP 1.1 Ping behind SPNEGO (gokrb5's server side with the service keytab);
//	           the answer names the authenticated client principal
//	/soap12    SOAP 1.2 GetStatus
//	/fault     always a SOAP 1.1 Server fault with HTTP 500
//	/healthz   GET; 200 while the server runs (the container health check, -health-check)
//
// A request that differs from what the endpoint expects (Content-Type, SOAPAction, the
// action parameter of SOAP 1.2, the envelope version) gets a Client (1.1) or Sender (1.2)
// fault naming the difference, so that a failing smoke test shows it in the probe message.
package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

const (
	serviceNS    = "http://example.com/soap"
	pingAction   = serviceNS + "/Ping"
	statusAction = serviceNS + "/GetStatus"

	soap11NS = "http://schemas.xmlsoap.org/soap/envelope/"
	soap12NS = "http://www.w3.org/2003/05/soap-envelope"

	maxRequestSize = 1 << 20
)

func main() {
	os.Exit(run())
}

func run() int {
	listen := flag.String("listen", ":8080", "Listen address.")
	keytabPath := flag.String("keytab", "/keytabs/HTTP_mocksoap.keytab",
		"Keytab of the service principal (HTTP/<host>) for the /kerberos endpoint.")
	healthCheck := flag.Bool("health-check", false,
		"Check that the server on -listen answers GET /healthz, and exit.")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if *healthCheck {
		if err := checkHealth(*listen); err != nil {
			fmt.Fprintln(os.Stderr, "health check:", err)
			return 1
		}
		return 0
	}

	kt, err := keytab.Load(*keytabPath)
	if err != nil {
		logger.Error("Loading the service keytab failed", "path", *keytabPath, "err", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(kt, logger),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe() }()
	logger.Info("Listening", "address", *listen, "keytab", *keytabPath)

	select {
	case err := <-served:
		logger.Error("Server failed", "err", err)
		return 1
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Shutdown failed", "err", err)
		return 1
	}
	return 0
}

// newHandler returns the endpoints; kt is the service keytab of /kerberos.
func newHandler(kt *keytab.Keytab, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /soap11", ping)
	mux.Handle("POST /kerberos", spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(ping), kt,
		service.Logger(slog.NewLogLogger(logger.Handler(), slog.LevelInfo)),
		// MIT KDCs add a PAC without the logon information of Active Directory.
		service.DecodePAC(false),
	))
	mux.HandleFunc("POST /soap12", status)
	mux.HandleFunc("POST /fault", func(w http.ResponseWriter, _ *http.Request) {
		writeFault11(w, "Server", "Service temporarily unavailable (mock fault)")
	})
	return logRequests(mux, logger)
}

// ping serves the SOAP 1.1 Ping operation.
func ping(w http.ResponseWriter, r *http.Request) {
	if msg := checkRequest(r, soap11NS, pingAction); msg != "" {
		writeFault11(w, "Client", msg)
		return
	}
	var client string
	if id := goidentity.FromHTTPRequestContext(r); id != nil {
		client = "\n      <Client>" + escape(id.UserName()+"@"+id.Domain()) + "</Client>"
	}
	write(w, http.StatusOK, "text/xml; charset=utf-8", envelope(soap11NS, `
    <PingResponse xmlns="`+serviceNS+`">
      <PingResult>OK</PingResult>`+client+`
    </PingResponse>`))
}

// status serves the SOAP 1.2 GetStatus operation.
func status(w http.ResponseWriter, r *http.Request) {
	if msg := checkRequest(r, soap12NS, statusAction); msg != "" {
		writeFault12(w, http.StatusBadRequest, "Sender", msg)
		return
	}
	write(w, http.StatusOK, "application/soap+xml; charset=utf-8", envelope(soap12NS, `
    <GetStatusResponse xmlns="`+serviceNS+`">
      <Status>Running</Status>
    </GetStatusResponse>`))
}

// checkRequest returns why r is not a SOAP request with the envelope namespace envNS and the
// action, or "" if it is one. SOAP 1.1 carries the action in the SOAPAction header, quoted;
// SOAP 1.2 in the action parameter of the Content-Type.
func checkRequest(r *http.Request, envNS, action string) string {
	contentType := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Sprintf("invalid Content-Type %q: %v", contentType, err)
	}
	if cs := params["charset"]; !strings.EqualFold(cs, "utf-8") {
		return fmt.Sprintf("Content-Type charset %q, want utf-8", cs)
	}
	switch envNS {
	case soap11NS:
		if mediaType != "text/xml" {
			return fmt.Sprintf("Content-Type %q, want text/xml for SOAP 1.1", mediaType)
		}
		want := `"` + action + `"`
		if got := r.Header.Values("SOAPAction"); len(got) != 1 || got[0] != want {
			return fmt.Sprintf("SOAPAction %q, want exactly one %s", got, want)
		}
	case soap12NS:
		if mediaType != "application/soap+xml" {
			return fmt.Sprintf("Content-Type %q, want application/soap+xml for SOAP 1.2", mediaType)
		}
		if got := params["action"]; got != action {
			return fmt.Sprintf("Content-Type action %q, want %q", got, action)
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestSize+1))
	if err != nil {
		return fmt.Sprintf("reading the request body: %v", err)
	}
	if len(body) > maxRequestSize {
		return fmt.Sprintf("request body larger than %d bytes", maxRequestSize)
	}
	root, err := rootElement(body)
	if err != nil {
		return fmt.Sprintf("request body: %v", err)
	}
	if root.Space != envNS || root.Local != "Envelope" {
		return fmt.Sprintf("request root element {%s}%s, want {%s}Envelope", root.Space, root.Local, envNS)
	}
	return ""
}

// rootElement returns the name of the root element of a well-formed XML document.
func rootElement(doc []byte) (xml.Name, error) {
	var root xml.Name
	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if root.Local == "" {
				return root, errors.New("no XML element")
			}
			return root, nil
		}
		if err != nil {
			return root, err
		}
		if se, ok := tok.(xml.StartElement); ok && root.Local == "" {
			root = se.Name
		}
	}
}

// writeFault11 answers with a SOAP 1.1 fault; code is Client or Server.
func writeFault11(w http.ResponseWriter, code, text string) {
	write(w, http.StatusInternalServerError, "text/xml; charset=utf-8", envelope(soap11NS, `
    <soap:Fault>
      <faultcode>soap:`+code+`</faultcode>
      <faultstring>`+escape(text)+`</faultstring>
    </soap:Fault>`))
}

// writeFault12 answers with a SOAP 1.2 fault; code is Sender or Receiver.
func writeFault12(w http.ResponseWriter, httpStatus int, code, text string) {
	write(w, httpStatus, "application/soap+xml; charset=utf-8", envelope(soap12NS, `
    <soap:Fault>
      <soap:Code><soap:Value>soap:`+code+`</soap:Value></soap:Code>
      <soap:Reason><soap:Text xml:lang="en">`+escape(text)+`</soap:Text></soap:Reason>
    </soap:Fault>`))
}

// envelope wraps body in an envelope with the namespace envNS, bound to the prefix soap.
func envelope(envNS, body string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="` + envNS + `">
  <soap:Body>` + body + `
  </soap:Body>
</soap:Envelope>
`
}

func write(w http.ResponseWriter, code int, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

func escape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// statusRecorder remembers the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests logs every request with its outcome.
func logRequests(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" {
			return
		}
		logger.Info("Request", "method", r.Method, "path", r.URL.Path, "status", rec.code,
			"duration", time.Since(start), "user_agent", r.UserAgent(),
			"negotiate", strings.HasPrefix(r.Header.Get("Authorization"), "Negotiate "))
	})
}

// checkHealth asks the server listening on listen for GET /healthz.
func checkHealth(listen string) error {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return nil
}
