package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

const (
	envelope11 = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Ping xmlns="http://example.com/soap"/></soap:Body></soap:Envelope>`
	envelope12 = `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body><GetStatus xmlns="http://example.com/soap"/></env:Body></env:Envelope>`

	contentType11 = "text/xml; charset=utf-8"
	contentType12 = `application/soap+xml; charset=utf-8; action="http://example.com/soap/GetStatus"`
)

func TestHandler(t *testing.T) {
	srv := httptest.NewServer(newHandler(keytab.New(), slog.New(slog.DiscardHandler)))
	defer srv.Close()

	tests := []struct {
		name        string
		method      string
		path        string
		header      map[string]string
		body        string
		wantStatus  int
		wantType    string // prefix of the response Content-Type
		wantContent string
	}{
		{
			name:   "soap11",
			path:   "/soap11",
			header: map[string]string{"Content-Type": contentType11, "SOAPAction": `"http://example.com/soap/Ping"`},
			body:   envelope11, wantStatus: http.StatusOK, wantType: "text/xml", wantContent: "<PingResult>OK</PingResult>",
		},
		{
			name:   "soap11 unquoted SOAPAction",
			path:   "/soap11",
			header: map[string]string{"Content-Type": contentType11, "SOAPAction": "http://example.com/soap/Ping"},
			body:   envelope11, wantStatus: http.StatusInternalServerError, wantType: "text/xml", wantContent: "soap:Client",
		},
		{
			name:   "soap11 without SOAPAction",
			path:   "/soap11",
			header: map[string]string{"Content-Type": contentType11},
			body:   envelope11, wantStatus: http.StatusInternalServerError, wantContent: "SOAPAction []",
		},
		{
			name:   "soap11 with a SOAP 1.2 envelope",
			path:   "/soap11",
			header: map[string]string{"Content-Type": contentType11, "SOAPAction": `"http://example.com/soap/Ping"`},
			body:   envelope12, wantStatus: http.StatusInternalServerError, wantContent: "want {http://schemas.xmlsoap.org/soap/envelope/}Envelope",
		},
		{
			name:   "soap11 malformed body",
			path:   "/soap11",
			header: map[string]string{"Content-Type": contentType11, "SOAPAction": `"http://example.com/soap/Ping"`},
			body:   "<soap:Envelope", wantStatus: http.StatusInternalServerError, wantContent: "request body:",
		},
		{
			name:   "soap11 GET",
			method: http.MethodGet,
			path:   "/soap11", wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "soap12",
			path:   "/soap12",
			header: map[string]string{"Content-Type": contentType12},
			body:   envelope12, wantStatus: http.StatusOK, wantType: "application/soap+xml", wantContent: "<Status>Running</Status>",
		},
		{
			name:   "soap12 without action",
			path:   "/soap12",
			header: map[string]string{"Content-Type": "application/soap+xml; charset=utf-8"},
			body:   envelope12, wantStatus: http.StatusBadRequest, wantType: "application/soap+xml", wantContent: "soap:Sender",
		},
		{
			name:   "soap12 as text/xml",
			path:   "/soap12",
			header: map[string]string{"Content-Type": contentType11},
			body:   envelope12, wantStatus: http.StatusBadRequest, wantContent: "want application/soap+xml",
		},
		{
			name: "fault", path: "/fault", body: envelope11,
			wantStatus: http.StatusInternalServerError, wantType: "text/xml", wantContent: "<faultcode>soap:Server</faultcode>",
		},
		{
			name:   "kerberos without a token",
			path:   "/kerberos",
			header: map[string]string{"Content-Type": contentType11, "SOAPAction": `"http://example.com/soap/Ping"`},
			body:   envelope11, wantStatus: http.StatusUnauthorized,
		},
		{
			name: "healthz", method: http.MethodGet, path: "/healthz",
			wantStatus: http.StatusOK, wantContent: "ok",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tt.header {
				req.Header[k] = []string{v}
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status %d, want %d; body:\n%s", resp.StatusCode, tt.wantStatus, body)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, tt.wantType) {
				t.Errorf("Content-Type %q, want prefix %q", ct, tt.wantType)
			}
			if !strings.Contains(string(body), tt.wantContent) {
				t.Errorf("body does not contain %q:\n%s", tt.wantContent, body)
			}
		})
	}
}

func TestCheckHealth(t *testing.T) {
	if err := checkHealth("no port"); err == nil {
		t.Error("checkHealth accepted a listen address without a port")
	}
}
