//go:build integration

package integration

import (
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// serverClockSkew is the clock skew the service tolerates. It is far below the default of
// 5 minutes, so that an expired service ticket is rejected soon after it expires.
const serverClockSkew = 10 * time.Second

// soapServer is a SOAP 1.1 service protected by gokrb5's server-side SPNEGO handler. It
// counts every request it receives, authenticated or not, and answers an authenticated one
// with an envelope naming the client principal.
type soapServer struct {
	*httptest.Server
	keytab   atomic.Pointer[keytab.Keytab]
	requests atomic.Int64
}

func newSOAPServer(t *testing.T, serviceKeytab []byte, logger *log.Logger) *soapServer {
	t.Helper()
	s := &soapServer{}
	s.setKeytab(t, serviceKeytab)
	settings := []func(*service.Settings){
		service.Logger(logger),
		service.MaxClockSkew(serverClockSkew),
		// MIT KDCs add a PAC without the logon information of Active Directory.
		service.DecodePAC(false),
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		// The keytab is read per request, so that a test can rotate it.
		spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(answer), s.keytab.Load(), settings...).ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// setKeytab replaces the service keytab.
func (s *soapServer) setKeytab(t *testing.T, b []byte) {
	t.Helper()
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatalf("parse service keytab: %v", err)
	}
	s.keytab.Store(kt)
}

// answer serves an authenticated request.
func answer(w http.ResponseWriter, r *http.Request) {
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var client string
	if id := goidentity.FromHTTPRequestContext(r); id != nil {
		client = id.UserName() + "@" + id.Domain()
	}
	var name strings.Builder
	_ = xml.EscapeText(&name, []byte(client))
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <PingResponse xmlns="http://tempuri.org/">
      <PingResult>OK</PingResult>
      <Client>`+name.String()+`</Client>
    </PingResponse>
  </soap:Body>
</soap:Envelope>
`)
}
