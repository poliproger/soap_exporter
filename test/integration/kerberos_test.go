//go:build integration

// Package integration holds the Kerberos integration tests (plan phase 8): an MIT KDC in a
// container (built from test/kdc), a SOAP service protected by gokrb5's server-side SPNEGO
// handler, and the exporter's own stack (krb5.conf → backend → credential registry → prober)
// probing it. They need Docker and run with
//
//	go test -tags integration -race -count=1 ./test/integration/...
//
// -short skips the TGT expiry test, which takes about 5 minutes.
package integration

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/testcontainers/testcontainers-go"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/prober"
	"github.com/poliproger/soap_exporter/internal/result"
)

// The TGT expiry test probes every tgtProbeInterval for tgtTestDuration against a KDC whose
// tickets live 2 minutes and are renewable for 3, so it sees a new login and, with a backend
// that renews its TGT, renewals.
const (
	tgtTestDuration  = 5 * time.Minute
	tgtProbeInterval = 20 * time.Second
)

func TestKerberos(t *testing.T) {
	// The only reason to skip: without Docker there is no KDC. Any later failure to build or
	// start the KDC fails the test.
	testcontainers.SkipIfProviderIsNotHealthy(t)

	scenarios := []struct {
		name string
		run  func(*testing.T, backend)
	}{
		{"success", testSuccess},
		{"wrong_spn/unknown_to_kdc", testSPNUnknownToKDC},
		{"wrong_spn/not_in_service_keytab", testSPNNotInServiceKeytab},
		{"tgt_expiry", testTGTExpiry},
		{"client_keytab_rotation", testClientKeytabRotation},
		{"kvno0_client_keytab", testKVNO0ClientKeytab},
		{"service_key_rotation", testServiceKeyRotation},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			for _, s := range scenarios {
				t.Run(s.name, func(t *testing.T) {
					t.Parallel() // every scenario has its own KDC and service
					s.run(t, b)
				})
			}
		})
	}
}

// testSuccess: a probe succeeds, and later probes reuse the tickets.
func testSuccess(t *testing.T, b backend) {
	f := newFixture(t, b, kdcConfig{})
	p := f.prober(clientPrincipal, f.writeKeytab("monitor.keytab", f.kdc.keytab(clientName)), serviceName)
	for range 3 {
		r := f.probe(p, result.ReasonNone, 1)
		if r.HTTPStatus != http.StatusOK || r.SPN != serviceName {
			t.Errorf("probe: status %d, SPN %q; want %d, %q", r.HTTPStatus, r.SPN, http.StatusOK, serviceName)
		}
	}
	// One login and one service ticket for all probes (plan D6).
	f.wantTickets("AS_REQ", clientPrincipal, tgsPrincipal, 1)
	f.wantTickets("TGS_REQ", clientPrincipal, servicePrincipal, 1)
}

// testSPNUnknownToKDC: the KDC refuses the service ticket, so no request is sent.
func testSPNUnknownToKDC(t *testing.T, b backend) {
	const spn = "HTTP/unknown.corp.example"
	f := newFixture(t, b, kdcConfig{})
	p := f.prober(clientPrincipal, f.writeKeytab("monitor.keytab", f.kdc.keytab(clientName)), spn)
	for range 2 {
		r := f.probe(p, result.ReasonAuth, 0)
		if !strings.Contains(r.Message, spn) || !strings.Contains(r.Message, "not found in Kerberos database") {
			t.Errorf("probe message %q does not name the SPN %s and the KDC's error", r.Message, spn)
		}
	}
}

// testSPNNotInServiceKeytab: the KDC issues the service ticket, but the service has no key
// for it and answers 401. Every probe sends exactly one request (no retry) and resets the
// credential.
func testSPNNotInServiceKeytab(t *testing.T, b backend) {
	const spn = "HTTP/other.corp.example"
	f := newFixture(t, b, kdcConfig{principals: []string{clientName, serviceName, spn}})
	p := f.prober(clientPrincipal, f.writeKeytab("monitor.keytab", f.kdc.keytab(clientName)), spn)
	const probes = 3
	for range probes {
		if r := f.probe(p, result.ReasonAuth, 1); r.HTTPStatus != http.StatusUnauthorized {
			t.Errorf("probe: status %d, want %d", r.HTTPStatus, http.StatusUnauthorized)
		}
	}
	// Each 401 reset the credential, so each probe logged in again.
	f.wantTickets("AS_REQ", clientPrincipal, tgsPrincipal, probes)
}

// testTGTExpiry: tickets live 2 minutes and are renewable for 3; probes keep succeeding for 5
// minutes, across a new login and, if the backend renews its TGT, renewals.
func testTGTExpiry(t *testing.T, b backend) {
	if testing.Short() {
		t.Skipf("takes %s; skipped with -short", tgtTestDuration)
	}
	f := newFixture(t, b, kdcConfig{
		maxLife:          "2m",
		maxRenewableLife: "3m",
		// The KDC accepts expired tickets for this long, as the service does (serverClockSkew).
		clockSkew: serverClockSkew,
	})
	p := f.prober(clientPrincipal, f.writeKeytab("monitor.keytab", f.kdc.keytab(clientName)), serviceName)
	start := time.Now()
	probes := 0
	for {
		f.probe(p, result.ReasonNone, 1)
		probes++
		if time.Since(start) >= tgtTestDuration {
			break
		}
		select {
		case <-time.After(tgtProbeInterval):
		case <-t.Context().Done():
			t.Fatalf("stopped after %d probes: %v", probes, t.Context().Err())
		}
	}
	logins := f.kdc.tickets("AS_REQ", clientPrincipal, tgsPrincipal)
	renewals := f.kdc.tickets("TGS_REQ", clientPrincipal, tgsPrincipal)
	serviceTickets := f.kdc.tickets("TGS_REQ", clientPrincipal, servicePrincipal)
	t.Logf("%d probes in %s; the KDC issued %d TGTs by login, renewed TGTs %d times and issued %d service tickets",
		probes, time.Since(start).Round(time.Second), logins, renewals, serviceTickets)
	// No ticket lives longer than 2 minutes, so covering 5 minutes takes at least 3 of each kind.
	if logins+renewals < 3 || serviceTickets < 3 {
		t.Errorf("the KDC issued %d TGTs and %d service tickets, want at least 3 of each", logins+renewals, serviceTickets)
	}
	// The first TGT cannot be renewed past 3 minutes, so the last probes need a new login. One
	// login means the renewable limit did not take effect and the path went untested.
	if logins < 2 {
		t.Errorf("the KDC issued %d TGTs by login, want at least 2", logins)
	}
	// A renewing backend renews the first TGT before it expires at 2 minutes.
	if b.renewsTGT && renewals < 1 {
		t.Errorf("the KDC renewed TGTs %d times, want at least 1", renewals)
	}
}

// testClientKeytabRotation: the client gets a new key (kvno 2) and its keytab file is
// replaced; the credential logs in again with the new keytab, nothing is restarted.
func testClientKeytabRotation(t *testing.T, b backend) {
	f := newFixture(t, b, kdcConfig{})
	keytabFile := f.writeKeytab("monitor.keytab", f.kdc.keytab(clientName))
	p := f.prober(clientPrincipal, keytabFile, serviceName)
	f.probe(p, result.ReasonNone, 1)
	f.wantTickets("AS_REQ", clientPrincipal, tgsPrincipal, 1)

	// From now on the KDC accepts only the new key.
	f.writeKeytab(keytabFile, f.kdc.rotateKey(clientPrincipal, 2))
	for range 2 {
		f.probe(p, result.ReasonNone, 1)
	}
	// One new login, which only succeeds with the new key; the second probe reused it.
	f.wantTickets("AS_REQ", clientPrincipal, tgsPrincipal, 2)
}

// testKVNO0ClientKeytab: the client keytab holds the right keys with kvno 0, while the AS-REP
// names the principal's kvno 3, as Active Directory's does (plan finding 8).
func testKVNO0ClientKeytab(t *testing.T, b backend) {
	const (
		name      = "legacy"
		principal = name + "@" + realm
		password  = "kvno0-test-password"
		kvno      = 3
	)
	f := newFixture(t, b, kdcConfig{})
	// Three keys from the same password: kvno 1, 2 and 3.
	f.kdc.kadmin("addprinc -clearpolicy -pw " + password + " " + principal)
	f.kdc.kadmin("cpw -pw " + password + " " + principal)
	f.kdc.kadmin("cpw -pw " + password + " " + principal)
	if out := f.kdc.kadmin("getprinc " + principal); !strings.Contains(out, fmt.Sprintf("Key: vno %d,", kvno)) {
		t.Fatalf("%s should have kvno %d:\n%s", principal, kvno, out)
	}
	// The MIT KDC leaves the kvno out of the AS-REP; the proxy adds it.
	proxy := startKVNOProxy(t, f.kdc.addr, kvno)
	f.kdcAddr = proxy.addr

	kt := keytab.New()
	for _, etype := range []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96} {
		if err := kt.AddEntry(name, realm, password, time.Now(), 0, etype); err != nil {
			t.Fatalf("keytab entry: %v", err)
		}
	}
	data, err := kt.Marshal()
	if err != nil {
		t.Fatalf("marshal keytab: %v", err)
	}
	p := f.prober(principal, f.writeKeytab("legacy.keytab", data), serviceName)
	for range 2 {
		f.probe(p, result.ReasonNone, 1)
	}
	if n := proxy.rewritten.Load(); n != 1 {
		t.Errorf("the proxy set the kvno of %d AS-REPs, want 1", n)
	}
	if b.kvnoWorkaroundLog != "" && !f.logs.hasLine("level=INFO", b.kvnoWorkaroundLog) {
		t.Errorf("no info log line containing %q", b.kvnoWorkaroundLog)
	}
}

// testServiceKeyRotation: the service gets a new key (kvno 2). The cached service ticket no
// longer works: the probe fails with 401 and resets the credential, and the next probe gets a
// ticket for the new key.
func testServiceKeyRotation(t *testing.T, b backend) {
	f := newFixture(t, b, kdcConfig{})
	p := f.prober(clientPrincipal, f.writeKeytab("monitor.keytab", f.kdc.keytab(clientName)), serviceName)
	f.probe(p, result.ReasonNone, 1)

	f.server.setKeytab(t, f.kdc.rotateKey(servicePrincipal, 2))
	if r := f.probe(p, result.ReasonAuth, 1); r.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("probe after the rotation: status %d, want %d", r.HTTPStatus, http.StatusUnauthorized)
	}
	for range 2 {
		f.probe(p, result.ReasonNone, 1)
	}
	// The reset dropped the tickets: a new login and a new service ticket, reused afterwards.
	f.wantTickets("AS_REQ", clientPrincipal, tgsPrincipal, 2)
	f.wantTickets("TGS_REQ", clientPrincipal, servicePrincipal, 2)
}

// fixture is the world of one scenario: a KDC, the protected service, and the exporter's side
// built the way the exporter builds it (krb5.conf → backend → registry → prober).
type fixture struct {
	t       *testing.T
	backend backend
	kdc     *kdc
	server  *soapServer
	dir     string     // the exporter's files: krb5.conf, keytabs
	logs    *logBuffer // the exporter's log, and the service's with the prefix "service: "
	logger  *slog.Logger
	// kdcAddr is the KDC address in the exporter's krb5.conf; it can be changed until the first
	// prober is built.
	kdcAddr string
	// registry is created with the first prober.
	registry *kerberos.Registry
}

// krb5ConfTemplate is the exporter's krb5.conf: the KDC on its mapped TCP port, no DNS.
const krb5ConfTemplate = `[libdefaults]
  default_realm = %[1]s
  dns_lookup_kdc = false
  dns_lookup_realm = false
  udp_preference_limit = 1
  ticket_lifetime = 10h
  renew_lifetime = 7d

[realms]
  %[1]s = {
    kdc = %[2]s
  }
`

func newFixture(t *testing.T, b backend, cfg kdcConfig) *fixture {
	t.Helper()
	f := &fixture{t: t, backend: b, dir: t.TempDir(), logs: &logBuffer{}}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("exporter and service log:\n%s", f.logs)
		}
	})
	f.logger = slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.kdc = startKDC(t, cfg)
	f.kdcAddr = f.kdc.addr
	f.server = newSOAPServer(t, f.kdc.keytab(serviceName), log.New(f.logs, "service: ", log.LstdFlags|log.Lmicroseconds))
	return f
}

// initKerberos writes krb5.conf and creates the backend and the credential registry.
func (f *fixture) initKerberos() {
	f.t.Helper()
	krb5Conf := filepath.Join(f.dir, "krb5.conf")
	if err := os.WriteFile(krb5Conf, fmt.Appendf(nil, krb5ConfTemplate, realm, f.kdcAddr), 0o600); err != nil {
		f.t.Fatal(err)
	}
	be, err := f.backend.new(krb5Conf, f.logger)
	if err != nil {
		f.t.Fatalf("%s backend: %v", f.backend.name, err)
	}
	f.registry = kerberos.NewRegistry(be, f.logger)
	f.t.Cleanup(f.registry.Close)
}

// writeKeytab writes a keytab into the exporter's directory and returns its file name. An
// existing file is replaced atomically, as a secret update does.
func (f *fixture) writeKeytab(name string, data []byte) string {
	f.t.Helper()
	tmp, err := os.CreateTemp(f.dir, ".keytab-*")
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(f.dir, name))
	}
	if err != nil {
		f.t.Fatalf("write keytab %s: %v", name, err)
	}
	return name
}

// targetTemplate is a SOAP 1.1 Kerberos target; the XPath checks that the service
// authenticated the client principal.
const targetTemplate = `targets:
  - name: kerberos
    url: %[1]s/Service.asmx
    interval: 1m
    timeout: 10s
    soap:
      version: "1.1"
      action: http://tempuri.org/Ping
    body: |
      <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body><Ping xmlns="http://tempuri.org/"/></soap:Body>
      </soap:Envelope>
    kerberos:
      principal: %[2]s
      keytab: %[3]s
      spn: %[4]s
    expect:
      namespaces:
        t: http://tempuri.org/
      xpath:
        - "//t:PingResponse[t:PingResult = 'OK']/t:Client = '%[2]s'"
`

// prober builds the prober of a Kerberos target through config.LoadBytes, the credential
// registry and prober.New, as the exporter does. The URL is on 127.0.0.1 and the SPN is
// explicit, so nothing needs DNS.
func (f *fixture) prober(principal, keytabFile, spn string) *prober.Prober {
	f.t.Helper()
	if f.registry == nil {
		f.initKerberos()
	}
	cfg, err := config.LoadBytes(fmt.Appendf(nil, targetTemplate, f.server.URL, principal, keytabFile, spn), f.dir)
	if err != nil {
		f.t.Fatalf("load config: %v", err)
	}
	target := cfg.Targets[0]
	cred, err := f.registry.Get(kerberos.Key{Principal: target.Kerberos.Principal, Keytab: target.Kerberos.Keytab})
	if err != nil {
		f.t.Fatalf("credential: %v", err)
	}
	p, err := prober.New(target, cred, prober.Options{UserAgent: "soap_exporter/integration-test", Logger: f.logger})
	if err != nil {
		f.t.Fatalf("prober: %v", err)
	}
	f.t.Cleanup(p.Close)
	return p
}

// probe runs one probe and checks its reason and the number of HTTP requests the service
// received meanwhile. A mismatch ends the test: later steps build on this one.
func (f *fixture) probe(p *prober.Prober, want result.Reason, wantRequests int64) result.Result {
	f.t.Helper()
	before := f.server.requests.Load()
	r := p.Probe(f.t.Context())
	requests := f.server.requests.Load() - before
	if r.Reason != want || requests != wantRequests {
		f.t.Fatalf("probe at %s: reason %s with %d requests to the service, want %s with %d (status %d, message %q)",
			r.Start.Format("15:04:05.000"), reasonName(r.Reason), requests, reasonName(want), wantRequests,
			r.HTTPStatus, r.Message)
	}
	return r
}

func reasonName(r result.Reason) string {
	if r == result.ReasonNone {
		return result.ResultSuccess
	}
	return string(r)
}

// wantTickets checks the number of tickets of a request type the KDC issued to client for
// server.
func (f *fixture) wantTickets(req, client, server string, want int) {
	f.t.Helper()
	if n := f.kdc.waitTickets(req, client, server, want); n != want {
		f.t.Errorf("the KDC issued %d tickets by %s for %s to %s, want %d", n, req, server, client, want)
	}
}

// logBuffer collects log output from several goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// hasLine reports whether a log line contains all the substrings.
func (b *logBuffer) hasLine(substrings ...string) bool {
	for line := range strings.Lines(b.String()) {
		found := true
		for _, s := range substrings {
			found = found && strings.Contains(line, s)
		}
		if found {
			return true
		}
	}
	return false
}
