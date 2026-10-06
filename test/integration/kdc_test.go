//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	realm = "CORP.EXAMPLE"
	// clientName and serviceName are created by the KDC image by default (KDC_PRINCIPALS).
	clientName       = "monitor"
	serviceName      = "HTTP/app.corp.example"
	clientPrincipal  = clientName + "@" + realm
	servicePrincipal = serviceName + "@" + realm
	tgsPrincipal     = "krbtgt/" + realm + "@" + realm

	// kdcImage is built from test/kdc and kept, so that later runs reuse its layers.
	kdcImageRepo = "soap-exporter-test-kdc"
	kdcImageTag  = "integration"
	kdcImage     = kdcImageRepo + ":" + kdcImageTag
	// kdcKeytabDir is KDC_KEYTAB_DIR of the image.
	kdcKeytabDir = "/keytabs"
	// testLabel marks every container the tests start.
	testLabel = "soap-exporter-test"
)

// kdcConfig configures a KDC container through the environment of test/kdc/entrypoint.sh.
// Zero values keep the image defaults.
type kdcConfig struct {
	principals       []string // without the realm; default clientName and serviceName
	maxLife          string   // KDC_MAX_LIFE, e.g. "2m"
	maxRenewableLife string   // KDC_MAX_RENEWABLE_LIFE
	clockSkew        time.Duration
}

func (c kdcConfig) env() map[string]string {
	env := map[string]string{"KDC_REALM": realm}
	if c.principals != nil {
		env["KDC_PRINCIPALS"] = strings.Join(c.principals, " ")
	}
	if c.maxLife != "" {
		env["KDC_MAX_LIFE"] = c.maxLife
	}
	if c.maxRenewableLife != "" {
		env["KDC_MAX_RENEWABLE_LIFE"] = c.maxRenewableLife
	}
	if c.clockSkew != 0 {
		env["KDC_CLOCKSKEW"] = strconv.Itoa(int(c.clockSkew / time.Second))
	}
	return env
}

// kdc is a running MIT KDC container.
type kdc struct {
	t   *testing.T
	ctr testcontainers.Container
	// addr is the host:port of the KDC's TCP port on the host.
	addr string
}

// buildKDCImage builds test/kdc once per test binary.
var buildKDCImage = sync.OnceValue(func() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		return fmt.Errorf("docker provider: %w", err)
	}
	defer provider.Close()
	var log bytes.Buffer
	_, err = provider.BuildImage(ctx, &testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:        filepath.Join("..", "kdc"),
			Repo:           kdcImageRepo,
			Tag:            kdcImageTag,
			KeepImage:      true,
			BuildLogWriter: &log,
		},
	})
	if err != nil {
		return fmt.Errorf("build the KDC image from test/kdc: %w\nbuild log:\n%s", err, log.String())
	}
	return nil
})

// startKDC starts a KDC container for the test; it is removed when the test ends. A failure
// to start it fails the test: Docker is known to be available at this point.
func startKDC(t *testing.T, cfg kdcConfig) *kdc {
	t.Helper()
	if err := buildKDCImage(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	ctr, err := testcontainers.Run(ctx, kdcImage,
		testcontainers.WithName(containerName(t)),
		testcontainers.WithLabels(map[string]string{testLabel: "kdc"}),
		testcontainers.WithEnv(cfg.env()),
		testcontainers.WithExposedPorts("88/tcp"),
		testcontainers.WithWaitStrategyAndDeadline(time.Minute,
			wait.ForLog("commencing operation"),
			wait.ForListeningPort("88/tcp"),
		),
	)
	testcontainers.CleanupContainer(t, ctr)
	k := &kdc{t: t, ctr: ctr}
	// Registered after CleanupContainer, so it runs before the container is removed.
	t.Cleanup(func() {
		if t.Failed() && ctr != nil {
			t.Logf("KDC log:\n%s", k.log())
		}
	})
	if err != nil {
		t.Fatalf("start the KDC container: %v", err)
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("KDC container host: %v", err)
	}
	if host == "localhost" {
		host = "127.0.0.1" // no name resolution, and no attempt on ::1 first
	}
	port, err := ctr.MappedPort(ctx, "88/tcp")
	if err != nil {
		t.Fatalf("KDC container port: %v", err)
	}
	k.addr = net.JoinHostPort(host, strconv.Itoa(int(port.Num())))
	return k
}

// containerName returns a recognizable, unique container name for the test.
func containerName(t *testing.T) string {
	name := strings.NewReplacer("/", "-", "_", "-").Replace(strings.ToLower(t.Name()))
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return testLabel + "-" + name + "-" + hex.EncodeToString(b)
}

// kadmin runs a kadmin.local query in the container and returns its output. kadmin.local
// exits with 0 even if the query failed, so callers check the effect where it matters.
func (k *kdc) kadmin(query string) string {
	k.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	code, r, err := k.ctr.Exec(ctx, []string{"kadmin.local", "-q", query}, tcexec.Multiplexed())
	if err != nil {
		k.t.Fatalf("kadmin.local -q %q: %v", query, err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		k.t.Fatalf("kadmin.local -q %q: read output: %v", query, err)
	}
	if code != 0 {
		k.t.Fatalf("kadmin.local -q %q: exit code %d:\n%s", query, code, out)
	}
	return string(out)
}

// file returns the contents of a file in the container.
func (k *kdc) file(path string) []byte {
	k.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rc, err := k.ctr.CopyFileFromContainer(ctx, path)
	if err != nil {
		k.t.Fatalf("copy %s from the KDC container: %v", path, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		k.t.Fatalf("copy %s from the KDC container: %v", path, err)
	}
	return b
}

// keytab returns the keytab the image exported for a principal created at startup.
func (k *kdc) keytab(name string) []byte {
	k.t.Helper()
	return k.file(kdcKeytabDir + "/" + strings.ReplaceAll(name, "/", "_") + ".keytab")
}

// rotateKey gives the principal a new random key (kvno + 1) and returns a keytab that holds
// only the new key.
func (k *kdc) rotateKey(principal string, wantKVNO uint32) []byte {
	k.t.Helper()
	path := "/tmp/rotated-" + strings.NewReplacer("/", "_", "@", "_").Replace(principal) + ".keytab"
	k.kadmin("ktadd -k " + path + " " + principal)
	b := k.file(path)
	if kvnos := keytabKVNOs(k.t, b); len(kvnos) != 1 || kvnos[0] != wantKVNO {
		k.t.Fatalf("rotated keytab of %s has kvnos %v, want only %d", principal, kvnos, wantKVNO)
	}
	return b
}

// log returns the container log (krb5kdc logs every request to stderr).
func (k *kdc) log() string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc, err := k.ctr.Logs(ctx)
	if err != nil {
		return "(container log unavailable: " + err.Error() + ")"
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return string(b) + "\n(reading the container log failed: " + err.Error() + ")"
	}
	return string(b)
}

// issueLine matches a ticket the KDC issued, e.g.
//
//	AS_REQ (2 etypes {…}) 172.17.0.1: ISSUE: authtime 1790000000, etypes {…}, monitor@CORP.EXAMPLE for krbtgt/CORP.EXAMPLE@CORP.EXAMPLE
var issueLine = regexp.MustCompile(`\b(AS_REQ|TGS_REQ) .*: ISSUE: .* (\S+) for (\S+)$`)

// tickets counts the tickets of the given request type ("AS_REQ" or "TGS_REQ") that the KDC
// issued to client for server so far.
func (k *kdc) tickets(req, client, server string) int {
	n := 0
	s := bufio.NewScanner(strings.NewReader(k.log()))
	for s.Scan() {
		m := issueLine.FindStringSubmatch(strings.TrimRight(s.Text(), "\r"))
		if len(m) == 4 && m[1] == req && m[2] == client && m[3] == server {
			n++
		}
	}
	return n
}

// waitTickets is tickets after waiting up to a few seconds for the count to reach want: the
// container log lags behind the KDC.
func (k *kdc) waitTickets(req, client, server string, want int) int {
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := k.tickets(req, client, server)
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// keytabKVNOs returns the distinct kvnos of the keytab entries in file order.
func keytabKVNOs(t *testing.T, b []byte) []uint32 {
	t.Helper()
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatalf("parse keytab: %v", err)
	}
	var kvnos []uint32
	for _, e := range kt.Entries {
		if !slices.Contains(kvnos, e.KVNO) {
			kvnos = append(kvnos, e.KVNO)
		}
	}
	return kvnos
}
