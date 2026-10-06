package gokrb5

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

const (
	testRealm     = "CORP.EXAMPLE"
	testName      = "HTTP/svc.corp.example"
	testPrincipal = testName + "@" + testRealm
)

// ktEntry describes a keytab entry; its key is derived from a fixed password.
type ktEntry struct {
	name, realm string
	kvno        uint8
	etype       int32
}

// entries returns one entry of testPrincipal per usable Active Directory enctype.
func entries(kvno uint8) []ktEntry {
	return []ktEntry{
		{testName, testRealm, kvno, etypeID.RC4_HMAC},
		{testName, testRealm, kvno, etypeID.AES256_CTS_HMAC_SHA1_96},
		{testName, testRealm, kvno, etypeID.AES128_CTS_HMAC_SHA1_96},
	}
}

func buildKeytab(t *testing.T, es ...ktEntry) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	for _, e := range es {
		if err := kt.AddEntry(e.name, e.realm, "s3cret", time.Unix(1_790_000_000, 0), e.kvno, e.etype); err != nil {
			t.Fatalf("AddEntry: %v", err)
		}
	}
	return kt
}

func marshalKeytab(t *testing.T, es ...ktEntry) []byte {
	t.Helper()
	b, err := buildKeytab(t, es...).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

// writeKeytab writes a keytab with the entries to path and returns path.
func writeKeytab(t *testing.T, path string, es ...ktEntry) string {
	t.Helper()
	writeFile(t, path, marshalKeytab(t, es...))
	return path
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func tempKeytab(t *testing.T, es ...ktEntry) string {
	t.Helper()
	return writeKeytab(t, filepath.Join(t.TempDir(), "client.keytab"), es...)
}

// logBuffer collects log output; gokrb5 logs from its own goroutines.
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

func newLogger() (*slog.Logger, *logBuffer) {
	var b logBuffer
	return slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})), &b
}

func newBackend(t *testing.T, conf string) (*Backend, *logBuffer) {
	t.Helper()
	logger, logs := newLogger()
	b, err := New(filepath.Join("testdata", conf), logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b, logs
}
