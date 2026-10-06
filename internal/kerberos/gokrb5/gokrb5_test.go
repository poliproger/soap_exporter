package gokrb5

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		conf      string                    // in testdata
		path      func(t *testing.T) string // instead of conf
		wantErr   string
		wantWarn  bool
		wantRealm string
		wantKDCs  int
	}{
		{name: "valid", conf: "krb5.conf", wantRealm: "CORP.EXAMPLE", wantKDCs: 1},
		{name: "unsupported directive", conf: "krb5-unsupported.conf", wantWarn: true, wantRealm: "CORP.EXAMPLE", wantKDCs: 1},
		{name: "no default realm", conf: "krb5-no-default-realm.conf", wantKDCs: 1},
		{name: "invalid", conf: "krb5-invalid.conf", wantErr: "dns_lookup_kdc"},
		{name: "missing", conf: "missing.conf", wantErr: "no such file"},
		{
			// What Docker mounts when the source of a bind mount does not exist.
			name:    "directory",
			path:    func(t *testing.T) string { return t.TempDir() },
			wantErr: "is a directory, not a regular file",
		},
		{
			// gokrb5 alone would stop at the long line and return the sections before it.
			name: "line too long",
			path: func(t *testing.T) string {
				conf, err := os.ReadFile(filepath.Join("testdata", "krb5.conf"))
				if err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(t.TempDir(), "krb5.conf")
				writeFile(t, p, append([]byte("# "+strings.Repeat("x", 64<<10)+"\n"), conf...))
				return p
			},
			wantErr: "a line is longer than 64 KiB",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("testdata", tt.conf)
			if tt.path != nil {
				path = tt.path(t)
			}
			logger, logs := newLogger()
			b, err := New(path, logger)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("New() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if got := b.cfg.LibDefaults.DefaultRealm; got != tt.wantRealm {
				t.Errorf("default realm = %q, want %q", got, tt.wantRealm)
			}
			var kdcs int
			for _, r := range b.cfg.Realms {
				kdcs += len(r.KDC)
			}
			if kdcs != tt.wantKDCs {
				t.Errorf("krb5.conf has %d KDCs, want %d", kdcs, tt.wantKDCs)
			}
			if got := strings.Contains(logs.String(), "level=WARN"); got != tt.wantWarn {
				t.Errorf("warning logged = %v, want %v; log:\n%s", got, tt.wantWarn, logs)
			}
			if b.Name() != Name {
				t.Errorf("Name() = %q, want %q", b.Name(), Name)
			}
		})
	}
}

func TestNewMissingFileIsNotExist(t *testing.T) {
	_, err := New(filepath.Join(t.TempDir(), "krb5.conf"), nil)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("New() error = %v, want fs.ErrNotExist", err)
	}
}

func TestSplitPrincipal(t *testing.T) {
	tests := []struct {
		in        string
		name      string
		realm     string
		wantError bool
	}{
		{in: "HTTP/svc.corp.example@CORP.EXAMPLE", name: "HTTP/svc.corp.example", realm: "CORP.EXAMPLE"},
		{in: "monitor@CORP.EXAMPLE", name: "monitor", realm: "CORP.EXAMPLE"},
		{in: "monitor", name: "monitor"},
		{in: "HTTP/svc.corp.example", name: "HTTP/svc.corp.example"},
		{in: "odd@name@CORP.EXAMPLE", name: "odd@name", realm: "CORP.EXAMPLE"},
		{in: "", wantError: true},
		{in: "@CORP.EXAMPLE", wantError: true},
		{in: "monitor@", wantError: true},
		{in: "HTTP/@CORP.EXAMPLE", wantError: true},
		{in: "/svc.corp.example", wantError: true},
		{in: "HTTP//svc.corp.example", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			name, realm, err := splitPrincipal(tt.in)
			if tt.wantError {
				if err == nil {
					t.Fatalf("splitPrincipal(%q) = %q, %q, want an error", tt.in, name, realm)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitPrincipal(%q) error = %v", tt.in, err)
			}
			if name != tt.name || realm != tt.realm {
				t.Errorf("splitPrincipal(%q) = %q, %q, want %q, %q", tt.in, name, realm, tt.name, tt.realm)
			}
		})
	}
}

func TestNewCredential(t *testing.T) {
	tests := []struct {
		name      string
		conf      string // default krb5.conf
		principal string
		keytab    func(t *testing.T) string // returns the keytab path
		wantErr   string
		wantRealm string
		wantKVNO0 bool // the kvno workaround applies
	}{
		{
			name:      "principal with realm",
			principal: testPrincipal,
			keytab:    func(t *testing.T) string { return tempKeytab(t, entries(3)...) },
			wantRealm: testRealm,
		},
		{
			name:      "default realm",
			principal: testName,
			keytab:    func(t *testing.T) string { return tempKeytab(t, entries(3)...) },
			wantRealm: testRealm,
		},
		{
			name:      "kvno 0",
			principal: testPrincipal,
			keytab:    func(t *testing.T) string { return tempKeytab(t, entries(0)...) },
			wantRealm: testRealm,
			wantKVNO0: true,
		},
		{
			name:      "no realm and no default realm",
			conf:      "krb5-no-default-realm.conf",
			principal: testName,
			keytab:    func(t *testing.T) string { return tempKeytab(t, entries(3)...) },
			wantErr:   "no default_realm",
		},
		{
			name:      "invalid principal",
			principal: "monitor@",
			keytab:    func(t *testing.T) string { return tempKeytab(t, entries(3)...) },
			wantErr:   "empty realm",
		},
		{
			name:      "missing keytab",
			principal: testPrincipal,
			keytab:    func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.keytab") },
			wantErr:   "no such file",
		},
		{
			name:      "directory",
			principal: testPrincipal,
			keytab:    func(t *testing.T) string { return t.TempDir() },
			wantErr:   "not a regular file",
		},
		{
			name:      "garbage",
			principal: testPrincipal,
			keytab: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "client.keytab")
				writeFile(t, p, []byte("-----BEGIN CERTIFICATE-----\n"))
				return p
			},
			wantErr: "not a keytab file",
		},
		{
			name:      "no entries",
			principal: testPrincipal,
			keytab:    func(t *testing.T) string { return tempKeytab(t) },
			wantErr:   "has no entry for HTTP/svc.corp.example@CORP.EXAMPLE (it has no principals)",
		},
		{
			name:      "other principal",
			principal: testPrincipal,
			keytab: func(t *testing.T) string {
				return tempKeytab(t, ktEntry{"HTTP/other.corp.example", testRealm, 3, 18})
			},
			wantErr: "has no entry for HTTP/svc.corp.example@CORP.EXAMPLE (it has only HTTP/other.corp.example@CORP.EXAMPLE)",
		},
		{
			name:      "other realm",
			principal: testPrincipal,
			keytab: func(t *testing.T) string {
				return tempKeytab(t, ktEntry{testName, "OTHER.EXAMPLE", 3, 18})
			},
			wantErr: "it has only HTTP/svc.corp.example@OTHER.EXAMPLE",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := tt.conf
			if conf == "" {
				conf = "krb5.conf"
			}
			b, logs := newBackend(t, conf)
			cred, err := b.NewCredential(tt.principal, tt.keytab(t))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewCredential() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewCredential() error = %v", err)
			}
			c := cred.(*credential)
			t.Cleanup(func() { _ = c.Close() })
			if c.realm != tt.wantRealm {
				t.Errorf("realm = %q, want %q", c.realm, tt.wantRealm)
			}
			if c.workaround != tt.wantKVNO0 {
				t.Errorf("kvno workaround = %v, want %v", c.workaround, tt.wantKVNO0)
			}
			if got := strings.Count(logs.String(), "kvno workaround"); got != map[bool]int{true: 1}[tt.wantKVNO0] {
				t.Errorf("kvno workaround logged %d times; log:\n%s", got, logs)
			}
			if tt.wantKVNO0 && !strings.Contains(logs.String(), "also used for kvno 1–255") {
				t.Errorf("the kvno workaround log does not name the kvno range; log:\n%s", logs)
			}
			if c.cl != nil {
				t.Error("NewCredential logged in; it must not contact the KDC")
			}
		})
	}
}

func TestNewCredentialHidesKeyMaterial(t *testing.T) {
	b, _ := newBackend(t, "krb5.conf")
	data := marshalKeytab(t, entries(3)...)
	path := filepath.Join(t.TempDir(), "client.keytab")
	writeFile(t, path, data[:len(data)-10])

	_, err := b.NewCredential(testPrincipal, path)
	if err == nil {
		t.Fatal("NewCredential() accepted a truncated keytab")
	}
	if want := "keytab " + path + ": malformed keytab"; err.Error() != want {
		t.Errorf("NewCredential() error = %q, want %q", err, want)
	}
}

func TestNewCredentialKeepsKeytabFile(t *testing.T) {
	b, _ := newBackend(t, "krb5.conf")
	path := tempKeytab(t, entries(0)...)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := b.NewCredential(testPrincipal, path)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	t.Cleanup(func() { _ = cred.Close() })
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the kvno workaround changed the keytab file")
	}
}
