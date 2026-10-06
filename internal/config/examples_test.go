package config_test

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	commoncfg "github.com/prometheus/common/config"

	"github.com/poliproger/soap_exporter/internal/config"
)

// examplesDir holds the shipped example configuration (examples/config.yml and the request
// bodies it references).
const examplesDir = "../../examples"

// exampleLocalDirs are the directories of a deployment made from the example: the README
// tells users to create them next to docker-compose.yml, and examples/.gitignore keeps them
// out of the repository. The test neither copies nor reads them.
var exampleLocalDirs = []string{"secrets", "certs"}

// examplePlaceholders are the secret, key and certificate files that examples/config.yml
// references but the repository does not ship. config.Load only checks that keytabs are
// non-empty regular files; the other files are read when probers are built or at probe time.
var examplePlaceholders = []string{
	"secrets/monitor.keytab",
	"secrets/orders-password",
	"secrets/partner-client-secret",
	"secrets/archive-token",
	"secrets/archive-api-key",
	"certs/corp-root-ca.pem",
	"certs/soap-monitor.pem",
	"certs/soap-monitor.key",
}

// TestExampleConfig loads a copy of examples/ with placeholder secrets: the example must be
// valid, produce no warnings, keep every referenced file inside its directory (so that it can
// be copied or mounted as a whole), and use every request body it ships.
func TestExampleConfig(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, examplesDir, dir, exampleLocalDirs)
	for _, name := range examplePlaceholders {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("placeholder for the example config test\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := config.Load(filepath.Join(dir, "config.yml"))
	if err != nil {
		t.Fatalf("examples/config.yml does not load:\n%v", err)
	}
	if len(cfg.Warnings) > 0 {
		t.Errorf("examples/config.yml has warnings:\n%s", strings.Join(cfg.Warnings, "\n"))
	}

	auth := map[string]string{}
	for _, tg := range cfg.Targets {
		auth[tg.Name] = tg.AuthType()
	}
	wantAuth := map[string]string{
		"branches":         "kerberos",
		"customer-lookup":  "kerberos",
		"orders-status":    "basic",
		"payments-gateway": "none",
		"partner-rates":    "oauth2",
		"document-archive": "authorization",
		"audit-ingest":     "none",
		"legacy-billing":   "none",
	}
	if len(auth) != len(wantAuth) {
		t.Errorf("targets and auth methods = %v, want %v", auth, wantAuth)
	}
	for name, want := range wantAuth {
		if got, ok := auth[name]; !ok || got != want {
			t.Errorf("target %q: auth = %q (present %v), want %q", name, got, ok, want)
		}
	}

	used := map[string]bool{}
	for _, tg := range cfg.Targets {
		for _, ref := range referencedFiles(tg) {
			rel, err := filepath.Rel(dir, ref.path)
			if err != nil || !filepath.IsLocal(rel) {
				t.Errorf("target %q: %s %s is outside the example directory", tg.Name, ref.field, ref.path)
				continue
			}
			used[filepath.ToSlash(rel)] = true
			if _, err := os.Stat(ref.path); err != nil {
				t.Errorf("target %q: %s: %v (add it to examplePlaceholders if it is a secret)", tg.Name, ref.field, err)
			}
		}
	}
	requests, err := filepath.Glob(filepath.Join(dir, "requests", "*.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) == 0 {
		t.Error("examples/requests has no request bodies")
	}
	for _, path := range requests {
		if rel := "requests/" + filepath.Base(path); !used[rel] {
			t.Errorf("examples/%s is not used by any target", rel)
		}
	}
	for _, name := range examplePlaceholders {
		if !used[name] {
			t.Errorf("placeholder %s is not referenced by examples/config.yml", name)
		}
		if d, _, _ := strings.Cut(name, "/"); !slices.Contains(exampleLocalDirs, d) {
			t.Errorf("placeholder %s is not in one of %v, which are kept out of git", name, exampleLocalDirs)
		}
	}
}

// TestExampleGitignore checks that the secrets and keys of a deployment made from the example
// cannot be committed by accident.
func TestExampleGitignore(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(examplesDir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for _, d := range exampleLocalDirs {
		if !slices.Contains(lines, "/"+d+"/") {
			t.Errorf("examples/.gitignore does not ignore /%s/", d)
		}
	}
}

type fileRef struct {
	field, path string
}

// referencedFiles returns the files a loaded target reads, with their paths resolved.
func referencedFiles(tg *config.Target) []fileRef {
	var refs []fileRef
	add := func(field, path string) {
		if path != "" {
			refs = append(refs, fileRef{field, path})
		}
	}
	add("body_file", tg.BodyFile)
	if k := tg.Kerberos; k != nil {
		add("kerberos.keytab", k.Keytab)
	}
	hc := &tg.HTTPClientConfig
	if b := hc.BasicAuth; b != nil {
		add("basic_auth.username_file", b.UsernameFile)
		add("basic_auth.password_file", b.PasswordFile)
	}
	if a := hc.Authorization; a != nil {
		add("authorization.credentials_file", a.CredentialsFile)
	}
	add("bearer_token_file", hc.BearerTokenFile)
	addTLS := func(field string, c *commoncfg.TLSConfig) {
		add(field+".ca_file", c.CAFile)
		add(field+".cert_file", c.CertFile)
		add(field+".key_file", c.KeyFile)
	}
	addTLS("tls_config", &hc.TLSConfig)
	if o := hc.OAuth2; o != nil {
		add("oauth2.client_secret_file", o.ClientSecretFile)
		add("oauth2.client_certificate_key_file", o.ClientCertificateKeyFile)
		addTLS("oauth2.tls_config", &o.TLSConfig)
	}
	if h := hc.HTTPHeaders; h != nil {
		for _, name := range slices.Sorted(maps.Keys(h.Headers)) {
			for _, f := range h.Headers[name].Files {
				add("http_headers."+name+".files", f)
			}
		}
	}
	return refs
}

// copyTree copies the regular files and directories under src to dst, except the top-level
// directories in skip.
func copyTree(t *testing.T, src, dst string, skip []string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir() && slices.Contains(skip, filepath.ToSlash(rel)):
			return fs.SkipDir
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case !d.Type().IsRegular():
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
