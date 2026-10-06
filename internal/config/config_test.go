package config

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"go.yaml.in/yaml/v2"

	"github.com/poliproger/soap_exporter/internal/soap"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const exampleFile = "testdata/valid/example/config.yml"

func mustLoad(t *testing.T, path string) *Config {
	t.Helper()
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	return c
}

func targetByName(t *testing.T, c *Config, name string) *Target {
	t.Helper()
	for _, tg := range c.Targets {
		if tg.Name == name {
			return tg
		}
	}
	t.Fatalf("no target %q", name)
	return nil
}

func absDir(t *testing.T, path string) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func check[T comparable](t *testing.T, field string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", field, got, want)
	}
}

func checkMap(t *testing.T, field string, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", field, got, want)
		return
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %v, want %v", field, got, want)
			return
		}
	}
}

func TestLoadExample(t *testing.T) {
	c := mustLoad(t, exampleFile)
	dir := absDir(t, exampleFile)
	check(t, "File", c.File, filepath.Join(dir, "config.yml"))
	if len(c.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none", c.Warnings)
	}
	var names []string
	for _, tg := range c.Targets {
		names = append(names, tg.Name)
	}
	if want := []string{"branches-load", "orders-status", "inventory"}; !slices.Equal(names, want) {
		t.Fatalf("targets = %q, want %q (file order)", names, want)
	}

	t.Run("branches-load", func(t *testing.T) {
		tg := targetByName(t, c, "branches-load")
		check(t, "Interval", tg.Interval, model.Duration(5*time.Minute))
		check(t, "Timeout", tg.Timeout, model.Duration(30*time.Second))
		check(t, "SOAP.Version", tg.SOAP.Version, soap.V11) // quoted "1.1"
		check(t, "SOAP.Action", tg.SOAP.Action, "http://tempuri.org/LoadBranches")
		checkMap(t, "Labels", tg.Labels, map[string]string{"system": "core", "team": "core-banking"})
		checkMap(t, "Headers", tg.Headers, map[string]string{"X-Request-Source": "monitoring"})
		// The kerberos block merges key by key: principal and keytab inherited, spn set.
		check(t, "Kerberos", *tg.Kerberos, Kerberos{
			Principal: "monitor@CORP.EXAMPLE",
			Keytab:    filepath.Join(dir, "monitor.keytab"),
			SPN:       "HTTP/core-alias.corp.example",
		})
		check(t, "AuthType", tg.AuthType(), "kerberos")
		check(t, "BodyFile", tg.BodyFile, filepath.Join(dir, "requests", "load-branches.xml"))
		body, err := os.ReadFile(filepath.Join(dir, "requests", "load-branches.xml"))
		if err != nil {
			t.Fatal(err)
		}
		check(t, "RequestBody", string(tg.RequestBody), string(body))
		check(t, "MaxResponseSize", tg.MaxResponseSize, DefaultMaxResponseSize)
		check(t, "TLSConfig.CAFile", tg.HTTPClientConfig.TLSConfig.CAFile, filepath.Join(dir, "certs", "corp-root.pem"))
		check(t, "Expect.NotRegex", regexSources(tg.Expect.NotRegex), `ORA-\d{5}`)
		check(t, "Expect.XPath", xpathSources(tg.Expect.XPath), "//ds:Branches[ds:Id = '1']")
		if tg.Expect.XPath[0].Compiled == nil {
			t.Error("Expect.XPath[0] is not compiled")
		}
	})

	t.Run("orders-status", func(t *testing.T) {
		tg := targetByName(t, c, "orders-status")
		check(t, "Interval", tg.Interval, model.Duration(time.Minute)) // from defaults
		check(t, "Timeout", tg.Timeout, model.Duration(10*time.Second))
		check(t, "SOAP.Version", tg.SOAP.Version, soap.V12) // unquoted 1.2
		// Scalars keep their text through the merge: 1.10 and 2.0 are not numbers here.
		checkMap(t, "Labels", tg.Labels, map[string]string{"system": "core", "team": "payments", "release": "1.10"})
		checkMap(t, "Headers", tg.Headers, map[string]string{"X-Request-Source": "monitoring", "X-Api-Version": "2.0"})
		if tg.Kerberos != nil {
			t.Errorf("Kerberos = %+v, want nil (kerberos: null drops the inherited block)", tg.Kerberos)
		}
		check(t, "AuthType", tg.AuthType(), "basic")
		ba := tg.HTTPClientConfig.BasicAuth
		check(t, "BasicAuth.Username", ba.Username, "monitor")
		check(t, "BasicAuth.PasswordFile", ba.PasswordFile, filepath.Join(dir, "secrets", "orders-password"))
		// tls_config merges key by key.
		tls := tg.HTTPClientConfig.TLSConfig
		check(t, "TLSConfig.CAFile", tls.CAFile, filepath.Join(dir, "certs", "corp-root.pem"))
		check(t, "TLSConfig.CertFile", tls.CertFile, filepath.Join(dir, "certs", "monitor.pem"))
		check(t, "TLSConfig.KeyFile", tls.KeyFile, filepath.Join(dir, "certs", "monitor.key"))
		check(t, "TLSConfig.MinVersion", tls.MinVersion.String(), "TLS12")
		check(t, "ProxyURL", tg.HTTPClientConfig.ProxyURL.String(), "http://proxy.corp.example:3128")
		check(t, "MaxResponseSize", tg.MaxResponseSize, 4<<20)
		check(t, "Body", tg.Body, "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\n"+
			"  <s:Body><GetStatus xmlns=\"http://corp.example/\"/></s:Body>\n</s:Envelope>\n")
		check(t, "RequestBody", string(tg.RequestBody), tg.Body)
		check(t, "BodyFile", tg.BodyFile, "")
		// Lists replace: the inherited not_regex is gone.
		check(t, "Expect.NotRegex", regexSources(tg.Expect.NotRegex), "Exception")
		check(t, "Expect.XPath", xpathSources(tg.Expect.XPath), "count(//o:Order) > 0")
		check(t, "Expect.NotXPath", xpathSources(tg.Expect.NotXPath), "//o:Status[. = 'Maintenance']")
		check(t, "len(Expect.Headers)", len(tg.Expect.Headers), 1)
		h := tg.Expect.Headers[0]
		check(t, "Expect.Headers[0].Name", h.Name, "Content-Type")
		check(t, "Expect.Headers[0].Regex", h.Regex.String(), `^application/soap\+xml`)
		if h.NotRegex != nil {
			t.Errorf("Expect.Headers[0].NotRegex = %v, want nil", h.NotRegex)
		}
		check(t, "ParsedURL.Port", tg.ParsedURL.Port(), "8443")
	})

	t.Run("inventory", func(t *testing.T) {
		tg := targetByName(t, c, "inventory")
		check(t, "SOAP.Version", tg.SOAP.Version, soap.V11) // built-in default
		// null drops an inherited header.
		checkMap(t, "Headers", tg.Headers, map[string]string{"User-Agent": "inventory-probe/1.0"})
		// The SPN defaults to HTTP/<url hostname>, without the port.
		check(t, "Kerberos.SPN", tg.Kerberos.SPN, "HTTP/inventory.corp.example")
		check(t, "MaxResponseSize", tg.MaxResponseSize, 512<<10)
		check(t, "Expect.Status", fmt.Sprint(tg.Expect.Status), "[200 202]")
		check(t, "Expect.AllowSOAPFault", tg.Expect.AllowSOAPFault, true)
		check(t, "Expect.NotRegex", regexSources(tg.Expect.NotRegex), `ORA-\d{5}`)
	})
}

func regexSources(rs []Regexp) string {
	s := make([]string, len(rs))
	for i, r := range rs {
		s[i] = r.String()
	}
	return strings.Join(s, " | ")
}

func xpathSources(xs []XPath) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = x.Expr
	}
	return strings.Join(s, " | ")
}

func TestBuiltInDefaults(t *testing.T) {
	c := mustLoad(t, "testdata/valid/minimal.yml")
	tg := targetByName(t, c, "minimal")
	check(t, "Interval", tg.Interval, model.Duration(time.Minute))
	check(t, "Timeout", tg.Timeout, model.Duration(10*time.Second))
	check(t, "SOAP.Version", tg.SOAP.Version, soap.V11)
	check(t, "MaxResponseSize", tg.MaxResponseSize, DefaultMaxResponseSize)
	check(t, "Expect.Status", fmt.Sprint(tg.Expect.Status), "[200]")
	check(t, "FollowRedirects", tg.HTTPClientConfig.FollowRedirects, false)
	check(t, "EnableHTTP2", tg.HTTPClientConfig.EnableHTTP2, false)
	check(t, "KeepAlive", tg.KeepAlive, false)
	check(t, "AuthType", tg.AuthType(), "none")
	check(t, "ParsedURL.Host", tg.ParsedURL.Host, "soap.example.com")

	fast := targetByName(t, c, "fast")
	check(t, "fast Timeout", fast.Timeout, model.Duration(5*time.Second))
}

// containsPattern reports whether s contains pattern, where "..." in pattern matches any
// text (such as the absolute path of the fixture directory).
func containsPattern(s, pattern string) bool {
	for part := range strings.SplitSeq(pattern, "...") {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return true
}

// Invalid fixtures declare the expected errors in "# want:" lines, in the order they are
// reported, and strings that must not appear (secrets) in "# reject:" lines.
func TestLoadInvalid(t *testing.T) {
	files, err := filepath.Glob("testdata/invalid/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".yml"), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var want, reject []string
			for line := range strings.Lines(string(data)) {
				line = strings.TrimRight(line, "\n")
				if w, ok := strings.CutPrefix(line, "# want: "); ok {
					want = append(want, w)
				}
				if r, ok := strings.CutPrefix(line, "# reject: "); ok {
					reject = append(reject, r)
				}
			}
			if len(want) == 0 {
				t.Fatal("fixture has no # want: line")
			}
			c, err := Load(file)
			if err == nil {
				t.Fatalf("Load succeeded with %d targets, want errors %q", len(c.Targets), want)
			}
			errs := []error{err}
			if joined, ok := err.(interface{ Unwrap() []error }); ok {
				errs = joined.Unwrap()
			}
			if len(errs) != len(want) {
				t.Errorf("got %d errors, want %d:\n%v", len(errs), len(want), err)
			}
			for i, e := range errs[:min(len(errs), len(want))] {
				if !containsPattern(e.Error(), want[i]) {
					t.Errorf("error %d = %q, want it to contain %q", i, e, want[i])
				}
			}
			for _, r := range reject {
				if strings.Contains(err.Error(), r) {
					t.Errorf("errors contain %q:\n%v", r, err)
				}
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load("testdata/valid/missing.yml"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load(missing) = %v, want ErrNotExist", err)
	}
	if _, err := LoadBytes(nil, t.TempDir()); err == nil || !strings.Contains(err.Error(), "targets: at least one target is required") {
		t.Errorf("LoadBytes(empty) = %v, want no-targets error", err)
	}
}

func TestKeytabUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file permissions do not restrict this user")
	}
	dir := t.TempDir()
	keytab := filepath.Join(dir, "monitor.keytab")
	if err := os.WriteFile(keytab, []byte{5, 2}, 0o200); err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`
targets:
  - name: orders
    url: https://orders.example.com/Orders.svc
    body: '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>'
    kerberos:
      principal: monitor@CORP.EXAMPLE
      keytab: monitor.keytab
`)
	_, err := LoadBytes(cfg, dir)
	if want := `target "orders": kerberos.keytab: open ` + keytab + ": permission denied"; err == nil || err.Error() != want {
		t.Errorf("LoadBytes = %v, want %s", err, want)
	}
}

// Rules across fields of tls_config and oauth2 apply to the merged targets, not to the
// defaults alone.
func TestDefaultsCompletedByTargets(t *testing.T) {
	const file = "testdata/valid/defaults-partial.yml"
	tg := targetByName(t, mustLoad(t, file), "orders")
	dir := absDir(t, file)
	tls := tg.HTTPClientConfig.TLSConfig
	check(t, "TLSConfig.CertFile", tls.CertFile, filepath.Join(dir, "certs", "monitor.pem"))
	check(t, "TLSConfig.KeyFile", tls.KeyFile, filepath.Join(dir, "certs", "monitor.key"))
	oauth2 := tg.HTTPClientConfig.OAuth2
	check(t, "OAuth2.TokenURL", oauth2.TokenURL, "https://auth.corp.example/token")
	check(t, "OAuth2.ProxyURL", oauth2.ProxyURL.String(), "http://proxy.corp.example:3128")
}

func TestBodyFileSizeLimit(t *testing.T) {
	const envelope = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>`
	cfg := []byte(`
targets:
  - name: orders
    url: https://orders.example.com/Orders.svc
    body_file: request.xml
`)
	for _, size := range []int{maxBodyFileSize, maxBodyFileSize + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			dir := t.TempDir()
			body := filepath.Join(dir, "request.xml")
			// Whitespace after the root element is well-formed XML.
			data := append([]byte(envelope), bytes.Repeat([]byte("\n"), size-len(envelope))...)
			if err := os.WriteFile(body, data, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadBytes(cfg, dir)
			if size <= maxBodyFileSize {
				if err != nil {
					t.Errorf("LoadBytes = %v, want no error", err)
				}
				return
			}
			if want := `target "orders": body_file: ` + body + " is larger than 1MiB"; err == nil || err.Error() != want {
				t.Errorf("LoadBytes = %v, want %s", err, want)
			}
		})
	}
}

// Merge keys (<<) behave as when yaml v2 decodes a Target: in a target or the defaults, a
// key overrides the merged values that precede it. Nested mappings cannot override merged
// keys.
func TestMergeKeys(t *testing.T) {
	const body = `'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>'`
	const base = `
  - &base
    name: a
    url: https://a.example.com/Service.svc
    body: ` + body + `
    interval: 2m
    labels: &labels
      system: billing
`
	tests := []struct {
		name    string
		yaml    string
		check   func(t *testing.T, c *Config)
		wantErr string
	}{
		{
			name: "keys after the merge key override merged values",
			yaml: `
defaults:
  labels:
    team: core
targets:` + base + `
  - <<: *base
    name: b
    url: https://b.example.com/Service.svc
  - <<: *base
    name: c
    labels: null
`,
			check: func(t *testing.T, c *Config) {
				b := targetByName(t, c, "b")
				check(t, "b URL", b.URL, "https://b.example.com/Service.svc")
				check(t, "b Interval", b.Interval, model.Duration(2*time.Minute))
				checkMap(t, "b Labels", b.Labels, map[string]string{"team": "core", "system": "billing"})
				// null drops the merged and the inherited labels.
				checkMap(t, "c Labels", targetByName(t, c, "c").Labels, nil)

				expanded, err := LoadBytes([]byte(`
defaults:
  labels:
    team: core
targets:
  - name: b
    url: https://b.example.com/Service.svc
    body: `+body+`
    interval: 2m
    labels:
      system: billing
`), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				check(t, "b Fingerprint", b.Fingerprint, expanded.Targets[0].Fingerprint)
			},
		},
		{
			name: "a merge key overrides the keys before it",
			yaml: "targets:" + base + `
  - interval: 3m
    <<: *base
    name: b
`,
			check: func(t *testing.T, c *Config) {
				check(t, "b Interval", targetByName(t, c, "b").Interval, model.Duration(2*time.Minute))
			},
		},
		{
			name: "earlier merged mappings take precedence",
			yaml: "targets:" + base + `
  - &other
    name: other
    url: https://other.example.com/Service.svc
    body: ` + body + `
    interval: 3m
    timeout: 5s
  - <<: [*base, *other]
    name: b
`,
			check: func(t *testing.T, c *Config) {
				b := targetByName(t, c, "b")
				check(t, "b URL", b.URL, "https://a.example.com/Service.svc")
				check(t, "b Interval", b.Interval, model.Duration(2*time.Minute))
				check(t, "b Timeout", b.Timeout, model.Duration(5*time.Second))
			},
		},
		{
			name: "defaults",
			yaml: `
defaults:
  <<: {interval: 2m, timeout: 5s}
  interval: 3m
targets:
  - name: a
    url: https://a.example.com/Service.svc
    body: ` + body + `
`,
			check: func(t *testing.T, c *Config) {
				a := targetByName(t, c, "a")
				check(t, "a Interval", a.Interval, model.Duration(3*time.Minute))
				check(t, "a Timeout", a.Timeout, model.Duration(5*time.Second))
			},
		},
		{
			name: "nested mappings merge the keys they do not set",
			yaml: "targets:" + base + `
  - name: b
    url: https://b.example.com/Service.svc
    body: ` + body + `
    labels:
      <<: *labels
      team: core
`,
			check: func(t *testing.T, c *Config) {
				checkMap(t, "b Labels", targetByName(t, c, "b").Labels, map[string]string{"system": "billing", "team": "core"})
			},
		},
		{
			name: "nested mappings cannot override merged keys",
			yaml: "targets:" + base + `
  - name: b
    url: https://b.example.com/Service.svc
    body: ` + body + `
    labels:
      <<: *labels
      system: payments
`,
			wantErr: `key "system" already set in map`,
		},
		{
			name: "a key set twice",
			yaml: "targets:" + base + `
  - <<: *base
    name: b
    name: c
`,
			wantErr: "field name already set in type config.Target",
		},
		{
			name: "an unknown key",
			yaml: "targets:" + base + `
  - <<: *base
    name: b
    intervall: 3m
`,
			wantErr: "field intervall not found in type config.Target",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadBytes([]byte(tt.yaml), t.TempDir())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoadBytes = %v, want an error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, c)
		})
	}
}

func TestLoadBytesResolvesRelativeDir(t *testing.T) {
	data, err := os.ReadFile(exampleFile)
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadBytes(data, filepath.Dir(exampleFile))
	if err != nil {
		t.Fatal(err)
	}
	check(t, "File", c.File, "")
	want := filepath.Join(absDir(t, exampleFile), "monitor.keytab")
	check(t, "Keytab", targetByName(t, c, "inventory").Kerberos.Keytab, want)

	// The same configuration from the file has the same fingerprints.
	fromFile := mustLoad(t, exampleFile)
	for i, tg := range c.Targets {
		check(t, tg.Name+" Fingerprint", tg.Fingerprint, fromFile.Targets[i].Fingerprint)
	}
}

func TestWarnings(t *testing.T) {
	c := mustLoad(t, "testdata/valid/operator-labels.yml")
	want := []string{
		`target "orders": labels.container: becomes exported_container when scraped through the Prometheus Operator`,
		`target "orders": labels.endpoint: becomes exported_endpoint when scraped through the Prometheus Operator`,
		`target "orders": labels.namespace: becomes exported_namespace when scraped through the Prometheus Operator`,
		`target "orders": labels.pod: becomes exported_pod when scraped through the Prometheus Operator`,
		`target "orders": labels.service: becomes exported_service when scraped through the Prometheus Operator`,
	}
	if !slices.Equal(c.Warnings, want) {
		t.Errorf("Warnings =\n%s\nwant\n%s", strings.Join(c.Warnings, "\n"), strings.Join(want, "\n"))
	}
	check(t, "namespace label", c.Targets[0].Labels["namespace"], "payments")
}

// copyDir copies the example fixture so that tests can change its files.
func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
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
	return dst
}

func fingerprints(c *Config) map[string]string {
	m := make(map[string]string, len(c.Targets))
	for _, tg := range c.Targets {
		m[tg.Name] = tg.Fingerprint
	}
	return m
}

func TestFingerprint(t *testing.T) {
	dir := copyDir(t, filepath.Dir(exampleFile))
	file := filepath.Join(dir, "config.yml")
	first := fingerprints(mustLoad(t, file))
	if len(first) != 3 || first["branches-load"] == first["orders-status"] || first["orders-status"] == first["inventory"] {
		t.Fatalf("fingerprints are not distinct: %v", first)
	}
	for name, fp := range first {
		if len(fp) != 64 {
			t.Errorf("%s: fingerprint %q is not a hex SHA-256", name, fp)
		}
	}

	t.Run("stable", func(t *testing.T) {
		checkMap(t, "fingerprints", fingerprints(mustLoad(t, file)), first)
	})

	t.Run("body file changes", func(t *testing.T) {
		req := filepath.Join(dir, "requests", "load-branches.xml")
		orig, err := os.ReadFile(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile(req, orig, 0o644) })
		changed := bytes.Replace(orig, []byte("<LoadBranches "), []byte("<LoadBranches region=\"north\" "), 1)
		if err := os.WriteFile(req, changed, 0o644); err != nil {
			t.Fatal(err)
		}
		got := fingerprints(mustLoad(t, file))
		if got["branches-load"] == first["branches-load"] {
			t.Error("branches-load fingerprint unchanged after its body file changed")
		}
		check(t, "orders-status", got["orders-status"], first["orders-status"])
		check(t, "inventory", got["inventory"], first["inventory"])
	})

	t.Run("defaults change", func(t *testing.T) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		// branches-load sets its own timeout; the others inherit it.
		data = bytes.Replace(data, []byte("  timeout: 10s\n"), []byte("  timeout: 20s\n"), 1)
		c, err := LoadBytes(data, dir)
		if err != nil {
			t.Fatal(err)
		}
		got := fingerprints(c)
		check(t, "branches-load", got["branches-load"], first["branches-load"])
		if got["orders-status"] == first["orders-status"] || got["inventory"] == first["inventory"] {
			t.Error("fingerprints of targets inheriting the timeout did not change")
		}
	})

	t.Run("key order does not matter", func(t *testing.T) {
		const body = `'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>'`
		a, err := LoadBytes([]byte(`
targets:
  - name: x
    url: http://soap.example.com/
    labels: {a: "1", b: "2"}
    body: `+body), dir)
		if err != nil {
			t.Fatal(err)
		}
		b, err := LoadBytes([]byte(`
targets:
  - body: `+body+`
    labels: {b: "2", a: "1"}
    url: http://soap.example.com/
    name: x
`), dir)
		if err != nil {
			t.Fatal(err)
		}
		check(t, "fingerprint", b.Targets[0].Fingerprint, a.Targets[0].Fingerprint)
	})
}

func TestRedacted(t *testing.T) {
	c := mustLoad(t, "testdata/valid/secrets.yml")
	out, err := c.Redacted()
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "s3cret") {
		t.Errorf("Redacted leaks a secret:\n%s", text)
	}
	// header, basic, TLS key, authorization, bearer (converted to authorization), oauth2,
	// proxy CONNECT header.
	if n := strings.Count(text, "<secret>"); n < 7+3 {
		t.Errorf("Redacted has %d <secret> markers, want 10 (http_headers is inherited by all four targets):\n%s", n, text)
	}
	for _, want := range []string{
		"http://proxy-user:xxxxx@proxy.example.com:3128",
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>`,
		"-----BEGIN CERTIFICATE-----",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Redacted lacks %q:\n%s", want, text)
		}
	}
	var parsed struct {
		Targets []map[string]any `yaml:"targets"`
	}
	if err := yaml.Unmarshal(out, &parsed); err != nil || len(parsed.Targets) != 4 {
		t.Fatalf("Redacted output does not parse into 4 targets: %v", err)
	}
	check(t, "bearer authorization type", parsed.Targets[2]["authorization"].(map[any]any)["type"], any("Bearer"))
}

func TestRedactedRefusesToExposeSecrets(t *testing.T) {
	c := mustLoad(t, "testdata/valid/secrets.yml")
	commoncfg.MarshalSecretValue = true
	t.Cleanup(func() { commoncfg.MarshalSecretValue = false })
	if out, err := c.Redacted(); err == nil {
		t.Errorf("Redacted with MarshalSecretValue = %s, want an error", out)
	}
}

// The redacted example is compared with a golden file, with the fixture directory replaced
// by $DIR. Run with -update to rewrite it.
func TestRedactedGolden(t *testing.T) {
	out, err := mustLoad(t, exampleFile).Redacted()
	if err != nil {
		t.Fatal(err)
	}
	out = bytes.ReplaceAll(out, []byte(absDir(t, exampleFile)), []byte("$DIR"))
	golden := "testdata/valid/example/redacted.golden.yml"
	if *update {
		if err := os.WriteFile(golden, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Errorf("Redacted differs from %s (run with -update):\n%s", golden, out)
	}
}
