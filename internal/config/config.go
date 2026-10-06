// Package config loads, merges, validates and compiles the exporter configuration
// (plan §5).
package config

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"github.com/antchfx/xpath"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"go.yaml.in/yaml/v2"

	"github.com/poliproger/soap_exporter/internal/soap"
)

// DefaultMaxResponseSize is the default of max_response_size.
const DefaultMaxResponseSize ByteSize = 10 << 20

// Built-in XPath prefixes (plan §5.3). "soap" is bound to the envelope namespace of the
// target's SOAP version. They cannot be redefined in expect.namespaces.
const (
	PrefixSOAP   = "soap"
	PrefixSOAP11 = "soap11"
	PrefixSOAP12 = "soap12"
)

// Config is a loaded, validated configuration.
type Config struct {
	// Targets in file order.
	Targets []*Target
	// Warnings are non-fatal findings (e.g. Prometheus Operator label names), each naming
	// the target and the field.
	Warnings []string
	// File is the absolute path of the loaded file ("" for LoadBytes).
	File string
}

// Target is one probed SOAP endpoint after the defaults were merged in.
type Target struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	// Interval defaults to 1m.
	Interval model.Duration `yaml:"interval"`
	// Timeout defaults to 10s, but at most Interval (as scrape_timeout in Prometheus).
	Timeout  model.Duration    `yaml:"timeout"`
	Labels   map[string]string `yaml:"labels,omitempty"`
	SOAP     SOAP              `yaml:"soap"`
	Body     string            `yaml:"body,omitempty"`
	BodyFile string            `yaml:"body_file,omitempty"`
	// Headers are extra request headers. Content-Type, SOAPAction and Authorization are
	// rejected (plan §5.2); User-Agent overrides the default.
	Headers   map[string]string `yaml:"headers,omitempty"`
	Kerberos  *Kerberos         `yaml:"kerberos,omitempty"`
	KeepAlive bool              `yaml:"keep_alive"`
	// MaxResponseSize defaults to DefaultMaxResponseSize.
	MaxResponseSize ByteSize `yaml:"max_response_size"`
	Expect          Expect   `yaml:"expect"`

	// HTTPClientConfig is the standard Prometheus HTTP client config, inlined. Defaults
	// differ from prometheus/common: follow_redirects and enable_http2 are false (D4).
	HTTPClientConfig commoncfg.HTTPClientConfig `yaml:",inline"`

	// Derived at load time.

	// ParsedURL is URL parsed.
	ParsedURL *url.URL `yaml:"-"`
	// RequestBody is the body (from body or body_file) sent with every probe.
	RequestBody []byte `yaml:"-"`
	// Fingerprint identifies the effective target configuration, including the request
	// body contents. Two loads of an unchanged target yield the same fingerprint; on
	// reload, targets with an unchanged name and fingerprint keep their state (plan §7).
	Fingerprint string `yaml:"-"`
}

// SOAP selects the SOAP version and action.
type SOAP struct {
	// Version defaults to soap.V11. YAML accepts 1.1, 1.2, "1.1" and "1.2".
	Version soap.Version `yaml:"version"`
	Action  string       `yaml:"action,omitempty"`
}

// Kerberos configures SPNEGO authentication.
type Kerberos struct {
	// Principal is "name@REALM" or "name" (the default realm of krb5.conf applies).
	Principal string `yaml:"principal"`
	// Keytab is the keytab path, resolved against the config file directory.
	Keytab string `yaml:"keytab"`
	// SPN is the service principal; it defaults to "HTTP/<url hostname>" (no port, no DNS
	// canonicalization, plan D5). It is always set after loading.
	SPN string `yaml:"spn,omitempty"`
}

// Expect configures the response checks (plan §6.4).
type Expect struct {
	// Status lists the accepted HTTP status codes; default [200].
	Status         []int             `yaml:"status"`
	AllowSOAPFault bool              `yaml:"allow_soap_fault"`
	Namespaces     map[string]string `yaml:"namespaces,omitempty"`
	Headers        []HeaderCheck     `yaml:"headers,omitempty"`
	Regex          []Regexp          `yaml:"regex,omitempty"`
	NotRegex       []Regexp          `yaml:"not_regex,omitempty"`
	XPath          []XPath           `yaml:"xpath,omitempty"`
	NotXPath       []XPath           `yaml:"not_xpath,omitempty"`
}

// HeaderCheck checks one response header. A missing header fails a Regex check; NotRegex
// passes for a missing header. At least one of Regex and NotRegex is required.
type HeaderCheck struct {
	Name     string  `yaml:"name"`
	Regex    *Regexp `yaml:"regex,omitempty"`
	NotRegex *Regexp `yaml:"not_regex,omitempty"`
}

// Regexp is a compiled Go RE2 regular expression that marshals back to its source.
type Regexp struct {
	*regexp.Regexp
}

// XPath is an XPath 1.0 expression compiled with the target's namespaces plus the built-in
// prefixes. Expressions using undeclared prefixes are rejected at load (plan finding 3).
type XPath struct {
	Expr     string
	Compiled *xpath.Expr
}

// ByteSize is a size in bytes. YAML accepts integers and units such as 4MiB, 512KiB, 10MB.
type ByteSize int64

// Load reads the config file and returns the validated configuration. Relative paths are
// resolved against the directory of the file. All errors name the target and the field.
//
// Each target is deep-merged over defaults (plan §5.2). A null value removes an inherited
// value, so the built-in default applies again.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	c, err := load(data, filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	c.File = abs
	return c, nil
}

// LoadBytes is Load for in-memory data; relative paths are resolved against dir.
func LoadBytes(data []byte, dir string) (*Config, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return load(data, dir)
}

// Redacted returns the effective configuration as YAML with all secrets replaced by
// "<secret>" (for the /config endpoint). Inline request bodies are kept.
func (c *Config) Redacted() ([]byte, error) {
	// Secrets marshal as "<secret>" unless this prometheus/common switch is turned on.
	if commoncfg.MarshalSecretValue {
		return nil, errors.New("refusing to marshal the configuration: config.MarshalSecretValue would expose secrets")
	}
	return yaml.Marshal(struct {
		Targets []*Target `yaml:"targets"`
	}{c.Targets})
}

// AuthType returns the auth method of the target for soap_target_info: "kerberos",
// "basic", "authorization", "oauth2" or "none".
func (t *Target) AuthType() string {
	switch {
	case t.Kerberos != nil:
		return "kerberos"
	case t.HTTPClientConfig.BasicAuth != nil:
		return "basic"
	case t.HTTPClientConfig.Authorization != nil,
		t.HTTPClientConfig.BearerToken != "", t.HTTPClientConfig.BearerTokenFile != "":
		return "authorization"
	case t.HTTPClientConfig.OAuth2 != nil:
		return "oauth2"
	}
	return "none"
}
