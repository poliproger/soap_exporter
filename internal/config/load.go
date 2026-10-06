package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/alecthomas/units"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"go.yaml.in/yaml/v2"
	"golang.org/x/net/http/httpguts"

	"github.com/poliproger/soap_exporter/internal/soap"
)

// Built-in defaults for fields that neither defaults nor the target set. An unset timeout
// is defaultTimeout, but at most the interval (as Prometheus does for scrape_timeout).
const (
	defaultInterval = model.Duration(time.Minute)
	defaultTimeout  = model.Duration(10 * time.Second)
)

// targetOnlyFields may not appear in defaults (plan §5.2).
var targetOnlyFields = []string{"name", "url", "body", "body_file"}

// reservedLabels are the exporter's own labels, the target labels Prometheus attaches to
// every series, and le, the bucket label of soap_probe_duration_seconds.
var reservedLabels = map[string]bool{
	"target": true, "result": true, "reason": true, "phase": true, "version": true,
	"url": true, "soap_version": true, "soap_action": true, "auth": true,
	"job": true, "instance": true, "le": true,
}

// operatorLabels are target labels of the Prometheus Operator: scraped through it, user
// labels with these names become exported_<name> (plan D8).
var operatorLabels = map[string]bool{
	"namespace": true, "service": true, "pod": true, "container": true, "endpoint": true,
}

// loader collects the problems of one load. Every message starts with its scope ("defaults",
// `target "orders"`, "targets[2]" or nothing for the top level) and the field path.
type loader struct {
	dir      string // the directory relative paths are resolved against
	errs     []error
	warnings []string
}

func (l *loader) errorf(scope, path, format string, args ...any) {
	l.errs = append(l.errs, errors.New(location(scope, path)+fmt.Sprintf(format, args...)))
}

func (l *loader) warnf(scope, path, format string, args ...any) {
	l.warnings = append(l.warnings, location(scope, path)+fmt.Sprintf(format, args...))
}

func location(scope, path string) string {
	var b strings.Builder
	for _, s := range []string{scope, path} {
		if s != "" {
			b.WriteString(s)
			b.WriteString(": ")
		}
	}
	return b.String()
}

func load(data []byte, dir string) (*Config, error) {
	root, err := parse(data)
	if err != nil {
		return nil, err
	}
	l := &loader{dir: dir}
	defaults, targets := l.split(root)
	if len(l.errs) > 0 {
		// Every target inherits the defaults; their problems are reported once.
		return nil, errors.Join(l.errs...)
	}
	cfg := &Config{}
	names := make(map[string]int, len(targets))
	for i, tn := range targets {
		scope := fmt.Sprintf("targets[%d]", i)
		if tn.kind != mappingNode {
			l.errorf(scope, "", "want a mapping, got %s", tn.describe())
			continue
		}
		merged := merge(defaults, tn)
		if name, ok := merged.m["name"].scalar(); ok && name != "" {
			scope = fmt.Sprintf("target %q", name)
			if j, dup := names[name]; dup {
				l.errorf(scope, "name", "duplicate target name (also used by targets[%d])", j)
			} else {
				names[name] = i
			}
		}
		if t := l.target(scope, merged); t != nil {
			cfg.Targets = append(cfg.Targets, t)
		}
	}
	if len(l.errs) > 0 {
		return nil, errors.Join(l.errs...)
	}
	cfg.Warnings = l.warnings
	return cfg, nil
}

// split checks the top level and the defaults and returns the defaults and the targets.
func (l *loader) split(root node) (defaults node, targets []node) {
	if root.kind == nullNode {
		l.errorf("", "targets", "at least one target is required")
		return node{}, nil
	}
	if root.kind != mappingNode {
		l.errorf("", "", "want a mapping with defaults and targets, got %s", root.describe())
		return node{}, nil
	}
	for _, k := range slices.Sorted(maps.Keys(root.m)) {
		if k != "defaults" && k != "targets" {
			l.errorf("", joinPath("", k), "unknown field (the top level has defaults and targets)")
		}
	}
	if defaults = root.m["defaults"]; defaults.kind != nullNode {
		l.checkDefaults(defaults)
	}
	switch ts := root.m["targets"]; {
	case ts.kind == nullNode || ts.kind == sequenceNode && len(ts.items) == 0:
		l.errorf("", "targets", "at least one target is required")
	case ts.kind != sequenceNode:
		l.errorf("", "targets", "want a list, got %s", ts.describe())
	default:
		targets = ts.items
	}
	return defaults, targets
}

func (l *loader) checkDefaults(d node) {
	if d.kind != mappingNode {
		l.errorf("defaults", "", "want a mapping, got %s", d.describe())
		return
	}
	for _, k := range targetOnlyFields {
		if _, ok := d.m[k]; ok {
			l.errorf("defaults", k, "not allowed in defaults (set it per target)")
		}
	}
	// Decoding the defaults on their own reports unknown fields and invalid values once
	// instead of for every target. Rules across fields are checked in the targets, which
	// may complete the defaults.
	report := func(path, msg string) { l.errorf("defaults", path, "%s", msg) }
	decoder{report: report, partial: true}.decode(d, new(Target), "")
}

// httpClientKeys are the keys of the inlined HTTP client config.
var httpClientKeys = yamlKeys(reflect.TypeFor[commoncfg.HTTPClientConfig]())

// target decodes and validates one merged target. It returns nil if the target is invalid;
// the problems are recorded in l.
func (l *loader) target(scope string, n node) *Target {
	t, failed := decodeTarget(n, func(path, msg string) {
		l.errorf(scope, path, "%s", msg)
	})
	if t == nil {
		return nil
	}
	// A check runs only if the fields it reads were decoded, so that it neither repeats
	// their problems nor reports missing values.
	_, timeoutSet := n.m["timeout"]
	c := &targetCheck{l: l, scope: scope, t: t, failed: failed}
	if c.decoded("name") {
		c.name()
	}
	if c.decoded("url") {
		c.url()
	}
	if c.decoded("interval", "timeout") {
		c.durations(timeoutSet)
	}
	if c.decoded("soap") {
		c.soapAction()
	}
	if c.decoded("body", "body_file", "soap") {
		c.body()
	}
	if c.decoded("labels") {
		c.labels()
	}
	if c.decoded("headers") {
		c.headers()
	}
	authOK := c.auth()
	if c.decoded("kerberos") {
		c.kerberos()
	}
	if c.decoded(httpClientKeys...) {
		c.httpClient(authOK)
	}
	if c.decoded("max_response_size") && t.MaxResponseSize <= 0 {
		c.errorf("max_response_size", "must be positive")
	}
	if c.decoded("expect") {
		c.expect()
	}
	if len(failed) > 0 {
		return nil
	}
	t.Fingerprint = fingerprint(n, t.RequestBody)
	return t
}

// newTarget returns a target with the built-in defaults.
func newTarget() *Target {
	return &Target{
		Interval:        defaultInterval,
		SOAP:            SOAP{Version: soap.V11},
		MaxResponseSize: DefaultMaxResponseSize,
		Expect:          Expect{Status: []int{http.StatusOK}},
	}
}

// decodeTarget decodes a merged target. The keys whose values do not decode are reported
// and returned; t holds all the other values. t is nil if n does not decode at all.
func decodeTarget(n node, report reporter) (t *Target, failed map[string]bool) {
	t = newTarget()
	err := yaml.UnmarshalStrict(n.encode(), t)
	if err == nil {
		return t, nil
	}
	d := decoder{report: report}
	failed = make(map[string]bool)
	valid := node{kind: mappingNode, m: make(map[string]node, len(n.m))}
	for _, k := range slices.Sorted(maps.Keys(n.m)) {
		one := node{kind: mappingNode, m: map[string]node{k: n.m[k]}}
		if d.decode(one, newTarget(), "") {
			valid.m[k] = n.m[k]
		} else {
			failed[k] = true
		}
	}
	t = newTarget()
	if len(failed) == 0 || yaml.UnmarshalStrict(valid.encode(), t) != nil {
		reportYAMLError(err, "", report) // not a problem of single keys
		return nil, nil
	}
	return t, failed
}

// fingerprint hashes the canonical merged YAML of a target and its request body.
func fingerprint(n node, body []byte) string {
	h := sha256.New()
	h.Write(n.encode())
	h.Write([]byte{0}) // the encoded YAML never contains a NUL byte
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// targetCheck validates a decoded target and fills in its derived fields.
type targetCheck struct {
	l      *loader
	scope  string
	t      *Target
	failed map[string]bool // keys whose values did not decode
}

func (c *targetCheck) errorf(path, format string, args ...any) {
	c.l.errorf(c.scope, path, format, args...)
}

// decoded reports whether the values of all keys decoded.
func (c *targetCheck) decoded(keys ...string) bool {
	return !slices.ContainsFunc(keys, func(k string) bool { return c.failed[k] })
}

// name checks the name, which is the target label of every series and appears in logs.
func (c *targetCheck) name() {
	switch name := c.t.Name; {
	case name == "":
		c.errorf("name", "required")
	case !utf8.ValidString(name):
		c.errorf("name", "not valid UTF-8")
	case strings.ContainsFunc(name, unicode.IsControl):
		c.errorf("name", "contains control characters")
	}
}

// url parses the URL. The messages do not quote it: when url.Parse does not recognize the
// user info, as in "user:password@host/path", the password would end up in the logs.
func (c *targetCheck) url() {
	t := c.t
	if t.URL == "" {
		c.errorf("url", "required")
		return
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		c.errorf("url", "invalid URL: %s", urlError(err))
		return
	}
	switch {
	case u.User != nil:
		c.errorf("url", "must not contain credentials (use basic_auth)")
	case u.Scheme != "http" && u.Scheme != "https":
		c.errorf("url", "must be an absolute http or https URL")
	case u.Hostname() == "":
		c.errorf("url", "has no host")
	default:
		t.ParsedURL = u
	}
}

func (c *targetCheck) durations(timeoutSet bool) {
	t := c.t
	if t.Interval <= 0 {
		c.errorf("interval", "must be positive")
	}
	if !timeoutSet {
		t.Timeout = defaultTimeout
		if t.Interval > 0 {
			t.Timeout = min(t.Timeout, t.Interval)
		}
	}
	switch {
	case t.Timeout <= 0:
		c.errorf("timeout", "must be positive")
	case t.Interval > 0 && t.Timeout > t.Interval:
		c.errorf("timeout", "%s exceeds the interval %s", t.Timeout, t.Interval)
	}
}

func (c *targetCheck) soapAction() {
	if a := c.t.SOAP.Action; !httpguts.ValidHeaderFieldValue(a) {
		c.errorf("soap.action", "contains characters not allowed in an HTTP header")
	}
}

func (c *targetCheck) body() {
	t := c.t
	var field string
	switch {
	case t.Body != "" && t.BodyFile != "":
		c.errorf("body", "body and body_file are mutually exclusive")
		return
	case t.BodyFile != "":
		field = "body_file"
		t.BodyFile = commoncfg.JoinDir(c.l.dir, t.BodyFile)
		b, err := readBodyFile(t.BodyFile)
		if err != nil {
			c.errorf(field, "%v", err)
			return
		}
		t.RequestBody = b
	case t.Body != "":
		field = "body"
		t.RequestBody = []byte(t.Body)
	default:
		c.errorf("body", "one of body and body_file is required")
		return
	}
	if err := soap.ValidateRequest(t.RequestBody, t.SOAP.Version); err != nil {
		c.errorf(field, "invalid request: %v", err)
	}
}

// maxBodyFileSize limits body_file. Request bodies are small; the limit stops a load that
// reads a device such as /dev/zero.
const maxBodyFileSize = 1 << 20

func readBodyFile(path string) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBodyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBodyFileSize {
		return nil, fmt.Errorf("%s is larger than %s", path, units.Base2Bytes(maxBodyFileSize))
	}
	return b, nil
}

// openRegular opens a regular file for reading. Opening a named pipe would block the load
// until a writer appears.
func openRegular(path string) (*os.File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.Open(path)
}

func (c *targetCheck) labels() {
	for _, name := range slices.Sorted(maps.Keys(c.t.Labels)) {
		path := joinPath("labels", name)
		switch {
		case !model.LegacyValidation.IsValidLabelName(name):
			c.errorf(path, "invalid label name (want [a-zA-Z_][a-zA-Z0-9_]*)")
		case strings.HasPrefix(name, "__"):
			c.errorf(path, "label names starting with __ are reserved")
		case reservedLabels[name]:
			c.errorf(path, "reserved label name")
		case operatorLabels[name]:
			c.l.warnf(c.scope, path, "becomes exported_%s when scraped through the Prometheus Operator", name)
		}
		if !model.LabelValue(c.t.Labels[name]).IsValid() {
			c.errorf(path, "label value is not valid UTF-8")
		}
	}
}

// derivedHeader reports whether a request header comes from the SOAP or auth settings and
// may not be set directly (plan §5.2).
func derivedHeader(name string) (why string, ok bool) {
	switch strings.ToLower(name) {
	case "content-type", "soapaction":
		return "derived from soap.version and soap.action", true
	case "authorization":
		return "set by the auth settings", true
	}
	return "", false
}

func (c *targetCheck) headers() {
	seen := make(map[string]string, len(c.t.Headers))
	for _, name := range slices.Sorted(maps.Keys(c.t.Headers)) {
		path := joinPath("headers", name)
		if why, ok := derivedHeader(name); ok {
			c.errorf(path, "not allowed: %s", why)
			continue
		}
		if !httpguts.ValidHeaderFieldName(name) {
			c.errorf(path, "invalid header name")
			continue
		}
		if !httpguts.ValidHeaderFieldValue(c.t.Headers[name]) {
			c.errorf(path, "invalid header value")
		}
		key := http.CanonicalHeaderKey(name)
		if prev, ok := seen[key]; ok {
			c.errorf(path, "same header as %s", joinPath("headers", prev))
		}
		seen[key] = name
	}
}

// auth checks that at most one auth method is set and reports whether that is the case.
// bearer_token and bearer_token_file are the legacy form of authorization. A method whose
// value did not decode counts as set.
func (c *targetCheck) auth() bool {
	hc := &c.t.HTTPClientConfig
	type field struct {
		name string
		set  bool
	}
	methods := [][]field{
		{{"kerberos", c.t.Kerberos != nil}},
		{{"basic_auth", hc.BasicAuth != nil}},
		{
			{"authorization", hc.Authorization != nil},
			{"bearer_token", hc.BearerToken != ""},
			{"bearer_token_file", hc.BearerTokenFile != ""},
		},
		{{"oauth2", hc.OAuth2 != nil}},
	}
	var set []string
	n := 0
	for _, fields := range methods {
		used := false
		for _, f := range fields {
			if f.set || c.failed[f.name] {
				set = append(set, f.name)
				used = true
			}
		}
		if used {
			n++
		}
	}
	if n > 1 {
		c.errorf("", "at most one auth method may be set, found %s", strings.Join(set, ", "))
		return false
	}
	return true
}

func (c *targetCheck) kerberos() {
	k := c.t.Kerberos
	if k == nil {
		return
	}
	if k.Principal == "" {
		c.errorf("kerberos.principal", "required")
	}
	if k.Keytab == "" {
		c.errorf("kerberos.keytab", "required")
	} else {
		k.Keytab = commoncfg.JoinDir(c.l.dir, k.Keytab)
		if err := checkKeytab(k.Keytab); err != nil {
			c.errorf("kerberos.keytab", "%v", err)
		}
	}
	if k.SPN == "" && c.t.ParsedURL != nil {
		k.SPN = "HTTP/" + c.t.ParsedURL.Hostname()
	}
}

// checkKeytab checks that path is a readable non-empty regular file. Parsing it is the
// Kerberos backend's job.
func checkKeytab(path string) error {
	f, err := openRegular(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() == 0 {
		return fmt.Errorf("%s is empty", path)
	}
	return nil
}

// httpClient resolves the relative paths of the HTTP client config and validates it. Its
// UnmarshalYAML, which validates, is not called for an inlined struct.
func (c *targetCheck) httpClient(authOK bool) {
	hc := &c.t.HTTPClientConfig
	hc.SetDirectory(c.l.dir)
	if hc.OAuth2 != nil {
		// Not covered by OAuth2.SetDirectory.
		hc.OAuth2.ClientCertificateKeyFile = commoncfg.JoinDir(c.l.dir, hc.OAuth2.ClientCertificateKeyFile)
	}
	headers := hc.HTTPHeaders
	headersOK := true
	if headers != nil {
		for _, name := range slices.Sorted(maps.Keys(headers.Headers)) {
			if why, ok := derivedHeader(name); ok {
				c.errorf(joinPath("http_headers", name), "not allowed: %s", why)
				headersOK = false
			}
		}
		if headersOK {
			if err := headers.Validate(); err != nil {
				c.errorf("http_headers", "%v", err)
			}
		}
	}
	if !authOK {
		return // Validate would report the auth conflict again
	}
	// The headers were checked above; Validate stops at its first problem.
	hc.HTTPHeaders = nil
	err := hc.Validate()
	hc.HTTPHeaders = headers
	if err != nil {
		c.errorf("", "%v", err)
	}
}

func (c *targetCheck) expect() {
	e := &c.t.Expect
	if len(e.Status) == 0 {
		c.errorf("expect.status", "at least one status code is required")
	}
	for i, s := range e.Status {
		if s < 100 || s > 599 {
			c.errorf(fmt.Sprintf("expect.status[%d]", i), "%d is not an HTTP status code (100-599)", s)
		}
	}
	for i, h := range e.Headers {
		path := fmt.Sprintf("expect.headers[%d]", i)
		switch {
		case h.Name == "":
			c.errorf(path+".name", "required")
		case !httpguts.ValidHeaderFieldName(h.Name):
			c.errorf(path+".name", "invalid header name")
		}
		if h.Regex == nil && h.NotRegex == nil {
			c.errorf(path, "one of regex and not_regex is required")
		}
	}
	// The decoder leaves a null item a Regexp without an expression.
	for _, list := range []struct {
		field string
		res   []Regexp
	}{{"expect.regex", e.Regex}, {"expect.not_regex", e.NotRegex}} {
		for i, r := range list.res {
			if r.Regexp == nil {
				c.errorf(fmt.Sprintf("%s[%d]", list.field, i), "want a regular expression, got null")
			}
		}
	}
	ns, ok := c.namespaces()
	if !ok {
		return // the XPath errors would only repeat the namespace problems
	}
	for _, list := range []struct {
		field string
		exprs []XPath
	}{{"expect.xpath", e.XPath}, {"expect.not_xpath", e.NotXPath}} {
		for i := range list.exprs {
			if err := list.exprs[i].compile(ns); err != nil {
				c.errorf(fmt.Sprintf("%s[%d]", list.field, i), "%v", err)
			}
		}
	}
}

// namespaces returns the XPath namespace bindings of the target: expect.namespaces plus the
// built-in prefixes.
func (c *targetCheck) namespaces() (map[string]string, bool) {
	ns := map[string]string{
		PrefixSOAP:   c.t.SOAP.Version.EnvelopeNS(),
		PrefixSOAP11: soap.NS11,
		PrefixSOAP12: soap.NS12,
	}
	ok := true
	for _, prefix := range slices.Sorted(maps.Keys(c.t.Expect.Namespaces)) {
		uri := c.t.Expect.Namespaces[prefix]
		path := joinPath("expect.namespaces", prefix)
		switch {
		case prefix == PrefixSOAP || prefix == PrefixSOAP11 || prefix == PrefixSOAP12:
			c.errorf(path, "built-in prefix, cannot be redefined")
		case !isNCName(prefix):
			c.errorf(path, "invalid prefix (want an XML NCName)")
		case prefix == "xmlns":
			c.errorf(path, "reserved prefix")
		case prefix == "xml" && uri != xmlNS:
			c.errorf(path, "the prefix xml can only be bound to %s", xmlNS)
		case prefix != "xml" && uri == xmlNS:
			c.errorf(path, "only the prefix xml can be bound to %s", xmlNS)
		case uri == "":
			c.errorf(path, "empty namespace URI")
		default:
			ns[prefix] = uri
			continue
		}
		ok = false
	}
	return ns, ok
}
