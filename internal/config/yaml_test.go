package config

import (
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v2"

	"github.com/poliproger/soap_exporter/internal/soap"
)

func parseNode(t *testing.T, s string) node {
	t.Helper()
	var n node
	if err := yaml.UnmarshalStrict([]byte(s), &n); err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name       string
		base, over string
		want       string
	}{
		{
			name: "mappings merge recursively",
			base: "{a: 1, m: {x: 1, y: 2}}",
			over: "{m: {y: 3, z: 4}}",
			want: `{"a": 1, "m": {"x": 1, "y": 3, "z": 4}}`,
		},
		{
			name: "lists replace",
			base: "{l: [1, 2]}",
			over: "{l: [3]}",
			want: `{"l": [3]}`,
		},
		{
			name: "scalar replaces mapping",
			base: "{m: {x: 1}}",
			over: "{m: x}",
			want: `{"m": "x"}`,
		},
		{
			name: "mapping replaces scalar",
			base: "{m: x}",
			over: "{m: {x: 1}}",
			want: `{"m": {"x": 1}}`,
		},
		{
			name: "null removes an inherited block",
			base: "{kerberos: {principal: p, keytab: k}, a: 1}",
			over: "{kerberos: null}",
			want: `{"a": 1}`,
		},
		{
			name: "null removes an inherited key",
			base: "{headers: {A: a, B: b}}",
			over: "{headers: {A: ~}}",
			want: `{"headers": {"B": "b"}}`,
		},
		{
			name: "an empty mapping keeps the inherited keys",
			base: "{m: {x: 1}}",
			over: "{m: {}}",
			want: `{"m": {"x": 1}}`,
		},
		{
			name: "nulls without a base value are dropped",
			base: "{}",
			over: "{x: null, y: {z: null}}",
			want: `{"y": {}}`,
		},
		{
			name: "nulls in the base are dropped",
			base: "{a: null, b: {c: null, d: 1}}",
			over: "{}",
			want: `{"b": {"d": 1}}`,
		},
		{
			name: "no base",
			base: "",
			over: "{a: 1, b: null}",
			want: `{"a": 1}`,
		},
		{
			name: "list items are kept as they are",
			base: "{}",
			over: "{l: [1, null, {a: null}]}",
			want: `{"l": [1, null, {}]}`,
		},
		{
			name: "scalars keep their text and type",
			base: "{a: x}",
			over: `{a: "1.10", b: 1.10, c: yes, d: 'yes', e: 0x1F, f: 1_000, g: .inf, h: 2001-12-14}`,
			want: `{"a": "1.10", "b": 1.10, "c": yes, "d": "yes", "e": 0x1F, "f": 1_000, "g": .inf, "h": "2001-12-14"}`,
		},
		{
			name: "quoted null is a string",
			base: "{}",
			over: `{a: "null", b: '~', c: null, "null": x}`,
			want: `{"a": !!str "null", "b": !!str "~", !!str "null": "x"}`,
		},
		{
			name: "keys are strings",
			base: "{1: a, true: b}",
			over: "{1: c}",
			want: `{"1": "c", "true": "b"}`,
		},
		{
			name: "keys are not YAML 1.1 booleans",
			base: "{}",
			over: "{y: a, yes: b, n: c, no: d, on: e, off: f}",
			want: `{"n": "c", "no": "d", "off": "f", "on": "e", "y": "a", "yes": "b"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var base node
			if tt.base != "" {
				base = parseNode(t, tt.base)
			}
			over := parseNode(t, tt.over)
			baseBefore, overBefore := string(base.encode()), string(over.encode())
			got := string(merge(base, over).encode())
			if got != tt.want {
				t.Errorf("merge = %s, want %s", got, tt.want)
			}
			if string(base.encode()) != baseBefore || string(over.encode()) != overBefore {
				t.Error("merge modified its inputs")
			}
		})
	}
}

// Encoding a tree and decoding it strictly gives the same values as decoding the original
// document: strings keep their text, other scalars their type.
func TestEncodeDecodesLikeTheOriginal(t *testing.T) {
	const doc = `
s1: 1.10
s2: 2.0
s3: yes
s4: 0x1F
s5: "quoted"
s6: 2001-12-14
s7: ~
i1: 0x1F
i2: 1_000
b1: yes
b2: off
f1: 1.10
f2: .inf
`
	type values struct {
		S1, S2, S3, S4, S5, S6, S7 string
		I1, I2                     int
		B1, B2                     bool
		F1, F2                     float64
	}
	var want, got values
	if err := yaml.UnmarshalStrict([]byte(doc), &want); err != nil {
		t.Fatal(err)
	}
	encoded := parseNode(t, doc).encode()
	if err := yaml.UnmarshalStrict(encoded, &got); err != nil {
		t.Fatalf("decode %s: %v", encoded, err)
	}
	if got != want {
		t.Errorf("decoded encoding = %+v\nwant %+v\nencoding: %s", got, want, encoded)
	}
	if want.S1 != "1.10" || want.S2 != "2.0" || want.S3 != "yes" || want.I1 != 31 || !want.B1 {
		t.Errorf("unexpected YAML semantics: %+v", want)
	}
}

// Every value is decoded once. A decoder that decodes each subtree again on every level
// above it takes seconds for a deeply nested value.
func TestParseDeepNesting(t *testing.T) {
	const depth = 9000 // yaml v2 rejects more than 10000
	doc := []byte("targets:\n  - name: a\n    labels: " + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "\n")
	start := time.Now()
	var v any
	if err := yaml.UnmarshalStrict(doc, &v); err != nil {
		t.Fatal(err)
	}
	plain := time.Since(start)

	start = time.Now()
	_, err := LoadBytes(doc, t.TempDir())
	elapsed := time.Since(start)
	if want := `target "a": labels: want a mapping, got a list`; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("LoadBytes = %v, want an error containing %q", err, want)
	}
	// Decoding the tree takes about 5 times as long as yaml v2 needs for an any.
	if elapsed > 50*plain+time.Second {
		t.Errorf("LoadBytes took %v, decoding into an any %v", elapsed, plain)
	}
}

func checkQuotedRoundTrip(t *testing.T, s string) {
	t.Helper()
	encoded := node{kind: mappingNode, m: map[string]node{s: {kind: stringNode, text: s}}}.encode()
	if strings.ContainsAny(string(encoded), "\n\x00") {
		t.Errorf("encoding of %q is not one line: %q", s, encoded)
	}
	var m map[string]string
	if err := yaml.UnmarshalStrict(encoded, &m); err != nil {
		t.Fatalf("decode encoding of %q (%q): %v", s, encoded, err)
	}
	if v, ok := m[s]; !ok || v != s || len(m) != 1 {
		t.Errorf("round trip of %q via %q = %q", s, encoded, m)
	}
	var n node
	if err := yaml.UnmarshalStrict(encoded, &n); err != nil {
		t.Fatal(err)
	}
	if v := n.m[s]; v.kind != stringNode || v.text != s {
		t.Errorf("round trip of %q into a node = %+v", s, v)
	}
}

var quotedSeeds = []string{
	"", "plain", `with "quotes" and \backslash`, "line1\nline2\r\n", "\ttab", " lead and trail ",
	"\x00\x01\x1f\x7f", "\u0085\u2028\u2029", "\ufeffbom", "\ufffe\uffff", "\u00e9moji \U0001F600", "\U0010FFFF",
	"\xff\xfe invalid UTF-8", "1.10", "yes", "null", "~", "2001-12-14", "- a", "a: b", "#c", "{x}",
	"[y]", "&anchor", "*alias", "!tag", "%", "@", "`", "<<", "? key", strings.Repeat("k", 2000),
	strings.Repeat("\x01", 400),
}

func TestEncodeQuoted(t *testing.T) {
	for _, s := range quotedSeeds {
		checkQuotedRoundTrip(t, s)
	}
}

func FuzzEncodeQuoted(f *testing.F) {
	for _, s := range quotedSeeds {
		f.Add(s)
	}
	f.Fuzz(checkQuotedRoundTrip)
}

func TestByteSize(t *testing.T) {
	tests := []struct {
		yaml    string
		want    ByteSize
		wantErr string
	}{
		{yaml: "4MiB", want: 4 << 20},
		{yaml: "512KiB", want: 512 << 10},
		{yaml: "10MB", want: 10 << 20}, // 1024-based as in Prometheus
		{yaml: "1.5MiB", want: 3 << 19},
		{yaml: "1GiB512MiB", want: 3 << 29},
		{yaml: "1048576", want: 1 << 20},
		{yaml: `"1048576"`, want: 1 << 20},
		{yaml: "0", want: 0},
		{yaml: "4mib", wantErr: `invalid size "4mib"`},
		{yaml: "4 MiB", wantErr: `invalid size "4 MiB"`},
		{yaml: "1.5", wantErr: "invalid size 1.5"},
		{yaml: "[1]", wantErr: "invalid size [1]"},
		{yaml: "99999999999999999999", wantErr: "invalid size 99999999999999999999"},
	}
	for _, tt := range tests {
		t.Run(tt.yaml, func(t *testing.T) {
			var b ByteSize
			err := yaml.UnmarshalStrict([]byte(tt.yaml), &b)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || b != tt.want {
				t.Errorf("= %d, %v; want %d", b, err, tt.want)
			}
		})
	}

	for size, want := range map[ByteSize]string{10 << 20: "10MiB\n", 512 << 10: "512KiB\n", 1500: "1KiB476B\n", 0: "0B\n"} {
		out, err := yaml.Marshal(size)
		if err != nil || string(out) != want {
			t.Errorf("Marshal(%d) = %q, %v; want %q", size, out, err, want)
		}
		var back ByteSize
		if err := yaml.UnmarshalStrict(out, &back); err != nil || back != size {
			t.Errorf("Unmarshal(%q) = %d, %v; want %d", out, back, err, size)
		}
	}
}

func TestSOAPYAML(t *testing.T) {
	tests := []struct {
		yaml    string
		want    SOAP
		wantErr string
	}{
		{yaml: "{version: 1.1}", want: SOAP{Version: soap.V11}},
		{yaml: "{version: 1.2}", want: SOAP{Version: soap.V12}},
		{yaml: `{version: "1.1"}`, want: SOAP{Version: soap.V11}},
		{yaml: `{version: '1.2', action: urn:x}`, want: SOAP{Version: soap.V12, Action: "urn:x"}},
		{yaml: "{action: urn:x}", want: SOAP{Version: soap.V12, Action: "urn:x"}}, // keeps the version
		{yaml: "{version: null}", want: SOAP{Version: soap.V12}},
		{yaml: "{version: 1.3}", wantErr: `version: unsupported SOAP version "1.3"`},
		{yaml: `{version: "1.10"}`, wantErr: `version: unsupported SOAP version "1.10"`},
		{yaml: "{version: 2}", wantErr: `version: unsupported SOAP version "2"`},
		{yaml: "{version: [1.1]}", wantErr: `version: unsupported SOAP version "[1.1]"`},
		{yaml: "{soap_version: 1.1}", wantErr: "field soap_version not found"},
	}
	for _, tt := range tests {
		t.Run(tt.yaml, func(t *testing.T) {
			s := SOAP{Version: soap.V12}
			err := yaml.UnmarshalStrict([]byte(tt.yaml), &s)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || s != tt.want {
				t.Errorf("= %+v, %v; want %+v", s, err, tt.want)
			}
		})
	}

	out, err := yaml.Marshal(SOAP{Version: soap.V12, Action: "urn:x"})
	if want := "version: \"1.2\"\naction: urn:x\n"; err != nil || string(out) != want {
		t.Errorf("Marshal = %q, %v; want %q", out, err, want)
	}
}

func TestRegexpAndXPathYAML(t *testing.T) {
	var v struct {
		R  Regexp  `yaml:"r"`
		P  *Regexp `yaml:"p"`
		X  XPath   `yaml:"x"`
		NP *Regexp `yaml:"np,omitempty"`
	}
	const doc = "r: ^a+$\np: (?s)b.c\nx: //a[@b = 'c']\n"
	if err := yaml.UnmarshalStrict([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	if !v.R.MatchString("aa") || v.R.MatchString("ab") || !v.P.MatchString("b\nc") || v.X.Expr != "//a[@b = 'c']" {
		t.Errorf("decoded %+v", v)
	}
	out, err := yaml.Marshal(v)
	if err != nil || string(out) != doc {
		t.Errorf("Marshal = %q, %v; want %q", out, err, doc)
	}
	if err := yaml.UnmarshalStrict([]byte("r: '(?i'"), &v); err == nil || !strings.Contains(err.Error(), "error parsing regexp") {
		t.Errorf("invalid regexp: error = %v", err)
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct{ path, key, want string }{
		{"", "labels", "labels"},
		{"labels", "team", "labels.team"},
		{"headers", "X Source", `headers["X Source"]`},
		{"headers", "a.b", `headers["a.b"]`},
		{"expect.namespaces", "", `expect.namespaces[""]`},
	}
	for _, tt := range tests {
		if got := joinPath(tt.path, tt.key); got != tt.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", tt.path, tt.key, got, tt.want)
		}
	}
}

// go.yaml.in/yaml/v2 takes the quoted strings "null" and "~" for null, and Regexp would
// inherit an UnmarshalText from the embedded nil *regexp.Regexp that panics on them.
func TestQuotedNull(t *testing.T) {
	var res []Regexp
	if err := yaml.UnmarshalStrict([]byte(`["null", "~"]`), &res); err != nil || len(res) != 2 || res[0].String() != "null" {
		t.Errorf("[]Regexp = %v, %v", res, err)
	}

	c, err := LoadBytes([]byte(`
targets:
  - name: "null"
    url: http://soap.example.com/
    body: '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>'
    labels:
      tier: "null"
    headers:
      X-Tilde: "~"
    expect:
      not_regex: ["null"]
      headers:
        - name: X-Null
          regex: "~"
`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tg := c.Targets[0]
	if tg.Name != "null" || tg.Labels["tier"] != "null" || tg.Headers["X-Tilde"] != "~" ||
		tg.Expect.NotRegex[0].String() != "null" || tg.Expect.Headers[0].Regex.String() != "~" {
		t.Errorf("target = %+v", tg)
	}
}
