package config

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"

	"github.com/poliproger/soap_exporter/internal/soap"
)

func formatQNames(names []qname) string {
	s := make([]string, len(names))
	for i, q := range names {
		s[i] = q.prefix + ":" + q.local
		if q.function {
			s[i] += "()"
		}
	}
	return strings.Join(s, " ")
}

var prefixTests = []struct {
	expr string
	want string // prefixed names as p:local, functions as p:local()
}{
	{"//a", ""},
	{"/soap:Envelope/soap:Body", "soap:Envelope soap:Body"},
	{"//p:*", "p:*"},
	{"//p:*/q:a", "p:* q:a"},
	{"//*", ""},
	{"//@*", ""},
	{"*", ""},
	{"//p:a/@q:b", "p:a q:b"},
	{"@q:b", "q:b"},
	// Axis names are not prefixes, with or without spaces before "::".
	{"child::p:a", "p:a"},
	{"child :: p:a", "p:a"},
	{"child::*", ""},
	{"attribute::p:a", "p:a"},
	{"descendant-or-self::node()/p:a", "p:a"},
	{"ancestor-or-self::p:a/following-sibling::q:b", "p:a q:b"},
	// String literals are skipped.
	{"//a[@q:attr='x:y']", "q:attr"},
	{`concat("a:b", 'c:d')`, ""},
	{`//a[. = "it's p:x"]`, ""},
	{`//a[. = 'say "p:x"']`, ""},
	{`'unterminated p:a`, ""},
	{`//a[@b = "unterminated p:a]`, ""},
	// Node type tests and functions.
	{"//text()", ""},
	{"//p:a/text()", "p:a"},
	{"processing-instruction('p:x')", ""},
	{"//comment()|//node()", ""},
	{"count(//p:a) > 0", "p:a"},
	{"not(//p:a)", "p:a"},
	{"p:f(//a)", "p:f()"},
	{"p:f (//a)", "p:f()"},
	{"p:f\t()", "p:f()"},
	{"//p:a [1]", "p:a"},
	// Variables.
	{"$v:x", "v:x"},
	{"$x", ""},
	// Operators and numbers.
	{"price*0.01", ""},
	{"p:a*q:b", "p:a q:b"},
	{"//p:a|//q:b", "p:a q:b"},
	{"//a[p:b!=1]", "p:b"},
	{"//a[p:b<=1 and q:c>=2]", "p:b q:c"},
	{"//a[p:b=1 or q:c=2]", "p:b q:c"},
	{"5 div p:x", "p:x"},
	{"5div p:x", "p:x"},
	{"1.5+p:x", "p:x"},
	{".5", ""},
	{"..//p:x", "p:x"},
	{"./p:x", "p:x"},
	{"-p:x", "p:x"},
	{"//a -b:c", "b:c"},
	// Names may contain "-", "." and digits, and non-ASCII letters.
	{"//ns-1:a.b", "ns-1:a.b"},
	{"//a-b:c-d", "a-b:c-d"},
	{"//a.b:c", "a.b:c"},
	{"//p:1a", "p:1a"},
	{"//é:ü", "é:ü"},
	{"//日本:語", "日本:語"},
	// Not QNames: the compiler rejects these.
	{"p: x", ""},
	{"p :x", ""},
	{"//a:b:c", "a:b"},
	{"//:a", ""},
	{"", ""},
	// Typical expressions.
	{"//ds:Branches[ds:Id = '1']", "ds:Branches ds:Id"},
	{"count(//o:Order) > 0", "o:Order"},
	{"//o:Status[. = 'Maintenance']", "o:Status"},
	{"boolean(/soap12:Envelope/soap12:Body/*[local-name() = 'GetStatusResponse'])", "soap12:Envelope soap12:Body"},
	{"//*[local-name()='Row' and namespace-uri()='urn:x']", ""},
}

func TestPrefixedNames(t *testing.T) {
	for _, tt := range prefixTests {
		if got := formatQNames(prefixedNames(tt.expr)); got != tt.want {
			t.Errorf("prefixedNames(%q) = %q, want %q", tt.expr, got, tt.want)
		}
	}
}

// bind declares every prefix the lexer found.
func bind(names []qname) map[string]string {
	ns := map[string]string{}
	for _, q := range names {
		ns[q.prefix] = "urn:" + q.prefix
	}
	return ns
}

// antchfx/xpath rejects an undeclared prefix of a name test when it gets a namespace map.
// Declaring exactly the prefixes found by prefixedNames must therefore satisfy it: it never
// sees a prefix the lexer missed.
func checkLexerSeesAntchfxPrefixes(t *testing.T, expr string) {
	t.Helper()
	_, err := xpath.CompileWithNS(expr, bind(prefixedNames(expr)))
	if err != nil && strings.Contains(err.Error(), "not defined") {
		t.Errorf("CompileWithNS(%q) with the prefixes %q found by the lexer: %v",
			expr, formatQNames(prefixedNames(expr)), err)
	}
}

func TestPrefixedNamesAgreesWithAntchfx(t *testing.T) {
	for _, tt := range prefixTests {
		checkLexerSeesAntchfxPrefixes(t, tt.expr)
	}
}

func FuzzPrefixedNames(f *testing.F) {
	for _, tt := range prefixTests {
		f.Add(tt.expr)
	}
	f.Fuzz(func(t *testing.T, expr string) {
		if strings.ContainsRune(expr, 0) {
			return // rejected before lexing
		}
		checkLexerSeesAntchfxPrefixes(t, expr)
	})
}

func TestIsNCName(t *testing.T) {
	for s, want := range map[string]bool{
		"o": true, "_a": true, "ns-1": true, "a.b": true, "é": true, "a·b": true, "日本": true,
		"": false, "1a": false, "-a": false, ".a": false, "·a": false, "a:b": false, "a b": false,
		"a*": false, "$a": false,
	} {
		if got := isNCName(s); got != want {
			t.Errorf("isNCName(%q) = %v, want %v", s, got, want)
		}
	}
}

const (
	soap11Doc = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` +
		`<x:Orders xmlns:x="http://corp.example/"><x:Order/></x:Orders></soap:Body></soap:Envelope>`
	soap12Doc = `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body>` +
		`<Orders xmlns="http://corp.example/"><Order/><Order/></Orders></env:Body></env:Envelope>`
)

// evaluate converts the result of an expression with XPath boolean().
func evaluate(t *testing.T, x XPath, doc string) bool {
	t.Helper()
	root, err := soap.ParseXML(doc)
	if err != nil {
		t.Fatal(err)
	}
	switch v := x.Compiled.Evaluate(xmlquery.CreateXPathNavigator(root)).(type) {
	case bool:
		return v
	case float64:
		return v != 0 && !math.IsNaN(v)
	case string:
		return v != ""
	case *xpath.NodeIterator:
		return v.MoveNext()
	default:
		t.Fatalf("unexpected result %T", v)
		return false
	}
}

func loadXPaths(t *testing.T, version string, namespaces map[string]string, exprs ...string) ([]XPath, error) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "targets:\n  - name: x\n    url: http://soap.example.com/\n    soap: {version: %q}\n", version)
	if version == "1.1" {
		b.WriteString(`    body: '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>'` + "\n")
	} else {
		b.WriteString(`    body: '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>'` + "\n")
	}
	b.WriteString("    expect:\n      namespaces: {")
	for p, uri := range namespaces {
		fmt.Fprintf(&b, "%q: %q, ", p, uri)
	}
	b.WriteString("}\n      xpath:\n")
	for _, e := range exprs {
		fmt.Fprintf(&b, "        - %q\n", e)
	}
	c, err := LoadBytes([]byte(b.String()), t.TempDir())
	if err != nil {
		return nil, err
	}
	return c.Targets[0].Expect.XPath, nil
}

func TestXPathNamespaces(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		namespaces map[string]string
		expr       string
		doc        string
		want       bool
	}{
		{"soap is the 1.1 envelope", "1.1", nil, "/soap:Envelope/soap:Body", soap11Doc, true},
		{"soap is not the 1.2 envelope for 1.1", "1.1", nil, "/soap:Envelope/soap:Body", soap12Doc, false},
		{"soap is the 1.2 envelope", "1.2", nil, "/soap:Envelope/soap:Body", soap12Doc, true},
		{"soap11", "1.2", nil, "/soap11:Envelope", soap11Doc, true},
		{"soap12", "1.1", nil, "/soap12:Envelope", soap12Doc, true},
		// A declared prefix matches by namespace URI, whatever prefix the document uses.
		{"declared prefix", "1.1", map[string]string{"o": "http://corp.example/"}, "count(//o:Order) = 1", soap11Doc, true},
		{"declared prefix, default namespace", "1.2", map[string]string{"o": "http://corp.example/"}, "count(//o:Order) = 2", soap12Doc, true},
		{"declared prefix, other namespace", "1.1", map[string]string{"o": "http://other.example/"}, "//o:Order", soap11Doc, false},
		{"xml prefix", "1.1", map[string]string{"xml": xmlNS}, "not(//@xml:lang)", soap11Doc, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xs, err := loadXPaths(t, tt.version, tt.namespaces, tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			if got := evaluate(t, xs[0], tt.doc); got != tt.want {
				t.Errorf("%s = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

// The document's own prefix x is not a declared prefix: antchfx/xpath would match it
// literally (plan finding 3), so it is rejected.
func TestXPathUndeclaredPrefixes(t *testing.T) {
	tests := []struct{ expr, want string }{
		{"//x:Order", `namespace prefix "x" is not declared`},
		{"x:count(//a) > 0", `namespace prefix "x" is not declared`},
		{"$x:v", `namespace prefix "x" is not declared`},
		{"//x:Order[y:a = 1]|//x:*", `namespace prefixes "x", "y" are not declared`},
		{"soap:count(//a)", "prefixed function name soap:count is not supported"},
		{"//a\x00/x:b", "expression contains a NUL character"},
		{"   ", "empty expression"},
		{"//a[", "invalid expression"},
	}
	for _, tt := range tests {
		_, err := loadXPaths(t, "1.1", nil, tt.expr)
		if err == nil || !strings.Contains(err.Error(), "expect.xpath[0]: "+tt.want) {
			t.Errorf("%q: error = %v, want %q", tt.expr, err, tt.want)
		}
	}
}
