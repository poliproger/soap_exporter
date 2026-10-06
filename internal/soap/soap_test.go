package soap

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	"golang.org/x/net/html/charset"
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// encode converts UTF-8 text to the charset named by label.
func encode(t testing.TB, label, s string) []byte {
	t.Helper()
	e, _ := charset.Lookup(label)
	if e == nil {
		t.Fatalf("unknown charset %q", label)
	}
	b, err := e.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func utf16Bytes(s string, bigEndian bool) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			b = append(b, byte(u>>8), byte(u))
		} else {
			b = append(b, byte(u), byte(u>>8))
		}
	}
	return b
}

func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatalf("unexpected error: %v", err)
	case want != "" && err == nil:
		t.Fatalf("error = nil, want one containing %q", want)
	case want != "" && !strings.Contains(err.Error(), want):
		t.Fatalf("error = %q, want one containing %q", err, want)
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in      string
		want    Version
		wantNS  string
		wantErr bool
	}{
		{in: "1.1", want: V11, wantNS: NS11},
		{in: "1.2", want: V12, wantNS: NS12},
		{in: "1.0", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := ParseVersion(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if v != tt.want || v.String() != tt.in || v.EnvelopeNS() != tt.wantNS {
				t.Errorf("got %v (%q, %q), want %v (%q, %q)", int(v), v, v.EnvelopeNS(), int(tt.want), tt.in, tt.wantNS)
			}
		})
	}
	if s := Version(0).String(); s != "invalid" {
		t.Errorf("Version(0).String() = %q, want invalid", s)
	}
}

func TestSetRequestHeaders(t *testing.T) {
	tests := []struct {
		name   string
		v      Version
		action string
		want   http.Header
	}{
		{
			name:   "1.1",
			v:      V11,
			action: "urn:example:GetStatus",
			want: http.Header{
				"Content-Type": {"text/xml; charset=utf-8"},
				"SOAPAction":   {`"urn:example:GetStatus"`},
			},
		},
		{
			name: "1.1 empty action",
			v:    V11,
			want: http.Header{
				"Content-Type": {"text/xml; charset=utf-8"},
				"SOAPAction":   {`""`},
			},
		},
		{
			name:   "1.1 action with quote and backslash",
			v:      V11,
			action: `urn:example:a"b\c`,
			want: http.Header{
				"Content-Type": {"text/xml; charset=utf-8"},
				"SOAPAction":   {`"urn:example:a\"b\\c"`},
			},
		},
		{
			name:   "1.2",
			v:      V12,
			action: "http://example.com/GetStatus",
			want: http.Header{
				"Content-Type": {`application/soap+xml; charset=utf-8; action="http://example.com/GetStatus"`},
			},
		},
		{
			name: "1.2 empty action",
			v:    V12,
			want: http.Header{
				"Content-Type": {"application/soap+xml; charset=utf-8"},
			},
		},
		{
			name:   "invalid version",
			v:      Version(0),
			action: "urn:example:GetStatus",
			want:   http.Header{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			SetRequestHeaders(h, tt.v, tt.action)
			if !reflect.DeepEqual(h, tt.want) {
				t.Errorf("headers = %#v, want %#v", h, tt.want)
			}
		})
	}
}

func TestSetRequestHeadersOnTheWire(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://example.com/service.asmx", strings.NewReader("<a/>"))
	if err != nil {
		t.Fatal(err)
	}
	SetRequestHeaders(req.Header, V11, "urn:example:GetStatus")
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatal(err)
	}
	wire := buf.String()
	if !strings.Contains(wire, "\r\nSOAPAction: \"urn:example:GetStatus\"\r\n") {
		t.Errorf("request does not carry SOAPAction with its exact spelling:\n%s", wire)
	}
	if strings.Contains(wire, "Soapaction") {
		t.Errorf("request carries a canonicalized Soapaction header:\n%s", wire)
	}
}

func TestDecodeBody(t *testing.T) {
	const (
		doc      = "<a>Привет, мир</a>"
		decl1251 = `<?xml version="1.0" encoding="windows-1251"?>`
		declKOI8 = `<?xml version="1.0" encoding="koi8-r"?>`
	)
	tests := []struct {
		name        string
		body        []byte
		contentType string
		wantText    string
		wantCharset string
		wantErr     string
	}{
		{
			name:        "default utf-8",
			body:        []byte(doc),
			contentType: "text/xml",
			wantText:    doc,
			wantCharset: "utf-8",
		},
		{
			name:        "no content type",
			body:        []byte(doc),
			wantText:    doc,
			wantCharset: "utf-8",
		},
		{
			name:        "empty body",
			contentType: "text/xml; charset=utf-8",
			wantCharset: "utf-8",
		},
		{
			name:        "utf-8 BOM",
			body:        concat(bomUTF8, []byte(doc)),
			wantText:    doc,
			wantCharset: "utf-8",
		},
		{
			name:        "utf-16le BOM",
			body:        concat(bomUTF16LE, utf16Bytes(doc, false)),
			wantText:    doc,
			wantCharset: "utf-16le",
		},
		{
			name:        "utf-16be BOM",
			body:        concat(bomUTF16BE, utf16Bytes(doc, true)),
			wantText:    doc,
			wantCharset: "utf-16be",
		},
		{
			name:        "windows-1251 via charset parameter",
			body:        []byte("<a>\xcf\xf0\xe8\xe2\xe5\xf2, \xec\xe8\xf0</a>"),
			contentType: "text/xml; charset=windows-1251",
			wantText:    doc,
			wantCharset: "windows-1251",
		},
		{
			name:        "charset parameter is case-insensitive and may be quoted",
			body:        encode(t, "koi8-r", doc),
			contentType: `text/xml; Charset="KOI8-R"`,
			wantText:    doc,
			wantCharset: "koi8-r",
		},
		{
			name:        "charset alias resolves to the canonical name",
			body:        encode(t, "windows-1251", doc),
			contentType: "text/xml; charset=cp1251",
			wantText:    doc,
			wantCharset: "windows-1251",
		},
		{
			name:        "windows-1251 via declaration only",
			body:        encode(t, "windows-1251", decl1251+doc),
			contentType: "text/xml",
			wantText:    decl1251 + doc,
			wantCharset: "windows-1251",
		},
		{
			name:        "declaration with single quotes after whitespace",
			body:        encode(t, "windows-1251", "\r\n<?xml version='1.0' encoding = 'Windows-1251' ?>"+doc),
			wantText:    "\r\n<?xml version='1.0' encoding = 'Windows-1251' ?>" + doc,
			wantCharset: "windows-1251",
		},
		{
			name:        "charset parameter beats declaration",
			body:        encode(t, "windows-1251", declKOI8+doc),
			contentType: "text/xml; charset=windows-1251",
			wantText:    declKOI8 + doc,
			wantCharset: "windows-1251",
		},
		{
			name:        "utf-8 charset parameter beats declaration",
			body:        []byte(decl1251 + doc),
			contentType: "application/soap+xml; charset=utf-8",
			wantText:    decl1251 + doc,
			wantCharset: "utf-8",
		},
		{
			name:        "BOM beats charset parameter",
			body:        concat(bomUTF8, []byte(doc)),
			contentType: "text/xml; charset=windows-1251",
			wantText:    doc,
			wantCharset: "utf-8",
		},
		{
			name:        "BOM beats declaration",
			body:        concat(bomUTF16LE, utf16Bytes(decl1251+doc, false)),
			wantText:    decl1251 + doc,
			wantCharset: "utf-16le",
		},
		{
			name:        "iso-8859-1 resolves to windows-1252",
			body:        []byte("<a>caf\xe9 \x80</a>"),
			contentType: "text/xml; charset=ISO-8859-1",
			wantText:    "<a>café €</a>",
			wantCharset: "windows-1252",
		},
		{
			name:        "malformed content type",
			body:        encode(t, "windows-1251", doc),
			contentType: "text/xml; charset=windows-1251; foo",
			wantText:    doc,
			wantCharset: "windows-1251",
		},
		{
			name:        "duplicate charset parameters",
			body:        encode(t, "windows-1251", doc),
			contentType: "text/xml; charset=windows-1251; charset=utf-8",
			wantText:    doc,
			wantCharset: "windows-1251",
		},
		{
			name:        "empty charset parameter falls through to declaration",
			body:        encode(t, "windows-1251", decl1251+doc),
			contentType: "text/xml; charset=",
			wantText:    decl1251 + doc,
			wantCharset: "windows-1251",
		},
		{
			name:        "declaration claiming utf-16 is read as utf-8",
			body:        []byte(`<?xml version="1.0" encoding="UTF-16"?>` + doc),
			wantText:    `<?xml version="1.0" encoding="UTF-16"?>` + doc,
			wantCharset: "utf-8",
		},
		{
			name:        "encoding outside the declaration is ignored",
			body:        []byte(`<?xml version="1.0"?><a encoding="koi8-r">Привет</a>`),
			wantText:    `<?xml version="1.0"?><a encoding="koi8-r">Привет</a>`,
			wantCharset: "utf-8",
		},
		{
			name:        "invalid utf-8 is kept as is",
			body:        []byte("<a>\xff\xfe</a>"),
			wantText:    "<a>\xff\xfe</a>",
			wantCharset: "utf-8",
		},
		{
			name:        "unknown charset parameter",
			body:        []byte(doc),
			contentType: "text/xml; charset=x-unknown",
			wantErr:     `unknown charset "x-unknown" in Content-Type`,
		},
		{
			name:    "unknown charset in declaration",
			body:    []byte(`<?xml version="1.0" encoding="x-unknown"?><a/>`),
			wantErr: `unknown charset "x-unknown" in XML declaration`,
		},
		{
			name:        "replacement encoding is unknown",
			body:        []byte(doc),
			contentType: "text/xml; charset=iso-2022-kr",
			wantErr:     `unknown charset "iso-2022-kr"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, cs, err := DecodeBody(tt.body, tt.contentType)
			checkErr(t, err, tt.wantErr)
			if text != tt.wantText || cs != tt.wantCharset {
				t.Errorf("DecodeBody() = %q, %q, want %q, %q", text, cs, tt.wantText, tt.wantCharset)
			}
		})
	}
}

func TestParseXML(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		wantText string // text content of the root element
		wantErr  string
	}{
		{name: "element", text: `<a>x</a>`, wantText: "x"},
		{
			name:     "declaration claiming windows-1251 on utf-8 text",
			text:     `<?xml version="1.0" encoding="windows-1251"?><a>Привет</a>`,
			wantText: "Привет",
		},
		{name: "leading BOM", text: "\xef\xbb\xbf<a>x</a>", wantText: "x"},
		{name: "comment before root without declaration", text: "<!-- c -->\n<a>x</a>\n", wantText: "x"},
		{name: "predefined entities and character references", text: `<a>&lt;&amp;&gt;&quot;&apos;&#1055;&#x440;</a>`, wantText: `<&>"'Пр`},
		{name: "DOCTYPE quoted in CDATA", text: `<a><![CDATA[<!DOCTYPE html>]]></a>`, wantText: "<!DOCTYPE html>"},
		{name: "DOCTYPE in a comment", text: `<!-- <!DOCTYPE a> --><a>x</a>`, wantText: "x"},
		{name: "DOCTYPE", text: `<!DOCTYPE a><a/>`, wantErr: "DOCTYPE is not allowed"},
		{
			name:    "DOCTYPE after declaration and comment",
			text:    "<?xml version=\"1.0\"?>\n<!-- c -->\n<!DOCTYPE a SYSTEM \"http://example.com/a.dtd\">\n<a/>",
			wantErr: "DOCTYPE is not allowed",
		},
		{
			name:    "DOCTYPE with an internal entity",
			text:    `<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>`,
			wantErr: "DOCTYPE is not allowed",
		},
		{name: "DOCTYPE after the root element", text: `<a/><!DOCTYPE a>`, wantErr: "DOCTYPE is not allowed"},
		{name: "markup declaration inside an element", text: `<a><!ELEMENT a ANY></a>`, wantErr: "DTD markup declarations are not allowed"},
		{name: "HTML entity", text: `<a>&nbsp;</a>`, wantErr: "invalid character entity &nbsp;"},
		{name: "undefined entity", text: `<a>&e;</a>`, wantErr: "invalid character entity &e;"},
		{name: "unclosed element", text: `<a><b></a>`, wantErr: "XML syntax error"},
		{name: "truncated", text: `<a>`, wantErr: "XML syntax error"},
		{name: "HTML", text: `<html><body><br></body></html>`, wantErr: "XML syntax error"},
		{name: "invalid utf-8", text: "<a>\xff</a>", wantErr: "invalid UTF-8"},
		{name: "undeclared prefix", text: `<x:a/>`, wantErr: "element <x:a>: namespace prefix x is not declared"},
		{
			name:    "prefix declared on a closed sibling",
			text:    `<a><p:b xmlns:p="urn:example:p"/><p:c/></a>`,
			wantErr: "element <p:c>: namespace prefix p is not declared",
		},
		{name: "xmlns as an element prefix", text: `<xmlns:a/>`, wantErr: "namespace prefix xmlns is not declared"},
		{
			name:    "end tag with another prefix",
			text:    `<p:a xmlns:p="urn:example:p" xmlns:q="urn:example:p"></q:a>`,
			wantErr: "element <p:a> closed by </q:a>",
		},
		{name: "end tag after the root element", text: "<a/>\n</b>", wantErr: "XML syntax error on line 2: unexpected end element </b>"},
		{name: "unclosed root element", text: `<a><b/>`, wantErr: "unexpected EOF: element <a> is not closed"},
		{name: "empty", wantErr: "empty document"},
		{name: "whitespace only", text: " \r\n\t", wantErr: "empty document"},
		{name: "comment only", text: `<!-- c -->`, wantErr: "no root element"},
		{name: "two root elements", text: `<a/><b/>`, wantErr: "more than one root element"},
		{name: "text after the root element", text: `<a/>junk`, wantErr: "text outside the root element"},
		{name: "text before the root element", text: `junk<a/>`, wantErr: "text outside the root element"},
		{name: "CDATA before the root element", text: `<![CDATA[ ]]><a/>`, wantErr: "text outside the root element"},
		// Responses are read as leniently as encoding/xml reads them; ValidateRequest is stricter.
		{name: "XML declaration after a comment", text: `<!-- c --><?xml version="1.0" encoding="koi8-r"?><a>x</a>`, wantText: "x"},
		{name: "XML declaration after the root element", text: `<a>x</a><?xml version="1.0"?>`, wantText: "x"},
		{name: "repeated attribute", text: `<a b="1" b="2">x</a>`, wantText: "x"},
		{name: "undeclared attribute prefix", text: `<a xsi:nil="true">x</a>`, wantText: "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParseXML(tt.text)
			checkErr(t, err, tt.wantErr)
			if err != nil {
				return
			}
			if got := rootElement(doc).InnerText(); got != tt.wantText {
				t.Errorf("root text = %q, want %q", got, tt.wantText)
			}
		})
	}
}

var nodeTypeNames = map[xmlquery.NodeType]string{
	xmlquery.DocumentNode:          "document",
	xmlquery.DeclarationNode:       "declaration",
	xmlquery.ElementNode:           "element",
	xmlquery.TextNode:              "text",
	xmlquery.CharDataNode:          "cdata",
	xmlquery.CommentNode:           "comment",
	xmlquery.NotationNode:          "notation",
	xmlquery.ProcessingInstruction: "pi",
}

// dumpTree renders the subtree of n with every field the XPath navigator reads, one node per
// line, and reports broken links between nodes.
func dumpTree(n *xmlquery.Node) string {
	var b strings.Builder
	var dump func(n *xmlquery.Node, indent string)
	dump = func(n *xmlquery.Node, indent string) {
		fmt.Fprintf(&b, "%s%s %q", indent, nodeTypeNames[n.Type], n.Data)
		if n.Prefix != "" {
			fmt.Fprintf(&b, " prefix=%s", n.Prefix)
		}
		if n.NamespaceURI != "" {
			fmt.Fprintf(&b, " ns=%s", n.NamespaceURI)
		}
		if n.ProcInst != nil {
			// xmlquery also reads pseudo-attributes from processing instructions; ParseXML does not.
			fmt.Fprintf(&b, " inst=%q\n", n.ProcInst.Inst)
		} else {
			for _, a := range n.Attr {
				fmt.Fprintf(&b, " @%s=%q", qname(a.Name), a.Value)
				if a.NamespaceURI != "" {
					fmt.Fprintf(&b, "{%s}", a.NamespaceURI)
				}
			}
			b.WriteByte('\n')
		}
		var prev *xmlquery.Node
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Parent != n || c.PrevSibling != prev {
				fmt.Fprintf(&b, "%s  broken link to %s %q\n", indent, nodeTypeNames[c.Type], c.Data)
			}
			dump(c, indent+"  ")
			prev = c
		}
		if n.LastChild != prev {
			fmt.Fprintf(&b, "%s  broken LastChild\n", indent)
		}
	}
	dump(n, "")
	return b.String()
}

func TestParseXMLTree(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "prolog and epilog",
			text: "\uFEFF<?xml version=\"1.0\"?>\n<!-- c -->\n<?pi  x=\"1\" ?>\n<a/>\n<!-- d -->\n",
			want: `document ""
  comment " c "
  pi "pi" inst="x=\"1\""
  element "a"
  comment " d "
`,
		},
		{
			name: "text, CDATA and comments",
			text: `<a>t<![CDATA[<c>]]>&lt;<!--x-->u<?pi?></a>`,
			want: `document ""
  element "a"
    text "t"
    cdata "<c>"
    text "<"
    comment "x"
    text "u"
    pi "pi" inst=""
`,
		},
		{
			name: "prefix as written when a namespace has two prefixes",
			text: `<a:x xmlns:a="urn:example:u" xmlns:b="urn:example:u"><b:y/></a:x>`,
			want: `document ""
  element "x" prefix=a ns=urn:example:u @xmlns:a="urn:example:u"{xmlns} @xmlns:b="urn:example:u"{xmlns}
    element "y" prefix=b ns=urn:example:u
`,
		},
		{
			name: "namespace scope",
			text: `<a xmlns:p="urn:example:1"><p:b xmlns:p="urn:example:2"/><p:c/></a>`,
			want: `document ""
  element "a" @xmlns:p="urn:example:1"{xmlns}
    element "b" prefix=p ns=urn:example:2 @xmlns:p="urn:example:2"{xmlns}
    element "c" prefix=p ns=urn:example:1
`,
		},
		{
			name: "default namespace",
			text: `<a xmlns="urn:example:1"><b xmlns=""><c/></b><d/></a>`,
			want: `document ""
  element "a" ns=urn:example:1 @xmlns="urn:example:1"
    element "b" @xmlns=""
      element "c"
    element "d" ns=urn:example:1
`,
		},
		{
			name: "attributes",
			text: `<a xmlns:p="urn:example:p" x="1" p:y="2" xml:lang="en" q:z="3"/>`,
			want: `document ""
  element "a" @xmlns:p="urn:example:p"{xmlns} @x="1" @p:y="2"{urn:example:p} @xml:lang="en"{http://www.w3.org/XML/1998/namespace} @q:z="3"{q}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParseXML(tt.text)
			if err != nil {
				t.Fatal(err)
			}
			if got := dumpTree(doc); got != tt.want {
				t.Errorf("tree:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

// TestParseXMLMatchesXmlquery compares the root element's subtree with the one xmlquery
// builds. The fixtures bind every namespace to a single prefix, so Prefix must match too.
func TestParseXMLMatchesXmlquery(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.xml"))
	if err != nil {
		t.Fatal(err)
	}
	opts := xmlquery.ParserOptions{Decoder: &xmlquery.DecoderOptions{
		Strict:        true,
		CharsetReader: func(_ string, input io.Reader) (io.Reader, error) { return input, nil },
	}}
	for _, name := range files {
		t.Run(filepath.Base(name), func(t *testing.T) {
			text, _, err := DecodeBody(readFixture(t, filepath.Base(name)), "")
			if err != nil {
				t.Fatal(err)
			}
			doc, err := ParseXML(text)
			if err != nil {
				t.Fatal(err)
			}
			want, err := xmlquery.ParseWithOptions(strings.NewReader(text), opts)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := dumpTree(rootElement(doc)), dumpTree(rootElement(want)); got != want {
				t.Errorf("tree:\n%s\nxmlquery:\n%s", got, want)
			}
		})
	}
}

func TestParseXMLXPath(t *testing.T) {
	doc, err := ParseXML(string(readFixture(t, "namespaces.xml")))
	if err != nil {
		t.Fatal(err)
	}
	ns := map[string]string{
		"soap": NS11,
		"st":   "urn:example:status",
		"ds":   "http://tempuri.org/Status.xsd",
		"o":    "urn:example:other",
		"xml":  xmlNS,
	}
	tests := []struct {
		expr string
		want any
	}{
		{expr: `count(/node())`, want: float64(4)},
		{expr: `count(/comment())`, want: float64(2)},
		{expr: `string(/soap:Envelope/soap:Body/st:GetStatusResponse/st:Result)`, want: "OK & ready"},
		{expr: `string(//st:Item[@id="1"])`, want: "one <raw> twothree!"},
		{expr: `count(//st:Item[@xml:lang="en"]/text())`, want: float64(4)},
		{expr: `string(//Legacy/Row)`, want: "no namespace"},
		{expr: `boolean(//st:Legacy)`, want: false},
		{expr: `string(//o:Inner/@o:attr)`, want: "v"},
		{expr: `string(//*[local-name()="Table"]/ds:Name)`, want: "Сервис"},
		{expr: `name(//o:Inner)`, want: "p:Inner"},
		// Unprefixed names match by the empty prefix, also in a default namespace (plan §2, finding 3).
		{expr: `count(//Item)`, want: float64(3)},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			expr, err := xpath.CompileWithNS(tt.expr, ns)
			if err != nil {
				t.Fatal(err)
			}
			if got := expr.Evaluate(xmlquery.CreateXPathNavigator(doc)); got != tt.want {
				t.Errorf("%s = %#v, want %#v", tt.expr, got, tt.want)
			}
		})
	}
}

// TestParseXMLLinearTime guards against quadratic tree building: xmlquery's parser walks the
// sibling chain again for every comment, text or CDATA node that follows an element or
// precedes the root, and spends about half a minute on each of these documents.
func TestParseXMLLinearTime(t *testing.T) {
	const n = 100_000
	envelope := func(body string) string {
		return `<s:Envelope xmlns:s="` + NS11 + `"><s:Body>` + body + `</s:Body></s:Envelope>`
	}
	tests := []struct {
		name string
		text string
	}{
		{name: "comments after an element", text: envelope(`<x/>` + strings.Repeat("<!---->", n))},
		{name: "CDATA after an element", text: envelope(`<x/>` + strings.Repeat("<![CDATA[c]]>", n))},
		{name: "text and comments after a nested element", text: envelope(`<x><y/></x>` + strings.Repeat("t<!---->", n/2))},
		{name: "comments before the root element", text: strings.Repeat("<!---->", n) + envelope("")},
		{name: "comments after the root element", text: envelope("") + strings.Repeat("<!---->", n)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			doc, err := ParseXML(tt.text)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			nodes := 0
			_ = walk(doc, func(*xmlquery.Node) error { nodes++; return nil })
			if nodes < n {
				t.Errorf("tree has %d nodes, want at least %d", nodes, n)
			}
			// Linear parsing takes well under a second even with -race.
			if elapsed > 5*time.Second {
				t.Errorf("ParseXML took %v", elapsed)
			}
		})
	}
}

func TestParseEnvelope(t *testing.T) {
	tests := []struct {
		name      string
		file      string // fixture in testdata, or
		text      string
		wantVer   Version
		wantFault *Fault
		wantErr   string
	}{
		{name: "1.1", file: "envelope11.xml", wantVer: V11},
		{name: "1.1 in the default namespace", file: "envelope11-default-ns.xml", wantVer: V11},
		{name: "1.2", file: "envelope12.xml", wantVer: V12},
		{
			name:    "prefix soap bound to the 1.2 namespace",
			text:    `<soap:Envelope xmlns:soap="` + NS12 + `"><soap:Body/></soap:Envelope>`,
			wantVer: V12,
		},
		{
			name:      "1.1 fault",
			file:      "fault11.xml",
			wantVer:   V11,
			wantFault: &Fault{Code: "soap:Server", Reason: "Server was unable to process request. ---> Timeout expired."},
		},
		{
			name:      "1.1 fault with qualified children and CDATA",
			file:      "fault11-qualified.xml",
			wantVer:   V11,
			wantFault: &Fault{Code: "s:Client", Reason: "Invalid <request>"},
		},
		{
			name:      "1.2 fault with subcodes",
			file:      "fault12.xml",
			wantVer:   V12,
			wantFault: &Fault{Code: "env:Sender / m:MessageTimeout / m:Retry", Reason: "Sender Timeout"},
		},
		{
			name: "1.2 fault without subcode and reason",
			text: `<env:Envelope xmlns:env="` + NS12 + `"><env:Body><env:Fault>` +
				`<env:Code><env:Value>env:Receiver</env:Value></env:Code>` +
				`</env:Fault></env:Body></env:Envelope>`,
			wantVer:   V12,
			wantFault: &Fault{Code: "env:Receiver"},
		},
		{name: "fault that is not a direct child of Body", file: "fault-nested.xml", wantVer: V11},
		{name: "Fault element of an application namespace", file: "fault-wrong-ns.xml", wantVer: V11},
		{
			name: "1.2 Fault in a 1.1 envelope",
			text: `<s:Envelope xmlns:s="` + NS11 + `"><s:Body><e:Fault xmlns:e="` + NS12 + `">` +
				`<e:Code><e:Value>e:Sender</e:Value></e:Code></e:Fault></s:Body></s:Envelope>`,
			wantVer: V11,
		},
		{
			name:    "wrong root element",
			file:    "html.xml",
			wantErr: "root element is {http://www.w3.org/1999/xhtml}html, want a SOAP Envelope",
		},
		{
			name:    "wrong namespace",
			text:    `<e:Envelope xmlns:e="urn:example:envelope"><e:Body/></e:Envelope>`,
			wantErr: "root element {urn:example:envelope}Envelope is not in a SOAP envelope namespace",
		},
		{
			name:    "no namespace",
			text:    `<Envelope><Body/></Envelope>`,
			wantErr: "root element Envelope is not in a SOAP envelope namespace",
		},
		{
			name:    "missing Body",
			text:    `<soap:Envelope xmlns:soap="` + NS11 + `"><soap:Header/></soap:Envelope>`,
			wantErr: "SOAP 1.1 Envelope has no Body element",
		},
		{
			name:    "Body of the other version",
			text:    `<s:Envelope xmlns:s="` + NS11 + `" xmlns:e="` + NS12 + `"><e:Body/></s:Envelope>`,
			wantErr: "SOAP 1.1 Envelope has no Body element",
		},
		{
			name:    "Body nested deeper",
			text:    `<e:Envelope xmlns:e="` + NS12 + `"><e:Header><e:Body/></e:Header></e:Envelope>`,
			wantErr: "SOAP 1.2 Envelope has no Body element",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := tt.text
			if tt.file != "" {
				text = string(readFixture(t, tt.file))
			}
			doc, err := ParseXML(text)
			if err != nil {
				t.Fatalf("ParseXML: %v", err)
			}
			env, err := ParseEnvelope(doc)
			checkErr(t, err, tt.wantErr)
			if err != nil {
				return
			}
			if env.Version != tt.wantVer {
				t.Errorf("Version = %v, want %v", env.Version, tt.wantVer)
			}
			if env.Body == nil || env.Body.Data != "Body" || env.Body.NamespaceURI != tt.wantVer.EnvelopeNS() {
				t.Errorf("Body = %+v, want the Body element of SOAP %v", env.Body, tt.wantVer)
			}
			if !reflect.DeepEqual(env.Fault, tt.wantFault) {
				t.Errorf("Fault = %+v, want %+v", env.Fault, tt.wantFault)
			}
		})
	}
}

func TestParseEnvelopeNil(t *testing.T) {
	if _, err := ParseEnvelope(nil); err == nil {
		t.Fatal("ParseEnvelope(nil) succeeded")
	}
}

func TestFaultString(t *testing.T) {
	tests := []struct {
		name  string
		fault *Fault
		want  string
	}{
		{name: "code and reason", fault: &Fault{Code: "soap:Server", Reason: "Timeout expired."}, want: "soap:Server: Timeout expired."},
		{name: "subcodes", fault: &Fault{Code: "env:Sender / m:Retry", Reason: "Sender Timeout"}, want: "env:Sender / m:Retry: Sender Timeout"},
		{name: "nil", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fault.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestWindows1251Fault runs a legacy-encoded response through the whole pipeline.
func TestWindows1251Fault(t *testing.T) {
	body := readFixture(t, "fault11-windows-1251.xml")
	for _, ct := range []string{"text/xml", "text/xml; charset=windows-1251"} {
		t.Run(ct, func(t *testing.T) {
			text, cs, err := DecodeBody(body, ct)
			if err != nil {
				t.Fatal(err)
			}
			if cs != "windows-1251" {
				t.Errorf("charset = %q, want windows-1251", cs)
			}
			doc, err := ParseXML(text)
			if err != nil {
				t.Fatal(err)
			}
			env, err := ParseEnvelope(doc)
			if err != nil {
				t.Fatal(err)
			}
			want := &Fault{Code: "soap:Server", Reason: "Сервис временно недоступен"}
			if !reflect.DeepEqual(env.Fault, want) {
				t.Errorf("Fault = %+v, want %+v", env.Fault, want)
			}
		})
	}
}

func TestValidateRequest(t *testing.T) {
	const env11 = `<soap:Envelope xmlns:soap="` + NS11 + `"><soap:Body><GetStatus xmlns="urn:example:status"/></soap:Body></soap:Envelope>`
	// withBody wraps the content of a SOAP 1.1 Body.
	withBody := func(content string) []byte {
		return []byte(`<soap:Envelope xmlns:soap="` + NS11 + `"><soap:Body>` + content + `</soap:Body></soap:Envelope>`)
	}
	tests := []struct {
		name    string
		body    []byte
		v       Version
		wantErr string
	}{
		{name: "1.1", body: readFixture(t, "request11.xml"), v: V11},
		{name: "1.2", body: readFixture(t, "request12.xml"), v: V12},
		{name: "without declaration", body: []byte(env11), v: V11},
		{name: "declaration without encoding", body: []byte(`<?xml version="1.0"?>` + env11), v: V11},
		{name: "declaration with lower-case utf-8", body: []byte(`<?xml version='1.0' encoding='utf-8'?>` + env11), v: V11},
		{name: "utf-8 BOM", body: concat(bomUTF8, readFixture(t, "request11.xml")), v: V11},
		{name: "fault in the request is not checked", body: readFixture(t, "fault11.xml"), v: V11},
		{name: "comments, processing instructions and namespaces", body: readFixture(t, "namespaces.xml"), v: V11},
		{
			name: "declared attribute prefixes",
			body: withBody(`<m:GetStatus xmlns:m="urn:example:status" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
				`<m:id xsi:nil="true" m:kind="a" kind="b" xml:lang="en"/></m:GetStatus>`),
			v: V11,
		},
		{
			name: "xml prefix bound to its own namespace",
			body: withBody(`<GetStatus xmlns:xml="http://www.w3.org/XML/1998/namespace" xml:lang="en"/>`),
			v:    V11,
		},
		{name: "default namespace undeclared", body: withBody(`<GetStatus xmlns=""/>`), v: V11},
		{
			name:    "declaration after a comment",
			body:    []byte("<!-- template -->\n<?xml version=\"1.0\" encoding=\"windows-1251\"?>\n" + env11),
			v:       V11,
			wantErr: "XML syntax error on line 2: XML declaration allowed only at the start of the document",
		},
		{
			name:    "whitespace before the declaration",
			body:    []byte("\n<?xml version=\"1.0\" encoding=\"utf-8\"?>" + env11),
			v:       V11,
			wantErr: "XML declaration allowed only at the start",
		},
		{
			name:    "BOM and whitespace before the declaration",
			body:    concat(bomUTF8, []byte(" <?xml version=\"1.0\"?>"+env11)),
			v:       V11,
			wantErr: "XML declaration allowed only at the start",
		},
		{
			name:    "second declaration",
			body:    []byte(`<?xml version="1.0"?><?xml version="1.0" encoding="koi8-r"?>` + env11),
			v:       V11,
			wantErr: "XML declaration allowed only at the start",
		},
		{
			name:    "declaration after the envelope",
			body:    []byte(env11 + `<?xml version="1.0" encoding="koi8-r"?>`),
			v:       V11,
			wantErr: "XML declaration allowed only at the start",
		},
		{
			name:    "upper-case declaration",
			body:    []byte(`<?XML version="1.0"?>` + env11),
			v:       V11,
			wantErr: "processing instruction target XML is reserved",
		},
		{
			name:    "undeclared attribute prefix",
			body:    withBody(`<GetStatus xmlns="urn:example:status"><id xsi:nil="true"/></GetStatus>`),
			v:       V11,
			wantErr: "element <id>: attribute xsi:nil: namespace prefix xsi is not declared",
		},
		{
			name:    "repeated attribute",
			body:    withBody(`<GetStatus a="1" a="2"/>`),
			v:       V11,
			wantErr: "element <GetStatus>: attribute a is repeated",
		},
		{
			name:    "repeated attribute after resolving prefixes",
			body:    withBody(`<GetStatus xmlns:m="urn:example:status" xmlns:n="urn:example:status" m:a="1" n:a="2"/>`),
			v:       V11,
			wantErr: "attribute n:a is repeated",
		},
		{
			name:    "repeated namespace declaration",
			body:    withBody(`<m:GetStatus xmlns:m="urn:example:a" xmlns:m="urn:example:b"/>`),
			v:       V11,
			wantErr: "attribute xmlns:m is repeated",
		},
		{
			name:    "prefix bound to an empty namespace",
			body:    withBody(`<GetStatus xmlns:m=""/>`),
			v:       V11,
			wantErr: "namespace prefix m is bound to an empty namespace name",
		},
		{
			name:    "xml prefix bound to another namespace",
			body:    withBody(`<GetStatus xmlns:xml="urn:example:xml"/>`),
			v:       V11,
			wantErr: "namespace prefix xml must be bound to http://www.w3.org/XML/1998/namespace",
		},
		{
			name:    "xml namespace bound to another prefix",
			body:    withBody(`<GetStatus xmlns:x="http://www.w3.org/XML/1998/namespace"/>`),
			v:       V11,
			wantErr: "may only be bound to prefix xml",
		},
		{
			name:    "xmlns prefix declared",
			body:    withBody(`<GetStatus xmlns:xmlns="urn:example:xmlns"/>`),
			v:       V11,
			wantErr: "the xmlns prefix and namespace must not be declared",
		},
		{
			name:    "xmlns namespace declared as default",
			body:    withBody(`<GetStatus xmlns="http://www.w3.org/2000/xmlns/"/>`),
			v:       V11,
			wantErr: "the xmlns prefix and namespace must not be declared",
		},
		{
			name:    "1.1 body for a 1.2 target",
			body:    readFixture(t, "request11.xml"),
			v:       V12,
			wantErr: "request envelope is SOAP 1.1, want SOAP 1.2",
		},
		{
			name:    "1.2 body for a 1.1 target",
			body:    readFixture(t, "request12.xml"),
			v:       V11,
			wantErr: "request envelope is SOAP 1.2, want SOAP 1.1",
		},
		{name: "invalid version", body: []byte(env11), v: Version(0), wantErr: "want SOAP invalid"},
		{name: "invalid utf-8", body: []byte("<a>\xff</a>"), v: V11, wantErr: "not valid UTF-8"},
		{name: "utf-16", body: concat(bomUTF16LE, utf16Bytes(env11, false)), v: V11, wantErr: "not valid UTF-8"},
		{
			name:    "declaration with windows-1251",
			body:    []byte(`<?xml version="1.0" encoding="windows-1251"?>` + env11),
			v:       V11,
			wantErr: `XML declaration declares encoding "windows-1251"`,
		},
		{
			name:    "declaration with an unknown encoding",
			body:    []byte(`<?xml version="1.0" encoding="x-unknown"?>` + env11),
			v:       V11,
			wantErr: `XML declaration declares encoding "x-unknown"`,
		},
		{
			name:    "malformed",
			body:    []byte(`<soap:Envelope xmlns:soap="` + NS11 + `"><soap:Body></soap:Envelope>`),
			v:       V11,
			wantErr: "XML syntax error",
		},
		{name: "DOCTYPE", body: []byte(`<!DOCTYPE soap:Envelope>` + env11), v: V11, wantErr: "DOCTYPE is not allowed"},
		{name: "not an envelope", body: []byte(`<GetStatus xmlns="urn:example:status"/>`), v: V11, wantErr: "want a SOAP Envelope"},
		{
			name:    "no Body",
			body:    []byte(`<soap:Envelope xmlns:soap="` + NS11 + `"><soap:Header/></soap:Envelope>`),
			v:       V11,
			wantErr: "has no Body element",
		},
		{name: "empty", v: V11, wantErr: "empty document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkErr(t, ValidateRequest(tt.body, tt.v), tt.wantErr)
		})
	}
}
