// Package soap knows the SOAP 1.1 and 1.2 wire formats: request headers, response body
// decoding (RFC 7303), envelope parsing and Fault extraction (plan §6.1, §6.3).
package soap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/antchfx/xmlquery"
	"golang.org/x/net/html/charset"
)

// Envelope namespaces.
const (
	NS11 = "http://schemas.xmlsoap.org/soap/envelope/"
	NS12 = "http://www.w3.org/2003/05/soap-envelope"
)

// Version is a SOAP version. The zero value is invalid; config defaults it to V11.
type Version int

// Supported SOAP versions.
const (
	V11 Version = iota + 1
	V12
)

// ParseVersion accepts "1.1" and "1.2".
func ParseVersion(s string) (Version, error) {
	switch s {
	case "1.1":
		return V11, nil
	case "1.2":
		return V12, nil
	}
	return 0, fmt.Errorf("unsupported SOAP version %q (want 1.1 or 1.2)", s)
}

// String returns "1.1" or "1.2" (the `soap_version` label value).
func (v Version) String() string {
	switch v {
	case V11:
		return "1.1"
	case V12:
		return "1.2"
	}
	return "invalid"
}

// EnvelopeNS returns the envelope namespace of the version.
func (v Version) EnvelopeNS() string {
	switch v {
	case V11:
		return NS11
	case V12:
		return NS12
	}
	return ""
}

// SetRequestHeaders sets Content-Type and, for SOAP 1.1, SOAPAction (plan §6.1):
//
//	1.1: Content-Type: text/xml; charset=utf-8
//	     SOAPAction: "<action>"  (always present, `""` when action is empty)
//	1.2: Content-Type: application/soap+xml; charset=utf-8; action="<action>"
//	     (the action parameter only when action is not empty)
//
// SOAPAction is assigned directly in the header map so that it is sent with exactly this
// spelling (Header.Set would canonicalize it to "Soapaction").
func SetRequestHeaders(h http.Header, v Version, action string) {
	switch v {
	case V11:
		h.Set("Content-Type", "text/xml; charset=utf-8")
		h["SOAPAction"] = []string{quote(action)}
	case V12:
		ct := "application/soap+xml; charset=utf-8"
		if action != "" {
			ct += "; action=" + quote(action)
		}
		h.Set("Content-Type", ct)
	}
}

var quotedPairs = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// quote returns s as an HTTP quoted-string (RFC 9110 §5.6.4).
func quote(s string) string {
	return `"` + quotedPairs.Replace(s) + `"`
}

// Fault is a SOAP Fault.
type Fault struct {
	// Code is the 1.1 faultcode or the 1.2 Code/Value (with Subcode values appended,
	// separated by " / ").
	Code string
	// Reason is the 1.1 faultstring or the first 1.2 Reason/Text.
	Reason string
}

// String returns "<code>: <reason>".
func (f *Fault) String() string {
	if f == nil {
		return ""
	}
	return f.Code + ": " + f.Reason
}

// Envelope is a parsed SOAP envelope.
type Envelope struct {
	Version Version
	// Body is the Body element.
	Body *xmlquery.Node
	// Fault is the Fault inside Body, nil if there is none.
	Fault *Fault
}

// ParseEnvelope inspects a parsed document. The root element must be Envelope in one of the
// two SOAP namespaces and must contain a Body element of the same namespace. A Fault is
// recognized only as a direct child of Body.
func ParseEnvelope(doc *xmlquery.Node) (*Envelope, error) {
	root := rootElement(doc)
	if root == nil {
		return nil, errors.New("no root element")
	}
	var v Version
	switch {
	case root.Data != "Envelope":
		return nil, fmt.Errorf("root element is %s, want a SOAP Envelope", clarkName(root))
	case root.NamespaceURI == NS11:
		v = V11
	case root.NamespaceURI == NS12:
		v = V12
	default:
		return nil, fmt.Errorf("root element %s is not in a SOAP envelope namespace", clarkName(root))
	}
	ns := v.EnvelopeNS()
	body := childElement(root, ns, "Body")
	if body == nil {
		return nil, fmt.Errorf("SOAP %s Envelope has no Body element in namespace %s", v, ns)
	}
	env := &Envelope{Version: v, Body: body}
	if f := childElement(body, ns, "Fault"); f != nil {
		env.Fault = parseFault(f, v)
	}
	return env, nil
}

// parseFault reads the code and the reason of a Fault element. Its children are matched by
// local name: SOAP 1.1 leaves faultcode and faultstring unqualified, but some stacks qualify them.
func parseFault(f *xmlquery.Node, v Version) *Fault {
	if v == V11 {
		return &Fault{
			Code:   elementText(childElement(f, "*", "faultcode")),
			Reason: elementText(childElement(f, "*", "faultstring")),
		}
	}
	var codes []string
	for c := childElement(f, "*", "Code"); c != nil; c = childElement(c, "*", "Subcode") {
		if val := elementText(childElement(c, "*", "Value")); val != "" {
			codes = append(codes, val)
		}
	}
	return &Fault{
		Code:   strings.Join(codes, " / "),
		Reason: elementText(childElement(childElement(f, "*", "Reason"), "*", "Text")),
	}
}

// rootElement returns doc itself if it is an element, otherwise its first element child.
func rootElement(doc *xmlquery.Node) *xmlquery.Node {
	if doc == nil || doc.Type == xmlquery.ElementNode {
		return doc
	}
	return childElement(doc, "*", "")
}

// childElement returns the first child element of n with the given namespace URI and local
// name; "*" matches any namespace and "" any local name. It is nil-safe.
func childElement(n *xmlquery.Node, ns, local string) *xmlquery.Node {
	if n == nil {
		return nil
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == xmlquery.ElementNode &&
			(ns == "*" || c.NamespaceURI == ns) &&
			(local == "" || c.Data == local) {
			return c
		}
	}
	return nil
}

// elementText returns the trimmed text content of n, "" for nil. Unlike Node.InnerText it
// does not recurse, so a deeply nested hostile response cannot grow the stack.
func elementText(n *xmlquery.Node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	_ = walk(n, func(c *xmlquery.Node) error {
		if c.Type == xmlquery.TextNode || c.Type == xmlquery.CharDataNode {
			b.WriteString(c.Data)
		}
		return nil
	})
	return strings.TrimSpace(b.String())
}

// clarkName formats an element name as {namespace}local.
func clarkName(n *xmlquery.Node) string {
	if n.NamespaceURI == "" {
		return n.Data
	}
	return "{" + n.NamespaceURI + "}" + n.Data
}

// DecodeBody converts a response body to UTF-8 following RFC 7303 (plan §6.3): a BOM wins,
// then the charset parameter of contentType, then the encoding of the XML declaration,
// then UTF-8. It returns the decoded text and the name of the charset used. Unknown
// charsets are an error. Invalid UTF-8 input in a UTF-8 body is not an error (it is kept
// as is and fails XML parsing later).
func DecodeBody(body []byte, contentType string) (text string, charset string, err error) {
	if label, n := sniffBOM(body); n > 0 {
		return decode(body[n:], label, "byte order mark")
	}
	if label := charsetParam(contentType); label != "" {
		return decode(body, label, "Content-Type")
	}
	if label := declaredEncoding(body); label != "" {
		// A declaration readable as ASCII rules UTF-16 out (XML 1.0 Appendix F), whatever it says.
		if isUTF16(label) {
			label = "utf-8"
		}
		return decode(body, label, "XML declaration")
	}
	return string(body), "utf-8", nil
}

var (
	bomUTF8    = []byte{0xEF, 0xBB, 0xBF}
	bomUTF16LE = []byte{0xFF, 0xFE}
	bomUTF16BE = []byte{0xFE, 0xFF}
)

// sniffBOM returns the charset announced by a byte order mark and the length of the mark.
func sniffBOM(b []byte) (label string, n int) {
	switch {
	case bytes.HasPrefix(b, bomUTF8):
		return "utf-8", len(bomUTF8)
	case bytes.HasPrefix(b, bomUTF16LE):
		return "utf-16le", len(bomUTF16LE)
	case bytes.HasPrefix(b, bomUTF16BE):
		return "utf-16be", len(bomUTF16BE)
	}
	return "", 0
}

// charsetParam returns the charset parameter of a Content-Type value, "" if there is none.
func charsetParam(contentType string) string {
	if _, params, err := mime.ParseMediaType(contentType); err == nil {
		return params["charset"]
	}
	// A malformed header (stray tokens, duplicate or unquoted parameters) still often carries
	// a usable charset: take the first one.
	for p := range strings.SplitSeq(contentType, ";") {
		if k, v, ok := strings.Cut(p, "="); ok && strings.EqualFold(strings.TrimSpace(k), "charset") {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// maxDeclLen bounds the search for the XML declaration at the start of a body.
const maxDeclLen = 1024

// declEncodingRE matches the encoding pseudo-attribute of an XML declaration. Leading
// whitespace is tolerated because encoding/xml accepts it too.
var declEncodingRE = regexp.MustCompile(
	`^[ \t\r\n]*<\?xml(?:[ \t\r\n][^?>]*?)?[ \t\r\n]encoding[ \t\r\n]*=[ \t\r\n]*(?:"([^"]*)"|'([^']*)')`)

// declaredEncoding returns the encoding of the XML declaration at the start of b, "" if there
// is no declaration or it has no encoding.
func declaredEncoding(b []byte) string {
	m := declEncodingRE.FindSubmatch(b[:min(len(b), maxDeclLen)])
	if m == nil {
		return ""
	}
	return string(m[1]) + string(m[2])
}

// lookup resolves a charset label to its canonical WHATWG name, "" if the label is unknown.
// The "replacement" encoding (ISO-2022-KR and friends) decodes everything to U+FFFD and is
// treated as unknown.
func lookup(label string) string {
	if e, name := charset.Lookup(label); e != nil && name != "replacement" {
		return name
	}
	return ""
}

func isUTF16(label string) bool {
	name := lookup(label)
	return name == "utf-16le" || name == "utf-16be"
}

// decode converts b from the charset named by label to UTF-8. UTF-8 input is returned
// unchanged, invalid sequences included. source names where the label came from.
func decode(b []byte, label, source string) (string, string, error) {
	name := lookup(label)
	if name == "" {
		return "", "", fmt.Errorf("unknown charset %q in %s", label, source)
	}
	if name == "utf-8" {
		return string(b), name, nil
	}
	e, _ := charset.Lookup(name)
	out, err := e.NewDecoder().Bytes(b)
	if err != nil {
		return "", "", fmt.Errorf("decode %s body: %w", name, err)
	}
	return string(out), name, nil
}

// Namespaces reserved by Namespaces in XML 1.0.
const (
	xmlNS   = "http://www.w3.org/XML/1998/namespace"
	xmlnsNS = "http://www.w3.org/2000/xmlns/"
)

const xmlSpace = " \t\r\n"

var (
	errDOCTYPE = errors.New("DOCTYPE is not allowed")
	errDTD     = errors.New("DTD markup declarations are not allowed")
)

// ParseXML parses already decoded UTF-8 text strictly: only the predefined entities are
// known and there must be exactly one root element. The XML declaration's encoding is
// ignored (the text was decoded once by DecodeBody). Any DOCTYPE is an error (plan §6.3).
//
// The document node's children are the comments, processing instructions and the root
// element; the XML declaration and whitespace outside the root element are not nodes.
func ParseXML(text string) (*xmlquery.Node, error) {
	return parse(text, false)
}

// parse builds the tree from encoding/xml tokens instead of calling xmlquery.Parse, which
// links each comment, text and CDATA node by walking the sibling chain from the last
// element: a long run of them costs quadratic time, and a few megabytes of "<!---->" would
// pin a core for hours. Here every node is appended in constant time.
//
// Nodes are filled as xmlquery fills them, except that Prefix is always the prefix written
// in the document (xmlquery loses it when a namespace is bound to several prefixes) and
// processing instructions get no pseudo-attributes.
//
// strict adds what encoding/xml does not check: the XML declaration only at the very start,
// declared attribute prefixes, unique attribute names and no reserved namespace bindings.
// Request bodies are validated with it; responses are read as leniently as encoding/xml
// reads them.
func parse(text string, strict bool) (*xmlquery.Node, error) {
	text = strings.TrimPrefix(text, "\uFEFF")
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("empty document")
	}
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.Strict = true
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	doc := &xmlquery.Node{Type: xmlquery.DocumentNode}
	b := &builder{text: text, strict: strict, cur: doc, ns: map[string]string{}}
	for {
		start := int(dec.InputOffset())
		b.line, _ = dec.InputPos()
		// RawToken, unlike Token, keeps prefixes as written; namespaces are resolved here.
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if err := b.add(tok, start); err != nil {
			return nil, err
		}
	}
	if len(b.open) > 0 {
		return nil, b.errorf("unexpected EOF: element <%s> is not closed", qname(b.open[len(b.open)-1].name))
	}
	if !b.root {
		return nil, errors.New("no root element")
	}
	return doc, nil
}

// builder assembles the tree from raw tokens. It matches end tags and resolves namespaces
// itself, because RawToken does neither.
type builder struct {
	text   string
	strict bool
	line   int            // line where the current token starts
	cur    *xmlquery.Node // the innermost open element, or the document
	open   []openElement
	root   bool              // the root element has been seen
	ns     map[string]string // namespaces in scope by prefix; "" is the default namespace
	undo   []binding         // bindings shadowed by open elements, restored when they close
}

type openElement struct {
	name xml.Name // as written: Space is the prefix
	undo int      // len(builder.undo) before the element's declarations
}

type binding struct {
	prefix, uri string
	bound       bool // whether prefix was bound (to uri) before
}

// add appends a token to the tree; start is the token's byte offset in the text.
func (b *builder) add(tok xml.Token, start int) error {
	switch t := tok.(type) {
	case xml.StartElement:
		return b.startElement(t)
	case xml.EndElement:
		return b.endElement(t)
	case xml.CharData:
		// Text and CDATA sections come as the same token; only CDATA starts with markup.
		cdata := strings.HasPrefix(b.text[start:], "<![CDATA[")
		if len(b.open) == 0 {
			if cdata || len(bytes.Trim(t, xmlSpace)) > 0 {
				return b.errorf("text outside the root element")
			}
			return nil
		}
		typ := xmlquery.TextNode
		if cdata {
			typ = xmlquery.CharDataNode
		}
		xmlquery.AddChild(b.cur, &xmlquery.Node{Type: typ, Data: string(t)})
	case xml.Comment:
		xmlquery.AddChild(b.cur, &xmlquery.Node{Type: xmlquery.CommentNode, Data: string(t)})
	case xml.ProcInst:
		return b.procInst(t, start)
	case xml.Directive:
		if bytes.HasPrefix(t, []byte("DOCTYPE")) {
			return errDOCTYPE
		}
		return errDTD
	}
	return nil
}

func (b *builder) startElement(t xml.StartElement) error {
	if len(b.open) == 0 {
		if b.root {
			return b.errorf("more than one root element")
		}
		b.root = true
	}
	b.open = append(b.open, openElement{name: t.Name, undo: len(b.undo)})
	// Declarations apply to the element's own name and attributes, so they come first.
	for _, a := range t.Attr {
		var err error
		switch {
		case a.Name.Space == "xmlns":
			err = b.bind(a.Name.Local, a.Value)
		case a.Name.Space == "" && a.Name.Local == "xmlns":
			err = b.bind("", a.Value)
		}
		if err != nil {
			return err
		}
	}
	uri, ok := b.resolve(t.Name.Space)
	if !ok {
		return b.errorf("element <%s>: namespace prefix %s is not declared", qname(t.Name), t.Name.Space)
	}
	attrs, err := b.attrs(t)
	if err != nil {
		return err
	}
	n := &xmlquery.Node{Type: xmlquery.ElementNode, Data: t.Name.Local, NamespaceURI: uri, Attr: attrs}
	if uri != "" {
		n.Prefix = t.Name.Space
	}
	xmlquery.AddChild(b.cur, n)
	b.cur = n
	return nil
}

func (b *builder) endElement(t xml.EndElement) error {
	if len(b.open) == 0 {
		return b.errorf("unexpected end element </%s>", qname(t.Name))
	}
	top := b.open[len(b.open)-1]
	if t.Name != top.name {
		return b.errorf("element <%s> closed by </%s>", qname(top.name), qname(t.Name))
	}
	b.open = b.open[:len(b.open)-1]
	for len(b.undo) > top.undo {
		u := b.undo[len(b.undo)-1]
		b.undo = b.undo[:len(b.undo)-1]
		if u.bound {
			b.ns[u.prefix] = u.uri
		} else {
			delete(b.ns, u.prefix)
		}
	}
	b.cur = b.cur.Parent
	return nil
}

// attrs converts the attributes of an element. As in encoding/xml, namespace declarations
// keep "xmlns" as their namespace and an undeclared prefix stands for its namespace (an
// error if strict).
func (b *builder) attrs(t xml.StartElement) ([]xmlquery.Attr, error) {
	if len(t.Attr) == 0 {
		return nil, nil
	}
	attrs := make([]xmlquery.Attr, len(t.Attr))
	var seen map[xml.Name]bool
	if b.strict {
		seen = make(map[xml.Name]bool, len(t.Attr))
	}
	for i, a := range t.Attr {
		uri := a.Name.Space
		if uri != "" && uri != "xmlns" {
			var ok bool
			if uri, ok = b.resolve(a.Name.Space); !ok {
				if b.strict {
					return nil, b.errorf("element <%s>: attribute %s: namespace prefix %s is not declared",
						qname(t.Name), qname(a.Name), a.Name.Space)
				}
				uri = a.Name.Space
			}
		}
		attrs[i] = xmlquery.Attr{Name: a.Name, Value: a.Value, NamespaceURI: uri}
		if seen != nil {
			// Names must be unique also after prefixes are resolved.
			key := xml.Name{Space: uri, Local: a.Name.Local}
			if a.Name.Space == "xmlns" {
				key.Space = xmlnsNS
			}
			if seen[key] {
				return nil, b.errorf("element <%s>: attribute %s is repeated", qname(t.Name), qname(a.Name))
			}
			seen[key] = true
		}
	}
	return attrs, nil
}

// resolve returns the namespace bound to a prefix as written; "" is the default namespace.
func (b *builder) resolve(prefix string) (string, bool) {
	switch prefix {
	case "":
		return b.ns[""], true
	case "xml":
		return xmlNS, true
	case "xmlns":
		return "", false
	}
	uri, ok := b.ns[prefix]
	return uri, ok
}

// bind declares a prefix ("" for the default namespace) for the element being opened.
func (b *builder) bind(prefix, uri string) error {
	if b.strict {
		// Namespaces in XML 1.0, §3 and §5.
		switch {
		case prefix == "xmlns" || uri == xmlnsNS:
			return b.errorf("the xmlns prefix and namespace must not be declared")
		case prefix == "xml" && uri != xmlNS:
			return b.errorf("namespace prefix xml must be bound to %s", xmlNS)
		case prefix != "xml" && uri == xmlNS:
			return b.errorf("namespace %s may only be bound to prefix xml", xmlNS)
		case prefix != "" && uri == "":
			return b.errorf("namespace prefix %s is bound to an empty namespace name", prefix)
		}
	}
	old, bound := b.ns[prefix]
	b.undo = append(b.undo, binding{prefix: prefix, uri: old, bound: bound})
	b.ns[prefix] = uri
	return nil
}

// procInst handles a processing instruction. The XML declaration is not a node;
// encoding/xml accepts it anywhere, strict mode only as the very first bytes.
func (b *builder) procInst(t xml.ProcInst, start int) error {
	switch {
	case t.Target == "xml":
		if b.strict && start != 0 {
			return b.errorf("XML declaration allowed only at the start of the document")
		}
		return nil
	case b.strict && strings.EqualFold(t.Target, "xml"):
		return b.errorf("processing instruction target %s is reserved", t.Target)
	}
	xmlquery.AddChild(b.cur, &xmlquery.Node{
		Type:     xmlquery.ProcessingInstruction,
		Data:     t.Target,
		ProcInst: &xmlquery.ProcInstData{Target: t.Target, Inst: strings.TrimSpace(string(t.Inst))},
	})
	return nil
}

// errorf returns a syntax error at the line where the current token starts.
func (b *builder) errorf(format string, args ...any) error {
	return &xml.SyntaxError{Msg: fmt.Sprintf(format, args...), Line: b.line}
}

// qname formats a name as written, prefix:local.
func qname(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}

// walk calls fn for n and its descendants in document order and stops at the first error.
// It is iterative, so nesting depth does not matter.
func walk(n *xmlquery.Node, fn func(*xmlquery.Node) error) error {
	for c := n; ; {
		if err := fn(c); err != nil {
			return err
		}
		if c.FirstChild != nil {
			c = c.FirstChild
			continue
		}
		for c != n && c.NextSibling == nil {
			c = c.Parent
		}
		if c == n {
			return nil
		}
		c = c.NextSibling
	}
}

// ValidateRequest checks a request body at config load: valid UTF-8, well-formed XML that
// also satisfies Namespaces in XML, no DOCTYPE, an XML declaration (if present) at the very
// start that declares UTF-8, and an envelope of version v with a Body.
func ValidateRequest(body []byte, v Version) error {
	if !utf8.Valid(body) {
		return errors.New("request body is not valid UTF-8")
	}
	body = bytes.TrimPrefix(body, bomUTF8)
	if label := declaredEncoding(body); label != "" && lookup(label) != "utf-8" {
		return fmt.Errorf("XML declaration declares encoding %q, but the request is sent as UTF-8", label)
	}
	doc, err := parse(string(body), true)
	if err != nil {
		return err
	}
	env, err := ParseEnvelope(doc)
	if err != nil {
		return err
	}
	if env.Version != v {
		return fmt.Errorf("request envelope is SOAP %s, want SOAP %s", env.Version, v)
	}
	return nil
}
