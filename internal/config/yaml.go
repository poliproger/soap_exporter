package config

import (
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/alecthomas/units"
	commoncfg "github.com/prometheus/common/config"
	"go.yaml.in/yaml/v2"

	"github.com/poliproger/soap_exporter/internal/soap"
)

// node is a YAML value as written in the file. Defaults are merged into targets on this tree,
// which is then encoded again and decoded strictly into a Target. The zero node is null.
//
// Scalars keep their text: going through float64 would turn the label value 1.10 into "1.1"
// and the header value 2.0 into "2", while the strict decoder gives string fields the text.
type node struct {
	kind  nodeKind
	text  string          // stringNode: the value; plainNode: the text as written
	m     map[string]node // mappingNode
	items []node          // sequenceNode
}

type nodeKind uint8

const (
	nullNode  nodeKind = iota
	plainNode          // a number or a boolean
	stringNode
	mappingNode
	sequenceNode
	absentNode // a field of targetShadow that the mapping does not set; never in a tree
)

// UnmarshalYAML implements yaml.Unmarshaler. The decoder does not call it for null, which
// leaves the zero node.
//
// The value is decoded only into the form of its kind, so every value is decoded once.
// Decoding it into any first would decode each subtree again on every level above it and
// resolve mapping keys as YAML 1.1 scalars, which makes y and yes the same key.
func (n *node) UnmarshalYAML(unmarshal func(any) error) error {
	*n = node{}
	// Only a scalar decodes into a string; a mapping or a list fails without being read.
	var text string
	textErr := unmarshal(&text)
	if textErr == nil {
		var v any // tells strings from numbers and booleans
		if err := unmarshal(&v); err != nil {
			return err
		}
		switch v := v.(type) {
		case nil:
		case string:
			n.kind, n.text = stringNode, v
		default:
			n.kind, n.text = plainNode, text
		}
		return nil
	}
	// The decoder creates the map or the slice before it decodes the entries, so a non-nil
	// one means the value has that kind, even if an entry fails. Keys are decoded as
	// strings, as the strict decoder decodes field names and the keys of the schema's maps.
	if err := unmarshal(&n.m); n.m != nil {
		n.kind = mappingNode
		return err
	}
	if err := unmarshal(&n.items); n.items != nil {
		n.kind = sequenceNode
		return err
	}
	return textErr
}

// UnmarshalText implements encoding.TextUnmarshaler. go.yaml.in/yaml/v2 mistakes the quoted
// strings "null" and "~" for null and calls this instead of UnmarshalYAML for them.
func (n *node) UnmarshalText(text []byte) error {
	*n = node{kind: stringNode, text: string(text)}
	return nil
}

// describe names the kind of n for error messages.
func (n node) describe() string {
	switch n.kind {
	case nullNode:
		return "null"
	case mappingNode:
		return "a mapping"
	case sequenceNode:
		return "a list"
	case stringNode:
		return "a string"
	}
	return n.text
}

// scalar returns the text of a scalar node and whether n is one.
func (n node) scalar() (string, bool) {
	if n.kind != plainNode && n.kind != stringNode {
		return "", false
	}
	return n.text, true
}

// parse decodes a configuration file into a tree.
func parse(data []byte) (node, error) {
	var top map[string]topNode
	err := yaml.UnmarshalStrict(data, &top)
	if top == nil {
		if err == nil {
			return node{}, nil // an empty file
		}
		// Not a mapping: the tree keeps the value for the error message.
		var root node
		err = yaml.UnmarshalStrict(data, &root)
		return root, err
	}
	if err != nil {
		return node{}, err
	}
	root := node{kind: mappingNode, m: make(map[string]node, len(top))}
	for k, v := range top {
		root.m[k] = v.node
	}
	return root, nil
}

// topNode is a value at the top level of the file: a list is decoded as targets, a mapping
// as a target (the defaults).
type topNode struct{ node }

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *topNode) UnmarshalYAML(unmarshal func(any) error) error {
	var targets []targetNode
	if err := unmarshal(&targets); targets != nil {
		v.node = node{kind: sequenceNode, items: make([]node, len(targets))}
		for i, t := range targets {
			v.items[i] = t.node
		}
		return err
	}
	var t targetNode
	err := t.UnmarshalYAML(unmarshal)
	v.node = t.node
	return err
}

// targetNode is a target or the defaults.
type targetNode struct{ node }

// targetShadow has a node field for each key of Target.
var targetShadow = func() reflect.Type {
	var fields []reflect.StructField
	for _, key := range yamlKeys(reflect.TypeFor[Target]()) {
		fields = append(fields, reflect.StructField{
			Name: fmt.Sprintf("F%d", len(fields)),
			Type: reflect.TypeFor[node](),
			Tag:  reflect.StructTag(fmt.Sprintf("yaml:%q", key)),
		})
	}
	return reflect.StructOf(fields)
}()

// UnmarshalYAML implements yaml.Unmarshaler.
//
// yaml v2 applies a merge key (<<) by decoding the merged mappings into the value being
// decoded, so a map, such as a tree's, rejects a key that overrides a merged one as set
// twice. A struct only rejects a field set twice by one mapping. A target that fails as a
// tree is therefore decoded again into targetShadow: keys override merged values that
// precede them, as when yaml v2 decodes a Target. Nested mappings are trees, so their keys
// cannot override merged ones (yaml v2 rejects that for string maps too).
func (t *targetNode) UnmarshalYAML(unmarshal func(any) error) error {
	err := t.node.UnmarshalYAML(unmarshal)
	var te *yaml.TypeError
	if err == nil || t.kind != mappingNode || !errors.As(err, &te) {
		return err
	}
	s := reflect.New(targetShadow).Elem()
	for i := range s.NumField() {
		s.Field(i).Set(reflect.ValueOf(node{kind: absentNode}))
	}
	if err := unmarshal(s.Addr().Interface()); err != nil {
		// The problems of the target without those of the merge keys, phrased as for a
		// Target.
		if errors.As(err, &te) {
			for i, msg := range te.Errors {
				te.Errors[i] = strings.ReplaceAll(msg, targetShadow.String(), reflect.TypeFor[Target]().String())
			}
		}
		return err
	}
	t.node = node{kind: mappingNode, m: make(map[string]node, s.NumField())}
	for i := range s.NumField() {
		if v := s.Field(i).Interface().(node); v.kind != absentNode {
			t.m[targetShadow.Field(i).Tag.Get("yaml")] = v
		}
	}
	return nil
}

// merge deep-merges over into base (plan §5.2): mappings merge key by key; scalars, lists
// and null replace. Null values are dropped from the result, so null removes an inherited
// value and leaves a field at its built-in default. The inputs are not modified.
func merge(base, over node) node {
	if base.kind != mappingNode || over.kind != mappingNode {
		return prune(over)
	}
	out := node{kind: mappingNode, m: make(map[string]node, len(base.m)+len(over.m))}
	for k, v := range base.m {
		if v.kind != nullNode {
			out.m[k] = prune(v)
		}
	}
	for k, v := range over.m {
		switch prev, inherited := out.m[k]; {
		case v.kind == nullNode:
			delete(out.m, k)
		case inherited:
			out.m[k] = merge(prev, v)
		default:
			out.m[k] = prune(v)
		}
	}
	return out
}

// prune returns a copy of n without null mapping values.
func prune(n node) node {
	switch n.kind {
	case mappingNode:
		out := node{kind: mappingNode, m: make(map[string]node, len(n.m))}
		for k, v := range n.m {
			if v.kind != nullNode {
				out.m[k] = prune(v)
			}
		}
		return out
	case sequenceNode:
		out := node{kind: sequenceNode, items: make([]node, len(n.items))}
		for i, v := range n.items {
			out.items[i] = prune(v)
		}
		return out
	}
	return n
}

// encode returns n as a one-line flow-style YAML document with sorted keys. It is canonical:
// equal trees give equal bytes, whatever the key order and quoting style in the file.
func (n node) encode() []byte {
	return n.appendTo(nil)
}

func (n node) appendTo(b []byte) []byte {
	switch n.kind {
	case nullNode:
		return append(b, "null"...)
	case mappingNode:
		b = append(b, '{')
		for i, k := range slices.Sorted(maps.Keys(n.m)) {
			if i > 0 {
				b = append(b, ", "...)
			}
			b = appendKey(b, k)
			b = n.m[k].appendTo(b)
		}
		return append(b, '}')
	case sequenceNode:
		b = append(b, '[')
		for i, v := range n.items {
			if i > 0 {
				b = append(b, ", "...)
			}
			b = v.appendTo(b)
		}
		return append(b, ']')
	case stringNode:
		return appendQuoted(b, n.text)
	}
	// Numbers and booleans are written as they were, so the decoder resolves them the
	// same way again.
	return append(b, n.text...)
}

// maxImplicitKey is below the 1024-character limit of YAML implicit (simple) keys.
const maxImplicitKey = 1000

func appendKey(b []byte, k string) []byte {
	q := appendQuoted(nil, k)
	if len(q) > maxImplicitKey {
		b = append(b, "? "...)
		b = append(b, q...)
		return append(b, " : "...)
	}
	b = append(b, q...)
	return append(b, ": "...)
}

// appendQuoted appends s as a double-quoted YAML scalar on one line. Only a !!binary
// scalar can hold invalid UTF-8; such a string is written as !!binary again. The strings
// "null" and "~" get an explicit !!str tag: go.yaml.in/yaml/v2 takes them for null even
// when quoted and then fails to decode them into pointers and custom types.
func appendQuoted(b []byte, s string) []byte {
	switch {
	case !utf8.ValidString(s):
		b = append(b, "!!binary "...)
		s = base64.StdEncoding.EncodeToString([]byte(s))
	case s == "null" || s == "~":
		b = append(b, "!!str "...)
	}
	b = append(b, '"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b = append(b, '\\', byte(r))
		case r == '\n':
			b = append(b, `\n`...)
		case r == '\t':
			b = append(b, `\t`...)
		case r == '\r':
			b = append(b, `\r`...)
		case printable(r):
			b = utf8.AppendRune(b, r)
		case r <= 0xFFFF:
			b = fmt.Appendf(b, `\u%04X`, r)
		default:
			b = fmt.Appendf(b, `\U%08X`, r)
		}
	}
	return append(b, '"')
}

// printable reports whether r may appear unescaped in a double-quoted scalar: the YAML 1.1
// printable characters as the parser checks them, minus the line breaks NEL, LS and PS,
// which would be folded.
func printable(r rune) bool {
	switch {
	case r >= 0x20 && r <= 0x7E,
		r >= 0xA0 && r <= 0xD7FF && r != 0x2028 && r != 0x2029,
		r >= 0xE000 && r <= 0xFFFD && r != 0xFEFF,
		r >= 0x10000 && r <= utf8.MaxRune:
		return true
	}
	return false
}

// reporter receives a decoding or validation problem at a field path such as
// "expect.xpath[0]" ("" for the value as a whole).
type reporter func(path, msg string)

// A decoder decodes trees into configuration values and reports every problem at the path
// of the value it concerns.
type decoder struct {
	report reporter
	// partial only checks field names and the values of single fields, not the rules that
	// plainStructs validate across fields: other values may complete a fragment such as
	// the defaults.
	partial bool
}

// decode strictly decodes n into the value out points to. If that fails, the fields, keys
// or items of n are decoded one by one so that every problem is reported at the path of
// the value it concerns; the strict decoder itself stops at the first error of a custom
// unmarshaler and reports line numbers of the merged document, which mean nothing to the
// user.
func (d decoder) decode(n node, out any, path string) bool {
	t := reflect.TypeOf(out).Elem()
	if d.partial && descends(t) {
		// What a strict decode would add are the checks of plainStructs.
		return !d.locate(n, t, path)
	}
	err := yaml.UnmarshalStrict(n.encode(), out)
	if err == nil {
		return true
	}
	if !d.locate(n, t, path) {
		reportYAMLError(err, path, d.report)
	}
	return false
}

var (
	unmarshalerType     = reflect.TypeFor[yaml.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()

	// plainStructs have an UnmarshalYAML that decodes them as plain structs and then
	// validates them, so their fields can be decoded one by one.
	plainStructs = map[reflect.Type]bool{
		reflect.TypeFor[commoncfg.HTTPClientConfig](): true,
		reflect.TypeFor[commoncfg.TLSConfig]():        true,
		reflect.TypeFor[commoncfg.OAuth2]():           true,
	}
)

// descends reports whether locate decodes the fields, keys or items of a value of type t
// one by one.
func descends(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if plainStructs[t] {
		return true
	}
	if pt := reflect.PointerTo(t); pt.Implements(unmarshalerType) || pt.Implements(textUnmarshalerType) {
		return false
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Map, reflect.Slice:
		return true
	}
	return false
}

// locate decodes the children of n into fresh values of their types and reports their
// problems. It returns false if it reported nothing, i.e. the problem concerns n as a whole.
func (d decoder) locate(n node, t reflect.Type, path string) bool {
	if n.kind == nullNode || !descends(t) {
		return false
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	found := false
	child := func(c node, ct reflect.Type, cpath string) {
		if !d.decode(c, reflect.New(ct).Interface(), cpath) {
			found = true
		}
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Map:
		if n.kind != mappingNode {
			d.report(path, "want a mapping, got "+n.describe())
			return true
		}
		for _, k := range slices.Sorted(maps.Keys(n.m)) {
			ct, ok := valueType(t, k)
			if !ok {
				d.report(joinPath(path, k), "unknown field")
				found = true
				continue
			}
			child(n.m[k], ct, joinPath(path, k))
		}
	case reflect.Slice:
		if n.kind != sequenceNode {
			d.report(path, "want a list, got "+n.describe())
			return true
		}
		for i, c := range n.items {
			child(c, t.Elem(), fmt.Sprintf("%s[%d]", path, i))
		}
	}
	return found
}

// valueType returns the type of the value that the YAML key name sets in a struct or map
// of type t.
func valueType(t reflect.Type, name string) (reflect.Type, bool) {
	if t.Kind() == reflect.Map {
		return t.Elem(), true
	}
	return fieldType(t, name)
}

// fieldType returns the type of the value that the YAML key name sets in struct type t,
// following inlined structs and maps like the YAML decoder.
func fieldType(t reflect.Type, name string) (reflect.Type, bool) {
	var inlineMap reflect.Type
	for key, ft := range yamlFields(t) {
		switch key {
		case "":
			inlineMap = ft.Elem()
		case name:
			return ft, true
		}
	}
	return inlineMap, inlineMap != nil
}

// yamlFields yields the YAML key and the type of every field of struct type t, following
// inlined structs. An inlined map is yielded with the key "".
func yamlFields(t reflect.Type) iter.Seq2[string, reflect.Type] {
	return func(yield func(string, reflect.Type) bool) {
		for i := range t.NumField() {
			f := t.Field(i)
			tag := f.Tag.Get("yaml")
			if !f.IsExported() || tag == "-" {
				continue
			}
			key, opts, _ := strings.Cut(tag, ",")
			switch {
			case !slices.Contains(strings.Split(opts, ","), "inline"):
				if key == "" {
					key = strings.ToLower(f.Name)
				}
			case f.Type.Kind() == reflect.Struct:
				for k, ft := range yamlFields(f.Type) {
					if !yield(k, ft) {
						return
					}
				}
				continue
			default:
				key = ""
			}
			if !yield(key, f.Type) {
				return
			}
		}
	}
}

// yamlKeys returns the YAML keys of struct type t.
func yamlKeys(t reflect.Type) []string {
	var keys []string
	for k := range yamlFields(t) {
		if k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

var (
	yamlLineRE     = regexp.MustCompile(`^line \d+: `)
	yamlNotFoundRE = regexp.MustCompile(`^field (\S+) not found in type \S+$`)
	quotedRE       = regexp.MustCompile(`\s*"(?:[^"\\]|\\.)*"`)
)

// urlError describes an error of url.Parse without the URL and the parts of it that the
// messages quote, which may be a password: a port in "user:password/path" or an escape in
// the password.
func urlError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return quotedRE.ReplaceAllString(err.Error(), "")
}

// reportYAMLError reports a decoding error of the value at path, without the line numbers.
func reportYAMLError(err error, path string, report reporter) {
	var fe *fieldError
	if errors.As(err, &fe) {
		report(joinPath(path, fe.field), fe.err.Error())
		return
	}
	var ue *url.Error
	if errors.As(err, &ue) { // proxy_url
		report(path, "invalid URL: "+urlError(err))
		return
	}
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		report(path, err.Error())
		return
	}
	for _, msg := range te.Errors {
		msg = yamlLineRE.ReplaceAllString(msg, "")
		if m := yamlNotFoundRE.FindStringSubmatch(msg); m != nil {
			report(joinPath(path, m[1]), "unknown field")
			continue
		}
		report(path, msg)
	}
}

// fieldError is an error of a custom unmarshaler about one of the fields it decodes.
type fieldError struct {
	field string
	err   error
}

func (e *fieldError) Error() string { return e.field + ": " + e.err.Error() }

func (e *fieldError) Unwrap() error { return e.err }

// joinPath appends a key to a field path; keys that would make the path ambiguous are
// quoted.
func joinPath(path, key string) string {
	if key == "" || strings.ContainsAny(key, ".[]\" \t") {
		return path + "[" + strconv.Quote(key) + "]"
	}
	if path == "" {
		return key
	}
	return path + "." + key
}

// soapFields is the YAML form of SOAP.
type soapFields struct {
	Version any    `yaml:"version"`
	Action  string `yaml:"action,omitempty"`
}

// UnmarshalYAML implements yaml.Unmarshaler. The version may be the float 1.1 or 1.2 or
// the string "1.1" or "1.2"; fields that are not set keep their value.
func (s *SOAP) UnmarshalYAML(unmarshal func(any) error) error {
	f := soapFields{Action: s.Action}
	if err := unmarshal(&f); err != nil {
		return err
	}
	s.Action = f.Action
	var text string
	switch v := f.Version.(type) {
	case nil:
		return nil
	case string:
		text = v
	case float64:
		text = strconv.FormatFloat(v, 'f', -1, 64)
	default:
		text = fmt.Sprint(v)
	}
	v, err := soap.ParseVersion(text)
	if err != nil {
		return &fieldError{field: "version", err: err}
	}
	s.Version = v
	return nil
}

// MarshalYAML implements yaml.Marshaler; the version is written as a string.
func (s SOAP) MarshalYAML() (any, error) {
	return soapFields{Version: s.Version.String(), Action: s.Action}, nil
}

// UnmarshalYAML implements yaml.Unmarshaler. KB, MB, … are 1024-based as in Prometheus,
// like KiB, MiB, ….
func (b *ByteSize) UnmarshalYAML(unmarshal func(any) error) error {
	var v any
	if err := unmarshal(&v); err != nil {
		return err
	}
	var text string
	switch v := v.(type) {
	case int:
		*b = ByteSize(v)
		return nil
	case int64: // beyond int on 32-bit platforms
		*b = ByteSize(v)
		return nil
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			*b = ByteSize(n)
			return nil
		}
		if n, err := units.ParseBase2Bytes(v); err == nil {
			*b = ByteSize(n)
			return nil
		}
		text = strconv.Quote(v)
	default:
		// The text as written: an integer too large for int64 would print as a float.
		if unmarshal(&text) != nil {
			text = fmt.Sprint(v)
		}
	}
	return fmt.Errorf("invalid size %s (want a number of bytes or a size such as 512KiB or 4MiB)", text)
}

// MarshalYAML implements yaml.Marshaler, e.g. "10MiB".
func (b ByteSize) MarshalYAML() (any, error) {
	return units.Base2Bytes(b).String(), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *Regexp) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return r.UnmarshalText([]byte(s))
}

// UnmarshalText implements encoding.TextUnmarshaler. It replaces the method promoted from
// the embedded *regexp.Regexp, which would dereference a nil pointer.
func (r *Regexp) UnmarshalText(text []byte) error {
	re, err := regexp.Compile(string(text))
	if err != nil {
		return err
	}
	r.Regexp = re
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (r Regexp) MarshalYAML() (any, error) {
	if r.Regexp == nil {
		return nil, nil
	}
	return r.String(), nil
}

// UnmarshalYAML implements yaml.Unmarshaler. The expression is compiled once the target's
// namespaces are known.
func (x *XPath) UnmarshalYAML(unmarshal func(any) error) error {
	return unmarshal(&x.Expr)
}

// MarshalYAML implements yaml.Marshaler.
func (x XPath) MarshalYAML() (any, error) {
	return x.Expr, nil
}
