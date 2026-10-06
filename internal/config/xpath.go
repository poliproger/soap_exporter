package config

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/antchfx/xpath"
)

// xmlNS is the namespace the prefix xml is bound to (Namespaces in XML 1.0).
const xmlNS = "http://www.w3.org/XML/1998/namespace"

// compile compiles x with the namespace bindings ns. Every prefix of the expression is
// checked first: antchfx/xpath matches undeclared prefixes literally unless it gets a
// namespace map (plan finding 3), ignores the prefixes of function names, and reports an
// undeclared name test prefix less clearly.
func (x *XPath) compile(ns map[string]string) error {
	switch {
	case strings.TrimSpace(x.Expr) == "":
		return errors.New("empty expression")
	case strings.ContainsRune(x.Expr, 0):
		// The XPath scanner stops at a NUL and would ignore the rest of the expression.
		return errors.New("expression contains a NUL character")
	}
	var undeclared []string
	for _, q := range prefixedNames(x.Expr) {
		if _, ok := ns[q.prefix]; !ok {
			if !slices.Contains(undeclared, q.prefix) {
				undeclared = append(undeclared, q.prefix)
			}
			continue
		}
		if q.function {
			return fmt.Errorf("prefixed function name %s:%s is not supported", q.prefix, q.local)
		}
	}
	switch len(undeclared) {
	case 0:
	case 1:
		return fmt.Errorf("namespace prefix %q is not declared (declare it in expect.namespaces)", undeclared[0])
	default:
		return fmt.Errorf("namespace prefixes %s are not declared (declare them in expect.namespaces)", quoteList(undeclared))
	}
	c, err := xpath.CompileWithNS(x.Expr, ns)
	if err != nil {
		return fmt.Errorf("invalid expression: %w", err)
	}
	x.Compiled = c
	return nil
}

// quoteList formats strings as "a", "b".
func quoteList(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = strconv.Quote(s)
	}
	return strings.Join(q, ", ")
}

// qname is a prefixed name in an XPath expression.
type qname struct {
	prefix string
	local  string // "*" for a prefix:* name test
	// function is set for a function call (the name is followed by "(").
	function bool
}

// prefixedNames returns the prefixed names of an XPath 1.0 expression: name tests
// (p:name, p:*), function names and variable references ($p:name). String literals, axis
// names (child::, also "child ::"), node type tests (text()) and the wildcard * have no
// prefix.
//
// It tokenizes like the antchfx/xpath scanner, except that every character that is not an
// XPath delimiter counts as a name character: whatever that scanner reads as a prefix, this
// reads as one too. For invalid expressions the two may disagree; compilation rejects those.
func prefixedNames(expr string) []qname {
	var names []qname
	for i := 0; i < len(expr); {
		r, size := utf8.DecodeRuneInString(expr[i:])
		switch {
		case r == '"' || r == '\'':
			end := strings.IndexRune(expr[i+size:], r)
			if end < 0 {
				return names // unterminated literal
			}
			i += size + end + 1
		case unicode.IsDigit(r):
			i = skipNumber(expr, i)
		case isNameStart(r):
			j := scanName(expr, i)
			if q, end, ok := scanQName(expr, i, j); ok {
				names = append(names, q)
				j = end
			}
			i = j
		default:
			i += size
		}
	}
	return names
}

// scanQName reads the rest of a QName whose prefix is expr[start:colon]. A name followed by
// "::" is an axis name.
func scanQName(expr string, start, colon int) (q qname, end int, ok bool) {
	rest := expr[colon:]
	if !strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "::") {
		return qname{}, 0, false
	}
	q.prefix = expr[start:colon]
	local := colon + 1
	r, size := utf8.DecodeRuneInString(expr[local:])
	switch {
	case r == '*':
		q.local = "*"
		return q, local + size, true
	case isNameChar(r):
		end = scanName(expr, local)
		q.local = expr[local:end]
		next := strings.TrimLeftFunc(expr[end:], unicode.IsSpace)
		q.function = strings.HasPrefix(next, "(")
		return q, end, true
	}
	// "p:" followed by anything else is not a name; compilation reports it.
	return qname{}, 0, false
}

// isXPathDelimiter reports whether r ends a name in an XPath expression.
func isXPathDelimiter(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(`"'()[],@|*+=#$<>!/:`, r)
}

func isNameStart(r rune) bool {
	return !isXPathDelimiter(r) && r != '-' && r != '.' && !unicode.IsDigit(r)
}

func isNameChar(r rune) bool {
	return !isXPathDelimiter(r)
}

// scanName returns the end of the name starting at expr[i].
func scanName(expr string, i int) int {
	for i < len(expr) {
		r, size := utf8.DecodeRuneInString(expr[i:])
		if !isNameChar(r) {
			break
		}
		i += size
	}
	return i
}

// skipNumber returns the end of the number starting at expr[i]: digits, optionally followed
// by "." and more digits.
func skipNumber(expr string, i int) int {
	digits := func(i int) int {
		for i < len(expr) {
			r, size := utf8.DecodeRuneInString(expr[i:])
			if !unicode.IsDigit(r) {
				break
			}
			i += size
		}
		return i
	}
	i = digits(i)
	if i < len(expr) && expr[i] == '.' {
		i = digits(i + 1)
	}
	return i
}

// isNCName reports whether s is a valid namespace prefix: an XML 1.0 (fifth edition) Name
// without colons.
func isNCName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 && !isXMLNameStart(r) || !isXMLNameChar(r) {
			return false
		}
	}
	return true
}

func isXMLNameStart(r rune) bool {
	switch {
	case r == '_', 'A' <= r && r <= 'Z', 'a' <= r && r <= 'z',
		0xC0 <= r && r <= 0xD6, 0xD8 <= r && r <= 0xF6, 0xF8 <= r && r <= 0x2FF,
		0x370 <= r && r <= 0x37D, 0x37F <= r && r <= 0x1FFF, 0x200C <= r && r <= 0x200D,
		0x2070 <= r && r <= 0x218F, 0x2C00 <= r && r <= 0x2FEF, 0x3001 <= r && r <= 0xD7FF,
		0xF900 <= r && r <= 0xFDCF, 0xFDF0 <= r && r <= 0xFFFD, 0x10000 <= r && r <= 0xEFFFF:
		return true
	}
	return false
}

func isXMLNameChar(r rune) bool {
	return isXMLNameStart(r) || r == '-' || r == '.' || '0' <= r && r <= '9' || r == 0xB7 ||
		0x300 <= r && r <= 0x36F || 0x203F <= r && r <= 0x2040
}
