package check

import (
	"fmt"
	"strings"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
)

// maxSteps bounds the work of one XPath evaluation (see navigator). Typical expressions
// take a few million steps on a 10 MiB response; the limit costs at most a couple of
// seconds of CPU.
const maxSteps = 20_000_000

// textPerStep is the number of bytes of text that count as one step.
const textPerStep = 16

// tooExpensiveError stops an evaluation that has taken all the steps it may take.
type tooExpensiveError struct {
	limit int
}

func (e *tooExpensiveError) Error() string {
	return fmt.Sprintf("stopped after %d steps, the expression is too expensive for this response", e.limit)
}

// navigator is an xmlquery navigator that counts the steps of an evaluation and panics with
// a *tooExpensiveError once it has taken its limit; antchfx/xpath has no other way to stop.
// Some reasonable expressions take time quadratic in the size of a hostile response:
// a[last()] counts the siblings of every a, and the string value of an element spans its
// subtree, so //a = 'x' on a elements nested a million deep reads the innermost text a
// million times.
//
// A step is a move or a copy of the navigator, a node passed, or textPerStep bytes of text
// read. Value builds the string value of an element iteratively, whereas xmlquery recurses
// once per nesting level.
type navigator struct {
	*xmlquery.NodeNavigator
	budget *budget // shared by all copies
}

// budget counts the steps of an evaluation.
type budget struct {
	limit, left int
}

// newNavigator returns a navigator at the root of doc that may take limit steps.
func newNavigator(doc *xmlquery.Node, limit int) *navigator {
	return &navigator{NodeNavigator: xmlquery.CreateXPathNavigator(doc), budget: &budget{limit: limit, left: limit}}
}

// step takes n steps.
func (x *navigator) step(n int) {
	x.budget.left -= n
	if x.budget.left < 0 {
		panic(&tooExpensiveError{limit: x.budget.limit})
	}
}

func (x *navigator) Copy() xpath.NodeNavigator {
	x.step(1)
	return &navigator{NodeNavigator: x.NodeNavigator.Copy().(*xmlquery.NodeNavigator), budget: x.budget}
}

func (x *navigator) MoveTo(other xpath.NodeNavigator) bool {
	x.step(1)
	o, ok := other.(*navigator)
	return ok && x.NodeNavigator.MoveTo(o.NodeNavigator)
}

func (x *navigator) MoveToRoot() {
	x.step(1)
	x.NodeNavigator.MoveToRoot()
}

func (x *navigator) MoveToParent() bool {
	x.step(1)
	return x.NodeNavigator.MoveToParent()
}

func (x *navigator) MoveToNextAttribute() bool {
	x.step(1)
	return x.NodeNavigator.MoveToNextAttribute()
}

func (x *navigator) MoveToChild() bool {
	x.step(1)
	return x.NodeNavigator.MoveToChild()
}

// MoveToFirst takes a step per preceding sibling: xmlquery walks them all in one call.
func (x *navigator) MoveToFirst() bool {
	x.step(1)
	for n := x.Current().PrevSibling; n != nil; n = n.PrevSibling {
		x.step(1)
	}
	return x.NodeNavigator.MoveToFirst()
}

// MoveToNext also takes steps for the white space text nodes xmlquery skips.
func (x *navigator) MoveToNext() bool {
	x.step(1)
	if x.NodeType() != xpath.AttributeNode {
		for n := x.Current().NextSibling; n != nil && isBlank(n); n = n.NextSibling {
			x.step(1 + len(n.Data)/textPerStep)
		}
	}
	return x.NodeNavigator.MoveToNext()
}

// MoveToPrevious also takes steps for the white space text nodes xmlquery skips.
func (x *navigator) MoveToPrevious() bool {
	x.step(1)
	if x.NodeType() != xpath.AttributeNode {
		for n := x.Current().PrevSibling; n != nil && isBlank(n); n = n.PrevSibling {
			x.step(1 + len(n.Data)/textPerStep)
		}
	}
	return x.NodeNavigator.MoveToPrevious()
}

// isBlank reports whether n is a text node that xmlquery's MoveToNext and MoveToPrevious skip.
func isBlank(n *xmlquery.Node) bool {
	return n.Type == xmlquery.TextNode && strings.TrimSpace(n.Data) == ""
}

// Value returns the string value of the current node as xmlquery does: the text and CDATA
// of an element's subtree, the value of an attribute, the text of a text or comment node,
// otherwise "".
func (x *navigator) Value() string {
	n := x.Current()
	if n.Type != xmlquery.ElementNode || x.NodeType() == xpath.AttributeNode {
		v := x.NodeNavigator.Value()
		x.step(1 + len(v)/textPerStep)
		return v
	}
	var b strings.Builder
	for c := n; ; {
		x.step(1)
		if c.Type == xmlquery.TextNode || c.Type == xmlquery.CharDataNode {
			x.step(len(c.Data) / textPerStep)
			b.WriteString(c.Data)
		}
		if c.FirstChild != nil {
			c = c.FirstChild
			continue
		}
		for c != n && c.NextSibling == nil {
			c = c.Parent
		}
		if c == n {
			return b.String()
		}
		c = c.NextSibling
	}
}

func (x *navigator) String() string {
	return x.Value()
}
