package check

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"strconv"

	"github.com/antchfx/xpath"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/soap"
)

func checkXPaths(outcomes []result.CheckOutcome, t *config.Target, b *body) []result.CheckOutcome {
	e := &t.Expect
	if len(e.XPath)+len(e.NotXPath) == 0 {
		return outcomes
	}
	ns := namespaces(t)
	for _, x := range e.XPath {
		outcomes = append(outcomes, checkXPath("xpath", x.Expr, true, ns, b))
	}
	for _, x := range e.NotXPath {
		outcomes = append(outcomes, checkXPath("not_xpath", x.Expr, false, ns, b))
	}
	return outcomes
}

// namespaces returns the prefix bindings config compiled the expressions of t with:
// expect.namespaces plus the built-in prefixes (plan §5.3).
func namespaces(t *config.Target) map[string]string {
	ns := make(map[string]string, len(t.Expect.Namespaces)+3)
	maps.Copy(ns, t.Expect.Namespaces)
	ns[config.PrefixSOAP] = t.SOAP.Version.EnvelopeNS()
	ns[config.PrefixSOAP11] = soap.NS11
	ns[config.PrefixSOAP12] = soap.NS12
	return ns
}

// checkXPath passes if the boolean value of expr is want. An expression that cannot be
// evaluated fails, whatever want is.
func checkXPath(kind, expr string, want bool, ns map[string]string, b *body) result.CheckOutcome {
	name := kind + " " + quote(expr)
	o := result.CheckOutcome{Name: name, Reason: result.ReasonXPath}
	var (
		got   bool
		value string
		err   error
	)
	switch {
	case b.empty:
		err = errors.New("the body is empty")
	case b.doc == nil:
		err = b.err
	default:
		got, value, err = evaluateBool(expr, ns, newNavigator(b.doc, maxSteps))
	}
	switch {
	case err != nil:
		o.Message = name + " cannot be evaluated: " + oneLine(err.Error())
	case got == want:
		o.Passed = true
	default:
		o.Message = name + " " + value
	}
	return o
}

// evaluateBool evaluates expr on the document of nav and converts the result as the XPath
// boolean() function does. value describes the result for a message, e.g. "is false",
// "is 0" or "selects no nodes". A panic inside antchfx/xpath (some functions panic on
// argument types only known at run time) is returned as an error, as is a
// *tooExpensiveError.
//
// expr is compiled for every evaluation; the copy config compiled at load is not used.
// An xpath.Expr keeps evaluation state in its query tree, so it is not safe for concurrent
// use, and some expressions give a different result when evaluated again:
// (//a)[2]/b = 'x' is true only the first time.
func evaluateBool(expr string, ns map[string]string, nav *navigator) (b bool, value string, err error) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("%v", p)
			}
		}
	}()
	compiled, err := xpath.CompileWithNS(expr, ns)
	if err != nil {
		return false, "", err
	}
	switch v := compiled.Evaluate(nav).(type) {
	case bool:
		return v, "is " + strconv.FormatBool(v), nil
	case float64:
		return v != 0 && !math.IsNaN(v), "is " + clip(formatNumber(v)), nil
	case string:
		return v != "", "is " + quoteValue(v), nil
	case *xpath.NodeIterator:
		if v.MoveNext() {
			return true, "selects a node", nil
		}
		return false, "selects no nodes", nil
	default:
		return false, "", fmt.Errorf("unexpected result type %T", v)
	}
}

// formatNumber converts a number to a string as the XPath string() function does:
// integers without a decimal point, no exponent, Infinity, -Infinity and NaN.
func formatNumber(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "Infinity"
	case math.IsInf(v, -1):
		return "-Infinity"
	case v == 0:
		return "0" // also -0
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
