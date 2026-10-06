package check

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/soap"
)

// corpNS declares the prefix o for the namespace of the order fixtures.
const corpNS = "namespaces: {o: 'http://corp.example/'}\n"

// xpathOutcome evaluates a response against a target with exactly one xpath or not_xpath
// expression and returns that expression's outcome.
func xpathOutcome(t *testing.T, version, expect string, r *Response) result.CheckOutcome {
	t.Helper()
	tgt := loadTarget(t, version, expect)
	if n := len(tgt.Expect.XPath) + len(tgt.Expect.NotXPath); n != 1 {
		t.Fatalf("the target has %d XPath expressions, want 1", n)
	}
	outcomes, _, _ := evaluate(t, tgt, r)
	return outcomes[len(outcomes)-1]
}

func TestEvaluateXPath(t *testing.T) {
	orders11 := &Response{Status: 200, Text: fixture(t, "orders11.xml")}
	orders12 := &Response{Status: 200, Text: fixture(t, "orders12.xml")}
	noOrders11 := &Response{Status: 200, Text: fixture(t, "no-orders11.xml")}
	tests := []struct {
		name        string
		version     string
		expect      string
		response    *Response
		wantPassed  bool
		wantMessage string
	}{
		// Declared prefixes match by namespace URI, here a default namespace in the document.
		{
			name:       "declared prefix",
			expect:     corpNS + `xpath: ["count(//o:Order) > 0"]`,
			response:   orders11,
			wantPassed: true,
		},
		{
			name:        "declared prefix, false",
			expect:      corpNS + `xpath: ["count(//o:Order) > 0"]`,
			response:    noOrders11,
			wantMessage: `xpath "count(//o:Order) > 0" is false`,
		},
		{
			name:       "declared prefix, document with another prefix",
			version:    "1.2",
			expect:     "namespaces: {c: 'http://corp.example/'}\n" + `xpath: ["//c:Order[c:Id = 7]"]`,
			response:   orders12,
			wantPassed: true,
		},
		{
			name:       "built-in soap prefix, SOAP 1.1",
			expect:     corpNS + `xpath: ["/soap:Envelope/soap:Body/o:GetOrdersResponse"]`,
			response:   orders11,
			wantPassed: true,
		},
		{
			name:       "built-in soap prefix, SOAP 1.2",
			version:    "1.2",
			expect:     corpNS + `xpath: ["/soap:Envelope/soap:Body/o:GetStatusResponse"]`,
			response:   orders12,
			wantPassed: true,
		},
		{
			name:       "built-in soap11 prefix",
			expect:     `xpath: ["/soap11:Envelope/soap11:Body"]`,
			response:   orders11,
			wantPassed: true,
		},
		{
			name:        "built-in soap12 prefix on a SOAP 1.1 response",
			expect:      `xpath: ["/soap12:Envelope"]`,
			response:    orders11,
			wantMessage: `xpath "/soap12:Envelope" selects no nodes`,
		},
		{
			name:       "local-name()",
			expect:     `xpath: ["//*[local-name() = 'Order'][*[local-name() = 'Id'] = 2]"]`,
			response:   orders11,
			wantPassed: true,
		},
		{
			name:        "local-name(), false",
			expect:      `xpath: ["//*[local-name() = 'Order'][*[local-name() = 'Id'] = 3]"]`,
			response:    orders11,
			wantMessage: `xpath "//*[local-name() = 'Order'][*[local-name() = 'Id'] = 3]" selects no nodes`,
		},
		// Plan finding 3: an unprefixed name matches an element with an empty prefix even
		// inside a default namespace.
		{
			name:       "unprefixed name in a default namespace",
			expect:     `xpath: ["count(//Order) = 2"]`,
			response:   orders11,
			wantPassed: true,
		},
		// Results are converted as boolean() does.
		{
			name:       "number",
			expect:     corpNS + `xpath: ["count(//o:Order)"]`,
			response:   orders11,
			wantPassed: true,
		},
		{
			name:        "number zero",
			expect:      corpNS + `xpath: ["count(//o:Order)"]`,
			response:    noOrders11,
			wantMessage: `xpath "count(//o:Order)" is 0`,
		},
		{
			name:        "number NaN",
			expect:      corpNS + `xpath: ["number(//o:Order[1]/o:Status)"]`,
			response:    orders11,
			wantMessage: `xpath "number(//o:Order[1]/o:Status)" is NaN`,
		},
		// Numbers are formatted as the XPath string() function does.
		{
			name:        "large integer",
			expect:      corpNS + `not_xpath: ["count(//o:Order) * 1000000"]`,
			response:    orders11,
			wantMessage: `not_xpath "count(//o:Order) * 1000000" is 2000000`,
		},
		{
			name:        "fraction",
			expect:      `not_xpath: ["0.1 + 0.2"]`,
			response:    orders11,
			wantMessage: `not_xpath "0.1 + 0.2" is 0.30000000000000004`,
		},
		{
			name:        "infinity",
			expect:      `not_xpath: ["1 div 0"]`,
			response:    orders11,
			wantMessage: `not_xpath "1 div 0" is Infinity`,
		},
		{
			name:        "negative zero",
			expect:      `xpath: ["0 * -1"]`,
			response:    orders11,
			wantMessage: `xpath "0 * -1" is 0`,
		},
		{
			name:       "string",
			expect:     corpNS + `xpath: ["string(//o:Order[1]/o:Status)"]`,
			response:   orders11,
			wantPassed: true,
		},
		{
			name:        "empty string",
			expect:      corpNS + `xpath: ["string(//o:Order[3]/o:Status)"]`,
			response:    orders11,
			wantMessage: `xpath "string(//o:Order[3]/o:Status)" is ""`,
		},
		{
			name:        "boolean",
			expect:      corpNS + `xpath: ["//o:Order[1]/o:Status = 'Open'"]`,
			response:    orders11,
			wantMessage: `xpath "//o:Order[1]/o:Status = 'Open'" is false`,
		},
		{
			name:       "attribute",
			expect:     "namespaces: {xsi: 'http://www.w3.org/2001/XMLSchema-instance'}\n" + `xpath: ["/soap:Envelope[not(@xsi:type)]"]`,
			response:   orders11,
			wantPassed: true,
		},
		// not_xpath fails if the result is true.
		{
			name:       "not_xpath node-set",
			expect:     corpNS + `not_xpath: ["//o:Status[. = 'Maintenance']"]`,
			response:   orders11,
			wantPassed: true,
		},
		{
			name:        "not_xpath node-set, selected",
			version:     "1.2",
			expect:      corpNS + `not_xpath: ["//o:Status[. = 'Maintenance']"]`,
			response:    orders12,
			wantMessage: `not_xpath "//o:Status[. = 'Maintenance']" selects a node`,
		},
		{
			name:        "not_xpath number",
			expect:      corpNS + `not_xpath: ["count(//o:Error)"]`,
			response:    noOrders11,
			wantMessage: `not_xpath "count(//o:Error)" is 1`,
		},
		{
			name:        "not_xpath string",
			expect:      corpNS + `not_xpath: ["string(//o:Error)"]`,
			response:    noOrders11,
			wantMessage: `not_xpath "string(//o:Error)" is "ORA-12541: TNS:no listener"`,
		},
		{
			name:        "not_xpath boolean",
			expect:      corpNS + `not_xpath: ["//o:Order/o:Id = 2"]`,
			response:    orders11,
			wantMessage: `not_xpath "//o:Order/o:Id = 2" is true`,
		},
		// Without a document neither xpath nor not_xpath can pass.
		{
			name:        "empty body",
			expect:      "status: [202]\n" + corpNS + `xpath: ["//o:Order"]`,
			response:    &Response{Status: 202},
			wantMessage: `xpath "//o:Order" cannot be evaluated: the body is empty`,
		},
		{
			name:        "not_xpath on an empty body",
			expect:      "status: [202]\n" + corpNS + `not_xpath: ["//o:Error"]`,
			response:    &Response{Status: 202},
			wantMessage: `not_xpath "//o:Error" cannot be evaluated: the body is empty`,
		},
		{
			name:        "not_xpath on a body that is not well-formed",
			expect:      corpNS + `not_xpath: ["//o:Error"]`,
			response:    &Response{Status: 200, Text: fixture(t, "bad-gateway.html")},
			wantMessage: `not_xpath "//o:Error" cannot be evaluated: XML syntax error on line 6: element <hr> closed by </body>`,
		},
		// The parser's reason is given: this page is well-formed, but has a DOCTYPE.
		{
			name:        "xpath on a body with a DOCTYPE",
			expect:      corpNS + `xpath: ["//o:Order"]`,
			response:    &Response{Status: 200, Text: fixture(t, "error-page.html")},
			wantMessage: `xpath "//o:Order" cannot be evaluated: DOCTYPE is not allowed`,
		},
		// A well-formed document is queried even if it is not an envelope.
		{
			name:       "document that is not an envelope",
			expect:     `xpath: ["/html/body = 'OK'"]`,
			response:   &Response{Status: 200, Text: "<html><body>OK</body></html>"},
			wantPassed: true,
		},
		// Some functions panic on argument types known only at run time.
		{
			name:        "run-time error",
			expect:      corpNS + `xpath: ["starts-with(//o:Status, 1)"]`,
			response:    orders11,
			wantMessage: `xpath "starts-with(//o:Status, 1)" cannot be evaluated: starts-with() function argument type must be string`,
		},
		{
			name:        "run-time error in not_xpath",
			expect:      `not_xpath: ["sum('abc')"]`,
			response:    orders11,
			wantMessage: `not_xpath "sum('abc')" cannot be evaluated: sum() function argument type must be a node-set or number`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := xpathOutcome(t, cmp.Or(tt.version, "1.1"), tt.expect, tt.response)
			if o.Reason != result.ReasonXPath {
				t.Errorf("reason = %q, want %q", o.Reason, result.ReasonXPath)
			}
			if o.Passed != tt.wantPassed || o.Message != tt.wantMessage {
				t.Errorf("passed, message = %v, %q, want %v, %q", o.Passed, o.Message, tt.wantPassed, tt.wantMessage)
			}
		})
	}
}

// An ASMX DataSet keeps its rows in the DataSet's own default namespace inside the diffgram,
// not in the service namespace (plan finding 9).
func TestEvaluateXPathDataSet(t *testing.T) {
	const namespaces = `namespaces:
  svc: http://tempuri.org/
  ds: http://tempuri.org/BranchesDataset.xsd
  diffgr: urn:schemas-microsoft-com:xml-diffgram-v1
  msdata: urn:schemas-microsoft-com:xml-msdata
  xs: http://www.w3.org/2001/XMLSchema
`
	tests := []struct {
		expr        string
		wantMessage string // "" if the expression is true
	}{
		{expr: "//ds:Branches[ds:Id = '1']"},
		{expr: "count(//ds:Branches) = 2"},
		{expr: "/soap:Envelope/soap:Body/svc:LoadBranchesResponse/svc:LoadBranchesResult/diffgr:diffgram/ds:BranchesDataset/ds:Branches[ds:Name = 'North']"},
		{expr: "//ds:Branches[@diffgr:id = 'Branches2' and @msdata:rowOrder = 1]/ds:Name = 'North'"},
		{expr: "//*[local-name() = 'Branches'][*[local-name() = 'Name'] = 'Main']"},
		{expr: "//xs:schema/@id = 'BranchesDataset'"},
		// The rows are not in the service namespace.
		{expr: "//svc:Branches", wantMessage: `xpath "//svc:Branches" selects no nodes`},
		{expr: "//ds:Branches[ds:Id = '3']", wantMessage: `xpath "//ds:Branches[ds:Id = '3']" selects no nodes`},
		{expr: "sum(//ds:Branches/ds:Id)"},
		{expr: "string(//ds:Branches[ds:Id = 2]/ds:Name) = 'Main'", wantMessage: `xpath "string(//ds:Branches[ds:Id = 2]/ds:Name) = 'Main'" is false`},
	}
	r := &Response{Status: 200, Text: fixture(t, "dataset11.xml")}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			o := xpathOutcome(t, "1.1", namespaces+"xpath: ["+yamlQuote(tt.expr)+"]", r)
			if o.Passed != (tt.wantMessage == "") || o.Message != tt.wantMessage {
				t.Errorf("passed, message = %v, %q, want message %q", o.Passed, o.Message, tt.wantMessage)
			}
		})
	}
}

// yamlQuote returns s as a double-quoted YAML scalar; s must not contain '"' or '\'.
func yamlQuote(s string) string {
	return `"` + s + `"`
}

// The same target is evaluated concurrently by scheduled and on-demand probes, while a
// compiled xpath.Expr keeps evaluation state. Run with -race.
func TestEvaluateConcurrent(t *testing.T) {
	tgt := loadTarget(t, "1.1", `namespaces: {o: 'http://corp.example/'}
xpath:
  - "count(//o:Order) > 0"
  - "//o:Order[o:Id = '2']/o:Status = 'Open'"
  - "concat(//o:Order[1]/o:Id, '-', //o:Order[last()]/o:Id) = '1-2'"
  - "sum(//o:Order/o:Id) = 3"
  - "//o:Order[position() = 2]/o:Id"
  - "//*[local-name() = 'Status'][starts-with(., 'Ship')] or //o:Error"
not_xpath:
  - "//o:Order[contains(o:Status, 'Maint')]"
  - "//o:Error"`)
	responses := []*Response{
		{Status: 200, Text: fixture(t, "orders11.xml")},
		{Status: 200, Text: fixture(t, "no-orders11.xml")},
		{Status: 200, Text: fixture(t, "dataset11.xml")},
	}
	want := make([][]result.CheckOutcome, len(responses))
	for i, r := range responses {
		want[i], _, _ = Evaluate(tgt, r)
	}
	if _, reason, message := Evaluate(tgt, responses[0]); reason != result.ReasonNone {
		t.Fatalf("orders: reason, message = %q, %q, want a pass", reason, message)
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 100 {
				k := (g + i) % len(responses)
				if got, _, _ := Evaluate(tgt, responses[k]); !slices.Equal(got, want[k]) {
					t.Errorf("response %d: concurrent outcomes differ:\n got %+v\nwant %+v", k, got, want[k])
					return
				}
			}
		})
	}
	wg.Wait()
}

// A compiled xpath.Expr keeps state between evaluations, and some expressions are true only
// the first time it is evaluated.
func TestEvaluateXPathRepeated(t *testing.T) {
	tgt := loadTarget(t, "1.1", corpNS+`xpath:
  - "(//o:Order)[1]/o:Status = 'Shipped'"
  - "(//o:Order/o:Id)[2] = 2"`)
	r := &Response{Status: 200, Text: fixture(t, "orders11.xml")}
	for i := range 3 {
		if _, reason, message := evaluate(t, tgt, r); reason != result.ReasonNone {
			t.Fatalf("evaluation %d: reason, message = %q, %q", i+1, reason, message)
		}
	}
}

// antchfx/xpath v1.3.8 mishandles last() in a predicate of a parenthesized path. Compared
// with a value, (path)[last()]/step acts as if it selected no nodes, so the comparison is
// always false and a not_xpath with it always passes; last() - 1 there selects the wrong
// node. If this test fails after an upgrade, the bugs are fixed and the documented
// workarounds are no longer needed.
func TestEvaluateXPathLastBug(t *testing.T) {
	tests := []struct {
		expr string
		want bool
	}{
		{expr: "(//o:Order)[last()]/o:Status = 'Open'", want: false},        // should be true
		{expr: "string((//o:Order)[last() - 1]/o:Id) = '1'", want: false},   // should be true
		{expr: "string((//o:Order)[last()]/o:Status) = 'Open'", want: true}, // workaround
		{expr: "(//o:Order)[last()][o:Status = 'Open']", want: true},        // workaround
	}
	r := &Response{Status: 200, Text: fixture(t, "orders11.xml")}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			if o := xpathOutcome(t, "1.1", corpNS+"xpath: ["+yamlQuote(tt.expr)+"]", r); o.Passed != tt.want {
				t.Errorf("passed = %v, want %v (%s)", o.Passed, tt.want, o.Message)
			}
		})
	}
}

// envelopeR returns a SOAP 1.1 envelope whose body holds content in an R element of the
// namespace http://corp.example/.
func envelopeR(content string) string {
	return `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` +
		`<R xmlns="http://corp.example/">` + content + `</R></soap:Body></soap:Envelope>`
}

// An expression whose cost grows quadratically with a hostile response stops after maxSteps
// instead of pinning a core for hours: here the string value of every Status spans all
// the Status elements below it. A deep document as such is fine.
func TestEvaluateXPathTooExpensive(t *testing.T) {
	const depth = 10_000
	r := &Response{Status: 200, Text: envelopeR(strings.Repeat("<Status>", depth) + "Closed" + strings.Repeat("</Status>", depth))}
	tests := []struct {
		expr        string
		wantMessage string
	}{
		{
			expr:        "//o:Status = 'Open'",
			wantMessage: `xpath "//o:Status = 'Open'" cannot be evaluated: ` + (&tooExpensiveError{limit: maxSteps}).Error(),
		},
		{expr: fmt.Sprintf("count(//o:Status) = %d", depth)},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			o := xpathOutcome(t, "1.1", corpNS+"xpath: ["+yamlQuote(tt.expr)+"]", r)
			if o.Passed != (tt.wantMessage == "") || o.Message != tt.wantMessage {
				t.Errorf("passed, message = %v, %q, want message %q", o.Passed, o.Message, tt.wantMessage)
			}
		})
	}
}

// Every kind of work that can grow quadratically with the response counts against the limit.
func TestNavigatorLimit(t *testing.T) {
	const limit = 100_000
	deep := envelopeR(strings.Repeat("<Status>", 1000) + "Closed" + strings.Repeat("</Status>", 1000))
	wide := envelopeR(strings.Repeat("<Order><Status>Open</Status></Order>\n", 1000))
	// Long text and white space: with one step per node they would stay within the limit.
	longText := envelopeR(strings.Repeat("<Status>", 100) + strings.Repeat("x", 1<<20) + strings.Repeat("</Status>", 100))
	blanks := envelopeR(strings.Repeat("<Order/>"+strings.Repeat(" ", 1000), 100))
	tests := []struct {
		name    string
		body    string
		expr    string
		wantErr bool
	}{
		{name: "string values of nested elements", body: deep, expr: "//o:Status = 'Open'", wantErr: true},
		{name: "nested elements", body: deep, expr: "count(//o:Status) = 1000"},
		{name: "last() in a step", body: wide, expr: "//o:Order[last()]/o:Status = 'Open'", wantErr: true},
		{name: "union", body: wide, expr: "//o:Order | //soap:Fault", wantErr: true},
		{name: "siblings", body: wide, expr: "string((//o:Order)[last()]/o:Status) = 'Open'"},
		{name: "long text of nested elements", body: longText, expr: "//o:Status = 'Open'", wantErr: true},
		{name: "long text", body: longText, expr: "count(//o:Status) = 100"},
		{name: "last() with long white space", body: blanks, expr: "//o:Order[last()] = 'x'", wantErr: true},
		{name: "long white space", body: blanks, expr: "count(//o:Order) = 100"},
	}
	ns := map[string]string{"o": "http://corp.example/", "soap": soap.NS11}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := soap.ParseXML(tt.body)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := evaluateBool(tt.expr, ns, newNavigator(doc, limit))
			var tooExpensive *tooExpensiveError
			switch {
			case tt.wantErr && (!errors.As(err, &tooExpensive) || tooExpensive.limit != limit):
				t.Errorf("err = %v, want a tooExpensiveError with limit %d", err, limit)
			case !tt.wantErr && (err != nil || !got):
				t.Errorf("got %v, %v, want true", got, err)
			}
		})
	}
}

// Typical expressions stay far below maxSteps on a response of the default
// max_response_size. The steps are measured on 1 MiB and scaled.
func TestEvaluateXPathSteps(t *testing.T) {
	const size = 1 << 20
	ds := fixture(t, "dataset11.xml")
	first, last := strings.Index(ds, "<Branches "), strings.LastIndex(ds, "</Branches>")+len("</Branches>")
	var b strings.Builder
	b.WriteString(ds[:first])
	for b.Len() < size {
		b.WriteString(ds[first:last])
	}
	b.WriteString(ds[last:])
	doc, err := soap.ParseXML(b.String())
	if err != nil {
		t.Fatal(err)
	}
	ns := map[string]string{
		"soap":   soap.NS11,
		"ds":     "http://tempuri.org/BranchesDataset.xsd",
		"diffgr": "urn:schemas-microsoft-com:xml-diffgram-v1",
	}
	for _, expr := range []string{
		"count(//ds:Branches) > 0",
		"//ds:Branches[ds:Id = '7']/ds:Name = 'Main'",
		"//*[local-name() = 'Branches'][*[local-name() = 'Name'] = 'Main']",
		"sum(//ds:Branches/ds:Id) > 0",
		"//ds:Branches[ds:Name = '']",
		"string((//ds:Branches)[last()]/ds:Name) = 'North'",
		"//diffgr:diffgram/*/ds:Branches[@diffgr:id = 'Branches0']",
		"//soap:Fault",
	} {
		nav := newNavigator(doc, maxSteps)
		if _, _, err := evaluateBool(expr, ns, nav); err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		steps := (maxSteps - nav.budget.left) * int(config.DefaultMaxResponseSize/size)
		if steps > maxSteps/4 {
			t.Errorf("%s takes about %d steps on %d bytes, want at most %d", expr, steps, config.DefaultMaxResponseSize, maxSteps/4)
		}
	}
}

// The navigator selects the same nodes with the same values as xmlquery's navigator.
func TestNavigator(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.xml"))
	if err != nil {
		t.Fatal(err)
	}
	exprs := []string{
		"/", "//node()", "//@*", "//*[last()]", "//*[1]/following-sibling::node()",
		"//text()/preceding-sibling::node()", "//*/ancestor::*", "//node()[. = ../*[1]]",
		"(//*)[last() - 1]",
	}
	for _, name := range files {
		t.Run(filepath.Base(name), func(t *testing.T) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			text, _, err := soap.DecodeBody(data, "")
			if err != nil {
				t.Fatal(err)
			}
			doc, err := soap.ParseXML(text)
			if err != nil {
				t.Fatal(err)
			}
			for _, expr := range exprs {
				e := xpath.MustCompile(expr)
				want := nodes(e.Select(xmlquery.CreateXPathNavigator(doc)))
				if got := nodes(e.Select(newNavigator(doc, maxSteps))); !slices.Equal(got, want) {
					t.Errorf("%s:\n got %q\nwant %q", expr, got, want)
				}
			}
		})
	}
}

// nodes describes the nodes an iterator selects.
func nodes(it *xpath.NodeIterator) []string {
	var s []string
	for it.MoveNext() {
		n := it.Current()
		s = append(s, fmt.Sprintf("%d %s:%s=%q", n.NodeType(), n.Prefix(), n.LocalName(), n.Value()))
	}
	return s
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{math.Copysign(0, -1), "0"},
		{2, "2"},
		{-2.5, "-2.5"},
		{2e6, "2000000"},
		{1e21, "1000000000000000000000"},
		{1e-7, "0.0000001"},
		{0.30000000000000004, "0.30000000000000004"},
		{math.Inf(1), "Infinity"},
		{math.Inf(-1), "-Infinity"},
		{math.NaN(), "NaN"},
	}
	for _, tt := range tests {
		if got := formatNumber(tt.in); got != tt.want {
			t.Errorf("formatNumber(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
