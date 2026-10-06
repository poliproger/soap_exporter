package check

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// FuzzEvaluate checks that arbitrary responses never make Evaluate panic and that every
// result has the documented shape.
func FuzzEvaluate(f *testing.F) {
	tgt := loadTarget(f, "1.1", `status: [200, 202]
namespaces: {o: 'http://corp.example/', ds: 'http://tempuri.org/BranchesDataset.xsd'}
headers:
  - {name: Content-Type, regex: '^text/xml', not_regex: 'html'}
regex: ['<Order>']
not_regex: ['ORA-\d{5}']
xpath:
  - "count(//o:Order) > 0"
  - "string(//o:Order[1]/o:Status)"
  - "sum(//o:Order/o:Id)"
  - "//*[local-name() = 'Branches'][starts-with(*[1], '1')]"
  - "starts-with(//o:Status, 1)"
not_xpath:
  - "//o:Error | //soap:Fault"
  - "concat(//ds:Id, '')"`)
	files, err := filepath.Glob(filepath.Join("testdata", "*"))
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(200, "text/xml; charset=utf-8", string(data))
		f.Add(500, "text/html", string(data))
	}
	f.Add(202, "", "")
	f.Add(401, "", " \n")
	f.Add(200, "", "<a")
	f.Add(200, "", "\uFEFF")
	f.Add(200, "", `<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>`)
	f.Add(200, "", `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode/></soap:Fault></soap:Body></soap:Envelope>`)
	f.Fuzz(func(t *testing.T, status int, contentType, text string) {
		r := &Response{Status: status, Header: http.Header{"Content-Type": {contentType}}, Text: text}
		outcomes, reason, message := Evaluate(tgt, r)
		if err := checkInvariants(tgt, outcomes, reason, message); err != nil {
			t.Fatalf("%v\noutcomes: %+v", err, outcomes)
		}
	})
}
