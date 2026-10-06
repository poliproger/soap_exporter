package soap

import (
	"path/filepath"
	"testing"
)

// FuzzParse feeds arbitrary bodies and Content-Type values through the response pipeline
// (DecodeBody, ParseXML, ParseEnvelope) and the request validation; none of them may panic,
// and ValidateRequest must not accept a body that ParseXML rejects.
func FuzzParse(f *testing.F) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.xml"))
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range files {
		body := readFixture(f, filepath.Base(name))
		f.Add(body, "")
		f.Add(body, "text/xml; charset=utf-8")
	}
	seeds := []struct {
		body        string
		contentType string
	}{
		{"\xef\xbb\xbf<a/>", "text/xml; charset=windows-1251"},
		{"\xff\xfe<\x00a\x00/\x00>\x00", ""},
		{"\xfe\xff\x00<\x00a\x00/\x00>", "application/soap+xml"},
		{`<?xml version="1.0" encoding="koi8-r"?><a>` + "\xf0\xd2\xc9\xd7\xc5\xd4" + `</a>`, ""},
		{`<?xml version="1.0" encoding="x-unknown"?><a/>`, ""},
		{`<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>`, "text/xml"},
		{`<a/><!DOCTYPE a>`, "text/xml"},
		{`<a/>junk`, "text/xml; charset=windows-1251; foo"},
		{`<!-- c --><?pi x?><a><?pi y?><!-- d --><![CDATA[z]]></a>`, `charset="utf-16"`},
		{"", "text/xml; charset=iso-2022-kr"},
		{`<!-- c --><?xml version="1.0"?><a xsi:nil="1" b="1" b="2"><x/><!----><!----><![CDATA[c]]>t</a>`, ""},
		{`<a xmlns:p="urn:p" xmlns:q="urn:p" p:b="1" q:b="2"><p:c xmlns:p=""/></a>`, ""},
	}
	for _, s := range seeds {
		f.Add([]byte(s.body), s.contentType)
	}
	f.Fuzz(func(t *testing.T, body []byte, contentType string) {
		if ValidateRequest(body, V11) == nil {
			if _, err := ParseXML(string(body)); err != nil {
				t.Fatalf("ValidateRequest accepts the body, ParseXML rejects it: %v", err)
			}
		}
		text, cs, err := DecodeBody(body, contentType)
		if err != nil {
			return
		}
		if cs == "" {
			t.Fatal("DecodeBody returned no charset and no error")
		}
		doc, err := ParseXML(text)
		if err != nil {
			return
		}
		env, err := ParseEnvelope(doc)
		if err != nil {
			return
		}
		if env.Body == nil {
			t.Fatal("ParseEnvelope returned an envelope without Body")
		}
		_ = env.Fault.String()
	})
}
