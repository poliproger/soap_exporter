// Package redact hides credentials, cookies and authentication tokens in HTTP header values,
// so that check messages, logs and the debug pages never show them.
package redact

import (
	"net/http"
	"regexp"
	"strings"
)

// Placeholder replaces a hidden value or token.
const Placeholder = "<redacted>"

// tokenChallenge matches a challenge of a WWW-Authenticate or Proxy-Authenticate value that
// may carry a token, such as the mutual-auth token of "Negotiate <token>"; group 3 is the
// word after the scheme.
var tokenChallenge = regexp.MustCompile(`(?i)\b(Negotiate|NTLM|Kerberos)(\s+)([^\s,]+)`)

// authParam matches an auth-param such as realm="X": a name, "=" and a value. A token68 has
// "=" only as padding at its end.
var authParam = regexp.MustCompile(`^[^=]+=[^=]`)

// SecretHeader reports whether values of the header can carry credentials, cookies or
// authentication tokens: Authorization, Proxy-Authorization, Cookie, Set-Cookie,
// WWW-Authenticate and Proxy-Authenticate, in any case.
func SecretHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "Www-Authenticate", "Proxy-Authenticate":
		return true
	}
	return false
}

// HeaderValue returns a value of header name with credentials, cookies and authentication
// tokens replaced by Placeholder. Challenges without a token, such as "Negotiate" or
// `Basic realm="x"`, stay visible: they show which schemes a server offers. Values of
// other headers are returned as they are.
func HeaderValue(name, value string) string {
	switch http.CanonicalHeaderKey(name) {
	case "Www-Authenticate", "Proxy-Authenticate":
		return redactTokens(value)
	}
	if SecretHeader(name) {
		return Placeholder
	}
	return value
}

// redactTokens replaces the word after each Negotiate, NTLM or Kerberos scheme in a challenge
// value, unless it is an auth-param. Anything else is taken for a token, also when it is not
// well-formed: hiding too much is better than showing part of a token.
func redactTokens(value string) string {
	var b strings.Builder
	last := 0
	for _, m := range tokenChallenge.FindAllStringSubmatchIndex(value, -1) {
		word := value[m[6]:m[7]]
		if authParam.MatchString(word) {
			continue
		}
		b.WriteString(value[last:m[6]])
		b.WriteString(Placeholder)
		last = m[7]
	}
	if last == 0 {
		return value
	}
	b.WriteString(value[last:])
	return b.String()
}
