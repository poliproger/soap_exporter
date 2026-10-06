package redact

import "testing"

func TestHeaderValue(t *testing.T) {
	const token = "oYG3MIG0oAMKAQChCwYJKoZIgvcSAQICooGf+/BIGc=="
	tests := []struct {
		name, value, want string
	}{
		{"Authorization", "Negotiate YIIGhgYGKwYBBQUC", Placeholder},
		{"authorization", "Basic bW9uaXRvcjpzM2NyZXQ=", Placeholder},
		{"Proxy-Authorization", "Basic bW9uaXRvcjpzM2NyZXQ=", Placeholder},
		{"Cookie", "a=b; c=d", Placeholder},
		{"Set-Cookie", "ASP.NET_SessionId=abc; path=/", Placeholder},
		{"WWW-Authenticate", "Negotiate " + token, "Negotiate " + Placeholder},
		{"Www-Authenticate", "negotiate  abc=", "negotiate  " + Placeholder},
		{"WWW-Authenticate", "Negotiate", "Negotiate"},
		{"WWW-Authenticate", `Negotiate, NTLM, Basic realm="corp.example"`, `Negotiate, NTLM, Basic realm="corp.example"`},
		{"WWW-Authenticate", "NTLM TlRMTVNTUAACAAAA, Negotiate abc", "NTLM " + Placeholder + ", Negotiate " + Placeholder},
		{"WWW-Authenticate", `Kerberos realm="CORP.EXAMPLE"`, `Kerberos realm="CORP.EXAMPLE"`},
		{"Proxy-Authenticate", "Negotiate abc", "Negotiate " + Placeholder},
		{"WWW-Authenticate", `Bearer error="invalid_token"`, `Bearer error="invalid_token"`},
		// Malformed tokens go as well.
		{"WWW-Authenticate", "Negotiate " + token + token, "Negotiate " + Placeholder},
		{"WWW-Authenticate", "Negotiate abc;def ghi", "Negotiate " + Placeholder + " ghi"},
		{"WWW-Authenticate", "Kerberos =abc, NTLM", "Kerberos " + Placeholder + ", NTLM"},
		{"WWW-Authenticate", `Kerberos realm="CORP EXAMPLE", Negotiate abc==`, `Kerberos realm="CORP EXAMPLE", Negotiate ` + Placeholder},
		{"Content-Type", "text/xml; charset=utf-8", "text/xml; charset=utf-8"},
		{"X-Note", "Negotiate abc", "Negotiate abc"},
	}
	for _, tt := range tests {
		if got := HeaderValue(tt.name, tt.value); got != tt.want {
			t.Errorf("HeaderValue(%q, %q) = %q, want %q", tt.name, tt.value, got, tt.want)
		}
	}
}

func TestSecretHeader(t *testing.T) {
	for _, name := range []string{
		"Authorization", "proxy-authorization", "Cookie", "SET-COOKIE", "WWW-Authenticate", "Proxy-Authenticate",
	} {
		if !SecretHeader(name) {
			t.Errorf("SecretHeader(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"Content-Type", "Server", "X-Authorization-Note", ""} {
		if SecretHeader(name) {
			t.Errorf("SecretHeader(%q) = true, want false", name)
		}
	}
}
