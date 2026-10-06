package gokrb5

import (
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestParseKeytab(t *testing.T) {
	valid := marshalKeytab(t, entries(3)...)
	tests := []struct {
		name        string
		data        []byte
		wantErr     string
		wantEntries int
	}{
		{name: "valid", data: valid, wantEntries: 3},
		{name: "valid version 1 header", data: []byte{5, 1}},
		{name: "no entries", data: []byte{5, 2}},
		{name: "empty file", data: nil, wantErr: "not a keytab file"},
		{name: "one byte", data: []byte{5}, wantErr: "not a keytab file"},
		{name: "text", data: []byte("[libdefaults]\n"), wantErr: "not a keytab file"},
		{name: "unknown version", data: []byte{5, 3, 0, 0, 0, 0}, wantErr: "not a keytab file"},
		{name: "truncated entry", data: valid[:len(valid)-10], wantErr: "malformed keytab"},
		{name: "truncated length", data: valid[:4], wantErr: "malformed keytab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kt, err := parseKeytab(tt.data)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("parseKeytab() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKeytab() error = %v", err)
			}
			if len(kt.Entries) != tt.wantEntries {
				t.Errorf("parseKeytab() has %d entries, want %d", len(kt.Entries), tt.wantEntries)
			}
		})
	}
}

func TestApplyKVNOWorkaround(t *testing.T) {
	other := "HTTP/other.corp.example"
	tests := []struct {
		name        string
		entries     []ktEntry
		wantApplied bool
		wantEntries int
	}{
		{name: "all kvno 0", entries: entries(0), wantApplied: true, wantEntries: 3 * 256},
		{name: "kvno 3", entries: entries(3), wantEntries: 3},
		{
			name: "mixed kvno",
			entries: []ktEntry{
				{testName, testRealm, 0, etypeID.RC4_HMAC},
				{testName, testRealm, 3, etypeID.AES256_CTS_HMAC_SHA1_96},
			},
			wantEntries: 2,
		},
		{
			name: "only another principal has kvno 0",
			entries: []ktEntry{
				{other, testRealm, 0, etypeID.AES256_CTS_HMAC_SHA1_96},
				{testName, testRealm, 2, etypeID.AES256_CTS_HMAC_SHA1_96},
			},
			wantEntries: 2,
		},
		{
			name: "another principal is not cloned",
			entries: []ktEntry{
				{other, testRealm, 0, etypeID.AES256_CTS_HMAC_SHA1_96},
				{testName, testRealm, 0, etypeID.AES256_CTS_HMAC_SHA1_96},
			},
			wantApplied: true,
			wantEntries: 2 + 255,
		},
		{name: "no entries"},
	}
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, testName)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kt := buildKeytab(t, tt.entries...)
			idx := entriesOf(kt, cname.NameString, testRealm)
			if got := applyKVNOWorkaround(kt, idx); got != tt.wantApplied {
				t.Fatalf("applyKVNOWorkaround() = %v, want %v", got, tt.wantApplied)
			}
			if len(kt.Entries) != tt.wantEntries {
				t.Errorf("keytab has %d entries, want %d", len(kt.Entries), tt.wantEntries)
			}
			if !tt.wantApplied {
				return
			}
			// What gokrb5 does with the AS-REP of a KDC that reports kvno 15 (plan finding 8).
			for _, kvno := range []int{0, 1, 15, 255} {
				if _, _, err := kt.GetEncryptionKey(cname, testRealm, kvno, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
					t.Errorf("GetEncryptionKey(kvno %d) error = %v", kvno, err)
				}
			}
			otherName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, other)
			if _, _, err := kt.GetEncryptionKey(otherName, testRealm, 15, etypeID.AES256_CTS_HMAC_SHA1_96); err == nil {
				t.Error("the entry of another principal was cloned")
			}
		})
	}
}

func TestKVNOMismatchWithoutWorkaround(t *testing.T) {
	// The failure the workaround exists for: gokrb5 matches the kvno of the reply exactly.
	kt := buildKeytab(t, entries(0)...)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, testName)
	_, _, err := kt.GetEncryptionKey(cname, testRealm, 15, etypeID.AES256_CTS_HMAC_SHA1_96)
	if err == nil || !strings.Contains(err.Error(), "matching key not found in keytab") {
		t.Fatalf("GetEncryptionKey(kvno 15) error = %v, want a missing key", err)
	}
}

func TestPrincipals(t *testing.T) {
	kt := buildKeytab(t, append(entries(3), ktEntry{"monitor", "OTHER.EXAMPLE", 1, etypeID.RC4_HMAC})...)
	got := strings.Join(principals(kt), ", ")
	if want := testPrincipal + ", monitor@OTHER.EXAMPLE"; got != want {
		t.Errorf("principals() = %q, want %q", got, want)
	}
}
