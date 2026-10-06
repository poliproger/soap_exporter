package main

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestParseFlagsDefaults(t *testing.T) {
	t.Setenv("KRB5_CONFIG", "") // kingpin ignores an empty variable
	var stdout, stderr bytes.Buffer
	o, code, ok := parseFlags(nil, &stdout, &stderr)
	if !ok {
		t.Fatalf("parseFlags: code %d, stderr:\n%s", code, &stderr)
	}
	checks := []struct {
		flag      string
		got, want any
	}{
		{"--config.file", o.configFile, "/etc/soap_exporter/config.yml"},
		{"--config.check", o.configCheck, false},
		{"--web.listen-address", *o.web.WebListenAddresses, []string{":10057"}},
		{"--web.config.file", *o.web.WebConfigFile, ""},
		{"--web.enable-lifecycle", o.enableLifecycle, false},
		{"--log.level", o.log.Level.String(), "info"},
		{"--log.format", o.log.Format.String(), "logfmt"},
		{"--kerberos.config-file", o.krb5Config, "/etc/krb5.conf"},
		{"--kerberos.backend", o.kerberosBackend, "gokrb5"},
		{"--history.limit", o.historyLimit, 20},
		{"--debug.capture-bodies", o.captureBodies, false},
	}
	for _, c := range checks {
		if got, want := jsonOf(t, c.got), jsonOf(t, c.want); got != want {
			t.Errorf("%s = %s, want %s", c.flag, got, want)
		}
	}
	if stdout.Len() > 0 || stderr.Len() > 0 {
		t.Errorf("unexpected output:\nstdout: %s\nstderr: %s", &stdout, &stderr)
	}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		// krb5Env is the value of KRB5_CONFIG.
		krb5Env string
		check   func(t *testing.T, o *options)
		// wantErr is part of the error on stderr; the exit code is then exitUsage.
		wantErr string
	}{
		{
			name: "all flags",
			args: []string{
				"--config.file=/srv/config.yml", "--config.check",
				"--web.listen-address=127.0.0.1:1", "--web.listen-address=[::1]:1",
				"--web.config.file=/srv/web.yml", "--web.enable-lifecycle",
				"--log.level=debug", "--log.format=json",
				"--kerberos.config-file=/srv/krb5.conf", "--kerberos.backend=gokrb5",
				"--history.limit=5", "--debug.capture-bodies",
			},
			check: func(t *testing.T, o *options) {
				got := []any{
					o.configFile, o.configCheck, *o.web.WebListenAddresses, *o.web.WebConfigFile,
					o.enableLifecycle, o.log.Level.String(), o.log.Format.String(), o.krb5Config,
					o.kerberosBackend, o.historyLimit, o.captureBodies,
				}
				want := []any{
					"/srv/config.yml", true, []string{"127.0.0.1:1", "[::1]:1"}, "/srv/web.yml",
					true, "debug", "json", "/srv/krb5.conf",
					"gokrb5", 5, true,
				}
				if g, w := jsonOf(t, got), jsonOf(t, want); g != w {
					t.Errorf("options = %s, want %s", g, w)
				}
			},
		},
		{
			name:    "KRB5_CONFIG is the default krb5.conf",
			krb5Env: "/srv/env-krb5.conf",
			check: func(t *testing.T, o *options) {
				if o.krb5Config != "/srv/env-krb5.conf" {
					t.Errorf("krb5Config = %q, want the value of KRB5_CONFIG", o.krb5Config)
				}
			},
		},
		{
			name:    "the flag overrides KRB5_CONFIG",
			args:    []string{"--kerberos.config-file=/srv/flag-krb5.conf"},
			krb5Env: "/srv/env-krb5.conf",
			check: func(t *testing.T, o *options) {
				if o.krb5Config != "/srv/flag-krb5.conf" {
					t.Errorf("krb5Config = %q, want the flag value", o.krb5Config)
				}
			},
		},
		{
			name: "history limit zero",
			args: []string{"--history.limit=0"},
			check: func(t *testing.T, o *options) {
				if o.historyLimit != 0 {
					t.Errorf("historyLimit = %d, want 0", o.historyLimit)
				}
			},
		},
		{
			name:    "negative history limit",
			args:    []string{"--history.limit=-1"},
			wantErr: "soap_exporter: error: --history.limit must not be negative, got -1",
		},
		{
			name:    "history limit not a number",
			args:    []string{"--history.limit=many"},
			wantErr: `parsing "many": invalid syntax`,
		},
		{
			name:    "unknown kerberos backend",
			args:    []string{"--kerberos.backend=gssapi"},
			wantErr: "enum value must be one of gokrb5, got 'gssapi'",
		},
		{
			name:    "unknown log level",
			args:    []string{"--log.level=verbose"},
			wantErr: "unrecognized log level verbose",
		},
		{
			name:    "unknown log format",
			args:    []string{"--log.format=xml"},
			wantErr: "unrecognized log format xml",
		},
		{
			name:    "unknown flag",
			args:    []string{"--config.path=/srv/config.yml"},
			wantErr: "soap_exporter: error: unknown long flag '--config.path', try --help",
		},
		{
			name:    "positional argument",
			args:    []string{"config.yml"},
			wantErr: "unexpected config.yml",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KRB5_CONFIG", tc.krb5Env)
			var stdout, stderr bytes.Buffer
			o, code, ok := parseFlags(tc.args, &stdout, &stderr)
			if tc.wantErr != "" {
				if ok || code != exitUsage {
					t.Fatalf("parseFlags = ok %v, code %d; want code %d", ok, code, exitUsage)
				}
				mustContain(t, "stderr", stderr.String(), tc.wantErr)
				return
			}
			if !ok {
				t.Fatalf("parseFlags: code %d, stderr:\n%s", code, &stderr)
			}
			tc.check(t, o)
		})
	}
}

func TestHelpAndVersion(t *testing.T) {
	tests := []struct {
		args []string
		want []string
	}{
		{
			args: []string{"--version"},
			want: []string{"soap_exporter, version", "go version:"},
		},
		{
			args: []string{"--help"},
			want: []string{
				"usage: soap_exporter [<flags>]",
				`--config.file="/etc/soap_exporter/config.yml"`,
				"--[no-]config.check",
				"--web.listen-address=:10057",
				`--web.config.file=""`,
				"--[no-]web.enable-lifecycle",
				"--log.level=info",
				"--log.format=logfmt",
				`--kerberos.config-file="/etc/krb5.conf"`,
				"($KRB5_CONFIG)",
				"restart", // krb5.conf is not read again on a reload
				"--kerberos.backend=gokrb5",
				"--history.limit=20",
				"--[no-]debug.capture-bodies",
			},
		},
		{
			args: []string{"-h"},
			want: []string{"usage: soap_exporter [<flags>]"},
		},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Setenv("KRB5_CONFIG", "")
			var stdout, stderr syncBuffer
			if code := run(t.Context(), tc.args, &stdout, &stderr); code != 0 {
				t.Fatalf("run = %d, want 0; stderr:\n%s", code, &stderr)
			}
			mustContain(t, "stdout", stdout.String(), tc.want...)
			if s := stderr.String(); s != "" {
				t.Errorf("unexpected stderr:\n%s", s)
			}
		})
	}
}

// TestDockerfileCMD checks that the image's default arguments parse.
func TestDockerfileCMD(t *testing.T) {
	b, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	for line := range strings.Lines(string(b)) {
		if rest, ok := strings.CutPrefix(line, "CMD "); ok {
			if err := json.Unmarshal([]byte(rest), &args); err != nil {
				t.Fatalf("CMD is not in exec form: %v", err)
			}
		}
	}
	if args == nil {
		t.Fatal("the Dockerfile has no CMD")
	}
	var stdout, stderr bytes.Buffer
	o, code, ok := parseFlags(args, &stdout, &stderr)
	if !ok {
		t.Fatalf("parseFlags(%q): code %d, stderr:\n%s", args, code, &stderr)
	}
	if o.configFile != "/etc/soap_exporter/config.yml" {
		t.Errorf("configFile = %q", o.configFile)
	}
	if !slices.Equal(*o.web.WebListenAddresses, []string{":10057"}) {
		t.Errorf("listen addresses = %q, want the exposed port", *o.web.WebListenAddresses)
	}
}
