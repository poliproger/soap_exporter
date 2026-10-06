package main

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/version"
)

func TestConfigCheck(t *testing.T) {
	tests := []struct {
		name string
		args []string
		// krb5Env is the value of KRB5_CONFIG.
		krb5Env    string
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{
			name:       "valid",
			args:       []string{"--config.file=testdata/valid.yml"},
			wantStdout: []string{"SUCCESS: config file testdata/valid.yml is valid, 2 targets\n"},
		},
		{
			name: "warnings",
			args: []string{"--config.file=testdata/warnings.yml"},
			wantStdout: []string{
				`WARNING: target "orders": labels.namespace: becomes exported_namespace`,
				"SUCCESS: config file testdata/warnings.yml is valid, 1 target\n",
			},
		},
		{
			name:     "invalid",
			args:     []string{"--config.file=testdata/invalid.yml"},
			wantCode: 1,
			wantStderr: []string{
				`FAILED: config file testdata/invalid.yml: target "orders": timeout: 2m exceeds the interval 1m` + "\n" +
					`  target "branches": url: required` + "\n",
			},
		},
		{
			name:       "missing",
			args:       []string{"--config.file=testdata/missing.yml"},
			wantCode:   1,
			wantStderr: []string{"FAILED: config file testdata/missing.yml: open "},
		},
		{
			name:       "kerberos with --kerberos.config-file",
			args:       []string{"--config.file=testdata/kerberos.yml", "--kerberos.config-file=testdata/krb5.conf"},
			wantStdout: []string{"SUCCESS: config file testdata/kerberos.yml is valid, 1 target\n"},
		},
		{
			name:       "kerberos with KRB5_CONFIG",
			args:       []string{"--config.file=testdata/kerberos.yml"},
			krb5Env:    "testdata/krb5.conf",
			wantStdout: []string{"SUCCESS: config file testdata/kerberos.yml is valid, 1 target\n"},
		},
		{
			name:     "kerberos with a missing krb5.conf",
			args:     []string{"--config.file=testdata/kerberos.yml"},
			krb5Env:  "testdata/missing.conf",
			wantCode: 1,
			wantStderr: []string{
				"FAILED: config file testdata/kerberos.yml: kerberos backend: krb5.conf: stat testdata/missing.conf: ",
			},
		},
		{
			name:       "web config",
			args:       []string{"--config.file=testdata/valid.yml", "--web.config.file=testdata/web-config.yml"},
			wantStdout: []string{"SUCCESS: config file testdata/valid.yml is valid, 2 targets\n"},
		},
		{
			name:       "invalid web config",
			args:       []string{"--config.file=testdata/valid.yml", "--web.config.file=testdata/web-config-invalid.yml"},
			wantCode:   1,
			wantStderr: []string{"FAILED: web config file testdata/web-config-invalid.yml: ", "unknown_field"},
		},
		{
			name:     "web config with a plain-text password",
			args:     []string{"--config.file=testdata/valid.yml", "--web.config.file=testdata/web-config-plain-password.yml"},
			wantCode: 1,
			wantStderr: []string{
				"FAILED: web config file testdata/web-config-plain-password.yml: ", "bcrypted password",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KRB5_CONFIG", tc.krb5Env)
			var stdout, stderr syncBuffer
			args := append([]string{"--config.check"}, tc.args...)
			if code := run(t.Context(), args, &stdout, &stderr); code != tc.wantCode {
				t.Errorf("run = %d, want %d", code, tc.wantCode)
			}
			mustContain(t, "stdout", stdout.String(), tc.wantStdout...)
			mustContain(t, "stderr", stderr.String(), tc.wantStderr...)
			if tc.wantCode != 0 && strings.Contains(stdout.String(), "SUCCESS") {
				t.Errorf("stdout reports success:\n%s", &stdout)
			}
			if tc.wantCode == 0 && stderr.String() != "" {
				t.Errorf("unexpected stderr:\n%s", &stderr)
			}
		})
	}
}

// TestRun runs the exporter against a SOAP server: probes show up in the metrics, the
// lifecycle endpoints work, and cancelling the context shuts it down.
func TestRun(t *testing.T) {
	soap := newSOAPServer(t)
	config := newConfigDir(t, "run.yml", soap.URL)
	e := startExporter(t, "--config.file="+config, "--web.enable-lifecycle")

	var samples []sample
	eventually(t, func() bool {
		samples = scrape(t, e.base)
		_, orders := find(samples, "soap_probe_success", "target", "orders")
		_, branches := find(samples, "soap_probe_success", "target", "branches")
		return orders && branches
	}, "no probe results in /metrics")
	wantSamples := []struct {
		name   string
		labels []string
		value  float64
	}{
		{"soap_probe_success", []string{"target", "orders", "team", "payments"}, 1},
		{"soap_probe_success", []string{"target", "branches"}, 0},
		{"soap_probe_failure_reason", []string{"target", "branches", "reason", "soap_fault"}, 1},
		{"soap_probe_http_status_code", []string{"target", "branches"}, http.StatusInternalServerError},
		{"soap_exporter_build_info", nil, 1},
		{"soap_exporter_config_last_reload_successful", nil, 1},
	}
	for _, w := range wantSamples {
		if got, ok := find(samples, w.name, w.labels...); !ok || got != w.value {
			t.Errorf("%s%q = %v (found: %v), want %v", w.name, w.labels, got, ok, w.value)
		}
	}
	for _, name := range []string{"go_goroutines", "soap_exporter_config_last_reload_success_timestamp_seconds"} {
		if _, ok := find(samples, name); !ok {
			t.Errorf("%s is missing", name)
		}
	}
	if got, want := soap.lastUserAgent(), userAgent(); got != want {
		t.Errorf("User-Agent of the probes = %q, want %q", got, want)
	}
	if code, body := do(t, http.MethodGet, e.base+"/", ""); code != http.StatusOK ||
		!strings.Contains(body, "Kerberos backend: gokrb5") {
		t.Errorf("GET /: status %d, want 200 and the Kerberos backend\n%s", code, body)
	}

	t.Run("reload", func(t *testing.T) {
		writeConfig(t, config, "run-reloaded.yml", soap.URL)
		if code, body := do(t, http.MethodPost, e.base+"/-/reload", ""); code != http.StatusOK {
			t.Fatalf("POST /-/reload: status %d\n%s", code, body)
		}
		samples := scrape(t, e.base)
		if got, want := targets(samples, "soap_target_info"), []string{"orders", "inventory"}; !sameElements(got, want) {
			t.Errorf("targets after the reload = %q, want %q", got, want)
		}
		if got, _ := find(samples, "soap_exporter_config_last_reload_successful"); got != 1 {
			t.Errorf("soap_exporter_config_last_reload_successful = %v, want 1", got)
		}
	})

	t.Run("failed reload", func(t *testing.T) {
		writeFile(t, config, []byte("targets: [}"))
		if code, body := do(t, http.MethodPost, e.base+"/-/reload", ""); code != http.StatusInternalServerError {
			t.Fatalf("POST /-/reload: status %d, want 500\n%s", code, body)
		}
		mustLogErrorOnce(t, e.stderr.String(),
			`msg="Reloading configuration failed, the previous configuration stays in effect"`)
		samples := scrape(t, e.base)
		if got, _ := find(samples, "soap_exporter_config_last_reload_successful"); got != 0 {
			t.Errorf("soap_exporter_config_last_reload_successful = %v, want 0", got)
		}
		if got, want := targets(samples, "soap_target_info"), []string{"orders", "inventory"}; !sameElements(got, want) {
			t.Errorf("targets after the failed reload = %q, want the previous %q", got, want)
		}
	})

	t.Run("log level", func(t *testing.T) {
		if code, body := do(t, http.MethodPut, e.base+"/-/log-level", "debug"); code != http.StatusOK {
			t.Fatalf("PUT /-/log-level: status %d\n%s", code, body)
		}
		if _, body := do(t, http.MethodGet, e.base+"/-/log-level", ""); body != "debug\n" {
			t.Errorf("GET /-/log-level = %q, want debug", body)
		}
	})

	if code := e.stop(); code != 0 {
		t.Errorf("run = %d, want 0", code)
	}
	mustContain(t, "log", e.stderr.String(), `msg="Starting soap_exporter"`, `msg="Shutting down"`)
	if _, err := client.Get(e.base + "/-/healthy"); err == nil {
		t.Error("the exporter still serves after shutdown")
	}
}

func sameElements(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// TestRunShutdownCancelsOnDemandProbe checks that shutdown cancels an on-demand probe in
// flight at once instead of waiting for it until the shutdown timeout.
func TestRunShutdownCancelsOnDemandProbe(t *testing.T) {
	soap := newSOAPServer(t)
	e := startExporter(t, "--config.file="+newConfigDir(t, "run-slow.yml", soap.URL), "--web.enable-lifecycle")

	// A scheduled probe of the target hangs as well, at most one within the minute.
	before := soap.hangCount()
	status := make(chan int, 1)
	go func() {
		resp, err := client.Post(e.base+"/debug/probe?target=slow&format=json", "", nil)
		if err != nil {
			status <- 0
			return
		}
		resp.Body.Close()
		status <- resp.StatusCode
	}()
	eventually(t, func() bool { return soap.hangCount() > before }, "the on-demand probe did not reach the server")

	start := time.Now()
	if code := e.stop(); code != 0 {
		t.Errorf("run = %d, want 0", code)
	}
	if d := time.Since(start); d >= shutdownTimeout {
		t.Errorf("shutdown took %v, want less than the shutdown timeout %v", d, shutdownTimeout)
	}
	if code := <-status; code != http.StatusOK {
		t.Errorf("POST /debug/probe: status %d, want 200 with the report of the cancelled probe", code)
	}
	if log := e.stderr.String(); strings.Contains(log, "after the shutdown timeout") {
		t.Errorf("the shutdown waited for the on-demand probe:\n%s", log)
	}
}

// TestNewServer checks the server settings: idle keep-alive connections are closed, no
// timeout cuts off the report of a long on-demand probe, and requests end with the context.
func TestNewServer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	srv := newServer(ctx, http.NotFoundHandler(), promslog.NewNopLogger())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("ReadHeaderTimeout %v, ReadTimeout %v, IdleTimeout %v, want all set",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.IdleTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v, want none", srv.WriteTimeout)
	}
	base := srv.BaseContext(nil)
	cancel()
	select {
	case <-base.Done():
	default:
		t.Error("the base context of the requests does not end with the context")
	}
}

func TestRunLifecycleDisabled(t *testing.T) {
	soap := newSOAPServer(t)
	e := startExporter(t, "--config.file="+newConfigDir(t, "run.yml", soap.URL))
	if code, _ := do(t, http.MethodPost, e.base+"/-/reload", ""); code != http.StatusForbidden {
		t.Errorf("POST /-/reload: status %d, want 403", code)
	}
	if code := e.stop(); code != 0 {
		t.Errorf("run = %d, want 0", code)
	}
}

func TestRunFails(t *testing.T) {
	soap := newSOAPServer(t)
	config := newConfigDir(t, "run.yml", soap.URL)
	// busy is an address in use.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { busy.Close() })

	// loaded is logged once the probes have started.
	const loaded = `msg="Configuration loaded"`
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantLog  []string
		// wantNoLog must not be logged.
		wantNoLog string
	}{
		{
			name:     "invalid config",
			args:     []string{"--config.file=testdata/invalid.yml", "--web.listen-address=" + freeAddr(t)},
			wantCode: 1,
			wantLog:  []string{`msg="Exiting: the configuration could not be loaded"`},
		},
		{
			name:     "missing config",
			args:     []string{"--config.file=testdata/missing.yml", "--web.listen-address=" + freeAddr(t)},
			wantCode: 1,
			wantLog:  []string{`msg="Exiting: the configuration could not be loaded"`, "testdata/missing.yml"},
		},
		{
			name:     "address in use",
			args:     []string{"--config.file=" + config, "--web.listen-address=" + busy.Addr().String()},
			wantCode: 1,
			wantLog:  []string{`msg="HTTP server failed"`},
		},
		{
			name: "invalid web config",
			args: []string{
				"--config.file=" + config, "--web.listen-address=" + freeAddr(t),
				"--web.config.file=testdata/web-config-invalid.yml",
			},
			wantCode: 1,
			wantLog: []string{
				`msg="Exiting: the web configuration file is invalid" file=testdata/web-config-invalid.yml`,
				"unknown_field",
			},
			wantNoLog: loaded,
		},
		{
			name: "web config with a plain-text password",
			args: []string{
				"--config.file=" + config, "--web.listen-address=" + freeAddr(t),
				"--web.config.file=testdata/web-config-plain-password.yml",
			},
			wantCode: 1,
			wantLog: []string{
				`msg="Exiting: the web configuration file is invalid" file=testdata/web-config-plain-password.yml`,
				"bcrypted password",
			},
			wantNoLog: loaded,
		},
		{
			name: "missing web config",
			args: []string{
				"--config.file=" + config, "--web.listen-address=" + freeAddr(t),
				"--web.config.file=testdata/missing.yml",
			},
			wantCode:  1,
			wantLog:   []string{`msg="Exiting: the web configuration file is invalid" file=testdata/missing.yml`},
			wantNoLog: loaded,
		},
		{
			name:     "invalid flag",
			args:     []string{"--history.limit=-1"},
			wantCode: exitUsage,
			wantLog:  []string{"--history.limit must not be negative"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr syncBuffer
			if code := run(t.Context(), tc.args, &stdout, &stderr); code != tc.wantCode {
				t.Errorf("run = %d, want %d", code, tc.wantCode)
			}
			mustContain(t, "stderr", stderr.String(), tc.wantLog...)
			if tc.wantCode == 1 {
				// One error line per failure.
				mustLogErrorOnce(t, stderr.String(), tc.wantLog[0])
			}
			if tc.wantNoLog != "" && strings.Contains(stderr.String(), tc.wantNoLog) {
				t.Errorf("stderr contains %q:\n%s", tc.wantNoLog, &stderr)
			}
		})
	}
}

func TestUserAgent(t *testing.T) {
	saved := version.Version
	t.Cleanup(func() { version.Version = saved })
	tests := []struct {
		version string
		want    string
	}{
		{"", "soap_exporter"},
		{"1.2.3", "soap_exporter/1.2.3"},
	}
	for _, tc := range tests {
		version.Version = tc.version
		if got := userAgent(); got != tc.want {
			t.Errorf("userAgent() with version %q = %q, want %q", tc.version, got, tc.want)
		}
	}
}

// TestMainExitCode runs the binary: a configuration that does not load ends it with 1.
func TestMainExitCode(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantLog  string
	}{
		{"missing config", []string{"--config.file=testdata/missing.yml"}, 1, "Exiting: the configuration could not be loaded"},
		{"invalid config", []string{"--config.file=testdata/invalid.yml"}, 1, "Exiting: the configuration could not be loaded"},
		{"config check", []string{"--config.check", "--config.file=testdata/invalid.yml"}, 1, "FAILED: config file testdata/invalid.yml"},
		{"invalid flag", []string{"--kerberos.backend=gssapi"}, exitUsage, "enum value must be one of gokrb5"},
		{"version", []string{"--version"}, 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, stderr := mainCommand(t, append(tc.args, "--web.listen-address="+freeAddr(t))...)
			if code := exitCode(t, cmd.Run()); code != tc.wantCode {
				t.Errorf("exit code %d, want %d", code, tc.wantCode)
			}
			mustContain(t, "stderr", stderr.String(), tc.wantLog)
		})
	}
}
