//go:build unix

package main

import (
	"slices"
	"strings"
	"syscall"
	"testing"
)

// TestMainSignals runs the binary: SIGHUP reloads the configuration, a failed reload is
// logged once, SIGTERM shuts the exporter down with exit code 0.
func TestMainSignals(t *testing.T) {
	soap := newSOAPServer(t)
	config := newConfigDir(t, "run.yml", soap.URL)
	addr := freeAddr(t)
	cmd, stderr := mainCommand(t, "--config.file="+config, "--web.listen-address="+addr)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	base := "http://" + addr
	waitReady(t, base, func() (int, bool) {
		select {
		case err := <-exited:
			return exitCode(t, err), true
		default:
			return 0, false
		}
	})

	writeConfig(t, config, "run-reloaded.yml", soap.URL)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		return slices.Contains(targets(scrape(t, base), "soap_target_info"), "inventory")
	}, "SIGHUP did not reload the configuration")

	const reloadFailed = `msg="Reloading configuration failed, the previous configuration stays in effect"`
	writeFile(t, config, []byte("targets: ["))
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return strings.Contains(stderr.String(), reloadFailed) },
		"SIGHUP with an invalid configuration was not reported")

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(t, <-exited); code != 0 {
		t.Errorf("exit code %d after SIGTERM, want 0", code)
	}
	mustContain(t, "stderr", stderr.String(),
		`msg="Reloading configuration" signal=SIGHUP`, `msg="Shutting down"`)
	// The process has ended, so a second line about the failed reload would be there.
	mustLogErrorOnce(t, stderr.String(), reloadFailed)
}
