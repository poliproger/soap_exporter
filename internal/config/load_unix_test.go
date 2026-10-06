//go:build linux || darwin

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A named pipe would block the load until a writer appears, a device would be read without
// end.
func TestBodyFileNotRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "request.xml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, "/dev/zero"} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg := []byte(`
targets:
  - name: orders
    url: https://orders.example.com/Orders.svc
    body_file: ` + path + `
`)
			done := make(chan error, 1)
			go func() {
				_, err := LoadBytes(cfg, dir)
				done <- err
			}()
			select {
			case err := <-done:
				if want := `target "orders": body_file: ` + path + " is not a regular file"; err == nil || err.Error() != want {
					t.Errorf("LoadBytes = %v, want %s", err, want)
				}
			case <-time.After(10 * time.Second):
				// Release a load blocked on the pipe.
				if f, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
					f.Close()
				}
				t.Fatal("LoadBytes blocked")
			}
		})
	}
}
