//go:build unix

package gokrb5

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// mkfifo creates a FIFO at path. Opening it for reading blocks until a writer appears; the
// cleanup opens it for writing, so a call that blocks on it does not outlive the test.
func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

func TestReadFIFO(t *testing.T) {
	tests := []struct {
		name string
		// setup prepares a FIFO at path and returns the call that reads it.
		setup func(t *testing.T, path string) func() error
	}{
		{
			name: "krb5.conf",
			setup: func(t *testing.T, path string) func() error {
				mkfifo(t, path)
				return func() error {
					_, err := New(path, nil)
					return err
				}
			},
		},
		{
			name: "keytab",
			setup: func(t *testing.T, path string) func() error {
				mkfifo(t, path)
				b, _ := newBackend(t, "krb5.conf")
				return func() error {
					_, err := b.NewCredential(testPrincipal, path)
					return err
				}
			},
		},
		{
			name: "keytab replaced at run time",
			setup: func(t *testing.T, path string) func() error {
				c, _, _ := newTestCredential(t, writeKeytab(t, path, entries(3)...))
				mustToken(t, c, testSPN)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				mkfifo(t, path)
				return func() error {
					_, err := c.Token(t.Context(), testSPN)
					return err
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := tt.setup(t, filepath.Join(t.TempDir(), "fifo"))
			done := make(chan error, 1)
			go func() { done <- call() }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
					t.Errorf("error = %v, want it to contain %q", err, "is not a regular file")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("blocked opening the FIFO")
			}
		})
	}
}
