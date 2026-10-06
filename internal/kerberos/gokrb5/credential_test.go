package gokrb5

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
)

const testSPN = "HTTP/app.corp.example"

// fakeKDC replaces the calls of a credential that need a KDC.
type fakeKDC struct {
	block chan struct{} // if set, login waits until it is closed
	delay time.Duration // login takes this long

	mu        sync.Mutex
	loginErrs []error // returned by the next logins
	tokenErrs []error // returned by the next token calls
	panics    int     // the next token calls panic
	clients   []*client.Client
	tokens    int
}

func (f *fakeKDC) login(cl *client.Client) error {
	f.mu.Lock()
	f.clients = append(f.clients, cl)
	var err error
	if len(f.loginErrs) > 0 {
		err, f.loginErrs = f.loginErrs[0], f.loginErrs[1:]
	}
	f.mu.Unlock()
	if f.block != nil {
		<-f.block
	}
	time.Sleep(f.delay)
	return err
}

func (f *fakeKDC) token(_ *client.Client, spn string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panics > 0 {
		f.panics--
		panic("malformed KDC reply")
	}
	if len(f.tokenErrs) > 0 {
		err := f.tokenErrs[0]
		f.tokenErrs = f.tokenErrs[1:]
		return nil, err
	}
	f.tokens++
	return fmt.Appendf(nil, "%s#%d", spn, f.tokens), nil
}

func (f *fakeKDC) logins() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.clients)
}

func (f *fakeKDC) client(i int) *client.Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clients[i]
}

func newTestCredential(t *testing.T, keytabPath string) (*credential, *fakeKDC, *logBuffer) {
	t.Helper()
	b, logs := newBackend(t, "krb5.conf")
	cred, err := b.NewCredential(testPrincipal, keytabPath)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	c := cred.(*credential)
	f := &fakeKDC{}
	c.login, c.newToken = f.login, f.token
	t.Cleanup(func() { _ = c.Close() })
	return c, f, logs
}

func mustToken(t *testing.T, c *credential, spn string) string {
	t.Helper()
	tok, err := c.Token(t.Context(), spn)
	if err != nil {
		t.Fatalf("Token(%q) error = %v", spn, err)
	}
	return string(tok)
}

// destroyed reports whether gokrb5's Destroy was called on cl.
func destroyed(cl *client.Client) bool {
	return cl.Credentials.UserName() == ""
}

// locked runs f with the credential's lock held.
func locked(c *credential, f func()) {
	c.lock <- struct{}{}
	defer c.unlock()
	f()
}

func TestTokenLogsInOnce(t *testing.T) {
	c, f, _ := newTestCredential(t, tempKeytab(t, entries(0)...))
	if n := f.logins(); n != 0 {
		t.Fatalf("logins after NewCredential = %d, want 0", n)
	}
	tokens := []string{
		mustToken(t, c, testSPN),
		mustToken(t, c, testSPN),
		mustToken(t, c, "HTTP/other.corp.example"),
	}
	if n := f.logins(); n != 1 {
		t.Errorf("logins = %d, want 1", n)
	}
	if tokens[0] == tokens[1] {
		t.Errorf("two calls returned the same token %q", tokens[0])
	}
	if !strings.HasPrefix(tokens[2], "HTTP/other.corp.example#") {
		t.Errorf("token for another SPN = %q", tokens[2])
	}

	cl := f.client(0)
	if got := cl.Credentials.CName().PrincipalNameString(); got != testName {
		t.Errorf("client name = %q, want %q", got, testName)
	}
	if got := cl.Credentials.Domain(); got != testRealm {
		t.Errorf("client realm = %q, want %q", got, testRealm)
	}
	if got, want := len(cl.Credentials.Keytab().Entries), 3*256; got != want {
		t.Errorf("client keytab has %d entries, want %d (with the kvno workaround)", got, want)
	}
}

func TestTokenLoginFailure(t *testing.T) {
	c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
	errKDC := errors.New("KDC_ERR_PREAUTH_FAILED")
	f.loginErrs = []error{errKDC}

	_, err := c.Token(t.Context(), testSPN)
	if !errors.Is(err, errKDC) || !strings.Contains(err.Error(), "login as "+testPrincipal) {
		t.Fatalf("Token() error = %v, want the login error", err)
	}
	var left *client.Client
	locked(c, func() { left = c.cl })
	if left != nil {
		t.Error("a failed login left a client")
	}

	mustToken(t, c, testSPN)
	if n := f.logins(); n != 2 {
		t.Errorf("logins = %d, want 2 (the failed login is retried)", n)
	}
}

func TestTokenErrorKeepsClient(t *testing.T) {
	c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
	errKDC := errors.New("KDC_ERR_S_PRINCIPAL_UNKNOWN")
	f.tokenErrs = []error{errKDC}

	if _, err := c.Token(t.Context(), testSPN); !errors.Is(err, errKDC) {
		t.Fatalf("Token() error = %v, want %v", err, errKDC)
	}
	mustToken(t, c, testSPN)
	if n := f.logins(); n != 1 {
		t.Errorf("logins = %d, want 1", n)
	}
}

func TestTokenRecoversPanic(t *testing.T) {
	c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
	f.panics = 1

	_, err := c.Token(t.Context(), testSPN)
	if err == nil || !strings.Contains(err.Error(), "gokrb5 panicked: malformed KDC reply") {
		t.Fatalf("Token() error = %v, want the panic", err)
	}
	if !destroyed(f.client(0)) {
		t.Error("the client was not destroyed after a panic; its TGT renewal goes on")
	}
	mustToken(t, c, testSPN)
	if n := f.logins(); n != 2 {
		t.Errorf("logins = %d, want 2 (the client is dropped after a panic)", n)
	}
}

func TestReset(t *testing.T) {
	c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
	mustToken(t, c, testSPN)
	first := f.client(0)

	c.Reset()
	mustToken(t, c, testSPN)
	if n := f.logins(); n != 2 {
		t.Fatalf("logins = %d, want 2", n)
	}
	if !destroyed(first) {
		t.Error("the client from before Reset was not destroyed")
	}
	if destroyed(f.client(1)) {
		t.Error("the new client is destroyed")
	}

	mustToken(t, c, testSPN)
	if n := f.logins(); n != 2 {
		t.Errorf("logins = %d, want 2 (Reset applies once)", n)
	}
}

func TestResetDoesNotWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
		f.block = make(chan struct{})
		done := make(chan error)
		go func() {
			_, err := c.Token(t.Context(), testSPN)
			done <- err
		}()
		synctest.Wait() // the login is in progress and holds the lock

		c.Reset()
		close(f.block)
		if err := <-done; err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		mustToken(t, c, testSPN)
		if n := f.logins(); n != 2 {
			t.Errorf("logins = %d, want 2 (Reset during a login applies to the next call)", n)
		}
	})
}

func TestClose(t *testing.T) {
	c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
	mustToken(t, c, testSPN)

	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !destroyed(f.client(0)) {
		t.Error("Close did not destroy the client")
	}
	if _, err := c.Token(t.Context(), testSPN); !errors.Is(err, errClosed) {
		t.Errorf("Token() after Close error = %v, want %v", err, errClosed)
	}
	if n := f.logins(); n != 1 {
		t.Errorf("logins = %d, want 1", n)
	}
	if err := c.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}
}

func TestCloseDoesNotWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
		f.block = make(chan struct{})
		// One call logs in, the calls for other SPNs wait for it.
		const n = 3
		errs := make(chan error, n)
		for i := range n {
			go func() {
				_, err := c.Token(t.Context(), fmt.Sprintf("HTTP/app%d.corp.example", i))
				errs <- err
			}()
		}
		synctest.Wait()

		closed := make(chan struct{})
		go func() {
			if err := c.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
		default:
			close(f.block)
			t.Fatal("Close waits for the login in progress")
		}
		for range n - 1 {
			if err := <-errs; !errors.Is(err, errClosed) {
				t.Errorf("waiting Token() error = %v, want %v", err, errClosed)
			}
		}
		if _, err := c.Token(t.Context(), testSPN); !errors.Is(err, errClosed) {
			t.Errorf("Token() after Close error = %v, want %v", err, errClosed)
		}

		// The login in progress completes, and its client is destroyed afterwards.
		close(f.block)
		if err := <-errs; err != nil {
			t.Errorf("Token() in progress error = %v", err)
		}
		synctest.Wait()
		if !destroyed(f.client(0)) {
			t.Error("the client of the login in progress was not destroyed")
		}
		if n := f.logins(); n != 1 {
			t.Errorf("logins = %d, want 1", n)
		}
	})
}

// Targets on different hosts that share a credential call Token with different SPNs. While
// the KDC is unreachable, each of their calls must not queue up a slow login of its own.
func TestTokenSharesLoginFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
		errKDC := errors.New("[Root cause: Networking_Error] no KDC reachable")
		f.loginErrs = []error{errKDC}
		f.delay = 10 * time.Second

		const n = 6
		errs := make(chan error, n)
		start := time.Now()
		for i := range n {
			go func() {
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				_, err := c.Token(ctx, fmt.Sprintf("HTTP/app%d.corp.example", i))
				errs <- err
			}()
		}
		for range n {
			if err := <-errs; !errors.Is(err, errKDC) {
				t.Errorf("Token() error = %v, want the login error", err)
			}
		}
		if d := time.Since(start); d != f.delay {
			t.Errorf("the calls returned after %v, want %v (one login)", d, f.delay)
		}
		if got := f.logins(); got != 1 {
			t.Errorf("logins = %d, want 1", got)
		}

		// A call that starts after the failure tries again.
		mustToken(t, c, testSPN)
		if got := f.logins(); got != 2 {
			t.Errorf("logins = %d, want 2", got)
		}
	})
}

func TestTokenLoginErrorAfterKeytabChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := tempKeytab(t, entries(3)...)
		c, f, _ := newTestCredential(t, path)
		errKDC := errors.New("KDC_ERR_PREAUTH_FAILED")
		f.loginErrs = []error{errKDC}
		f.block = make(chan struct{})

		errs := make(chan error, 2)
		for _, spn := range []string{testSPN, "HTTP/other.corp.example"} {
			go func() {
				_, err := c.Token(t.Context(), spn)
				errs <- err
			}()
		}
		synctest.Wait()
		// The keytab is fixed while the login with the old one fails: the waiting call logs
		// in with the new keytab instead of taking the old error.
		writeKeytab(t, path, append(entries(4), ktEntry{"HTTP/other.corp.example", testRealm, 4, etypeID.AES256_CTS_HMAC_SHA1_96})...)
		close(f.block)
		var failed int
		for range 2 {
			if err := <-errs; errors.Is(err, errKDC) {
				failed++
			} else if err != nil {
				t.Errorf("Token() error = %v", err)
			}
		}
		if failed != 1 {
			t.Errorf("%d calls failed, want 1", failed)
		}
		if got := f.logins(); got != 2 {
			t.Errorf("logins = %d, want 2", got)
		}
	})
}

func TestLoginErrorKVNOHint(t *testing.T) {
	errKey := errors.New("[Root cause: Decrypting_Error] KRBMessage_Handling_Error: AS Exchange Error: " +
		"failed setting AS_REP session key < Decrypting_Error: error decrypting AS_REP encrypted part: " +
		`matching key not found in keytab. Looking for "HTTP/svc.corp.example" realm: CORP.EXAMPLE kvno: 256 etype: 18`)
	errOther := errors.New("[Root cause: KDC_Error] KDC_ERR_C_PRINCIPAL_UNKNOWN")
	tests := []struct {
		name     string
		kvno     uint8
		err      error
		wantHint bool
	}{
		{name: "kvno workaround", kvno: 0, err: errKey, wantHint: true},
		{name: "no kvno workaround", kvno: 3, err: errKey},
		{name: "another error", kvno: 0, err: errOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, f, _ := newTestCredential(t, tempKeytab(t, entries(tt.kvno)...))
			f.loginErrs = []error{tt.err}
			_, err := c.Token(t.Context(), testSPN)
			if !errors.Is(err, tt.err) {
				t.Fatalf("Token() error = %v, want %v", err, tt.err)
			}
			if got := strings.Contains(err.Error(), "kvno workaround covers kvno 1–255"); got != tt.wantHint {
				t.Errorf("hint in %q = %v, want %v", err, got, tt.wantHint)
			}
		})
	}
}

func TestTokenContextDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
		f.block = make(chan struct{})
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		start := time.Now()
		_, err := c.Token(ctx, testSPN)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Token() error = %v, want context.DeadlineExceeded", err)
		}
		if d := time.Since(start); d != 5*time.Second {
			t.Errorf("Token() returned after %v, want 5s", d)
		}

		// The abandoned login goes on; the next call uses its client.
		close(f.block)
		mustToken(t, c, testSPN)
		if n := f.logins(); n != 1 {
			t.Errorf("logins = %d, want 1", n)
		}
	})
}

func TestTokenContextDoneBeforeCall(t *testing.T) {
	c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Token(ctx, testSPN); !errors.Is(err, context.Canceled) {
		t.Fatalf("Token() error = %v, want context.Canceled", err)
	}
	if n := f.logins(); n != 0 {
		t.Errorf("logins = %d, want 0", n)
	}
}

func TestTokenConcurrentCallers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, f, _ := newTestCredential(t, tempKeytab(t, entries(3)...))
		f.block = make(chan struct{})
		const n = 5
		tokens := make(chan string, n)
		for range n {
			go func() {
				tok, err := c.Token(t.Context(), testSPN)
				if err != nil {
					t.Errorf("Token() error = %v", err)
				}
				tokens <- string(tok)
			}()
		}
		// Every caller is durably blocked: one runs the login, the others wait for its
		// result rather than for the lock.
		synctest.Wait()
		if got := f.logins(); got != 1 {
			t.Fatalf("logins started = %d, want 1", got)
		}

		close(f.block)
		seen := make(map[string]bool)
		for range n {
			tok := <-tokens
			if seen[tok] {
				t.Errorf("token %q was handed out twice", tok)
			}
			seen[tok] = true
		}
		if got := f.logins(); got != 1 {
			t.Errorf("logins = %d, want 1", got)
		}
	})
}

func TestTokenReloadsChangedKeytab(t *testing.T) {
	path := tempKeytab(t, entries(0)...)
	c, f, logs := newTestCredential(t, path)
	mustToken(t, c, testSPN)

	grown := append(entries(0), ktEntry{"HTTP/other.corp.example", testRealm, 0, etypeID.AES256_CTS_HMAC_SHA1_96})
	writeKeytab(t, path, grown...)
	mustToken(t, c, testSPN)
	if n := f.logins(); n != 2 {
		t.Fatalf("logins = %d, want 2 (login again after a keytab change)", n)
	}
	if !destroyed(f.client(0)) {
		t.Error("the client of the old keytab was not destroyed")
	}
	if got, want := len(f.client(1).Credentials.Keytab().Entries), 3*256+1; got != want {
		t.Errorf("reloaded keytab has %d entries, want %d (with the kvno workaround)", got, want)
	}
	if !strings.Contains(logs.String(), "Keytab changed") {
		t.Errorf("the reload was not logged; log:\n%s", logs)
	}
	if n := strings.Count(logs.String(), "kvno workaround"); n != 1 {
		t.Errorf("kvno workaround logged %d times, want 1", n)
	}

	writeFile(t, path, []byte("garbage"))
	if _, err := c.Token(t.Context(), testSPN); err == nil || !strings.Contains(err.Error(), "not a keytab file") {
		t.Fatalf("Token() with a broken keytab error = %v", err)
	}
	writeKeytab(t, path, entries(0)...)
	mustToken(t, c, testSPN)
	if n := f.logins(); n != 3 {
		t.Errorf("logins = %d, want 3", n)
	}
}

func TestRefresh(t *testing.T) {
	grown := append(entries(3), ktEntry{"HTTP/other.corp.example", testRealm, 3, etypeID.AES256_CTS_HMAC_SHA1_96})
	tests := []struct {
		name       string
		change     func(t *testing.T, path string)
		wantReload bool
		wantErr    string
	}{
		{name: "unchanged", change: func(*testing.T, string) {}},
		{
			name:       "rewritten",
			change:     func(t *testing.T, path string) { writeKeytab(t, path, grown...) },
			wantReload: true,
		},
		{
			name: "touched",
			change: func(t *testing.T, path string) {
				mtime := time.Now().Add(time.Hour)
				if err := os.Chtimes(path, mtime, mtime); err != nil {
					t.Fatal(err)
				}
			},
			wantReload: true,
		},
		{
			name: "replaced with the same size and mtime",
			change: func(t *testing.T, path string) {
				fi, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				tmp := filepath.Join(filepath.Dir(path), "client.keytab.new")
				writeKeytab(t, tmp, entries(4)...)
				if err := os.Chtimes(tmp, fi.ModTime(), fi.ModTime()); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, path); err != nil {
					t.Fatal(err)
				}
			},
			wantReload: true,
		},
		{
			name:    "broken",
			change:  func(t *testing.T, path string) { writeFile(t, path, []byte{5, 2, 0, 0}) },
			wantErr: "malformed keytab",
		},
		{
			name: "removed",
			change: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "no such file",
		},
		{
			name: "principal removed",
			change: func(t *testing.T, path string) {
				writeKeytab(t, path, ktEntry{"HTTP/other.corp.example", testRealm, 3, etypeID.AES256_CTS_HMAC_SHA1_96})
			},
			wantErr: "has no entry for " + testPrincipal,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tempKeytab(t, entries(3)...)
			c, f, _ := newTestCredential(t, path)
			mustToken(t, c, testSPN)
			c.lock <- struct{}{}
			defer c.unlock()
			oldKT, oldClient := c.kt, c.cl

			tt.change(t, path)
			err := c.refresh()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("refresh() error = %v, want it to contain %q", err, tt.wantErr)
				}
				if c.kt != nil || c.ktInfo != nil || c.cl != nil {
					t.Error("a failed reload kept the old keytab or client")
				}
				if !destroyed(oldClient) {
					t.Error("a failed reload did not destroy the client")
				}
				// The next call tries again.
				writeKeytab(t, path, entries(3)...)
				if err := c.refresh(); err != nil || c.kt == nil {
					t.Errorf("refresh() after the fix: error = %v, keytab loaded = %v", err, c.kt != nil)
				}
				return
			}
			if err != nil {
				t.Fatalf("refresh() error = %v", err)
			}
			if reloaded := c.kt != oldKT; reloaded != tt.wantReload {
				t.Errorf("reloaded = %v, want %v", reloaded, tt.wantReload)
			}
			if tt.wantReload != (c.cl == nil) {
				t.Errorf("client kept = %v, want %v", c.cl != nil, !tt.wantReload)
			}
			if tt.wantReload != destroyed(f.client(0)) {
				t.Errorf("client destroyed = %v, want %v", destroyed(f.client(0)), tt.wantReload)
			}
		})
	}
}

func TestGokrb5LogsAtDebug(t *testing.T) {
	c, _, logs := newTestCredential(t, tempKeytab(t, entries(3)...))
	mustToken(t, c, testSPN)
	c.Reset()
	mustToken(t, c, testSPN) // destroys the old client, which gokrb5 logs

	var line string
	for l := range strings.Lines(logs.String()) {
		if strings.Contains(l, "client destroyed") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("gokrb5's message is missing; log:\n%s", logs)
	}
	for _, want := range []string{"level=DEBUG", `msg="client destroyed"`, "principal=" + testPrincipal} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q does not contain %q", line, want)
		}
	}
}
