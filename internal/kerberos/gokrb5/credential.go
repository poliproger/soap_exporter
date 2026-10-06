package gokrb5

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"golang.org/x/sync/singleflight"
)

var errClosed = errors.New("credential is closed")

// credential implements kerberos.Credential. The gokrb5 client caches service tickets and
// renews its TGT by itself; credential adds lazy login, keytab reloading, reset and
// cancellation.
type credential struct {
	name, realm string // the client principal
	path        string // the keytab
	cfg         *config.Config
	logger      *slog.Logger
	krbLogger   *log.Logger // gokrb5's own messages, at debug level

	// The calls that need a KDC; tests replace them.
	login    func(cl *client.Client) error
	newToken func(cl *client.Client, spn string) ([]byte, error)

	flight    singleflight.Group // Token calls in progress, by SPN
	stale     atomic.Bool        // set by Reset: the client is destroyed before its next use
	logins    atomic.Uint64      // login attempts so far; incremented with lock held
	done      chan struct{}      // closed by Close
	closeOnce sync.Once

	// lock serializes everything below, including the KDC exchanges that use the client; it
	// is held while it contains a value. It is a channel rather than a sync.Mutex so that
	// waiting for it ends when the credential is closed.
	lock       chan struct{}
	kt         *keytab.Keytab // nil until loaded and after a failed reload
	ktInfo     os.FileInfo    // the keytab file kt was read from
	workaround bool           // the loaded keytab needed the kvno workaround
	cl         *client.Client // logged in; nil until the next Token call
	loginErr   error          // of the last login attempt; nil if it succeeded or is outdated
}

func newCredential(cfg *config.Config, logger *slog.Logger, name, realm, path string) *credential {
	logger = logger.With("principal", name+"@"+realm, "keytab", path)
	return &credential{
		name:      name,
		realm:     realm,
		path:      path,
		cfg:       cfg,
		logger:    logger,
		krbLogger: slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
		login:     (*client.Client).Login,
		newToken:  spnegoToken,
		done:      make(chan struct{}),
		lock:      make(chan struct{}, 1),
	}
}

// spnegoToken makes an initial SPNEGO token. The client fetches the service ticket from the
// KDC, or takes it from its cache.
func spnegoToken(cl *client.Client, spn string) ([]byte, error) {
	s := spnego.SPNEGOClient(cl, spn)
	if err := s.AcquireCred(); err != nil {
		return nil, err
	}
	ct, err := s.InitSecContext()
	if err != nil {
		return nil, err
	}
	return ct.Marshal()
}

// sharedToken is the result of a Token call that concurrent callers share.
type sharedToken struct {
	token []byte
	taken atomic.Bool
}

// Token implements kerberos.Credential.
func (c *credential) Token(ctx context.Context, spn string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, canceled(ctx)
	}
	// gokrb5 takes no context, so the work runs in a goroutine, and concurrent callers for the
	// same SPN share it. The token it makes goes to one of them; the others make their own,
	// because a server with a replay cache rejects an authenticator it has already seen.
	ch := c.flight.DoChan(spn, func() (any, error) {
		token, err := c.token(spn)
		return &sharedToken{token: token}, err
	})
	var r singleflight.Result
	select {
	case r = <-ch:
	case <-ctx.Done():
		return nil, canceled(ctx)
	}
	if r.Err != nil {
		return nil, r.Err
	}
	if st := r.Val.(*sharedToken); st.taken.CompareAndSwap(false, true) {
		return st.token, nil
	}
	// The client has logged in and cached the service ticket by now, so this is quick unless
	// the state changed in between.
	type result struct {
		token []byte
		err   error
	}
	own := make(chan result, 1)
	go func() {
		token, err := c.token(spn)
		own <- result{token, err}
	}()
	select {
	case r := <-own:
		return r.token, r.err
	case <-ctx.Done():
		return nil, canceled(ctx)
	}
}

func canceled(ctx context.Context) error {
	return fmt.Errorf("gave up waiting for the KDC: %w", ctx.Err())
}

// Reset implements kerberos.Credential. It does not wait for a Token call in progress (it is
// called on the probe path): the client is destroyed before its next use instead.
func (c *credential) Reset() {
	c.stale.Store(true)
}

// Close implements kerberos.Credential. Later Token calls fail, and so do the calls waiting
// for the lock. Close does not wait for a KDC exchange in progress, which can take seconds
// per unreachable KDC: its client is destroyed when it ends.
func (c *credential) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		select {
		case c.lock <- struct{}{}:
			c.free()
		default:
			go func() {
				c.lock <- struct{}{}
				c.free()
			}()
		}
	})
	return nil
}

// free destroys the client, forgets the keytab and releases the lock.
func (c *credential) free() {
	defer c.unlock()
	c.dropClient()
	c.kt, c.ktInfo = nil, nil
}

func (c *credential) unlock() { <-c.lock }

func (c *credential) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// token makes a token for spn, logging in first if needed.
func (c *credential) token(spn string) (token []byte, err error) {
	logins := c.logins.Load()
	select {
	case c.lock <- struct{}{}:
	case <-c.done:
		return nil, errClosed
	}
	defer c.unlock()
	// This runs in its own goroutine, out of reach of the prober's panic handler, and gokrb5
	// parses what the KDC sends.
	defer func() {
		if v := recover(); v != nil {
			c.dropClient() // its state is unknown; Destroy also stops its TGT renewal
			token, err = nil, fmt.Errorf("gokrb5 panicked: %v", v)
		}
	}()
	cl, err := c.client(logins)
	if err != nil {
		return nil, err
	}
	return c.newToken(cl, spn)
}

// client returns a logged-in client for the current keytab. logins is the number of login
// attempts before the call started to wait for the lock. A failed login leaves no client;
// the calls that waited for it get its error, later calls try again. The lock must be held.
func (c *credential) client(logins uint64) (*client.Client, error) {
	if c.closed() {
		return nil, errClosed
	}
	if c.stale.Swap(false) {
		c.dropClient()
		c.loginErr = nil
	}
	if err := c.refresh(); err != nil {
		return nil, err
	}
	if c.cl != nil {
		return c.cl, nil
	}
	// With an unreachable KDC a login takes seconds per KDC. Calls for other SPNs queue
	// behind it, and each would repeat it.
	if c.loginErr != nil && c.logins.Load() != logins {
		return nil, c.loginErr
	}
	cl := client.NewWithKeytab(c.name, c.realm, c.kt, c.cfg,
		client.DisablePAFXFAST(true), client.Logger(c.krbLogger))
	err := c.login(cl)
	c.logins.Add(1)
	if err != nil {
		c.loginErr = c.loginError(err)
		return nil, c.loginErr
	}
	c.loginErr = nil
	c.logger.Debug("Kerberos login succeeded")
	c.cl = cl
	return cl, nil
}

// loginError describes a failed login.
func (c *credential) loginError(err error) error {
	err = fmt.Errorf("login as %s@%s: %w", c.name, c.realm, err)
	// gokrb5 found no key for the kvno or etype of the AS-REP. Its error has no type to
	// match, and its kvno may be one the workaround does not cover.
	if c.workaround && strings.Contains(err.Error(), "matching key not found in keytab") {
		err = fmt.Errorf("%w (the kvno workaround covers kvno 1–255)", err)
	}
	return err
}

// dropClient destroys the client, which also stops its TGT renewal. The lock must be held.
func (c *credential) dropClient() {
	if c.cl != nil {
		c.cl.Destroy()
		c.cl = nil
	}
}

// refresh reloads the keytab if the file changed since it was read; the client then logs in
// again. A failed reload keeps neither the old keytab nor the client, and the next call tries
// again. The lock must be held.
func (c *credential) refresh() error {
	if c.kt != nil {
		if fi, err := os.Stat(c.path); err == nil && !changed(c.ktInfo, fi) {
			return nil
		}
		c.logger.Info("Keytab changed, reloading it")
	}
	c.dropClient()
	c.kt, c.ktInfo, c.loginErr = nil, nil, nil
	return c.load()
}

// load reads the keytab, checks that it has keys for the principal and applies the kvno
// workaround. The lock must be held once c is shared.
func (c *credential) load() error {
	kt, fi, err := readKeytab(c.path)
	if err != nil {
		return err
	}
	idx := entriesOf(kt, strings.Split(c.name, "/"), c.realm)
	if len(idx) == 0 {
		msg := "no principals"
		if names := principals(kt); len(names) > 0 {
			msg = "only " + strings.Join(names, ", ")
		}
		return fmt.Errorf("keytab %s has no entry for %s@%s (it has %s)", c.path, c.name, c.realm, msg)
	}
	workaround := applyKVNOWorkaround(kt, idx)
	if workaround && !c.workaround {
		c.logger.Info("All keytab entries of the principal have kvno 0; " +
			"they are also used for kvno 1–255 (kvno workaround)")
	}
	c.kt, c.ktInfo, c.workaround = kt, fi, workaround
	return nil
}
