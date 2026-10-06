// Package app wires configuration, Kerberos credentials, probers, the scheduler and the
// state store together, and implements (re)loading and on-demand probes (plan §5, §7, §8).
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/poliproger/soap_exporter/internal/collector"
	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/kerberos"
	"github.com/poliproger/soap_exporter/internal/prober"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/scheduler"
	"github.com/poliproger/soap_exporter/internal/state"
)

// Errors returned by ProbeNow.
var (
	ErrUnknownTarget = errors.New("unknown target")
	ErrRateLimited   = errors.New("too many on-demand probes for this target, try again later")
)

// errStopped is returned by loads and ProbeNow once Stop has begun.
var errStopped = errors.New("the exporter is shutting down")

// defaultDebugProbeInterval is the default of Options.DebugProbeInterval.
const defaultDebugProbeInterval = 5 * time.Second

// Options configure an App.
type Options struct {
	// ConfigFile is the path of the exporter configuration.
	ConfigFile string
	// NewBackend creates the Kerberos backend. It is called on the first load of a
	// configuration that has Kerberos targets and, once it succeeded, never again (a reload
	// does not pick up a changed krb5.conf); a failed call is retried on the next load.
	NewBackend func() (kerberos.Backend, error)
	// UserAgent is the default User-Agent of probe requests.
	UserAgent string
	// HistoryLimit is the number of results kept per target (--history.limit).
	HistoryLimit int
	// CaptureBodies keeps body snippets in the history (--debug.capture-bodies).
	CaptureBodies bool
	// DebugProbeInterval is the minimum time between two on-demand probes of one target;
	// default 5s.
	DebugProbeInterval time.Duration
	// Registerer receives the target collector and the reload metrics
	// (soap_exporter_config_last_reload_successful and
	// soap_exporter_config_last_reload_success_timestamp_seconds).
	Registerer prometheus.Registerer
	Logger     *slog.Logger
}

// App is safe for concurrent use.
type App struct {
	opts       Options
	logger     *slog.Logger
	store      *state.Store
	sched      *scheduler.Scheduler
	reloadOK   prometheus.Gauge
	reloadTime prometheus.Gauge
	// now is replaced in tests.
	now func() time.Time
	// stopping is set by Stop, under mu; loads and on-demand probes fail from then on.
	stopping atomic.Bool
	// ctx is cancelled by Stop. On-demand probes run under it as well as under their
	// caller's context, and probes counts them, so that Stop can wait for them.
	ctx    context.Context
	cancel context.CancelFunc
	probes sync.WaitGroup

	// loadMu serializes loads and the end of Stop; it guards builder.
	loadMu  sync.Mutex
	builder *builder

	// mu guards the fields below. It is held only briefly, never across a load.
	mu        sync.Mutex
	cfg       *config.Config
	names     map[string]struct{}  // target names of cfg
	lastProbe map[string]time.Time // start of the last accepted on-demand probe by target
}

// New creates an App and registers its collectors. It does not load the configuration.
func New(opts Options) (*App, error) {
	if opts.DebugProbeInterval <= 0 {
		opts.DebugProbeInterval = defaultDebugProbeInterval
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	store := state.New(opts.HistoryLimit, opts.CaptureBodies)
	a := &App{
		opts:   opts,
		logger: logger,
		store:  store,
		// The scheduler resets the store between stopping obsolete loops and starting new
		// ones, so the app never calls SetTargets itself.
		sched: scheduler.New(store, scheduler.Options{Logger: logger, Reconcile: store.SetTargets}),
		reloadOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "soap_exporter_config_last_reload_successful",
			Help: "Whether the last configuration reload attempt was successful.",
		}),
		reloadTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "soap_exporter_config_last_reload_success_timestamp_seconds",
			Help: "Timestamp of the last successful configuration reload.",
		}),
		now:       time.Now,
		builder:   newBuilder(opts.NewBackend, prober.Options{UserAgent: opts.UserAgent, Logger: logger}),
		lastProbe: map[string]time.Time{},
	}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	// The unchecked target collector goes last: it cannot be unregistered.
	if err := register(opts.Registerer, a.reloadOK, a.reloadTime, collector.New(store)); err != nil {
		return nil, err
	}
	return a, nil
}

// register registers cs with reg (if not nil). On error, the collectors registered so far
// are unregistered again.
func register(reg prometheus.Registerer, cs ...prometheus.Collector) error {
	if reg == nil {
		return nil
	}
	for i, c := range cs {
		if err := reg.Register(c); err != nil {
			for _, done := range cs[:i] {
				reg.Unregister(done)
			}
			return fmt.Errorf("registering metrics: %w", err)
		}
	}
	return nil
}

// Start loads the configuration and starts probing. An invalid configuration is an error,
// which Start returns without logging it: the caller decides what follows.
func (a *App) Start() error {
	return a.load(false)
}

// Reload loads the configuration again. The new configuration is parsed, validated and its
// credentials and probers are built in full before anything changes; on error the old
// configuration keeps running, the reload metric drops to 0, and the error is logged and
// returned, so that callers (SIGHUP, POST /-/reload) need not log it again.
// On success unchanged targets keep their state and schedule, changed targets restart with
// fresh state and removed targets disappear (plan §9 phase 5). Concurrent calls are
// serialized.
func (a *App) Reload() error {
	return a.load(true)
}

// load is Start and Reload: a failed Start may be retried, and a Reload before Start starts.
// logFailure logs a failed load.
func (a *App) load(logFailure bool) error {
	a.loadMu.Lock()
	defer a.loadMu.Unlock()
	if a.stopping.Load() {
		return errStopped
	}

	path := a.opts.ConfigFile
	cfg, err := config.Load(path)
	if err != nil {
		return a.loadFailed(path, err, logFailure)
	}
	for _, w := range cfg.Warnings {
		a.logger.Warn("Configuration warning", "file", cfg.File, "warning", w)
	}
	jobs, keys, err := a.builder.build(cfg, a.sched.Fingerprints())
	if err != nil {
		// Close the credentials that only the rejected configuration needed.
		a.builder.retain(credentialKeys(a.Config()))
		return a.loadFailed(path, err, logFailure)
	}
	if a.stopping.Load() {
		// Stop closes the credentials once this load returns.
		closeProbers(jobs)
		return errStopped
	}

	names := make(map[string]struct{}, len(cfg.Targets))
	for _, t := range cfg.Targets {
		names[t.Name] = struct{}{}
	}
	a.mu.Lock()
	a.cfg, a.names = cfg, names
	maps.DeleteFunc(a.lastProbe, func(name string, _ time.Time) bool {
		_, ok := names[name]
		return !ok
	})
	a.mu.Unlock()

	a.sched.Apply(jobs)
	// After Apply: the loops of removed and changed targets, which may still have used a
	// dropped credential, have finished.
	a.builder.retain(keys)
	a.reloadOK.Set(1)
	a.reloadTime.Set(float64(a.now().UnixNano()) / 1e9)
	a.logger.Info("Configuration loaded", "file", cfg.File, "targets", len(cfg.Targets),
		"kerberos_credentials", len(keys))
	return nil
}

func (a *App) loadFailed(path string, err error, logFailure bool) error {
	a.reloadOK.Set(0)
	err = fmt.Errorf("config file %s: %w", path, err)
	if logFailure {
		msg := "Reloading configuration failed, the previous configuration stays in effect"
		if a.Config() == nil {
			msg = "Loading configuration failed"
		}
		a.logger.Error(msg, "err", err)
	}
	return err
}

// builder creates the Kerberos credentials and the probers of a configuration. An App keeps
// one for its lifetime; Check uses one for a single configuration, so that both accept the
// same configurations. It is not safe for concurrent use.
type builder struct {
	newBackend func() (kerberos.Backend, error)
	// newProber is replaced in tests.
	newProber func(t *config.Target, cred kerberos.Credential) (scheduler.Prober, error)
	logger    *slog.Logger
	// registry is created by the first build with Kerberos targets.
	registry *kerberos.Registry
}

func newBuilder(newBackend func() (kerberos.Backend, error), opts prober.Options) *builder {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &builder{
		newBackend: newBackend,
		newProber: func(t *config.Target, cred kerberos.Credential) (scheduler.Prober, error) {
			p, err := prober.New(t, cred, opts)
			if err != nil {
				return nil, err // not a nil *prober.Prober in a non-nil interface
			}
			return p, nil
		},
		logger: logger,
	}
}

// build returns the scheduler jobs for cfg and the credential keys cfg uses. A target whose
// name and fingerprint match an entry of running (a scheduler's Fingerprints) gets a job
// without a prober, so that its loop keeps running unchanged; every other target gets a new
// prober. On error, all errors are returned joined and the probers created so far are
// closed; the credentials are left to the caller.
func (b *builder) build(cfg *config.Config, running map[string]string) ([]scheduler.Job, []kerberos.Key, error) {
	keys := credentialKeys(cfg)
	if len(keys) > 0 && b.registry == nil {
		if err := b.initKerberos(); err != nil {
			return nil, nil, err
		}
	}

	jobs := make([]scheduler.Job, 0, len(cfg.Targets))
	failed := map[kerberos.Key]bool{}
	var errs []error
	for _, t := range cfg.Targets {
		if fp, ok := running[t.Name]; ok && fp == t.Fingerprint {
			jobs = append(jobs, scheduler.Job{Target: t})
			continue
		}
		var cred kerberos.Credential
		if t.Kerberos != nil {
			k := credentialKey(t)
			if failed[k] {
				continue // reported for the first target using it
			}
			var err error
			if cred, err = b.registry.Get(k); err != nil {
				failed[k] = true
				errs = append(errs, fmt.Errorf("target %q: kerberos: %w", t.Name, err))
				continue
			}
		}
		p, err := b.newProber(t, cred)
		if err != nil {
			errs = append(errs, fmt.Errorf("target %q: %w", t.Name, err))
			continue
		}
		jobs = append(jobs, scheduler.Job{Target: t, Prober: p})
	}
	if len(errs) > 0 {
		closeProbers(jobs)
		return nil, nil, errors.Join(errs...)
	}
	return jobs, keys, nil
}

// initKerberos creates the backend and the credential registry. A failed attempt is
// retried on the next build, so that a fixed krb5.conf is picked up by a reload.
func (b *builder) initKerberos() error {
	if b.newBackend == nil {
		return errors.New("kerberos: no backend available")
	}
	backend, err := b.newBackend()
	if err != nil {
		return fmt.Errorf("kerberos backend: %w", err)
	}
	b.registry = kerberos.NewRegistry(backend, b.logger)
	b.logger.Info("Kerberos backend initialized", "backend", backend.Name())
	return nil
}

// retain closes the credentials whose keys are not in keep.
func (b *builder) retain(keep []kerberos.Key) {
	if b.registry != nil {
		b.registry.Retain(keep)
	}
}

// close closes all credentials.
func (b *builder) close() {
	if b.registry != nil {
		b.registry.Close()
	}
}

func closeProbers(jobs []scheduler.Job) {
	for _, j := range jobs {
		if j.Prober != nil {
			j.Prober.Close()
		}
	}
}

func credentialKey(t *config.Target) kerberos.Key {
	return kerberos.Key{Principal: t.Kerberos.Principal, Keytab: t.Kerberos.Keytab}
}

// credentialKeys returns the distinct credential keys of cfg's Kerberos targets in target
// order; none for a nil cfg.
func credentialKeys(cfg *config.Config) []kerberos.Key {
	if cfg == nil {
		return nil
	}
	var keys []kerberos.Key
	seen := map[kerberos.Key]bool{}
	for _, t := range cfg.Targets {
		if t.Kerberos == nil {
			continue
		}
		if k := credentialKey(t); !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

// Config returns the configuration in effect (nil before Start).
func (a *App) Config() *config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// Store returns the state store.
func (a *App) Store() *state.Store {
	return a.store
}

// Ready reports whether a configuration is loaded and the scheduler is running.
func (a *App) Ready() bool {
	return a.Config() != nil && a.sched.Running()
}

// ProbeNow runs a probe of target immediately and returns the full result, including the
// body snippet. The result is not recorded in metrics or history. Calls for one target are
// limited to one per DebugProbeInterval (ErrRateLimited). Stop cancels the probe and waits
// for it; once Stop has begun, ProbeNow fails.
func (a *App) ProbeNow(ctx context.Context, target string) (result.Result, error) {
	p, err := a.onDemandProber(target)
	if err != nil {
		return result.Result{}, err
	}
	defer a.probes.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	return p.Probe(ctx), nil
}

// onDemandProber returns the running prober of target, starts its rate-limit window and
// adds the probe to a.probes; the caller calls a.probes.Done. A rejected call does not move
// the window.
func (a *App) onDemandProber(target string) (scheduler.Prober, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopping.Load() {
		return nil, errStopped
	}
	if _, ok := a.names[target]; !ok {
		return nil, ErrUnknownTarget
	}
	p, ok := a.sched.Prober(target)
	if !ok || p == nil {
		return nil, ErrUnknownTarget
	}
	now := a.now()
	if last, ok := a.lastProbe[target]; ok && now.Sub(last) < a.opts.DebugProbeInterval {
		return nil, ErrRateLimited
	}
	a.lastProbe[target] = now
	a.probes.Add(1)
	return p, nil
}

// Stop stops probing, cancels in-flight scheduled and on-demand probes and waits for them,
// and closes credentials. Loads and on-demand probes fail from then on.
func (a *App) Stop() {
	// Under mu, so that no on-demand probe starts once Stop waits for them.
	a.mu.Lock()
	a.stopping.Store(true)
	a.mu.Unlock()
	a.cancel()
	// The scheduler cancels its probes right away, even during a concurrent load.
	a.sched.Stop()
	a.probes.Wait()
	// A load in progress may still create credentials; they are closed once it returns.
	a.loadMu.Lock()
	defer a.loadMu.Unlock()
	a.builder.close()
}

// Check validates the configuration file for --config.check: the configuration is loaded
// and, if it has Kerberos targets, the backend is created and every credential is built
// (keytabs parsed, no KDC contact); then every target's prober is built as by Start (TLS
// files read, no network contact), so that Check accepts exactly the configurations that
// Start accepts. It returns the loaded configuration for its warnings, also when a later
// check fails.
func Check(configFile string, newBackend func() (kerberos.Backend, error)) (*config.Config, error) {
	cfg, err := config.Load(configFile)
	if err != nil {
		return nil, fmt.Errorf("config file %s: %w", configFile, err)
	}
	b := newBuilder(newBackend, prober.Options{})
	jobs, _, err := b.build(cfg, nil)
	closeProbers(jobs)
	b.close()
	if err != nil {
		return cfg, fmt.Errorf("config file %s: %w", configFile, err)
	}
	return cfg, nil
}
