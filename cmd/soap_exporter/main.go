// Command soap_exporter probes SOAP services on a schedule and exposes the results as
// Prometheus metrics.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/version"
	toolkitweb "github.com/prometheus/exporter-toolkit/web"

	"github.com/poliproger/soap_exporter/internal/app"
	"github.com/poliproger/soap_exporter/internal/web"
)

const (
	// readHeaderTimeout bounds the time a client may take to send the request headers.
	readHeaderTimeout = 10 * time.Second
	// readTimeout bounds the time a client may take to send a whole request. It does not
	// limit handlers, which wait as long as an on-demand probe runs.
	readTimeout = time.Minute
	// idleTimeout bounds the wait of a keep-alive connection for the next request; it is
	// longer than common scrape intervals.
	idleTimeout = 2 * time.Minute
	// shutdownTimeout bounds the wait for in-flight requests on shutdown.
	shutdownTimeout = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Once shutdown has begun, a second signal ends the process at once.
	context.AfterFunc(ctx, stop)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run runs the exporter with the command-line arguments args and returns the exit code.
// Cancelling ctx shuts the exporter down gracefully; SIGHUP reloads the configuration.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, code, ok := parseFlags(args, stdout, stderr)
	if !ok {
		return code
	}
	o.log.Writer = stderr
	logger := promslog.New(&o.log)
	if o.configCheck {
		return checkConfig(o, logger, stdout, stderr)
	}
	return serve(ctx, o, logger)
}

// checkConfig implements --config.check. Warnings and the verdict go to stdout, errors to
// stderr.
func checkConfig(o *options, logger *slog.Logger, stdout, stderr io.Writer) int {
	cfg, err := app.Check(o.configFile, o.newKerberosBackend(logger))
	if cfg != nil {
		for _, w := range cfg.Warnings {
			fmt.Fprintf(stdout, "WARNING: %s\n", w)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "FAILED: %s\n", indent(err.Error()))
		return 1
	}
	if path := *o.web.WebConfigFile; path != "" {
		if err := toolkitweb.Validate(path); err != nil {
			fmt.Fprintf(stderr, "FAILED: web config file %s: %s\n", path, indent(err.Error()))
			return 1
		}
	}
	targets := "targets"
	if len(cfg.Targets) == 1 {
		targets = "target"
	}
	fmt.Fprintf(stdout, "SUCCESS: config file %s is valid, %d %s\n", o.configFile, len(cfg.Targets), targets)
	return 0
}

// indent indents the continuation lines of a multi-line message, e.g. joined errors.
func indent(msg string) string {
	return strings.ReplaceAll(msg, "\n", "\n  ")
}

// serve runs the exporter until ctx is cancelled.
func serve(ctx context.Context, o *options, logger *slog.Logger) int {
	logger.Info("Starting soap_exporter", "version", version.Info())
	logger.Info("Build context", "build_context", version.BuildContext())

	// The server reads the file only once it listens, after the probes have started.
	if err := toolkitweb.Validate(*o.web.WebConfigFile); err != nil {
		logger.Error("Exiting: the web configuration file is invalid", "file", *o.web.WebConfigFile, "err", err)
		return 1
	}

	// Before the first load: the default action of SIGHUP ends the process.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		versioncollector.NewCollector("soap_exporter"),
	)
	a, err := app.New(app.Options{
		ConfigFile:    o.configFile,
		NewBackend:    o.newKerberosBackend(logger),
		UserAgent:     userAgent(),
		HistoryLimit:  o.historyLimit,
		CaptureBodies: o.captureBodies,
		Registerer:    reg,
		Logger:        logger,
	})
	if err != nil {
		logger.Error("Creating the exporter failed", "err", err)
		return 1
	}
	// Runs last: in-flight requests have been served or cut off by then.
	defer a.Stop()
	if err := a.Start(); err != nil {
		logger.Error("Exiting: the configuration could not be loaded", "err", err)
		return 1
	}

	handler, err := web.NewHandler(web.Options{
		App:             a,
		Gatherer:        reg,
		LogLevel:        o.log.Level,
		EnableLifecycle: o.enableLifecycle,
		KerberosBackend: o.kerberosBackend,
		Logger:          logger,
	})
	if err != nil {
		logger.Error("Creating the HTTP handler failed", "err", err)
		return 1
	}
	srv := newServer(ctx, handler, logger)
	served := make(chan error, 1)
	go func() { served <- toolkitweb.ListenAndServe(srv, o.web, logger) }()

	for {
		select {
		case <-hup:
			logger.Info("Reloading configuration", "signal", "SIGHUP")
			// Reload logs a failure itself.
			_ = a.Reload()
		case err := <-served:
			logger.Error("HTTP server failed", "err", err)
			return 1
		case <-ctx.Done():
			return shutdown(srv, served, logger)
		}
	}
}

// newServer returns the HTTP server of handler. The contexts of its requests end with ctx,
// so that an on-demand probe in flight does not hold up the shutdown, which begins then.
// There is no WriteTimeout: it would cut off the report of a long on-demand probe.
func newServer(ctx context.Context, handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
}

// shutdown stops srv, whose ListenAndServe reports to served.
func shutdown(srv *http.Server, served <-chan error, logger *slog.Logger) int {
	logger.Info("Shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Warn("Requests still running after the shutdown timeout, closing their connections",
			"timeout", shutdownTimeout, "err", err)
		_ = srv.Close()
	}
	// The server may have failed before it was shut down.
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTP server failed", "err", err)
		return 1
	}
	return 0
}

// userAgent is the default User-Agent of probe requests, "soap_exporter/<version>".
func userAgent() string {
	if version.Version == "" {
		// Built without version information (plain go build).
		return "soap_exporter"
	}
	return version.ComponentUserAgent("soap_exporter")
}
