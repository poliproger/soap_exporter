// Package web serves the exporter's HTTP endpoints (plan §8).
package web

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/version"
	toolkitweb "github.com/prometheus/exporter-toolkit/web"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/redact"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/state"
)

// App is what the handlers need from the application; *app.App implements it.
type App interface {
	Reload() error
	Config() *config.Config
	Store() *state.Store
	Ready() bool
	ProbeNow(ctx context.Context, target string) (result.Result, error)
}

// Options configure the handler.
type Options struct {
	App      App
	Gatherer prometheus.Gatherer
	// LogLevel is changed by PUT /-/log-level.
	LogLevel *promslog.Level
	// EnableLifecycle enables POST /-/reload, PUT /-/log-level and POST /debug/probe.
	EnableLifecycle bool
	// KerberosBackend is the name of the active Kerberos backend, shown on the landing page.
	KerberosBackend string
	Logger          *slog.Logger
}

// maxLogLevelBody limits the request body of PUT /-/log-level.
const maxLogLevelBody = 256

// Content-Security-Policy of the landing page, whose exporter-toolkit template has an
// inline style element.
const landingCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; " +
	"form-action 'none'; frame-ancestors 'none'"

// NewHandler returns the handler for all endpoints:
//
//	GET      /                     landing page (exporter-toolkit) with links to the endpoints
//	GET      /metrics              Gatherer
//	GET      /-/healthy            200 "Healthy"
//	GET      /-/ready              200 "Ready" if App.Ready, else 503
//	POST     /-/reload             App.Reload; 200, or 500 with the error (lifecycle)
//	GET, PUT /-/log-level          read / set the level (PUT needs lifecycle)
//	GET      /config               App.Config().Redacted() as text/plain YAML
//	GET      /debug/probes         recent results per target (HTML, ?format=json, ?target=<name>)
//	POST     /debug/probe?target=  App.ProbeNow; full report (HTML, ?format=json) (lifecycle);
//	                               404 unknown target, 429 rate limited
//
// Lifecycle endpoints answer 403 when EnableLifecycle is false. Wrong methods answer 405.
// Every page escapes target-controlled text (bodies, headers, messages). Values of
// Authorization, Proxy-Authorization, Cookie and Set-Cookie and authentication tokens are
// redacted wherever they are rendered: response headers (redact.HeaderValue) and the
// targets' request headers in /config. The messages of header checks come redacted from
// check.Evaluate.
//
// Unsafe cross-origin browser requests (CSRF against the lifecycle endpoints) are rejected
// with 403 by http.CrossOriginProtection; requests without browser headers, such as curl's,
// are not affected.
func NewHandler(opts Options) (http.Handler, error) {
	switch {
	case opts.App == nil:
		return nil, errors.New("web: Options.App is required")
	case opts.Gatherer == nil:
		return nil, errors.New("web: Options.Gatherer is required")
	case opts.LogLevel == nil:
		return nil, errors.New("web: Options.LogLevel is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = promslog.NewNopLogger()
	}
	landing, err := newLandingPage(opts.KerberosBackend)
	if err != nil {
		return nil, fmt.Errorf("web: creating the landing page: %w", err)
	}

	h := &handler{
		app:       opts.App,
		level:     opts.LogLevel,
		lifecycle: opts.EnableLifecycle,
		logger:    logger,
	}
	// Patterns with a method answer other methods with 405 and an Allow header; GET
	// patterns also match HEAD.
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", withSecurityHeaders(landing, landingCSP))
	mux.Handle("GET /metrics", promhttp.HandlerFor(opts.Gatherer, promhttp.HandlerOpts{
		ErrorLog:      promhttpLogger{logger},
		ErrorHandling: promhttp.ContinueOnError,
	}))
	mux.HandleFunc("GET /-/healthy", healthy)
	mux.HandleFunc("GET /-/ready", h.ready)
	mux.HandleFunc("POST /-/reload", h.requireLifecycle(h.reload))
	mux.HandleFunc("GET /-/log-level", h.getLogLevel)
	mux.HandleFunc("PUT /-/log-level", h.requireLifecycle(h.setLogLevel))
	mux.HandleFunc("GET /config", h.config)
	mux.HandleFunc("GET /debug/probes", h.probes)
	mux.HandleFunc("POST /debug/probe", h.requireLifecycle(h.probe))

	return withNoSniff(http.NewCrossOriginProtection().Handler(mux)), nil
}

type handler struct {
	app       App
	level     *promslog.Level
	lifecycle bool
	logger    *slog.Logger
}

func newLandingPage(kerberosBackend string) (http.Handler, error) {
	description := "Probes SOAP services and exposes the results as Prometheus metrics"
	if kerberosBackend != "" {
		description += " (Kerberos backend: " + kerberosBackend + ")"
	}
	// The toolkit renders the page with text/template, so values are escaped here.
	return toolkitweb.NewLandingPage(toolkitweb.LandingConfig{
		Name:        "soap_exporter",
		Description: html.EscapeString(description),
		Version:     html.EscapeString(version.Info()),
		Profiling:   "false",
		Links: []toolkitweb.LandingLinks{
			{Address: "/metrics", Text: "Metrics"},
			{Address: "/config", Text: "Configuration", Description: "effective configuration, secrets redacted"},
			{Address: "/debug/probes", Text: "Probe history", Description: "recent results per target"},
			{Address: "/-/healthy", Text: "Health"},
			{Address: "/-/ready", Text: "Readiness"},
		},
	})
}

func (h *handler) requireLifecycle(next http.HandlerFunc) http.HandlerFunc {
	if h.lifecycle {
		return next
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Lifecycle endpoints are disabled; start the exporter with --web.enable-lifecycle",
			http.StatusForbidden)
	}
}

func healthy(w http.ResponseWriter, _ *http.Request) {
	writeText(w, http.StatusOK, "Healthy\n")
}

func (h *handler) ready(w http.ResponseWriter, _ *http.Request) {
	if !h.app.Ready() {
		writeText(w, http.StatusServiceUnavailable, "Not ready\n")
		return
	}
	writeText(w, http.StatusOK, "Ready\n")
}

func (h *handler) reload(w http.ResponseWriter, _ *http.Request) {
	if err := h.app.Reload(); err != nil {
		http.Error(w, "Failed to reload the configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *handler) getLogLevel(w http.ResponseWriter, _ *http.Request) {
	writeText(w, http.StatusOK, h.level.String()+"\n")
}

// setLogLevel takes the level from ?level= or from the request body, which is either the
// bare level or a form with a level field (curl -d level=debug).
func (h *handler) setLogLevel(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	if level == "" {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLogLevelBody))
		if err != nil {
			if maxErr, ok := errors.AsType[*http.MaxBytesError](err); ok {
				http.Error(w, fmt.Sprintf("Request body larger than %d bytes", maxErr.Limit),
					http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Reading the request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		level = strings.TrimSpace(string(body))
		if form, err := url.ParseQuery(level); err == nil && form.Has("level") {
			level = strings.TrimSpace(form.Get("level"))
		}
	}
	if level == "" {
		http.Error(w, "Missing log level: send it as the request body or as ?level=", http.StatusBadRequest)
		return
	}

	requested := promslog.NewLevel()
	if err := requested.Set(level); err != nil {
		http.Error(w, fmt.Sprintf("Unknown log level %q, want one of %s", level,
			strings.Join(promslog.LevelFlagOptions, ", ")), http.StatusBadRequest)
		return
	}
	if previous, current := h.level.Level(), requested.Level(); current != previous {
		// Log while the more verbose of the two levels is in effect, and at a level it lets
		// through, so that every change shows up, e.g. also one from warn to error.
		logLevel := max(slog.LevelInfo, min(previous, current))
		attrs := []any{"from", h.level.String(), "to", requested.String()}
		if current > previous {
			h.logger.Log(r.Context(), logLevel, "Log level changed", attrs...)
			_ = h.level.Set(requested.String())
		} else {
			_ = h.level.Set(requested.String())
			h.logger.Log(r.Context(), logLevel, "Log level changed", attrs...)
		}
	}
	writeText(w, http.StatusOK, requested.String()+"\n")
}

func (h *handler) config(w http.ResponseWriter, _ *http.Request) {
	cfg := h.app.Config()
	if cfg == nil {
		http.Error(w, "No configuration loaded yet", http.StatusServiceUnavailable)
		return
	}
	out, err := redactRequestHeaders(cfg).Redacted()
	if err != nil {
		h.logger.Error("Rendering the configuration failed", "err", err)
		http.Error(w, "Rendering the configuration failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out)
}

// redactRequestHeaders returns cfg with the values of credential headers in the targets'
// headers replaced by "<secret>", as Redacted marshals secrets. Plan §5.2 puts secret
// headers into http_headers, but config rejects only Authorization in headers, so
// Proxy-Authorization or Cookie could otherwise show in clear text. cfg is not modified.
func redactRequestHeaders(cfg *config.Config) *config.Config {
	out := *cfg
	out.Targets = slices.Clone(cfg.Targets)
	for i, t := range out.Targets {
		var headers map[string]string
		for name := range t.Headers {
			if redact.SecretHeader(name) {
				if headers == nil {
					headers = maps.Clone(t.Headers)
				}
				headers[name] = "<secret>"
			}
		}
		if headers != nil {
			redactedTarget := *t
			redactedTarget.Headers = headers
			out.Targets[i] = &redactedTarget
		}
	}
	return &out
}

func writeText(w http.ResponseWriter, code int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, text)
}

func withNoSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders sets the headers of setSecurityHeaders for a handler that sets its
// own Content-Type.
func withSecurityHeaders(next http.Handler, csp string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header(), csp)
		next.ServeHTTP(w, r)
	})
}

// setSecurityHeaders sets the headers every HTML page gets besides X-Content-Type-Options,
// which withNoSniff sets on all responses.
func setSecurityHeaders(h http.Header, csp string) {
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	// Not no-referrer: under it browsers send "Origin: null" with the POST of the "Probe now"
	// form, and over plain HTTP to a host other than localhost, where they send no
	// Sec-Fetch-Site, CrossOriginProtection rejects that. same-origin keeps the Origin of
	// same-origin requests and sends no referrer to other origins.
	h.Set("Referrer-Policy", "same-origin")
}

// promhttpLogger adapts slog to promhttp.Logger. promhttp logs a description followed by
// the error, e.g. Println("error gathering metrics:", err).
type promhttpLogger struct {
	logger *slog.Logger
}

func (l promhttpLogger) Println(v ...any) {
	if n := len(v); n > 1 {
		if err, ok := v[n-1].(error); ok {
			msg := strings.TrimRight(fmt.Sprintln(v[:n-1]...), ": \n")
			l.logger.Error(msg, "err", err)
			return
		}
	}
	l.logger.Error(strings.TrimSuffix(fmt.Sprintln(v...), "\n"))
}
