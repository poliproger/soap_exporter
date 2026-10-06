package web

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/poliproger/soap_exporter/internal/app"
	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/redact"
	"github.com/poliproger/soap_exporter/internal/result"
)

// retryAfterSeconds is the Retry-After of a rate-limited on-demand probe: the default
// minimum interval between two of them (app.Options.DebugProbeInterval).
const retryAfterSeconds = "5"

// Timestamp formats: JSON keeps full precision, HTML shows milliseconds. Both are RFC 3339.
const (
	jsonTimeFormat = time.RFC3339Nano
	htmlTimeFormat = "2006-01-02T15:04:05.000Z07:00"
)

var (
	//go:embed debug.html
	debugHTML string
	//go:embed debug.css
	debugCSS string

	debugTemplates = template.Must(template.New("debug").Funcs(template.FuncMap{
		"ts":       htmlTime,
		"duration": formatDuration,
		"elapsed":  func(r result.Result) string { return formatDuration(r.Duration()) },
		"phases":   orderedPhases,
		"headers":  redactedHeaderFields,
		"join":     strings.Join,
		// The stylesheet is static and trusted; debugCSP allows exactly this text.
		"stylesheet": func() template.CSS { return template.CSS(debugCSS) },
	}).Parse(debugHTML))

	// debugCSP allows nothing but the debug pages' own inline style element and forms that
	// post to /debug/probe.
	debugCSP = "default-src 'none'; style-src '" + cspHash(debugCSS) + "'; base-uri 'none'; " +
		"form-action 'self'; frame-ancestors 'none'"
)

func cspHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// probes serves GET /debug/probes.
func (h *handler) probes(w http.ResponseWriter, r *http.Request) {
	asJSON, ok := wantJSON(w, r)
	if !ok {
		return
	}
	cfg := h.app.Config()
	if cfg == nil {
		http.Error(w, "No configuration loaded yet", http.StatusServiceUnavailable)
		return
	}
	targets, filter := cfg.Targets, ""
	if q := r.URL.Query(); q.Has("target") {
		filter = q.Get("target")
		t := findTarget(cfg, filter)
		if t == nil {
			http.Error(w, fmt.Sprintf("Unknown target %q", filter), http.StatusNotFound)
			return
		}
		targets = []*config.Target{t}
	}

	store := h.app.Store()
	histories := make([]targetHistory, len(targets))
	for i, t := range targets {
		// A target that the store does not know yet (during a reload) has no history.
		results, _ := store.History(t.Name)
		histories[i] = targetHistory{Target: t, URL: targetURL(t), Results: results}
	}

	w.Header().Set("Cache-Control", "no-store")
	if asJSON {
		doc := probesJSON{Targets: make([]targetHistoryJSON, len(histories))}
		for i, th := range histories {
			doc.Targets[i] = targetHistoryJSON{
				targetJSON: newTargetJSON(th.Target.Name, th.Target),
				Results:    make([]resultJSON, len(th.Results)),
			}
			for j := range th.Results {
				doc.Targets[i].Results[j] = newResultJSON(&th.Results[j])
			}
		}
		h.writeJSON(w, doc)
		return
	}
	h.writeHTML(w, "probes", probesPage{
		Title:           "Probe history - soap_exporter",
		Lifecycle:       h.lifecycle,
		HistoryDisabled: store.HistoryLimit() == 0,
		Filter:          filter,
		Targets:         histories,
	})
}

// probe serves POST /debug/probe?target=<name>.
func (h *handler) probe(w http.ResponseWriter, r *http.Request) {
	asJSON, ok := wantJSON(w, r)
	if !ok {
		return
	}
	name := r.URL.Query().Get("target")
	if name == "" {
		http.Error(w, "Missing target: use /debug/probe?target=<name>", http.StatusBadRequest)
		return
	}

	res, err := h.app.ProbeNow(r.Context(), name)
	switch {
	case errors.Is(err, app.ErrUnknownTarget):
		http.Error(w, fmt.Sprintf("Unknown target %q", name), http.StatusNotFound)
		return
	case errors.Is(err, app.ErrRateLimited):
		w.Header().Set("Retry-After", retryAfterSeconds)
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	case err != nil:
		h.logger.Warn("On-demand probe failed", "target", name, "err", err)
		http.Error(w, "Probe failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.logger.Debug("On-demand probe finished", "target", name, "success", res.Success,
		"reason", res.Reason)

	// The target may have been removed by a reload in the meantime.
	var target *config.Target
	if cfg := h.app.Config(); cfg != nil {
		target = findTarget(cfg, name)
	}

	w.Header().Set("Cache-Control", "no-store")
	if asJSON {
		h.writeJSON(w, reportJSON{Target: newTargetJSON(name, target), Result: newResultJSON(&res)})
		return
	}
	h.writeHTML(w, "report", reportPage{
		Title:  "Probe of " + name + " - soap_exporter",
		Name:   name,
		Target: target,
		URL:    targetURL(target),
		Result: res,
	})
}

// wantJSON reports whether ?format= asks for JSON; ok is false after an unknown format was
// answered with 400.
func wantJSON(w http.ResponseWriter, r *http.Request) (asJSON, ok bool) {
	switch f := r.URL.Query().Get("format"); f {
	case "", "html":
		return false, true
	case "json":
		return true, true
	default:
		http.Error(w, fmt.Sprintf("Unknown format %q, want html or json", f), http.StatusBadRequest)
		return false, false
	}
}

func findTarget(cfg *config.Config, name string) *config.Target {
	for _, t := range cfg.Targets {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// targetURL returns the target URL with any password replaced; config rejects user info
// in target URLs, so this is only a safety net.
func targetURL(t *config.Target) string {
	switch {
	case t == nil:
		return ""
	case t.ParsedURL != nil:
		return t.ParsedURL.Redacted()
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return u.Redacted()
}

// writeHTML renders a page into a buffer first, so that a template error becomes a clean 500.
func (h *handler) writeHTML(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := debugTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.Error("Rendering a debug page failed", "page", name, "err", err)
		http.Error(w, "Rendering the page failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setSecurityHeaders(w.Header(), debugCSP)
	_, _ = w.Write(buf.Bytes())
}

// writeJSON writes v indented. The encoder escapes <, > and & as \u003c etc., so the
// document is inert even if a browser were to sniff it.
func (h *handler) writeJSON(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		h.logger.Error("Encoding a debug report failed", "err", err)
		http.Error(w, "Encoding the report failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
}

// HTML views. Templates get result.Result values as they are; html/template escapes every
// value, and the funcs below take care of ordering, formatting and redaction.

type probesPage struct {
	Title     string
	Lifecycle bool
	// HistoryDisabled is set with --history.limit=0: no target has results to show.
	HistoryDisabled bool
	// Filter is the ?target= value, empty for all targets.
	Filter  string
	Targets []targetHistory
}

type targetHistory struct {
	Target *config.Target
	// URL is the redacted target URL.
	URL string
	// Results are newest first.
	Results []result.Result
}

type reportPage struct {
	Title string
	Name  string
	// Target is nil if the target was removed after the probe.
	Target *config.Target
	URL    string
	Result result.Result
}

type phaseDuration struct {
	Phase    result.Phase
	Duration time.Duration
}

type headerField struct {
	Name, Value string
}

// orderedPhases returns the measured phases in the order of result.AllPhases.
func orderedPhases(phases map[result.Phase]time.Duration) []phaseDuration {
	out := make([]phaseDuration, 0, len(phases))
	for _, p := range result.AllPhases {
		if d, ok := phases[p]; ok {
			out = append(out, phaseDuration{Phase: p, Duration: d})
		}
	}
	return out
}

// redactedHeaderFields returns one field per header value, sorted by name, with secrets
// redacted.
func redactedHeaderFields(h http.Header) []headerField {
	var out []headerField
	for _, name := range slices.Sorted(maps.Keys(h)) {
		for _, v := range h[name] {
			out = append(out, headerField{Name: name, Value: redact.HeaderValue(name, v)})
		}
	}
	return out
}

func redactedHeaders(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for name, values := range h {
		r := make([]string, len(values))
		for i, v := range values {
			r[i] = redact.HeaderValue(name, v)
		}
		out[name] = r
	}
	return out
}

func htmlTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(htmlTimeFormat)
}

func jsonTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(jsonTimeFormat)
}

// formatDuration rounds d to three or four significant digits, e.g. 1.5s, 312ms, 1.23ms, 250µs.
func formatDuration(d time.Duration) string {
	switch {
	case d >= time.Second:
		return d.Round(time.Millisecond).String()
	case d >= time.Millisecond:
		return d.Round(10 * time.Microsecond).String()
	}
	return d.Round(time.Microsecond).String()
}

// JSON views: durations are seconds, times RFC 3339 in UTC.

// probesJSON is the document of GET /debug/probes?format=json.
type probesJSON struct {
	Targets []targetHistoryJSON `json:"targets"`
}

type targetHistoryJSON struct {
	targetJSON
	// Results are newest first.
	Results []resultJSON `json:"results"`
}

// reportJSON is the document of POST /debug/probe?format=json.
type reportJSON struct {
	Target targetJSON `json:"target"`
	Result resultJSON `json:"result"`
}

type targetJSON struct {
	Name            string            `json:"name"`
	URL             string            `json:"url,omitempty"`
	SOAPVersion     string            `json:"soap_version,omitempty"`
	SOAPAction      string            `json:"soap_action,omitempty"`
	Auth            string            `json:"auth,omitempty"`
	IntervalSeconds float64           `json:"interval_seconds,omitempty"`
	TimeoutSeconds  float64           `json:"timeout_seconds,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

type resultJSON struct {
	Start           string  `json:"start"`
	End             string  `json:"end"`
	DurationSeconds float64 `json:"duration_seconds"`
	Success         bool    `json:"success"`
	Reason          string  `json:"reason"`
	Message         string  `json:"message"`
	// PhaseDurationSeconds maps each measured phase to its duration.
	PhaseDurationSeconds map[string]float64  `json:"phase_duration_seconds"`
	Checks               []checkJSON         `json:"checks"`
	GotResponse          bool                `json:"got_response"`
	HTTPStatus           int                 `json:"http_status"`
	BodySizeBytes        int64               `json:"body_size_bytes"`
	ResponseHeaders      map[string][]string `json:"response_headers,omitempty"`
	TLS                  *tlsJSON            `json:"tls,omitempty"`
	SPN                  string              `json:"spn,omitempty"`
	Charset              string              `json:"charset,omitempty"`
	Body                 string              `json:"body,omitempty"`
	BodyTruncated        bool                `json:"body_truncated,omitempty"`
}

type checkJSON struct {
	Name    string `json:"name"`
	Reason  string `json:"reason"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

type tlsJSON struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	ServerName  string `json:"server_name,omitempty"`
	// EarliestExpiry is the earliest not_after in the chain.
	EarliestExpiry string     `json:"earliest_expiry,omitempty"`
	Chain          []certJSON `json:"chain"`
}

type certJSON struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DNSNames  []string `json:"dns_names,omitempty"`
}

// newTargetJSON describes target t named name; t may be nil.
func newTargetJSON(name string, t *config.Target) targetJSON {
	v := targetJSON{Name: name}
	if t == nil {
		return v
	}
	v.URL = targetURL(t)
	v.SOAPVersion = t.SOAP.Version.String()
	v.SOAPAction = t.SOAP.Action
	v.Auth = t.AuthType()
	v.IntervalSeconds = time.Duration(t.Interval).Seconds()
	v.TimeoutSeconds = time.Duration(t.Timeout).Seconds()
	v.Labels = t.Labels
	return v
}

func newResultJSON(r *result.Result) resultJSON {
	v := resultJSON{
		Start:                jsonTime(r.Start),
		End:                  jsonTime(r.End),
		DurationSeconds:      r.Duration().Seconds(),
		Success:              r.Success,
		Reason:               string(r.Reason),
		Message:              r.Message,
		PhaseDurationSeconds: make(map[string]float64, len(r.Phases)),
		Checks:               make([]checkJSON, len(r.Checks)),
		GotResponse:          r.GotResponse,
		HTTPStatus:           r.HTTPStatus,
		BodySizeBytes:        r.BodySize,
		ResponseHeaders:      redactedHeaders(r.ResponseHeader),
		SPN:                  r.SPN,
		Charset:              r.Charset,
		Body:                 r.Body,
		BodyTruncated:        r.BodyTruncated,
	}
	for p, d := range r.Phases {
		v.PhaseDurationSeconds[string(p)] = d.Seconds()
	}
	for i, c := range r.Checks {
		v.Checks[i] = checkJSON{Name: c.Name, Reason: string(c.Reason), Passed: c.Passed, Message: c.Message}
	}
	if t := r.TLS; t != nil {
		v.TLS = &tlsJSON{
			Version:        t.Version,
			CipherSuite:    t.CipherSuite,
			ServerName:     t.ServerName,
			EarliestExpiry: jsonTime(t.EarliestExpiry()),
			Chain:          make([]certJSON, len(t.Chain)),
		}
		for i, c := range t.Chain {
			v.TLS.Chain[i] = certJSON{
				Subject:   c.Subject,
				Issuer:    c.Issuer,
				NotBefore: jsonTime(c.NotBefore),
				NotAfter:  jsonTime(c.NotAfter),
				DNSNames:  c.DNSNames,
			}
		}
	}
	return v
}
