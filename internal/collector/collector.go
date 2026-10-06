// Package collector renders the state store into the target metrics of plan §7.
package collector

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/poliproger/soap_exporter/internal/config"
	"github.com/poliproger/soap_exporter/internal/result"
	"github.com/poliproger/soap_exporter/internal/state"
)

// Collector is an unchecked prometheus.Collector (Describe sends nothing) that renders one
// consistent state.Store snapshot per scrape. Every target series carries `target` plus the
// union of all targets' user label names; a target without a label gets an empty value.
type Collector struct {
	store *state.Store
}

var _ prometheus.Collector = (*Collector)(nil)

// New returns a collector for store.
func New(store *state.Store) *Collector {
	return &Collector{store: store}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	snap := c.store.Snapshot()
	if len(snap) == 0 {
		return
	}
	userLabels := userLabelNames(snap)
	d := newDescs(append([]string{"target"}, userLabels...))
	if slices.Contains(userLabels, bucketLabel) {
		// Neither NewConstHistogram nor Gather checks the bucket label against the variable
		// labels, so every bucket would carry "le" twice and Prometheus would reject the whole
		// scrape. Report the histogram instead; on the other metrics "le" is an ordinary label.
		ch <- prometheus.NewInvalidMetric(d.duration, bucketLabelClash(snap))
		d.duration = nil
	}
	for i := range snap {
		collectTarget(ch, d, &snap[i], userLabels)
	}
}

// bucketLabel is the label of histogram buckets; a user label of that name cannot go on the
// duration histogram.
const bucketLabel = "le"

// descs are the metric descriptors of one scrape; their label names depend on the union of
// user labels. duration is nil when the histogram cannot be exposed (see bucketLabel).
type descs struct {
	info, interval              *prometheus.Desc
	probes, duration            *prometheus.Desc
	success, failureReason      *prometheus.Desc
	lastTimestamp, httpStatus   *prometheus.Desc
	responseSize, phaseDuration *prometheus.Desc
	tlsVersion, tlsCertExpiry   *prometheus.Desc
}

func newDescs(base []string) *descs {
	desc := func(name, help string, extra ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, append(slices.Clip(base), extra...), nil)
	}
	return &descs{
		info: desc("soap_target_info",
			"Static information about the probed target; always 1.",
			"url", "soap_version", "soap_action", "auth"),
		interval: desc("soap_probe_interval_seconds",
			"Configured probe interval in seconds."),
		probes: desc("soap_probes_total",
			"Probes by result: success or the failure reason.",
			"result"),
		duration: desc("soap_probe_duration_seconds",
			"Total duration of probes that received an HTTP response."),
		success: desc("soap_probe_success",
			"Whether the last probe passed all checks."),
		failureReason: desc("soap_probe_failure_reason",
			"Failure reason of the last probe; absent while the target is healthy.",
			"reason"),
		lastTimestamp: desc("soap_probe_last_timestamp_seconds",
			"Unix time when the last probe finished."),
		httpStatus: desc("soap_probe_http_status_code",
			"HTTP status code of the last probe, 0 if there was no response."),
		responseSize: desc("soap_probe_response_size_bytes",
			"Response body size of the last probe in bytes."),
		phaseDuration: desc("soap_probe_phase_duration_seconds",
			"Duration of each phase of the last probe.",
			"phase"),
		tlsVersion: desc("soap_probe_tls_version_info",
			"TLS version negotiated by the last probe.",
			"version"),
		tlsCertExpiry: desc("soap_probe_tls_cert_expiry_timestamp_seconds",
			"Earliest NotAfter in the server certificate chain of the last probe, as a Unix time."),
	}
}

// userLabelNames returns the sorted union of the targets' user label names.
func userLabelNames(snap []state.TargetState) []string {
	set := map[string]struct{}{}
	for _, ts := range snap {
		for name := range ts.Target.Labels {
			set[name] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// bucketLabelClash returns the error that replaces the duration histogram when a user label
// is named like the bucket label.
func bucketLabelClash(snap []state.TargetState) error {
	var targets []string
	for _, ts := range snap {
		if _, ok := ts.Target.Labels[bucketLabel]; ok {
			targets = append(targets, ts.Target.Name)
		}
	}
	return fmt.Errorf("targets %q: user label %q clashes with the histogram bucket label", targets, bucketLabel)
}

func collectTarget(ch chan<- prometheus.Metric, d *descs, ts *state.TargetState, userLabels []string) {
	t := ts.Target
	base := make([]string, 0, 1+len(userLabels))
	base = append(base, t.Name)
	for _, name := range userLabels {
		base = append(base, t.Labels[name])
	}
	gauge := func(desc *prometheus.Desc, v float64, extra ...string) {
		send(ch, desc, prometheus.GaugeValue, v, base, extra...)
	}

	gauge(d.info, 1, redactedURL(t), t.SOAP.Version.String(), t.SOAP.Action, t.AuthType())
	gauge(d.interval, time.Duration(t.Interval).Seconds())

	for _, label := range resultLabels(ts.Results) {
		send(ch, d.probes, prometheus.CounterValue, float64(ts.Results[label]), base, label)
	}
	if d.duration != nil {
		h := ts.Histogram
		if m, err := prometheus.NewConstHistogram(d.duration, h.Count, h.Sum, h.Buckets, base...); err != nil {
			ch <- prometheus.NewInvalidMetric(d.duration, err)
		} else {
			ch <- m
		}
	}

	last := ts.Last
	if last == nil {
		return
	}
	gauge(d.success, boolToFloat(last.Success))
	if !last.Success {
		reason := last.Reason
		if reason == result.ReasonNone {
			// Counted as internal by the store as well.
			reason = result.ReasonInternal
		}
		gauge(d.failureReason, 1, string(reason))
	}
	gauge(d.lastTimestamp, unixSeconds(last.End))
	gauge(d.httpStatus, float64(last.HTTPStatus))
	gauge(d.responseSize, float64(last.BodySize))
	for phase, dur := range last.Phases {
		gauge(d.phaseDuration, dur.Seconds(), string(phase))
	}
	if last.TLS != nil && len(last.TLS.Chain) > 0 {
		gauge(d.tlsVersion, 1, last.TLS.Version)
		gauge(d.tlsCertExpiry, unixSeconds(last.TLS.EarliestExpiry()))
	}
}

// send emits one const metric; label errors become an invalid metric that fails the scrape
// visibly instead of panicking.
func send(ch chan<- prometheus.Metric, desc *prometheus.Desc, vt prometheus.ValueType, v float64, base []string, extra ...string) {
	m, err := prometheus.NewConstMetric(desc, vt, v, append(slices.Clip(base), extra...)...)
	if err != nil {
		m = prometheus.NewInvalidMetric(desc, err)
	}
	ch <- m
}

// resultLabels returns the `result` label values of soap_probes_total: success and every
// failure reason, so that the first failure is a counter increase rather than a new
// series, followed by any other counted values.
func resultLabels(counts map[string]uint64) []string {
	labels := make([]string, 0, 1+len(result.AllReasons))
	labels = append(labels, result.ResultSuccess)
	for _, r := range result.AllReasons {
		labels = append(labels, string(r))
	}
	var extra []string
	for label := range counts {
		if !slices.Contains(labels, label) {
			extra = append(extra, label)
		}
	}
	slices.Sort(extra)
	return append(labels, extra...)
}

// redactedURL returns the target URL with any password replaced.
func redactedURL(t *config.Target) string {
	u := t.ParsedURL
	if u == nil {
		var err error
		if u, err = url.Parse(t.URL); err != nil {
			// Validated at load; never risk exposing an unparsable URL with credentials.
			return ""
		}
	}
	return u.Redacted()
}

// unixSeconds converts t to fractional Unix seconds without the year-2262 overflow of
// UnixNano (certificates may expire as late as 9999).
func unixSeconds(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
