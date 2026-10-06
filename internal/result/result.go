// Package result holds the outcome of a single probe. It is a leaf package shared by the
// prober (which builds a Result), the checks (which add their outcomes), the state store,
// the collector and the web handlers.
package result

import (
	"net/http"
	"time"
)

// Reason is the machine-readable failure reason of a probe (plan §6.4). It is used as the
// value of the `reason` and `result` metric labels.
type Reason string

// Failure reasons, in the order of plan §6.4.
const (
	ReasonNone            Reason = ""
	ReasonDNS             Reason = "dns"
	ReasonConnect         Reason = "connect"
	ReasonTLS             Reason = "tls"
	ReasonTimeout         Reason = "timeout"
	ReasonAuth            Reason = "auth"
	ReasonHTTP            Reason = "http"
	ReasonBodyTooLarge    Reason = "body_too_large"
	ReasonSOAPFault       Reason = "soap_fault"
	ReasonStatus          Reason = "status"
	ReasonInvalidEnvelope Reason = "invalid_envelope"
	ReasonHeader          Reason = "header"
	ReasonRegex           Reason = "regex"
	ReasonXPath           Reason = "xpath"
	ReasonInternal        Reason = "internal"
)

// AllReasons lists every failure reason in a stable order.
var AllReasons = []Reason{
	ReasonDNS, ReasonConnect, ReasonTLS, ReasonTimeout, ReasonAuth, ReasonHTTP,
	ReasonBodyTooLarge, ReasonSOAPFault, ReasonStatus, ReasonInvalidEnvelope,
	ReasonHeader, ReasonRegex, ReasonXPath, ReasonInternal,
}

// ResultSuccess is the `result` label value of soap_probes_total for a passing probe.
const ResultSuccess = "success"

// Phase is one timed part of a probe (plan §6.2).
type Phase string

// Probe phases measured with httptrace.
const (
	PhaseResolve    Phase = "resolve"    // DNS lookup
	PhaseConnect    Phase = "connect"    // TCP connect
	PhaseTLS        Phase = "tls"        // TLS handshake
	PhaseProcessing Phase = "processing" // request written → first response byte
	PhaseTransfer   Phase = "transfer"   // first response byte → body fully read
)

// AllPhases lists every phase in a stable order.
var AllPhases = []Phase{PhaseResolve, PhaseConnect, PhaseTLS, PhaseProcessing, PhaseTransfer}

// CheckOutcome is the outcome of one response check (plan §6.4, steps 2–7).
type CheckOutcome struct {
	// Name identifies the check for humans, e.g. "soap_fault", "status",
	// "envelope", `header "Content-Type" regex`, `regex "ORA-\d{5}"`, `xpath "//t:Id"`.
	Name string `json:"name"`
	// Reason is the failure reason this check reports when it fails.
	Reason Reason `json:"reason"`
	// Passed is true if the check passed.
	Passed bool `json:"passed"`
	// Message explains the outcome, e.g. the fault text or "got 502, want [200]".
	Message string `json:"message,omitempty"`
}

// CertInfo describes one certificate of the server's chain.
type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names,omitempty"`
}

// TLSInfo is the negotiated TLS state of a probe connection.
type TLSInfo struct {
	// Version is the negotiated version as returned by tls.VersionName, e.g. "TLS 1.3".
	// It is the value of the `version` label of soap_probe_tls_version_info.
	Version     string     `json:"version"`
	CipherSuite string     `json:"cipher_suite"`
	ServerName  string     `json:"server_name,omitempty"`
	Chain       []CertInfo `json:"chain"`
}

// EarliestExpiry returns the earliest NotAfter in the chain, or the zero time if the chain
// is empty.
func (t *TLSInfo) EarliestExpiry() time.Time {
	var earliest time.Time
	if t == nil {
		return earliest
	}
	for _, c := range t.Chain {
		if earliest.IsZero() || c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
	}
	return earliest
}

// Result is the outcome of one probe of one target.
type Result struct {
	// Target is the target name (the `target` label).
	Target string `json:"target"`
	// Start and End delimit the whole probe, including Kerberos token acquisition.
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	// Phases holds the durations of the phases that happened (plan §6.2).
	Phases map[Phase]time.Duration `json:"phases,omitempty"`

	// Success is true if the probe passed all checks.
	Success bool `json:"success"`
	// Reason is the failure reason (ReasonNone on success).
	Reason Reason `json:"reason,omitempty"`
	// Message is a human-readable explanation of the failure.
	Message string `json:"message,omitempty"`

	// GotResponse is true if an HTTP response (status line and headers) was received.
	// Only such probes are observed by the duration histogram.
	GotResponse bool `json:"got_response"`
	// HTTPStatus is the response status code, 0 if there was none.
	HTTPStatus int `json:"http_status"`
	// ResponseHeader holds the response headers (nil if there was no response).
	ResponseHeader http.Header `json:"response_header,omitempty"`
	// BodySize is the number of response body bytes read (before decoding).
	BodySize int64 `json:"body_size"`
	// Charset is the character encoding used to decode the body (plan §6.3), e.g. "utf-8".
	Charset string `json:"charset,omitempty"`
	// Body is the decoded response body, truncated to BodySnippetLimit bytes.
	Body string `json:"body,omitempty"`
	// BodyTruncated is true if Body was truncated.
	BodyTruncated bool `json:"body_truncated,omitempty"`

	// TLS is the TLS state, nil for plain HTTP or if no handshake completed.
	TLS *TLSInfo `json:"tls,omitempty"`
	// SPN is the Kerberos service principal used, empty if Kerberos is not configured.
	SPN string `json:"spn,omitempty"`

	// Checks holds every check outcome in evaluation order; empty after a transport error.
	Checks []CheckOutcome `json:"checks,omitempty"`
}

// BodySnippetLimit is the maximum size of Result.Body in bytes.
const BodySnippetLimit = 64 << 10

// Duration returns End - Start.
func (r *Result) Duration() time.Duration { return r.End.Sub(r.Start) }
