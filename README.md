# soap_exporter

A Prometheus exporter that calls SOAP services on its own schedule and tells you whether each
one answers correctly, how fast, and why it fails.

soap_exporter sends a real SOAP 1.1 or 1.2 request to every configured service at the
service's own interval, checks the response (HTTP status, SOAP envelope, SOAP Fault,
headers, regular expressions, namespace-aware XPath) and serves the results of the last
probes on `/metrics`. Every failed probe gets a machine-readable reason, per-phase timings,
TLS details and a debug report.

- SOAP 1.1 and 1.2, SOAP-aware by default: an HTML error page with status 200 or a SOAP Fault
  never counts as success.
- No auth, HTTP Basic, Bearer, OAuth2, mutual TLS, and Kerberos (SPNEGO, Windows
  authentication) from a keytab, in pure Go. Kerberos keytab rotation without a restart.
- The standard Prometheus HTTP client configuration: `tls_config`, `basic_auth`, `oauth2`,
  `proxy_url`, secrets from files.
- Failure reasons (`dns`, `connect`, `tls`, `timeout`, `auth`, `soap_fault`, `status`,
  `invalid_envelope`, `xpath`, ...), phase durations (DNS, connect, TLS, processing,
  transfer) and TLS certificate expiry as metrics.
- Hot reload, strict configuration validation, health endpoints, probe history and
  on-demand probes for debugging.
- A static binary in a distroless, non-root image of about 18 MB for `linux/amd64` and
  `linux/arm64`. Default port **10057**.

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Probe semantics](#probe-semantics)
- [Metrics](#metrics)
- [HTTP endpoints](#http-endpoints)
- [Command-line flags](#command-line-flags)
- [Kerberos](#kerberos)
- [Deployment with Docker Compose](#deployment-with-docker-compose)
- [Debugging](#debugging)
- [Security](#security)
- [Building from source](#building-from-source)
- [License](#license)

## How it works

```text
config ─► scheduler ─(every interval, per target)─► probe ─► checks ─► state ─► /metrics (on scrape)
                                                      └─► probe history ─► /debug/probes
```

soap_exporter probes its targets **on its own schedule**. A scrape of `/metrics` only reads
the results of the last probes; it never calls a SOAP service. This differs from
blackbox_exporter's multi-target pattern, where Prometheus calls `/probe?target=...` and
every scrape performs a probe:

- SOAP calls can be expensive (a report, a database query behind the service), so they often
  run every 5 to 15 minutes. That does not fit the scrape model: a probe per scrape is too
  often, and a scrape interval longer than Prometheus' 5-minute lookback makes series go
  stale.
- With a highly available pair of Prometheus servers, every probe would run twice.
- Kerberos tickets, TLS state and probe history live in the exporter anyway.

Each target has its own `interval`. Prometheus scrapes the exporter like any other, at its
usual scrape interval, and `soap_probes_total` counts every probe even if a scrape misses
one. The configuration describes the targets; Prometheus has one scrape job for the
exporter.

For non-SOAP checks (TCP, ICMP, DNS, plain HTTP, WSDL availability) use
[blackbox_exporter](https://github.com/prometheus/blackbox_exporter).

## Quick start

Create `config.yml` with one target. This one calls a public demo service:

```yaml
targets:
  - name: number-conversion
    url: https://www.dataaccess.com/webservicesserver/NumberConversion.wso
    interval: 30s
    body: |
      <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <NumberToWords xmlns="http://www.dataaccess.com/webservicesserver/">
            <ubiNum>42</ubiNum>
          </NumberToWords>
        </soap:Body>
      </soap:Envelope>
    expect:
      namespaces:
        n: http://www.dataaccess.com/webservicesserver/
      xpath:
        - "starts-with(//n:NumberToWordsResult, 'forty two')"
```

### With Docker

```console
docker run --rm --name soap_exporter -p 10057:10057 -v "$PWD:/etc/soap_exporter:ro" \
  ghcr.io/poliproger/soap-exporter:latest
```

The image reads `/etc/soap_exporter/config.yml`. Images are published for every release
(`1.0.0`, `1.0`, `1`), for every commit to `main` (`latest`, `sha-<commit>`), for
`linux/amd64` and `linux/arm64`.

### With the binary

```console
go install github.com/poliproger/soap_exporter/cmd/soap_exporter@latest
soap_exporter --config.file=config.yml
```

(or [build it from source](#building-from-source)). On macOS, if your services or KDCs have
`.local` names, start it with `GODEBUG=netdns=go`
([why](docs/kerberos.md#running-the-binary-on-macos)).

### See the results

The first probe starts within ten seconds, then one every 30 seconds:

```console
$ curl -s localhost:10057/metrics | grep -E '^soap_probe_(success|http_status_code)'
soap_probe_http_status_code{target="number-conversion"} 200
soap_probe_success{target="number-conversion"} 1
```

Open <http://localhost:10057/debug/probes> for the probe history with phases, checks and
response headers. To see a failing probe, change `'forty two'` to `'forty three'` and reload
the configuration with `docker kill -s HUP soap_exporter` (or `kill -HUP` the binary):
`soap_probe_failure_reason{reason="xpath"}` appears with the next probe, and the history shows
the message `xpath "starts-with(//n:NumberToWordsResult, 'forty three')" is false`.

[`examples/`](examples/) has a complete setup: a [configuration](examples/config.yml) that uses
every soap_exporter setting and the common HTTP client settings, a
[Docker Compose stack](examples/docker-compose.yml) with Prometheus and Grafana,
[alert rules](examples/alerts.yml) and a [Grafana dashboard](examples/grafana-dashboard.json).

## Configuration

The configuration is one YAML file with optional `defaults` and a list of `targets`:

```yaml
defaults:                          # deep-merged into every target
  interval: 1m
  labels:
    team: integration
  kerberos:
    principal: monitor@CORP.EXAMPLE
    keytab: secrets/monitor.keytab # relative to this file

targets:
  - name: branches                 # the value of the target label
    url: http://core.corp.example/CoreService.asmx
    interval: 5m
    timeout: 30s
    labels:
      team: core-banking           # overrides the default
    soap:
      version: "1.1"               # "1.1" (default) or "1.2"
      action: http://tempuri.org/GetBranches
    body_file: requests/get-branches.xml   # or an inline body
    expect:
      status: [200]                # the default
      namespaces:
        ds: http://tempuri.org/BranchDataSet.xsd
      xpath:
        - "//ds:Branch[ds:Id = '1']"

  - name: orders-status
    url: https://orders.corp.example/OrderService.svc
    soap:
      version: "1.2"
      action: http://corp.example/orders/IOrderService/GetStatus
    body_file: requests/get-status.xml
    kerberos: null                 # drop the inherited Kerberos block
    basic_auth:                    # standard Prometheus HTTP client settings
      username: soap-monitor
      password_file: secrets/orders-password
    tls_config:
      ca_file: certs/corp-root-ca.pem
    expect:
      namespaces:
        o: http://corp.example/orders
      not_xpath:
        - "//o:Status = 'Maintenance'"
      headers:
        - name: Content-Type
          regex: '^application/soap\+xml'
```

The essentials:

- **Targets** need `name`, `url` and `body` or `body_file` (a complete SOAP envelope). The
  other fields have defaults: `interval` 1m, `timeout` min(10s, interval), SOAP 1.1,
  `expect.status: [200]`, `max_response_size` 10MiB.
- **Defaults** are deep-merged into every target: mappings merge key by key, scalars and
  lists replace, and `null` removes an inherited value.
- **Auth**: at most one of `kerberos`, `basic_auth`, `authorization` and `oauth2` per target;
  mutual TLS combines with any of them.
- **Labels** describe the probed service (team, system, criticality). Environment-wide labels
  such as `env` or `region` belong in the Prometheus scrape configuration.
- **Relative paths** resolve against the directory of the configuration file.
- **Strict validation**: unknown fields, invalid regular expressions, XPath with undeclared
  prefixes, invalid request envelopes and `timeout > interval` are errors at load time, reported
  together with the target and the field. Check a file with `soap_exporter --config.check`.
- **Transport defaults** differ from Prometheus: a new connection per probe (`keep_alive:
  false`), HTTP/1.1 only (`enable_http2: false`), no redirects (`follow_redirects: false`).

The **[configuration reference](docs/configuration.md)** describes every field with its type
and default, the merge and validation rules, and how to write XPath and regex checks.

## Probe semantics

### Request

| | SOAP 1.1 | SOAP 1.2 |
|---|---|---|
| Method | `POST` | `POST` |
| `Content-Type` | `text/xml; charset=utf-8` | `application/soap+xml; charset=utf-8; action="<action>"` (`action` only if set) |
| Action | `SOAPAction: "<action>"`, quoted; `""` when unset (the header is mandatory in 1.1) | in `Content-Type` |

The header is sent as `SOAPAction`, with exactly this spelling: some SOAP stacks compare
header names case-sensitively. `User-Agent` is `soap_exporter/<version>` unless `headers`
sets one.

### Transport

- **One deadline** (`timeout`) covers the whole probe: Kerberos or OAuth2 token acquisition,
  DNS, connect, TLS, sending the request and reading the body.
- **A fresh connection per probe** unless `keep_alive: true`, so every probe measures DNS,
  connect and TLS, and certificate or DNS changes show up immediately.
- **HTTP/1.1** unless `enable_http2: true`; IIS refuses Windows authentication over HTTP/2.
- **No redirects** unless `follow_redirects: true`. A redirect on a SOAP endpoint is usually
  a misconfiguration, and the 3xx status fails the probe.
- **Phases**, measured per probe: `resolve` (DNS), `connect` (TCP), `tls` (handshake),
  `processing` (request written until the first response byte) and `transfer` (first byte
  until the body is read). A phase that did not happen (no `tls` over plain HTTP, no
  `resolve` for an IP address or a reused connection) is not reported. Through a proxy,
  `resolve` and `connect` measure the connection to the proxy.
- **Kerberos**: the token is sent with the first request, a `401` is never retried, and it
  drops the cached tickets so that the next probe starts fresh. See the
  [Kerberos guide](docs/kerberos.md).

### Response body

- The body is read up to `max_response_size` (default 10 MiB); a larger body fails the probe
  with reason `body_too_large`.
- The character encoding is determined as RFC 7303 says: a byte order mark, then the
  `charset` parameter of `Content-Type`, then the XML declaration, then UTF-8. Charset names
  follow the WHATWG Encoding Standard, so `iso-8859-1` and `us-ascii` are decoded as
  `windows-1252`, the name the debug report shows. The body is decoded to UTF-8 once, before
  any check; regular expressions and XPath run on the same text. A body that cannot be
  decoded (an unknown charset) fails the probe with `invalid_envelope` whatever the HTTP
  status: the Fault and status checks do not run, so even a `401` is reported as
  `invalid_envelope`.
- A `DOCTYPE` makes the response invalid (`invalid_envelope`): SOAP forbids DTDs, and this
  rules out entity expansion attacks.

### Checks and failure reasons

Checks run in this order. The first one that fails sets the failure reason; the outcome of
every check is kept for the debug pages.

| Order | Check | Reason |
|---|---|---|
| 1 | transport errors | `dns`, `connect`, `tls`, `timeout`, `auth`, `http`, `body_too_large` |
| 2 | the body cannot be decoded: an unknown charset in `Content-Type` or the XML declaration ([response body](#response-body)) | `invalid_envelope`; no further checks run |
| 3 | a SOAP Fault in the response, unless `expect.allow_soap_fault: true` | `soap_fault` (fault code and text in the message) |
| 4 | HTTP status not in `expect.status` | `auth` for 401 and 407, otherwise `status` |
| 5 | not a SOAP envelope of the configured version; an empty body passes only with status 202 (one-way operations) | `invalid_envelope` |
| 6 | `expect.headers`: `regex` must match (a missing header fails), `not_regex` must not match | `header` |
| 7 | `expect.regex` must match, `expect.not_regex` must not match the body | `regex` |
| 8 | `expect.xpath` must be true, `expect.not_xpath` false (XPath `boolean()`) | `xpath` |
| — | a panic inside the probe (recovered) | `internal` |

The Fault check runs before the status check because a SOAP 1.1 Fault arrives with HTTP 500,
and `soap_fault` with the fault text says more than `status`. With `allow_soap_fault: true`
the status check still applies: add 500 to `expect.status` for SOAP 1.1 faults.

Every failure reason:

| Reason | Meaning |
|---|---|
| `dns` | The host name of the URL (or of the proxy) did not resolve. |
| `connect` | The TCP connection failed: refused, unreachable, reset. |
| `tls` | The TLS handshake failed: untrusted, expired or mismatched certificate, protocol error. |
| `timeout` | The probe did not finish within `timeout`. The message names the stage, e.g. `timed out while connecting (timeout 10s)` or `timed out while acquiring a Kerberos token`. |
| `auth` | Kerberos or OAuth2 token acquisition failed (including an unreachable KDC or token endpoint), or the service answered 401 or 407 and that status is not expected (unless the body cannot be decoded, which is `invalid_envelope`). |
| `http` | An HTTP protocol error, e.g. a malformed or truncated response, or too many redirects. |
| `body_too_large` | The response body exceeds `max_response_size`. |
| `soap_fault` | The response contains a SOAP Fault. |
| `status` | The HTTP status is not in `expect.status`. |
| `invalid_envelope` | The body is not a SOAP envelope of the configured version: HTML, not well-formed XML, a `DOCTYPE`, the other SOAP version, or an empty body without status 202. Or the body cannot be decoded (an unknown charset), whatever the status. |
| `header` | A response header check failed. |
| `regex` | A `regex` did not match or a `not_regex` matched. |
| `xpath` | An `xpath` was false or a `not_xpath` true, or an expression could not be evaluated (the body is not XML, the expression is [too expensive](docs/configuration.md#writing-xpath-checks)). |
| `internal` | A bug in the exporter; the log has the details. Please report it. |

The failure message (on `/debug/probes`, in the `Target is down` log line) explains the
reason, e.g. `got 502, want [200]`, `SOAP fault soap:Server: Object reference not set to an
instance of an object` or `xpath "count(//o:Order) > 0" is false`.

### Scheduling

- The first probe of a target runs after a random delay of up to min(interval, 10s), so that
  targets do not all start at once; then one probe starts every `interval`.
- Probes of one target never overlap. `timeout` is at most `interval`, and a tick missed
  while a probe runs is dropped.
- A reload keeps the schedule, counters and history of unchanged targets; changed targets
  start over ([details](docs/configuration.md#reloading)).
- The log has a line when a target goes down (warn, with reason and message) and when it
  recovers (info); single probes are logged only at debug level.

## Metrics

All target metrics carry the label `target` (the target name) and the target's user
`labels`.

| Metric | Type | Extra labels | Meaning |
|---|---|---|---|
| `soap_probe_success` | gauge | | 1 if the last probe passed all checks, else 0. |
| `soap_probe_failure_reason` | gauge | `reason` | 1 for the reason of the last probe if it failed; absent while the target is healthy. |
| `soap_probes_total` | counter | `result` | Probes by outcome: `success` or a failure reason. All values start at 0. |
| `soap_probe_duration_seconds` | histogram | | Total duration of the probes that got an HTTP response, including token acquisition. Buckets: .01 .025 .05 .1 .25 .5 1 2.5 5 10 30 60. |
| `soap_probe_phase_duration_seconds` | gauge | `phase` | Phases of the last probe: `resolve`, `connect`, `tls`, `processing`, `transfer` (only those that happened). |
| `soap_probe_http_status_code` | gauge | | HTTP status of the last probe, 0 if there was no response. |
| `soap_probe_response_size_bytes` | gauge | | Response body size of the last probe. |
| `soap_probe_tls_version_info` | gauge | `version` | 1 for the TLS version of the last probe, e.g. `TLS 1.3`; absent without TLS. |
| `soap_probe_tls_cert_expiry_timestamp_seconds` | gauge | | Earliest `NotAfter` in the server's certificate chain of the last probe, as a Unix time; absent without TLS. |
| `soap_probe_last_timestamp_seconds` | gauge | | When the last probe finished, as a Unix time. |
| `soap_probe_interval_seconds` | gauge | | The configured interval, for staleness alerts. |
| `soap_target_info` | gauge | `url`, `soap_version`, `soap_action`, `auth` | Always 1. `auth` is `kerberos`, `basic`, `authorization`, `oauth2` or `none`. |

`soap_target_info`, `soap_probe_interval_seconds`, `soap_probes_total` and the histogram exist
from the start; the other metrics appear with the first probe result. A target removed by a
reload disappears from `/metrics`.

Exporter metrics, without target labels:

| Metric | Meaning |
|---|---|
| `soap_exporter_build_info` | Version, revision, branch and Go version as labels; always 1. |
| `soap_exporter_config_last_reload_successful` | 1 if the last load of the configuration succeeded, else 0. |
| `soap_exporter_config_last_reload_success_timestamp_seconds` | Time of the last successful load. |
| `go_*`, `process_*` | Go runtime and process metrics. |

### Labels

`target` identifies the target; static metadata such as the URL and the SOAP action is only
on `soap_target_info`, so that it does not multiply the other series. Join it when needed:

```promql
soap_probe_success * on (job, instance, target) group_left (url) soap_target_info
```

User `labels` should describe the probed service: owner team, system, criticality. They go on
every target series, so alerts can be routed on them without joins. Environment-wide labels
(`env`, `cluster`, `region`) belong in the Prometheus scrape configuration (`labels` of a
static config, or relabeling), as Prometheus' exporter guidelines require. Avoid user labels
named like Prometheus Operator target labels (`namespace`, `service`, `pod`, `container`,
`endpoint`): scraped through the Operator they become `exported_*`. The exporter warns about
them.

### Useful queries

```promql
# Targets whose last probe failed, with the reason
soap_probe_failure_reason == 1

# Average probe duration over 15 minutes
rate(soap_probe_duration_seconds_sum[15m]) / rate(soap_probe_duration_seconds_count[15m])

# Failed probes in the last hour by target and reason
sum by (target, result) (increase(soap_probes_total{result!="success"}[1h])) > 0

# Success rate over a day
sum by (target) (increase(soap_probes_total{result="success"}[1d]))
  / sum by (target) (increase(soap_probes_total[1d]))

# Days until the server certificate expires
(soap_probe_tls_cert_expiry_timestamp_seconds - time()) / 86400
```

Choose `rate()` windows longer than the probe interval of the targets: in a window without a
probe the average is 0/0, which has no value (NaN).

### Alerts and dashboard

[`examples/alerts.yml`](examples/alerts.yml) has these rules:

| Alert | Expression | `for` |
|---|---|---|
| `SoapTargetDown` | `soap_probe_success == 0`; the description names the reason from `soap_probe_failure_reason` | 5m |
| `SoapProbeStale` | `time() - soap_probe_last_timestamp_seconds > 3 * soap_probe_interval_seconds` | 5m |
| `SoapCertExpiringSoon` | `soap_probe_tls_cert_expiry_timestamp_seconds - time() < 14 * 86400` | 15m |
| `SoapExporterReloadFailed` | `soap_exporter_config_last_reload_successful == 0` | 5m |

Also alert on `up{job="soap_exporter"} == 0`: when the exporter is down, its series vanish
and none of these rules fires.

[`examples/grafana-dashboard.json`](examples/grafana-dashboard.json) shows the status, URL and
auth method of every target, the current failure reasons, availability over time, response
times, failures by reason, success rates, TLS certificate expiry and the phases of each
target's last probe. It selects the data source and the targets with variables, so it can be
imported as it is.

## HTTP endpoints

| Path | Method | Purpose |
|---|---|---|
| `/` | GET | Landing page with links. |
| `/metrics` | GET | Metrics. |
| `/-/healthy` | GET | Liveness: always 200. |
| `/-/ready` | GET | Readiness: 200 once a configuration is loaded and the probes run, else 503. |
| `/-/reload` | POST | Reload the configuration (as `SIGHUP` does); 500 with the error if the new configuration is invalid. Needs `--web.enable-lifecycle`. |
| `/-/log-level` | GET, PUT | Read or change the log level at runtime (`debug`, `info`, `warn`, `error`). PUT needs `--web.enable-lifecycle`. |
| `/config` | GET | The effective configuration (after merging the defaults, with resolved paths), secrets redacted. |
| `/debug/probes` | GET | The recent probes of every target (HTML; `?format=json`, `?target=<name>`). |
| `/debug/probe?target=<name>` | POST | Probe a target now and return the full report (HTML; `?format=json`). Not recorded in metrics or history; at most one per target every 5 seconds (429 otherwise). Needs `--web.enable-lifecycle`. |

Without `--web.enable-lifecycle` the lifecycle endpoints answer 403. Requests that a browser
sends from another origin to them are rejected, so a web page cannot trigger them.

## Command-line flags

| Flag | Default | Meaning |
|---|---|---|
| `--config.file` | `/etc/soap_exporter/config.yml` | Configuration file. |
| `--config.check` | off | Validate the configuration file (and the web configuration file, if set), initialize the Kerberos backend and parse the keytabs if a target uses Kerberos, build every target's HTTP client, and exit: 0 if valid, 1 if not. No network contact. |
| `--web.listen-address` | `:10057` | Address to listen on; repeatable. |
| `--web.config.file` | none | [Web configuration](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md) for TLS and basic authentication of the exporter's own endpoints. |
| `--web.systemd-socket` | off | Use systemd socket activation (Linux only). |
| `--web.enable-lifecycle` | off | Enable `POST /-/reload`, `PUT /-/log-level` and `POST /debug/probe`. |
| `--log.level` | `info` | `debug`, `info`, `warn` or `error`. |
| `--log.format` | `logfmt` | `logfmt` or `json`. |
| `--kerberos.config-file` | `$KRB5_CONFIG`, else `/etc/krb5.conf` | `krb5.conf`. Read only if a target uses Kerberos, and only once: a change needs a restart. |
| `--kerberos.backend` | `gokrb5` | Kerberos implementation; this build has only `gokrb5`. |
| `--history.limit` | `20` | Probe results kept per target for `/debug/probes`; 0 disables the history. |
| `--debug.capture-bodies` | off | Keep response body snippets (up to 64 KiB) in the probe history. On-demand probes always include them. |

Signals: `SIGHUP` reloads the configuration; `SIGINT` and `SIGTERM` stop the probes, cancel
probes in flight and shut down gracefully (a second signal exits at once). A configuration
that fails to load at startup ends the process with exit code 1.

## Kerberos

Kerberos targets need a keytab, a `krb5.conf` and the service principal name (SPN) of the
service:

```yaml
kerberos:
  principal: monitor@CORP.EXAMPLE
  keytab: secrets/monitor.keytab
  spn: HTTP/crm-app01.corp.example   # default: HTTP/<url host>, no DNS canonicalization
```

The token is sent with the first request; all targets with the same principal and keytab share
one login, and a replaced keytab is picked up without a restart. Keytabs whose entries all
have kvno 0 work too. The **[Kerberos guide](docs/kerberos.md)** covers SPN selection,
`krb5.conf` (read once: changes need a restart), keytab permissions for the non-root user of
the image, rotation, kvno-0 keytabs, clock skew, the slow `.local` resolver on macOS and
troubleshooting.

## Deployment with Docker Compose

[`examples/docker-compose.yml`](examples/docker-compose.yml) runs soap_exporter with
Prometheus (scrape configuration and alert rules) and Grafana (data source and dashboard
provisioned). The exporter gets the whole `examples/` directory as `/etc/soap_exporter`:

```text
examples/                    mounted read-only at /etc/soap_exporter
├── docker-compose.yml
├── config.yml               exporter configuration
├── requests/*.xml           request bodies
├── secrets/                 keytab, password and token files (create it; not in git)
├── certs/                   CA and client certificates (create it)
├── krb5.conf
├── prometheus.yml, alerts.yml
└── grafana-dashboard.json, grafana/provisioning/
```

```console
cd examples
docker compose up -d
docker compose kill -s HUP soap-exporter    # reload config.yml after a change
```

Then open <http://localhost:10057/debug/probes>, Prometheus on <http://localhost:9090> and
Grafana on <http://localhost:3000>. Things to get right:

**Mounts.** Mount everything read-only. The configuration is read from
`/etc/soap_exporter/config.yml`, and relative paths in it resolve against `/etc/soap_exporter`,
so the request files, secrets and certificates belong below it with the same relative paths:
the example mounts its directory as a whole. Mount directories, not single files, for
everything that changes while the exporter runs: the configuration, request bodies, keytabs,
secrets and certificates. Editors such as vim, `sed -i` and atomic keytab rotation replace a
file by renaming a new one over it, and a single-file bind mount does not follow that: inside
the container the file then disappears or keeps its old content, so a reload fails, or
reports success while it still reads the old configuration. Mount `krb5.conf` at
`/etc/krb5.conf`; it is read once at startup, so a change needs a restart anyway.

**Names that only the host knows.** If the SOAP services or the KDCs resolve only through the
host's `/etc/hosts`, not DNS, the container does not see them: list them in `extra_hosts`.

```yaml
extra_hosts:
  - "core.corp.example:192.0.2.10"
  - "dc01.corp.example:192.0.2.53"
```

The symptom of a missing entry is reason `dns` for a service, or `auth` with `error resolving
KDC address` for a KDC.

**Keytab ownership.** The image runs as uid/gid 65532. On a Linux host every file the
exporter reads must be readable by that user and its directories searchable. For
`config.yml` and `requests/` the usual modes 0644 and 0755 are enough; for the keytab and
the other secrets, e.g.
`chown -R 65532:65532 secrets && chmod 0500 secrets && chmod 0400 secrets/*`, or run the
container as the owner of the files with `user: "1000:1000"`. Docker Desktop on macOS and
Windows maps file ownership and hides the problem; it shows up on the Linux server as a
startup failure with `permission denied`.

**Time.** Kerberos tolerates 5 minutes of clock skew, and containers use the host clock:
keep the host synchronized (chrony, systemd-timesyncd).

**Hardening.** The exporter writes nothing to disk and needs no capabilities: the example runs
it with `read_only: true`, `cap_drop: [ALL]` and `no-new-privileges`. The image has no shell,
so a Compose `healthcheck` cannot run inside it; Prometheus' `up` metric and `/-/ready` serve
that purpose.

**Lifecycle endpoints.** The example enables `--web.enable-lifecycle` and publishes port
10057. Anyone who can reach the port can then reload the configuration and trigger probes;
see [security](#security).

## Debugging

**Validate first.** `soap_exporter --config.check` reports configuration problems with the
target and field. `/config` shows the effective configuration of each target after the
defaults were merged in.

**Probe history.** `/debug/probes` lists the last `--history.limit` (20) scheduled probes of
every target, newest first: time, duration, phases, HTTP status, failure reason and message,
the outcome of every check, the Kerberos SPN used, the TLS version, cipher and certificate
chain (subject, issuer, validity), and the response headers. `?target=<name>` shows one
target, `?format=json` returns JSON.

**Probe now.** With `--web.enable-lifecycle`, `POST /debug/probe?target=<name>` runs a probe
immediately with the target's own client and credentials and returns the full report,
including the start of the response body (up to 64 KiB) as the exporter decoded it. The
result does not touch the metrics or the history. The probe history page has a button for it.

```console
$ curl -s -X POST 'localhost:10057/debug/probe?target=orders-status&format=json' \
    | jq '.result | {success, reason, message, http_status, checks}'
```

**Response bodies.** Bodies are not kept in the history unless the exporter runs with
`--debug.capture-bodies`; on-demand probes always include them.

**Log level.** `--log.level=debug` logs every probe (target, success, reason, duration) and
the Kerberos logins with gokrb5's own messages. At runtime, with `--web.enable-lifecycle`:

```console
curl -X PUT -d debug localhost:10057/-/log-level
curl -X PUT -d info localhost:10057/-/log-level
```

**Reading a failure.**

| Reason | Check first |
|---|---|
| `dns` | The host name; `extra_hosts` in containers; on macOS, `GODEBUG=netdns=go` for `.local` names. |
| `connect` | Port, firewall, proxy (`proxy_url`, `no_proxy`). |
| `tls` | `tls_config.ca_file` for an internal CA, `server_name` when the URL uses another name, client certificate. |
| `timeout` | The stage in the message; whether `timeout` fits the service; phase durations of earlier probes. |
| `auth` | The message: Kerberos error, OAuth2 token error, or status 401/407 ([Kerberos troubleshooting](docs/kerberos.md#troubleshooting)). |
| `status` | The status in the message; a 3xx means a redirect (`follow_redirects`). |
| `soap_fault` | The fault code and text in the message; the request body and `soap.action`. |
| `invalid_envelope` | The body in an on-demand report: an HTML error or login page, the other SOAP version (`soap.version`), a `DOCTYPE`. A message starting with `decode response body` means an unknown charset; the HTTP status shows what the service actually answered. |
| `xpath` | Namespaces: [declare the response's namespaces](docs/configuration.md#writing-xpath-checks); test the expression against the body of an on-demand report. |

## Security

- **Lifecycle endpoints.** `--web.enable-lifecycle` lets anyone who can reach the exporter
  reload its configuration, change the log level and trigger probes, which call the SOAP
  services with the configured credentials (rate-limited to one on-demand probe per target
  every 5 seconds). Enable it only where the port is not reachable by untrusted clients, or
  protect the exporter with a web configuration. Cross-origin browser requests to these
  endpoints are always rejected.
- **Web configuration.** `--web.config.file` adds TLS and basic authentication to all
  endpoints, including `/metrics`, `/config` and the debug pages
  ([format](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md)).
  Prometheus then needs matching `scheme`, `tls_config` and `basic_auth` in its scrape
  configuration (see [`examples/prometheus.yml`](examples/prometheus.yml)).
- **Information on the read-only pages.** `/config` and `/debug/probes` need no lifecycle
  flag. They show target URLs, request headers and inline request bodies, response headers,
  failure messages and TLS details. Secrets are redacted: passwords, tokens and other secret
  fields of the HTTP client settings show as `<secret>`; values of `Authorization`,
  `Proxy-Authorization`, `Cookie` and `Set-Cookie`, and tokens in `WWW-Authenticate` and
  `Proxy-Authenticate` headers (such as Kerberos' mutual authentication token), show as
  `<redacted>`. Put secret request headers into `http_headers` with `secrets` or `files`,
  never into `headers` or request bodies. URLs with credentials are rejected.
- **Body capture.** Response bodies can contain personal or business data.
  `--debug.capture-bodies` keeps up to 64 KiB of every recorded probe's body in memory and
  shows it on `/debug/probes`; leave it off unless you need it. On-demand probe reports
  always contain the body.
- **Files.** Keep keytabs, passwords and keys readable only by the exporter's user (uid 65532
  in the image) and mount them read-only. Prefer `*_file` settings over inline secrets.
- **Responses are untrusted.** Response bodies are parsed without DTDs (`DOCTYPE` is rejected),
  their size is limited, XPath evaluation has a cost limit, and the debug pages escape
  everything they show.

## Building from source

Go 1.27.1 or newer:

```console
git clone https://github.com/poliproger/soap_exporter.git
cd soap_exporter
make build          # ./soap_exporter with version information
make test           # go test -race ./...
make lint           # golangci-lint
make docker         # the image, for the local platform
```

`go build ./cmd/soap_exporter` works too, without version information. The binary is static
(`CGO_ENABLED=0`). For a multi-platform image:

```console
docker buildx build --platform linux/amd64,linux/arm64 -t soap_exporter .
```

## License

[MIT](LICENSE)
