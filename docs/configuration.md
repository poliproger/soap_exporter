# Configuration reference

soap_exporter reads one YAML file, `/etc/soap_exporter/config.yml` by default
(`--config.file`). [`examples/config.yml`](../examples/config.yml) uses every soap_exporter
setting described here (some as comments) and the common HTTP client settings, with comments.

- [File structure](#file-structure)
- [Defaults and how they merge](#defaults-and-how-they-merge)
- [Target fields](#target-fields)
- [HTTP client settings](#http-client-settings)
- [`expect`: response checks](#expect-response-checks)
- [Value types](#value-types)
- [Validation](#validation)
- [Writing XPath checks](#writing-xpath-checks)
- [Writing regular expressions](#writing-regular-expressions)
- [Reloading](#reloading)

## File structure

```yaml
defaults:       # optional: fields applied to every target
  ...
targets:        # required: at least one target
  - name: ...
    url: ...
    body_file: ...
```

The top level has only these two keys. Decoding is strict: unknown fields, duplicate keys and
values of the wrong type are errors. YAML anchors, aliases and merge keys (`<<: *anchor`) can
be used to share fragments, with one limit of the YAML library: a key next to `<<` overrides a
merged value only directly in a target (or in `defaults`). In a nested mapping such as
`labels`, `headers`, `expect` or `tls_config`, it is an error (`key "team" already set in
map`); merging adds keys there but cannot replace them. To override inherited values, use
[`defaults`](#defaults-and-how-they-merge), which merge at every level.

```yaml
targets:
  - &orders
    name: orders-eu
    url: https://orders-eu.corp.example/OrderService.svc
    body_file: requests/get-status.xml
    labels: &orders-labels {team: payments, criticality: high}
  - <<: *orders
    name: orders-us                                   # overrides the merged name and url
    url: https://orders-us.corp.example/OrderService.svc
    labels: {<<: *orders-labels, system: orders-us}   # adds a key; criticality: low would be an error
```

Check a file without starting the exporter:

```console
$ soap_exporter --config.check --config.file=config.yml
SUCCESS: config file config.yml is valid, 8 targets
```

`--config.check` loads the file, initializes the Kerberos backend and parses the keytabs if a
target uses Kerberos, and builds every target's HTTP client (TLS files are read). It contacts
no SOAP service and no KDC. It exits with 1 and prints the problems if the file is invalid,
and prints warnings (`WARNING: ...`) without failing.

## Defaults and how they merge

`defaults` accepts every target field except `name`, `url`, `body` and `body_file`. Each
target is deep-merged over the defaults before it is decoded:

- mappings merge key by key, recursively: `labels`, `headers`, `kerberos`, `tls_config`,
  `basic_auth`, `expect`, `expect.namespaces`, ...;
- scalars and lists replace the inherited value: `interval`, `expect.status`, `expect.xpath`,
  `expect.not_regex`, ...;
- `null` removes the inherited value, so the built-in default applies again.

```yaml
defaults:
  labels: {team: integration}
  headers: {X-Request-Source: soap_exporter}
  kerberos:
    principal: monitor@CORP.EXAMPLE
    keytab: secrets/monitor.keytab
  expect:
    not_regex: ['ORA-\d{5}']

targets:
  - name: branches          # inherits labels, headers, kerberos and expect from the defaults
    url: http://core.corp.example/CoreService.asmx
    body_file: requests/get-branches.xml
    labels: {criticality: high}           # labels: {team: integration, criticality: high}
    kerberos: {spn: HTTP/core01.corp.example}   # merged with defaults.kerberos; without it
                                                # the SPN is HTTP/core.corp.example

  - name: orders-status
    url: https://orders.corp.example/OrderService.svc
    body_file: requests/get-status.xml
    kerberos: null                        # no Kerberos for this target
    basic_auth: {username: soap-monitor, password_file: secrets/orders-password}
    headers: {X-Request-Source: null}     # drop one inherited header
    expect:
      not_regex: ['Exception']            # replaces the inherited list
```

Problems with the defaults themselves (unknown fields, invalid values) are reported once, as
`defaults: <field>: <message>`, not for every target. Rules that combine several fields, such
as `timeout <= interval`, are checked on each merged target: a target can complete or override
the defaults.

[`/config`](../README.md#http-endpoints) shows every target after the merge, with secrets
redacted.

## Target fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | Unique name, the value of the `target` label of every series of this target and the name used in logs and on the debug pages. Any UTF-8 text without control characters. |
| `url` | string | required | Absolute `http` or `https` URL of the SOAP endpoint. It must not contain credentials (`user:password@`): use `basic_auth`. |
| `interval` | [duration](#value-types) | `1m` | Time between the starts of two probes. |
| `timeout` | duration | `min(10s, interval)` | Deadline of one probe, at most `interval`. It covers everything: Kerberos or OAuth2 token acquisition, DNS, connect, TLS, sending the request and reading the response. |
| `labels` | map of strings | none | Labels that describe the probed service (team, system, criticality); see [label rules](#labels). |
| `soap.version` | `1.1` or `1.2` | `1.1` | SOAP version of request and response, with or without quotes. |
| `soap.action` | string | `""` | SOAP action. SOAP 1.1 sends it as `SOAPAction: "<action>"` (always present, `""` when empty); SOAP 1.2 as the `action` parameter of `Content-Type` (only when set). |
| `body` | string | — | The request, a complete SOAP envelope. Exactly one of `body` and `body_file` is required. |
| `body_file` | path | — | File with the request, read when the configuration is loaded. |
| `headers` | map of strings | none | Additional request headers; see [headers](#request-headers). |
| `kerberos` | mapping or `null` | none | Kerberos (SPNEGO) authentication; see [below](#kerberos). |
| `keep_alive` | bool | `false` | Reuse the connection between probes. By default every probe opens a new connection, so DNS, connect and TLS are measured every time and certificate or DNS changes show immediately. |
| `max_response_size` | [size](#value-types) | `10MiB` | Larger response bodies fail the probe with reason `body_too_large`. |
| `expect` | mapping | see [`expect`](#expect-response-checks) | Response checks. |
| HTTP client settings | | | `tls_config`, `basic_auth`, `oauth2`, `proxy_url`, ... inlined into the target; see [below](#http-client-settings). |

### Request body

The request body is validated when the configuration is loaded, so a broken request template
fails the load instead of every probe:

- valid UTF-8, sent as UTF-8; an XML declaration, if any, must be at the very start and
  declare UTF-8 (or no encoding);
- well-formed XML that also satisfies Namespaces in XML (declared prefixes, unique attributes);
- no `DOCTYPE`;
- a SOAP `Envelope` of the target's `soap.version` with a `Body`.

`body_file` must be a regular file of at most 1 MiB. Its content is read at load time: after
changing the file, reload the configuration. Inline `body` values are shown on `/config`; do
not put secrets into request bodies.

### Request headers

Every probe is a `POST` with these headers:

| | SOAP 1.1 | SOAP 1.2 |
|---|---|---|
| `Content-Type` | `text/xml; charset=utf-8` | `application/soap+xml; charset=utf-8; action="<action>"` (`action` only if set) |
| `SOAPAction` | `"<action>"` (quoted, `""` when empty), sent with exactly this spelling | — |
| `User-Agent` | `soap_exporter/<version>` | same |
| `Authorization` | from the auth settings | same |

`headers` adds more:

- `Content-Type`, `SOAPAction` and `Authorization` cannot be set (any spelling): they come
  from `soap` and the auth settings;
- names and values must be valid HTTP; two names that differ only in case are an error;
- `User-Agent` replaces the default;
- `Host` sets the Host header, e.g. for a URL with an IP address. The Kerberos SPN is still
  derived from the URL host;
- `null` removes a header inherited from the defaults.

Values in `headers` are visible on `/config` (except `Proxy-Authorization`, `Cookie` and
other credential headers, which are redacted). Secret headers belong in
[`http_headers`](#http-client-settings), whose values can come from files.

### Labels

User labels go on every series of the target, next to `target`. They should describe the
probed service, so that alerts can be routed without joins: owner team, system, criticality.
Environment-wide labels (`env`, `cluster`, `region`) belong in the Prometheus scrape
configuration, which adds them to every series of the exporter.

- Names must be valid Prometheus label names (`[a-zA-Z_][a-zA-Z0-9_]*`) and must not start
  with `__`. Values must be valid UTF-8.
- Reserved names are an error: `target`, `result`, `reason`, `phase`, `version`, `url`,
  `soap_version`, `soap_action`, `auth`, `job`, `instance` and `le`.
- The Prometheus Operator target labels `namespace`, `service`, `pod`, `container` and
  `endpoint` only produce a warning: scraped through the Operator, they are renamed to
  `exported_<name>`.
- Targets may use different label names. Every target series carries the union of all names;
  a target without a label gets an empty value, which Prometheus treats as absent.

### Kerberos

```yaml
kerberos:
  principal: monitor@CORP.EXAMPLE    # required
  keytab: secrets/monitor.keytab     # required
  spn: HTTP/core01.corp.example      # optional
```

| Field | Default | Meaning |
|---|---|---|
| `principal` | required | Client principal, `name@REALM` or `name` (the `default_realm` of `krb5.conf` applies). Service principals such as `HTTP/host@REALM` work as clients too. |
| `keytab` | required | Keytab with the principal's keys. It must be a readable, non-empty regular file and contain entries for the principal; it is parsed at load. Changes to the file are picked up without a reload. |
| `spn` | `HTTP/<url host>` | Service principal the token is requested for. The default takes the host of `url` as written, without port and without DNS canonicalization. |

`kerberos` is one auth method: it cannot be combined with `basic_auth`, `authorization` or
`oauth2`. `kerberos: null` drops a block inherited from the defaults. The
[Kerberos guide](kerberos.md) explains SPN selection, `krb5.conf`, keytab permissions,
rotation and kvno-0 keytabs.

## HTTP client settings

Every field of the standard Prometheus HTTP client configuration
([`http_config`](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#http_config))
is inlined into the target and can be set in the defaults:

| Field | Meaning |
|---|---|
| `basic_auth` | `username` or `username_file`, `password` or `password_file`. |
| `authorization` | `type` (default `Bearer`) and `credentials` or `credentials_file`. `bearer_token` and `bearer_token_file` are the legacy form. |
| `oauth2` | `client_id`, `client_secret` or `client_secret_file`, `token_url`, `scopes`, `endpoint_params`, its own `tls_config` and proxy settings. A failing token request fails the probe with reason `auth`. |
| `tls_config` | `ca_file`, `cert_file`, `key_file` (mutual TLS; or inline `ca`, `cert`, `key`), `server_name`, `insecure_skip_verify`, `min_version`, `max_version`. |
| `proxy_url`, `no_proxy`, `proxy_from_environment`, `proxy_connect_header` | HTTP proxy. |
| `follow_redirects` | Default **`false`** (Prometheus: true). A redirect is then a response with a 3xx status, which fails the `status` check. With `true`, up to 10 redirects are followed; a Kerberos token is never sent to another host. |
| `enable_http2` | Default **`false`** (Prometheus: true). IIS does not support Windows authentication over HTTP/2. |
| `http_headers` | Extra headers whose values come from `values`, `secrets` or `files`; for API keys and other secret headers. The reserved headers of Prometheus and `Content-Type`, `SOAPAction` and `Authorization` cannot be set. |

At most one auth method can be set per target: `kerberos`, `basic_auth`, `authorization`
(including `bearer_token` and `bearer_token_file`) or `oauth2`. A client certificate
(`tls_config.cert_file`) is not an auth method and combines with any of them.

Files referenced by these settings are read when they are used, so a changed password, token
or certificate takes effect without a reload: passwords, tokens and header files for every
request, TLS files when they change. The `*_ref` fields (`password_ref`, `credentials_ref`,
...) need a secret manager, which the exporter does not have; they make the load fail.

## `expect`: response checks

| Field | Type | Default | Meaning |
|---|---|---|---|
| `status` | list of integers | `[200]` | Accepted HTTP status codes (100–599), at least one. |
| `allow_soap_fault` | bool | `false` | Let a SOAP Fault pass. The status check still applies: a SOAP 1.1 Fault usually comes with status 500, so add 500 to `status`. |
| `namespaces` | map prefix → URI | none | Namespace prefixes for `xpath` and `not_xpath`. |
| `headers` | list | none | Response header checks: `name` plus `regex` and/or `not_regex`. `regex` passes if any value of the header matches; a missing header fails. `not_regex` fails if any value matches; a missing header passes. |
| `regex` | list of regexes | none | Each must match the response body. |
| `not_regex` | list of regexes | none | None may match the response body. |
| `xpath` | list of XPath 1.0 expressions | none | Each must be true. |
| `not_xpath` | list of XPath 1.0 expressions | none | Each must be false. |

Besides these, every response must be a SOAP envelope of the target's version (an empty body
passes only with status 202), and a SOAP Fault fails the probe unless allowed. The order of
the checks and the failure reason each one reports are described in
[probe semantics](../README.md#checks-and-failure-reasons).

Regular expressions and XPath run on the response body decoded to UTF-8 (see
[response body](../README.md#response-body)).

## Value types

| Type | Syntax |
|---|---|
| duration | Prometheus durations: `500ms`, `30s`, `5m`, `1h30m`, `1d`. |
| size | A number of bytes, or a number with a unit: `512KiB`, `4MiB`, `1GiB`. Units are base 2: `KB`, `MB` and `GB` mean the same as `KiB`, `MiB` and `GiB` (as in Prometheus); `kB` is rejected. |
| path | Relative paths are resolved against the directory of the configuration file: `body_file`, `kerberos.keytab`, and every file of the HTTP client settings. `/config` shows the resolved paths. |
| regex | Go [RE2 syntax](https://github.com/google/re2/wiki/Syntax), see [below](#writing-regular-expressions). |
| XPath | XPath 1.0, see [below](#writing-xpath-checks). |

## Validation

Everything is checked when the configuration is loaded (at startup, on reload and with
`--config.check`). An invalid file stops the startup; an invalid reload keeps the previous
configuration running. All problems found are reported together, each naming the target
(`target "name"`, or `targets[2]` if the name is missing) or `defaults`, and the field. A
value that cannot be decoded at all (such as an invalid regular expression in `expect`) skips
the checks that depend on its field, so fixing it can reveal further problems:

```text
FAILED: config file config.yml: target "orders": url: must not contain credentials (use basic_auth)
  target "orders": timeout: 30s exceeds the interval 10s
  target "orders": headers.SOAPAction: not allowed: derived from soap.version and soap.action
  targets[2]: name: required
  targets[2]: expect.xpath[0]: namespace prefix "o" is not declared (declare it in expect.namespaces)
```

The rules:

- at least one target; the top level has only `defaults` and `targets`; `defaults` cannot set
  `name`, `url`, `body` or `body_file`;
- `name` is required and unique; `url` is an absolute `http` or `https` URL with a host and
  without credentials;
- `interval > 0`, `0 < timeout <= interval`;
- exactly one of `body` and `body_file`, and the request is a valid envelope of the
  configured SOAP version ([request body](#request-body)); `soap.action` is a valid header
  value;
- at most one auth method; `kerberos` needs `principal` and a readable, non-empty `keytab`
  that has entries for the principal;
- `headers` and `http_headers` do not set derived or reserved headers;
- labels follow the [label rules](#labels);
- `max_response_size > 0`; `expect.status` has at least one code between 100 and 599; every
  header check has a `name` and a `regex` or `not_regex`;
- regular expressions compile;
- XPath expressions compile with the target's namespaces; undeclared prefixes, prefixed
  function names and redefining `soap`, `soap11` or `soap12` are errors;
- the HTTP client settings pass the checks of the Prometheus HTTP client, and their TLS files
  can be read.

## Writing XPath checks

An expression passes if its result is true after conversion with the XPath `boolean()`
function: a node-set must not be empty, a number must not be 0 or NaN, a string must not be
empty. `not_xpath` passes if the result is false. On failure the message says what the
expression returned, e.g. `xpath "count(//o:Order) > 0" is false` or `... selects no nodes`.

**Namespaces.** SOAP responses are namespaced, and XPath matches names by namespace URI,
not by the prefix the response uses. Declare a prefix for every namespace you query:

```yaml
expect:
  namespaces:
    o: http://corp.example/orders        # whatever prefix the response uses
  xpath:
    - "/soap:Envelope/soap:Body/o:GetStatusResponse/o:Status = 'Online'"
```

- `soap` is built in and bound to the envelope namespace of the target's SOAP version;
  `soap11` (`http://schemas.xmlsoap.org/soap/envelope/`) and `soap12`
  (`http://www.w3.org/2003/05/soap-envelope`) are always available. They cannot be redefined.
- A prefix used in an expression but not declared is a load error. (The XPath library would
  otherwise match it literally against the prefixes in the document.)
- An unprefixed name matches an element without a prefix even when that element is in a
  default namespace: `//Status` matches `<Status xmlns="http://corp.example/orders">`. This
  is a quirk of the XPath library; use a declared prefix or
  `//*[local-name() = 'Status']` to be explicit.
- ASMX services that return an ADO.NET DataSet put its rows into the DataSet's own default
  namespace (`http://tempuri.org/<DataSetName>.xsd`), not the service namespace. Declare that
  namespace, or match with `local-name()`:

  ```yaml
  namespaces:
    ds: http://tempuri.org/BranchDataSet.xsd
  xpath:
    - "//ds:Branch[ds:Id = '1']"
    - "//*[local-name() = 'Branch'][*[local-name() = 'Id'] = '1']"   # the same without namespaces
  ```

- SOAP 1.1 leaves `faultcode` and `faultstring` unqualified:
  `/soap:Envelope/soap:Body/soap:Fault/faultstring`.

**Known library bug.** The XPath library (antchfx/xpath v1.3.8) evaluates `last()` in a
predicate of a parenthesized path wrongly: `(//o:Order)[last()]/o:Status = 'Open'` is always
false, so a `not_xpath` with it always passes, and `(//o:Order)[last() - 1]` selects the
wrong node. Rewrite such expressions:

```yaml
xpath:
  - "string((//o:Order)[last()]/o:Status) = 'Open'"   # instead of (//o:Order)[last()]/o:Status = 'Open'
  - "(//o:Order)[last()][o:Status = 'Open']"          # also works
```

`//o:Order[last()]` (last() in a step, not after parentheses) is not affected.

**Cost limit.** One evaluation may take at most 20 million steps (moves through the document
and chunks of text read). Ordinary expressions need far fewer, even on a 10 MiB response;
expressions whose cost grows quadratically with the size of the response, such as
`//*[last()]` over many siblings or comparing deeply nested elements by their text, can hit
the limit on a large or hostile response. The check then fails with reason `xpath` and the
message `... cannot be evaluated: stopped after 20000000 steps, the expression is too
expensive for this response`.

Other notes:

- Prefixed function names (`fn:count()`) are not supported; XPath 1.0 functions have no prefix.
- Every expression is evaluated on a body that parses as XML. A response that is not XML
  fails the envelope check first (`invalid_envelope`); `xpath` and `not_xpath` then fail too.
- In YAML, wrap expressions in double quotes and use single quotes inside them, as in the
  examples above.

## Writing regular expressions

`regex`, `not_regex` and the header checks use Go [RE2 syntax](https://github.com/google/re2/wiki/Syntax),
without implicit flags:

- a match anywhere in the body is enough (use `^` and `$` to anchor);
- `.` does not match a newline unless the expression starts with `(?s)`;
- matching is case-sensitive unless it starts with `(?i)`; `(?m)` makes `^` and `$` match at
  line boundaries;
- RE2 has no backreferences or lookarounds.

In YAML, single-quoted strings keep backslashes as they are: `'ORA-\d{5}'`. In double-quoted
strings they must be doubled: `"ORA-\\d{5}"`.

## Reloading

Send `SIGHUP` to the process, or `POST /-/reload` with `--web.enable-lifecycle`. The new file
is loaded and validated in full, and its Kerberos credentials and HTTP clients are built,
before anything changes:

- if anything fails, the previous configuration keeps running,
  `soap_exporter_config_last_reload_successful` drops to 0 and the error is logged;
- otherwise targets are compared by name and by their effective configuration (after the
  merge, including the content of `body_file`): unchanged targets keep their schedule,
  counters and history; changed targets start over with fresh state; removed targets
  disappear from `/metrics`; new targets start after a random delay of up to
  min(interval, 10s).

Not everything needs a reload. The exporter picks up changes to these files by itself:
keytabs (checked before each use), password, token and `http_headers` files (read for every
request) and TLS certificates and keys. `krb5.conf` is the exception the other way round: it
is read once and needs a restart.
