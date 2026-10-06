# Kerberos guide

soap_exporter authenticates to services that use Windows authentication (IIS, ASMX, WCF) or
any other SPNEGO (`Negotiate`) protection with a keytab. Kerberos is implemented in pure Go
([gokrb5](https://github.com/jcmturner/gokrb5)); the image needs no Kerberos libraries and
no `kinit`.

- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Choosing the SPN](#choosing-the-spn)
- [krb5.conf](#krb5conf)
- [The keytab](#the-keytab)
- [Keytabs with kvno 0](#keytabs-with-kvno-0)
- [Rotation](#rotation)
- [Clock skew](#clock-skew)
- [Running the binary on macOS](#running-the-binary-on-macos)
- [Troubleshooting](#troubleshooting)

## How it works

- Every probe sends `Authorization: Negotiate <token>` with the first request
  (preemptively), so a probe is one HTTP request. The token is made for an explicit service
  principal name (SPN); there is no DNS canonicalization, and the Host header is never
  changed.
- A `401` response is not retried. It fails the probe with reason `auth`, and the cached
  tickets are dropped, so the next probe starts with a fresh login. This covers a rotated
  service key, which would otherwise keep failing until the cached ticket expires.
- All targets with the same principal and keytab share one login: one TGT for many targets.
  Service tickets are cached per SPN. The login happens with the first probe that needs it;
  when the TGT expires, the client renews it or logs in again from the keytab.
- Token acquisition counts towards the probe `timeout` and the probe duration. A KDC that
  cannot be reached fails the probe with reason `auth` (or `timeout` if the deadline expires
  first, with the message `timed out while acquiring a Kerberos token`). A failed login never
  stops the exporter; the next probe tries again.
- Mutual authentication is not requested: a `WWW-Authenticate: Negotiate <token>` header in
  a successful response is ignored. NTLM is not supported; a server that offers
  `Negotiate, NTLM` in its 401 works, because the token is sent before the challenge.
- With `follow_redirects: true`, a redirect to another host fails the probe with reason
  `auth` instead of sending the token there.

## Configuration

```yaml
defaults:
  kerberos:
    principal: monitor@CORP.EXAMPLE
    keytab: secrets/monitor.keytab     # relative to the configuration file

targets:
  - name: branches
    url: http://core.corp.example/CoreService.asmx
    body_file: requests/get-branches.xml
    # SPN: HTTP/core.corp.example (the default)

  - name: customer-lookup
    url: http://crm.corp.example/Customers/CustomerService.asmx
    body_file: requests/find-customer.xml
    kerberos:
      spn: HTTP/crm-app01.corp.example  # merged with the defaults
```

`principal` is `name@REALM`, or `name` with the `default_realm` of `krb5.conf`. The principal
does not have to be a user: a service account's own `HTTP/<host>@REALM` principal works as a
client too. The command-line flags:

| Flag | Default | Meaning |
|---|---|---|
| `--kerberos.config-file` | `$KRB5_CONFIG`, else `/etc/krb5.conf` | `krb5.conf` to use. |
| `--kerberos.backend` | `gokrb5` | Kerberos implementation; this build has only `gokrb5`. |

`krb5.conf` is only read if a target uses Kerberos.

## Choosing the SPN

The token is requested for the SPN `HTTP/<host of url>` unless `kerberos.spn` says otherwise.
The host is taken as written in `url`, without the port. Browsers and curl canonicalize the
host name through DNS (CNAME) first; soap_exporter does not, so that the result does not
depend on DNS.

Set `spn` explicitly when the URL does not use the name the SPN is registered for:

- the URL uses a DNS alias or a load balancer name, and the SPN is registered for the real
  host (`HTTP/crm-app01.corp.example`);
- the URL uses an IP address;
- the service runs under an account whose SPN has another form.

Find the registered SPN with `setspn -Q HTTP/<host>` on a domain-joined Windows machine, or
ask the Active Directory administrators. A wrong SPN fails the probe with reason `auth` and a
message that contains `KDC_ERR_S_PRINCIPAL_UNKNOWN`. The SPN a probe used is shown on
`/debug/probes`.

## krb5.conf

A minimal file for Active Directory (also in [`examples/krb5.conf`](../examples/krb5.conf)):

```ini
[libdefaults]
  default_realm = CORP.EXAMPLE
  dns_lookup_kdc = false
  dns_lookup_realm = false
  udp_preference_limit = 1

[realms]
  CORP.EXAMPLE = {
    kdc = dc01.corp.example
    kdc = dc02.corp.example
  }

[domain_realm]
  .corp.example = CORP.EXAMPLE
  corp.example = CORP.EXAMPLE
```

- **Read once.** The file is read when the first configuration with a Kerberos target is
  loaded. A changed `krb5.conf` needs a restart; a reload does not pick it up. If reading it
  fails, the load fails, and the next reload tries again.
- **List the KDCs.** gokrb5 does not look KDCs up in DNS unless `dns_lookup_kdc = true`.
- **Prefer TCP.** `udp_preference_limit = 1` sends every request over TCP. Active Directory
  tickets carry a PAC and often do not fit into a UDP datagram.
- **One file.** `include` and `includedir` are not followed. Directives gokrb5 does not
  support are logged as a warning and ignored.
- **Encryption types.** AES (`aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96`) and RC4
  keys work; DES keys in a keytab are ignored.

In a container, mount it at `/etc/krb5.conf` (read-only), or anywhere else with
`--kerberos.config-file`.

## The keytab

The keytab must be a regular, non-empty file that contains keys for the configured
principal. It is parsed when the configuration is loaded (also by `--config.check`); a
keytab without the principal is a load error that lists the principals it does contain.

Create it on the Active Directory side with `ktpass`, or with `ktutil` (MIT or Heimdal) from
the account's password. Inspect it with `klist -k -t -e <file>` (MIT) or
`ktutil -k <file> list` (Heimdal, macOS).

### Permissions in a container

The image runs as the non-root user **65532:65532**. The keytab, like every other secret,
must be readable by that user, and every directory on its path must be searchable:

```console
# on the Docker host (Linux)
sudo chown -R 65532:65532 secrets
sudo chmod 0500 secrets
sudo chmod 0400 secrets/monitor.keytab
```

Alternatively, keep the files owned by a host user and run the container as that user
(`user: "1000:1000"` in Compose, `--user 1000:1000` with `docker run`); the binary needs no
entry in `/etc/passwd`.

Docker Desktop on macOS and Windows maps file ownership, so a keytab that is readable there
can still be unreadable for uid 65532 on a Linux server. The symptom is a startup failure
(`open ...: permission denied` for an unreadable file, `stat ...: permission denied` for a
directory that cannot be searched):

```text
level=ERROR msg="Exiting: the configuration could not be loaded" err="config file /etc/soap_exporter/config.yml: target \"branches\": kerberos.keytab: stat /etc/soap_exporter/secrets/monitor.keytab: permission denied"
```

Mount secrets read-only. Mount the directory that holds the keytab rather than the file
itself, so that a keytab replaced by renaming is visible in the container (see
[rotation](#rotation)).

## Keytabs with kvno 0

Every keytab entry records the key version number (kvno) of its key. Some keytabs, often
ones made with `ktpass` or by third-party tools, record kvno 0 for all entries. MIT Kerberos
and Java accept them. gokrb5 looks a key up by the exact kvno the KDC puts into its reply;
Active Directory sends the account's real kvno, so the login would fail with
`matching key not found in keytab ... kvno: N` although the key is right.

soap_exporter works around this. If **all** keytab entries of the principal have kvno 0, it
uses them for every kvno from 1 to 255, in memory only (the file is not changed), and logs
once at info level:

```text
msg="All keytab entries of the principal have kvno 0; they are also used for kvno 1–255 (kvno workaround)"
```

Nothing has to be configured. This was verified against Active Directory. A keytab that mixes
kvno 0 with other kvnos gets no workaround; it must contain the key with the kvno the KDC
uses. A kvno above 255 is not covered, and the error says so.

If you can, regenerate the keytab with the right kvno instead. Do not reset the account's
password just for that if other systems use the same keytab: that changes the key and breaks
them.

## Rotation

**Client keytab.** Before each use the exporter checks whether the keytab file changed
(another file at the path, another size or modification time). If so, it reads the keytab
again and logs in again (`Keytab changed, reloading it`). No restart or reload is needed.

- Replace the file atomically: write the new keytab next to the old one and rename it over
  the old one. A keytab that is read half-written fails to parse; the probe fails with
  `auth` and the next probe tries again.
- A single-file bind mount (`-v ./monitor.keytab:/etc/.../monitor.keytab`) does not follow a
  rename on the host: the container keeps seeing the old file (Linux) or none at all (Docker
  Desktop). Mount the directory.
- Changing the keytab path or the principal is a configuration change: reload.

**Service key.** When the service's key changes (a password change of its account), cached
service tickets become invalid. The next probe gets a `401` and fails with `auth`; the
exporter then drops its tickets, and the probe after it succeeds with fresh ones. Expect one
failed probe per target.

## Clock skew

Kerberos rejects requests from clients whose clock differs from the KDC's by more than 5
minutes (`KRB_AP_ERR_SKEW`, "clock skew too great"). A container uses the clock of its host:
keep the host synchronized with NTP (chrony, systemd-timesyncd) against the domain
controllers or the same source. Docker Desktop VMs can drift after the Mac sleeps; Docker
Desktop resynchronizes them, a restart of Docker Desktop fixes a persistent drift.

## Running the binary on macOS

On macOS, Go binaries use the system resolver. For names under `.local`, a common Active
Directory domain suffix, it asks multicast DNS first and waits 5 seconds before it falls back
to `/etc/hosts` or DNS. Every KDC exchange and every probe then takes 5 seconds longer, and
short timeouts expire. Use Go's own resolver:

```console
GODEBUG=netdns=go ./soap_exporter --config.file=config.yml --kerberos.config-file=krb5.conf
```

Linux and containers are not affected.

## Troubleshooting

Kerberos problems fail probes with reason `auth` (or `timeout`); the message on
`/debug/probes` and in the `Target is down` log line has the Kerberos error. With
`--log.level=debug` (or `PUT /-/log-level`) the log also shows the logins and gokrb5's own
messages.

| Message contains | Likely cause |
|---|---|
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | Wrong SPN: [set `kerberos.spn`](#choosing-the-spn). |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | The client principal does not exist in the realm (typo, wrong realm). |
| `KDC_ERR_PREAUTH_FAILED` | The keytab's key is outdated: the account's password changed. |
| `matching key not found in keytab` | The keytab has no key for the kvno or encryption type the KDC uses; see [kvno 0](#keytabs-with-kvno-0). |
| `KRB_AP_ERR_SKEW`, `clock skew` | [Clock skew](#clock-skew) of more than 5 minutes. |
| `error resolving KDC address`, `failed sending AS_REQ to KDC` | The KDC name does not resolve or is unreachable: `krb5.conf`, DNS, `extra_hosts`, firewall (port 88). |
| `timed out while acquiring a Kerberos token` | The KDC does not answer within the probe timeout. |
| status `401`, reason `auth`, every probe | The service rejects the ticket: wrong SPN for this service, or the service is not configured for Kerberos (only NTLM). |
| `redirect to another host` | `follow_redirects: true` and the service redirects elsewhere; no token is sent there. |
