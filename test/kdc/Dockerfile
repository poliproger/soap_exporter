# A throwaway MIT Kerberos KDC for tests: the Kerberos integration tests (test/integration) and
# the docker compose smoke test. It creates a realm and principals with random keys, exports one
# keytab per principal and runs krb5kdc in the foreground. Not for production use.
# Configuration: see the environment variables in entrypoint.sh.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      krb5-kdc krb5-admin-server \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/kdc-entrypoint
RUN chmod 0755 /usr/local/bin/kdc-entrypoint

# The KDC answers on 88/udp and 88/tcp. The keytabs land in /keytabs (KDC_KEYTAB_DIR); mount a
# volume there to share them with other containers.
EXPOSE 88/tcp 88/udp

# Healthy once krb5kdc listens on TCP port 88 (hex 0058, state 0A), i.e. after the keytabs were
# written.
HEALTHCHECK --interval=2s --timeout=2s --start-period=30s --retries=3 \
  CMD awk '$4 == "0A" && $2 ~ /:0058$/ { found = 1 } END { exit !found }' /proc/net/tcp /proc/net/tcp6

ENTRYPOINT ["/usr/local/bin/kdc-entrypoint"]
