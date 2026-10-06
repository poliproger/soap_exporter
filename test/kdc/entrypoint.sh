#!/bin/sh
# Entrypoint of the test KDC (see Dockerfile). On the first start it creates the realm, the
# principals and their keytabs; then it runs krb5kdc in the foreground, logging to stderr. A
# restarted container keeps its database and keytabs.
#
# Environment:
#   KDC_REALM               realm (default CORP.EXAMPLE)
#   KDC_PRINCIPALS          principals to create with random keys, without the realm, separated
#                           by spaces (default "monitor HTTP/app.corp.example"; empty for none).
#                           Each gets its own keytab, named after the principal with "/" replaced
#                           by "_", e.g. monitor.keytab and HTTP_app.corp.example.keytab.
#   KDC_MAX_LIFE            maximum ticket lifetime (default 10h)
#   KDC_MAX_RENEWABLE_LIFE  maximum renewable lifetime (default 7d; 0 means not renewable)
#   KDC_CLOCKSKEW           tolerated clock skew in seconds (default 300); the KDC also accepts
#                           tickets that expired less than this long ago
#   KDC_KEYTAB_DIR          directory for the keytabs (default /keytabs)
#   KDC_KEYTAB_OWNER        owner of the keytabs (default 65532:65532, the distroless nonroot user)
#   KDC_KEYTAB_MODE         mode of the keytabs (default 0440)
#
# The keytabs hold the principals' current keys with kvno 1 and the enctypes
# aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96. Pre-authentication is required, as in
# Active Directory. A new key (kvno + 1) for a principal is exported with, for example:
#   kadmin.local -q "ktadd -k /tmp/new.keytab monitor"
set -eu
set -f # the principal list is split on spaces, never globbed

realm=${KDC_REALM:-CORP.EXAMPLE}
principals=${KDC_PRINCIPALS-monitor HTTP/app.corp.example}
max_life=${KDC_MAX_LIFE:-10h}
max_renewable_life=${KDC_MAX_RENEWABLE_LIFE:-7d}
clockskew=${KDC_CLOCKSKEW:-300}
keytab_dir=${KDC_KEYTAB_DIR:-/keytabs}
keytab_owner=${KDC_KEYTAB_OWNER:-65532:65532}
keytab_mode=${KDC_KEYTAB_MODE:-0440}

db=/var/lib/krb5kdc/principal

log() {
	echo "kdc-entrypoint: $*" >&2
}

cat >/etc/krb5.conf <<EOF
[libdefaults]
  default_realm = $realm
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  clockskew = $clockskew

[realms]
  $realm = {
    kdc = localhost
    admin_server = localhost
  }

[plugins]
  kdcpreauth = {
    # SPAKE needs configured groups; without them it only logs an error at startup.
    disable = spake
  }
EOF

cat >/etc/krb5kdc/kdc.conf <<EOF
[kdcdefaults]
  kdc_listen = 88
  kdc_tcp_listen = 88

[realms]
  $realm = {
    database_name = $db
    key_stash_file = /etc/krb5kdc/stash
    max_life = $max_life
    max_renewable_life = $max_renewable_life
    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    default_principal_flags = +preauth
  }

[logging]
  kdc = STDERR
EOF

if [ ! -e "$db" ]; then
	# The master key is kept in the stash file only.
	master=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
	kdb5_util create -s -r "$realm" -P "$master" >/dev/null
	log "created realm $realm (max_life $max_life, max_renewable_life $max_renewable_life, clockskew $clockskew)"

	mkdir -p "$keytab_dir"
	for p in $principals; do
		kadmin.local -q "addprinc -clearpolicy -randkey $p@$realm" >/dev/null
		kt="$keytab_dir/$(printf '%s' "$p" | tr / _).keytab"
		rm -f "$kt"
		# -norandkey exports the key just created instead of a new one, so the kvno stays 1.
		kadmin.local -q "ktadd -norandkey -k $kt $p@$realm" >/dev/null
		if [ ! -s "$kt" ]; then
			log "exporting the keytab of $p@$realm failed"
			exit 1
		fi
		chown "$keytab_owner" "$kt"
		chmod "$keytab_mode" "$kt"
		log "created $p@$realm, keytab $kt"
	done
fi

exec krb5kdc -n
