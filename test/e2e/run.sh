#!/usr/bin/env bash
# End-to-end smoke test (plan §9 phase 8): starts the exporter, an MIT KDC and a mock SOAP
# service with docker compose (see docker-compose.yml), waits for the first probes and
# asserts the exported series. The stack is always removed at the end; on failure the logs
# are printed first. Needs Docker Engine 25 or later with Compose v2, curl and awk; runs
# with bash 3.2 (macOS).
#
#   test/e2e/run.sh                              build the exporter image from the repository
#   SOAP_EXPORTER_IMAGE=<image> test/e2e/run.sh  test that image instead, e.g. a release
#                                                image; it is pulled if it is not present
#
# E2E_TIMEOUT is the wait for readiness and for the first probes in seconds (default 60).
# The compose project is soap-exporter-test-e2e.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$here"

export COMPOSE_PROJECT_NAME=soap-exporter-test-e2e
export COMPOSE_FILE=docker-compose.yml
if [[ -z ${SOAP_EXPORTER_IMAGE:-} ]]; then
	export SOAP_EXPORTER_IMAGE=soap-exporter-test-e2e-exporter:local
	COMPOSE_FILE+=:docker-compose.build.yml
fi
timeout=${E2E_TIMEOUT:-60}
# The targets of exporter/config.yml.
targets="plain kerberos soap12 fault"

# METRICS holds the last scrape of /metrics.
METRICS=
started=$SECONDS

log() { printf '==> %s\n' "$*"; }
pass() { printf 'ok   %s\n' "$*"; }
fail() {
	printf 'FAIL %s\n' "$*" >&2
	exit 1
}

cleanup() {
	local status=$?
	set +e
	trap - EXIT INT TERM
	if ((status != 0)); then
		if [[ -n $METRICS ]]; then
			log "Last scrape, soap_* series without histogram buckets"
			grep '^soap_' <<<"$METRICS" | grep -v '_bucket{'
		fi
		log "Exporter logs"
		docker compose logs --no-color --timestamps exporter
		log "Mock SOAP service and KDC logs"
		docker compose logs --no-color --timestamps mocksoap kdc
	fi
	log "Removing the stack"
	docker compose down --volumes --remove-orphans --timeout 10
	if ((status == 0)); then
		log "PASS in $((SECONDS - started))s"
	else
		log "FAILED after $((SECONDS - started))s"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# retry DESCRIPTION COMMAND...: runs COMMAND every second until it succeeds; fails after
# $timeout seconds.
retry() {
	local what=$1
	shift
	local deadline=$((SECONDS + timeout))
	until "$@"; do
		((SECONDS < deadline)) || fail "timed out after ${timeout}s waiting for $what"
		sleep 1
	done
}

scrape() {
	METRICS=$(curl -fsS --max-time 5 "$base/metrics")
}

# sample NAME [LABEL=VALUE...]: prints the value of every sample of the metric NAME whose
# labels include all the given pairs. Values must not contain spaces.
sample() {
	local name=$1
	shift
	awk -v name="$name" -v pairs="$*" '
		BEGIN { n = split(pairs, want, " ") }
		/^#/ { next }
		{
			series = substr($0, 1, length($0) - length($NF) - 1)
			if (series != name && index(series, name "{") != 1) next
			labels = substr(series, length(name) + 1)
			for (i = 1; i <= n; i++) {
				eq = index(want[i], "=")
				pair = substr(want[i], 1, eq) "\"" substr(want[i], eq + 1) "\""
				if (index(labels, "{" pair) == 0 && index(labels, "," pair) == 0) next
			}
			print $NF
		}' <<<"$METRICS"
}

# series NAME [LABEL=VALUE...]: the selector as text, for messages.
series() {
	local name=$1
	shift
	local IFS=,
	printf '%s{%s}' "$name" "$*"
}

# expect WANT NAME [LABEL=VALUE...]: the selected series has exactly one sample, WANT.
expect() {
	local want=$1
	shift
	local got
	got=$(sample "$@")
	[[ $got == "$want" ]] || fail "$(series "$@") = ${got:-<no sample>}, want $want"
	pass "$(series "$@") = $want"
}

# expect_absent NAME [LABEL=VALUE...]: the selected series has no sample.
expect_absent() {
	local got
	got=$(sample "$@")
	[[ -z $got ]] || fail "$(series "$@") = $got, want no sample"
	pass "$(series "$@") absent"
}

# compare A OP B DESCRIPTION: a numeric comparison of two sample values (awk, so that
# floats in exponent notation work).
compare() {
	awk -v a="$1" -v b="$3" -v op="$2" 'BEGIN {
		if (a == "" || b == "") exit 1
		a += 0; b += 0
		if (op == ">") exit !(a > b)
		if (op == ">=") exit !(a >= b)
		exit 1
	}' || fail "$4: $1 $2 $3 does not hold"
	pass "$4 ($1 $2 $3)"
}

all_probed() {
	scrape || return 1
	local t
	for t in $targets; do
		[[ -n $(sample soap_probe_success target="$t") ]] || return 1
	done
}

log "Removing leftovers of an earlier run"
docker compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true

log "Building and starting the stack (exporter image $SOAP_EXPORTER_IMAGE)"
docker compose up --detach --build --wait --wait-timeout 180

base=http://$(docker compose port exporter 10057)
log "Exporter at $base"

user=$(docker inspect --format '{{.Config.User}}' "$(docker compose ps --quiet exporter)")
[[ $user == 65532 || $user == 65532:* ]] || fail "the exporter runs as user '$user', want 65532"
pass "the exporter runs as user $user"

retry "/-/ready" curl -fsS -o /dev/null --max-time 2 "$base/-/ready"
pass "/-/ready"
curl -fsS -o /dev/null --max-time 2 "$base/-/healthy" || fail "/-/healthy"
pass "/-/healthy"

log "Waiting for the first probe of every target"
retry "a soap_probe_success sample of every target ($targets)" all_probed
pass "every target was probed"

expect 1 soap_probe_success target=plain
expect 1 soap_probe_success target=kerberos
expect 1 soap_probe_success target=soap12
expect 0 soap_probe_success target=fault
expect_absent soap_probe_failure_reason target=kerberos
expect 1 soap_probe_failure_reason target=fault reason=soap_fault
expect 200 soap_probe_http_status_code target=kerberos
expect 500 soap_probe_http_status_code target=fault
expect 1 soap_target_info target=plain auth=none soap_version=1.1 team=e2e
expect 1 soap_target_info target=kerberos auth=kerberos url=http://mocksoap:8080/kerberos
expect 1 soap_target_info target=soap12 auth=none soap_version=1.2
expect 5 soap_probe_interval_seconds target=kerberos
expect 1 soap_exporter_build_info
grep '^soap_exporter_build_info' <<<"$METRICS"
expect 1 soap_exporter_config_last_reload_successful

log "On-demand probe of the Kerberos target"
report=$(curl -fsS --max-time 10 -X POST "$base/debug/probe?target=kerberos&format=json") ||
	fail "POST /debug/probe?target=kerberos"
grep -q '"success": true' <<<"$report" || fail "on-demand probe of kerberos did not succeed:"$'\n'"$report"
grep -q '"spn": "HTTP/mocksoap"' <<<"$report" || fail "on-demand probe of kerberos: SPN is not HTTP/mocksoap:"$'\n'"$report"
pass "POST /debug/probe?target=kerberos succeeded with SPN HTTP/mocksoap"

log "Reloading the configuration"
# Two probes before the reload: if the reload reset the state of the unchanged target, it
# would have no result, or one at most, right after it.
two_probes() {
	scrape || return 1
	awk -v n="$(sample soap_probes_total target=kerberos result=success)" 'BEGIN { exit !(n + 0 >= 2) }'
}
retry "a second probe of the Kerberos target" two_probes
reload_time=$(sample soap_exporter_config_last_reload_success_timestamp_seconds)
probes=$(sample soap_probes_total target=kerberos result=success)
curl -fsS --max-time 10 -X POST -o /dev/null "$base/-/reload" || fail "POST /-/reload"
pass "POST /-/reload"
scrape
expect 1 soap_exporter_config_last_reload_successful
compare "$(sample soap_exporter_config_last_reload_success_timestamp_seconds)" ">" "$reload_time" \
	"the reload time advanced"
compare "$(sample soap_probes_total target=kerberos result=success)" ">=" "$probes" \
	"the unchanged target kept its counters"
expect 1 soap_probe_success target=kerberos
