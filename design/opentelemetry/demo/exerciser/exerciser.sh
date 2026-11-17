#!/bin/sh
#
# Pelican tracing demo: download objects through the federation, forever.
#
# Picks a scenario by weight, runs it, logs one line, sleeps, repeats.
# Every `pelican object get` is its own process, and so its own trace.
# A failed download is logged and the loop carries on; the `missing`
# scenario is meant to fail.
#
# All settings are environment variables (see the demo README, section 6).

set -u

FED="${EXERCISER_FEDERATION:-pelican://director:8444}"
NS="${EXERCISER_NAMESPACE:-/demo}"
DATA="${EXERCISER_DATA_DIR:-/data/demo}"
WORK="${EXERCISER_WORK_DIR:-/tmp/exerciser}"
CLIENT_LOG="${EXERCISER_CLIENT_LOG:-/var/log/pelican/client.log}"

INTERVAL="${EXERCISER_INTERVAL:-2}"
GET_TIMEOUT="${EXERCISER_GET_TIMEOUT:-300}"
RETAIN_MINUTES="${EXERCISER_RETAIN_MINUTES:-10}"
DEBUG="${EXERCISER_DEBUG:-false}"

W_HIT="${EXERCISER_WEIGHT_HIT:-6}"
W_MISS="${EXERCISER_WEIGHT_MISS:-3}"
W_LARGE="${EXERCISER_WEIGHT_LARGE:-1}"
W_SHARED="${EXERCISER_WEIGHT_SHARED:-1}"
W_DIRECT="${EXERCISER_WEIGHT_DIRECT:-2}"
W_MISSING="${EXERCISER_WEIGHT_MISSING:-1}"

HIT_OBJECTS="${EXERCISER_HIT_OBJECTS:-5}"
SMALL_KB="${EXERCISER_SMALL_SIZE_KB:-512}"
LARGE_MB="${EXERCISER_LARGE_SIZE_MB:-100}"
SHARED_MB="${EXERCISER_SHARED_SIZE_MB:-20}"
SHARED_CLIENTS="${EXERCISER_SHARED_CLIENTS:-4}"

log() {
	echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
}

now_ms() {
	echo $(($(date +%s%N) / 1000000))
}

rand() {
	# A random integer in [0, $1).
	echo $(($(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % $1))
}

# make_object <path under $DATA> <size in KiB>
# Written under a temporary name and renamed, so the origin never serves a
# partial file.
make_object() {
	dir="$DATA/$(dirname "$1")"
	mkdir -p "$dir"
	tmp="$dir/.tmp.$$.$(rand 1000000)"
	head -c $(($2 * 1024)) /dev/urandom >"$tmp" && mv "$tmp" "$DATA/$1"
}

# get <object path under $NS> <url suffix> <destination>
# Runs one `pelican object get`.  Its log (stderr, in the same logrus format
# as the servers' files) goes to a private file first and is then appended to
# $CLIENT_LOG whole, so concurrent clients do not interleave lines.
# Not `-L <file>`: on a failed download the client exits without flushing
# that file, so the error line would be lost.
# Sets GET_STATUS and GET_ERROR.
get() {
	runlog="$3.log"
	set -- "$FED$NS/$1$2" "$3"
	if [ "$DEBUG" = "true" ]; then
		timeout "$GET_TIMEOUT" pelican object get -d "$@" >/dev/null 2>"$runlog"
	else
		timeout "$GET_TIMEOUT" pelican object get "$@" >/dev/null 2>"$runlog"
	fi
	GET_STATUS=$?
	GET_ERROR=""
	if [ -f "$runlog" ]; then
		if [ "$GET_STATUS" -ne 0 ]; then
			GET_ERROR=$(grep -E 'level=(error|fatal)' "$runlog" | tail -n 1 | sed -n 's/.*msg="\{0,1\}\(.*\)$/\1/p' | cut -c1-200 | tr -d '"')
		fi
		# Only logrus lines; the client also prints a few plain lines.
		grep -E '^(time=|level=)' "$runlog" >>"$CLIENT_LOG" 2>/dev/null
		rm -f "$runlog"
	fi
	[ "$GET_STATUS" -eq 124 ] && GET_ERROR="timed out after ${GET_TIMEOUT}s"
	return "$GET_STATUS"
}

# report <scenario> <object> <start ms> <expect: ok|fail> [extra]
report() {
	dur=$(($(now_ms) - $3))
	if [ "$GET_STATUS" -eq 0 ]; then outcome=ok; else outcome=failed; fi
	if [ "$4" = "fail" ]; then
		if [ "$outcome" = failed ]; then expected=yes; else expected=no; fi
	else
		if [ "$outcome" = ok ]; then expected=yes; else expected=no; fi
	fi
	line="scenario=$1 object=$NS/$2 outcome=$outcome expected=$expected exit=$GET_STATUS duration_ms=$dur"
	[ -n "${5:-}" ] && line="$line $5"
	[ -n "$GET_ERROR" ] && line="$line error=\"$GET_ERROR\""
	log "$line"
}

run_dir() {
	d="$WORK/$1.$$.$(rand 1000000)"
	mkdir -p "$d"
	echo "$d"
}

stamp() {
	echo "$(date +%s)-$(rand 100000)"
}

scenario_hit() {
	obj="fixed/obj-$(($(rand "$HIT_OBJECTS") + 1)).bin"
	d=$(run_dir hit)
	t=$(now_ms)
	get "$obj" "" "$d/out"
	report hit "$obj" "$t" ok
	rm -rf "$d"
}

scenario_miss() {
	obj="gen/miss-$(stamp).bin"
	make_object "$obj" "$SMALL_KB"
	d=$(run_dir miss)
	t=$(now_ms)
	get "$obj" "" "$d/out"
	report miss "$obj" "$t" ok
	rm -rf "$d"
}

scenario_large() {
	obj="gen/large-$(stamp).bin"
	make_object "$obj" $((LARGE_MB * 1024))
	d=$(run_dir large)
	t=$(now_ms)
	get "$obj" "" "$d/out"
	report large "$obj" "$t" ok "size_mb=$LARGE_MB"
	rm -rf "$d"
	# Large objects are not kept on the origin.
	rm -f "$DATA/$obj"
}

scenario_shared() {
	obj="gen/shared-$(stamp).bin"
	make_object "$obj" $((SHARED_MB * 1024))
	d=$(run_dir shared)
	t=$(now_ms)
	i=1
	pids=""
	while [ "$i" -le "$SHARED_CLIENTS" ]; do
		(get "$obj" "" "$d/out.$i"; echo "$GET_STATUS" >"$d/status.$i") &
		pids="$pids $!"
		i=$((i + 1))
	done
	# shellcheck disable=SC2086
	wait $pids
	ok=0
	failed=0
	GET_STATUS=0
	GET_ERROR=""
	for f in "$d"/status.*; do
		if [ "$(cat "$f")" = 0 ]; then ok=$((ok + 1)); else failed=$((failed + 1)); GET_STATUS=$(cat "$f"); fi
	done
	report shared "$obj" "$t" ok "clients=$SHARED_CLIENTS ok=$ok failed=$failed"
	rm -rf "$d"
	rm -f "$DATA/$obj"
}

scenario_direct() {
	obj="fixed/obj-$(($(rand "$HIT_OBJECTS") + 1)).bin"
	d=$(run_dir direct)
	t=$(now_ms)
	get "$obj" "?directread" "$d/out"
	report direct "$obj" "$t" ok
	rm -rf "$d"
}

scenario_missing() {
	obj="missing/no-such-object-$(stamp).bin"
	d=$(run_dir missing)
	t=$(now_ms)
	get "$obj" "" "$d/out"
	report missing "$obj" "$t" fail
	rm -rf "$d"
}

pick() {
	total=$((W_HIT + W_MISS + W_LARGE + W_SHARED + W_DIRECT + W_MISSING))
	if [ "$total" -le 0 ]; then
		echo hit
		return
	fi
	r=$(rand "$total")
	for pair in "hit:$W_HIT" "miss:$W_MISS" "large:$W_LARGE" "shared:$W_SHARED" "direct:$W_DIRECT" "missing:$W_MISSING"; do
		w=${pair#*:}
		if [ "$r" -lt "$w" ]; then
			echo "${pair%%:*}"
			return
		fi
		r=$((r - w))
	done
	echo hit
}

cleanup_old() {
	# Generated objects on the origin, and anything a killed run left behind.
	find "$DATA/gen" -type f -mmin +"$RETAIN_MINUTES" -exec rm -f {} + 2>/dev/null
	find "$DATA" -name '.tmp.*' -type f -mmin +60 -exec rm -f {} + 2>/dev/null
	find "$WORK" -mindepth 1 -maxdepth 1 -mmin +60 -exec rm -rf {} + 2>/dev/null
	# The client log is append-only; keep it from growing without bound.
	if [ -f "$CLIENT_LOG" ] && [ "$(wc -c <"$CLIENT_LOG")" -gt 52428800 ]; then
		mv -f "$CLIENT_LOG" "$CLIENT_LOG.1"
	fi
}

setup() {
	mkdir -p "$WORK" "$DATA/fixed" "$DATA/gen" "$(dirname "$CLIENT_LOG")"
	i=1
	while [ "$i" -le "$HIT_OBJECTS" ]; do
		[ -f "$DATA/fixed/obj-$i.bin" ] || make_object "fixed/obj-$i.bin" "$SMALL_KB"
		i=$((i + 1))
	done
	# The origin reads the volume as root; make sure it could as any user too.
	chmod -R a+rX "$DATA"
}

wait_for_federation() {
	log "waiting for the federation: $FED$NS/fixed/obj-1.bin"
	while :; do
		d=$(run_dir wait)
		get "fixed/obj-1.bin" "" "$d/out"
		rm -rf "$d"
		if [ "$GET_STATUS" -eq 0 ]; then
			log "federation is ready"
			return
		fi
		log "not ready yet (exit=$GET_STATUS${GET_ERROR:+ error=\"$GET_ERROR\"}); retrying in 5s"
		sleep 5
	done
}

setup
wait_for_federation
log "starting: interval=${INTERVAL}s weights hit=$W_HIT miss=$W_MISS large=$W_LARGE shared=$W_SHARED direct=$W_DIRECT missing=$W_MISSING"
runs=0
while :; do
	"scenario_$(pick)"
	runs=$((runs + 1))
	[ $((runs % 20)) -eq 0 ] && cleanup_old
	sleep "$INTERVAL"
done
