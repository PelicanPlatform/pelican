#!/bin/bash -xe

# Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You may
# obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This tests the Director's cache availability weighting.
#
# It starts a Director, Registry, a public-reads Origin, and 5 isolated caches.
# Then it primes a subset of caches (caches 1-2) by curling them directly, and
# kills cache 5 entirely (including its XRootD subprocess) so that it becomes
# unreachable and gets a median-imputed availability weight.
#
# A debug query to the Director with X-Pelican-Debug should show:
#   - Primed caches (Age > 0):   availabilityWeight == 2.0  (objAvailabilityFactor)
#   - Cold caches   (Age == 0):  availabilityWeight == 0.5  (1 / objAvailabilityFactor)
#   - Stopped cache (unreachable): availabilityWeight == 1.25 (median of [0.5,0.5,2.0,2.0])

set -e

NUM_CACHES=5
NUM_PRIMED=2          # caches 1..2 will be primed
STOPPED_CACHE_IDX=5   # cache 5 is killed before the Director query to mock "unknown" availability

TEST_ROOT="$(mktemp -d "/tmp/pel-avail.XXXXXX")"
chmod 755 "${TEST_ROOT}"

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
FED_CONFIG_DIR="${TEST_ROOT}/fed_cfg"
FED_RUNTIME_DIR="${TEST_ROOT}/fed_rt"
ORIGIN_DIR="${TEST_ROOT}/origin"
ORIGIN_RUN="${TEST_ROOT}/orun"

mkdir -p "${FED_CONFIG_DIR}" "${FED_RUNTIME_DIR}" "${ORIGIN_DIR}" "${ORIGIN_RUN}"
chmod 755 "${FED_CONFIG_DIR}" "${FED_RUNTIME_DIR}" "${ORIGIN_DIR}" "${ORIGIN_RUN}"
if [ "$(id -u)" -eq 0 ]; then
    chown xrootd: "${ORIGIN_DIR}"
fi

echo "fake-oidc-secret" > "${FED_CONFIG_DIR}/oidc-secret"

# Per-cache directories
for i in $(seq 1 ${NUM_CACHES}); do
    mkdir -p "${TEST_ROOT}/cache${i}_cfg" "${TEST_ROOT}/cache${i}_rt" \
             "${TEST_ROOT}/cache${i}_run" "${TEST_ROOT}/cache${i}_data"
    chmod 755 "${TEST_ROOT}/cache${i}_cfg" "${TEST_ROOT}/cache${i}_rt" \
              "${TEST_ROOT}/cache${i}_run"
    chmod 777 "${TEST_ROOT}/cache${i}_data"
done

# ---------------------------------------------------------------------------
# Common env for the federation (director + registry + origin)
# ---------------------------------------------------------------------------
export PELICAN_TLSSKIPVERIFY=true
export PELICAN_SERVER_ENABLEUI=false
export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_ORIGIN_ENABLEPUBLICREADS=true
export PELICAN_ORIGIN_ENABLEVOMS=false
export PELICAN_REGISTRY_REQUIRECACHEAPPROVAL=false
export PELICAN_REGISTRY_REQUIREORIGINAPPROVAL=false
export PELICAN_LOGGING_LEVEL=debug
export PELICAN_DIRECTOR_STATTIMEOUT=5s
export PELICAN_DIRECTOR_CACHESORTMETHOD=adaptive
# Prevent the Director from filtering the killed cache out of the working set
# before we stat it — the health-test poller may mark it as "error" within
# seconds of the kill.
export PELICAN_DIRECTOR_FILTERCACHESINERRORSTATE=false

# Federation process config
export PELICAN_CONFIGDIR="${FED_CONFIG_DIR}"
export PELICAN_RUNTIMEDIR="${FED_RUNTIME_DIR}"
export PELICAN_SERVER_DBLOCATION="${FED_CONFIG_DIR}/registry.sql"
export PELICAN_SERVER_WEBPORT=0
export PELICAN_ORIGIN_PORT=0
export PELICAN_ORIGIN_RUNLOCATION="${ORIGIN_RUN}"
export PELICAN_OIDC_CLIENTID="sometexthere"
export PELICAN_OIDC_CLIENTSECRETFILE="${FED_CONFIG_DIR}/oidc-secret"
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="${ORIGIN_DIR}"

# Create a small test file
echo "hello-availability-test" > "${ORIGIN_DIR}/avail.txt"
touch "${FED_CONFIG_DIR}/empty.yaml"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
CACHE_PIDS=()

# Collect all descendant PIDs of a process (children, grandchildren, etc.)
# then SIGKILL the entire tree.  This is necessary because `pelican cache serve`
# spawns an XRootD child process that survives a simple `kill -9` of the parent
# (it gets reparented to init and keeps serving).
kill_tree() {
    local root_pid="$1"
    local descendants
    descendants=$(pgrep -P "${root_pid}" 2>/dev/null) || true
    # Recurse into children first so we collect grandchildren while the tree is intact
    local all_pids="${root_pid}"
    for child in ${descendants}; do
        local grandchildren
        grandchildren=$(pgrep -P "${child}" 2>/dev/null) || true
        all_pids="${all_pids} ${child} ${grandchildren}"
    done
    # Kill everything at once
    # shellcheck disable=SC2086
    kill -9 ${all_pids} 2>/dev/null || true
}

cleanup() {
    echo "============================================"
    echo "Cleaning up..."
    echo "============================================"

    if [ -n "${FED_PID:-}" ]; then
        kill -SIGINT "${FED_PID}" 2>/dev/null || true
        sleep 1
        kill_tree "${FED_PID}"
    fi

    for pid in "${CACHE_PIDS[@]}"; do
        kill_tree "${pid}"
    done

    rm -rf "${TEST_ROOT}"

    unset PELICAN_TLSSKIPVERIFY PELICAN_SERVER_ENABLEUI PELICAN_ORIGIN_ENABLEDIRECTREADS
    unset PELICAN_ORIGIN_ENABLEPUBLICREADS PELICAN_ORIGIN_ENABLEVOMS
    unset PELICAN_REGISTRY_REQUIRECACHEAPPROVAL PELICAN_REGISTRY_REQUIREORIGINAPPROVAL
    unset PELICAN_LOGGING_LEVEL PELICAN_DIRECTOR_STATTIMEOUT PELICAN_DIRECTOR_CACHESORTMETHOD PELICAN_DIRECTOR_FILTERCACHESINERRORSTATE
    unset PELICAN_CONFIGDIR PELICAN_RUNTIMEDIR PELICAN_SERVER_DBLOCATION
    unset PELICAN_SERVER_WEBPORT PELICAN_ORIGIN_PORT PELICAN_ORIGIN_RUNLOCATION
    unset PELICAN_OIDC_CLIENTID PELICAN_OIDC_CLIENTSECRETFILE
    unset PELICAN_ORIGIN_FEDERATIONPREFIX PELICAN_ORIGIN_STORAGEPREFIX
    unset PELICAN_FEDERATION_DIRECTORURL PELICAN_FEDERATION_REGISTRYURL
    echo "Cleanup done."
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helper: wait for an address file; sets ADDRESS_CONTENTS afterwards
# ---------------------------------------------------------------------------
wait_for_address_file() {
    local file="$1"
    local label="$2"
    local pid="$3"
    local tries=0
    echo "Waiting for ${label} address file: ${file}"
    while [ ! -f "${file}" ]; do
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo "${label} process exited before address file was created"
            echo "TEST FAILED"
            exit 1
        fi
        sleep 0.5
        tries=$((tries + 1))
        if [ "${tries}" -gt 60 ]; then
            echo "${label} address file not created after 30 s"
            echo "TEST FAILED"
            exit 1
        fi
    done
    ADDRESS_CONTENTS="$(cat "${file}")"
}

# ---------------------------------------------------------------------------
# Helper: wait for health endpoint to return 200
# ---------------------------------------------------------------------------
wait_for_healthy() {
    local url="$1"
    local label="$2"
    local tries=0
    echo "Waiting for ${label} health at ${url} ..."
    while true; do
        code=$(curl -m 5 -k -s -o /dev/null -w "%{http_code}" "${url}") || true
        if [ "${code}" = "200" ]; then
            echo "${label} is healthy."
            return 0
        fi
        sleep 0.5
        tries=$((tries + 1))
        if [ "${tries}" -gt 60 ]; then
            echo "${label} not healthy after 30 s"
            echo "TEST FAILED"
            exit 1
        fi
    done
}

# ---------------------------------------------------------------------------
# 1. Start federation (director + registry + origin, NO built-in cache)
# ---------------------------------------------------------------------------
echo "Starting federation (director + registry + origin) ..."
./pelican serve --module director --module registry --module origin -d &
FED_PID=$!

FED_ADDR_FILE="${FED_RUNTIME_DIR}/pelican.addresses"
wait_for_address_file "${FED_ADDR_FILE}" "federation" "${FED_PID}"
# shellcheck source=/dev/null
source "${FED_ADDR_FILE}"
FED_WEB_URL="${SERVER_EXTERNAL_WEB_URL}"

export PELICAN_FEDERATION_DIRECTORURL="${FED_WEB_URL}"
export PELICAN_FEDERATION_REGISTRYURL="${FED_WEB_URL}"

wait_for_healthy "${FED_WEB_URL}/api/v1.0/health" "federation"

echo "Federation URL: ${FED_WEB_URL}"

# ---------------------------------------------------------------------------
# 2. Start 5 isolated caches
# ---------------------------------------------------------------------------
CACHE_URLS=()       # XRootD data URLs (e.g. https://host:port)
CACHE_WEB_URLS=()   # Web/API URLs

for i in $(seq 1 ${NUM_CACHES}); do
    echo "Starting cache ${i} ..."

    CACHE_CFG="${TEST_ROOT}/cache${i}_cfg/pelican.yaml"
    CACHE_RT="${TEST_ROOT}/cache${i}_rt"

    cat > "${CACHE_CFG}" <<EOF
RuntimeDir: ${CACHE_RT}
ConfigDir: ${TEST_ROOT}/cache${i}_cfg
Server:
  WebPort: 0
  DbLocation: ${TEST_ROOT}/cache${i}_cfg/cache.sql
  TLSSkipVerify: true
  EnableUI: false
Cache:
  Port: 0
  RunLocation: ${TEST_ROOT}/cache${i}_run
  StorageLocation: ${TEST_ROOT}/cache${i}_data
  EnableVoms: false
Federation:
  DirectorUrl: ${FED_WEB_URL}
  RegistryUrl: ${FED_WEB_URL}
OIDC:
  ClientID: "cache${i}-client"
Registry:
  RequireCacheApproval: false
Logging:
  Level: debug
EOF

    # Each cache runs in its own PELICAN_RUNTIMEDIR so address files don't collide.
    PELICAN_RUNTIMEDIR="${CACHE_RT}" \
        ./pelican cache serve --config "${CACHE_CFG}" -d &
    CACHE_PIDS+=($!)

    CACHE_ADDR_FILE="${CACHE_RT}/pelican.addresses"
    wait_for_address_file "${CACHE_ADDR_FILE}" "cache-${i}" "${CACHE_PIDS[-1]}"

    # Parse address file (don't source — variables would clobber each other)
    CACHE_WEB=""
    CACHE_DATA=""
    while IFS='=' read -r key val; do
        case "${key}" in
            SERVER_EXTERNAL_WEB_URL) CACHE_WEB="${val}" ;;
            CACHE_URL)               CACHE_DATA="${val}" ;;
        esac
    done < "${CACHE_ADDR_FILE}"

    if [ -z "${CACHE_DATA}" ] || [ -z "${CACHE_WEB}" ]; then
        echo "Cache ${i} address file incomplete."
        echo "TEST FAILED"
        exit 1
    fi

    CACHE_URLS+=("${CACHE_DATA}")
    CACHE_WEB_URLS+=("${CACHE_WEB}")

    wait_for_healthy "${CACHE_WEB}/api/v1.0/health" "cache-${i}"
    echo "  cache-${i}: data=${CACHE_DATA}  web=${CACHE_WEB}"
done

echo "All ${NUM_CACHES} caches are running."

# ---------------------------------------------------------------------------
# 3. Wait for all caches to be advertising at the Director
# ---------------------------------------------------------------------------
echo "Waiting for all caches to appear in the Director's server list ..."
TOTAL_WAIT=0
while true; do
    DIRECTOR_SERVERS=$(curl -k -s "${FED_WEB_URL}/api/v1.0/director_ui/servers" 2>/dev/null || echo "[]")
    # Count how many of our cache data URLs appear in the listing
    FOUND=0
    for u in "${CACHE_URLS[@]}"; do
        if echo "${DIRECTOR_SERVERS}" | grep -q "${u}"; then
            FOUND=$((FOUND + 1))
        fi
    done
    if [ "${FOUND}" -ge "${NUM_CACHES}" ]; then
        echo "All ${NUM_CACHES} caches are advertising."
        break
    fi
    sleep 1
    TOTAL_WAIT=$((TOTAL_WAIT + 1))
    if [ "${TOTAL_WAIT}" -gt 60 ]; then
        echo "Only ${FOUND}/${NUM_CACHES} caches advertising after 60 s"
        echo "TEST FAILED"
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 4. Prime caches 1..NUM_PRIMED by fetching the test object through each
# ---------------------------------------------------------------------------
OBJECT_PATH="/test/avail.txt"

# Helper: poll HEAD until Age > 0 (object written to local disk) or timeout.
# A fixed sleep is too fragile — on loaded CI a 1 s window may not be enough
# for XRootD to flush the newly-fetched object.
wait_for_age_positive() {
    local url="$1"
    local label="$2"
    local tries=0
    local max_tries=60   # 60 × 0.5 s = 30 s max
    while true; do
        local age
        age=$(curl -sk --head "${url}" 2>/dev/null \
              | grep -i "^age:" | awk '{print $2}' | tr -d '\r')
        if [ -n "${age}" ] && [ "${age}" -gt 0 ] 2>/dev/null; then
            echo "  ${label}: Age=${age} s (object locally stored — good)"
            return 0
        fi
        tries=$((tries + 1))
        if [ "${tries}" -ge "${max_tries}" ]; then
            return 1
        fi
        sleep 0.5
    done
}

for i in $(seq 1 ${NUM_PRIMED}); do
    echo "Priming cache ${i} at ${CACHE_URLS[$((i-1))]} ..."
    RESULT=$(curl -sk "${CACHE_URLS[$((i-1))]}${OBJECT_PATH}" 2>&1)
    if [ "${RESULT}" != "hello-availability-test" ]; then
        echo "Unexpected response from cache ${i}: ${RESULT}"
        echo "TEST FAILED"
        exit 1
    fi

    # Block until XRootD reports Age > 0 for this object.  We must confirm
    # local storage before querying the Director, otherwise the cache will
    # still report Age=0 and receive availabilityWeight=0.5 instead of 2.0.
    if ! wait_for_age_positive "${CACHE_URLS[$((i-1))]}${OBJECT_PATH}" "cache-${i}"; then
        echo "cache-${i} never returned Age > 0 after 30 s."
        echo "Your XRootD build may not report the Age header on HEAD responses."
        echo "TEST FAILED"
        exit 1
    fi
done

echo "Primed caches 1-${NUM_PRIMED} — all confirmed Age > 0."

# ---------------------------------------------------------------------------
# 5. Stop cache STOPPED_CACHE_IDX to force an error/unknown stat result
# ---------------------------------------------------------------------------
# We kill the entire process tree (pelican + xrootd) and wait until the cache's
# HTTPS port no longer accepts connections.
echo "Stopping cache ${STOPPED_CACHE_IDX} (PID ${CACHE_PIDS[$((STOPPED_CACHE_IDX-1))]}) ..."
STOPPED_CACHE_DATA_URL="${CACHE_URLS[$((STOPPED_CACHE_IDX-1))]}"
STOPPED_CACHE_WEB_URL="${CACHE_WEB_URLS[$((STOPPED_CACHE_IDX-1))]}"
kill_tree "${CACHE_PIDS[$((STOPPED_CACHE_IDX-1))]}"

# Wait until the cache's web port is closed (max 15 s).
TRIES=0
while true; do
    CODE=$(curl -m 2 -k -s -o /dev/null -w "%{http_code}" "${STOPPED_CACHE_WEB_URL}/api/v1.0/health" 2>/dev/null) || true
    if [ "${CODE}" != "200" ]; then
        echo "  cache-${STOPPED_CACHE_IDX} is confirmed down (HTTP ${CODE})."
        break
    fi
    TRIES=$((TRIES + 1))
    if [ "${TRIES}" -gt 30 ]; then
        echo "WARNING: cache-${STOPPED_CACHE_IDX} still responding after 15 s; proceeding anyway."
        break
    fi
    sleep 0.5
done

# Also verify the data port is down — this is what the Director stats.
TRIES=0
while true; do
    CODE=$(curl -m 2 -k -s -o /dev/null -w "%{http_code}" "${STOPPED_CACHE_DATA_URL}/test/avail.txt" 2>/dev/null) || true
    if [ "${CODE}" = "000" ] || [ "${CODE}" = "" ]; then
        echo "  cache-${STOPPED_CACHE_IDX} data port is confirmed down."
        break
    fi
    TRIES=$((TRIES + 1))
    if [ "${TRIES}" -gt 30 ]; then
        echo "WARNING: cache-${STOPPED_CACHE_IDX} data port still responding after 15 s."
        break
    fi
    sleep 0.5
done

# ---------------------------------------------------------------------------
# 6. Query the Director with X-Pelican-Debug to get the redirect JSON
# ---------------------------------------------------------------------------
echo "Querying Director for debug redirect info ..."

# The Director may need a brief moment before stat caches are complete,
# so retry with a short backoff for 429 (rate limit) responses.
MAX_RETRIES=15
RETRY=0
DEBUG_JSON=""

while [ "${RETRY}" -lt "${MAX_RETRIES}" ]; do
    HTTP_RESP=$(curl -sk -w "\n%{http_code}" \
        -H "X-Pelican-Debug: true" \
        "${FED_WEB_URL}${OBJECT_PATH}" 2>/dev/null)
    HTTP_CODE=$(echo "${HTTP_RESP}" | tail -n1)
    BODY=$(echo "${HTTP_RESP}" | sed '$d')

    if [ "${HTTP_CODE}" = "429" ]; then
        echo "  429 — Director not ready yet, retrying (${RETRY}/${MAX_RETRIES}) ..."
        RETRY=$((RETRY + 1))
        sleep 2
        continue
    fi

    if [ "${HTTP_CODE}" = "307" ] || [ "${HTTP_CODE}" = "200" ]; then
        DEBUG_JSON="${BODY}"
        break
    fi

    echo "  Unexpected HTTP ${HTTP_CODE}, retrying ..."
    RETRY=$((RETRY + 1))
    sleep 2
done

if [ -z "${DEBUG_JSON}" ]; then
    echo "Failed to get debug redirect JSON from Director after ${MAX_RETRIES} attempts."
    echo "TEST FAILED"
    exit 1
fi

echo "Director debug response:"
echo "${DEBUG_JSON}" | python3 -m json.tool 2>/dev/null || echo "${DEBUG_JSON}"

# ---------------------------------------------------------------------------
# 7. Validate availabilityWeight for each cache
# ---------------------------------------------------------------------------
# Expected weights (objAvailabilityFactor = 2.0):
#   primed  (Age > 0):    2.0
#   cold    (Age == 0):   0.5
#   stopped (unreachable): median of [0.5, 0.5, 2.0, 2.0] = 1.25
#
# The JSON structure is:
#   { "serversInfo": { "<url>": { "RedirectWeights": { "availabilityWeight": N } } } }

FAILURES=0

check_weight() {
    local cache_idx="$1"
    local expected="$2"
    local tolerance="$3"   # absolute tolerance for float compare
    local url="${CACHE_URLS[$((cache_idx - 1))]}"

    # The URL in serversInfo may not have a trailing slash, but otherwise should
    # match the CACHE_URL from the address file.  Try both.
    local weight
    weight=$(echo "${DEBUG_JSON}" | python3 -c "
import json, sys
from urllib.parse import urlparse
data = json.load(sys.stdin)
si = data.get('serversInfo', {})
target = urlparse('${url}')
target_hp = target.hostname + ':' + str(target.port) if target.port else target.hostname
# Match by host:port since URL schemes/paths may differ slightly
for k, v in si.items():
    pk = urlparse(k)
    pk_hp = pk.hostname + ':' + str(pk.port) if pk.port else pk.hostname
    if pk_hp == target_hp:
        w = v.get('RedirectWeights', {}).get('availabilityWeight', None)
        if w is not None:
            print(w)
            sys.exit(0)
print('NOT_FOUND')
" 2>/dev/null)

    if [ "${weight}" = "NOT_FOUND" ]; then
        echo "  cache-${cache_idx} (${url}): not found in serversInfo (may not be in working set — OK if cache was truncated)"
        return 0
    fi

    local diff
    diff=$(python3 -c "print(abs(${weight} - ${expected}))" 2>/dev/null)
    local ok
    ok=$(python3 -c "print('yes' if ${diff} <= ${tolerance} else 'no')" 2>/dev/null)

    if [ "${ok}" = "yes" ]; then
        echo "  PASS  cache-${cache_idx}: availabilityWeight=${weight} (expected ${expected} ±${tolerance})"
    else
        echo "  FAIL  cache-${cache_idx}: availabilityWeight=${weight} (expected ${expected} ±${tolerance})"
        FAILURES=$((FAILURES + 1))
    fi
}

echo ""
echo "Checking availabilityWeight values ..."

# Primed caches (1..NUM_PRIMED) should have weight = 2.0
for i in $(seq 1 ${NUM_PRIMED}); do
    check_weight "${i}" "2.0" "0.01"
done

# Cold (unprimed, still running) caches should have weight = 0.5
# Skip the stopped cache in this loop.
for i in $(seq $((NUM_PRIMED + 1)) ${NUM_CACHES}); do
    if [ "${i}" -eq "${STOPPED_CACHE_IDX}" ]; then
        continue
    fi
    check_weight "${i}" "0.5" "0.01"
done

# Stopped cache should get median-imputed weight.
# The 4 valid weights are:
#   primed caches 1-2: 2.0 each  →  [2.0, 2.0]
#   cold   caches 3-4: 0.5 each  →  [0.5, 0.5]
# Sorted: [0.5, 0.5, 2.0, 2.0] → median = (0.5 + 2.0) / 2 = 1.25
echo ""
echo "Checking stopped cache ${STOPPED_CACHE_IDX} (expect median-imputed weight = 1.25) ..."
STOPPED_WEIGHT=$(echo "${DEBUG_JSON}" | python3 -c "
import json, sys
from urllib.parse import urlparse
data = json.load(sys.stdin)
si = data.get('serversInfo', {})
target = urlparse('${STOPPED_CACHE_DATA_URL}')
target_hp = target.hostname + ':' + str(target.port) if target.port else target.hostname
for k, v in si.items():
    pk = urlparse(k)
    pk_hp = pk.hostname + ':' + str(pk.port) if pk.port else pk.hostname
    if pk_hp == target_hp:
        w = v.get('RedirectWeights', {}).get('availabilityWeight', None)
        if w is not None:
            print(w)
            sys.exit(0)
print('NOT_IN_SET')
" 2>/dev/null)

if [ "${STOPPED_WEIGHT}" = "NOT_IN_SET" ]; then
    echo "  FAIL  stopped cache-${STOPPED_CACHE_IDX} not found in serversInfo"
    echo "        Expected it in working set (FilterCachesInErrorState=false)"
    FAILURES=$((FAILURES + 1))
else
    OK=$(python3 -c "print('yes' if abs(${STOPPED_WEIGHT} - 1.25) <= 0.01 else 'no')" 2>/dev/null)
    if [ "${OK}" = "yes" ]; then
        echo "  PASS  cache-${STOPPED_CACHE_IDX} (stopped): availabilityWeight=${STOPPED_WEIGHT} (expected 1.25 median-imputed)"
    else
        echo "  FAIL  cache-${STOPPED_CACHE_IDX} (stopped): availabilityWeight=${STOPPED_WEIGHT} (expected 1.25 median-imputed)"
        FAILURES=$((FAILURES + 1))
    fi
fi

echo ""
echo "============================================"
if [ "${FAILURES}" -gt 0 ]; then
    echo "TEST FAILED (${FAILURES} assertion(s) failed)"
    exit 1
else
    echo "TEST PASSED"
    exit 0
fi
