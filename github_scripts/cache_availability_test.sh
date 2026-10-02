#!/bin/bash -xe
#
# Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

# This tests the director's cache availability weighting.
#
# It starts a federation (director + registry + origin) and 5 caches. Then
# it primes caches 1-2 by fetching an object through each of them, and kills
# cache 5 entirely (including its XRootD process), so that it becomes
# unreachable and gets a median-imputed availability weight.
#
# A debug query to the director with X-Pelican-Debug should show:
#   - Primed caches (Age > 0):     availabilityWeight == 2.0  (objAvailabilityFactor)
#   - Cold caches   (Age == 0):    availabilityWeight == 0.5  (1 / objAvailabilityFactor)
#   - Stopped cache (unreachable): availabilityWeight == 1.25 (median of [0.5,0.5,2.0,2.0])
#
# The test keeps to a temporary directory of its own, which it removes on
# exit, and its servers listen on ports that the OS picks, so that it can
# run alongside other tests.

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# shellcheck source=github_scripts/e2e_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e_common.sh"

require_binaries ./pelican-server
setup_test_root availability 60

export PELICAN_SERVER_ENABLEUI=false
export PELICAN_TLSSKIPVERIFY=true

# Give the registry OIDC client credentials, which this test never uses.
echo "placeholder-oidc-client-secret" > "${TEST_ROOT}/oidc-client-secret"
export PELICAN_OIDC_CLIENTID="placeholder-oidc-client-id"
export PELICAN_OIDC_CLIENTSECRETFILE="${TEST_ROOT}/oidc-client-secret"

ORIGIN_DIR="${TEST_ROOT}/origin"
mkdir -p "${ORIGIN_DIR}"
if [ "$(id -u)" -eq 0 ]; then
    chown xrootd: "${ORIGIN_DIR}"
fi

export PELICAN_ORIGIN_PORT=0
export PELICAN_ORIGIN_RUNLOCATION="${TEST_ROOT}/origin-run"
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="${ORIGIN_DIR}"
export PELICAN_ORIGIN_ENABLEPUBLICREADS=true
export PELICAN_ORIGIN_ENABLEVOMS=false
export PELICAN_REGISTRY_REQUIRECACHEAPPROVAL=false
export PELICAN_REGISTRY_REQUIREORIGINAPPROVAL=false
export PELICAN_DIRECTOR_STATTIMEOUT=5s
export PELICAN_DIRECTOR_CACHESORTMETHOD=adaptive
# Keep the director from filtering the killed cache out of the working set
# before we stat it: the health-test poller may mark it as "error" within
# seconds of the kill.
export PELICAN_DIRECTOR_FILTERCACHESINERRORSTATE=false

NUM_CACHES=5
NUM_PRIMED=2          # caches 1..2 will be primed
STOPPED_CACHE_IDX=5   # cache 5 is killed before the director query to mock "unknown" availability

# Keep the director from truncating any cache from the working set, so that
# every cache must appear in the debug response.
export PELICAN_DIRECTOR_ADAPTIVESORTTRUNCATECONSTANT="${NUM_CACHES}"

for i in $(seq 1 ${NUM_CACHES}); do
    mkdir -p "${TEST_ROOT}/cache${i}/config" "${TEST_ROOT}/cache${i}/runtime" \
             "${TEST_ROOT}/cache${i}/run" "${TEST_ROOT}/cache${i}/data"
    chmod 755 "${TEST_ROOT}/cache${i}"
    chmod 777 "${TEST_ROOT}/cache${i}/data"
done

# ---------------------------------------------------------------------------
# 1. Start the federation
# ---------------------------------------------------------------------------

echo "hello-availability-test" > "${ORIGIN_DIR}/avail.txt"

./pelican-server serve --module director --module registry --module origin -d &
PIDS+=($!)

wait_for_address_file "${PELICAN_RUNTIMEDIR}/pelican.addresses" "federation" "${PIDS[-1]}"
FED_WEB_URL="$(read_address "${PELICAN_RUNTIMEDIR}/pelican.addresses" SERVER_EXTERNAL_WEB_URL)"
wait_for_healthy "${FED_WEB_URL}" "federation"

export PELICAN_FEDERATION_DIRECTORURL="${FED_WEB_URL}"
export PELICAN_FEDERATION_REGISTRYURL="${FED_WEB_URL}"

# ---------------------------------------------------------------------------
# 2. Start the caches
# ---------------------------------------------------------------------------

CACHE_PIDS=()
CACHE_URLS=()       # XRootD data URLs (e.g. https://host:port)
CACHE_WEB_URLS=()   # Web/API URLs

for i in $(seq 1 ${NUM_CACHES}); do
    CACHE_DIR="${TEST_ROOT}/cache${i}"

    # The cache inherits the federation's exported settings, which take
    # precedence over its configuration file, so the file sets only what
    # the environment does not, or sets to the same value.
    cat > "${CACHE_DIR}/config/pelican.yaml" <<EOF
RuntimeDir: ${CACHE_DIR}/runtime
Server:
  WebPort: 0
  EnableUI: false
Cache:
  Port: 0
  RunLocation: ${CACHE_DIR}/run
  StorageLocation: ${CACHE_DIR}/data
  EnableVoms: false
Federation:
  DirectorUrl: ${FED_WEB_URL}
  RegistryUrl: ${FED_WEB_URL}
Registry:
  RequireCacheApproval: false
Logging:
  Level: debug
EOF

    # The exported PELICAN_RUNTIMEDIR would take precedence over the
    # configuration file, and the address files must not collide.
    PELICAN_RUNTIMEDIR="${CACHE_DIR}/runtime" \
        ./pelican-server cache serve --config "${CACHE_DIR}/config/pelican.yaml" -d &
    PIDS+=($!)
    CACHE_PIDS+=($!)

    wait_for_address_file "${CACHE_DIR}/runtime/pelican.addresses" "cache ${i}" "${PIDS[-1]}"
    CACHE_WEB_URLS+=("$(read_address "${CACHE_DIR}/runtime/pelican.addresses" SERVER_EXTERNAL_WEB_URL)")
    CACHE_URLS+=("$(read_address "${CACHE_DIR}/runtime/pelican.addresses" CACHE_URL)")
    wait_for_healthy "${CACHE_WEB_URLS[-1]}" "cache ${i}"
    echo "cache ${i}: data=${CACHE_URLS[-1]}  web=${CACHE_WEB_URLS[-1]}"
done

# ---------------------------------------------------------------------------
# 3. Wait for all caches to advertise to the director
# ---------------------------------------------------------------------------

# Succeed if the director lists all of the caches, and set FOUND to the
# number of them that it lists.
all_caches_advertised() {
    local servers u
    servers="$(e2e_curl "${FED_WEB_URL}/api/v1.0/director_ui/servers" || echo "[]")"
    FOUND=0
    for u in "${CACHE_URLS[@]}"; do
        if echo "${servers}" | grep -q "${u}"; then
            FOUND=$((FOUND + 1))
        fi
    done
    [ "${FOUND}" -ge "${NUM_CACHES}" ]
}

if ! retry_for 30 1 all_caches_advertised; then
    echo "TEST FAILED: Only ${FOUND} of ${NUM_CACHES} caches advertised within 30 seconds"
    exit 1
fi

# ---------------------------------------------------------------------------
# 4. Prime caches 1..NUM_PRIMED by fetching the object through each
# ---------------------------------------------------------------------------

OBJECT_PATH="/test/avail.txt"

# Succeed if a cache reports Age > 0 for an object, which means that the
# object is on its local disk.
age_positive() {
    local url="$1" label="$2" age
    age="$(e2e_curl --head "${url}" | grep -i "^age:" | awk '{print $2}' | tr -d '\r')"
    if [ -n "${age}" ] && [ "${age}" -gt 0 ] 2>/dev/null; then
        echo "${label}: Age=${age} s (object locally stored)"
        return 0
    fi
    return 1
}

for i in $(seq 1 ${NUM_PRIMED}); do
    echo "Priming cache ${i} at ${CACHE_URLS[$((i-1))]}"
    RESULT="$(e2e_curl "${CACHE_URLS[$((i-1))]}${OBJECT_PATH}")" || true
    if [ "${RESULT}" != "hello-availability-test" ]; then
        echo "TEST FAILED: Unexpected response from cache ${i}: ${RESULT}"
        exit 1
    fi

    # The director must not be queried until the object is stored locally:
    # otherwise the cache still reports Age=0 and gets availabilityWeight=0.5
    # instead of 2.0. A fixed sleep is too fragile: on a loaded CI runner,
    # XRootD may take more than a second to store the object.
    if ! retry_for 30 0.5 age_positive "${CACHE_URLS[$((i-1))]}${OBJECT_PATH}" "cache ${i}"; then
        echo "Your XRootD build may not report the Age header on HEAD responses."
        echo "TEST FAILED: Cache ${i} did not report Age > 0 within 30 seconds"
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 5. Kill cache STOPPED_CACHE_IDX to force an error/unknown stat result
# ---------------------------------------------------------------------------

STOPPED_CACHE_DATA_URL="${CACHE_URLS[$((STOPPED_CACHE_IDX-1))]}"
STOPPED_CACHE_WEB_URL="${CACHE_WEB_URLS[$((STOPPED_CACHE_IDX-1))]}"

# Kill it outright, rather than stopping it cleanly, so that it remains in
# the director's working set.
# shellcheck disable=SC2046
kill -9 $(tree_pids "${CACHE_PIDS[$((STOPPED_CACHE_IDX-1))]}") 2>/dev/null || true

# Succeed if a URL's port accepts no connections.
port_closed() {
    [ "$(e2e_curl -o /dev/null -w "%{http_code}" "$1")" = "000" ]
}

# Wait up to 15 seconds each for its web port and its data port, which is
# what the director stats, to close. The expected weight of the stopped
# cache depends on its being unreachable.
if ! retry_for 15 0.5 port_closed "${STOPPED_CACHE_WEB_URL}/api/v1.0/health"; then
    echo "TEST FAILED: Cache ${STOPPED_CACHE_IDX}'s web port is still open 15 seconds after it was killed"
    exit 1
fi
if ! retry_for 15 0.5 port_closed "${STOPPED_CACHE_DATA_URL}${OBJECT_PATH}"; then
    echo "TEST FAILED: Cache ${STOPPED_CACHE_IDX}'s data port is still open 15 seconds after it was killed"
    exit 1
fi

# ---------------------------------------------------------------------------
# 6. Query the director with X-Pelican-Debug to get the redirect JSON
# ---------------------------------------------------------------------------

# Query the director, and succeed and set DEBUG_JSON if it redirects.
query_director() {
    local response code
    response="$(e2e_curl -w "\n%{http_code}" -H "X-Pelican-Debug: true" "${FED_WEB_URL}${OBJECT_PATH}")"
    code="$(echo "${response}" | tail -n1)"
    if [ "${code}" = "307" ] || [ "${code}" = "200" ]; then
        DEBUG_JSON="$(echo "${response}" | sed '$d')"
        return 0
    fi
    echo "The director returned HTTP ${code}"
    return 1
}

# The director may need a moment before its stat results are complete,
# so retry 429 (rate limit) and other unexpected responses for up to
# 30 seconds.
DEBUG_JSON=""
retry_for 30 2 query_director || true

if [ -z "${DEBUG_JSON}" ]; then
    echo "TEST FAILED: The director returned no debug redirect JSON"
    exit 1
fi

echo "Director debug response:"
echo "${DEBUG_JSON}" | python3 -m json.tool 2>/dev/null || echo "${DEBUG_JSON}"

# ---------------------------------------------------------------------------
# 7. Check the availabilityWeight of each cache
# ---------------------------------------------------------------------------

# Expected weights (objAvailabilityFactor = 2.0):
#   primed  (Age > 0):     2.0
#   cold    (Age == 0):    0.5
#   stopped (unreachable): median of [0.5, 0.5, 2.0, 2.0] = 1.25
#
# The JSON structure is:
#   { "serversInfo": { "<url>": { "RedirectWeights": { "availabilityWeight": N } } } }

# The number of failed checks that did not stop the test.
FAILURES=0

# Print a cache's availabilityWeight from the debug JSON, or NOT_FOUND.
availability_weight() {
    local url="$1"
    echo "${DEBUG_JSON}" | python3 -c "
import json, sys
from urllib.parse import urlparse
data = json.load(sys.stdin)
si = data.get('serversInfo') or {}
target = urlparse('${url}')
target_hp = target.hostname + ':' + str(target.port) if target.port else target.hostname
# Match by host:port, since URL schemes and paths may differ slightly.
for k, v in si.items():
    pk = urlparse(k)
    pk_hp = pk.hostname + ':' + str(pk.port) if pk.port else pk.hostname
    if pk_hp == target_hp:
        w = v.get('RedirectWeights', {}).get('availabilityWeight', None)
        if w is not None:
            print(w)
            sys.exit(0)
print('NOT_FOUND')
"
}

# Usage: check_weight CACHE_IDX EXPECTED [LABEL]
#
# Check a cache's availabilityWeight. LABEL, such as "(stopped)", follows
# the cache's name in the messages.
check_weight() {
    local cache_idx="$1" expected="$2" url weight name
    url="${CACHE_URLS[$((cache_idx - 1))]}"
    name="cache ${cache_idx}${3:+ $3}"
    weight="$(availability_weight "${url}")"
    if [ "${weight}" = "NOT_FOUND" ]; then
        echo "CHECK FAILED: ${name} (${url}) is not in serversInfo"
        FAILURES=$((FAILURES + 1))
    elif python3 -c "import sys; sys.exit(abs(${weight} - ${expected}) > 0.01)"; then
        echo "${name}: availabilityWeight=${weight} (expected ${expected})"
    else
        echo "CHECK FAILED: ${name}: availabilityWeight=${weight} (expected ${expected})"
        FAILURES=$((FAILURES + 1))
    fi
}

# Primed caches (1..NUM_PRIMED) should have weight 2.0.
for i in $(seq 1 ${NUM_PRIMED}); do
    check_weight "${i}" "2.0"
done

# Cold (unprimed, still running) caches should have weight 0.5.
for i in $(seq $((NUM_PRIMED + 1)) ${NUM_CACHES}); do
    if [ "${i}" -ne "${STOPPED_CACHE_IDX}" ]; then
        check_weight "${i}" "0.5"
    fi
done

# The stopped cache should get the median-imputed weight, and must be in
# the working set, since FilterCachesInErrorState=false. The 4 valid
# weights, sorted, are [0.5, 0.5, 2.0, 2.0], so the median is 1.25.
check_weight "${STOPPED_CACHE_IDX}" "1.25" "(stopped)"

if [ "${FAILURES}" -gt 0 ]; then
    echo "TEST FAILED: ${FAILURES} checks failed"
    exit 1
fi

echo "TEST PASSED"
