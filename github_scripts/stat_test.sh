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

# This tests the director's stat call, which queries origins for the
# availability of an object, against a federation in a box (director +
# registry + origin).
#
# The test keeps to a temporary directory of its own, which it removes on
# exit, and its servers listen on ports that the OS picks, so that it can
# run alongside other tests.

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# shellcheck source=github_scripts/e2e_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e_common.sh"

require_binaries ./pelican ./pelican-server
setup_test_root stat 30

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
export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_ORIGIN_ENABLEPUBLICREADS=true
export PELICAN_ORIGIN_ENABLEVOMS=false
export PELICAN_DIRECTOR_STATTIMEOUT=1s

# ---------------------------------------------------------------------------
# 1. Start the federation
# ---------------------------------------------------------------------------

echo "This is some random content in the random file" > "${ORIGIN_DIR}/input.txt"

./pelican-server serve --module director --module registry --module origin -d &
PIDS+=($!)

wait_for_address_file "${PELICAN_RUNTIMEDIR}/pelican.addresses" "federation" "${PIDS[-1]}"
FED_WEB_URL="$(read_address "${PELICAN_RUNTIMEDIR}/pelican.addresses" SERVER_EXTERNAL_WEB_URL)"
# The issuer under which the director accepts tokens that the federation
# signs, which depends on the modules that it runs.
FED_ISSUER_URL="$(read_address "${PELICAN_RUNTIMEDIR}/pelican.addresses" LOCAL_ISSUER_URL)"
wait_for_healthy "${FED_WEB_URL}" "federation"

export PELICAN_FEDERATION_DIRECTORURL="${FED_WEB_URL}"
export PELICAN_FEDERATION_REGISTRYURL="${FED_WEB_URL}"

# ---------------------------------------------------------------------------
# 2. Query the director's stat endpoint
# ---------------------------------------------------------------------------

TOKEN="$(within_budget ./pelican-server origin token create \
    --audience "https://wlcg.cern.ch/jwt/v1/any" \
    --issuer "${FED_ISSUER_URL}" \
    --scope "web_ui.access" \
    --subject "bar" \
    --lifetime 3600)"

STAT_URL="${FED_WEB_URL}/api/v1.0/director_ui/servers/origins/stat/test/input.txt"

# Query the stat endpoint, setting HTTP_CODE and BODY, and succeed unless
# the director returned 429.
query_stat() {
    local response
    response="$(e2e_curl -w "\n%{http_code}" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        "${STAT_URL}")"
    HTTP_CODE="$(echo "${response}" | tail -n1)"
    BODY="$(echo "${response}" | sed '$d')"
    [ "${HTTP_CODE}" != "429" ]
}

# A director that has just started returns 429 for a while, so retry those
# until the budget runs out.
retry_for "$(time_left)" 1 query_stat

if [ "${HTTP_CODE}" != "200" ] || ! echo "${BODY}" | grep -q '"status":"success"'; then
    echo "TEST FAILED: The stat call returned HTTP ${HTTP_CODE}: ${BODY}"
    exit 1
fi

echo "TEST PASSED"
