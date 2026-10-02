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

# This tests "pelican object put" and "pelican object get" against a
# federation in a box (director + registry + origin).
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
setup_test_root get-put 30

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

# ---------------------------------------------------------------------------
# 1. Start the federation
# ---------------------------------------------------------------------------

./pelican-server serve --module director --module registry --module origin -d &
PIDS+=($!)

wait_for_address_file "${PELICAN_RUNTIMEDIR}/pelican.addresses" "federation" "${PIDS[-1]}"
FED_WEB_URL="$(read_address "${PELICAN_RUNTIMEDIR}/pelican.addresses" SERVER_EXTERNAL_WEB_URL)"
FED_HOSTPORT="${FED_WEB_URL#https://}"
wait_for_healthy "${FED_WEB_URL}" "federation"

# ---------------------------------------------------------------------------
# 2. Upload an object
# ---------------------------------------------------------------------------

echo "This is some random content in the random file" > "${TEST_ROOT}/input.txt"

within_budget ./pelican token create "pelican://${FED_HOSTPORT}/test" \
    --read --write \
    --audience "https://wlcg.cern.ch/jwt/v1/any" \
    --subject "origin" \
    --profile "wlcg" \
    --lifetime 60 \
    > "${TEST_ROOT}/token.jwt"

# Accept either 201 (Created; correct) or 200 (incorrect, but what older
# versions of XRootD return).
if ! within_budget ./pelican object put "${TEST_ROOT}/input.txt" "pelican://${FED_HOSTPORT}/test/input.txt" \
    -d -t "${TEST_ROOT}/token.jwt" -L "${TEST_ROOT}/put.log" \
    || ! grep -q "Dumping response: HTTP/1.1 20" "${TEST_ROOT}/put.log"; then
    cat "${TEST_ROOT}/put.log" || true
    echo "TEST FAILED: The upload did not succeed"
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Download the object
# ---------------------------------------------------------------------------

if ! within_budget ./pelican object get "pelican://${FED_HOSTPORT}/test/input.txt" "${TEST_ROOT}/output.txt" \
    -d -t "${TEST_ROOT}/token.jwt" -L "${TEST_ROOT}/get.log" \
    || ! grep -q "HTTP Transfer was successful" "${TEST_ROOT}/get.log"; then
    cat "${TEST_ROOT}/get.log" || true
    echo "TEST FAILED: The download did not succeed"
    exit 1
fi

if ! cmp "${TEST_ROOT}/input.txt" "${TEST_ROOT}/output.txt"; then
    echo "TEST FAILED: The downloaded object differs from the uploaded one"
    exit 1
fi

echo "TEST PASSED"
