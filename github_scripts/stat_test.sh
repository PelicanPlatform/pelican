#!/bin/bash -xe

# Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

# This tests the functionality of director's stat call to query origins for the availability of an object

set -e

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pelican-stat-test.XXXXXX")"

mkdir -p "${TEST_ROOT}/origin"
chmod 777 "${TEST_ROOT}/origin"

# Setup env variables needed - use port 0 to let Pelican choose random ports
export PELICAN_ORIGIN_PORT=0
export PELICAN_TLSSKIPVERIFY=true
export PELICAN_SERVER_ENABLEUI=false
export PELICAN_SERVER_WEBPORT=0
export PELICAN_ORIGIN_RUNLOCATION="${TEST_ROOT}/xrootdRunLocation"

export PELICAN_CONFIGDIR="${TEST_ROOT}"
export PELICAN_SERVER_DBLOCATION="${TEST_ROOT}/test-registry.sql"
export PELICAN_CONFIG="${PELICAN_CONFIGDIR}/empty.yaml"
export PELICAN_OIDC_CLIENTID="sometexthere"
export PELICAN_OIDC_CLIENTSECRETFILE="${TEST_ROOT}/oidc-secret"
echo "Placeholder OIDC secret" > "${TEST_ROOT}/oidc-secret"

export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="${TEST_ROOT}/origin"
export PELICAN_ORIGIN_ENABLEPUBLICREADS=true
export PELICAN_DIRECTOR_STATTIMEOUT=1s
export PELICAN_LOGGING_LEVEL=debug

# Function to cleanup after test ends
cleanup() {
    echo "Cleaning up..."
    if [ -n "${pid_federationServe:-}" ]; then
        echo "Sending SIGINT to PID ${pid_federationServe}"
        kill -SIGINT "${pid_federationServe}"
    else
        echo "No PID provided for cleanup."
    fi

    # Clean up temporary files
    rm -rf "${TEST_ROOT:-}"

    unset PELICAN_CONFIGDIR
    unset PELICAN_FEDERATION_DIRECTORURL
    unset PELICAN_FEDERATION_REGISTRYURL
    unset PELICAN_TLSSKIPVERIFY
    unset PELICAN_SERVER_DBLOCATION
    unset PELICAN_SERVER_ENABLEUI
    unset PELICAN_OIDC_CLIENTID
    unset PELICAN_OIDC_CLIENTSECRETFILE
    unset PELICAN_ORIGIN_ENABLEDIRECTREADS
    unset PELICAN_ORIGIN_ENABLEPUBLICREADS
    unset PELICAN_ORIGIN_RUNLOCATION
    unset PELICAN_ORIGIN_FEDERATION_PREFIX
    unset PELICAN_ORIGIN_STORAGEPREFIX
    unset PELICAN_DIRECTOR_STATTIMEOUT
    unset PELICAN_LOGGING_LEVEL
    unset PELICAN_ORIGIN_PORT
}

echo "This is some random content in the random file" > "${TEST_ROOT}/origin/input.txt"
touch "${PELICAN_CONFIG}"

# Run federation in the background with port 0 (random port)
federationServe="./pelican --config ${PELICAN_CONFIG} serve --module director --module registry --module origin --port 0 || :"

$federationServe &
pid_federationServe=$!

# Setup trap with the PID as an argument to the cleanup function
trap cleanup EXIT

# Wait for the address file to be created
# Address file is in runtime directory: $XDG_RUNTIME_DIR/pelican if set, otherwise falls back to ConfigDir
if [ -n "$XDG_RUNTIME_DIR" ]; then
    ADDRESS_FILE="$XDG_RUNTIME_DIR/pelican/pelican.addresses"
else
    ADDRESS_FILE="${PELICAN_CONFIGDIR}/pelican.addresses"
fi
echo "Waiting for address file: $ADDRESS_FILE"
TOTAL_WAIT=0
while [ ! -f "$ADDRESS_FILE" ]; do
    sleep 0.5
    TOTAL_WAIT=$((TOTAL_WAIT + 1))
    if [ "$TOTAL_WAIT" -gt 40 ]; then
        echo "Address file not created after 20 seconds, exiting..."
        echo "TEST FAILED"
        exit 1
    fi
done

echo "Address file found, sourcing it..."
# Source the address file to get the actual server addresses
# shellcheck source=/dev/null
source "$ADDRESS_FILE"

echo "SERVER_EXTERNAL_WEB_URL=$SERVER_EXTERNAL_WEB_URL"
echo "ORIGIN_URL=$ORIGIN_URL"

# Set environment variables for federation discovery based on actual addresses
export PELICAN_FEDERATION_DIRECTORURL="$SERVER_EXTERNAL_WEB_URL"
export PELICAN_FEDERATION_REGISTRYURL="$SERVER_EXTERNAL_WEB_URL"

# Prepare token for calling stat
TOKEN=$(./pelican --config "${PELICAN_CONFIG}" origin token create --audience "https://wlcg.cern.ch/jwt/v1/any" --issuer "$SERVER_EXTERNAL_WEB_URL" --scope "web_ui.access" --subject "bar" --lifetime 3600)

# Give the federation time to spin up:
API_URL="$SERVER_EXTERNAL_WEB_URL/api/v1.0/health"
DESIRED_RESPONSE="200"

# Function to check if the response indicates all servers are running
check_response() {
    date
    RESPONSE=$(curl -m 10 -k -s -I -X GET "$API_URL" --write-out "%{http_code}" --output /dev/null \
                 -H "Content-Type: application/json") \

    # Check if the response matches the desired output
    if echo "$RESPONSE" | grep -q "$DESIRED_RESPONSE"; then
        echo "Desired response received: $RESPONSE"
        return 0
    else
        echo "Waiting for desired response..."
        return 1
    fi
}

# We don't want to do this loop for too long, indicates there is an error
TOTAL_SLEEP_TIME=0

until check_response
do
    sleep .5
    TOTAL_SLEEP_TIME=$((TOTAL_SLEEP_TIME + 1))

    # Break loop if we sleep for more than 10 seconds
    if [ "$TOTAL_SLEEP_TIME" -gt 20 ]; then
        echo "Total sleep time exceeded, exiting..."
        echo "TEST FAILED"
        exit 1
    fi
done

STAT_URL="$SERVER_EXTERNAL_WEB_URL/api/v1.0/director_ui/servers/origins/stat/test/input.txt"

# Function to query the stat endpoint with retry logic for 429 responses
query_stat_endpoint() {
    local max_retries=10
    local retry_count=0

    while [ $retry_count -lt $max_retries ]; do
        # Make the curl request and capture both the response body and HTTP status code
        HTTP_RESPONSE=$(curl -k -w "\n%{http_code}" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$STAT_URL" 2>/dev/null)

        # Extract the status code (last line) and response body (everything else)
        HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)
        RESPONSE=$(echo "$HTTP_RESPONSE" | sed '$d')

        # Check if we got a 429 status code
        if [ "$HTTP_CODE" = "429" ]; then
            echo "Received 429 status code (director recently restarted), retrying in 1 second... (attempt $((retry_count + 1))/$max_retries)"
            retry_count=$((retry_count + 1))
            sleep 1
            continue
        fi

        # For any other status code, check if we got a successful response
        if echo "$RESPONSE" | grep -q "\"status\":\"success\""; then
            echo "Desired response received: $RESPONSE"
            echo "Test Succeeded"
            return 0
        else
            echo "Stat response returns error: $RESPONSE (HTTP status: $HTTP_CODE)"
            echo "Test Failed"
            return 1
        fi
    done

    # If we exhausted all retries
    echo "Exceeded maximum retries ($max_retries) for stat endpoint query"
    echo "Test Failed"
    return 1
}

# Query the stat endpoint with retry logic
if query_stat_endpoint; then
    trap - EXIT
    cleanup
    exit 0
else
    trap - EXIT
    cleanup
    exit 1
fi
