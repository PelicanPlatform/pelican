#!/bin/bash -xe
#
# Copyright (C) 2024, University of Nebraska-Lincoln
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

# This tests the functionality of `pelican object get` and `pelican object put` with the
# "federation in a box"

set -e

GET_PUT_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/pelican_get_put.XXXXXX")
chmod 755 "$GET_PUT_ROOT"
GET_PUT_CONFIG="$GET_PUT_ROOT/config"
GET_PUT_RUNTIME="$GET_PUT_ROOT/runtime"
GET_PUT_ORIGIN="$GET_PUT_ROOT/origin"
GET_PUT_INPUT="$GET_PUT_ROOT/input.txt"
GET_PUT_OUTPUT="$GET_PUT_ROOT/output.txt"
GET_PUT_PUT_LOG="$GET_PUT_ROOT/putOutput.txt"
GET_PUT_GET_LOG="$GET_PUT_ROOT/getOutput.txt"
GET_PUT_TOKEN="$GET_PUT_ROOT/test-token.jwt"

mkdir -p "$GET_PUT_CONFIG" "$GET_PUT_RUNTIME" "$GET_PUT_ORIGIN"
chmod 755 "$GET_PUT_CONFIG" "$GET_PUT_RUNTIME" "$GET_PUT_ORIGIN"
chown xrootd: "$GET_PUT_ORIGIN"

# Create OIDC client configuration files for registry OAuth functionality
echo "test-client-id" > "$GET_PUT_CONFIG/oidc-client-id"
echo "test-client-secret" > "$GET_PUT_CONFIG/oidc-client-secret"

# Setup env variables needed
export PELICAN_TLSSKIPVERIFY=true
export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_SERVER_ENABLEUI=false
export PELICAN_ORIGIN_RUNLOCATION="$GET_PUT_ROOT/xrootdRunLocation"
export PELICAN_RUNTIMEDIR="$GET_PUT_RUNTIME"
export PELICAN_SERVER_WEBPORT=0
export PELICAN_ORIGIN_PORT=0
export PELICAN_CONFIGDIR="$GET_PUT_CONFIG"
export PELICAN_SERVER_DBLOCATION="$GET_PUT_CONFIG/test-registry.sql"
export PELICAN_OIDC_CLIENTIDFILE="$GET_PUT_CONFIG/oidc-client-id"
export PELICAN_OIDC_CLIENTSECRETFILE="$GET_PUT_CONFIG/oidc-client-secret"
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="$GET_PUT_ORIGIN"

# Function to cleanup after test ends
cleanup() {
    local pid=$1  # Get the PID from the function argument
    echo "Cleaning up..."
    if [ -n "$pid" ]; then
        echo "Sending SIGINT to PID $pid"
        kill -SIGINT "$pid" 2>/dev/null || true
    else
    echo "No PID provided for cleanup."
    fi

    # Clean up temporary files
    if [ -n "${GET_PUT_ROOT:-}" ]; then
        rm -rf "$GET_PUT_ROOT"
    fi

    unset PELICAN_TLSSKIPVERIFY
    unset PELICAN_ORIGIN_FEDERATIONPREFIX
    unset PELICAN_ORIGIN_STORAGEPREFIX
    unset PELICAN_SERVER_ENABLEUI
    unset PELICAN_OIDC_CLIENTIDFILE
    unset PELICAN_OIDC_CLIENTSECRETFILE
    unset PELICAN_ORIGIN_ENABLEDIRECTREADS
    unset PELICAN_RUNTIMEDIR
    unset PELICAN_SERVER_WEBPORT
    unset PELICAN_ORIGIN_PORT
    unset GET_PUT_ROOT
    unset GET_PUT_CONFIG
    unset GET_PUT_RUNTIME
    unset GET_PUT_ORIGIN
    unset GET_PUT_INPUT
    unset GET_PUT_OUTPUT
    unset GET_PUT_PUT_LOG
    unset GET_PUT_GET_LOG
    unset GET_PUT_TOKEN
}

# Make a file to use for testing
echo "This is some random content in the random file" > "$GET_PUT_INPUT"

if [ ! -f ./pelican ]; then
  echo "Pelican executable does not exist in PWD. Exiting.."
  exit 1
fi

# Run federation in the background
./pelican serve --module director --module registry --module origin -d &
pid_federationServe=$!

# Setup trap with the PID as an argument to the cleanup function
trap_cleanup() {
    cleanup "$pid_federationServe"
}
trap trap_cleanup EXIT

# Wait for the address file to be created so we can discover the actual ports
ADDRESS_FILE="${PELICAN_RUNTIMEDIR%/}/pelican.addresses"
TOTAL_WAIT=0
echo "Waiting for address file: $ADDRESS_FILE"
while [ ! -f "$ADDRESS_FILE" ]; do
    if ! kill -0 "${pid_federationServe:-0}" 2>/dev/null; then
        echo "Pelican process exited before address file was created"
        echo "TEST FAILED"
        unset pid_federationServe
        exit 1
    fi
    sleep 0.5
    TOTAL_WAIT=$((TOTAL_WAIT + 1))
    if [ "$TOTAL_WAIT" -gt 40 ]; then
        echo "Address file not created after 20 seconds, exiting..."
        echo "TEST FAILED"
        exit 1
    fi
done

# shellcheck source=/dev/null
source "$ADDRESS_FILE"
if [ -z "${SERVER_EXTERNAL_WEB_URL:-}" ]; then
    echo "Address file missing SERVER_EXTERNAL_WEB_URL"
    exit 1
fi

DISCOVERY_HOSTPORT="${SERVER_EXTERNAL_WEB_URL#https://}"
DISCOVERY_HOSTPORT="${DISCOVERY_HOSTPORT#http://}"

# Give the federation time to spin up using the discovered address
API_URL="$SERVER_EXTERNAL_WEB_URL/api/v1.0/health"
DESIRED_RESPONSE="200"

# Function to check if the response indicates all servers are running
check_response() {
    local response
    response=$(curl -m 10 -k -s -o /dev/null -w "%{http_code}" -X GET "$API_URL" \
                 -H "Content-Type: application/json")

    if [ "$response" = "$DESIRED_RESPONSE" ]; then
        echo "Desired response received: $response"
        return 0
    fi

    echo "Waiting for desired response..."
    return 1
}

# We don't want to do this loop for too long, indicates there is an error
TOTAL_SLEEP_TIME=0

# Loop until director, origin, and registry are running
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

# Make a token to be used (now that federation is running)
./pelican token create "pelican://$DISCOVERY_HOSTPORT/test" --read --write --audience "https://wlcg.cern.ch/jwt/v1/any" --issuer "$SERVER_EXTERNAL_WEB_URL" --subject "origin"  --profile "wlcg" --lifetime 60 > "$GET_PUT_TOKEN"

echo "Token created"
cat "$GET_PUT_TOKEN"

# Run pelican object put
./pelican object put "$GET_PUT_INPUT" "pelican://$DISCOVERY_HOSTPORT/test/input.txt" -d -t "$GET_PUT_TOKEN" -L "$GET_PUT_PUT_LOG"

# Check output of command.  Note we can accept either
# 200 (old, incorrect response from XRootD but we accept it) or 201 (Created; correct)
if grep -q "Dumping response: HTTP/1.1 20" "$GET_PUT_PUT_LOG"; then
    echo "Uploaded bytes successfully!"
else
    echo "Did not upload correctly"
    cat "$GET_PUT_PUT_LOG"
    exit 1
fi

./pelican object get "pelican://$DISCOVERY_HOSTPORT/test/input.txt" "$GET_PUT_OUTPUT" -d -t "$GET_PUT_TOKEN" -L "$GET_PUT_GET_LOG"

# Check output of command
if grep -q "HTTP Transfer was successful" "$GET_PUT_GET_LOG"; then
    echo "Downloaded bytes successfully!"
else
    echo "Did not download correctly"
    cat "$GET_PUT_GET_LOG"
    exit 1
fi

if grep -q "This is some random content in the random file" "$GET_PUT_OUTPUT"; then
    echo "Content matches the uploaded file!"
else
    echo "Did not download correctly, content in downloaded file is different from the uploaded file"
    echo "Contents of the downloaded file:"
    cat "$GET_PUT_OUTPUT"
    echo "Contents of uploaded file:"
    cat "$GET_PUT_INPUT"
    exit 1
fi

exit 0
