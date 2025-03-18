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

mkdir -p /tmp/pelican-test/stat_test

mkdir -p /tmp/pelican-test/stat_test/origin
chmod 777 /tmp/pelican-test/stat_test/origin

# Helper func that finds an available port for the servers
find_available_port() {
    # Use Python to bind to port 0 and find an available port
    python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(('', 0)); print(s.getsockname()[1]); s.close()"
}

# Get two random available ports
WEBUI_PORT=$(find_available_port)
ORIGIN_PORT=$(find_available_port)

# Setup env variables needed
export PELICAN_FEDERATION_DIRECTORURL="https://$HOSTNAME:$WEBUI_PORT"
export PELICAN_FEDERATION_REGISTRYURL="https://$HOSTNAME:$WEBUI_PORT"
export PELICAN_ORIGIN_PORT=$ORIGIN_PORT
export PELICAN_TLSSKIPVERIFY=true
export PELICAN_SERVER_ENABLEUI=false
export PELICAN_ORIGIN_RUNLOCATION=/tmp/pelican-test/stat_test/xrootdRunLocation

export PELICAN_CONFIGDIR=/tmp/pelican-test/stat_test
export PELICAN_REGISTRY_DBLOCATION=/tmp/pelican-test/stat_test/test-registry.sql
export PELICAN_DIRECTOR_DBLOCATION=/tmp/pelican-test/stat_test/test-director.sql
export PELICAN_OIDC_CLIENTID="sometexthere"
export PELICAN_OIDC_CLIENTSECRETFILE=/tmp/pelican-test/stat_test/oidc-secret
echo "Placeholder OIDC secret" > /tmp/pelican-test/stat_test/oidc-secret

export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="/tmp/pelican-test/stat_test/origin"
export PELICAN_ORIGIN_ENABLEPUBLICREADS=true
export PELICAN_DIRECTOR_STATTIMEOUT=1s
export PELICAN_LOGGING_LEVEL=debug

# Function to cleanup after test ends
cleanup() {
    local pid=$1  # Get the PID from the function argument
    echo "Cleaning up..."
    if [ ! -z "$pid" ]; then
        echo "Sending SIGINT to PID $pid"
        kill -SIGINT "$pid"
    else
        echo "No PID provided for cleanup."
    fi

    # Clean up temporary files
    rm -rf /tmp/pelican-test/stat_test

    unset PELICAN_CONFIGDIR
    unset PELICAN_FEDERATION_DIRECTORURL
    unset PELICAN_FEDERATION_REGISTRYURL
    unset PELICAN_TLSSKIPVERIFY
    unset PELICAN_REGISTRY_DBLOCATION
    unset PELICAN_DIRECTOR_DBLOCATION
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

echo "This is some random content in the random file" > /tmp/pelican-test/stat_test/origin/input.txt

# Prepare token for calling stat
TOKEN=$(./pelican origin token create --audience "https://wlcg.cern.ch/jwt/v1/any" --issuer "https://`hostname`:$WEBUI_PORT" --scope "web_ui.access" --subject "bar" --lifetime 3600 --private-key /tmp/pelican-test/stat_test/issuer.jwk)

# Run federation in the background
federationServe="./pelican serve --module director --module registry --module origin --port $WEBUI_PORT"
$federationServe &
pid_federationServe=$!

# Setup trap with the PID as an argument to the cleanup function
trap 'cleanup $pid_federationServe' EXIT

# Give the federation time to spin up:
API_URL="https://$HOSTNAME:$WEBUI_PORT/api/v1.0/health"
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

while check_response; [ $? -ne 0 ]
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

STAT_URL="https://$HOSTNAME:$WEBUI_PORT/api/v1.0/director_ui/servers/origins/stat/test/input.txt"

RESPONSE=$(curl -k -H "Cookie: login=$TOKEN" -H "Content-Type: application/json" "$STAT_URL")

if echo "$RESPONSE" | grep -q "\"status\":\"success\""; then
    echo "Desired response received: $RESPONSE"
    echo "Test Succeeded"
    exit 0
else
    echo "Stat response returns error: $RESPONSE"
    echo "Test Failed"
    exit 1
fi
