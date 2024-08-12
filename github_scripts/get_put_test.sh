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

mkdir -p get_put_tmp/config
chmod 777 get_put_tmp/config

mkdir -p get_put_tmp/origin
chmod 777 get_put_tmp/origin

# Setup env variables needed
export PELICAN_FEDERATION_DIRECTORURL="https://$HOSTNAME:8444"
export PELICAN_FEDERATION_REGISTRYURL="https://$HOSTNAME:8444"
export PELICAN_TLSSKIPVERIFY=true
export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_SERVER_ENABLEUI=false
export PELICAN_ORIGIN_RUNLOCATION=$PWD/xrootdRunLocation
export PELICAN_CONFIGDIR=$PWD/get_put_tmp/config
export PELICAN_REGISTRY_DBLOCATION=$PWD/get_put_tmp/config/test.sql
export PELICAN_OIDC_CLIENTID="sometexthere"
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="$PWD/get_put_tmp/origin"

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
    rm -rf get_put_tmp
    rm -rf xrootdRunLocation

    unset PELICAN_FEDERATION_DIRECTORURL
    unset PELICAN_FEDERATION_REGISTRYURL
    unset PELICAN_TLSSKIPVERIFY
    unset PELICAN_ORIGIN_FEDERATIONPREFIX
    unset PELICAN_ORIGIN_STORAGEPREFIX
    unset PELICAN_SERVER_ENABLEUI
    unset PELICAN_OIDC_CLIENTID
    unset PELICAN_ORIGIN_ENABLEDIRECTREADS
}

# Make a file to use for testing
echo "This is some random content in the random file" > ./get_put_tmp/input.txt

if [ ! -f ./pelican ]; then
  echo "Pelican executable does not exist in PWD. Exiting.."
  exit 1
fi

# Make a token to be used
./pelican origin token create --audience "https://wlcg.cern.ch/jwt/v1/any" --issuer "https://`hostname`:8444" --scope "storage.read:/ storage.modify:/" --subject "origin"  --claim wlcg.ver=1.0 --lifetime 60 --private-key get_put_tmp/config/issuer.jwk > get_put_tmp/test-token.jwt

echo "Token created"
cat get_put_tmp/test-token.jwt

# Run federation in the background
federationServe="./pelican serve --module director --module registry --module origin -d"
$federationServe &
pid_federationServe=$!

# Setup trap with the PID as an argument to the cleanup function
trap 'cleanup $pid_federationServe' EXIT

# Give the federation time to spin up:
API_URL="https://$HOSTNAME:8444/api/v1.0/health"
DESIRED_RESPONSE="HTTP/2 200"

# Function to check if the response indicates all servers are running
check_response() {
    RESPONSE=$(curl -k -s -I -X GET "$API_URL" \
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

# Loop until director, origin, and registry are running
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

# Run pelican object put
./pelican object put ./get_put_tmp/input.txt pelican://$HOSTNAME:8444/test/input.txt -d -t get_put_tmp/test-token.jwt -l get_put_tmp/putOutput.txt

# Check output of command
if grep -q "Dumping response: HTTP/1.1 200 OK" get_put_tmp/putOutput.txt; then
    echo "Uploaded bytes successfully!"
else
    echo "Did not upload correctly"
    cat get_put_tmp/putOutput.txt
    exit 1
fi

./pelican object get pelican://$HOSTNAME:8444/test/input.txt get_put_tmp/output.txt -d -t get_put_tmp/test-token.jwt -l get_put_tmp/getOutput.txt

# Check output of command
if grep -q "HTTP Transfer was successful" get_put_tmp/getOutput.txt; then
    echo "Downloaded bytes successfully!"
else
    echo "Did not download correctly"
    cat get_put_tmp/getOutput.txt
    exit 1
fi

if grep -q "This is some random content in the random file" get_put_tmp/output.txt; then
    echo "Content matches the uploaded file!"
else
    echo "Did not download correctly, content in downloaded file is different from the uploaded file"
    echo "Contents of the downloaded file:"
    cat get_put_tmp/output.txt
    echo "Contents of uploaded file:"
    cat get_put_tmp/input.txt
    exit 1
fi

exit 0
