#!/bin/bash -xe
#
# Copyright (C) 2024, Morgridge Institute for Research
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

# This test the functionaliy of the x509 defer check
# Some prefixes allow for x509 authentication rather than using tokens, this tests
# that a file that requires authorization is retreivable when using either x509 authentication or a token
# and also tests that files that aren't allowed to use x509 authentication are not retreivable

mkdir -p x509/config
chmod 777 x509/config

mkdir -p x509/origin
chmod 777 x509/origin

mkdir -p x509/defer
chmod 777 x509/defer

# Setup env variables needed
export PELICAN_FEDERATION_DIRECTORURL="https://$HOSTNAME:8444"
export PELICAN_FEDERATION_REGISTRYURL="https://$HOSTNAME:8444"
export PELICAN_TLSSKIPVERIFY=false
export PELICAN_ORIGIN_ENABLEDIRECTREADS=false
export PELICAN_SERVER_ENABLEUI=false
export PELICAN_ORIGIN_RUNLOCATION=$PWD/xrootdRunLocation
export PELICAN_CACHE_RUNLOCATION=$PWD/xrootdCacheRunLocation
export PELICAN_CONFIGDIR=$PWD/x509/config
export PELICAN_REGISTRY_DBLOCATION=$PWD/x509/config/test.sql
export PELICAN_OIDC_CLIENTID="sometexthere"
export PELICAN_ORIGIN_EXPORTVOLUMES="$PWD/x509/origin:/test $PWD/x509/defer:/defer/"
export PELICAN_DIRECTOR_X509CLIENTAUTHENTICATIONPREFIXES="/defer"

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
    rm -rf x509
    rm -rf xrootdRunLocation
    rm -rf xrootdCacheRunLocation

    unset PELICAN_FEDERATION_DIRECTORURL
    unset PELICAN_FEDERATION_REGISTRYURL
    unset PELICAN_TLSSKIPVERIFY
    unset PELICAN_ORIGIN_EXPORTVOLUMES
    unset PELICAN_SERVER_ENABLEUI
    unset PELICAN_OIDC_CLIENTID
    unset PELICAN_ORIGIN_ENABLEDIRECTREADS
    unset PELICAN_DIRECTOR_X509CLIENTAUTHENTICATIONPREFIXES
}

# Make a file to use for testing
echo "This is some random content in the random file" > ./x509/input.txt

# Ensure we're running in a clean environment
rm -rf /etc/pelican/pelican.yaml
rm -rf /run/pelican

if [ ! -f ./pelican ]; then
  echo "Pelican executable does not exist in $PWD. Exiting.."
  exit 1
fi

# Make a token to be used
./pelican origin token create --audience "https://wlcg.cern.ch/jwt/v1/any" --issuer "https://`hostname`:8444" --scope "storage.read:/ storage.modify:/" --subject "origin"  --claim wlcg.ver=1.0 --lifetime 1200 --private-key x509/config/issuer.jwk > x509/test-token.jwt

echo "Token created"
cat x509/test-token.jwt


mkdir -p x509/config/xrootd
echo "u $(openssl x509 -in x509/config/certificates/tls.crt -noout -hash).0 /defer lr" > x509/config/xrootd/authfile

# Copy the test file into the origin at both locations
cp x509/input.txt x509/origin/input.txt
cp x509/input.txt x509/defer/input.txt

chmod 777 x509/origin/input.txt
chmod 777 x509/defer/input.txt

# Run federation in the background
federationServe="./pelican serve --module director --module registry --module origin --module cache -d"
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
    sleep 1
    TOTAL_SLEEP_TIME=$((TOTAL_SLEEP_TIME + 1))

    # Break loop if we sleep for more than 10 seconds
    if [ "$TOTAL_SLEEP_TIME" -gt 20 ]; then
        echo "Total sleep time exceeded, exiting..."
        echo "TEST FAILED"
        exit 1
    fi
done

# Run a curl with a token and no x509 (should still work)
curl -v -k -L https://localhost:8444/defer/input.txt -H "Authorization: Bearer $(cat x509/test-token.jwt)" &> x509/curlTokenOutput.txt

# Check output of command
if grep -q "HTTP/1.1 200 OK" x509/curlTokenOutput.txt; then
    echo "Downloaded bytes successfully!"
else
    echo "Did not download correctly"
    cat x509/curlTokenOutput.txt
    exit 1
fi

# Run a curl with a good x509 value to defer
curl -v -k -L https://localhost:8444/defer/input.txt --tlsv1.3 --cert x509/config/certificates/tls.crt --key x509/config/certificates/tls.key &> x509/curlX509Output.txt

# Check output of command
if grep -q "HTTP/1.1 200 OK" x509/curlX509Output.txt; then
    echo "Downloaded bytes successfully!"
else
    echo "Did not download correctly"
    cat x509/curlX509Output.txt
    exit 1
fi

# Run a curl with an x509 value on a non defered namespace prefix
curl -v -k -L https://localhost:8444/test/input.txt --tlsv1.3 --cert x509/config/certificates/tls.crt --key x509/config/certificates/tls.key &> x509/badCurlX509Output.txt

# Check output of command
if grep -q "Unable to open /test/input.txt; permission denied" x509/badCurlX509Output.txt; then
    echo "Correctly denied access!"
else
    echo "Encountered an unexpected error"
    cat x509/badCurlX509Output.txt
    exit 1
fi


# Run a curl with an x509 value on a non deferred namespace prefix with a token
curl -v -k -L https://localhost:8444/test/input.txt --tlsv1.3 --cert x509/config/certificates/tls.crt --key x509/config/certificates/tls.key -H "Authorization: Bearer $(cat x509/test-token.jwt)" &> x509/fallbackTokenOutput.txt

# Check output of command
if grep -q "HTTP/1.1 200 OK" x509/fallbackTokenOutput.txt; then
    echo "Downloaded bytes successfully!"
else
    echo "Did not download correctly"
    cat x509/fallbackTokenOutput.txt
    exit 1
fi

exit 0
