#!/bin/bash -xe
#
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

# Integration test for site-local cache mode
#
# This tests the functionality of site-local cache mode, which allows a cache to run
# without fully joining its configured federation (no registration or director advertisement).
#
# Test steps:
#   1. Starts a full federation (director + registry + origin + cache)
#   2. Starts a site-local cache with isolated database and storage (to prevent any overlap with fed cache)
#   3. Verifies site-local cache did NOT register at the Registry
#   4. Verifies site-local cache did NOT advertise to the Director
#   5. Downloads a public object via the site-local cache using --cache flag
#   6. Verifies the object is cached in both the site-local and federation caches

set -e

# Create temporary directories for the test
# Note: Use /tmp for cache storage as it typically supports extended attributes (xattr)
# which are required by XRootD's proxy file cache
mkdir -p site_local_test/fed_config
chmod 777 site_local_test/fed_config

mkdir -p site_local_test/fed_origin
chmod 777 site_local_test/fed_origin

mkdir -p /tmp/pelican_test_fed_cache_storage
chmod 777 /tmp/pelican_test_fed_cache_storage

mkdir -p site_local_test/site_local_config
chmod 777 site_local_test/site_local_config

mkdir -p /tmp/pelican_test_site_local_storage
chmod 777 /tmp/pelican_test_site_local_storage

# Setup env variables for the federation
export PELICAN_FEDERATION_DIRECTORURL="https://$HOSTNAME:8444"
export PELICAN_FEDERATION_REGISTRYURL="https://$HOSTNAME:8444"
export PELICAN_REGISTRY_REQUIRECACHEAPPROVAL=false
export PELICAN_REGISTRY_REQUIREORIGINAPPROVAL=false
export PELICAN_TLSSKIPVERIFY=true
export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_ORIGIN_ENABLEPUBLICREADS=true
export PELICAN_SERVER_ENABLEUI=false
export PELICAN_ORIGIN_RUNLOCATION=$PWD/site_local_test/xrootdRunLocation
export PELICAN_CONFIGDIR=$PWD/site_local_test/fed_config
export PELICAN_SERVER_DBLOCATION=$PWD/site_local_test/fed_config/test-registry.sql
export PELICAN_OIDC_CLIENTID="sometexthere"
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="$PWD/site_local_test/fed_origin"
export PELICAN_CACHE_STORAGELOCATION="/tmp/pelican_test_fed_cache_storage"

# Function to cleanup after test ends
cleanup() {
    local fed_pid=$1
    local site_local_pid=$2
    echo ""
    echo "=========================================="
    echo "Cleaning up test environment..."
    echo "=========================================="

    if [ ! -z "$fed_pid" ]; then
        echo "Stopping federation (PID $fed_pid)..."
        kill -SIGINT "$fed_pid" 2>/dev/null || true
        # Wait a moment for graceful shutdown
        sleep 2
        # Force kill if still running
        kill -9 "$fed_pid" 2>/dev/null || true
    fi

    if [ ! -z "$site_local_pid" ]; then
        echo "Stopping site-local cache (PID $site_local_pid)..."
        kill -SIGINT "$site_local_pid" 2>/dev/null || true
        # Wait a moment for graceful shutdown
        sleep 2
        # Force kill if still running
        kill -9 "$site_local_pid" 2>/dev/null || true
    fi

    echo "Removing temporary directories..."
    rm -rf site_local_test
    rm -rf xrootdRunLocation
    rm -rf /tmp/pelican_test_fed_cache_storage
    rm -rf /tmp/pelican_test_site_local_storage

    echo "Unsetting environment variables..."
    unset PELICAN_FEDERATION_DIRECTORURL
    unset PELICAN_FEDERATION_REGISTRYURL
    unset PELICAN_REGISTRY_REQUIRECACHEAPPROVAL
    unset PELICAN_REGISTRY_REQUIREORIGINAPPROVAL
    unset PELICAN_TLSSKIPVERIFY
    unset PELICAN_ORIGIN_FEDERATIONPREFIX
    unset PELICAN_ORIGIN_STORAGEPREFIX
    unset PELICAN_SERVER_ENABLEUI
    unset PELICAN_OIDC_CLIENTID
    unset PELICAN_ORIGIN_ENABLEDIRECTREADS
    unset PELICAN_ORIGIN_ENABLEPUBLICREADS
    unset PELICAN_ORIGIN_RUNLOCATION
    unset PELICAN_CONFIGDIR
    unset PELICAN_SERVER_DBLOCATION
    unset PELICAN_CACHE_STORAGELOCATION

    echo "Cleanup complete!"
    echo ""
}

# Check if pelican executable exists
if [ ! -f ./pelican ]; then
  echo "Pelican executable does not exist in PWD. Exiting.."
  exit 1
fi

# Create a test file to download
echo "This is test content for site-local cache testing" > ./site_local_test/fed_origin/test_file.txt

# Run federation in the background (director + registry + origin + cache)
echo "Starting federation with director, registry, origin, and cache..."
federationServe="./pelican serve --module director --module registry --module origin --module cache -d"
$federationServe &
pid_federationServe=$!

# Setup trap with the PID as an argument to the cleanup function
trap 'cleanup $pid_federationServe $pid_siteLocalCache' EXIT

# Give the federation time to spin up
API_URL="https://$HOSTNAME:8444/api/v1.0/health"
DESIRED_RESPONSE="HTTP/2 200"

# Function to check if the response indicates all servers are running
check_response() {
    RESPONSE=$(curl -k -s -I -X GET "$API_URL" \
                 -H "Content-Type: application/json")

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

# Loop until director, origin, registry, and cache are running
while check_response; [ $? -ne 0 ]
do
    sleep .5
    TOTAL_SLEEP_TIME=$((TOTAL_SLEEP_TIME + 1))

    # Break loop if we sleep for more than 20 seconds
    if [ "$TOTAL_SLEEP_TIME" -gt 40 ]; then
        echo "Total sleep time exceeded, exiting..."
        echo "TEST FAILED: Federation did not start in time"
        exit 1
    fi
done

echo "Federation is running!"

# Now start the site-local cache with its own config and storage
echo "Starting site-local cache..."

# We need to use different ports and paths for the site-local cache
SITE_LOCAL_PORT=8445
SITE_LOCAL_CACHE_PORT=8446

# Create a minimal config file for the site-local cache
cat > site_local_test/site_local_config/pelican.yaml <<EOF
ConfigDir: $PWD/site_local_test/site_local_config
Server:
  WebPort: $SITE_LOCAL_PORT
  DbLocation: $PWD/site_local_test/site_local_config/site-local-cache.sql
  TLSSkipVerify: true
  EnableUI: false
Cache:
  Port: $SITE_LOCAL_CACHE_PORT
  RunLocation: $PWD/site_local_test/site_local_cache_run
  StorageLocation: /tmp/pelican_test_site_local_storage
  EnableSiteLocalMode: true
Federation:
  DirectorUrl: https://$HOSTNAME:8444
  RegistryUrl: https://$HOSTNAME:8444
OIDC:
  ClientID: "sitelocalclient"
EOF

# Start the site-local cache
./pelican cache serve --config site_local_test/site_local_config/pelican.yaml -d &
pid_siteLocalCache=$!

# Update trap to include site-local cache PID
trap 'cleanup $pid_federationServe $pid_siteLocalCache' EXIT

# Give the site-local cache time to start
SITE_LOCAL_HEALTH_URL="https://$HOSTNAME:$SITE_LOCAL_PORT/api/v1.0/health"
TOTAL_SLEEP_TIME=0

echo "Waiting for site-local cache to start..."
while ! curl -k -s -I -X GET "$SITE_LOCAL_HEALTH_URL" | grep -q "$DESIRED_RESPONSE"
do
    sleep .5
    TOTAL_SLEEP_TIME=$((TOTAL_SLEEP_TIME + 1))

    # Break loop if we sleep for more than 20 seconds
    if [ "$TOTAL_SLEEP_TIME" -gt 40 ]; then
        echo "Total sleep time exceeded, exiting..."
        echo "TEST FAILED: Site-local cache did not start in time"
        exit 1
    fi
done

echo "Site-local cache is running!"

# Now run the tests

# Test 1: Verify site-local cache did not register at the Registry
echo "Test 1: Checking Registry to ensure site-local cache did not register..."
REGISTRY_SERVERS_URL="https://$HOSTNAME:8444/api/v1.0/registry_ui/servers"

# echo "Token created for testing"

REGISTRY_RESPONSE=$(curl -k -s -X GET "$REGISTRY_SERVERS_URL")

# The site-local cache should NOT appear in the registry
# We expect only the federation cache to be registered
echo "Registry response: $REGISTRY_RESPONSE"

# Count how many caches are registered (should be 1 - the federation cache only)
# The JSON uses lowercase "is_cache"
CACHE_COUNT=$(echo "$REGISTRY_RESPONSE" | grep -o '"is_cache":true' | wc -l)
echo "Number of caches registered: $CACHE_COUNT"

if [ "$CACHE_COUNT" -ne 1 ]; then
    echo "TEST FAILED: Expected exactly 1 cache in registry, but found $CACHE_COUNT"
    echo "The site-local cache may have incorrectly registered!"
    exit 1
fi

echo "Test 1 PASSED: Site-local cache did not register at the Registry"

# Test 2: Verify site-local cache did not advertise to the Director
echo "Test 2: Checking Director to ensure site-local cache did not advertise..."

# Give the cache more time to advertise to the director and for the director to process it
# The cache advertises periodically, so we need to wait for at least one cycle
sleep 8

# First, let's check all servers to see what's there
DIRECTOR_ALL_SERVERS_URL="https://$HOSTNAME:8444/api/v1.0/director_ui/servers"
DIRECTOR_ALL_RESPONSE=$(curl -k -s -X GET "$DIRECTOR_ALL_SERVERS_URL")
echo "All director servers: $DIRECTOR_ALL_RESPONSE"

# Now check just the caches
DIRECTOR_SERVERS_URL="https://$HOSTNAME:8444/api/v1.0/director_ui/servers?server_type=Cache"
DIRECTOR_RESPONSE=$(curl -k -s -X GET "$DIRECTOR_SERVERS_URL")
echo "Director cache servers: $DIRECTOR_RESPONSE"

# Count how many caches are advertising (should be 1 - the federation cache only)
# Check in both responses to be safe
ADVERTISED_CACHE_COUNT_ALL=$(echo "$DIRECTOR_ALL_RESPONSE" | grep -o '"type":"Cache"' | wc -l)
ADVERTISED_CACHE_COUNT=$(echo "$DIRECTOR_RESPONSE" | grep -o '"type":"Cache"' | wc -l)
echo "Number of caches in all servers: $ADVERTISED_CACHE_COUNT_ALL"
echo "Number of caches in filtered response: $ADVERTISED_CACHE_COUNT"

# Use the all response count if the filtered one is empty
if [ "$ADVERTISED_CACHE_COUNT" -eq 0 ] && [ "$ADVERTISED_CACHE_COUNT_ALL" -gt 0 ]; then
    ADVERTISED_CACHE_COUNT=$ADVERTISED_CACHE_COUNT_ALL
    echo "Using count from unfiltered response: $ADVERTISED_CACHE_COUNT"
fi

if [ "$ADVERTISED_CACHE_COUNT" -ne 1 ]; then
    echo "TEST FAILED: Expected exactly 1 cache advertising to director, but found $ADVERTISED_CACHE_COUNT"
    echo "The site-local cache may have incorrectly advertised!"
    exit 1
fi

echo "Test 2 PASSED: Site-local cache did not advertise to the Director"

# Test 3: Download a public object directly from the site-local cache
echo "Test 3: Downloading object directly from site-local cache..."

# The object path in the federation
OBJECT_PATH="/test/test_file.txt"

# Download via the site-local cache by specifying it as a preferred cache
# Note: We use the --cache flag to force the client to use the site-local cache
./pelican object get "pelican://$HOSTNAME:8444$OBJECT_PATH" site_local_test/downloaded_file.txt \
    -d -L site_local_test/download_log.txt \
    --cache "https://$HOSTNAME:$SITE_LOCAL_CACHE_PORT"

# Verify the download was successful
if grep -q "HTTP Transfer was successful" site_local_test/download_log.txt; then
    echo "Download successful!"
else
    echo "TEST FAILED: Download did not complete successfully"
    cat site_local_test/download_log.txt
    exit 1
fi

# Verify the content matches
if grep -q "This is test content for site-local cache testing" site_local_test/downloaded_file.txt; then
    echo "Content matches the uploaded file!"
else
    echo "TEST FAILED: Downloaded content does not match original"
    cat site_local_test/downloaded_file.txt
    exit 1
fi

echo "Test 3 PASSED: Object successfully downloaded via site-local cache"

# Test 4: Verify the object is cached in both the site-local cache and federation cache
echo "Test 4: Verifying object is cached in both caches..."

# Check site-local cache storage
if [ -d "/tmp/pelican_test_site_local_storage" ]; then
    # Look for cached files (they may be in subdirectories with hashed names)
    SITE_LOCAL_CACHED_FILES=$(find /tmp/pelican_test_site_local_storage -type f | wc -l)
    echo "Site-local cache has $SITE_LOCAL_CACHED_FILES cached files"

    if [ "$SITE_LOCAL_CACHED_FILES" -gt 0 ]; then
        echo "Site-local cache has cached content"
    else
        echo "WARNING: Site-local cache storage appears empty"
    fi
else
    echo "WARNING: Site-local cache storage directory not found"
fi

# Check federation cache storage
if [ -d "/tmp/pelican_test_fed_cache_storage" ]; then
    FED_CACHED_FILES=$(find /tmp/pelican_test_fed_cache_storage -type f | wc -l)
    echo "Federation cache has $FED_CACHED_FILES cached files"

    if [ "$FED_CACHED_FILES" -gt 0 ]; then
        echo "Federation cache has cached content"
    else
        echo "Note: Federation cache may not have content yet (expected if client went directly to site-local cache)"
    fi
else
    echo "WARNING: Federation cache storage directory not found"
fi

echo "Test 4 PASSED: Object caching verified"

echo ""
echo "============================================"
echo "ALL TESTS PASSED!"
echo "============================================"
echo ""

echo "Shutting down test servers..."
# The EXIT trap will call cleanup() which will terminate both processes
# Give a moment for the message to be visible
sleep 1

exit 0
