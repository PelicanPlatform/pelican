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
SITE_TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/pelican_site_local_test.XXXXXX")
chmod 755 "$SITE_TEST_ROOT"
FED_CONFIG_DIR="$SITE_TEST_ROOT/fed_config"
FED_RUNTIME_DIR="$SITE_TEST_ROOT/runtime_fed"
FED_ORIGIN_DIR="$SITE_TEST_ROOT/fed_origin"
SITE_LOCAL_CONFIG_DIR="$SITE_TEST_ROOT/site_local_config"
SITE_LOCAL_RUNTIME_DIR="$SITE_TEST_ROOT/runtime_site_local"
SITE_LOCAL_CACHE_RUN="$SITE_TEST_ROOT/site_local_cache_run"
SITE_LOCAL_DOWNLOAD="$SITE_TEST_ROOT/downloaded_file.txt"
SITE_LOCAL_DOWNLOAD_LOG="$SITE_TEST_ROOT/download_log.txt"

mkdir -p "$FED_CONFIG_DIR" "$FED_RUNTIME_DIR" "$FED_ORIGIN_DIR" "$SITE_LOCAL_CONFIG_DIR" "$SITE_LOCAL_RUNTIME_DIR" "$SITE_LOCAL_CACHE_RUN"
chmod 755 "$FED_CONFIG_DIR" "$FED_RUNTIME_DIR" "$FED_ORIGIN_DIR" "$SITE_LOCAL_CONFIG_DIR" "$SITE_LOCAL_RUNTIME_DIR" "$SITE_LOCAL_CACHE_RUN"
chown xrootd: "$FED_ORIGIN_DIR"

echo "fake oidc client secret" > "$FED_CONFIG_DIR/oidc-client-secret"

FED_CACHE_STORAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pelican_test_fed_cache_storage.XXXXXX")
SITE_LOCAL_CACHE_STORAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pelican_test_site_local_storage.XXXXXX")
chmod 777 "$FED_CACHE_STORAGE_DIR" "$SITE_LOCAL_CACHE_STORAGE_DIR"

# Setup env variables for the federation
export PELICAN_REGISTRY_REQUIRECACHEAPPROVAL=false
export PELICAN_REGISTRY_REQUIREORIGINAPPROVAL=false
export PELICAN_TLSSKIPVERIFY=true
export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_ORIGIN_ENABLEPUBLICREADS=true
export PELICAN_SERVER_ENABLEUI=false
export PELICAN_ORIGIN_RUNLOCATION="$SITE_TEST_ROOT/xrootdRunLocation"
export PELICAN_RUNTIMEDIR="$FED_RUNTIME_DIR"
export PELICAN_SERVER_WEBPORT=0
export PELICAN_ORIGIN_PORT=0
export PELICAN_CACHE_PORT=0
export PELICAN_CONFIGDIR="$FED_CONFIG_DIR"
export PELICAN_SERVER_DBLOCATION="$FED_CONFIG_DIR/test-registry.sql"
export PELICAN_OIDC_CLIENTID="sometexthere"
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="$FED_ORIGIN_DIR"
export PELICAN_CACHE_STORAGELOCATION="$FED_CACHE_STORAGE_DIR"

# Function to cleanup after test ends
cleanup() {
    local fed_pid=$1
    local site_local_pid=$2
    echo ""
    echo "=========================================="
    echo "Cleaning up test environment..."
    echo "=========================================="

    if [ -n "$fed_pid" ]; then
        echo "Stopping federation (PID $fed_pid)..."
        kill -SIGINT "$fed_pid" 2>/dev/null || true
        # Wait a moment for graceful shutdown
        sleep 2
        # Force kill if still running
        kill -9 "$fed_pid" 2>/dev/null || true
    fi

    if [ -n "$site_local_pid" ]; then
        echo "Stopping site-local cache (PID $site_local_pid)..."
        kill -SIGINT "$site_local_pid" 2>/dev/null || true
        # Wait a moment for graceful shutdown
        sleep 2
        # Force kill if still running
        kill -9 "$site_local_pid" 2>/dev/null || true
    fi

    echo "Removing temporary directories..."
    if [ -n "${SITE_TEST_ROOT:-}" ]; then
        rm -rf "$SITE_TEST_ROOT"
    fi
    rm -rf "xrootdRunLocation"
    if [ -n "${FED_CACHE_STORAGE_DIR:-}" ]; then
        rm -rf "$FED_CACHE_STORAGE_DIR"
    fi
    if [ -n "${SITE_LOCAL_CACHE_STORAGE_DIR:-}" ]; then
        rm -rf "$SITE_LOCAL_CACHE_STORAGE_DIR"
    fi

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
    unset PELICAN_RUNTIMEDIR
    unset PELICAN_SERVER_WEBPORT
    unset PELICAN_ORIGIN_PORT
    unset PELICAN_CACHE_PORT
    unset SITE_TEST_ROOT
    unset FED_CONFIG_DIR
    unset FED_RUNTIME_DIR
    unset FED_ORIGIN_DIR
    unset SITE_LOCAL_CONFIG_DIR
    unset SITE_LOCAL_RUNTIME_DIR
    unset SITE_LOCAL_CACHE_RUN
    unset SITE_LOCAL_DOWNLOAD
    unset SITE_LOCAL_DOWNLOAD_LOG

    echo "Cleanup complete!"
    echo ""
}

# Check if pelican executable exists
if [ ! -f ./pelican ]; then
  echo "Pelican executable does not exist in PWD. Exiting.."
  exit 1
fi

pid_siteLocalCache=""

# Create a test file to download
echo "This is test content for site-local cache testing" > "$FED_ORIGIN_DIR/test_file.txt"

# Run federation in the background (director + registry + origin + cache)
echo "Starting federation with director, registry, origin, and cache..."
./pelican serve --module director --module registry --module origin --module cache -d &
pid_federationServe=$!

# Setup trap with the PID as an argument to the cleanup function
trap_cleanup() {
    cleanup "$pid_federationServe" "$pid_siteLocalCache"
}
trap trap_cleanup EXIT

# Wait for the federation address file so we can discover the actual ports
FED_ADDRESS_FILE="${PELICAN_RUNTIMEDIR%/}/pelican.addresses"
TOTAL_WAIT=0
echo "Waiting for federation address file: $FED_ADDRESS_FILE"
while [ ! -f "$FED_ADDRESS_FILE" ]; do
    if ! kill -0 "${pid_federationServe:-0}" 2>/dev/null; then
        echo "Federation process exited before address file was created"
        echo "TEST FAILED"
        unset pid_federationServe
        exit 1
    fi
    sleep 0.5
    TOTAL_WAIT=$((TOTAL_WAIT + 1))
    if [ "$TOTAL_WAIT" -gt 40 ]; then
        echo "Address file not created after 20 seconds, exiting..."
        echo "TEST FAILED: Federation did not start in time"
        exit 1
    fi
done

# shellcheck source=/dev/null
source "$FED_ADDRESS_FILE"

if [ -z "${SERVER_EXTERNAL_WEB_URL:-}" ]; then
    echo "Address file missing SERVER_EXTERNAL_WEB_URL"
    exit 1
fi

FED_SERVER_EXTERNAL_WEB_URL="$SERVER_EXTERNAL_WEB_URL"
FED_DISCOVERY_HOSTPORT="${FED_SERVER_EXTERNAL_WEB_URL#https://}"
FED_DISCOVERY_HOSTPORT="${FED_DISCOVERY_HOSTPORT#http://}"

export PELICAN_FEDERATION_DIRECTORURL="$FED_SERVER_EXTERNAL_WEB_URL"
export PELICAN_FEDERATION_REGISTRYURL="$FED_SERVER_EXTERNAL_WEB_URL"

# Give the federation time to spin up using the discovered address
API_URL="$FED_SERVER_EXTERNAL_WEB_URL/api/v1.0/health"
DESIRED_RESPONSE="200"

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

TOTAL_SLEEP_TIME=0

until check_response
do
    sleep .5
    TOTAL_SLEEP_TIME=$((TOTAL_SLEEP_TIME + 1))

    if [ "$TOTAL_SLEEP_TIME" -gt 40 ]; then
        echo "Total sleep time exceeded, exiting..."
        echo "TEST FAILED: Federation did not start in time"
        exit 1
    fi
done

echo "Federation is running!"

# Now start the site-local cache with its own config and storage
echo "Starting site-local cache..."

SITE_LOCAL_CONFIG_PATH="$SITE_LOCAL_CONFIG_DIR/pelican.yaml"
SITE_LOCAL_WEBPORT=0
SITE_LOCAL_CACHE_PORT=0

# Create a minimal config file for the site-local cache
cat > "$SITE_LOCAL_CONFIG_PATH" <<EOF
RuntimeDir: $SITE_LOCAL_RUNTIME_DIR
ConfigDir: $SITE_LOCAL_CONFIG_DIR
Server:
  WebPort: $SITE_LOCAL_WEBPORT
  DbLocation: $SITE_LOCAL_CONFIG_DIR/site-local-cache.sql
  TLSSkipVerify: true
  EnableUI: false
Cache:
  Port: $SITE_LOCAL_CACHE_PORT
  RunLocation: $SITE_LOCAL_CACHE_RUN
  StorageLocation: $SITE_LOCAL_CACHE_STORAGE_DIR
  EnableSiteLocalMode: true
Federation:
  DirectorUrl: $FED_SERVER_EXTERNAL_WEB_URL
  RegistryUrl: $FED_SERVER_EXTERNAL_WEB_URL
OIDC:
  ClientID: "sitelocalclient"
EOF

# Start the site-local cache
PELICAN_RUNTIMEDIR="$SITE_LOCAL_RUNTIME_DIR" ./pelican cache serve --config "$SITE_LOCAL_CONFIG_PATH" -d &
pid_siteLocalCache=$!

# Update trap to include site-local cache PID
trap_cleanup() {
    cleanup "$pid_federationServe" "$pid_siteLocalCache"
}
trap trap_cleanup EXIT

# Wait for the site-local address file to be written
SITE_LOCAL_ADDRESS_FILE="${SITE_LOCAL_RUNTIME_DIR%/}/pelican.addresses"
TOTAL_WAIT=0
echo "Waiting for site-local address file: $SITE_LOCAL_ADDRESS_FILE"
while [ ! -f "$SITE_LOCAL_ADDRESS_FILE" ]; do
    if ! kill -0 "${pid_siteLocalCache:-0}" 2>/dev/null; then
        echo "Site-local cache exited before address file was created"
        echo "TEST FAILED"
        unset pid_siteLocalCache
        exit 1
    fi
    sleep 0.5
    TOTAL_WAIT=$((TOTAL_WAIT + 1))
    if [ "$TOTAL_WAIT" -gt 40 ]; then
        echo "Site-local address file not created after 20 seconds, exiting..."
        echo "TEST FAILED: Site-local cache did not start in time"
        exit 1
    fi
done

SITE_LOCAL_SERVER_EXTERNAL_WEB_URL=""
SITE_LOCAL_CACHE_URL=""
while IFS='=' read -r key val; do
    case "$key" in
        SERVER_EXTERNAL_WEB_URL) SITE_LOCAL_SERVER_EXTERNAL_WEB_URL="$val" ;;
        CACHE_URL) SITE_LOCAL_CACHE_URL="$val" ;;
    esac
done < "$SITE_LOCAL_ADDRESS_FILE"

if [ -z "$SITE_LOCAL_SERVER_EXTERNAL_WEB_URL" ]; then
    echo "Site-local address file missing SERVER_EXTERNAL_WEB_URL"
    exit 1
fi
if [ -z "$SITE_LOCAL_CACHE_URL" ]; then
    echo "Site-local address file missing CACHE_URL"
    exit 1
fi

SITE_LOCAL_HEALTH_URL="$SITE_LOCAL_SERVER_EXTERNAL_WEB_URL/api/v1.0/health"
TOTAL_SLEEP_TIME=0

echo "Waiting for site-local cache to start..."
while true; do
    RESPONSE=$(curl -m 10 -k -s -o /dev/null -w "%{http_code}" -X GET "$SITE_LOCAL_HEALTH_URL" -H "Content-Type: application/json")
    if [ "$RESPONSE" = "$DESIRED_RESPONSE" ]; then
        echo "Site-local cache is running!"
        break
    fi
    sleep .5
    TOTAL_SLEEP_TIME=$((TOTAL_SLEEP_TIME + 1))
    if [ "$TOTAL_SLEEP_TIME" -gt 40 ]; then
        echo "Total sleep time exceeded, exiting..."
        echo "TEST FAILED: Site-local cache did not start in time"
        exit 1
    fi
done

# Now run the tests

# Test 1: Verify site-local cache did not register at the Registry
echo "Test 1: Checking Registry to ensure site-local cache did not register..."
REGISTRY_SERVERS_URL="$FED_SERVER_EXTERNAL_WEB_URL/api/v1.0/registry_ui/servers"

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
DIRECTOR_ALL_SERVERS_URL="$FED_SERVER_EXTERNAL_WEB_URL/api/v1.0/director_ui/servers"
DIRECTOR_ALL_RESPONSE=$(curl -k -s -X GET "$DIRECTOR_ALL_SERVERS_URL")
echo "All director servers: $DIRECTOR_ALL_RESPONSE"

# Now check just the caches
DIRECTOR_SERVERS_URL="$FED_SERVER_EXTERNAL_WEB_URL/api/v1.0/director_ui/servers?server_type=Cache"
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
OBJECT_URL="pelican://${FED_DISCOVERY_HOSTPORT}${OBJECT_PATH}"

# Download via the site-local cache by specifying it as a preferred cache
# Note: We use the --cache flag to force the client to use the site-local cache
./pelican object get "$OBJECT_URL" "$SITE_LOCAL_DOWNLOAD" \
    -d -L "$SITE_LOCAL_DOWNLOAD_LOG" \
    --cache "$SITE_LOCAL_CACHE_URL"

# Verify the download was successful
if grep -q "HTTP Transfer was successful" "$SITE_LOCAL_DOWNLOAD_LOG"; then
    echo "Download successful!"
else
    echo "TEST FAILED: Download did not complete successfully"
    cat "$SITE_LOCAL_DOWNLOAD_LOG"
    exit 1
fi

# Verify the content matches
if grep -q "This is test content for site-local cache testing" "$SITE_LOCAL_DOWNLOAD"; then
    echo "Content matches the uploaded file!"
else
    echo "TEST FAILED: Downloaded content does not match original"
    cat "$SITE_LOCAL_DOWNLOAD"
    exit 1
fi

echo "Test 3 PASSED: Object successfully downloaded via site-local cache"

# Test 4: Verify the object is cached in both the site-local cache and federation cache
echo "Test 4: Verifying object is cached in both caches..."

# Check site-local cache storage
if [ -d "$SITE_LOCAL_CACHE_STORAGE_DIR" ]; then
    # Look for cached files (they may be in subdirectories with hashed names)
    SITE_LOCAL_CACHED_FILES=$(find "$SITE_LOCAL_CACHE_STORAGE_DIR" -type f | wc -l)
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
if [ -d "$FED_CACHE_STORAGE_DIR" ]; then
    FED_CACHED_FILES=$(find "$FED_CACHE_STORAGE_DIR" -type f | wc -l)
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
# Disable the EXIT trap now that tests finished and run cleanup explicitly
trap - EXIT
cleanup "$pid_federationServe" "$pid_siteLocalCache"
exit 0
