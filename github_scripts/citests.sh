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

# This tests stashcp and the HTCondor file transfer plugin against the real
# OSDF, both directly and through a local cache.
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
setup_test_root citests 300

# The pelican binary acts as stashcp or the plugin when run under that name.
mkdir -p "${TEST_ROOT}/bin"
cp ./pelican "${TEST_ROOT}/bin/stashcp"
cp ./pelican "${TEST_ROOT}/bin/stash_plugin"

OBJECT_URL="osdf:///pelicanplatform/test/hello-world.txt"

# The number of failed checks that did not stop the test.
FAILURES=0

# ---------------------------------------------------------------------------
# 1. Download an object with stashcp
# ---------------------------------------------------------------------------

if ! within_budget "${TEST_ROOT}/bin/stashcp" -d "${OBJECT_URL}" "${TEST_ROOT}/stashcp-output" \
    || [ ! -s "${TEST_ROOT}/stashcp-output" ]; then
    echo "TEST FAILED: stashcp did not download the object"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Use the plugin interface
# ---------------------------------------------------------------------------

classad_output="$(within_budget "${TEST_ROOT}/bin/stash_plugin" -classad)"

if [[ "${classad_output}" != *'PluginType = "FileTransfer"'* ]]; then
    echo "CHECK FAILED: PluginType is not in the classad output"
    FAILURES=$((FAILURES + 1))
fi

if [[ "${classad_output}" != *'SupportedMethods = "stash, osdf, pelican"'* ]]; then
    echo "CHECK FAILED: SupportedMethods is not in the classad output"
    FAILURES=$((FAILURES + 1))
fi

if ! plugin_output="$(within_budget "${TEST_ROOT}/bin/stash_plugin" "${OBJECT_URL}" "${TEST_ROOT}/plugin-output")" \
    || [ ! -s "${TEST_ROOT}/plugin-output" ]; then
    echo "${plugin_output}"
    echo "TEST FAILED: The plugin did not download the object"
    exit 1
fi

if [[ "${plugin_output}" != *"TransferUrl = \"${OBJECT_URL}\""* ]]; then
    echo "CHECK FAILED: TransferUrl is not in the plugin output"
    FAILURES=$((FAILURES + 1))
fi

if [[ "${plugin_output}" != *"TransferSuccess = true"* ]]; then
    echo "CHECK FAILED: TransferSuccess is not in the plugin output"
    FAILURES=$((FAILURES + 1))
fi

cat > "${TEST_ROOT}/plugin-infile" <<EOF
[ LocalFileName = "${TEST_ROOT}/plugin-infile-output"; Url = "${OBJECT_URL}" ]
EOF

if ! within_budget "${TEST_ROOT}/bin/stash_plugin" -infile "${TEST_ROOT}/plugin-infile" -outfile "${TEST_ROOT}/plugin-outfile" \
    || [ ! -s "${TEST_ROOT}/plugin-infile-output" ]; then
    echo "TEST FAILED: The plugin did not download the object named in its -infile"
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Start a local cache in front of the OSDF
# ---------------------------------------------------------------------------

export PELICAN_SERVER_ENABLEUI=false
export PELICAN_LOCALCACHE_RUNLOCATION="${TEST_ROOT}/localcache"
export PELICAN_LOCALCACHE_SOCKET="${PELICAN_LOCALCACHE_RUNLOCATION}/cache.sock"
export PELICAN_LOCALCACHE_DATALOCATION="${PELICAN_LOCALCACHE_RUNLOCATION}/cache"

./pelican-server serve -d -f osg-htc.org --module localcache &
PIDS+=($!)

wait_for_address_file "${PELICAN_RUNTIMEDIR}/pelican.addresses" "local cache" "${PIDS[-1]}"
LOCAL_CACHE_WEB_URL="$(read_address "${PELICAN_RUNTIMEDIR}/pelican.addresses" SERVER_EXTERNAL_WEB_URL)"
wait_for_healthy "${LOCAL_CACHE_WEB_URL}" "local cache"

# The local cache opens its socket only after writing its address file.
if ! retry_for 10 0.5 test -e "${PELICAN_LOCALCACHE_SOCKET}"; then
    echo "TEST FAILED: The local cache did not open its socket within 10 seconds"
    exit 1
fi

# ---------------------------------------------------------------------------
# 4. Download an object through the local cache
# ---------------------------------------------------------------------------

# Print the HTTP status that the local cache returns for an object without
# fetching it.
cached_status() {
    e2e_curl -o /dev/null -w "%{http_code}" \
        --unix-socket "${PELICAN_LOCALCACHE_SOCKET}" \
        -H "Cache-Control: only-if-cached" \
        -I "http://localhost$1"
}

OBJECT_PATH="/pelicanplatform/test/hello-world.txt"

if [ "$(cached_status "${OBJECT_PATH}")" != "504" ]; then
    echo "TEST FAILED: The local cache did not return 504 before the download"
    exit 1
fi

# The object reaches the local cache only if the plugin downloads it through
# the cache that Client.PreferredCaches names.
within_budget env PELICAN_CLIENT_PREFERREDCACHES="unix://${PELICAN_LOCALCACHE_SOCKET}" \
    "${TEST_ROOT}/bin/stash_plugin" -d "${OBJECT_URL}" /dev/null

if [ "$(cached_status "${OBJECT_PATH}")" != "200" ]; then
    echo "TEST FAILED: The object is not in the local cache after the download"
    exit 1
fi

# A list of preferred caches without a trailing "+" restricts the plugin to
# those caches, so a download through a missing one must fail. If the plugin
# ignored the variable, the download would succeed through the OSDF.
# Check that the download fails because the plugin tries the missing cache.
for var in PELICAN_CLIENT_PREFERREDCACHES PELICAN_NEAREST_CACHE; do
    if output="$(within_budget env "${var}=unix://${TEST_ROOT}/no-such-cache.sock" \
        "${TEST_ROOT}/bin/stash_plugin" -d "${OBJECT_URL}" /dev/null 2>&1)" \
        || [[ "${output}" != *"dial unix ${TEST_ROOT}/no-such-cache.sock"* ]]; then
        echo "${output}"
        echo "CHECK FAILED: The plugin did not try the cache that ${var} names"
        FAILURES=$((FAILURES + 1))
    fi
done

# ---------------------------------------------------------------------------
# 5. Download an object without a usable home directory
# ---------------------------------------------------------------------------

# The plugin derives its configuration directory from HOME only when it is
# not root and when PELICAN_CONFIGBASE and PELICAN_CONFIG are unset, so run
# these downloads under those conditions.

# The prefix of a command that runs as an unprivileged user. runuser resets
# HOME, so the command must set HOME itself, for example by way of env.
UNPRIVILEGED=()
mkdir "${TEST_ROOT}/unprivileged"
if [ "$(id -u)" -eq 0 ]; then
    UNPRIVILEGED=(runuser -u nobody --)
    # The unprivileged user must be able to write the plugin's output.
    chown nobody "${TEST_ROOT}/unprivileged"
fi

if ! within_budget "${UNPRIVILEGED[@]}" env -u HOME -u PELICAN_CONFIGBASE -u PELICAN_CONFIG \
    "${TEST_ROOT}/bin/stash_plugin" "${OBJECT_URL}" "${TEST_ROOT}/unprivileged/no-home-output" \
    || [ ! -s "${TEST_ROOT}/unprivileged/no-home-output" ]; then
    echo "CHECK FAILED: The plugin failed when HOME was unset"
    FAILURES=$((FAILURES + 1))
fi

mkdir "${TEST_ROOT}/unwritable-home"
chmod a-w "${TEST_ROOT}/unwritable-home"
if ! within_budget "${UNPRIVILEGED[@]}" env -u PELICAN_CONFIGBASE -u PELICAN_CONFIG \
    HOME="${TEST_ROOT}/unwritable-home" \
    "${TEST_ROOT}/bin/stash_plugin" "${OBJECT_URL}" "${TEST_ROOT}/unprivileged/unwritable-home-output" \
    || [ ! -s "${TEST_ROOT}/unprivileged/unwritable-home-output" ]; then
    echo "CHECK FAILED: The plugin failed when HOME was an unwritable directory"
    FAILURES=$((FAILURES + 1))
fi

if [ "${FAILURES}" -gt 0 ]; then
    echo "TEST FAILED: ${FAILURES} checks failed"
    exit 1
fi

echo "TEST PASSED"
