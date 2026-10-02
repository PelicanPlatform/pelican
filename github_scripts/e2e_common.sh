# shellcheck shell=bash
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

# The setup, cleanup, and helpers that the end-to-end scripts in this
# directory share. Each script sources this file before doing anything else.
#
# Each test has a time budget, which it passes to setup_test_root. The
# budget bounds only retry_for's waits, the requests made with e2e_curl,
# and the commands run with within_budget. Anything else that a test does,
# such as a plain command or a shell function, is bounded only by what it
# is built from. When the budget runs out, the test fails with a message
# naming what it was doing, so that a server that hangs fails the test
# instead of stalling it. Cleanup on exit is outside the budget and takes
# at most about 10 seconds.

# The scripts rely on errexit to stop at a failed command, so turn it on
# here, whether or not a script was run in a way that honors its shebang.
set -e

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Stop the test unless each of the given binaries is executable.
require_binaries() {
    local bin
    for bin in "$@"; do
        if [ ! -x "${bin}" ]; then
            echo "TEST FAILED: ${bin} does not exist or is not executable"
            exit 1
        fi
    done
}

# Usage: setup_test_root NAME BUDGET
#
# Start the test's budget of BUDGET seconds. Then create the test's
# temporary directory, TEST_ROOT, which is removed on exit, and point
# Pelican's files and ports into it.
setup_test_root() {
    E2E_BUDGET="$2"
    E2E_DEADLINE=$((SECONDS + E2E_BUDGET))

    # XRootD and the local cache limit the length of the paths to their
    # sockets, so keep this short.
    TEST_ROOT="$(mktemp -d "/tmp/pelican-$1.XXXXXX")"
    trap cleanup EXIT
    # The xrootd user must be able to reach the directories that XRootD
    # uses.
    chmod 755 "${TEST_ROOT}"

    # Keep Pelican's files and ports apart from those of other tests.
    # Run as root, Pelican would otherwise use system-wide paths, such
    # as /etc/pelican and /var/lib/pelican.
    export PELICAN_CONFIG="${TEST_ROOT}/pelican.yaml"
    export PELICAN_CONFIGBASE="${TEST_ROOT}/config"
    export PELICAN_RUNTIMEDIR="${TEST_ROOT}/runtime"
    export PELICAN_SERVER_DBLOCATION="${TEST_ROOT}/pelican.sqlite"
    export PELICAN_SERVER_DATABASEBACKUP_LOCATION="${TEST_ROOT}/backups"
    export PELICAN_MONITORING_DATALOCATION="${TEST_ROOT}/monitoring"
    export PELICAN_SERVER_WEBPORT=0
    touch "${PELICAN_CONFIG}"
    mkdir -p "${PELICAN_CONFIGBASE}" "${PELICAN_RUNTIMEDIR}"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# The PIDs of the servers that the test starts.
PIDS=()

# Print the PIDs of a process, its children, and its grandchildren,
# such as the XRootD processes that a Pelican server starts.
tree_pids() {
    local child
    echo "$1"
    for child in $(pgrep -P "$1" || true); do
        echo "${child}"
        pgrep -P "${child}" || true
    done
}

# Succeed if each of the given processes has exited.
has_exited() {
    local pid
    for pid in "$@"; do
        if kill -0 "${pid}" 2>/dev/null; then
            return 1
        fi
    done
}

# Stop the servers and their descendants, all at once. Send SIGINT first,
# so that Pelican can shut down cleanly, and then SIGKILL to whatever
# remains after 10 seconds. XRootD would keep running if only its parent
# were killed. A server that is still starting ignores SIGINT and may start
# more processes in the meantime, so look for descendants again.
# shellcheck disable=SC2329  # invoked indirectly via trap
cleanup() {
    local pid pids=()
    # Cleanup is outside the test's budget.
    unset E2E_DEADLINE
    for pid in "${PIDS[@]}"; do
        # shellcheck disable=SC2207  # PIDs have no spaces
        pids+=($(tree_pids "${pid}"))
        kill -INT "${pid}" 2>/dev/null || true
    done
    retry_for 10 0.5 has_exited "${PIDS[@]}" || true
    for pid in "${PIDS[@]}"; do
        # shellcheck disable=SC2207  # PIDs have no spaces
        pids+=($(tree_pids "${pid}"))
    done
    kill -9 "${pids[@]}" 2>/dev/null || true
    for pid in "${PIDS[@]}"; do
        wait "${pid}" 2>/dev/null || true
    done
    rm -rf "${TEST_ROOT}"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Print the number of seconds left in the test's budget.
time_left() {
    echo $((E2E_DEADLINE - SECONDS))
}

# Report that the test's budget ran out while it was running a command.
# Exiting from a command substitution ends only the subshell,
# so the message goes to stderr, where the caller can't capture it.
out_of_time() {
    echo "TEST FAILED: The test ran out of its ${E2E_BUDGET}-second budget while running: $*" >&2
}

# Run curl quietly, without verifying the servers' certificates, and with a
# time limit, so that a server that accepts a connection but never answers
# can't stall the test. The limit is 10 seconds, or whatever is left of the
# budget, if less.
e2e_curl() {
    local max_time=10 left
    if [ -n "${E2E_DEADLINE:-}" ]; then
        left="$(time_left)"
        if [ "${left}" -le 0 ]; then
            out_of_time curl "$@"
            return 1
        fi
        if [ "${left}" -lt "${max_time}" ]; then
            max_time="${left}"
        fi
    fi
    curl --connect-timeout 5 --max-time "${max_time}" -k -s "$@"
}

# Usage: within_budget COMMAND [ARG...]
#
# Run a command, and stop the test if the command does not finish within
# what is left of the budget. Otherwise, return the command's status. The
# command must be an executable, not a shell function.
within_budget() {
    local left status=0
    left="$(time_left)"
    if [ "${left}" -le 0 ]; then
        out_of_time "$@"
        exit 1
    fi
    # --foreground keeps the command in the test's process group, so that
    # Ctrl-C stops it too. In exchange, timeout stops only the command, not
    # any processes that it starts.
    timeout --foreground --kill-after=5 "${left}" "$@" || status=$?
    # timeout also returns 137 when something else, such as the OOM killer,
    # kills the command with SIGKILL, so check that the budget ran out.
    if { [ "${status}" -eq 124 ] || [ "${status}" -eq 137 ]; } \
        && [ "${SECONDS}" -ge "${E2E_DEADLINE}" ]; then
        out_of_time "$@"
        exit 1
    fi
    return "${status}"
}

# Usage: retry_for SECONDS INTERVAL COMMAND [ARG...]
#
# Run a command until it succeeds, sleeping INTERVAL seconds between
# attempts, and return 1 if it has not succeeded after SECONDS seconds.
# Stop the test if the budget runs out first. Bash ignores errexit while
# running the command, so a function used as the command must return the
# status that it means to.
retry_for() {
    local deadline=$((SECONDS + $1)) interval="$2"
    shift 2
    if [ -n "${E2E_DEADLINE:-}" ] && [ "${deadline}" -gt "${E2E_DEADLINE}" ]; then
        deadline="${E2E_DEADLINE}"
    fi
    until "$@"; do
        if [ "${SECONDS}" -ge "${deadline}" ]; then
            if [ -n "${E2E_DEADLINE:-}" ] && [ "${SECONDS}" -ge "${E2E_DEADLINE}" ]; then
                out_of_time "$@"
                exit 1
            fi
            return 1
        fi
        sleep "${interval}"
    done
}

# Succeed if a server has written its address file, and stop the test
# if the server has exited.
address_file_written() {
    local file="$1" label="$2" pid="$3"
    if [ -f "${file}" ]; then
        return 0
    fi
    if has_exited "${pid}"; then
        echo "TEST FAILED: The ${label} exited before writing its address file"
        exit 1
    fi
    return 1
}

# Wait up to 30 seconds, or until the budget runs out, if sooner, for a
# server to write its address file.
wait_for_address_file() {
    local file="$1" label="$2" pid="$3"
    echo "Waiting for the ${label} to write its address file: ${file}"
    if ! retry_for 30 0.5 address_file_written "${file}" "${label}" "${pid}"; then
        echo "TEST FAILED: The ${label} did not write its address file within 30 seconds"
        exit 1
    fi
}

# Print the value of a key in an address file. Reading it this way, rather
# than sourcing it, keeps one server's addresses from replacing another's.
read_address() {
    local value
    value="$(sed -n "s/^$2=//p" "$1")"
    if [ -z "${value}" ]; then
        echo "TEST FAILED: $1 has no $2" >&2
        return 1
    fi
    echo "${value}"
}

# Succeed if a server's health check does.
is_healthy() {
    [ "$(e2e_curl -o /dev/null -w "%{http_code}" "$1/api/v1.0/health")" = "200" ]
}

# Wait up to 30 seconds, or until the budget runs out, if sooner,
# for a server's health check to succeed.
wait_for_healthy() {
    local url="$1" label="$2"
    echo "Waiting for the ${label} to become healthy: ${url}/api/v1.0/health"
    if ! retry_for 30 0.5 is_healthy "${url}"; then
        echo "TEST FAILED: The ${label} did not become healthy within 30 seconds"
        exit 1
    fi
}
