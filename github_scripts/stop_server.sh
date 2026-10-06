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

# Sourced by the CI test scripts; not meant to be run on its own.

# stop_server PID [TIMEOUT_SECONDS]
#
# Asks a pelican server to shut down (SIGINT) and waits until it has exited.
# A server keeps writing under its config and runtime directories while it
# shuts down, so removing them before it is gone races those writes (and
# fails with "Directory not empty").  If the server has not exited after
# TIMEOUT_SECONDS (default 30), it and its direct children -- the XRootD
# daemons -- are killed.
stop_server() {
    local pid="$1"
    local timeout="${2:-30}"
    if [ -z "$pid" ] || ! kill -SIGINT "$pid" 2>/dev/null; then
        return 0 # never started, or already gone
    fi
    local polls=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$polls" -ge $((timeout * 2)) ]; then
            echo "Server PID $pid did not exit within ${timeout}s; killing it and its children"
            pkill -9 -P "$pid" 2>/dev/null || true
            kill -9 "$pid" 2>/dev/null || true
            break
        fi
        sleep 0.5
        polls=$((polls + 1))
    done
    # Reap it if it is our child, so it is fully gone before we return.
    wait "$pid" 2>/dev/null || true
}
