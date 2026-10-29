#!/bin/bash
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
# Starts a single-node dCache and runs Pelican's dCache tiering checks
# against it.  Usage: run.sh <work directory>
#
# It generates a throwaway CA, host certificate and token-issuer key
# (certs.sh), starts a minimal token issuer on the host (issuer.py), and
# starts dCache with Docker Compose (compose.yaml, project
# pelican-dcache-e2e, configured from dcache/).  Once the WebDAV door
# answers, it records how the door treats tokens and macaroons with curl
# (probe.sh), then runs the Go tests in local_cache/tier_dcache_e2e_test.go
# against it.  Logs land in <work directory>/logs, and the Compose project is
# removed on exit.  It needs Docker with Compose v2, Go, python3, openssl and
# curl; the dCache image is amd64-only, so on an arm64 machine it runs under
# emulation and takes a few minutes to start.  CI runs it from
# .github/workflows/dcache-e2e.yml.
#
# Environment:
#   DCACHE_E2E_KEEP=1     leave dCache and the issuer running afterwards
#   DCACHE_E2E_VERSION    dcache/dcache image tag (default in compose.yaml)
#   DCACHE_E2E_GO_TEST    go test selection (default -run=TestDCache)
#   DCACHE_E2E_SKIP_GO=1  stop after the curl probe
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=${1:?usage: run.sh <work directory>}
mkdir -p "$work"
work=$(cd "$work" && pwd)
logs=$work/logs
rm -rf "${logs:?}" "${work:?}/etc" "${work:?}/certs"
mkdir -p "$logs" "$work/etc"

project=pelican-dcache-e2e
issuer_port=${DCACHE_E2E_ISSUER_PORT:-8765}
# The containers reach the issuer, which runs on the host, by this name;
# compose.yaml maps it to the host gateway.  A token's iss must equal it.
issuer_url=http://host.docker.internal:$issuer_port
door=https://localhost:2880

compose() {
    DCACHE_E2E_ETC=$work/etc DCACHE_E2E_GRID_SECURITY=$work/certs/grid-security \
        docker compose -p "$project" -f "$here/compose.yaml" "$@"
}

issuer_pid=
collect_logs() {
    status=$?
    set +e
    echo "== Collecting logs (exit status $status)"
    compose ps -a >"$logs/compose-ps.txt" 2>&1
    compose logs --no-color --timestamps >"$logs/compose.log" 2>&1
    if [ -n "$(compose ps -q dcache 2>/dev/null)" ]; then
        compose cp dcache:/opt/dcache/var/log "$logs/dcache-var-log" >/dev/null 2>&1
    fi
    if [ -z "${DCACHE_E2E_KEEP:-}" ]; then
        [ -n "$issuer_pid" ] && kill "$issuer_pid" 2>/dev/null
        compose down -v --remove-orphans >/dev/null 2>&1
    fi
    exit "$status"
}
trap collect_logs EXIT

docker version >"$logs/docker-version.txt"
# A previous run left running with DCACHE_E2E_KEEP=1.
compose down -v --remove-orphans >/dev/null 2>&1 || true

echo "== Generating the CA, host certificate and issuer key"
bash "$here/certs.sh" "$work/certs"

echo "== Rendering the dCache configuration (issuer $issuer_url)"
for f in "$here"/dcache/*; do
    sed "s|@ISSUER_URL@|$issuer_url|g" "$f" >"$work/etc/$(basename "$f")"
done

echo "== Starting the token issuer on port $issuer_port"
python3 "$here/issuer.py" serve "$work/certs/issuer/key.pem" "$issuer_url" "$issuer_port" \
    >"$logs/issuer.log" 2>&1 &
issuer_pid=$!

echo "== Starting dCache"
start=$(date +%s)
compose up -d --quiet-pull 2>&1 | tee "$logs/compose-up.txt"

# The door answers once the domain is up; an unauthenticated request gets
# 401.  Under emulation (an arm64 workstation) startup takes minutes.
echo "== Waiting for the WebDAV door at $door"
deadline=$((start + ${DCACHE_E2E_START_TIMEOUT:-600}))
while :; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$work/certs/ca.pem" "$door/data/" || true)
    case $code in 401 | 200 | 207) break ;; esac
    if [ "$(date +%s)" -gt "$deadline" ]; then
        echo "The door did not come up (last status ${code:-none})" >&2
        exit 1
    fi
    if [ -z "$(compose ps --status running -q dcache)" ]; then
        echo "The dCache container exited" >&2
        exit 1
    fi
    sleep 5
done
echo "Door up after $(($(date +%s) - start))s (status $code)"

export DCACHE_E2E_WEBDAV_URL=$door
export DCACHE_E2E_CA_FILE=$work/certs/ca.pem
export DCACHE_E2E_ISSUER_URL=$issuer_url
export DCACHE_E2E_ISSUER_KEY=$work/certs/issuer/key.pem

echo "== Protocol probe with curl"
bash "$here/probe.sh" "$work" 2>&1 | tee "$logs/probe.txt"

if [ -n "${DCACHE_E2E_SKIP_GO:-}" ]; then
    exit 0
fi

echo "== Go tests against dCache"
cd "$repo"
set +e
# shellcheck disable=SC2086
go test -tags client,server -count=1 -v -timeout 20m ${DCACHE_E2E_GO_TEST:--run=TestDCache} ./local_cache/ \
    2>&1 | tee "$logs/go-test.txt"
status=${PIPESTATUS[0]}
set -e
echo "Total time $(($(date +%s) - start))s"
exit "$status"
