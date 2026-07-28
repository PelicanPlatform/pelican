#!/usr/bin/env bash
#
# Start a TWO-process federation for the WS5 origin-UI-proxy Playwright project:
#   - a director+registry on :8444 (the public front door / test baseURL), and
#   - a SEPARATE broker-mode posixv2 origin on :8445 (the "firewalled" origin the
#     admin can only reach through the director's proxy).
#
# Unlike the single-process e2e legs, WS5 fundamentally needs two processes with
# distinct issuers so the director genuinely proxies a remote origin's UI/API over
# the broker. Each process is fully isolated (own config dir, keys, db, runtime
# dir) so they don't collide.
#
# Usage: start-origin-ui-proxy-fed.sh <pelican-server-binary> <work-dir> [password]
# On success prints "VIEW_ORIGIN_ID=<serverId>" (the broker origin's ServerID) so
# the caller can hand it to the Playwright project via PELICAN_VIEW_ORIGIN_ID.
set -euo pipefail

BIN=${1:?path to pelican-server binary required}
ROOT=${2:?work directory required}
PASSWORD=${3:-password}

DIR_CFG="$ROOT/director"
ORG_CFG="$ROOT/origin"
ORG_DATA="$ROOT/origin-data"
mkdir -p "$DIR_CFG" "$ORG_CFG" "$ORG_DATA" "$ORG_CFG/run" "$ORG_CFG/xdg"
echo "hello-from-broker-origin" > "$ORG_DATA/hello.txt"
printf '%s' "$PASSWORD" > "$ROOT/pw.txt"

"$BIN" generate password --password "$ROOT/pw.txt" --output "$DIR_CFG/server-web-passwd" >/dev/null 2>&1
"$BIN" generate password --password "$ROOT/pw.txt" --output "$ORG_CFG/server-web-passwd" >/dev/null 2>&1

cat > "$DIR_CFG/pelican.yaml" <<EOF
TLSSkipVerify: true
Logging: { Level: info, LogLocation: $ROOT/director.log }
Server: { HostName: localhost, WebPort: 8444, AUPFile: none }
Director: { EnableBroker: true }
Federation: { DiscoveryUrl: https://localhost:8444 }
EOF

cat > "$ORG_CFG/pelican.yaml" <<EOF
TLSSkipVerify: true
Logging: { Level: info, LogLocation: $ROOT/origin.log }
Server: { HostName: localhost, WebPort: 8445, AUPFile: none }
Origin:
  StorageType: posixv2
  EnableBroker: true
  DirectorTest: false
  RunLocation: $ORG_CFG/run
  DbLocation: $ORG_CFG/origin.sqlite
  Exports:
    - FederationPrefix: /test/ws5
      StoragePrefix: $ORG_DATA
      Capabilities: [Reads, Listings, PublicReads]
Federation: { DiscoveryUrl: https://localhost:8444 }
EOF

start() { # name configdir module
  env PELICAN_CONFIGBASE="$2" HOME="$2" XDG_RUNTIME_DIR="$2/xdg" \
    "$BIN" serve --config "$2/pelican.yaml" --module "$3" > "$ROOT/$1.stdout" 2>&1 &
  echo $! > "$ROOT/$1.pid"
}

wait_health() { # url name
  for _ in $(seq 1 60); do
    kill -0 "$(cat "$ROOT/$2.pid")" 2>/dev/null || { echo "$2 died" >&2; tail -30 "$ROOT/$2.stdout" "$ROOT/$2.log" >&2 2>/dev/null; return 1; }
    curl -sk "$1/api/v1.0/health" >/dev/null 2>&1 && return 0
    sleep 2
  done
  echo "$2 not ready" >&2; tail -30 "$ROOT/$2.stdout" "$ROOT/$2.log" >&2 2>/dev/null; return 1
}

# Director MUST be up before the origin starts (the origin fetches federation
# metadata from it at boot).
start director "$DIR_CFG" director,registry
wait_health https://localhost:8444 director
start origin "$ORG_CFG" origin
wait_health https://localhost:8445 origin

# Wait for the origin to register and advertise its broker URL to the director.
ID=""
for _ in $(seq 1 60); do
  ADS=$(curl -sk https://localhost:8444/api/v1.0/director_ui/servers 2>/dev/null || true)
  if echo "$ADS" | grep -q '"brokerUrl":"https'; then
    ID=$(echo "$ADS" | python3 -c 'import sys,json; print(next(s["serverId"] for s in json.load(sys.stdin) if s.get("type")=="Origin" and s.get("brokerUrl")))')
    break
  fi
  sleep 2
done
[ -n "$ID" ] || { echo "origin did not register a broker URL" >&2; exit 1; }
echo "VIEW_ORIGIN_ID=$ID"
