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
# Probes, with curl, how the dCache door treats WLCG tokens and macaroons, and
# prints what it saw: the evidence the Go test's assumptions rest on.  Tokens
# and macaroons are shown only by their first characters.  It does not fail
# on an unexpected answer -- the point is to record the answer -- except when
# dCache cannot store and serve a file at all.
#
# Usage: probe.sh <work directory>, with the DCACHE_E2E_* variables run.sh
# exports.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?usage: probe.sh <work directory>}
door=${DCACHE_E2E_WEBDAV_URL:?}
ca=${DCACHE_E2E_CA_FILE:?}
iss=${DCACHE_E2E_ISSUER_URL:?}
key=${DCACHE_E2E_ISSUER_KEY:?}
tmp=$work/probe
rm -rf "$tmp" && mkdir -p "$tmp"

# curl labels --data-binary bodies application/x-www-form-urlencoded, and
# dCache's Jetty parses a PUT with that type as a form, consuming the body
# (see the first probe below); upload with a neutral type.
put=(-X PUT -H 'Content-Type: application/octet-stream')

mint() { python3 "$here/issuer.py" mint "$key" "$iss" "$@"; }
mac() { python3 "$here/macaroon.py" "$@"; }
short() { printf '%s' "${1:0:6}..."; }

# req <label> <curl args...>: prints the status, the redirect target (minus
# its query) and a short body.
req() {
    local label=$1
    shift
    local out
    out=$(curl -s --cacert "$ca" -o "$tmp/body" -D "$tmp/headers" -w '%{http_code} %{num_redirects} %{url_effective}' "$@")
    local code=${out%% *} rest=${out#* }
    local redirects=${rest%% *} url=${rest#* }
    printf '  %-58s -> %s' "$label" "$code"
    [ "$redirects" != 0 ] && printf ' (after %s redirect(s), ended at %s)' "$redirects" "${url%%\?*}"
    local loc
    loc=$(grep -i '^location:' "$tmp/headers" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
    [ -n "$loc" ] && [ "$redirects" = 0 ] && printf ' Location: %s' "${loc%%\?*}"
    local reason
    reason=$(head -1 "$tmp/headers" | tr -d '\r' | cut -d' ' -f3-)
    [ -n "$reason" ] && printf ' [%s]' "$reason"
    echo
    LAST_CODE=$code
}

# macreq <label> <token> <path> <json>: requests a macaroon, prints the
# answer and the decoded caveats; leaves the macaroon in $MACAROON.
macreq() {
    local label=$1 token=$2 path=$3 body=$4
    MACAROON=
    req "$label: POST $path $body" -X POST -H "Authorization: Bearer $token" \
        -H 'Content-Type: application/macaroon-request' --data "$body" "$door$path"
    if [ "$LAST_CODE" = 200 ]; then
        MACAROON=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["macaroon"])' "$tmp/body")
        echo "    macaroon $(short "$MACAROON") caveats:"
        mac decode "$MACAROON" | grep -v '^signature\|^location\|^identifier' | sed 's/^/      /'
    else
        echo "    body: $(head -c 300 "$tmp/body" | tr '\n' ' ')"
    fi
}

future() { python3 -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%S.000Z"))' "$1"; }

full=$(mint pelican-cache 600 "storage.read:/ storage.create:/ storage.modify:/")
sub=$(mint pelican-cache 600 "storage.read:/pelican storage.create:/pelican storage.modify:/pelican")
plain=$(mint pelican-cache 600 "openid")
chroot=$(mint pelican-chroot 600 "openid")
echo "Tokens: full-scope $(short "$full"), sub-path $(short "$sub"), no storage scopes $(short "$plain")"

echo
echo "-- 0. Plain WebDAV with the tokens (does gPlazma accept them at all?)"
printf 'hello from the dCache e2e probe\n' >"$tmp/hello.txt"
for _ in $(seq 1 30); do
    req "PUT /data/pelican/hello.txt (full-scope token)" "${put[@]}" -H "Authorization: Bearer $full" \
        --data-binary @"$tmp/hello.txt" "$door/data/pelican/hello.txt"
    [ "$LAST_CODE" = 201 ] || [ "$LAST_CODE" = 204 ] && break
    echo "    (retrying: the pool may not have registered yet) $(head -c 200 "$tmp/body")"
    sleep 5
done
req "PUT /data/pelican/form.txt, Content-Type x-www-form-urlencoded" -X PUT -H "Authorization: Bearer $full" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$tmp/hello.txt" "$door/data/pelican/form.txt"
echo "    body: $(head -c 200 "$tmp/body")"
req "MKCOL /data/pelican/sub (sub-path token)" -X MKCOL -H "Authorization: Bearer $sub" "$door/data/pelican/sub"
req "PUT /data/pelican/sub/obj.txt (no-storage-scope token)" "${put[@]}" -H "Authorization: Bearer $plain" \
    --data-binary @"$tmp/hello.txt" "$door/data/pelican/sub/obj.txt"
req "PUT /data/pelican/other.txt (no-storage-scope token)" "${put[@]}" -H "Authorization: Bearer $plain" \
    --data-binary @"$tmp/hello.txt" "$door/data/pelican/other.txt"
req "GET /data/pelican/hello.txt (sub-path token, no -L)" -H "Authorization: Bearer $sub" "$door/data/pelican/hello.txt"
req "GET /data/pelican/hello.txt (sub-path token, -L)" -L -H "Authorization: Bearer $sub" "$door/data/pelican/hello.txt"
if ! cmp -s "$tmp/body" "$tmp/hello.txt"; then
    echo "  FAILED: dCache did not serve back the file it stored" >&2
    exit 1
fi
echo "    body matches"
req "PUT /data/other/x.txt (sub-path token: outside its scope)" "${put[@]}" -H "Authorization: Bearer $sub" \
    --data-binary @"$tmp/hello.txt" "$door/data/other/x.txt"

echo
echo "-- (a) Macaroon request, token whose scopes cover the prefix root"
macreq "full-scope" "$full" /data/pelican/ '{"caveats":["activity:DOWNLOAD"],"validity":"PT15M"}'
macreq "full-scope, no validity" "$full" /data/pelican/ '{"caveats":["activity:DOWNLOAD"]}'

echo
echo "-- (b) Macaroon request, token restricted to /pelican"
macreq "sub-path" "$sub" /data/pelican/ '{"caveats":["activity:DOWNLOAD"],"validity":"PT15M"}'
macreq "sub-path, no validity" "$sub" /data/pelican/ '{"caveats":["activity:DOWNLOAD"]}'

echo
echo "-- (b') Macaroon request, token with no storage.* scopes (identity only)"
macreq "no-storage-scope" "$plain" /data/pelican/ '{"caveats":["activity:DOWNLOAD"],"validity":"PT15M"}'
root_mac=$MACAROON
macreq "no-storage-scope at /" "$plain" / '{"caveats":["activity:DOWNLOAD"],"validity":"PT15M"}'
slash_mac=$MACAROON
macreq "chrooted user (authzdb root /data/chroot) at /" "$chroot" / '{"caveats":["activity:DOWNLOAD"],"validity":"PT15M"}'
macreq "chrooted user at /sub" "$chroot" /sub '{"caveats":["activity:DOWNLOAD"],"validity":"PT15M"}'

echo
echo "-- (c) Attenuated macaroons used as ?authz="
if [ -n "$root_mac" ]; then
    soon=$(future 300)
    past=$(future -5)
    rel=$(mac attenuate "$root_mac" activity:DOWNLOAD path:/sub/obj.txt "before:$soon")
    abs=$(mac attenuate "$root_mac" activity:DOWNLOAD path:/data/pelican/sub/obj.txt "before:$soon")
    expired=$(mac attenuate "$root_mac" activity:DOWNLOAD path:/sub/obj.txt "before:$past")
    echo "  minted from the macaroon for /data/pelican/: path relative to it ($(short "$rel")), path absolute ($(short "$abs"))"
    req "GET own object, relative path caveat (-L)" -L "$door/data/pelican/sub/obj.txt?authz=$rel"
    cmp -s "$tmp/body" "$tmp/hello.txt" && echo "    body matches"
    req "GET own object, relative path caveat (no -L)" "$door/data/pelican/sub/obj.txt?authz=$rel"
    req "GET own object, absolute path caveat (-L)" -L "$door/data/pelican/sub/obj.txt?authz=$abs"
    req "GET another object (-L)" -L "$door/data/pelican/other.txt?authz=$rel"
    req "GET own object as Authorization: Bearer (-L)" -L -H "Authorization: Bearer $rel" "$door/data/pelican/sub/obj.txt"
    req "PUT own object" "${put[@]}" --data-binary @"$tmp/hello.txt" "$door/data/pelican/sub/obj.txt?authz=$rel"
    req "DELETE own object" -X DELETE "$door/data/pelican/sub/obj.txt?authz=$rel"
    req "PROPFIND own object" -X PROPFIND -H 'Depth: 0' "$door/data/pelican/sub/obj.txt?authz=$rel"
    req "GET own object after before: (-L)" -L "$door/data/pelican/sub/obj.txt?authz=$expired"
    req "GET own object, unattenuated root macaroon (-L)" -L "$door/data/pelican/sub/obj.txt?authz=$root_mac"
    req "PUT with the root macaroon (activity:DOWNLOAD)" "${put[@]}" --data-binary @"$tmp/hello.txt" "$door/data/pelican/new.txt?authz=$root_mac"
fi
if [ -n "$slash_mac" ]; then
    rel=$(mac attenuate "$slash_mac" activity:DOWNLOAD path:/data/pelican/sub/obj.txt "before:$(future 300)")
    req "GET via macaroon requested at /, path:/data/pelican/sub/obj.txt (-L)" -L "$door/data/pelican/sub/obj.txt?authz=$rel"
fi
exit 0
