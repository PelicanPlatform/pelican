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
# Generates a throwaway CA, a host certificate for localhost signed by it,
# the hashed CA directory dCache reads, and the issuer's signing key.
# Usage: certs.sh <directory>.  Nothing here is ever committed.
set -euo pipefail
dir=${1:?usage: certs.sh <directory>}
mkdir -p "$dir/grid-security/certificates" "$dir/issuer"
cd "$dir"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Pelican dCache e2e CA" \
    -keyout ca.key -out ca.pem \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

cat > host.ext <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EXT
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout grid-security/hostkey.pem -out host.csr 2>/dev/null
openssl x509 -req -in host.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile host.ext -out grid-security/hostcert.pem 2>/dev/null
cp ca.pem "grid-security/certificates/$(openssl x509 -hash -noout -in ca.pem).0"
# dCache runs as root in its container; the key need not be readable by
# anyone else.
chmod 0600 grid-security/hostkey.pem ca.key

openssl genrsa -out issuer/key.pem 2048 2>/dev/null
chmod 0600 issuer/key.pem
