#!/usr/bin/env python3
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
# A minimal token issuer for the dCache end-to-end test: serves an OpenID
# discovery document and a JWKS over plain HTTP, the way dCache's own test
# deployments point gPlazma at a Keycloak on http://, and mints WLCG-profile
# tokens signed with the same key.  Standard library plus the openssl CLI.
#
#   issuer.py serve <key.pem> <issuer URL> <port>
#   issuer.py mint  <key.pem> <issuer URL> <sub> <lifetime seconds> <scope>
import base64
import http.server
import json
import subprocess
import sys
import time
import uuid

KID = "dcache-e2e-1"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwks(key):
    out = subprocess.run(["openssl", "rsa", "-in", key, "-noout", "-modulus"],
                         check=True, capture_output=True, text=True).stdout
    modulus = bytes.fromhex(out.strip().split("=", 1)[1])
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                      "n": b64url(modulus), "e": b64url((65537).to_bytes(3, "big"))}]}


def serve(key, issuer, port):
    docs = {
        "/.well-known/openid-configuration": {
            "issuer": issuer,
            "jwks_uri": issuer + "/jwks.json",
            "token_endpoint": issuer + "/token",
            "userinfo_endpoint": issuer + "/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        },
        "/jwks.json": jwks(key),
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            doc = docs.get(self.path.split("?", 1)[0])
            if doc is None:
                self.send_error(404)
                return
            body = json.dumps(doc).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            sys.stderr.write("%s issuer: %s\n" % (time.strftime("%H:%M:%S"), fmt % args))
            sys.stderr.flush()

    http.server.ThreadingHTTPServer(("0.0.0.0", int(port)), Handler).serve_forever()


def mint(key, issuer, sub, lifetime, scope):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    claims = {"iss": issuer, "sub": sub, "aud": "https://wlcg.cern.ch/jwt/v1/any",
              "wlcg.ver": "1.0", "iat": now, "nbf": now - 60, "exp": now + int(lifetime),
              "jti": str(uuid.uuid4()), "scope": scope}
    signing_input = (b64url(json.dumps(header).encode()) + "." +
                     b64url(json.dumps(claims).encode())).encode()
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key], input=signing_input,
                         check=True, capture_output=True).stdout
    print(signing_input.decode() + "." + b64url(sig))


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "serve":
        serve(*sys.argv[2:])
    elif len(sys.argv) == 7 and sys.argv[1] == "mint":
        mint(*sys.argv[2:])
    else:
        sys.exit(__doc__ or "usage: issuer.py serve|mint ...")
