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
# Decodes and attenuates libmacaroons v1 macaroons (dCache's format) for the
# curl probe in probe.sh.  Standard library only.
#
#   macaroon.py decode <macaroon>
#   macaroon.py attenuate <macaroon> <caveat>...
import base64
import hashlib
import hmac
import sys


def b64decode(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def packets(raw):
    out = []
    while raw:
        n = int(raw[:4], 16)
        key, _, value = raw[4:n].partition(b" ")
        out.append((key.decode(), value[:-1] if value.endswith(b"\n") else value))
        raw = raw[n:]
    return out


def encode(key, value):
    body = key.encode() + b" " + value + b"\n"
    return b"%04x" % (len(body) + 4) + body


def main():
    cmd, mac = sys.argv[1], sys.argv[2]
    pkts = packets(b64decode(mac))
    if cmd == "decode":
        for key, value in pkts:
            if key == "signature":
                value = value.hex()[:8].encode() + b"..."
            print("%s %s" % (key, value.decode(errors="replace")))
        return
    sig = dict(pkts)["signature"]
    body = b"".join(encode(k, v) for k, v in pkts if k != "signature")
    for caveat in sys.argv[3:]:
        sig = hmac.new(sig, caveat.encode(), hashlib.sha256).digest()
        body += encode("cid", caveat.encode())
    print(base64.urlsafe_b64encode(body + encode("signature", sig)).rstrip(b"=").decode())


if __name__ == "__main__":
    main()
