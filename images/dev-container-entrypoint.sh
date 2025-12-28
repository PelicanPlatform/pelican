#!/bin/bash
# ***************************************************************
#
#  Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you
#  may not use this file except in compliance with the License.  You may
#  obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
# ***************************************************************

# Add additional CAs and certificates to the trust store.
if [ -d /certs ]; then
  shopt -s nullglob
  for ca_cert in /certs/*.crt; do
    cp "${ca_cert}" /etc/pki/ca-trust/source/anchors/
  done
  update-ca-trust extract
  shopt -u nullglob
fi

# Install the pre-commit hook.
if [ -d ./.git ]; then
  pre-commit install
fi

# Default to bash but if a command is passed, run it.
if [ $# -eq 0 ]; then
  exec /bin/bash
else
  exec "$@"
fi
