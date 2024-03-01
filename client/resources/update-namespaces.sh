#!/bin/bash
#
# Copyright (C) 2024, Pelican Project, University of Wisconsin-Madison
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

# Download the newest namespaces.json from Topology
# Requires: curl, jq

# Set default Topology server; you can override this to use a test instance for example
: "${TOPOLOGY:=https://topology.opensciencegrid.org}"


fail () {
    ret=$1
    shift &>/dev/null
    echo "$@" >&2
    exit "$ret"
}


require_program () {
    command -v "$1" &>/dev/null ||
        fail 127 "Required program '$1' not found in PATH"
}


require_program curl
require_program jq

curl -o namespaces.json.raw "${TOPOLOGY}/osdf/namespaces" ||
    fail $? "Download failed"
jq --sort-keys . namespaces.json.raw > namespaces.json.formatted ||
    fail $? "Formatting JSON failed"
mv -f namespaces.json.formatted namespaces.json ||
    fail $? "Move failed"
rm -f namespaces.json.raw
