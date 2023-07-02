#!/bin/bash
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

