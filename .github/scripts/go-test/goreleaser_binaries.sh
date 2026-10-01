#!/usr/bin/env bash
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

# Print a VAR=PATH line for each binary in dist/artifacts.json that the
# tests can use in place of building their own, as set up by a GoReleaser
# build. See test_utils/binaries.go.
#
# Only binaries for the platform that "go env GOOS GOARCH" reports are
# considered, so the script works after a full build as well as after a
# --single-target one, which honors the same variables.
#
# The paths are absolute, as the tests require. A test whose variable is
# unset quietly builds its own binary, so this script fails if any of the
# variables named on the command line is not found.
#
# Usage: goreleaser_binaries.sh VAR...

set -euo pipefail

cd "$(dirname "$0")/../../.."

# On Windows, $GITHUB_WORKSPACE is a native path, unlike $PWD.
base=${GITHUB_WORKSPACE:-$PWD}

goos=$(go env GOOS | tr -d '\r')
goarch=$(go env GOARCH | tr -d '\r')

# Run jq on its own, not in a process substitution, so that its exit
# status is checked.
binaries=$(jq -r --arg goos "$goos" --arg goarch "$goarch" '
    .[]
    | select(.type == "Binary" and .goos == $goos and .goarch == $goarch)
    | [.extra.ID, .path]
    | @tsv
  ' dist/artifacts.json |
  tr -d '\r')

found=()
while IFS=$'\t' read -r id path; do
  case "$id" in
    pelican) var=TEST_PELICAN_BINARY ;;
    pelican-server) var=TEST_PELICAN_SERVER_BINARY ;;
    *) continue ;;
  esac
  if [[ " ${found[*]-} " == *" $var "* ]]; then
    echo "::error::dist/artifacts.json lists more than one ${goos}/${goarch} binary for ${var}." >&2
    exit 1
  fi
  echo "${var}=${base}/${path}"
  found+=("$var")
done <<< "$binaries"

for var in "$@"; do
  if [[ " ${found[*]-} " != *" $var "* ]]; then
    echo "::error::dist/artifacts.json lists no ${goos}/${goarch} binary for ${var}." >&2
    exit 1
  fi
done
