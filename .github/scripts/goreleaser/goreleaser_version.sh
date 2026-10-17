#!/bin/sh
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

# Print the GoReleaser version pinned in images/Dockerfile, in a form that
# can be appended to $GITHUB_OUTPUT (e.g., "version=v2.18.3").
#
# images/Dockerfile is the single source of truth for the version because
# Dependabot can update its FROM lines but not the goreleaser-action's
# "version" input. This script exits with an error unless the
# goreleaser/goreleaser FROM lines agree on exactly one version.
#
# This script runs inside the CI containers too, so it sticks to POSIX sh,
# grep, and sed.
#
# Usage: goreleaser_version.sh

set -eu

cd "$(dirname "$0")/../../.."

versions=$(
  grep -E '^FROM[[:space:]].*goreleaser/goreleaser:' images/Dockerfile \
    | sed -E 's|.*goreleaser/goreleaser:([^@[:space:]]+).*|\1|' \
    | sort -u
)

count=$(printf '%s' "$versions" | grep -c . || true)
if [ "$count" -ne 1 ]; then
  echo "error: expected one GoReleaser version in images/Dockerfile, found $count:" >&2
  printf '%s\n' "$versions" >&2
  exit 1
fi

echo "version=$versions"
