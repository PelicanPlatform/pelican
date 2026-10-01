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

# Print, on one line, the packages whose files differ between the client
# and server build tags.
#
# The build tags select which commands go into the "cmd" package. CI tests
# every package with -tags=client, and only the packages printed here again
# with -tags=server.
#
# That approach is sound only if no package's non-test files differ, other
# than "cmd"'s: a main package can't be imported, so its differences can't
# change how any other package behaves. This script checks both that and
# that "cmd" is a main package, and exits with an error if either does not
# hold.
#
# This script assumes that no dependency uses the "client" or "server" build
# tags, and that no file combines them with another tag that "go test" might
# set, such as "race".
#
# Usage: build_tag_packages.sh

set -euo pipefail

cd "$(dirname "$0")/../../.."

pkg=github.com/pelicanplatform/pelican
files='{{.ImportPath}} {{.Name}} {{.GoFiles}} {{.CgoFiles}} {{.EmbedFiles}} {{.Imports}}'
# Build constraints apply to these non-Go sources, too.
files+=' {{.CFiles}} {{.CXXFiles}} {{.MFiles}} {{.HFiles}} {{.FFiles}} {{.SFiles}}'
files+=' {{.SwigFiles}} {{.SwigCXXFiles}}'
test_files='{{.TestGoFiles}} {{.XTestGoFiles}} {{.TestImports}} {{.XTestImports}}'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Write each list to a file, rather than diffing process substitutions,
# so that a failing "go list" stops the script with its own error.
for tag in client server; do
  for kind in non_test any; do
    template=$files
    if [ "$kind" = any ]; then
      template="$files $test_files"
    fi
    if ! go list -tags="$tag" -f "$template" ./... > "$tmp/$tag-$kind.txt"; then
      echo "::error::\"go list -tags=$tag\" failed." >&2
      exit 1
    fi
  done
done

# changed KIND: print the import paths that differ between the tags'
# lists of the given kind, one per line.
changed() {
  # diff exits 1 when the lists differ, which is expected; 2 is an error.
  # Its "<" and ">" lines hold the lists' differing lines;
  # print the first field of each, the import path.
  # A changed package appears on both sides, hence "sort -u".
  { diff "$tmp/client-$1.txt" "$tmp/server-$1.txt" || [ $? -eq 1 ]; } |
    sed -n 's/^[<>] \([^ ]*\).*/\1/p' | sort -u
}

# words LINES: print the lines joined with spaces.
words() {
  # Leaving $1 unquoted splits it into words,
  # which echo joins with spaces.
  # Import paths have no glob characters to expand.
  # shellcheck disable=SC2086
  echo $1
}

non_test=$(changed non_test)
any=$(changed any)
echo "Packages whose non-test files differ: $(words "$non_test")" >&2
echo "Packages whose files differ: $(words "$any")" >&2

if [ "$non_test" != "$pkg/cmd" ]; then
  echo "::error::Only cmd's non-test files may differ between the build tags." >&2
  exit 1
fi

for tag in client server; do
  # Each line of the list starts with the import path and package name.
  name=$(awk -v p="$pkg/cmd" '$1 == p { print $2 }' "$tmp/$tag-non_test.txt")
  if [ "$name" != main ]; then
    echo "::error::cmd must be a main package (-tags=$tag)." >&2
    exit 1
  fi
done

words "$any"
