#!/bin/bash -xe
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

# This tests the --version flag of the pelican binary, including when it
# runs under the names "stash" and "osdf".
#
# The test keeps to a temporary directory of its own, which it removes on
# exit, so that it can run alongside other tests.

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# shellcheck source=github_scripts/e2e_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e_common.sh"

require_binaries ./pelican
setup_test_root version 10

# ---------------------------------------------------------------------------
# 1. Check the version that each name prints
# ---------------------------------------------------------------------------

mkdir -p "${TEST_ROOT}/bin"
cp ./pelican "${TEST_ROOT}/bin/stash"
cp ./pelican "${TEST_ROOT}/bin/osdf"

for bin in ./pelican "${TEST_ROOT}/bin/stash" "${TEST_ROOT}/bin/osdf"; do
    if ! stdout="$(within_budget "${bin}" --version)" || [[ "${stdout}" != *"Version: "* ]]; then
        echo "TEST FAILED: ${bin} --version did not print a version"
        exit 1
    fi
done

echo "TEST PASSED"
