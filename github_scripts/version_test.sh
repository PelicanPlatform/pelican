#!/bin/bash -xe

# Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

# This tests the --version flag of various Pelican binaries (pelican/stash/osdf)

set -e

mkdir -p /tmp/pelican-test/version-test

export PELICAN_CONFIGDIR=/tmp/pelican-test/version-test
export OSDF_CONFIGDIR=/tmp/pelican-test/version-test
export STASH_CONFIGDIR=/tmp/pelican-test/version-test

# Function to cleanup after test ends
cleanup() {
    # Clean up temporary files
    rm -rf /tmp/pelican-test/version-test
    rm -f ./stash
    rm -f ./osdf
    unset PELICAN_CONFIGDIR
    unset OSDF_CONFIGDIR
    unset STASH_CONFIGDIR
}

# Setup trap with the PID as an argument to the cleanup function
trap 'cleanup' EXIT

if [ ! -f "./stash" ]; then
    cp ./pelican ./stash
fi

if [ ! -f "./osdf" ]; then
    cp ./pelican ./osdf
fi

stdout=$(./pelican --version)

# Use variables for comparison or matching
if [[ "$stdout" == *"Version: "* ]]; then
    echo "pelican --version Version found in stdout"
else
    echo "Version not found in stdout running pelican --version"
    echo "Test failed"
    exit 1
fi

stdout=$(./stash --version)

# Use variables for comparison or matching
if [[ "$stdout" == *"Version: "* ]]; then
    echo "stash --version Version found in stdout"
else
    echo "Version not found in stdout running stash --version"
    echo "Test failed"
    exit 1
fi

stdout=$(./osdf --version)

# Use variables for comparison or matching
if [[ "$stdout" == *"Version: "* ]]; then
    echo "osdf --version Version found in stdout"
else
    echo "Version not found in stdout running osdf --version"
    echo "Test failed"
    exit 1
fi

echo "Test succeeded"
exit 0
