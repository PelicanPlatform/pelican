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

# Usage: entrypoint.sh [osdf|pelican] [daemon name] [args...]

# Add additional CAs and certificates to the trust store.
if [ -d /certs ]; then
  shopt -s nullglob
  for ca_cert in /certs/*.crt; do
    cp "${ca_cert}" /etc/pki/ca-trust/source/anchors/
  done
  update-ca-trust extract
  shopt -u nullglob
fi

echo "Starting Pelican..."

# The first argument is the program selector
program_selector="$1"

# Shift the first argument so $@ contains the rest of the arguments
shift

# grab whatever arg is passed to container run command
# and use it to launch the corresponding pelican daemon
# (eg running the container with the arg director serve will
# launch the ./pelican director serve daemon)
if [ $# -ne 0 ]; then
    case "$program_selector" in
        pelican)
            # Run pelican with the rest of the arguments
            echo "Running pelican with arguments: $*"
            exec tini -- /usr/local/bin/pelican "$@"
            # we shouldn't get here
            echo >&2 "Exec of tini failed!"
            exit 1
            ;;
        pelican-server)
            # Our server-specific binary which may come with additional
            # features/system requirements (like Lotman)
            echo "Running pelican-server with arguments: $*"
            exec tini -- /usr/local/sbin/pelican-server "$@"
            # we shouldn't get here
            echo >&2 "Exec of tini failed!"
            exit 1
            ;;
        osdf)
            # Run osdf with the rest of the arguments
            echo "Running osdf with arguments: $*"
            exec tini -- /usr/local/bin/osdf "$@"
            # we shouldn't get here
            echo >&2 "Exec of tini failed!"
            exit 1
            ;;
        osdf-server)
            echo "Running osdf-server with arguments: $*"
            exec tini -- /usr/local/sbin/osdf-server "$@"
            # we shouldn't get here
            echo >&2 "Exec of tini failed!"
            exit 1
            ;;
        *)
            # Default case if the program selector does not match
            echo "Unknown program: $program_selector"
            exit 1
            ;;
    esac
else
  echo "Usage: [args...]"
  echo "example: docker run pelican_platform/cache -p 8443"
fi
