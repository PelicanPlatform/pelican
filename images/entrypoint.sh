#!/bin/bash

# ***************************************************************
#
#  Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

# Set up OA4MP only if this is an origin.
if [ "$2" == "origin" ]; then
    ####
    # Set up the OA4MP configuration. These items are taken from
    # https://github.com/scitokens/scitokens-oauth2-server/blob/master/start.sh,
    # which appears to have an Apache 2.0 license.
    #
    # NOTE: Some set up is taken care of by oa4mp/serve.go.
    ####

    # check for one or more files in a directory
    if [ -e /opt/scitokens-server/etc/qdl/ ]; then
        # Note that `-L` is added here; this is because Kubernetes sets up some volume mounts
        # as symlinks and `-r` will copy the symlinks (which then becomes broken).  `-L` will
        # dereference the symlink and copy the data, which is what we want.
        cp -rL /opt/scitokens-server/etc/qdl/*.qdl /opt/scitokens-server/var/qdl/scitokens/
        chown -R tomcat /opt/scitokens-server/var/qdl/
    fi

    # Load up additional trust roots.  If OA4MP needs to contact a LDAP server, we will need
    # the CA that signed the LDAP server's certificate to be in the java trust store.
    if [ -e /opt/scitokens-server/etc/trusted-cas ]; then

        shopt -s nullglob
        for fullfile in /opt/scitokens-server/etc/trusted-cas/*.pem; do
            aliasname=$(basename "$file")
            aliasname="${filename%.*}"
            keytool -cacerts -importcert -noprompt -storepass changeit -file "$fullfile" -alias "$aliasname"
        done
        shopt -u nullglob

    fi

    # Tomcat requires us to provide the intermediate chain (which, in Kubernetes, is often in the same
    # file as the host certificate itself.  If there wasn't one provided, try splitting it out.
    if [ ! -e /opt/tomcat/conf/chain.pem ]; then
        pushd /tmp > /dev/null
        if csplit -f tls- -b "%02d.crt.pem" -s -z "/opt/tomcat/conf/hostcert.pem" '/-----BEGIN CERTIFICATE-----/' '{1}' 2>/dev/null ; then
            cp /tmp/tls-01.crt.pem /opt/tomcat/conf/chain.pem
            rm /tmp/tls-*.crt.pem
        else
            # No intermediate CAs found.  Create an empty file.
            touch /opt/tomcat/conf/chain.pem
        fi
        popd > /dev/null
    fi
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
            echo "Running pelican with arguments: $@"
            exec tini -- /usr/local/bin/pelican "$@"
            # we shouldn't get here
            echo >&2 "Exec of tini failed!"
            exit 1
            ;;
        pelican-server)
            # Our server-specific binary which may come with additional
            # features/system requirements (like Lotman)
            echo "Running pelican-server with arguments: $@"
            exec tini -- /usr/local/sbin/pelican-server "$@"
            # we shouldn't get here
            echo >&2 "Exec of tini failed!"
            exit 1
            ;;
        osdf)
            # Run osdf with the rest of the arguments
            echo "Running osdf with arguments: $@"
            exec tini -- /usr/local/bin/osdf "$@"
            # we shouldn't get here
            echo >&2 "Exec of tini failed!"
            exit 1
            ;;
        osdf-server)
            echo "Running osdf-server with arguments: $@"
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
