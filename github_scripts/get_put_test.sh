#!/bin/bash -xe
#
# Copyright (C) 2023, University of Nebraska-Lincoln
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

# This tests the functionality of `pelican object get` and `pelican object put` with the
# "federation in a box"

# Setup env variables needed
to_exit=0
export PELICAN_FEDERATION_DIRECTORURL="https://$HOSTNAME:8444"
export PELICAN_FEDERATION_REGISTRYURL="https://$HOSTNAME:8444"
export PELICAN_TLSSKIPVERIFY=true
export PELICAN_ORIGIN_ENABLEFALLBACKREAD=true

mkdir origin
chmod 777 origin
export PELICAN_ORIGIN_EXPORTVOLUME="$PWD/origin:/test"
export PELICAN_SERVER_ENABLEUI=false
adduser test1234
export PELICAN_OIDC_CLIENTID="test1234"

# Make a file to use for testing
echo "This is some random content in the random file" > input.txt

# Make a token to be used
./pelican origin token create --audience "https://wlcg.cern.ch/jwt/v1/any" --issuer "https://`hostname`:8443" --scope "storage.read:/ storage.modify:/" --subject "bar" --lifetime 9999999999999 --private-key /etc/pelican/issuer.jwk > token

# Run federation in the background
federationServe="./pelican serve --module director --module registry --module origin -d"
$federationServe &
pid_federationServe=$!

# Give the federation time to spin up
sleep 10

# Run pelican object put
./pelican object put input.txt osdf:///test/input.txt -d -t token -l putOutput.txt

# Check output of command
if grep -q "Uploaded bytes: 47" putOutput.txt; then
    echo "Uploaded bytes successfully!"
else
    echo "Did not upload correctly"
    cat putOutput.txt
    to_exit=1
fi

./pelican object get osdf:///test/input.txt output.txt -d -t token -l getOutput.txt

# Check output of command
if grep -q "Downloaded bytes: 47" getOutput.txt; then
    echo "Downloaded bytes successfully!"
else
    echo "Did not download correctly"
    cat getOutput.txt
    to_exit=1
fi

# Kill the federation
kill $pid_federationServe

# Clean up temporary files
rm -f input.txt token putOutput.txt getOutput.txt output.txt

# cleanup
userdel -r test1234
rm -rf origin
unset PELICAN_FEDERATION_DIRECTORURL
unset PELICAN_FEDERATION_REGISTRYURL
unset PELICAN_TLSSKIPVERIFY
unset PELICAN_ORIGIN_EXPORTVOLUME
unset PELICAN_SERVER_ENABLEUI
unset PELICAN_OIDC_CLIENTID
unset PELICAN_ORIGIN_ENABLEFALLBACKREAD
exit $to_exit
