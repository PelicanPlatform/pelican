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
export PELICAN_SERVER_ENABLEUI=false

adduser test1234
export PELICAN_OIDC_CLIENTID="test1234"
su test1234 -c '

mkdir $HOME/origin
chmod 777 $HOME/origin
export PELICAN_ORIGIN_EXPORTVOLUME="$HOME/origin:/test"

# Make a file to use for testing
echo "This is some random content in the random file" > $HOME/input.txt

# Make a token to be used
./pelican origin token create --audience "https://wlcg.cern.ch/jwt/v1/any" --issuer "https://`hostname`:8443" --scope "storage.read:/ storage.modify:/" --subject "bar" --lifetime 60 --private-key $HOME/.config/pelican/issuer.jwk > $HOME/token

# Run federation in the background
federationServe="./pelican serve --module director --module registry --module origin -d"
$federationServe &
pid_federationServe=$!

# Give the federation time to spin up
sleep 10

# Run pelican object put
./pelican object put $HOME/input.txt osdf:///test/input.txt -d -t $HOME/token -l $HOME/putOutput.txt

# Check output of command
if grep -q "Uploaded bytes: 47" $HOME/putOutput.txt; then
    echo "Uploaded bytes successfully!"
else
    echo "Did not upload correctly"
    cat $HOME/putOutput.txt
    to_exit=1
fi

./pelican object get osdf:///test/input.txt $HOME/output.txt -d -t $HOME/token -l $HOME/getOutput.txt

# Check output of command
if grep -q "Downloaded bytes: 47" $HOME/getOutput.txt; then
    echo "Downloaded bytes successfully!"
else
    echo "Did not download correctly"
    cat $HOME/getOutput.txt
    to_exit=1
fi

if grep -q "This is some random content in the random file" $HOME/output.txt; then
    echo "Content matches the uploaded file!"
else
    echo "Did not download correctly, content in downloaded file is different from the uploaded file"
    echo "Contents of the downloaded file:"
    cat $HOME/output.txt
    echo "Contents of uploaded file:"
    cat $HOME/input.txt
    to_exit=1
fi

# Kill the federation
kill $pid_federationServe

# Clean up temporary files
rm -f $HOME/input.txt $HOME/token $HOME/putOutput.txt $HOME/getOutput.txt $HOME/output.txt

# cleanup
rm -rf $HOME/origin
'
userdel -r test1234
unset PELICAN_FEDERATION_DIRECTORURL
unset PELICAN_FEDERATION_REGISTRYURL
unset PELICAN_TLSSKIPVERIFY
unset PELICAN_ORIGIN_EXPORTVOLUME
unset PELICAN_SERVER_ENABLEUI
unset PELICAN_OIDC_CLIENTID
unset PELICAN_ORIGIN_ENABLEFALLBACKREAD
exit $to_exit
