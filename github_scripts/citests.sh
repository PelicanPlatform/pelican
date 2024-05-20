#!/bin/bash -xe
#
# Copyright (C) 2024, University of Nebraska-Lincoln
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

cp pelican stashcp
cp pelican stash_plugin

to_exit=0
./stashcp -d osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt ./query1
rm query1

# Test the plugin interface
classad_output=$(./stash_plugin -classad)

if ! [[ $classad_output =~ "PluginType = \"FileTransfer\"" ]]; then
  echo "PluginType not in classad output"
  to_exit=1
fi

if ! [[ $classad_output =~ "SupportedMethods = \"stash, osdf, pelican\"" ]]; then
  echo "SupportedMethods not in classad output"
  to_exit=1
fi

plugin_output=$(./stash_plugin osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt query1)
rm query1

if ! [[ $plugin_output =~ "TransferUrl = \"osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt\"" ]]; then
  echo "TransferUrl not in plugin output"
  to_exit=1
fi

if ! [[ $plugin_output =~ "TransferSuccess = true" ]]; then
  echo "TransferSuccess not in plugin output"
  to_exit=1
fi

cat > infile <<EOF
[ LocalFileName = "$PWD/query1"; Url = "osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt" ]
EOF

./stash_plugin -infile $PWD/infile -outfile $PWD/outfile


#####################################
## Test LocalCache in front of OSDF #
#####################################
SOCKET_DIR="`mktemp -d -t pelican-citest-XXXXXX`"
export PELICAN_LOCALCACHE_SOCKET=$SOCKET_DIR/socket
export PELICAN_LOCALCACHE_DATALOCATION=$SOCKET_DIR/data
export PELICAN_SERVER_ENABLEUI=false

./pelican serve -d -f osg-htc.org --module localcache &
PELICAN_PID=$!

cleanup() {
    rm -rf -- "$SOCKET_DIR"
    kill $PELICAN_PID
    wait $PELICAN_PID || :
}
trap cleanup EXIT

for idx in {1..20}; do
  if [ -e "$SOCKET_DIR/socket" ]; then
    break
  fi
  sleep 0.3
done
if [ ! -e "$SOCKET_DIR/socket" ]; then
  echo "pelican serve never dropped localcache socket"
  exit 1
fi


NEAREST_CACHE="unix://$SOCKET_DIR/socket" ./stash_plugin -d osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt /dev/null
exit_status=$?

if ! [[ "$exit_status" = 0 ]]; then
  echo "Cache plugin download failed"
  exit 1
fi

if [ ! -e "$SOCKET_DIR/data/ospool/uc-shared/public/OSG-Staff/validation/test.txt.DONE" ]; then
  echo "Test file not in local cache"
  exit 1
fi

# Test we work with PELICAN_NEAREST_CACHE as well
PELICAN_NEAREST_CACHE="unix://$SOCKET_DIR/socket" ./stash_plugin -d osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt /dev/null
exit_status=$?

if ! [[ "$exit_status" = 0 ]]; then
  echo "Cache plugin download failed"
  exit 1
fi

if [ ! -e "$SOCKET_DIR/data/ospool/uc-shared/public/OSG-Staff/validation/test.txt.DONE" ]; then
  echo "Test file not in local cache"
  exit 1
fi

########################################
# Test we return 0 when HOME is not set
########################################
OLDHOME=$HOME
unset HOME
./stash_plugin -classad
exit_status=$?

if ! [[ "$exit_status" = 0 ]]; then
  echo "Plugin did not return 0 when HOME is not set"
  to_exit=1
fi

export HOME=$OLDHOME

# Test we return 0 when HOME points to a nonwritable directory
OLDHOME=$HOME
unset HOME
mkdir unwritable_dir
chmod u-w,a-w unwritable_dir
export HOME=unwriteable_dir

./stash_plugin -classad
exit_status=$?

if ! [[ "$exit_status" = 0 ]]; then
  echo "Plugin did not return 0 when HOME is set to an unwritable dir"
  to_exit=1
fi

unset HOME
export HOME=$OLDHOME
rm -r unwritable_dir

exit $to_exit
