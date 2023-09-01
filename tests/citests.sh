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

cp pelican stashcp
cp pelican stash_plugin

to_exit=0
./stashcp -d /osgconnect/public/dweitzel/blast/queries/query1 ./
rm query1

# Test the plugin interface
classad_output=$(./stash_plugin -classad)

if ! [[ $classad_output =~ "PluginType = \"FileTransfer\"" ]]; then
  echo "PluginType not in classad output"
  to_exit=1
fi

if ! [[ $classad_output =~ "SupportedMethods = \"stash, osdf\"" ]]; then
  echo "SupportedMethods not in classad output"
  to_exit=1
fi

plugin_output=$(./stash_plugin stash:///osgconnect/public/dweitzel/blast/queries/query1 query1)
rm query1

if ! [[ $plugin_output =~ "TransferUrl = \"stash:///osgconnect/public/dweitzel/blast/queries/query1\"" ]]; then
  echo "TransferUrl not in plugin output"
  to_exit=1
fi

if ! [[ $plugin_output =~ "TransferSuccess = true" ]]; then
  echo "TransferSuccess not in plugin output"
  to_exit=1
fi

cat > infile <<EOF
[ LocalFileName = "$PWD/query1"; Url = "stash:///osgconnect/public/dweitzel/blast/queries//query1" ]
[ LocalFileName = "$PWD/query2"; Url = "stash:///osgconnect/public/dweitzel/blast/queries//query2" ]
[ LocalFileName = "$PWD/query3"; Url = "stash:///osgconnect/public/dweitzel/blast/queries//query3" ]
EOF

./stash_plugin -infile $PWD/infile -outfile $PWD/outfile

exit $to_exit
