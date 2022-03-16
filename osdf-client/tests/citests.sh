#!/bin/bash -xe

to_exit=0
./stashcp -d /osgconnect/public/dweitzel/blast/queries/query1 ./
rm query1

# Test the plugin interface
classad_output=$(./stash_plugin -classad)

if ! [[ $classad_output =~ "PluginType = \"FileTransfer\"" ]]; then
  echo "PluginType not in classad output"
  to_exit=1
fi

if ! [[ $classad_output =~ "SupportedMethods = \"stash\"" ]]; then
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