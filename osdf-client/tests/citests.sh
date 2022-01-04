#!/bin/sh -xe

to_exit=0
./stashcp -d /osgconnect/public/dweitzel/blast/queries/query1 ./

# Test the plugin interface
cp ./stashcp ./stash_plugin
classad_output=$(./stash_plugin -classad)

if ! [[ $classad_output =~ "PluginVersion = \"0.3\"" ]]; then
  echo "PluginVersion not in classad output"
  to_exit=1
fi

if ! [[ $classad_output =~ "PluginType = \"FileTransfer\"" ]]; then
  echo "PluginType not in classad output"
  to_exit=1
fi

if ! [[ $classad_output =~ "SupportedMethods = \"stash\"" ]]; then
  echo "SupportedMethods not in classad output"
  to_exit=1
fi

plugin_output=$(./stash_plugin stash:///osgconnect/public/dweitzel/blast/queries/query1 query1)

if ! [[ $plugin_output =~ "TransferUrl = \"stash:///osgconnect/public/dweitzel/blast/queries/query1\"" ]]; then
  echo "TransferUrl not in plugin output"
  to_exit=1
fi

if ! [[ $plugin_output =~ "TransferSuccess = true" ]]; then
  echo "TransferSuccess not in plugin output"
  to_exit=1
fi

exit $to_exit