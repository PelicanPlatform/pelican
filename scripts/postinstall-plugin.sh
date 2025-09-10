#!/bin/sh

# Reconfigure condor if there is a StartD running on the current machine
# so it re-tests the plugins.

if command -v condor_reconfig >/dev/null 2>&1
then
    if ps -e -o cmd | grep 'condor_startd' | grep -qv grep
    then
        condor_reconfig || :
    fi
fi
