#!/bin/bash

# Append environment variables to /etc/environment, excluding "no_proxy"
echo "Appending environment variables to /etc/environment"
printenv | grep -v "no_proxy" >> /etc/environment

# Run the login script
echo "Running login script"
/opt/bin/login.sh

# Start cron
echo "Starting cron"
cron

# Run the original Docker entrypoint script with any passed arguments
echo "Running original Docker entrypoint script with arguments: $@"
/docker-entrypoint.sh "$@"
