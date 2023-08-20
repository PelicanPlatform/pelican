#!/bin/bash

supervisord -c /etc/supervisord.conf

# grab whatever arg is passed to container run command
# and use it to launch the corresponding pelican_X daemon
# (eg running the container with the arg director_serve will
# launch the pelican_director_serve daemon through supervisord)
if [ "$1" ]; then
  supervisorctl start "pelican_$1"
  # Keep the container running
  tail -f /dev/null
else
  echo "A command must be provided"
fi


