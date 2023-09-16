#!/bin/bash
#
# Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
