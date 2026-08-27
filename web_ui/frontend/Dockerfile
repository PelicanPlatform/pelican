#
# Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

FROM node:24-alpine

# Install the exact pnpm version pinned by "packageManager" in package.json, so
# this image, CI, and developer machines all agree. Corepack used to provide
# this shim, but it is no longer bundled with current Node releases, so install
# it explicitly rather than depending on the base image shipping Corepack.
COPY package.json /tmp/frontend-package.json
RUN npm install -g "$(node -p "require('/tmp/frontend-package.json').packageManager")"

# Warm pnpm's content-addressable store from the lockfile.
#
# The Makefile bind-mounts the source tree over /webapp, which would hide any
# node_modules baked in here — npm got away with installing to / and pointing
# NODE_PATH at it, but pnpm's symlinked layout is not relocatable that way.
# Instead we pre-populate the store, so the `pnpm install` that runs against the
# mounted workspace only has to hardlink out of it: no network, and fast.
#
# This layer is invalidated only when the lockfile or the pnpm settings change.
# `pnpm fetch` reads the lockfile and ignores package.json by design; it is
# marked experimental upstream but is the documented way to do this in Docker.
WORKDIR /fetch
COPY pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm fetch

WORKDIR /webapp
