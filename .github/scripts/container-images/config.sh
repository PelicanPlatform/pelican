# shellcheck shell=bash disable=SC2034  # The variables are for the caller.
#
# Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

# Define where the GitHub repo in GITHUB_REPOSITORY pushes container
# images, and which images it releases. Workflows source this file, so
# that a new image or a new fork is added in one place.
#
# Sets:
#
#   - PRIVATE_REPO: Where images built off of semver tags are pushed.
#
#   - PUBLIC_REPO: Where images built off of `main` are pushed,
#     and where promote-images.yml copies the release images to.
#
#   - RELEASE_IMAGES: The images that a release consists of.
#
#     promote-images.yml reads this list from the tag being promoted by
#     parsing it, not by sourcing this file, so keep it a literal list of
#     names, with "RELEASE_IMAGES=(" and ")" on lines of their own.
#
# The two repos must be on the same registry host, because Docker keeps
# only one credential per host, and promotion needs to read from one repo
# while writing to the other.

PRIVATE_REPO=""
PUBLIC_REPO=""

case "${GITHUB_REPOSITORY}" in
  PelicanPlatform/pelican)
    PRIVATE_REPO="hub.osg-htc.org/pelican-ci"
    PUBLIC_REPO="hub.osg-htc.org/pelican_platform" ;;

  # Some testing scenarios require the ability to push container images
  # to a registry. Here, we list developers who have forked the main
  # PelicanPlatform/pelican repo and are able to push images somewhere.

  brianaydemir/pelicanplatform-pelican)
    PRIVATE_REPO="hub.osg-htc.org/brian.aydemir.r2"
    PUBLIC_REPO="hub.osg-htc.org/brian.aydemir.r1" ;;

  matyasselmeci/pelican)
    PRIVATE_REPO="hub.osg-htc.org/matyasosg" ;;
esac

RELEASE_IMAGES=(
  client
  cache director origin registry
  osdf-cache osdf-director osdf-origin osdf-registry
)
