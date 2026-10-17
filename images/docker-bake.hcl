# ***************************************************************
#
#  Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you
#  may not use this file except in compliance with the License.  You may
#  obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
# ***************************************************************

# Builds Pelican's container images, one target in images/Dockerfile
# per image. Building them in one invocation lets BuildKit build the stages
# they share only once.
#
# The build-and-test.yml workflow sets the variables below, except TAG.
# Locally, run from the root of the repository:
#
#   IMAGES_TO_BUILD=origin,cache docker buildx bake -f images/docker-bake.hcl --load
#
# To build for another architecture, also set PLATFORM, e.g., to "linux/arm64".

# Comma-separated lists of the images to build and to push.
variable "IMAGES_TO_BUILD" { default = "director,registry,origin,cache" }
variable "IMAGES_TO_PUSH" { default = "" }

# Where to push images, e.g., "hub.osg-htc.org/pelican_platform".
variable "REGISTRY_REPO" { default = "" }

# The platform to build for.
variable "PLATFORM" { default = "linux/amd64" }

# The tag for the images that are not pushed. It gets the architecture
# as a suffix, e.g., "dev-amd64", so that a build for one architecture
# does not replace another's.
variable "TAG" { default = "dev" }

function "should_push" {
  params = [image]
  result = contains(split(",", IMAGES_TO_PUSH), image)
}

function "tags" {
  params = [image]
  result = [
    "${REGISTRY_REPO != "" ? "${REGISTRY_REPO}/" : ""}${image}:${TAG}-${split("/", PLATFORM)[1]}"
  ]
}

group "default" {
  targets = ["image"]
}

target "image" {
  name       = img
  matrix     = { img = split(",", IMAGES_TO_BUILD) }
  context    = "."
  dockerfile = "images/Dockerfile"
  target     = img
  platforms  = [PLATFORM]

  # Push only the images in IMAGES_TO_PUSH, and push them by digest only.
  # build-and-test.yml tags them when it combines the architectures'
  # images into one manifest, so that a build that fails partway does not
  # leave behind tags that a registry might treat as immutable.
  # Leave the others' output unset so that --load still applies to them.
  tags   = should_push(img) ? ["${REGISTRY_REPO}/${img}"] : tags(img)
  output = should_push(img) ? ["type=registry,push-by-digest=true"] : []
}
