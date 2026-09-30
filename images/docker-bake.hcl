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
# The build-and-test.yml workflow sets the variables below.
# Locally, run from the root of the repository:
#
#   IMAGES_TO_BUILD=origin,cache docker buildx bake -f images/docker-bake.hcl --load

# Comma-separated lists of the images to build and to push.
variable "IMAGES_TO_BUILD" { default = "director,registry,origin,cache" }
variable "IMAGES_TO_PUSH" { default = "" }

# Where to push images, e.g., "hub.osg-htc.org/pelican_platform".
variable "REGISTRY_REPO" { default = "" }

# The platform and architecture to build for.
variable "PLATFORM" { default = "linux/amd64" }
variable "ARCH" { default = "amd64" }

# Tags to apply to the image, without the architecture suffix.
variable "GITHUB_SHA" { default = "" }
variable "TAG" { default = "dev" }
variable "TIMESTAMP" { default = "" }

# Determines whether to tag the image with "latest".
variable "IS_LATEST" { default = "false" }

function "should_push" {
  params = [image]
  result = contains(split(",", IMAGES_TO_PUSH), image)
}

function "tags" {
  params = [image]
  result = [
    for tag in compact(concat(
      [
        GITHUB_SHA != "" ? "sha-${substr(GITHUB_SHA, 0, 7)}" : "",
        TAG,
        TIMESTAMP,
      ],
      IS_LATEST == "true" ? ["latest"] : [],
    )) : "${REGISTRY_REPO != "" ? "${REGISTRY_REPO}/" : ""}${image}:${tag}-${ARCH}"
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

  # Push only the images in IMAGES_TO_PUSH.
  # Leave the others' output unset so that --load still applies to them.
  tags   = tags(img)
  output = should_push(img) ? ["type=registry"] : []
}
