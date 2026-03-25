#!/bin/bash

# Generate a GoReleaser file that has the current version substituted into
# "%VERSION%" placeholders.
# This is because GoRelease doesn't do {{ .Version }} substitution in some
# places we need it to, such as RPM version dependencies.

# Get the version GoReleaser "would" get.  It uses `git describe` to figure
# out the nearest tag.

# This really only works in a release, because releases are tagged from
# release branches and do not get merged into main.

fail () {
    set +exu
    local ret="${1}"
    shift
    echo >&2 -e "$*"
    exit "$ret"
}

INPUT="${1}"
OUTPUT="${2}"

[[ -n ${INPUT} ]] || fail 2 "Input template file not specified"
[[ -n ${OUTPUT} ]] || fail 2 "Output file not specified"

# GORELEASER_CURRENT_TAG is set by the Dockerfile to override what tag
# GoReleaser thinks we're building for.
if [[ -n ${GORELEASER_CURRENT_TAG} ]]
then
    GIT_VERSION=${GORELEASER_CURRENT_TAG}
else
    # Otherwise, use git-describe(1) to come up with a version.
    GIT_VERSION=$(git describe --tags --exact-match 2>/dev/null)

    if [[ -z ${GIT_VERSION} ]]
    then
        NEAREST_TAG=$(git describe --tags --abbrev=0 2>/dev/null)
        [[ -n $NEAREST_TAG ]] || NEAREST_TAG=v0.0.0
        GIT_VERSION="${NEAREST_TAG}-next"
    fi
fi

# Strip off the v, if present.
VERSION=${GIT_VERSION#v}
[[ -n ${VERSION} ]] || fail 1 "Unable to get a version number."
# ^^ I'm pretty sure this can only happen if the tag is just 'v'

# RPM cannot have `-` in version strings, use `~`.
# (This is special, meaning that the substring should be sorted as _less_
# than the actual version, e.g. v7.0.0~rc.1-1 < v7.0.0-1)
RPMVERSION=${VERSION//-/'~'}

# Make substitutions into the template file.
if [[ ! -f ${INPUT} ]]
then
    fail 1 "GoReleaser template file not found at ${INPUT}"
fi

{
    sed -e 's/%VERSION%/'"${VERSION}"'/g' \
        -e 's/%RPMVERSION%/'"${RPMVERSION}"'/g' \
    "${INPUT}" > "${OUTPUT}.tmp" && \
    mv -f "${OUTPUT}.tmp" "${OUTPUT}"
} || fail 1 "Could not create ${OUTPUT}"
