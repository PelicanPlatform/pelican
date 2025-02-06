# ***************************************************************
#
#  Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

# For selecting OSG-maintained packages.
ARG BASE_OS=el9
ARG OSG_SERIES=23
ARG OSG_REPO=release

# For compiling Pelican.
ARG GO_VER=1.21.6
ARG NODEJS_VER=20

# For compiling LotMan.
ARG JSON_VERSION="v3.11.3"
ARG JSON_SCHEMA_VALIDATOR_VERSION="2.3.0"
ARG LOTMAN_VERSION="v0.0.4"

# Set the image or build stage to use for building the development and
# testing containers. It should contain Pelican's run-time dependencies.
ARG DEVTEST_BASE_IMAGE=origin-base

# Throughout the build, we need to refer to the platform that
# we're building *on* and the platform that we're building *for*.
# (Go supports cross-compilation.)
#
# Reference: https://docs.docker.com/reference/dockerfile/#automatic-platform-args-in-the-global-scope
#
# ARG BUILDPLATFORM
# ARG BUILDOS
# ARG BUILDARCH
# ARG TARGETPLATFORM
# ARG TARGETOS
# ARG TARGETARCH

# Set scitokens-oauth2-server image as a build stage so that we can copy its
# OA4MP installation into the images being built here.
FROM --platform=linux/amd64 hub.opensciencegrid.org/sciauth/scitokens-oauth2-server:release-20231118-1823 AS scitokens-oauth2-server

#################################################################
# Pelican Build Base
#
# This stage sets up the infrastructure for building the Pelican
# binaries. The actual build happens in a later stage because it
# depends on the target we're building for.
#################################################################
FROM --platform=${BUILDPLATFORM} almalinux:9 AS pelican-build-base
ARG BUILDPLATFORM
ARG BUILDOS
ARG BUILDARCH
ARG GO_VER
ARG NODEJS_VER

WORKDIR /pelican-build

COPY <<ENDCOPY /etc/yum.repos.d/goreleaser.repo
[goreleaser]
name=GoReleaser
baseurl=https://repo.goreleaser.com/yum/
enabled=1
gpgcheck=0
ENDCOPY
RUN --mount=type=cache,id=dnf-${BUILDPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  dnf install -y goreleaser
ENDRUN

RUN curl -O https://dl.google.com/go/go${GO_VER}.${BUILDOS}-${BUILDARCH}.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go${GO_VER}.${BUILDOS}-${BUILDARCH}.tar.gz \
    && rm -rf go${GO_VER}.${BUILDOS}-${BUILDARCH}.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# We use npm to bootstrap the installation of the required Node.js version
# and an updated version of npm itself. The `dnf remove` in the middle is to
# avoid there being multiple, incompatible versions of npm.
RUN --mount=type=cache,id=dnf-${BUILDPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  dnf install -y npm
  npm install -g n
  n ${NODEJS_VER}
  dnf remove -y npm
  npm install -g npm@latest
  n prune
ENDRUN

#################################################################
# Pelican Build
#
# This stage builds the Pelican binaries. Later stages should
# COPY them out as needed.
#################################################################
FROM --platform=${BUILDPLATFORM} pelican-build-base AS pelican-build
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

ARG IS_NONRELEASE_BUILD=true
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

COPY . .

# Have Docker's build process cache the Go build's cache directories.
RUN --mount=type=cache,id=go-mod-${TARGETPLATFORM},target=/root/go,sharing=locked \
    --mount=type=cache,id=go-cache-${TARGETPLATFORM},target=/root/.cache,sharing=locked \
    <<ENDRUN

  set -eux

  if ${IS_NONRELEASE_BUILD}; then
    goreleaser build --clean --single-target --snapshot
  else
    goreleaser build --clean --single-target
  fi

  # NOTE (brianaydemir): GoReleaser creates a dist directory whose path
  # includes the target architecture variant. Unfortunately, Docker does
  # not seem to reliably set TARGETVARIANT.
  #
  # On the assumption that we will never build for multiple variants of
  # one architecture, we create a symlink to make it easier for later build
  # stages to COPY files out.

  if [ "$TARGETARCH" = "amd64" ]; then
    VARIANT="v1"
  elif [ "$TARGETARCH" = "arm64" ]; then
    VARIANT="v8.0"
  fi
  for dir in ${PWD}/dist/${TARGETOS}_${TARGETARCH}/*${TARGETOS}_${TARGETARCH}*; do
    ln -s ${dir} ${dir%_${VARIANT}}
  done
ENDRUN

#################################################################
# Pelican Software Base
#
# This stage should contain setup common to all images that we wish
# to build (director, registry, origin, cache, etc.).
#################################################################
FROM hub.opensciencegrid.org/osg-htc/software-base:${OSG_SERIES}-${BASE_OS}-${OSG_REPO} AS pelican-software-base
ARG TARGETPLATFORM

WORKDIR /pelican

RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux

  # Throughout this build, we will have Docker's build process cache dnf's
  # cache directory, so that we can not include it in any final images and
  # also not incur the penalty of constantly re-pulling repo metadata.
  #
  # We configure dnf to expire metadata after 30min so that any build that
  # is triggered uses relatively up-to-date metadata.
  printf '%s\n' "metadata_expire=1800" >> /etc/dnf/dnf.conf

  dnf install -y tini
ENDRUN

#################################################################
# XRootD Software Init
#
# This stage adds the core of the XRootD installation, i.e.,
# everything that can be installed from an RPM.
#################################################################
FROM pelican-software-base AS xrootd-software-init
ARG TARGETPLATFORM
ARG TARGETARCH
ARG BASE_OS
ARG OSG_SERIES

# xrootd's UID and GID here are effectively set in stone because of the
# existing data out in the wild that is owned by these IDs.
RUN groupadd -g 10940 xrootd \
    && useradd -u 10940 -g 10940 -d / -s /sbin/nologin xrootd

# We need to pin the install for many of the RPMs to "Koji" until all of
# Pelican's patches are ingested into the OSG repositories.
ARG XROOTD_VERSION="5.7.2"
ARG XROOTD_RELEASE="1.5.purge.osg${OSG_SERIES}.${BASE_OS}"
ARG KOJIHUB_BASE_URL="https://kojihub2000.chtc.wisc.edu/kojifiles/packages/xrootd/${XROOTD_VERSION}/${XROOTD_RELEASE}"

# The packages from Koji need to be installed in a single dnf command in
# order to avoid unresolvable dependencies.
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux

  # NOTE: The `devel` packages are not necessary for any production
  # container images, but including them here simplifies the process
  # of building the dev container image.

  PACKAGES="\
    xrootd \
    xrootd-libs \
    xrootd-client \
    xrootd-client-libs \
    xrootd-server \
    xrootd-server-libs \
    xrootd-scitokens \
    xrootd-selinux \
    xrootd-voms \
    xrdcl-http \
    \
    xrootd-devel \
    xrootd-client-devel \
    xrootd-server-devel \
    "

  if [ "$TARGETARCH" = "amd64" ]; then
      PKG_ARCH=x86_64
  elif [ "$TARGETARCH" = "arm64" ]; then
      PKG_ARCH=aarch64
  fi

  package_urls=()

  for package in ${PACKAGES}; do
    if [ "$package" = "xrootd-selinux" ]; then
      package_urls+=(${KOJIHUB_BASE_URL}/noarch/${package}-${XROOTD_VERSION}-${XROOTD_RELEASE}.noarch.rpm)
    else
      package_urls+=(${KOJIHUB_BASE_URL}/${PKG_ARCH}/${package}-${XROOTD_VERSION}-${XROOTD_RELEASE}.${PKG_ARCH}.rpm)
    fi
  done
  dnf install -y "${package_urls[@]}"

  # The remaining packages can be installed from our usual repositories.
  dnf install -y --enablerepo=epel-testing xrootd-s3-http
  dnf install -y --enablerepo=osg-testing xrootd-multiuser xrdcl-pelican
  dnf install -y --enablerepo=osg-contrib xrootd-lotman

  # Configure XRootD to use the Pelican plugin.
  rm -f /etc/xrootd/client.plugins.d/xrdcl-http-plugin.conf
ENDRUN

#################################################################
# XRootD Build
#
# This stage builds XRootD components from source. Later stages
# should COPY out objects as needed.
#################################################################
FROM xrootd-software-init AS xrootd-build
ARG JSON_VERSION
ARG JSON_SCHEMA_VALIDATOR_VERSION
ARG LOTMAN_VERSION

WORKDIR /xrootd-build

RUN dnf install -y \
          cmake3 \
          gcc-c++ \
          git \
          \
          curl-devel \
          openssl-devel \
          sqlite-devel

# These ADD commands are for cache-hashing of the external repositories that
# we rely on for the build.

ADD https://api.github.com/repos/nlohmann/json/git/refs/tags/${JSON_VERSION} /tmp/hash-json
ADD https://api.github.com/repos/pboettch/json-schema-validator/git/refs/tags/${JSON_SCHEMA_VALIDATOR_VERSION} /tmp/hash-json-schema-validator
ADD https://api.github.com/repos/PelicanPlatform/lotman/git/refs/tags/${LOTMAN_VERSION} /tmp/hash-lotman

# Install LotMan's dependencies.

RUN git clone https://github.com/nlohmann/json.git && \
    cd json && \
    git checkout ${JSON_VERSION} && \
    mkdir build && cd build && \
    cmake .. && \
    make -j`nproc` install

RUN git clone https://github.com/pboettch/json-schema-validator.git && \
    cd json-schema-validator && \
    git checkout ${JSON_SCHEMA_VALIDATOR_VERSION} && \
    mkdir build && cd build && \
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j`nproc` install

# Install LotMan.

RUN git clone https://github.com/PelicanPlatform/lotman.git && \
    cd lotman && \
    git checkout ${LOTMAN_VERSION} && \
    mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j`nproc` install

#################################################################
# XRootD Software Base
#
# This stage assembles together a complete XRootD installation
# for Pelican. In the name of simplicity, it includes both plugins
# for running an origin and plugins for running a cache.
#################################################################
FROM xrootd-software-init AS xrootd-software-base

# NOTE: If the xrootd-software-init stage installs the xrootd-lotman
# package, then we do *not* need to copy LotMan-related libraries from the
# xrootd-build stage. We maintain these commented-out build commands in
# order to make it easy to switch to building these libraries from source.

# COPY --from=xrootd-build /usr/include/nlohmann /usr/include/nlohmann
# COPY --from=xrootd-build /usr/lib64/libLotMan.so /usr/lib64/
# COPY --from=xrootd-build /usr/lib64/libnlohmann_json_schema_validator.a /usr/lib64/

#################################################################
# Origin Base
#
# This stage assembles together everything needed to run a Pelican
# origin, except for the `pelican` binary itself.
#################################################################
FROM xrootd-software-base AS origin-base
ARG TARGETPLATFORM

RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  dnf install -y java-17-openjdk-headless
ENDRUN

# Install OA4MP. Most of the installation is in /opt, but there are
# additional files and configuration required.
# Reference: https://github.com/scitokens/scitokens-oauth2-server/blob/master/Dockerfile
COPY --from=scitokens-oauth2-server --chown=root:root /opt /opt

# Fix ownership and permissions. This is necessary so long as the tomcat
# user's UID and GID are not fixed by scitokens-oauth2-server.
RUN useradd -r -s /sbin/nologin tomcat && \
    chgrp -R tomcat /opt/tomcat/conf && \
    chmod g+rwx /opt/tomcat/conf && \
    chmod g+r /opt/tomcat/conf/* && \
    chown -R tomcat /opt/tomcat/logs/ /opt/tomcat/temp/ /opt/tomcat/webapps/ /opt/tomcat/work/ && \
    chgrp -R tomcat /opt/tomcat/bin /opt/tomcat/lib && \
    chmod g+rwx /opt/tomcat/bin && \
    chmod g+r /opt/tomcat/bin/* && \
    chown -R tomcat:tomcat /opt/tomcat/webapps/scitokens-server/ && \
    chown -R tomcat:tomcat /opt/scitokens-server/

# Replace the Tomcat server's default configuration so that Pelican can
# communicate with it over a socket.
COPY --chown=root:tomcat oa4mp/resources/server.xml /opt/tomcat/conf/server.xml

# This script is a documented part of OA4MP's bootstrap process, but we
# otherwise do not need it.
COPY --from=scitokens-oauth2-server /usr/local/bin/generate_jwk.sh /usr/local/bin/generate_jwk.sh

RUN <<ENDRUN
  set -eux

  ln -sf /usr/lib64/libapr-1.so.0 /opt/tomcat/lib/libapr-1.so.0

  # This security constraint line forces a redirect to HTTPS, which we aren't using.
  sed 's/<security-constraint>/<!--&/; s/\/security-constraint>/&-->/;' /opt/scitokens-server/web.xml > /opt/tomcat/webapps/scitokens-server/WEB-INF/web.xml
ENDRUN

ENV JAVA_HOME="/usr/lib/jvm/jre" \
    JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -Djava.library.path=/opt/tomcat/lib" \
    \
    CATALINA_HOME="/opt/tomcat" \
    CATALINA_BASE="/opt/tomcat" \
    CATALINA_OPTS="-Xms512M -Xmx1024M -server -XX:+UseParallelGC" \
    CATALINA_PID="/opt/tomcat/temp/tomcat.pid" \
    \
    ST_HOME="/opt/scitokens-server" \
    QDL_HOME="/opt/qdl" \
    PATH="${ST_HOME}/bin:${QDL_HOME}/bin:${PATH}"

#################################################################
# Pelican Director
#################################################################
FROM pelican-software-base AS director
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/${TARGETOS}_${TARGETARCH}/pelican_${TARGETOS}_${TARGETARCH}/pelican /usr/local/bin/pelican
COPY images/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "pelican", "director"]
CMD ["serve"]

FROM director AS osdf-director
RUN ln -s pelican /usr/local/bin/osdf
ENTRYPOINT ["/entrypoint.sh", "osdf", "director"]
CMD ["serve"]

#################################################################
# Pelican Registry
#################################################################
FROM pelican-software-base AS registry
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/${TARGETOS}_${TARGETARCH}/pelican_${TARGETOS}_${TARGETARCH}/pelican /usr/local/bin/pelican
COPY images/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "pelican", "registry"]
CMD ["serve"]

FROM registry AS osdf-registry
RUN ln -s pelican /usr/local/bin/osdf
ENTRYPOINT ["/entrypoint.sh", "osdf", "registry"]
CMD ["serve"]

#################################################################
# Pelican Origin
#################################################################
FROM origin-base AS origin
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/${TARGETOS}_${TARGETARCH}/pelican_${TARGETOS}_${TARGETARCH}/pelican /usr/local/bin/pelican
COPY images/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "pelican", "origin"]
CMD ["serve"]

FROM origin AS osdf-origin
ARG TARGETPLATFORM
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux

  # These IDs must match OSG's sssd sidecar containers.
  groupadd -r -g 990 sssd
  useradd -r -g sssd -u 990 -d / -s /usr/sbin/nologin -c "System user for sssd" sssd
  dnf install -y sssd-client
ENDRUN
RUN ln -s pelican /usr/local/bin/osdf
ENTRYPOINT ["/entrypoint.sh", "osdf", "origin"]
CMD ["serve"]

#################################################################
# Pelican Cache
#################################################################
FROM xrootd-software-base AS cache
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/${TARGETOS}_${TARGETARCH}/pelican-server_${TARGETOS}_${TARGETARCH}/pelican-server /usr/local/bin/pelican-server
COPY images/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "pelican-server", "cache"]
CMD ["serve"]

FROM cache AS osdf-cache
RUN ln -s pelican-server /usr/local/bin/osdf-server
ENTRYPOINT ["/entrypoint.sh", "osdf-server", "cache"]
CMD ["serve"]

#################################################################
# DevTest Container Base
#################################################################
FROM ${DEVTEST_BASE_IMAGE} AS devtest-container-base
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG GO_VER
ARG NODEJS_VER

# Install the Go and Node.js toolchains using the same commands as the
# pelican-build-init stage, taking care that the installation matches this
# build's target platform.

COPY <<ENDCOPY /etc/yum.repos.d/goreleaser.repo
[goreleaser]
name=GoReleaser
baseurl=https://repo.goreleaser.com/yum/
enabled=1
gpgcheck=0
ENDCOPY
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  dnf install -y goreleaser
ENDRUN

RUN curl -O https://dl.google.com/go/go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz \
    && rm -rf go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  dnf install -y npm
  npm install -g n
  n ${NODEJS_VER}
  dnf remove -y npm
  npm install -g npm@latest
  n prune
ENDRUN

# Install the MinIO server and client for S3 tests.
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux

  if [ "$TARGETARCH" = "amd64" ]; then
      PKG_ARCH=x86_64
  elif [ "$TARGETARCH" = "arm64" ]; then
      PKG_ARCH=aarch64
  fi

  curl -o ./minio.rpm https://dl.min.io/server/minio/release/${TARGETOS}-${TARGETARCH}/archive/minio-20231214185157.0.0-1.${PKG_ARCH}.rpm
  dnf install -y ./minio.rpm
  rm -f ./minio.rpm
ENDRUN

#################################################################
# Development Container
#
# This container should contain all of Pelican's dependencies,
# both run-time and development-time. Because it is intended for
# development, it does not need Pelican itself.
#################################################################
FROM devtest-container-base AS dev-container
ARG TARGETPLATFORM

# Enable the CodeReady Linux Builder repository.
RUN /usr/bin/crb enable

# Install a kitchen sink's worth of development tools and libraries.
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked \
  dnf install -y --enablerepo=osg-contrib \
        cmake3 \
        docker \
        gdb \
        gcc-c++ \
        git \
        jq \
        make \
        nano \
        procps \
        python3-pip \
        systemd \
        valgrind \
        vim \
        \
        curl-devel \
        gtest-devel \
        libcap-devel \
        libuuid-devel \
        openssl-devel \
        sqlite-devel \
        tinyxml2-devel \
        zlib-devel \
        \
        json-schema-validator-devel \
        nlohmann-json-devel

# Suppress Git's "dubious ownership" warning.
ENV GOFLAGS="-buildvcs=false"

RUN python3 -m pip --no-cache-dir install pre-commit
COPY images/dev-config.yaml /etc/pelican/pelican.yaml
WORKDIR /app
COPY ./images/dev-container-entrypoint.sh /dev-container-entrypoint.sh
ENTRYPOINT ["/dev-container-entrypoint.sh"]
