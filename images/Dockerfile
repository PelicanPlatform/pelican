# ***************************************************************
#
#  Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

# For selecting OSG-maintained packages.
ARG BASE_OS=el9
ARG OSG_SERIES=24
ARG OSG_REPO=release

# For compiling Pelican.
ARG GO_VER=1.24.7
ARG GORELEASER_CURRENT_TAG
ARG NODEJS_VER=20

# For controlling the UID/GID of users in the container images.
ARG PELICAN_UID=10941
ARG PELICAN_GID=10941
ARG XROOTD_UID=10940
ARG XROOTD_GID=10940

# For controlling how XRootD plugins are installed:
#
#   - Set '*_BUILD' to 'true' to build RPMs from source.
#     Otherwise, the RPMs will be installed from the "usual" repositories.
#
#   - Set '*_VER' to the version (tag) to install, without the leading "v".
#     When building RPMs from source, this may be any commit spec understood
#     by 'git checkout'.
#
#     WARNING: When building an RPM from source, the version the built RPM
#     claims to be will *always* come from the .spec file. The upstream Git
#     repository must have a correct .spec file, or confusion will ensue.
#

ARG LOTMAN_SRC_BUILD=false
ARG LOTMAN_VER=0.0.4
# Note: github_scripts/osx_install.sh also (separately) specifies the version to use
# Until the two places are programmatically synchronized, please double-check by hand
# when doing version changes.
ARG XRDCL_PELICAN_SRC_BUILD=false
ARG XRDCL_PELICAN_VER=1.5.6
ARG XROOTD_LOTMAN_SRC_BUILD=false
ARG XROOTD_LOTMAN_VER=0.0.5
ARG XROOTD_S3_HTTP_SRC_BUILD=true
ARG XROOTD_S3_HTTP_VER=0.5.2
# Installed from Koji if not building it from source
ARG XRDHTTP_PELICAN_SRC_BUILD=false
ARG XRDHTTP_PELICAN_VER=0.0.7
ARG XRDHTTP_PELICAN_RELEASE="2.osg${OSG_SERIES}.${BASE_OS}"

# Set scitokens-oauth2-server image as a build stage so that we can copy its
# OA4MP installation into the images being built here.
FROM --platform=linux/amd64 hub.opensciencegrid.org/sciauth/scitokens-oauth2-server:release-20250625-2352 AS scitokens-oauth2-server

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
  dnf install -y goreleaser make
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

ARG GORELEASER_CURRENT_TAG
ENV GORELEASER_CURRENT_TAG=${GORELEASER_CURRENT_TAG}
ARG IS_NONRELEASE_BUILD=true
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

COPY . .

RUN --mount=type=cache,id=go-cache,target=/root/.cache/go-build,sharing=shared \
    --mount=type=cache,id=go-mod-cache-${TARGETPLATFORM},target=/root/go,sharing=locked \
    --mount=type=cache,id=npm-${TARGETPLATFORM},target=/root/.npm,sharing=locked \
    --mount=type=cache,id=node-modules-${TARGETPLATFORM},target=/pelican-build/web_ui/frontend/node_modules,sharing=locked \
    --mount=type=cache,id=nextjs-cache-${TARGETPLATFORM},target=/pelican-build/web_ui/frontend/.next/cache,sharing=locked \
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
ARG PELICAN_USER=pelican
ARG PELICAN_UID
ARG PELICAN_GID

WORKDIR /pelican

RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux

  # Create pelican user and group
  groupadd -g ${PELICAN_GID} ${PELICAN_USER}
  useradd -u ${PELICAN_UID} -g ${PELICAN_GID} -d / -s /sbin/nologin ${PELICAN_USER}

  # Throughout this build, we will have Docker's build process cache dnf's
  # cache directory, so that we can not include it in any final images and
  # also not incur the penalty of constantly re-pulling repo metadata.
  #
  # We configure dnf to expire metadata after 30min so that any build that
  # is triggered uses relatively up-to-date metadata.

  printf '%s\n' "metadata_expire=1800" >> /etc/dnf/dnf.conf

  dnf install -y tini 'dnf-command(versionlock)'

  mkdir -p /etc/pelican/config.d
  mkdir -p /usr/share/pelican/config.d
ENDRUN

COPY images/pelican.yaml /etc/pelican/pelican.yaml

#################################################################
# XRootD Software Init
#
# This stage adds the core of the XRootD installation, i.e.,
# everything that should be installed from an existing RPM.
#################################################################
FROM pelican-software-base AS xrootd-software-init
ARG TARGETPLATFORM
ARG TARGETARCH
ARG BASE_OS
ARG OSG_SERIES
ARG XROOTD_UID
ARG XROOTD_GID

# xrootd's UID and GID here are effectively set in stone because of the
# existing data out in the wild that is owned by these IDs.
RUN groupadd -g ${XROOTD_GID} xrootd \
    && useradd -u ${XROOTD_UID} -g ${XROOTD_GID} -d / -s /sbin/nologin xrootd

# We need to pin the install for many of the RPMs to "Koji" until all of
# Pelican's patches are ingested into the OSG repositories.
# NOTE: If you update this version, you must also update the version in
# github_scripts/osx_install.sh
ARG XROOTD_VER="5.9.1"
ARG XROOTD_RELEASE="1.2.osg${OSG_SERIES}.${BASE_OS}"
ARG KOJIHUB_BASE_URL="https://kojihub2000.chtc.wisc.edu/kojifiles/packages/xrootd/${XROOTD_VER}/${XROOTD_RELEASE}"

# The packages from Koji need to be installed in a single dnf command in
# order to avoid unresolvable dependencies.
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux

  # NOTE: The `devel` packages are not necessary for any production
  # container images, but including them here means we that don't need to
  # duplicate all this logic when building other stages and images.

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
    xrootd-private-devel \
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
      package_urls+=(${KOJIHUB_BASE_URL}/noarch/${package}-${XROOTD_VER}-${XROOTD_RELEASE}.noarch.rpm)
    else
      package_urls+=(${KOJIHUB_BASE_URL}/${PKG_ARCH}/${package}-${XROOTD_VER}-${XROOTD_RELEASE}.${PKG_ARCH}.rpm)
    fi
  done
  dnf install -y "${package_urls[@]}"

  # Pelican is sensitive to the exact XRootD version that is
  # installed, so having just installed a specific set of packages,
  # prevent other packages from changing them via dependencies.

  dnf versionlock "xrootd*"
ENDRUN

#################################################################
# XRootD Build
#
# This stage builds XRootD components from source.
#################################################################
FROM xrootd-software-init AS xrootd-build
ARG LOTMAN_SRC_BUILD
ARG LOTMAN_VER
ARG XRDCL_PELICAN_SRC_BUILD
ARG XRDCL_PELICAN_VER
ARG XRDHTTP_PELICAN_SRC_BUILD
ARG XRDHTTP_PELICAN_VER
ARG XROOTD_LOTMAN_SRC_BUILD
ARG XROOTD_LOTMAN_VER
ARG XROOTD_S3_HTTP_SRC_BUILD
ARG XROOTD_S3_HTTP_VER

WORKDIR /xrootd-build

RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux

  # Install the build requirements only if we actually need them, so that we
  # don't slow down the overall build unnecessarily.

  have_requirements=false

  install_requirements() {
    if ! ${have_requirements}; then
      dnf install -y --enablerepo=osg-contrib \
            cmake3 \
            gcc-c++ \
            git \
            systemd \
            \
            curl-devel \
            libcap-devel \
            libuuid-devel \
            openssl-devel \
            sqlite-devel \
            tinyxml2-devel \
            zlib-devel \
            \
            json-schema-validator-devel \
            nlohmann-json-devel
    fi
    have_requirements=true
  }

  # The implementation and use of `run_task` is made possible by bash's
  # "indirect expansion" feature, and an assumption that all of the relevant
  # GitHub repositories are laid out similarly.
  #
  # References:
  #   - https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html
  #   - https://unix.stackexchange.com/a/718622

  run_task() {
    local ARG=$1
    local PROJECT=$2
    local REPO=$3

    local SRC_BUILD=${ARG}_SRC_BUILD
    local VER=${ARG}_VER

    if ${!SRC_BUILD}; then
      install_requirements
      git clone https://github.com/${PROJECT}/${REPO}.git ${REPO}
      (
        # Use a subshell to scope the `cd` below to this `run_task` invocation.
        cd ${REPO}
        if [[ ${!VER} =~ "." ]]; then
          git checkout v${!VER}
        else
          git checkout ${!VER}
        fi
        rpmbuild -bb --build-in-place --define '_topdir /xrootd-build' rpm/${REPO}.spec
      )
      # Install the package in case its a dependency of a later package.
      dnf install -y /xrootd-build/RPMS/*/${REPO}-*.rpm
    fi
  }

  run_task  LOTMAN          PelicanPlatform  lotman
  run_task  XRDCL_PELICAN   PelicanPlatform  xrdcl-pelican
  run_task  XRDHTTP_PELICAN PelicanPlatform  xrdhttp-pelican
  run_task  XROOTD_LOTMAN   PelicanPlatform  xrootd-lotman
  run_task  XROOTD_S3_HTTP  PelicanPlatform  xrootd-s3-http
ENDRUN

#################################################################
# XRootD Software Base
#
# This stage assembles together a complete XRootD installation
# for Pelican. In the name of simplicity, it includes both plugins
# for running an origin and plugins for running a cache.
#################################################################
FROM xrootd-software-init AS xrootd-software-base
ARG TARGETARCH
ARG LOTMAN_SRC_BUILD
ARG LOTMAN_VER
ARG XRDCL_PELICAN_SRC_BUILD
ARG XRDCL_PELICAN_VER
ARG XRDHTTP_PELICAN_SRC_BUILD
ARG XRDHTTP_PELICAN_VER
ARG XRDHTTP_PELICAN_RELEASE
ARG XROOTD_LOTMAN_SRC_BUILD
ARG XROOTD_LOTMAN_VER
ARG XROOTD_S3_HTTP_SRC_BUILD
ARG XROOTD_S3_HTTP_VER

# If we didn't build it from source, install it from Koji instead.
# Note the %ARCH% placeholders that need to be substituted.
ARG XRDHTTP_PELICAN_KOJI_URL="https://kojihub2000.chtc.wisc.edu/kojifiles/packages/xrdhttp-pelican/${XRDHTTP_PELICAN_VER}/${XRDHTTP_PELICAN_RELEASE}/%ARCH%/xrdhttp-pelican-${XRDHTTP_PELICAN_VER}-${XRDHTTP_PELICAN_RELEASE}.%ARCH%.rpm"

RUN --mount=type=bind,from=xrootd-build,source=/xrootd-build,target=/xrootd-build \
    --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked \
    <<ENDRUN

  set -eux

  dnf install -y xrootd-multiuser

  if [ "$TARGETARCH" = "amd64" ]; then
      PKG_ARCH=x86_64
  elif [ "$TARGETARCH" = "arm64" ]; then
      PKG_ARCH=aarch64
  fi


  # NOTE: We include the `PROJECT` parameter here, even thought it is not
  # used, in order to maintain symmetry with the xrootd-build stage above.

  run_task() {
    local ARG=$1
    local PROJECT=$2
    local REPO=$3

    local SRC_BUILD=${ARG}_SRC_BUILD
    local VER=${ARG}_VER
    local KOJI_URL=${ARG}_KOJI_URL

    if ${!SRC_BUILD}; then
      dnf install -y /xrootd-build/RPMS/*/${REPO}-*.rpm
    elif [ -n "${!KOJI_URL-}" ]; then
      echo ${!KOJI_URL} | sed "s/%ARCH%/${PKG_ARCH}/g" | xargs \
          dnf install -y --enablerepo=epel-testing --enablerepo=osg-testing
    else
      dnf install -y --enablerepo=epel-testing --enablerepo=osg-development --enablerepo=osg-testing --enablerepo=osg-upcoming-testing ${REPO}-${!VER}
    fi
  }

  run_task  LOTMAN          PelicanPlatform  lotman
  run_task  XRDCL_PELICAN   PelicanPlatform  xrdcl-pelican
  run_task  XRDHTTP_PELICAN PelicanPlatform  xrdhttp-pelican
  run_task  XROOTD_LOTMAN   PelicanPlatform  xrootd-lotman
  run_task  XROOTD_S3_HTTP  PelicanPlatform  xrootd-s3-http

  # Configure XRootD to use the Pelican plugin.
  rm -f /etc/xrootd/client.plugins.d/xrdcl-http-plugin.conf
ENDRUN

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

  # We need OpenJDK for OA4MP.
  # We need sssd-client for some xrootd-multiuser setups.
  dnf install -y java-17-openjdk-headless sssd-client
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

# Replace other bits and bobs to take into account the fact that Pelican
# authenticates the user and proxies requests.
COPY --chown=tomcat:tomcat oa4mp/resources/client-template.xml /opt/scitokens-server/etc/templates/client-template.xml
COPY --chown=tomcat:tomcat oa4mp/resources/device-consent.jsp /opt/tomcat/webapps/scitokens-server/device-consent.jsp
COPY --chown=tomcat:tomcat oa4mp/resources/authorize-remote-user.jsp /opt/tomcat/webapps/scitokens-server/authorize-remote-user.jsp
COPY --chown=tomcat:tomcat oa4mp/resources/device-fail.jsp /opt/tomcat/webapps/scitokens-server/device-fail.jsp
COPY --chown=tomcat:tomcat oa4mp/resources/device-ok.jsp /opt/tomcat/webapps/scitokens-server/device-ok.jsp

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
COPY --from=pelican-build /pelican-build/dist/${TARGETOS}_${TARGETARCH}/pelican-server_${TARGETOS}_${TARGETARCH}/pelican-server /usr/local/sbin/pelican-server
COPY images/entrypoint.sh /entrypoint.sh
COPY scripts/geoquery.py /usr/local/sbin/geoquery
RUN dnf install -y python3-pip \
    && python3 -m pip install geoip2
ENTRYPOINT ["/entrypoint.sh", "pelican-server", "director"]
CMD ["serve"]

FROM director AS osdf-director
RUN ln -s pelican-server /usr/local/sbin/osdf-server
ENTRYPOINT ["/entrypoint.sh", "osdf-server", "director"]
CMD ["serve"]

#################################################################
# Pelican Registry
#################################################################
FROM pelican-software-base AS registry
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/${TARGETOS}_${TARGETARCH}/pelican-server_${TARGETOS}_${TARGETARCH}/pelican-server /usr/local/sbin/pelican-server
COPY images/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "pelican-server", "registry"]
CMD ["serve"]

FROM registry AS osdf-registry
RUN ln -s pelican-server /usr/local/sbin/osdf-server
ENTRYPOINT ["/entrypoint.sh", "osdf-server", "registry"]
CMD ["serve"]

#################################################################
# Pelican Origin
#################################################################
FROM origin-base AS origin
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/${TARGETOS}_${TARGETARCH}/pelican-server_${TARGETOS}_${TARGETARCH}/pelican-server /usr/local/sbin/pelican-server
COPY images/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "pelican-server", "origin"]
CMD ["serve"]

FROM origin AS osdf-origin
ARG TARGETPLATFORM
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux

  # These IDs must match OSG's sssd sidecar containers.
  groupadd -r -g 990 sssd
  useradd -r -g sssd -u 990 -d / -s /usr/sbin/nologin -c "System user for sssd" sssd
ENDRUN
RUN ln -s pelican-server /usr/local/sbin/osdf-server
ENTRYPOINT ["/entrypoint.sh", "osdf-server", "origin"]
CMD ["serve"]

#################################################################
# Pelican Cache
#################################################################
FROM xrootd-software-base AS cache
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/${TARGETOS}_${TARGETARCH}/pelican-server_${TARGETOS}_${TARGETARCH}/pelican-server /usr/local/sbin/pelican-server
COPY images/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "pelican-server", "cache"]
CMD ["serve"]

FROM cache AS osdf-cache
RUN ln -s pelican-server /usr/local/sbin/osdf-server
ENTRYPOINT ["/entrypoint.sh", "osdf-server", "cache"]
CMD ["serve"]

#################################################################
# Testing Environment
#
# This container should contain a minimum of extra packages and
# other software for testing a Pelican release.
#################################################################
FROM origin-base AS pelican-test
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG GO_VER

# Install select development packages.
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked \
  dnf install -y git make

# Install Go using the same commands as the pelican-build-init stage.
RUN curl -O https://dl.google.com/go/go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz \
    && rm -rf go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

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

ENTRYPOINT []
CMD ["/bin/bash"]
WORKDIR /app

#################################################################
# Development Environment
#
# This container should contain all of Pelican's dependencies,
# both run-time and development-time. Because it is intended for
# development, it does not need Pelican itself.
#################################################################
FROM pelican-test AS pelican-dev
ARG TARGETPLATFORM
ARG NODEJS_VER

# Install GoReleaser using the same commands as the pelican-build-init stage.
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

# Install Node.js using the same commands as the pelican-build-init stage.
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  dnf install -y npm
  npm install -g n
  n ${NODEJS_VER}
  dnf remove -y npm
  npm install -g npm@latest
  n prune
ENDRUN

# Enable the CodeReady Linux Builder repository.
RUN /usr/bin/crb enable

# Install a kitchen sink's worth of development tools and libraries.
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked \
  dnf install -y --enablerepo=osg-contrib \
        cmake3 \
        delve \
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
