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

# Throughout the build, we need to refer to the platform that
# we're building *on* and the platform that we're building *for*.
# (Docker BuildKit and Go both support cross-compilation.)
#
# For quick reference, the relevant build args are commented-out
# below. They are present in the global scope by default, so they
# only need to be declared in the build stages that need them.
#
# More thorough documentation can be found at:
#
#   https://docs.docker.com/reference/dockerfile/#automatic-platform-args-in-the-global-scope
#
# ARG BUILDPLATFORM
# ARG BUILDOS
# ARG BUILDARCH
# ARG TARGETPLATFORM
# ARG TARGETOS
# ARG TARGETARCH

# For selecting OSG-maintained packages.
ARG ALMALINUX_TAG=9
ARG BASE_OS=el9
ARG OSG_SERIES=25
ARG OSG_REPO=release

# For compiling custom/one-off releases of Pelican.
# (We cannot supply a default value because GoReleaser will use it as-is.)
ARG GORELEASER_CURRENT_TAG

# For controlling the UID/GID of users in the container images.
# Note that XRootD's UID and GID here are effectively set in stone
# because of existing data in the wild that is owned by these IDs.
ARG PELICAN_USERNAME=pelican
ARG PELICAN_UID=10941
ARG PELICAN_GID=10941
ARG XROOTD_USERNAME=xrootd
ARG XROOTD_UID=10940
ARG XROOTD_GID=10940
ARG TOMCAT_USERNAME=tomcat
ARG TOMCAT_UID=10443
ARG TOMCAT_GID=10443

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
ARG LOTMAN_SRC_BUILD=false
ARG LOTMAN_VER=0.0.4
# Note: github_scripts/osx_install.sh also (separately) specifies the version to use.
# Until the two places are programmatically synchronized, please double-check by hand
# when doing version changes.
ARG XRDCL_PELICAN_SRC_BUILD=false
ARG XRDCL_PELICAN_VER=1.5.6
ARG XROOTD_LOTMAN_SRC_BUILD=false
ARG XROOTD_LOTMAN_VER=0.0.5
ARG XROOTD_S3_HTTP_SRC_BUILD=true
ARG XROOTD_S3_HTTP_VER=0.6.4
# Installed from Koji if not building it from source.
ARG XRDHTTP_PELICAN_SRC_BUILD=false
ARG XRDHTTP_PELICAN_VER=0.0.10
ARG XRDHTTP_PELICAN_RELEASE="1.osg${OSG_SERIES}.${BASE_OS}"

# For controlling the version of OA4MP that is installed.
ARG OA4MP_VER=6.2.3
ARG JAVA_VER=17
ARG TOMCAT_VER=9.0.115

# For controlling where OA4MP is installed.
# The args' names loosely match Pelican's configuration parameters.
ARG QDL_LOC=/opt/qdl
ARG SCITOKENS_SERVER_LOC=/opt/scitokens-server
ARG TOMCAT_LOC=/opt/tomcat

#################################################################
# Pelican Build Base
#
# This stage sets up the infrastructure for building the Pelican
# binaries. The actual build happens in a later stage because it
# depends on the target we're building for.
#################################################################
FROM --platform=${BUILDPLATFORM} almalinux:${ALMALINUX_TAG} AS pelican-build-base
ARG BUILDPLATFORM
ARG BUILDOS
ARG BUILDARCH

WORKDIR /pelican-build
RUN --mount=type=bind,source=go.mod,target=/context/go.mod \
    --mount=type=bind,source=web_ui/frontend/package.json,target=/context/package.json \
    --mount=type=cache,id=dnf-${BUILDPLATFORM},target=/var/cache/dnf,sharing=locked \
    <<ENDRUN

  set -eux
  set -o pipefail

  # Install GoReleaser and other tools.

  cat >/etc/yum.repos.d/goreleaser.repo <<-EOF
		[goreleaser]
		name=GoReleaser
		baseurl=https://repo.goreleaser.com/yum/
		enabled=1
		gpgcheck=0
		exclude=goreleaser-pro
	EOF
  dnf install -y goreleaser jq make

  # Install Go.
  # Use go.mod and the go.dev API to determine the most recent version.
  # References:
  #   - https://pkg.go.dev/golang.org/x/website/internal/dl
  #   - https://github.com/golang/go/issues/34864

  GO_LANG_VER=$(grep -E '^go[[:space:]]*[0-9]+\.[0-9]+' /context/go.mod | grep -oE '[0-9]+\.[0-9]+')
  GO_TOOLCHAIN_VER=$(curl https://go.dev/dl/?mode=json | jq -r ".[].version | select(startswith(\"go${GO_LANG_VER}\"))" | sort -rV | head -n 1)
  rm -rf /usr/local/go
  curl -fSL https://dl.google.com/go/${GO_TOOLCHAIN_VER}.${BUILDOS}-${BUILDARCH}.tar.gz | tar -xz -f - -C /usr/local

  # Install Node.js.
  #
  # We use npm to bootstrap the installation of the required Node.js version
  # and an updated version of npm itself. The `dnf remove` in the middle is to
  # avoid there being multiple, incompatible versions of npm.

  dnf install -y npm
  npm install -g n
  n $(jq < /context/package.json -r .engines.node)
  dnf remove -y npm
  npm install -g npm@latest
  n prune
ENDRUN

# Make sure that the version of Go we just installed comes first.
ENV PATH="/usr/local/go/bin:${PATH}"

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
ARG IS_NONRELEASE_BUILD=true

ENV GORELEASER_CURRENT_TAG=${GORELEASER_CURRENT_TAG}
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
  set -o pipefail

  if ${IS_NONRELEASE_BUILD}; then
    goreleaser build --id pelican-server --clean --single-target --snapshot
  else
    goreleaser build --id pelican-server --clean --single-target
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
  for dir in ${PWD}/dist/*${TARGETOS}_${TARGETARCH}*; do
    ln -s ${dir} ${dir%_${VARIANT}}
  done
ENDRUN

#################################################################
# Pelican Software Base
#
# This stage should contain setup common to all images that we wish
# to build (director, registry, origin, cache, etc.).
#################################################################
FROM almalinux:${ALMALINUX_TAG} AS pelican-software-base
ARG TARGETPLATFORM
ARG BASE_OS
ARG OSG_SERIES
ARG PELICAN_USERNAME
ARG PELICAN_UID
ARG PELICAN_GID

WORKDIR /pelican
RUN --mount=type=bind,source=images/pelican.yaml,target=/context/pelican.yaml \
    --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked \
    <<ENDRUN

  set -eux
  set -o pipefail

  # Create a user and group for running Pelican daemons.

  groupadd -g ${PELICAN_GID} ${PELICAN_USERNAME}
  useradd -u ${PELICAN_UID} -g ${PELICAN_GID} -d / -s /sbin/nologin -c "Pelican daemons" ${PELICAN_USERNAME}

  # Create directories for Pelican's configuration files.

  mkdir -p /usr/share/pelican/config.d
  mkdir -p /etc/pelican/config.d
  cp /context/pelican.yaml /etc/pelican/pelican.yaml

  # Throughout this build, we will have Docker's build process cache dnf's
  # cache directory, so that we can not include it in any final images and
  # also not incur the penalty of constantly re-pulling repo metadata.
  #
  # We configure dnf to expire metadata after 30min so that any build that
  # is triggered uses relatively up-to-date metadata.

  printf '%s\n' "metadata_expire=1800" >> /etc/dnf/dnf.conf

  # Install OSG's yum repositories (https://osg-htc.org/docs/common/yum/).

  dnf install -y \
    epel-release \
    yum-utils \
    https://repo.osg-htc.org/osg/${OSG_SERIES}-main/osg-${OSG_SERIES}-main-${BASE_OS}-release-latest.rpm
  crb enable
  yum-config-manager --setopt=install_weak_deps=False --save

  # Install common software.

  dnf install -y \
    'dnf-command(versionlock)' \
    jq \
    less \
    osg-ca-certs \
    procps \
    psmisc \
    python3-pip \
    tini \
    unzip
ENDRUN

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
ARG XROOTD_USERNAME
ARG XROOTD_UID
ARG XROOTD_GID

# We need to pin the install for many of the RPMs to "Koji" until all of
# Pelican's patches are ingested into the OSG repositories.
# NOTE: If you update this version, you must also update the version in
# github_scripts/osx_install.sh.
ARG XROOTD_VER="5.9.1"
ARG XROOTD_RELEASE="1.3.osg${OSG_SERIES}.${BASE_OS}"
ARG KOJIHUB_BASE_URL="https://kojihub2000.chtc.wisc.edu/kojifiles/packages/xrootd/${XROOTD_VER}/${XROOTD_RELEASE}"

# The packages from Koji need to be installed in a single dnf command in
# order to avoid unresolvable dependencies.
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  set -o pipefail

  # Create a user and group for running XRootD daemons.

  groupadd -g ${XROOTD_GID} ${XROOTD_USERNAME}
  useradd -u ${XROOTD_UID} -g ${XROOTD_GID} -d / -s /sbin/nologin -c "XRootD daemons" ${XROOTD_USERNAME}

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
  set -o pipefail

  # Install the build requirements only if we actually need them, so that we
  # don't slow down the overall build unnecessarily.

  have_requirements=false

  install_requirements() {
    if ! ${have_requirements}; then
      dnf install -y --enablerepo=osg-contrib \
            cmake3 \
            gcc-c++ \
            git \
            rpmdevtools \
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
  set -o pipefail

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
# Origin Software Base
#
# This stage assembles together everything needed to run a Pelican
# origin, except for the `pelican` binary itself. Most of the work
# here is installing OA4MP and its dependencies by hand.
#################################################################
FROM xrootd-software-base AS origin-software-base
ARG TARGETPLATFORM
ARG TOMCAT_USERNAME
ARG TOMCAT_UID
ARG TOMCAT_GID
ARG OA4MP_VER
ARG JAVA_VER
ARG TOMCAT_VER
ARG QDL_LOC
ARG SCITOKENS_SERVER_LOC
ARG TOMCAT_LOC

# Define environment variables for where OA4MP and Apache Tomcat are
# installed, and for how to run them. Note that their names follow the
# conventions and requirements of these apps, not Pelican's.

ENV ST_HOME="${SCITOKENS_SERVER_LOC}" \
    QDL_HOME="${QDL_LOC}" \
    CATALINA_HOME="${TOMCAT_LOC}"

ENV CATALINA_PID="${CATALINA_HOME}/temp/tomcat.pid" \
    CATALINA_OPTS="-Xms512M -Xmx1024M -server -XX:+UseParallelGC" \
    JAVA_HOME="/usr/lib/jvm/jre" \
    JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/urandom -Djava.library.path=${CATALINA_HOME}/lib" \
    PATH="${ST_HOME}/bin:${QDL_HOME}/bin:${PATH}"

RUN --mount=type=bind,source=oa4mp/resources,target=/context \
    --mount=type=tmpfs,target=/tmp \
    --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked \
    <<ENDRUN

  # In the same vein as the cache mount for 'dnf', this step uses a tmpfs
  # mount for '/tmp' so that we can download files somewhere and not worry
  # about cleaning up after ourselves.

  set -eux
  set -o pipefail

  # OA4MP and Apache Tomcat both require a Java runtime.
  dnf install -y java-${JAVA_VER}-openjdk-headless

  #---------------------------------------------------------------
  # Install Apache Tomcat.

  # Create a user and group for running the Tomcat server.
  groupadd -g ${TOMCAT_GID} ${TOMCAT_USERNAME}
  useradd -u ${TOMCAT_UID} -g ${TOMCAT_GID} -d / -s /sbin/nologin -c "Apache Tomcat server" ${TOMCAT_USERNAME}

  # Download and install Tomcat.
  mkdir -p ${CATALINA_HOME}
  curl -fSL https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VER}/bin/apache-tomcat-${TOMCAT_VER}.tar.gz | tar -xz -f - -C ${CATALINA_HOME} --strip-components=1

  # Remove the demo apps to minimize unexpected behavior.
  rm -rf ${CATALINA_HOME}/webapps/*

  # Let Tomcat read its own installation.
  # The permissions in the tarball are unusually restrictive.
  chmod -R g+rX ${CATALINA_HOME}/*
  chgrp -R ${TOMCAT_USERNAME} ${CATALINA_HOME}/*

  # Let Tomcat write to its own working directories.
  chmod g+w ${CATALINA_HOME}/logs
  chmod g+w ${CATALINA_HOME}/temp
  chmod g+w ${CATALINA_HOME}/work

  #---------------------------------------------------------------
  # Install OA4MP.
  #
  # The OA4MP installer is overkill in that it installs quite a bit more
  # than what Pelican needs. However, to be consistent with QDL below, we
  # run the installer as intended and then remove extra bits afterwards.

  OA4MP_INSTALLER=/tmp/oa4mp-installer.jar
  curl -fSL https://github.com/ncsa/oa4mp/releases/download/v${OA4MP_VER}/server-installer.jar -o ${OA4MP_INSTALLER}
  java -jar ${OA4MP_INSTALLER} install -dir ${ST_HOME} -store file_store

  OA4MP_WEBAPP=${CATALINA_HOME}/webapps/scitokens-server
  mkdir -p ${OA4MP_WEBAPP}
  unzip -d ${OA4MP_WEBAPP} ${ST_HOME}/lib/oauth2.war

  # Make the unpacked webapp match the rest of the Tomcat installation.
  chmod -R u=rwX,g=rX,o= ${OA4MP_WEBAPP}
  chgrp -R ${TOMCAT_USERNAME} ${OA4MP_WEBAPP}

  # We have no need for .war files now that we've unpacked the ones we need.
  rm -rf ${ST_HOME}/lib/*.war

  # We have no need for this OAuth2 command-line tool.
  # (It does not even appear to come with a shell script for running it.)
  rm ${ST_HOME}/lib/clc.jar

  # We have no need for this JWT command-line tool.
  rm ${ST_HOME}/bin/jwt
  rm ${ST_HOME}/lib/jwt.jar

  # We currently have no need for this database migration tool.
  rm ${ST_HOME}/bin/migrate
  rm ${ST_HOME}/lib/fs-migrate.jar

  # Replace various web pages with Pelican-themed versions.
  cp /context/jsp-overrides/*.jsp ${OA4MP_WEBAPP}

  # Make OA4MP's executables executable by everyone, not only 'root'.
  chmod a+rX ${ST_HOME}/bin/*

  # Let OA4MP write to its own working directories.
  chmod -R ug=rwX,o= ${ST_HOME}/var/storage
  chgrp -R ${TOMCAT_USERNAME} ${ST_HOME}/var/storage

  #---------------------------------------------------------------
  # Install QDL.

  QDL_INSTALLER=/tmp/qdl-installer.jar
  curl -fSL https://github.com/ncsa/oa4mp/releases/download/v${OA4MP_VER}/qdl-installer.jar -o ${QDL_INSTALLER}
  java -jar ${QDL_INSTALLER} install -dir ${QDL_HOME} -qdl

  # Make QDL's executables executable by everyone, not only 'root'.
  chmod a+rX ${QDL_HOME}/bin/*

  #---------------------------------------------------------------
  # Set up Pelican's OAuth2 client templates.

  mkdir -p ${ST_HOME}/var/qdl/scitokens
  mkdir -p ${ST_HOME}/etc/templates
  cp /context/oa4mp-config/client-template.xml ${ST_HOME}/etc/templates
  mkdir -p ${QDL_HOME}/var/scripts
  cp /context/qdl-scripts/boot.qdl ${QDL_HOME}/var/scripts

  # Let Tomcat create the socket file it listens on.
  chmod ug=rwX,o= ${ST_HOME}/var
  chgrp ${TOMCAT_USERNAME} ${ST_HOME}/var
ENDRUN

#################################################################
# Pelican Director and Registry (a.k.a. the Central Services)
#################################################################
FROM pelican-software-base AS central-services-base
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/pelican-server_${TARGETOS}_${TARGETARCH}/pelican-server /usr/local/sbin/pelican-server
COPY images/entrypoint.sh /entrypoint.sh

FROM central-services-base AS director
RUN python3 -m pip install --no-cache-dir geoip2
COPY scripts/geoquery.py /usr/local/sbin/geoquery
ENTRYPOINT ["/entrypoint.sh", "pelican-server", "director"]
CMD ["serve"]

FROM director AS osdf-director
RUN ln -s pelican-server /usr/local/sbin/osdf-server
ENTRYPOINT ["/entrypoint.sh", "osdf-server", "director"]
CMD ["serve"]

FROM central-services-base AS registry
ENTRYPOINT ["/entrypoint.sh", "pelican-server", "registry"]
CMD ["serve"]

FROM registry AS osdf-registry
RUN ln -s pelican-server /usr/local/sbin/osdf-server
ENTRYPOINT ["/entrypoint.sh", "osdf-server", "registry"]
CMD ["serve"]

#################################################################
# Pelican Origin
#################################################################
FROM origin-software-base AS origin
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/pelican-server_${TARGETOS}_${TARGETARCH}/pelican-server /usr/local/sbin/pelican-server
COPY images/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh", "pelican-server", "origin"]
CMD ["serve"]

FROM origin AS osdf-origin
ARG TARGETPLATFORM
RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  set -o pipefail

  ln -s pelican-server /usr/local/sbin/osdf-server

  # Some XRootD multi-user setups require sssd-client.
  # The IDs here are chosen to match OSG's sssd sidecar containers.

  groupadd -r -g 990 sssd
  useradd -r -u 990 -g 990 -d / -s /sbin/nologin -c "System user for sssd" sssd
  dnf install -y sssd-client
ENDRUN
ENTRYPOINT ["/entrypoint.sh", "osdf-server", "origin"]
CMD ["serve"]

#################################################################
# Pelican Cache
#################################################################
FROM xrootd-software-base AS cache
ARG TARGETOS TARGETARCH
COPY --from=pelican-build /pelican-build/dist/pelican-server_${TARGETOS}_${TARGETARCH}/pelican-server /usr/local/sbin/pelican-server
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
# This container is for use in GitHub Actions workflows and should
# contain all of Pelican's runtime dependencies. It also contains
# additional packages that are needed for various test cases and that
# can reasonably be baked into the container.
#################################################################
FROM origin-software-base AS pelican-test
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked <<ENDRUN
  set -eux
  set -o pipefail

  # Install packages for building Pelican.
  dnf install -y git make

  # Install HTCondor for integration tests, but forcibly remove the
  # Pelican packages that it pulls in so that there is zero chance tests
  # are run using the wrong binary.
  dnf install -y condor
  rpm -e --nodeps pelican pelican-osdf-compat

  # Install the MinIO server and client for S3 tests.
  if [ "$TARGETARCH" = "amd64" ]; then
      PKG_ARCH=x86_64
  elif [ "$TARGETARCH" = "arm64" ]; then
      PKG_ARCH=aarch64
  fi
  dnf install -y https://dl.min.io/server/minio/release/${TARGETOS}-${TARGETARCH}/archive/minio-20231214185157.0.0-1.${PKG_ARCH}.rpm

  # Add some normal user accounts for testing.
  # The inspiration for their names: https://en.wikipedia.org/wiki/Alice_and_Bob#Cast_of_characters.
  for name in alice bob carol dave; do
    useradd -m -s /bin/bash -c "Someone who would like to test Pelican" ${name}
  done
ENDRUN

#################################################################
# Development Environment
#
# This container should contain all of Pelican's dependencies,
# both run-time and development-time. Because it is intended for
# development, it does not need Pelican itself.
#################################################################
FROM pelican-test AS pelican-dev
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=bind,source=go.mod,target=/context/go.mod \
    --mount=type=bind,source=web_ui/frontend/package.json,target=/context/package.json \
    --mount=type=cache,id=dnf-${TARGETPLATFORM},target=/var/cache/dnf,sharing=locked \
    <<ENDRUN

  set -eux
  set -o pipefail

  # Install GoReleaser and other tools.

  cat >/etc/yum.repos.d/goreleaser.repo <<-EOF
		[goreleaser]
		name=GoReleaser
		baseurl=https://repo.goreleaser.com/yum/
		enabled=1
		gpgcheck=0
		exclude=goreleaser-pro
	EOF
  dnf install -y goreleaser jq make

  # Install Go.
  # Use go.mod and the go.dev API to determine the most recent version.
  # References:
  #   - https://pkg.go.dev/golang.org/x/website/internal/dl
  #   - https://github.com/golang/go/issues/34864

  GO_LANG_VER=$(grep -E '^go[[:space:]]*[0-9]+\.[0-9]+' /context/go.mod | grep -oE '[0-9]+\.[0-9]+')
  GO_TOOLCHAIN_VER=$(curl https://go.dev/dl/?mode=json | jq -r ".[].version | select(startswith(\"go${GO_LANG_VER}\"))" | sort -rV | head -n 1)
  rm -rf /usr/local/go
  curl -fSL https://dl.google.com/go/${GO_TOOLCHAIN_VER}.${TARGETOS}-${TARGETARCH}.tar.gz | tar -xz -f - -C /usr/local

  # Install Node.js.
  #
  # We use npm to bootstrap the installation of the required Node.js version
  # and an updated version of npm itself. The `dnf remove` in the middle is to
  # avoid there being multiple, incompatible versions of npm.

  dnf install -y npm
  npm install -g n
  n $(jq < /context/package.json -r .engines.node)
  dnf remove -y npm
  npm install -g npm@latest
  n prune

  # Install gotestsum for better test output formatting.
  # Make a copy of the binary so that non-root users can use it.

  /usr/local/go/bin/go install gotest.tools/gotestsum@latest
  cp ~/go/bin/gotestsum /usr/local/bin/gotestsum

  # Install a kitchen sink's worth of development tools and libraries.

  dnf install -y --enablerepo=osg-contrib \
        cmake3 \
        delve \
        docker \
        gdb \
        gcc-c++ \
        graphviz \
        nano \
        systemd \
        valgrind \
        vim \
        \
        curl-devel \
        gtest-devel \
        libcap-devel \
        libuuid-devel \
        openssl-devel \
        python3-devel \
        sqlite-devel \
        tinyxml2-devel \
        zlib-devel \
        \
        json-schema-validator-devel \
        nlohmann-json-devel
ENDRUN

# Make sure that the version of Go we just installed comes first.
ENV PATH="/usr/local/go/bin:${PATH}"

# Suppress Git's "dubious ownership" warning.
ENV GOFLAGS="-buildvcs=false"

RUN python3 -m pip --no-cache-dir install pre-commit
COPY images/dev-config.yaml /etc/pelican/pelican.yaml
WORKDIR /app
COPY ./images/dev-container-entrypoint.sh /dev-container-entrypoint.sh
ENTRYPOINT ["/dev-container-entrypoint.sh"]
