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

# We specify the platform as scitokens-oauth2-server didn't publish arm version and we don't want to
# fail on building this container on arm machine
FROM --platform=linux/amd64 hub.opensciencegrid.org/sciauth/scitokens-oauth2-server:release-20231118-1823 AS scitokens-oauth2-server

FROM almalinux:9

# https://docs.docker.com/engine/reference/builder/#automatic-platform-args-in-the-global-scope
# Note -- will match arm64 or amd64, so adjust accordingly if you're expecting x86_64 or aarch64. Unfortunately,
# it appears that Docker makes it intentionally hard to derive an ENV without being passed an explicit ARG at build
# time, so there's no clean way to use TARGETARCH to populate a second ARCH var with these alternatives
ARG TARGETARCH

ARG BASE_YUM_REPO=release
ARG BASE_OSG_SERIES=23
ARG BASE_OS=el9

# Doing it caused bugs, so we're not doing it; More info here: https://pkg.go.dev/cmd/go
ENV GOFLAGS="-buildvcs=false"

# Create the xrootd user with a fixed GID/UID
RUN groupadd -o -g 10940 xrootd
RUN useradd -o -u 10940 -g 10940 -s /bin/sh xrootd

# Install EPEL and OSG repos -- we want OSG-patched versions of XRootD
RUN yum install -y \
    https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
    https://repo.opensciencegrid.org/osg/23-main/osg-23-main-el9-release-latest.rpm \
    yum-utils && \
    /usr/bin/crb enable && \
    # ^^ crb enables the Code Ready Builder repository (EL9) or PowerTools (EL8), needed for some of our dependencies \
    yum-config-manager --setopt=install_weak_deps=False --save && \
    # ^^ save some space by not installing weak dependencies \
    yum clean all

# Get goreleaser
# This is a bash-ism but on almalinux:9, /bin/sh _is_ bash so we don't need to change SHELL
RUN echo $'[goreleaser] \n\
name=GoReleaser \n\
baseurl=https://repo.goreleaser.com/yum/ \n\
enabled=1 \n\
gpgcheck=0' > /etc/yum.repos.d/goreleaser.repo

# Install goreleaser and various other packages we need
# Pin XRootD installs to RPMs from Koji -- this is intended to be a temporary measure until
# all our patches are ingested upstream in the OSG repos
ARG XROOTD_VERSION="5.7.2"
ARG XROOTD_RELEASE="1.4.purge.osg${BASE_OSG_SERIES}.${BASE_OS}"
ARG KOJIHUB_BASE_URL="https://kojihub2000.chtc.wisc.edu/kojifiles/packages/xrootd/${XROOTD_VERSION}/${XROOTD_RELEASE}"

# Define packages and install them. Note that they have to be installed in the same yum command to avoid
# unresolvable dependencies.
ENV PACKAGES="xrootd xrootd-libs xrootd-devel xrootd-server xrootd-server-devel xrootd-server-libs xrootd-client xrootd-client-libs xrootd-client-devel xrootd-scitokens xrootd-voms xrdcl-http"
RUN <<EOT
set -ex
package_urls=()
if [ "$TARGETARCH" = "amd64" ]; then
    for package in $PACKAGES; do
        package_urls+=(${KOJIHUB_BASE_URL}/x86_64/${package}-${XROOTD_VERSION}-${XROOTD_RELEASE}.x86_64.rpm)
    done
elif [ "$TARGETARCH" = "arm64" ]; then
    for package in $PACKAGES; do
        package_urls+=(${KOJIHUB_BASE_URL}/aarch64/${package}-${XROOTD_VERSION}-${XROOTD_RELEASE}.aarch64.rpm)
    done
fi
package_urls+=(${KOJIHUB_BASE_URL}/noarch/xrootd-selinux-${XROOTD_VERSION}-${XROOTD_RELEASE}.noarch.rpm)
yum install -y "${package_urls[@]}"
EOT

RUN yum install -y --enablerepo=osg-testing xrootd-multiuser goreleaser npm jq procps docker make curl-devel java-17-openjdk-headless \
    git cmake3 gcc-c++ openssl-devel sqlite-devel libcap-devel sssd-client zlib-devel vim valgrind gdb gtest-devel \
    && yum clean all

# The ADD command with an api.github.com URL in the next couple of sections
# are for cache-hashing of the external repository that we rely on to build
# the image
ENV XRDCL_PELICAN_VERSION="v1.0.2" \
    XROOTD_S3_HTTP_VERSION="v0.1.8" \
    JSON_VERSION="v3.11.3" \
    JSON_SCHEMA_VALIDATOR_VERSION="2.3.0" \
    LOTMAN_VERSION="v0.0.4" \
    XROOTD_LOTMAN_VERSION="v0.0.2"

ADD https://api.github.com/repos/PelicanPlatform/xrdcl-pelican/git/refs/tags/${XRDCL_PELICAN_VERSION} /tmp/hash-xrdcl-pelican
ADD https://api.github.com/repos/PelicanPlatform/xrootd-s3-http/git/refs/tags/${XROOTD_S3_HTTP_VERSION} /tmp/hash-xrootd-s3-http
ADD https://api.github.com/repos/nlohmann/json/git/refs/tags/${JSON_VERSION} /tmp/hash-json
ADD https://api.github.com/repos/pboettch/json-schema-validator/git/refs/tags/${JSON_SCHEMA_VALIDATOR_VERSION} /tmp/hash-json
ADD https://api.github.com/repos/PelicanPlatform/lotman/git/refs/tags/${LOTMAN_VERSION} /tmp/hash-json
ADD https://api.github.com/repos/PelicanPlatform/xrootd-lotman/git/refs/tags/${XROOTD_LOTMAN_VERSION} /tmp/hash-json

# Install xrdcl-pelican plugin and replace the xrdcl-http plugin
# Ping the xrdcl-pelican plugin at a specific commit
RUN \
    git clone https://github.com/PelicanPlatform/xrdcl-pelican.git && \
    cd xrdcl-pelican && \
    git checkout ${XRDCL_PELICAN_VERSION} && \
    mkdir build && cd build && \
    cmake -DLIB_INSTALL_DIR=/usr/lib64 -DCMAKE_BUILD_TYPE=RelWithDebInfo .. && \
    make && make install

# Install the S3 and HTTP server plugins for XRootD. For now we do this from source
# until we can sort out the RPMs.
# Ping the http plugin at a specific commit
RUN \
    git clone https://github.com/PelicanPlatform/xrootd-s3-http.git && \
    cd xrootd-s3-http && \
    git checkout ${XROOTD_S3_HTTP_VERSION} && \
    git submodule update --init --recursive && \
    mkdir build && cd build && \
    cmake -DLIB_INSTALL_DIR=/usr/lib64 .. && \
    make install

# LotMan Installation
# First install dependencies
RUN git clone https://github.com/nlohmann/json.git && \
    cd json && \
    git checkout ${JSON_VERSION} && \
    mkdir build && cd build && \
    cmake -DLIB_INSTALL_DIR=/usr/lib64 .. && \
    make -j`nproc` install
RUN git clone https://github.com/pboettch/json-schema-validator.git && \
    cd json-schema-validator && \
    git checkout ${JSON_SCHEMA_VALIDATOR_VERSION} && \
    mkdir build && cd build && \
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j`nproc` install
#Finally LotMan proper. For now we do this from source until we can sort out the RPMs.
#Ping LotMan at a specific commit
RUN \
    git clone https://github.com/PelicanPlatform/lotman.git && \
    cd lotman && \
    git checkout ${LOTMAN_VERSION} && \
    mkdir build && cd build && \
    # LotMan CMakeLists.txt needs to be updated to use -DLIB_INSTALL_DIR. Issue #6
    cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j`nproc` install

# XRootD LotMan purge plugin installation
RUN \
    git clone https://github.com/PelicanPlatform/xrootd-lotman.git && \
    cd xrootd-lotman && \
    git checkout ${XROOTD_LOTMAN_VERSION} && \
    mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j`nproc` install

# Copy xrdcl-pelican plugin config and remove http plugin to use pelican plugin
RUN \
    cp /usr/local/etc/xrootd/client.plugins.d/pelican-plugin.conf /etc/xrootd/client.plugins.d/pelican-plugin.conf && \
    rm -f /etc/xrootd/client.plugins.d/xrdcl-http-plugin.conf

# Install proper version of nodejs so that make web-build works
RUN \
    dnf module reset -y nodejs && \
    dnf module install -y nodejs:20

# Installing the right version of go
RUN curl https://dl.google.com/go/go1.21.6.linux-$TARGETARCH.tar.gz -o go1.21.6.linux-$TARGETARCH.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.6.linux-$TARGETARCH.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Use npm to install node
RUN npm install -g n
ENV PATH="${PATH}:/usr/lib/node_modules/npm/bin"

# Update node lts, upgrade npm, clean up
RUN n lts && \
    npm install -g npm@latest && \
    n prune

##
# Install and configure Tomcat and the scitokens server
##
RUN useradd -r -s /sbin/nologin tomcat ;\
    mkdir -p /opt/tomcat ;\
    curl -s -L https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.83/bin/apache-tomcat-9.0.83.tar.gz | tar -zxf - -C /opt/tomcat --strip-components=1 ;\
    chgrp -R tomcat /opt/tomcat/conf ;\
    chmod g+rwx /opt/tomcat/conf ;\
    chmod g+r /opt/tomcat/conf/* ;\
    chown -R tomcat /opt/tomcat/logs/ /opt/tomcat/temp/ /opt/tomcat/webapps/ /opt/tomcat/work/ ;\
    chgrp -R tomcat /opt/tomcat/bin /opt/tomcat/lib ;\
    chmod g+rwx /opt/tomcat/bin ;\
    chmod g+r /opt/tomcat/bin/* ;\
    ln -s /usr/lib64/libapr-1.so.0 /opt/tomcat/lib/libapr-1.so.0

RUN \
    # Create various empty directories needed by the webapp
    mkdir -p /opt/tomcat/webapps/scitokens-server ;\
    curl -s -L https://github.com/javaee/javamail/releases/download/JAVAMAIL-1_6_2/javax.mail.jar > /opt/tomcat/lib/javax.mail.jar ;\
    # Install support for the QDL CLI
    curl -L -s https://github.com/ncsa/OA4MP/releases/download/v5.3.1/oa2-qdl-installer.jar >/tmp/oa2-qdl-installer.jar ;\
    java -jar /tmp/oa2-qdl-installer.jar -dir /opt/qdl ;\
    rm /tmp/oa2-qdl-installer.jar ;\
    mkdir -p /opt/qdl/var/scripts ;\
    # Remove the default manager apps and examples -- we don't use these
    rm -rf /opt/tomcat/webapps/ROOT /opt/tomcat/webapps/docs /opt/tomcat/webapps/examples /opt/tomcat/webapps/host-manager /opt/tomcat/webapps/manager ;\
    true;

# The generate_jwk.sh script is part of the documented bootstrap of the container.
COPY --from=scitokens-oauth2-server /usr/local/bin/generate_jwk.sh /usr/local/bin/generate_jwk.sh

# Add other QDL CLI tools and configs
COPY --from=scitokens-oauth2-server /opt/qdl /opt/qdl

# Add in the tomcat server configuration
COPY --chown=root:tomcat oa4mp/resources/server.xml /opt/tomcat/conf/server.xml

# Copy over the OA4MP webapp.
COPY --from=scitokens-oauth2-server --chown=tomcat:tomcat /opt/tomcat/webapps/scitokens-server/ /opt/tomcat/webapps/scitokens-server/
COPY --from=scitokens-oauth2-server --chown=tomcat:tomcat /opt/scitokens-server/ /opt/scitokens-server/

# The security constraint line forces a redirect to HTTPS (which we aren't using)
RUN sed 's/<security-constraint>/<!--&/; s/\/security-constraint>/&-->/;' /opt/scitokens-server/web.xml > /opt/tomcat/webapps/scitokens-server/WEB-INF/web.xml

#

ENV JAVA_HOME=/usr/lib/jvm/jre \
    CATALINA_PID=/opt/tomcat/temp/tomcat.pid \
    CATALINA_HOME=/opt/tomcat \
    CATALINA_BASE=/opt/tomcat \
    CATALINA_OPTS="-Xms512M -Xmx1024M -server -XX:+UseParallelGC" \
    JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -Djava.library.path=/opt/tomcat/lib" \
    ST_HOME="/opt/scitokens-server" \
    QDL_HOME="/opt/qdl" \
    PATH="${ST_HOME}/bin:${QDL_HOME}/bin:${PATH}"

COPY images/dev-config.yaml /etc/pelican/pelican.yaml

# For S3 tests, we need the minIO server client, so we install based on detected arch
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        curl -o minio.rpm https://dl.min.io/server/minio/release/linux-amd64/archive/minio-20231214185157.0.0-1.x86_64.rpm &&\
        dnf install -y minio.rpm &&\
        rm -f minio.rpm; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        curl -o minio.rpm https://dl.min.io/server/minio/release/linux-arm64/archive/minio-20231214185157.0.0-1.aarch64.rpm &&\
        dnf install -y minio.rpm &&\
        rm -f minio.rpm; \
    fi

# Install pre-commit
RUN python3.9 -m ensurepip &&\
    pip3.9 install pre-commit

COPY ./images/dev-container-entrypoint.sh /usr/local/bin/

WORKDIR /app

ENTRYPOINT ["dev-container-entrypoint.sh"]

# Build with `docker build -t pelican-dev -f images/dev.Dockerfile .`
# Run from repo root with `docker run -it -p 8444:8444 -v $PWD:/app  pelican-dev`
