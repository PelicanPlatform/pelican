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
ARG TARGETARCH

# Doing it caused bugs, so we're not doing it; More info here: https://pkg.go.dev/cmd/go
ENV GOFLAGS="-buildvcs=false"

# Create the xrootd user with a fixed GID/UID
RUN groupadd -o -g 10940 xrootd
RUN useradd -o -u 10940 -g 10940 -s /bin/sh xrootd

RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && \
    /usr/bin/crb enable && \
    # ^^ crb enables the Code Ready Builder repository (EL9) or PowerTools (EL8), needed for some of our dependencies \
    yum clean all

# Get goreleaser
# NOTE: If using podman to build, you must pass --format=docker for the SHELL command to work
SHELL ["/bin/bash", "-c"]
RUN echo $'[goreleaser] \n\
name=GoReleaser \n\
baseurl=https://repo.goreleaser.com/yum/ \n\
enabled=1 \n\
gpgcheck=0' > /etc/yum.repos.d/goreleaser.repo

RUN echo '%_topdir /usr/local/src/rpmbuild' > $HOME/.rpmmacros

# Download OSG's XRootD SRPM and rebuild it. Create a yum repository to put the results in.
RUN yum install -y yum-utils createrepo https://repo.opensciencegrid.org/osg/23-main/osg-23-main-el9-release-latest.rpm && \
    yum-config-manager --setopt=install_weak_deps=False --save && \
    # ^^ save some space by not installing weak dependencies \
    yum-config-manager --disable osg --save && \
    # ^^ disable the OSG _binary_ repos, they may not be available for our arch \
    yum install -y rpm-build && \
    mkdir -p /usr/local/src/rpmbuild/SRPMS && \
    cd /usr/local/src/rpmbuild/SRPMS && \
    yumdownloader --source xrootd --disablerepo=\* --enablerepo=osg-development-source && \
    yum-builddep -y xrootd-*.osg*.src.rpm && \
    rpmbuild --define 'osg 1' \
             --define 'dist .osg.el9' \
             --without compat \
             --without doc \
             --nocheck \
             --rebuild \
             -bb xrootd-*.osg*.src.rpm  && \
    createrepo /usr/local/src/rpmbuild/RPMS && \
    yum clean all

RUN echo $'[local] \n\
name=Local \n\
baseurl=file:///usr/local/src/rpmbuild/RPMS/ \n\
enabled=1 \n\
priority=1 \n\
gpgcheck=0' > /etc/yum.repos.d/local.repo

# Install goreleaser and various other packages we need
RUN yum install -y goreleaser npm xrootd-devel xrootd-server-devel xrootd-client-devel nano xrootd-scitokens xrootd-voms \
    xrdcl-http jq procps docker make curl-devel java-17-openjdk-headless git cmake3 gcc-c++ openssl-devel sqlite-devel libcap-devel \
    && yum clean all

# The ADD command with a api.github.com URL in the next couple of sections
# are for cache-hashing of the external repository that we rely on to build
# the image
ADD https://api.github.com/repos/PelicanPlatform/xrdcl-pelican/git/refs/heads/main /tmp/hash-xrdcl-pelican

# Install xrdcl-pelican plugin and replace the xrdcl-http plugin
# Ping the xrdcl-pelican plugin at a specific commit
RUN \
    git clone https://github.com/PelicanPlatform/xrdcl-pelican.git && \
    cd xrdcl-pelican && \
    git reset cbd6850 --hard && \
    mkdir build && cd build && \
    cmake -DLIB_INSTALL_DIR=/usr/lib64 .. && \
    make && make install

# Install xrootd-multiuser from source (otherwise it's only available from osg repos)
ADD https://api.github.com/repos/opensciencegrid/xrootd-multiuser/git/refs/heads/master /tmp/hash-xrootd-multiuser
RUN \
    git clone https://github.com/opensciencegrid/xrootd-multiuser.git && \
    cd xrootd-multiuser && \
    git checkout v2.2.0-1 && \
    mkdir build && cd build && \
    cmake -DLIB_INSTALL_DIR=/usr/lib64 .. && \
    make && make install

ADD https://api.github.com/repos/PelicanPlatform/xrootd-s3-http/git/refs/heads/main /tmp/hash-xrootd-s3-http

# Install the S3 and HTTP server plugins for XRootD. For now we do this from source
# until we can sort out the RPMs.
# Ping the http plugin at a specific commit
RUN \
    git clone --recurse-submodules https://github.com/PelicanPlatform/xrootd-s3-http.git && \
    cd xrootd-s3-http && \
    git checkout v0.1.3 && \
    mkdir build && cd build && \
    cmake -DLIB_INSTALL_DIR=/usr/lib64 .. && \
    make install

ADD https://api.github.com/repos/nlohmann/json/git/refs/heads/master /tmp/hash-json
ADD https://api.github.com/repos/pboettch/json-schema-validator/git/refs/heads/master /tmp/hash-json
ADD https://api.github.com/repos/PelicanPlatform/lotman/git/refs/heads/main /tmp/hash-json

# LotMan Installation
# First install dependencies
RUN git clone https://github.com/nlohmann/json.git && \
    cd json && mkdir build && \
    cd build && cmake -DLIB_INSTALL_DIR=/usr/lib64 .. && \
    make -j`nproc` install
RUN git clone https://github.com/pboettch/json-schema-validator.git && \
    cd json-schema-validator && mkdir build && \
    cd build && cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j`nproc` install
#Finally LotMan proper. For now we do this from source until we can sort out the RPMs.
#Ping LotMan at a specific commit
RUN \
    git clone https://github.com/PelicanPlatform/lotman.git && \
    cd lotman && \
    git reset 2dd3738 --hard && \
    mkdir build && cd build && \
    # LotMan CMakeLists.txt needs to be updated to use -DLIB_INSTALL_DIR. Issue #6
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
SHELL ["/bin/sh", "-c"]
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
