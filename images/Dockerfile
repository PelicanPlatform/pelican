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

ARG BASE_YUM_REPO=release
ARG BASE_OSG_SERIES=23
ARG BASE_OS=el9

FROM goreleaser/goreleaser:v1.21.0 AS pelican-build
ARG IS_NONRELEASE_BUILD="true"

RUN apk add --update nodejs-current npm

WORKDIR /pelican

COPY . .

ENV GOOS="linux"
ENV GOARCH="amd64"

RUN\
    if $IS_NONRELEASE_BUILD;\
        then goreleaser build --clean --snapshot --single-target;\
    else goreleaser build --clean --single-target;\
    fi

FROM --platform=linux/amd64 hub.opensciencegrid.org/sciauth/scitokens-oauth2-server:release-20231118-1823 AS scitokens-oauth2-server

FROM --platform=linux/amd64 opensciencegrid/software-base:$BASE_OSG_SERIES-$BASE_OS-$BASE_YUM_REPO AS dependency-build

# Create the xrootd user with a fixed GID/UID
RUN groupadd -o -g 10940 xrootd
RUN useradd -o -u 10940 -g 10940 -s /bin/sh xrootd

# Install dependencies
# FIXME: We install xrootd from the osg-test repo to incorporate patch for the throttle plugin
# We should come back and remove it once xrootd 5.7.0 is released
RUN yum -y update \
    && yum -y --allowerasing --enablerepo osg-testing install tini xrootd xrootd-client xrdcl-http xrootd-server xrootd-scitokens xrootd-voms xrootd-multiuser curl java-17-openjdk-headless \
    && yum clean all \
    && rm -rf /var/cache/yum/

####
# Start building xrootd plugins (xrdcl-pelican and s3)
####
FROM dependency-build AS xrootd-plugin-builder
# Install necessary build dependencies
RUN  yum install -y --enablerepo=osg-testing xrootd-devel xrootd-server-devel xrootd-client-devel curl-devel openssl-devel git cmake3 gcc-c++ sqlite-devel

# The ADD command with a api.github.com URL in the next couple of sections
# are for cache-hashing of the external repository that we rely on to build
# the image
ADD https://api.github.com/repos/PelicanPlatform/xrdcl-pelican/git/refs/heads/main /tmp/hash-xrdcl-pelican

# Install xrdcl-pelican plugin and replace the xrdcl-http plugin
# Ping the xrdcl-pelican plugin at a specific commit
RUN \
    git clone https://github.com/PelicanPlatform/xrdcl-pelican.git && \
    cd xrdcl-pelican && \
    git reset 9562795 --hard && \
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
    cd build && cmake .. && \
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

FROM dependency-build AS final-stage

WORKDIR /pelican

####
# Now, start installing the SciTokens OA4MP server from
# - https://github.com/scitokens/scitokens-oauth2-server/blob/master/Dockerfile
####

# Download and install tomcat
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

ENV JAVA_HOME=/usr/lib/jvm/jre \
    CATALINA_PID=/opt/tomcat/temp/tomcat.pid \
    CATALINA_HOME=/opt/tomcat \
    CATALINA_BASE=/opt/tomcat \
    CATALINA_OPTS="-Xms512M -Xmx1024M -server -XX:+UseParallelGC" \
    JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom -Djava.library.path=/opt/tomcat/lib" \
    ST_HOME="/opt/scitokens-server" \
    QDL_HOME="/opt/qdl" \
    PATH="${ST_HOME}/bin:${QDL_HOME}/bin:${PATH}"

# Copy xrdcl-pelican plugin config
COPY --from=xrootd-plugin-builder /usr/local/etc/xrootd/client.plugins.d/pelican-plugin.conf /etc/xrootd/client.plugins.d/pelican-plugin.conf
# Remove http plugin to use pelican plugin
RUN rm -f /etc/xrootd/client.plugins.d/xrdcl-http-plugin.conf

# Copy built s3 plugin library and xrdcl-pelican plugin library from build
COPY --from=xrootd-plugin-builder /usr/lib64/libXrdS3-5.so /usr/lib64/libXrdHTTPServer-5.so /usr/lib64/libXrdClPelican-5.so \
    /usr/lib64/libLotMan.so /usr/lib64/

# Copy the nlohmann json headers
COPY --from=xrootd-plugin-builder /usr/include/nlohmann /usr/include/nlohmann
# Copy the JSON schema validator library
COPY --from=xrootd-plugin-builder /usr/lib64/libnlohmann_json_schema_validator.a /usr/lib64/

COPY images/entrypoint.sh /entrypoint.sh

# Copy here to reduce dependency on the pelican-build stage in the final-stage and x-base stage
COPY --from=pelican-build /pelican/dist/pelican_linux_amd64_v1/pelican /pelican/pelican
COPY --from=pelican-build /pelican/dist/pelican_linux_amd64_v1/pelican /pelican/osdf
RUN chmod +x /pelican/pelican \
    && chmod +x /pelican/osdf \
    && chmod +x /entrypoint.sh

######################
# Pelican base stage #
######################
FROM final-stage AS pelican-base

RUN rm -rf /pelican/osdf

######################
# OSDF base stage #
######################
FROM final-stage AS osdf-base

RUN rm -rf /pelican/pelican

####################
# pelican/cache    #
####################

FROM pelican-base AS cache

ENTRYPOINT [ "/entrypoint.sh", "pelican", "cache"]
CMD [ "serve" ]

####################
# pelican/origin   #
####################

FROM pelican-base AS origin

ENTRYPOINT [ "/entrypoint.sh" ,"pelican", "origin"]
CMD [ "serve" ]

####################
# pelican/director #
####################

FROM pelican-base AS director

ENTRYPOINT [ "/entrypoint.sh" ,"pelican", "director"]
CMD [ "serve" ]

####################
# pelican/registry #
####################

FROM pelican-base AS registry

ENTRYPOINT [ "/entrypoint.sh" ,"pelican", "registry"]
CMD [ "serve" ]

####################################
# OSDF                             #
####################################

####################
# osdf/cache       #
####################

FROM osdf-base AS osdf-cache

ENTRYPOINT [ "/entrypoint.sh" ,"osdf", "cache"]
CMD [ "serve" ]

####################
# osdf/origin      #
####################

FROM osdf-base AS osdf-origin

# Add support for SSSD
# sssd UID must match between the origin and SSSD sidecar containers
RUN groupadd -r -g 990 sssd \
    && useradd -r -g sssd -u 990 -d / -s /usr/sbin/nologin -c "System user for sssd" sssd

ENTRYPOINT [ "/entrypoint.sh" ,"osdf", "origin"]
CMD [ "serve" ]

####################
# osdf/director    #
####################

FROM osdf-base AS osdf-director

ENTRYPOINT [ "/entrypoint.sh" ,"osdf", "director"]
CMD [ "serve" ]


####################
# osdf/registry    #
####################

FROM osdf-base AS osdf-registry

ENTRYPOINT [ "/entrypoint.sh" ,"osdf", "registry"]
CMD [ "serve" ]
