#
# Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

ARG BASE_YUM_REPO=release
ARG BASE_OSG_SERIES=3.6
ARG IS_PR_BUILD=true

FROM node:20 AS website-build

WORKDIR /webapp

COPY web_ui/frontend/package.json package.json

RUN npm install
COPY web_ui/frontend ./

RUN npm run build

FROM goreleaser/goreleaser:v1.20.0 AS pelican-build

WORKDIR /pelican

COPY . .
COPY --from=website-build /webapp/out ./web_ui/frontend/out

RUN\
    if ["${IS_PR_BUILD}" == "false"];\
        then goreleaser build --clean;\
    else goreleaser build --clean --snapshot;\
    fi

FROM --platform=linux/amd64 hub.opensciencegrid.org/sciauth/scitokens-oauth2-server:release-20231118-1823 AS scitokens-oauth2-server

FROM --platform=linux/amd64 opensciencegrid/software-base:$BASE_OSG_SERIES-el8-$BASE_YUM_REPO AS dependency-build

# Create the xrootd user with a fixed GID/UID
RUN groupadd -o -g 10940 xrootd
RUN useradd -o -u 10940 -g 10940 -s /bin/sh xrootd

# Install dependencies
RUN yum -y update \
    && yum -y install xrootd xrootd-client xrdcl-http xrootd-server xrootd-scitokens xrootd-voms curl java-17-openjdk-headless \
    && yum clean all \
    && rm -rf /var/cache/yum/

####
# Start building xrootd plugins (xrdcl-pelican and s3)
####
FROM dependency-build AS xrootd-plugin-builder
# Install necessary build dependencies
RUN  yum install -y xrootd-devel xrootd-server-devel xrootd-client-devel curl-devel openssl-devel git cmake3 gcc-c++
# Install xrdcl-pelican plugin and replace the xrdcl-http plugin
RUN \
    git clone https://github.com/PelicanPlatform/xrdcl-pelican.git && \
    cd xrdcl-pelican && \
    mkdir build && cd build && \
    cmake -DLIB_INSTALL_DIR=/usr/lib64 .. && \
    make && make install
# Install the S3 and HTTP server plugins for XRootD. For now we do this from source
# until we can sort out the RPMs.
RUN \
    git clone https://github.com/PelicanPlatform/xrootd-s3-http.git && \
    cd xrootd-s3-http && \
    mkdir build && cd build && \
    cmake -DLIB_INSTALL_DIR=/usr/lib64 .. && \
    make install

FROM dependency-build AS final-stage

WORKDIR /pelican

# Copy over needed files
COPY --from=pelican-build /pelican/dist/pelican_linux_amd64_v1/pelican /pelican/osdf-client
COPY images/supervisord/supervisord.conf /etc/supervisord.conf

# Eventually add more entrypoint commands and corresponding supervisor
# daemons here
COPY images/supervisord/* /etc/supervisord.d/
COPY images/entrypoint.sh /entrypoint.sh


####
# Now, start installing the SciTokens OA4MP server from
# - https://github.com/scitokens/scitokens-oauth2-server/blob/master/Dockerfile
####

# Download and install tomcat
RUN useradd -r -s /sbin/nologin tomcat ;\
    mkdir -p /opt/tomcat ;\
    curl -s -L https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.80/bin/apache-tomcat-9.0.80.tar.gz | tar -zxf - -C /opt/tomcat --strip-components=1 ;\
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
COPY --from=xrootd-plugin-builder /usr/lib64/libXrdS3-5.so /usr/lib64/libXrdHTTPServer-5.so /usr/lib64/libXrdClPelican-5.so /usr/lib64

RUN chmod +x /pelican/osdf-client \
    && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
