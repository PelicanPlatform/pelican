
FROM hub.opensciencegrid.org/sciauth/scitokens-oauth2-server:release AS scitokens-oauth2-server

FROM almalinux:8

# https://docs.docker.com/engine/reference/builder/#automatic-platform-args-in-the-global-scope
ARG TARGETARCH

# Doing it caused bugs, so we're not doing it; More info here: https://pkg.go.dev/cmd/go
ENV GOFLAGS="-buildvcs=false"

# Create the xrootd user with a fixed GID/UID
RUN groupadd -o -g 10940 xrootd
RUN useradd -o -u 10940 -g 10940 -s /bin/sh xrootd

RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

# Get goreleaser
SHELL ["/bin/bash", "-c"]
RUN echo $'[goreleaser] \n\
name=GoReleaser \n\
baseurl=https://repo.goreleaser.com/yum/ \n\
enabled=1 \n\
gpgcheck=0' > /etc/yum.repos.d/goreleaser.repo

# Install goreleaser and various other packages we need
RUN yum install -y goreleaser npm xrootd xrootd-server xrootd-client nano xrootd-scitokens \
    xrootd-voms jq procps docker make curl java-17-openjdk-headless \
    && yum clean all

# Installing the right version of go
SHELL ["/bin/sh", "-c"]
RUN curl https://dl.google.com/go/go1.20.8.linux-$TARGETARCH.tar.gz -o go1.20.8.linux-$TARGETARCH.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.8.linux-$TARGETARCH.tar.gz
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

WORKDIR /app

CMD ["/bin/bash"]

# Build with `docker build -t pelican-dev -f images/dev.Dockerfile .`
# Run from repo root with `docker run -it -p 8444:8444 -v $PWD:/app  pelican-dev`
