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
    xrootd-voms jq procps docker make
RUN yum clean all

# Installing the right version of go
SHELL ["/bin/sh", "-c"]
RUN curl https://dl.google.com/go/go1.20.8.linux-$TARGETARCH.tar.gz -o go1.20.8.linux-$TARGETARCH.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.8.linux-$TARGETARCH.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Use npm to install node
RUN npm install -g n
ENV PATH="${PATH}:/usr/lib/node_modules/npm/bin"

# Update node lts, upgrade npm, clean up
RUN n lts && \
    npm install -g npm@latest && \
    n prune

COPY images/dev-config.yaml /etc/pelican/pelican.yaml

WORKDIR /app

CMD ["/bin/bash"]

# Build with `docker build -t pelican-dev -f images/dev.Dockerfile .`
# Run from repo root with `docker run -it -p 8444:8444 -v $PWD:/app  pelican-dev`
