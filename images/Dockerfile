
ARG BASE_YUM_REPO=release
ARG BASE_OSG_SERIES=3.6

FROM node:18 AS website-build

WORKDIR /webapp

COPY origin_ui/src/package.json package.json

RUN npm install
COPY origin_ui/src ./

RUN npm run build

FROM goreleaser/goreleaser:v1.19.2 AS pelican-build

WORKDIR /pelican

COPY . .
COPY --from=website-build /webapp/out ./origin_ui/src/out

RUN goreleaser --clean --snapshot

FROM --platform=linux/amd64 opensciencegrid/software-base:$BASE_OSG_SERIES-el7-$BASE_YUM_REPO

# Create the xrootd user with a fixed GID/UID
RUN groupadd -o -g 10940 xrootd
RUN useradd -o -u 10940 -g 10940 -s /bin/sh xrootd

# Install dependencies
RUN yum -y update \
    && yum -y install golang xrootd xrootd-client xrootd-server \
    && yum clean all \
    && rm -rf /var/cache/yum/

WORKDIR /pelican

# Copy over needed files
COPY --from=pelican-build /pelican/dist/pelican_linux_amd64_v1/pelican /pelican/osdf-client
COPY images/supervisord/supervisord.conf /etc/supervisord.conf

# Eventually add more entrypoint commands and corresponding supervisor
# daemons here
COPY images/supervisord/pelican_director_serve.conf /etc/supervisord.d/pelican_director_serve.conf
COPY images/entrypoint.sh /entrypoint.sh

RUN chmod +x /pelican/osdf-client \
    && chmod +x /entrypoint.sh

USER xrootd

ENTRYPOINT ["/entrypoint.sh"]

