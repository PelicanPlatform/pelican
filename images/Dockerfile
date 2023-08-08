ARG BASE_YUM_REPO=release
ARG BASE_OSG_SERIES=3.6

FROM opensciencegrid/software-base:$BASE_OSG_SERIES-el7-$BASE_YUM_REPO

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
# The build+push action that builds this dockerfile will copy the
# linux/amd64 pelican artifact into the correct spot whenever the action
# is triggered.
COPY pelican /pelican/osdf-client
COPY supervisord/supervisord.conf /etc/supervisord.conf

# Eventually add more entrypoint commands and corresponding supervisor
# daemons here
COPY supervisord/pelican_director_serve.conf /etc/supervisord.d/pelican_director_serve.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /pelican/osdf-client \
    && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

