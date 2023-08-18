ARG BASE_YUM_REPO=release
ARG BASE_OSG_SERIES=3.6

FROM opensciencegrid/software-base:$BASE_OSG_SERIES-el8-$BASE_YUM_REPO

# NOTE: This container is set up to be run by
# github actions in this repository. Using it
# without modification outside of that environment
# will result in lots of frustration. To use it 
# locally, copy your pelican binary named "pelican"
# into images. Build with context at the repo root
# level.

###############################################
#  Container setup & Dependency installation  #
###############################################

# Create the xrootd user with a fixed GID/UID
RUN groupadd -o -g 10940 xrootd
RUN useradd -o -u 10940 -g 10940 -s /bin/sh xrootd

# Install dependencies
RUN yum -y update \
    && yum -y install golang xrootd xrootd-client xrootd-server \
    xrootd-devel xrootd-client-devel xrootd-server-devel curl-devel \
    gcc gcc-c++ make cmake-3.20.2-5.el8 \
    && yum clean all \
    && rm -rf /var/cache/yum/

# Build and install origin plugins
# (eventually this should be done via the rpms...)
COPY origin_plugins/http_s3 http_s3
RUN cd http_s3 && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make install

###############################################
# Set up Pelican proper and handle supervisor #
###############################################
WORKDIR /pelican

# Copy over needed files
# The build+push action that builds this dockerfile will copy the
# linux/amd64 pelican artifact into the correct spot whenever the action
# is triggered.
COPY images/pelican /pelican/osdf-client
COPY images/supervisord/supervisord.conf /etc/supervisord.conf

# Eventually add more entrypoint commands and corresponding supervisor
# daemons here
COPY images/supervisord/pelican_director_serve.conf /etc/supervisord.d/pelican_director_serve.conf
COPY images/entrypoint.sh /entrypoint.sh

RUN chmod +x /pelican/osdf-client \
    && chmod +x /entrypoint.sh

# Can now run the container with an argument like
# director_serve or origin_serve, and it will 
# perform those actions.
ENTRYPOINT ["/entrypoint.sh"]

