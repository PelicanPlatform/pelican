#!/bin/sh

getent group pelican >/dev/null || groupadd -r pelican
getent passwd pelican >/dev/null || \
    useradd -r -g pelican -c "Pelican service user" \
        -s /sbin/nologin -d /var/lib/pelican pelican
