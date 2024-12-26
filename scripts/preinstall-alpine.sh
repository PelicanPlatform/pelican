#!/bin/sh

getent group pelican >/dev/null || addgroup -S pelican
getent passwd pelican >/dev/null || \
    adduser -S -G pelican -g "Pelican service user" \
        -s /sbin/nologin -D -H -h /var/lib/pelican pelican
