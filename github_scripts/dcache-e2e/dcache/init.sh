# shellcheck shell=sh
# Sourced by the image's /run.sh before dCache starts: creates the schema and
# the namespace the test uses.  Each step tolerates having been done already.
export JAVA=/usr/bin/java
/opt/dcache/bin/dcache database update
/opt/dcache/bin/chimera writetag / OSMTemplate "StoreName test" || true
/opt/dcache/bin/chimera writetag / sGroup "default" || true
/opt/dcache/bin/chimera mkdir /data || true
/opt/dcache/bin/chimera chmod 0755 /data || true
/opt/dcache/bin/chimera mkdir /data/pelican || true
/opt/dcache/bin/chimera chown 1000:1000 /data/pelican || true
/opt/dcache/bin/chimera mkdir /data/other || true
/opt/dcache/bin/chimera chown 1000:1000 /data/other || true
/opt/dcache/bin/chimera mkdir /data/chroot || true
/opt/dcache/bin/chimera chown 1001:1001 /data/chroot || true
mkdir -p /pool/data /pool/control
