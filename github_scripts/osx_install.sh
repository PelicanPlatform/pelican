#!/bin/sh -ex
# Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

#
# This script installs all the xrootd-related dependencies into the
# Mac OS X instance in GitHub.
#

scriptdir=$PWD/`dirname $0`

brew install minio ninja coreutils

mkdir dependencies
pushd dependencies

# Install scitokens first, which our xrootd build relies on
git clone --depth=1 https://github.com/scitokens/scitokens-cpp.git
pushd scitokens-cpp
mkdir build
cd build
export SCITOKENS_CPP_DIR=$PWD/release_dir
cmake .. -GNinja -DCMAKE_INSTALL_PREFIX=$PWD/release_dir
ninja install
sudo ln -s $PWD/release_dir/lib/libSciTokens*.dylib /usr/local/lib
popd

# Build XRootD from source
# TODO: Remove this patch and install from brew instead when XRootD releases 5.7.0
git clone --depth=1 https://github.com/xrootd/xrootd.git
pushd xrootd
patch -p1 < $scriptdir/pelican_protocol.patch
patch -p1 < $scriptdir/gstream.patch
patch -p1 < $scriptdir/gstream_clock_fix.patch
patch -p1 < $scriptdir/gstream_enable_throttle_osx.patch
mkdir xrootd_build
cd xrootd_build
cmake .. -GNinja
ninja
ninja install
popd

git clone --depth=1 https://github.com/PelicanPlatform/xrdcl-pelican.git
pushd xrdcl-pelican
mkdir build
cd build
cmake .. -GNinja -DCMAKE_INSTALL_PREFIX=$PWD/release_dir
ninja install
sudo mkdir -p /etc/xrootd/client.plugins.d/
sudo cp release_dir/etc/xrootd/client.plugins.d/pelican-plugin.conf /etc/xrootd/client.plugins.d/
popd

git clone --recurse-submodules --branch v0.1.3 https://github.com/PelicanPlatform/xrootd-s3-http.git
pushd xrootd-s3-http
git checkout v0.1.3
mkdir build
cd build
cmake .. -GNinja -DCMAKE_INSTALL_PREFIX=$PWD/release_dir
ninja install
xrootd_libdir=$(grealpath $(dirname $(grealpath `which xrootd`))/../lib/)
echo "Will install into: $xrootd_libdir"
sudo mkdir -p $xrootd_libdir
sudo ln -s $PWD/release_dir/lib/libXrdHTTPServer-5.so $xrootd_libdir
sudo ln -s $PWD/release_dir/lib/libXrdS3-5.so $xrootd_libdir
popd

popd

#
# WORKAROUND: force reverse DNS for IPv4 and IPv6
# Due to https://github.com/xrootd/xrootd/issues/2159, xrootd won't startup
# without reverse DNS entries.  If there's no corresponding entry, the
# reverse DNS lookup will take ~10 seconds to timeout.  This is sadly close
# to the time allocated to the various unit tests, meaning there is often
# few to no log messages.
#
# If only an IPv4 entry is present, then XRootD will still trigger a lookup
# on IPv6 which takes many seconds to timeout
ipv6_local=$(ifconfig en0 inet6 | grep inet6 | tail -n 1 | tr '%' ' ' | cut -w -f 3)
ipv4_local=$(ifconfig en0 inet  | grep inet | tail -n 1 | tr '%' ' ' | cut -w -f 3)

cat > /tmp/hosts_append << EOF
$ipv4_local $HOSTNAME
$ipv6_local $HOSTNAME
EOF
sudo /bin/sh -c "cat /tmp/hosts_append >> /etc/hosts"
cat /etc/hosts

# Do a quick test of xrootd startup
mkdir -p /tmp/xrootd

# Generated host cert and CA for test.example.com.  Useless
# except for getting rid of test failures.
cat > /tmp/xrootd/certs.pem << EOF
-----BEGIN CERTIFICATE-----
MIIB2DCCAX6gAwIBAgIQOlqxi40B7A9AM9kqOrq4NDAKBggqhkjOPQQDAjAwMRMw
EQYDVQQKEwpQZWxpY2FuIENBMRkwFwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMB4X
DTI0MDEwMTE0MDEwNFoXDTI0MTIzMTE0MDEwNFowLTEQMA4GA1UEChMHUGVsaWNh
bjEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABNbj9g9EVTKDsvgs/qoVxJ6beSnq/FLJA7lu56XdcevN2CPnRf48jHIc
VadComl88NnSmH4LKWWQx2CLZxAW0DOjfTB7MA4GA1UdDwEB/wQEAwIHgDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSME
GDAWgBSiCQ8T/sWWELavXSKuwGoGumFWNTAbBgNVHREEFDASghB0ZXN0LmV4YW1w
bGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIF/x2d8Dt9mYjLvD7+pxJlbGQ3oHmsFH
CzW/jqZZcmZBAiEAy8k1VcQ01ir6KW0Sna8CBoK7Rdfe7wCKp5+/zY7oSQY=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgz0a/I/I7IRmZlFgP
/Hngi/gC8kDpAyc9gjpEQDhfUGehRANCAATW4/YPRFUyg7L4LP6qFcSem3kp6vxS
yQO5buel3XHrzdgj50X+PIxyHFWnQqJpfPDZ0ph+CyllkMdgi2cQFtAz
-----END PRIVATE KEY-----
EOF
chmod 0400 /tmp/xrootd/certs.pem

cat > /tmp/xrootd/ca-bundle.pem << EOF
-----BEGIN CERTIFICATE-----
MIIBvzCCAWSgAwIBAgIRAOLJb0myOC4dRnv/7ZiqiGgwCgYIKoZIzj0EAwIwMDET
MBEGA1UEChMKUGVsaWNhbiBDQTEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTAe
Fw0yNDAxMDExNDAxMDRaFw0zNDAxMDExNDAxMDRaMDAxEzARBgNVBAoTClBlbGlj
YW4gQ0ExGTAXBgNVBAMTEHRlc3QuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATcOtoEPPDnaAZt+bpfgxilZpay+3Ti/Pnfh4GcLguBhBnuloax
CBaoX+C3Tj/fs+xnvPNJf67f+VM6RbYafmjNo18wXTAOBgNVHQ8BAf8EBAMCAoQw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUogkPE/7FlhC2r10irsBqBrphVjUw
GwYDVR0RBBQwEoIQdGVzdC5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNJADBGAiEA
9G2gM3d48qjQkqt7WsOky/1Vds7ekL9Qjcwy/y3UHPACIQC+A+4nO8Nrz2l8EolM
3OotNbcykY7qePWgk5In2raHMg==
-----END CERTIFICATE-----
EOF

touch /tmp/xrootd/authfile
cat > /tmp/xrootd/scitokens.cfg << EOF
[Global]
audience = https://localhost:8443

[Issuer DEMO]

issuer = https://demo.scitokens.org
base_path = /demo
default_user = test1234
EOF

cat > test.cfg << EOF
all.role server
if exec xrootd
  xrd.port 8443
  xrd.protocol http:8443 libXrdHttp.so
fi

# For now, disable these
xrd.tls /tmp/xrootd/certs.pem
xrd.tlsca certfile /tmp/xrootd/ca-bundle.pem

http.listingdeny true
http.header2cgi Authorization authz

all.sitename test_host

xrootd.monitor all auth flush 30s window 5s fstat 60 lfn ops xfr 5  dest redir fstat info files user pfc tcpmon ccm 127.0.0.1:9931
all.adminpath /tmp/xrootd
all.pidpath /tmp/xrootd
ofs.osslib libXrdS3.so

# The S3 plugin doesn't currently support async mode
xrootd.async off

s3.region test-region
s3.service_name test-name
s3.service_url http://localhost:9000
s3.url_style path
xrootd.seclib libXrdSec.so
sec.protocol ztn
ofs.authorize 1
acc.audit deny grant
acc.authdb /tmp/xrootd/authfile
ofs.authlib ++ libXrdAccSciTokens.so config=/tmp/xrootd/scitokens.cfg
all.export /test-name/test-region/test-bucket
xrootd.chksum max 2 md5 adler32 crc32
xrootd.trace emsg login stall redirect
scitokens.trace all
EOF

set +ex
ifconfig
hostname
xrootd -c test.cfg &
oldproc=$!

(sleep 2; kill $oldproc) &
wait $oldproc
if [ $? -eq 143 ]; then # Indicates the xrootd process lived until it was killed.
  exit 0
else
  echo "Launched xrootd process failed."
  exit 1
fi
