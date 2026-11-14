#############################################
# libLotMan, built from Pelican's Go engine #
#############################################
#
# This builds the C-ABI shared library that external C/C++ consumers link
# against -- in practice the XRootD pfc purge plugin, xrootd-lotman -- from
# Pelican's native Go lot engine (lotman/core, exposed by lotman/cshared).
# It is a drop-in replacement for the C++ `lotman` package from
# https://github.com/PelicanPlatform/lotman: same library name, same header
# path, same exported symbols and signatures.
#
# Pelican's own RPMs are built with GoReleaser/nfpm. This one is not, for two
# reasons. nfpm cannot produce a source RPM, and nfpm cannot express the
# Obsoletes below -- both of which this package needs, because it has to
# *replace* an already-published package rather than sit alongside it.
#
# Two ways to build it:
#
#   # In a Pelican checkout (what images/Dockerfile does):
#   rpmbuild -bb --nodeps --build-in-place --define "_topdir $PWD/dist/rpmbuild" rpm/pelican-lotman.spec
#
#   # The source RPM, and a rebuild of it:
#   make lotman-srpm
#   rpmbuild --rebuild dist/rpmbuild/SRPMS/pelican-lotman-*.src.rpm
#
# KNOWN GAP for distribution through OSG/Koji: %build runs `go build`, which
# resolves modules from the network. An offline builder needs the module cache
# vendored into the source tarball (`go mod vendor`) and `-mod=vendor` added
# below. That is a change to how Pelican's source tarball is produced, not to
# this spec, so it is left for whoever wires this into the release pipeline.

# The version is the C ABI this library implements, not Pelican's version.
# Consumers depend on the ABI -- xrootd-lotman carries
# `Requires: lotman >= 0.1.0` and `lotman < 0.2.0` -- and `Provides: lotman`
# has to satisfy that range, so tying the two together keeps them honest.
# Bump it when the exported ABI changes. Rebuilds of the same ABI against a
# newer Pelican bump the release instead:
#   rpmbuild ... --define "lotman_release 2"
%global lotman_abi 0.1.0
%{!?lotman_release: %global lotman_release 1}


Name:    pelican-lotman
Version: %{lotman_abi}
Release: %{lotman_release}%{?dist}
Summary: LotMan storage-lot management library (C ABI), built from Pelican's Go engine
License: Apache-2.0
URL:     https://github.com/PelicanPlatform/pelican

# A tree of Pelican's source, rooted at pelican-lotman-%%{version}/.
# `make lotman-srpm` produces it with `git archive` and names it from the same
# `lotman_abi` above, so the two cannot drift. It is deliberately named after
# the ABI rather than after the Pelican release it was cut from: everything
# %%prep needs has to be derivable from this spec alone, or the source RPM
# stops rebuilding the moment it leaves the tree that produced it.
Source0: pelican-lotman-%{version}.tar.gz

# These describe what a distribution builder needs. Pelican tracks the current
# Go release, which is newer than the `golang` any EL9 repo carries, so a
# builder that installs the toolchain itself -- images/Dockerfile fetches it
# from go.dev, as the Pelican build stages do -- passes `--nodeps` to rpmbuild
# and satisfies these out of band.
BuildRequires: gcc
# For %%check, which compiles the installed header the way a consumer does.
BuildRequires: gcc-c++
BuildRequires: golang >= 1.26

# This package installs %%{_libdir}/libLotMan.so and
# %%{_includedir}/lotman/lotman.h, both owned by the C++ `lotman` package it
# replaces. Without the Obsoletes, installing it on a host that already has
# xrootd-lotman's dependency fails with a file conflict instead of replacing
# it; with it, dnf swaps the two.
#
# The Provides is versioned at the C ABI level rather than at Pelican's
# version: an unversioned `Provides: lotman` does not satisfy a versioned
# dependency in RPM, so xrootd-lotman's `Requires: lotman >= 0.1.0` would go
# unmet. Obsoletes is matched by package name only, so it does not catch this
# package's own virtual Provides.
Provides:  lotman = %{version}-%{release}
Obsoletes: lotman < 0.2.0

%description
LotMan tracks data usage in dHTC environments through the "lot" object: a
reservation over a set of federation paths, carrying byte and object quotas
and a lifecycle, used to drive cache eviction.

This package provides libLotMan, the C ABI over Pelican's native Go lot
engine, and the lotman/lotman.h header. It is a drop-in replacement for the
C++ implementation: the exported symbols and their signatures are identical,
and Pelican's lotman/cshared/abi_conformance_test.go checks them against the
installed header on every build.

The on-disk SQLite schema is NOT the C++ library's. A cache and a C consumer
must share one lot database, and that database cannot be carried across the
cutover from the C++ library -- lots have to be recreated.

# Go links the debug info into the library and %%build strips it.
%global debug_package %{nil}

%prep
%autosetup -n pelican-lotman-%{version}

%build
export CGO_ENABLED=1
# -buildvcs=false: the build may run from an exported tarball with no .git,
# and stamping VCS metadata into a C library buys nothing anyway.
#
# -soname: Go's c-shared linker invocation passes -shared, -Wl,-z,nodelete and
# -Wl,-Bsymbolic, but never -Wl,-soname, so the library would carry no
# DT_SONAME. The C++ library it replaces has `DT_SONAME: libLotMan.so`
# (CMake's default), and setting it here keeps a consumer that recorded that
# name resolvable by a linker that checks it rather than only the filename.
go build \
    -buildvcs=false \
    -buildmode=c-shared \
    -ldflags "-s -w -extldflags '-Wl,-soname,libLotMan.so'" \
    -o libLotMan.so \
    ./lotman/cshared

%check
# Every consumer of this library is C++ -- xrootd-lotman compiles
# `#include <lotman/lotman.h>` from C++ -- so the header this package installs
# has to be usable from C++. That is not a given: the header cgo generates
# beside the library emits `_Bool`, which is not a C++ type, drops every
# `const`, and writes no `extern "C"` block, so it fails to compile and would
# mangle the symbol names if it did.
#
# Nothing else catches this. Go's tests never compile the header, `go vet` has
# no opinion on it, and the plugin is built from a different repository. So the
# check lives here, where the toolchain is guaranteed to be present, and runs
# on every build of this package -- including images/Dockerfile's.
cat > lotman-abi-check.cc <<'EOF'
#include <lotman/lotman.h>
#include <string>
// The call shapes xrootd-lotman uses (src/XrdPurgeLotMan.cc): a std::string's
// const char * into a parameter the cgo header would have declared char *.
int main() {
	std::string lotHome = "/nonexistent";
	char *err = NULL;
	char **lots = NULL;
	int rc = lotman_set_context_str("lot_home", lotHome.c_str(), &err);
	rc += lotman_get_lots_past_del(0, true, false, &lots, &err);
	lotman_free_string_list(lots);
	return rc;
}
EOF
g++ -std=c++17 -Wall -Werror -I lotman/cshared/include \
    -o lotman-abi-check lotman-abi-check.cc -L. -lLotMan

%install
install -D -p -m 0755 libLotMan.so %{buildroot}%{_libdir}/libLotMan.so
# xrootd-lotman compiles `#include <lotman/lotman.h>` (src/XrdPurgeLotMan.cc),
# so the header has to land in that subdirectory, not at the include root.
# This is the hand-maintained public header, NOT the one cgo generates
# alongside the library: cgo emits `_Bool`, drops every `const`, and writes no
# `extern "C"` block, so its output does not compile in C++ at all.
install -D -p -m 0644 lotman/cshared/include/lotman/lotman.h \
    %{buildroot}%{_includedir}/lotman/lotman.h

%files
%license LICENSE
%{_libdir}/libLotMan.so
%dir %{_includedir}/lotman
%{_includedir}/lotman/lotman.h

%changelog
* Sat Nov 14 2026 Pelican Team <help@pelicanplatform.org> - 0.1.0-1
- Initial release: libLotMan v0.1.0 C ABI over Pelican's native Go lot engine,
  replacing the C++ implementation.
