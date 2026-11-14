#
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

USE_DOCKER=0

CONTAINER_TOOL=docker

# When USE_DOCKER=1, Go's module and build caches are bind-mounted from the host
# so they persist between runs and don't live on the (small) Docker VM disk. A
# full goreleaser snapshot build compiles ~17 targets and needs well over 10GB of
# cache, which is enough to exhaust a default Docker Desktop VM disk.
DOCKER_CACHE_DIR ?= $(HOME)/.cache/pelican-docker
DOCKER_GO_CACHE_MOUNTS = -v $(DOCKER_CACHE_DIR)/go-mod:/go/pkg/mod -v $(DOCKER_CACHE_DIR)/go-build:/root/.cache/go-build

ifeq ($(OS),Windows_NT)
	goos := windows
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		goarch := arm64
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			goarch := arm64
		endif
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		goos := linux
	endif
	ifeq ($(UNAME_S),Darwin)
		goos := darwin
	endif
	UNAME_P := $(shell uname -p)
	UNAME_M := $(shell uname -m)
	ifneq ($(filter arm64%,$(UNAME_M)),)
		goarch := arm64
	endif
endif

WEBSITE_SRC_PATH := web_ui/frontend
WEBSITE_OUT_PATH := web_ui/frontend/out
WEBSITE_CACHE_PATH := web_ui/frontend/.next

WEBSITE_SRC_FILES := $(shell find $(WEBSITE_SRC_PATH) -type f -not -path "*.next*" -not -path "*/out/*" -not -path "*node_modules*" -not -path "*.pnpm-store*" -not -path "*pelican-swagger.yaml")
WEBSITE_CLEAN_LIST := $(WEBSITE_OUT_PATH) \
						$(WEBSITE_CACHE_PATH)

ifneq ($(wildcard $(WEBSITE_OUT_PATH)/index.html),)
$(info These files have changed causing the website to have to rebuild: [$(shell find $(WEBSITE_SRC_PATH) -type f -not -path "*.next*" -not -path "*/out/*" -not -path "*node_modules*" -not -path "*.pnpm-store*" -not -path "*pelican-swagger.yaml" -newer $(WEBSITE_OUT_PATH)/index.html)])
else
$(info Skipping website change check: $(WEBSITE_OUT_PATH)/index.html does not exist yet)
endif

.PHONY: all
all: pelican-build

.PHONY: web-clean
web-clean:
	@echo CLEAN $(WEBSITE_CLEAN_LIST)
	@rm -rf $(WEBSITE_CLEAN_LIST)

web_ui/frontend/public/data/parameters.json:
	@echo Creating web_ui/frontend/public/data/parameters.json...
	@mkdir -p web_ui/frontend/public/data && touch web_ui/frontend/public/data/parameters.json

docs/parameters.json:
	@echo Creating docs/parameters.json...
	@touch docs/parameters.json

.PHONY: generate
generate: docs/parameters.json web_ui/frontend/public/data/parameters.json swagger/pelican-swagger.yaml
ifeq ($(USE_DOCKER),0)
	@go generate ./...
else
	@mkdir -p $(DOCKER_CACHE_DIR)/go-mod $(DOCKER_CACHE_DIR)/go-build
	@$(CONTAINER_TOOL) run --rm $(DOCKER_GO_CACHE_MOUNTS) -v $(PWD):/code -w /code golang:1.26 go generate ./...
endif

.PHONY: web-build

ifeq ($(goos),windows)
web-build:
	@echo Skipping web build on Windows
	@mkdir -p web_ui/frontend/out
	@touch web_ui/frontend/out/index.html
else
web-build: generate web_ui/frontend/out/index.html
endif

# CI=true lets pnpm purge and recreate a node_modules that was populated by a
# different Node/pnpm on the host; without a TTY it would otherwise abort.
web_ui/frontend/out/index.html : $(WEBSITE_SRC_FILES) swagger/pelican-swagger.yaml
ifeq ($(USE_DOCKER),0)
	@cd $(WEBSITE_SRC_PATH) && pnpm install --frozen-lockfile && pnpm run build
else
	@cd $(WEBSITE_SRC_PATH) && $(CONTAINER_TOOL) build -t origin-ui . && $(CONTAINER_TOOL) run --rm -e CI=true -v `pwd`:/webapp origin-ui sh -c 'pnpm install --frozen-lockfile --prefer-offline && pnpm run build'
endif

.PHONY: web-serve
web-serve:
ifeq ($(USE_DOCKER),0)
	@cd $(WEBSITE_SRC_PATH) && pnpm install && pnpm run dev
else
	@cd $(WEBSITE_SRC_PATH) && $(CONTAINER_TOOL) build -t origin-ui . && $(CONTAINER_TOOL) run --rm -e CI=true -v `pwd`:/webapp -p 3000:3000 origin-ui sh -c 'pnpm install --frozen-lockfile --prefer-offline && pnpm run dev'
endif


PELICAN_DIST_PATH := dist

.PHONY: pelican-clean
pelican-clean:
	@echo CLEAN $(PELICAN_DIST_PATH)
	@rm -rf $(PELICAN_DIST_PATH)

.PHONY: goreleaser-config
goreleaser-config:
	@echo GENERATE GORELEASER FILE
	./scripts/generate_goreleaser.sh .goreleaser.in.yml .goreleaser.generated.yml

.PHONY: pelican-build
# web-build is listed here as well as in the goreleaser `before` hooks. When
# USE_DOCKER=1, goreleaser runs inside the goreleaser/goreleaser image, which
# has neither pnpm nor a Docker daemon, so the hook's `make web-build` can only
# succeed if web_ui/frontend/out is already up to date. Building the website
# here first (in its own node/pnpm container) guarantees the hook is a no-op.
pelican-build: goreleaser-config web-build
	@echo PELICAN BUILD
ifeq ($(USE_DOCKER),0)
	@goreleaser --clean --snapshot --config .goreleaser.generated.yml
else
	@mkdir -p $(DOCKER_CACHE_DIR)/go-mod $(DOCKER_CACHE_DIR)/go-build
	@$(CONTAINER_TOOL) run --rm $(DOCKER_GO_CACHE_MOUNTS) -w /app -v $(PWD):/app goreleaser/goreleaser --clean --snapshot --config .goreleaser.generated.yml
endif

.PHONY: pelican-dev-build
pelican-dev-build: web-build
	@echo PELICAN DEV BUILD
ifeq ($(USE_DOCKER),0)
	@goreleaser --clean --snapshot --config .goreleaser.dev.yml
else
	@mkdir -p $(DOCKER_CACHE_DIR)/go-mod $(DOCKER_CACHE_DIR)/go-build
	@$(CONTAINER_TOOL) run --rm $(DOCKER_GO_CACHE_MOUNTS) -w /app -v $(PWD):/app goreleaser/goreleaser --clean --snapshot --config .goreleaser.dev.yml
endif

.PHONY: pelican-serve-test-origin
pelican-serve-test-origin: pelican-build
	@echo SERVE TEST ORIGIN
	@cd $(PELICAN_DIST_PATH)/pelican_$(goos)_$(goarch) && cp pelican osdf && ./osdf origin serve  -f https://osg-htc.org -v /tmp/stash/:/test

.PHONY: pelican-build-server-image
pelican-build-server-image:
	@echo BUILD SERVER IMAGE
	@$(CONTAINER_TOOL) build -t pelican-server -f images/Dockerfile .

# libLotMan is the only artifact that needs CGO. The pelican / pelican-server
# binaries stay CGO-free (see the lotman/core embedded engine); this target
# builds the standalone C-ABI shared library that external C consumers — notably
# the XRootD pfc purge plugin — link against, from the same Go core.
LOTMAN_SHARED_EXT := so
ifeq ($(goos),darwin)
	LOTMAN_SHARED_EXT := dylib
endif
LOTMAN_SHARED_DIR := $(PELICAN_DIST_PATH)/lotman

# The XRootD pfc purge plugin (libXrdPurgeLotMan) links libLotMan at a specific C
# ABI. lotman v0.1.0 added query_time / include_reclaimed / hierarchical params to
# the eviction queries and update_lot_usage_by_dir; a plugin built against the
# older v0.0.4 ABI (shipped with xrootd-lotman v0.0.5) passes fewer arguments, so
# a new-ABI libLotMan reads shifted registers and segfaults. Build the matching
# ABI via the lotman_legacy_api build tag.
#
# LOTMAN_ABI picks the variant: auto (default — sniff the installed lotman
# header), new, or legacy. Override e.g. `make lotman-shared LOTMAN_ABI=legacy`.
LOTMAN_ABI ?= auto
ifeq ($(LOTMAN_ABI),auto)
  LOTMAN_HEADER := $(firstword $(wildcard \
    /usr/include/lotman.h /usr/include/lotman/lotman.h \
    /usr/local/include/lotman.h /usr/local/include/lotman/lotman.h))
  ifeq ($(LOTMAN_HEADER),)
    # No header to sniff (e.g. a cross build); assume the current ABI.
    LOTMAN_ABI_RESOLVED := new
  else ifeq ($(shell awk '/lotman_update_lot_usage_by_dir/{f=1} f{print} f&&/;/{exit}' $(LOTMAN_HEADER) | grep -c int64_t),0)
    # The new ABI added an int64_t query_time arg to update_lot_usage_by_dir.
    LOTMAN_ABI_RESOLVED := legacy
  else
    LOTMAN_ABI_RESOLVED := new
  endif
else
  LOTMAN_ABI_RESOLVED := $(LOTMAN_ABI)
endif
LOTMAN_BUILD_TAGS :=
ifeq ($(LOTMAN_ABI_RESOLVED),legacy)
  LOTMAN_BUILD_TAGS := -tags lotman_legacy_api
endif

# Go's c-shared link never passes -soname, so the library would carry no
# DT_SONAME; the C++ libLotMan it replaces has one (CMake's default). Match it,
# on ELF targets only -- it is a GNU ld option with no Mach-O spelling.
LOTMAN_LDFLAGS :=
ifneq ($(goos),darwin)
  LOTMAN_LDFLAGS := -ldflags "-extldflags '-Wl,-soname,libLotMan.so'"
endif

.PHONY: lotman-shared
lotman-shared:
	@echo "BUILD libLotMan C-ABI shared library (lotman ABI: $(LOTMAN_ABI_RESOLVED))"
	@mkdir -p $(LOTMAN_SHARED_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared $(LOTMAN_BUILD_TAGS) $(LOTMAN_LDFLAGS) -o $(LOTMAN_SHARED_DIR)/libLotMan.$(LOTMAN_SHARED_EXT) ./lotman/cshared
	@# cgo writes a libLotMan.h next to the library, but that file does not
	@# compile in C++ (it emits `_Bool`, drops every `const`, and has no
	@# `extern "C"` block) and every consumer of this library is C++. Ship the
	@# hand-maintained header instead -- the same one the RPM installs.
	@mkdir -p $(LOTMAN_SHARED_DIR)/include/lotman
	@cp lotman/cshared/include/lotman/lotman.h $(LOTMAN_SHARED_DIR)/include/lotman/lotman.h
	@echo "Wrote $(LOTMAN_SHARED_DIR)/libLotMan.$(LOTMAN_SHARED_EXT) and include/lotman/lotman.h"

# Produce the libLotMan RPM. This one is built with rpmbuild rather than
# GoReleaser/nfpm, because it has to *replace* an already-published package:
# nfpm cannot express Obsoletes and cannot produce a source RPM, and this
# package needs both. See rpm/pelican-lotman.spec.
#
# -buildmode=c-shared needs CGO and a per-target toolchain, so unlike the
# CGO-free pelican packages this is built natively per architecture rather than
# cross-compiled. images/Dockerfile's `lotman-build` stage runs the same
# rpmbuild command on the target platform.
LOTMAN_RPM_TOPDIR := $(abspath $(PELICAN_DIST_PATH)/rpmbuild)
# The Pelican source release the package is built from. It only names the
# tarball in the spec's Source0; the package's own version is the C ABI.
LOTMAN_PELICAN_VERSION ?= $(patsubst v%,%,$(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0))

.PHONY: lotman-package
lotman-package:
	@echo PACKAGE libLotMan
	@mkdir -p $(LOTMAN_RPM_TOPDIR)
	rpmbuild -bb --nodeps --build-in-place --define "_topdir $(LOTMAN_RPM_TOPDIR)" rpm/pelican-lotman.spec
	@find $(LOTMAN_RPM_TOPDIR)/RPMS -name '*.rpm'

# The source RPM, for distribution through OSG/Koji. Unlike the binary target
# this builds from a tarball, so the spec needs the Pelican version that names
# it.
.PHONY: lotman-srpm
lotman-srpm:
	@echo SRPM libLotMan \(pelican $(LOTMAN_PELICAN_VERSION)\)
	@mkdir -p $(LOTMAN_RPM_TOPDIR)/SOURCES
	git archive --format=tar.gz --prefix=pelican-$(LOTMAN_PELICAN_VERSION)/ \
		-o $(LOTMAN_RPM_TOPDIR)/SOURCES/pelican-$(LOTMAN_PELICAN_VERSION).tar.gz HEAD
	rpmbuild -bs --define "_topdir $(LOTMAN_RPM_TOPDIR)" \
		--define "pelican_version $(LOTMAN_PELICAN_VERSION)" rpm/pelican-lotman.spec
	@find $(LOTMAN_RPM_TOPDIR)/SRPMS -name '*.rpm'
