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

$(info These files have changed causing the website to have to rebuild: [$(shell find $(WEBSITE_SRC_PATH) -type f -not -path "*.next*" -not -path "*/out/*" -not -path "*node_modules*" -not -path "*.pnpm-store*" -not -path "*pelican-swagger.yaml" -newer web_ui/frontend/out/index.html)])


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
