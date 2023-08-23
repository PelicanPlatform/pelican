

CONTAINER_TOOL := docker

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

WEBSITE_SRC_PATH := origin_ui/src
WEBSITE_OUT_PATH := origin_ui/src/out
WEBSITE_CACHE_PATH := origin_ui/src/.next

WEBSITE_CLEAN_LIST := $(WEBSITE_OUT_PATH) \
					  $(WEBSITE_CACHE_PATH)

.PHONY: web-clean
web-clean:
	@echo CLEAN $(WEBSITE_CLEAN_LIST)
	@rm -rf $(WEBSITE_CLEAN_LIST)

.PHONY: web-build
web-build:
	@cd $(WEBSITE_SRC_PATH) && npm install && npm run build

.PHONY: web-serve
web-serve:
	@cd $(WEBSITE_SRC_PATH) && npm install && npm run dev

.PHONY: web-docker-build
web-docker-build:
	cd $(WEBSITE_SRC_PATH) && $(CONTAINER_TOOL) build -t origin-ui . && $(CONTAINER_TOOL) run --rm -v `pwd`:/webapp -it origin-ui npm install && npm run build

.PHONE: web-docker-serve
web-docker-serve:
	@cd $(WEBSITE_SRC_PATH) && $(CONTAINER_TOOL) build -t origin-ui . && $(CONTAINER_TOOL) run --rm -v `pwd`:/webapp -p 3000:3000 -it origin-ui npm install && npm run dev


PELICAN_DIST_PATH := dist

.PHONY: pelican-clean
pelican-clean:
	@echo CLEAN $(PELICAN_DIST_PATH)
	@rm -rf $(PELICAN_DIST_PATH)

.PHONY: pelican-build
pelican-build: web-build
	@echo PELICAN BUILD
	@goreleaser --clean --snapshot

# This take awhile to run due to the file mount
.PHONY: pelican-docker-build
pelican-docker-build: web-docker-build
	@echo PELICAN BUILD
	@$(CONTAINER_TOOL) run -w /app -v $(PWD):/app goreleaser/goreleaser --clean --snapshot

.PHONY: pelican-serve-test-origin
pelican-serve-test-origin: pelican-build
	@echo SERVE TEST ORIGIN
	@cd $(PELICAN_DIST_PATH)/pelican_$(goos)_$(goarch) && cp pelican osdf && ./osdf origin serve  -f https://osg-htc.org -v /tmp/stash/:/test

.PHONY: pelican-docker-serve-test-origin
pelican-docker-serve-test-origin:
	@echo SERVE TEST ORIGIN
	@$(CONTAINER_TOOL) run --rm -v `pwd`:/webapp -v /tmp/stash:/test -it pelican-server ./osdf-client origin serve  -f https://osg-htc.org -v /test

.PHONY: pelican-build-server-image
pelican-build-server-image:
	@echo BUILD SERVER IMAGE
	@$(CONTAINER_TOOL) build -t pelican-server -f images/Dockerfile .