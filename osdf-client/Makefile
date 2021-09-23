GIT_REV    ?= $(shell git rev-parse --short HEAD)
SOURCE_DATE_EPOCH ?= $(shell date +%s)
DATE       ?= $(shell date -u -d @${SOURCE_DATE_EPOCH} +"%Y-%m-%dT%H:%M:%SZ")
VERSION    ?= 6.2.0
all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-w -s -X main.VERSION=${VERSION} -X main.commit=${GIT_REV} -X main.builddate=${DATE}" \
    -a -o stashcp-x86
	go build \
    -ldflags "-w -s -X main.version=${VERSION} -X main.commit=${GIT_REV} -X main.builddate=${DATE}" \
    -a -o stashcp

test:
	go test
