GIT_REV    ?= $(shell git rev-parse --short HEAD)
SOURCE_DATE_EPOCH ?= $(shell date +%s)
DATE       ?= $(shell date -u -d @${SOURCE_DATE_EPOCH} +"%Y-%m-%dT%H:%M:%SZ")
VERSION    ?= 6.2.3
all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-w -s -X main.version=${VERSION} -X main.commit=${GIT_REV} -X main.date=${DATE}" \
    -a -o stashcp-x86
	CGO_ENABLED=0 go build \
    -ldflags "-w -s -X main.version=${VERSION} -X main.commit=${GIT_REV} -X main.date=${DATE}" \
    -a -o stashcp

test:
	go test -v

lint:
	go vet
	golangci-lint run
