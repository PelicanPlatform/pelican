# syntax=docker/dockerfile:1
#
# Builds `pelican` and `pelican-server` from the repository source for the
# tracing demo.  The build context is the repository root:
#
#   docker build -f design/opentelemetry/demo/Dockerfile .
#
# The compose file does this for you.  Only the Go-native origin (posixv2) and
# cache (Cache.EnableV2) run in this image, so it has no XRootD and no web UI.

ARG GO_IMAGE=golang:1.26.11-alpine3.24
ARG RUNTIME_IMAGE=alpine:3.24

FROM ${GO_IMAGE} AS build

# Stamped into both binaries; it becomes service.version on every span.
ARG PELICAN_VERSION=dev

WORKDIR /src

COPY . .

# Same tags and flags as the release build (.goreleaser.in.yml):
#   CGO_ENABLED=0 (SQLite is the pure-Go driver), `client` / `server` tags,
#   version metadata in ldflags, stripped symbols.
# The web UI is embedded from web_ui/frontend/out, where only the tracked
# placeholder exists here; the demo runs with Server.EnableUI: false.
# -buildvcs=false because .git is not in the build context.
# The module and build caches are BuildKit cache mounts, so a rebuild after a
# code change recompiles only what changed.  Together they hold about 3.5 GB
# of the Docker VM's disk; `make clean` removes them.  sharing=locked: compose
# builds the image for four services at once, and a shared mount used
# concurrently can end up duplicated.
RUN --mount=type=cache,sharing=locked,target=/go/pkg/mod \
    --mount=type=cache,sharing=locked,target=/root/.cache/go-build \
    set -eux; \
    LDFLAGS="-s -w \
      -X github.com/pelicanplatform/pelican/version.version=${PELICAN_VERSION} \
      -X github.com/pelicanplatform/pelican/version.builtBy=tracing-demo"; \
    CGO_ENABLED=0 go build -buildvcs=false -tags client -ldflags "${LDFLAGS}" -o /out/pelican ./cmd; \
    CGO_ENABLED=0 go build -buildvcs=false -tags server -ldflags "${LDFLAGS}" -o /out/pelican-server ./cmd

FROM ${RUNTIME_IMAGE}

# ca-certificates for TLS, curl for healthchecks, coreutils for the
# exerciser's `timeout`/`date +%s%N`.  The shell is busybox ash.
RUN apk add --no-cache ca-certificates curl coreutils \
 && addgroup -g 10940 xrootd && adduser -D -H -u 10940 -G xrootd xrootd

# Pelican, when run as root, looks up an `xrootd` user (config/privs.go);
# the release images create it with the same IDs as above.

COPY --from=build /out/pelican /usr/local/bin/pelican
COPY --from=build /out/pelican-server /usr/local/sbin/pelican-server

ENTRYPOINT ["/usr/local/sbin/pelican-server"]
