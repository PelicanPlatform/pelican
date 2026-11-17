# Pelican tracing demo.  Run from this directory; see README.md, section 6.
# Settings live in .env; a variable set in the shell overrides it.

COMPOSE ?= docker compose
PELICAN_IMAGE ?= pelican-otel-demo:dev

.PHONY: help build up down restart ps logs pelican-logs trace-logs exerciser-logs clean clean-go-cache

help:
	@echo "make build           build the Pelican image from this repository"
	@echo "make up              build if needed and start everything"
	@echo "make down            stop and remove the containers (keeps volumes)"
	@echo "make restart s=NAME  rebuild and restart one service, e.g. s=cache"
	@echo "make ps              container status and health"
	@echo "make logs            follow all container output"
	@echo "make pelican-logs    follow the Pelican log files (director, origin, cache, client)"
	@echo "make trace-logs id=TRACE_ID  each service's log lines for one download"
	@echo "make exerciser-logs  follow the exerciser's one-line-per-scenario log"
	@echo "make clean           down, and delete the volumes and the Pelican image"
	@echo "make clean-go-cache  delete BuildKit's Go module and build caches (all projects)"

build:
	$(COMPOSE) build

up:
	$(COMPOSE) up -d --build
	@echo
	@echo "Grafana     http://localhost:$$($(COMPOSE) port grafana 3000 | sed 's/.*://')/"
	@echo "Jaeger      http://localhost:$$($(COMPOSE) port jaeger 16686 | sed 's/.*://')/"
	@echo "Prometheus  http://localhost:$$($(COMPOSE) port prometheus 9090 | sed 's/.*://')/"

down:
	$(COMPOSE) down --remove-orphans

# Only `director` has the build section; the other Pelican services use the
# image it tags.
restart:
	$(COMPOSE) build
	$(COMPOSE) up -d --no-deps $(s)

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f --tail=100

# The Pelican servers log to files on a shared volume (for the collector),
# not to the container's output.
pelican-logs:
	$(COMPOSE) exec exerciser tail -F /var/log/pelican/director.log /var/log/pelican/origin.log /var/log/pelican/cache.log /var/log/pelican/client.log

# Logs are not collected centrally: in a real federation each origin and
# cache keeps its own, at its own site.  So search each service's log on that
# service, as an operator would on their own host.  The origin, cache and
# client tag request lines with trace_id; the director does not (its lines
# carry its own request ID, the pelican.job_id on its director.redirect span).
trace-logs:
	@test -n "$(id)" || { echo "usage: make trace-logs id=<trace id>"; exit 2; }
	@echo "== cache";  $(COMPOSE) exec -T cache grep -F 'trace_id=$(id)' /var/log/pelican/cache.log || true
	@echo "== origin"; $(COMPOSE) exec -T origin grep -F 'trace_id=$(id)' /var/log/pelican/origin.log || true
	@echo "== client"; $(COMPOSE) exec -T exerciser grep -F 'trace_id=$(id)' /var/log/pelican/client.log || true

exerciser-logs:
	$(COMPOSE) logs -f --tail=50 exerciser

clean:
	$(COMPOSE) down --remove-orphans --volumes
	-docker image rm $(PELICAN_IMAGE)

# The Dockerfile's cache mounts (/go/pkg/mod and /root/.cache/go-build) hold
# a few GB.  BuildKit names them by path, so this also removes the same
# caches of any other project built on this machine.
clean-go-cache:
	docker buildx prune --force --filter type=exec.cachemount
