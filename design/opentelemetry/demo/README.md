# Tracing demo

A docker compose stack that runs a small Pelican federation, exercises it with object downloads, and shows the resulting traces and metrics. It is modelled on the upstream OpenTelemetry demo: every service sends spans to one collector, and Jaeger, Prometheus and Grafana read from it.

Logs are not collected centrally. In a real federation the origins and caches run at other sites, often in other countries, where no central collector can read their log files. So, as there, each service keeps its own log. With tracing on, the origin, the cache and the client add `trace_id` and `span_id` to their request log lines, so a download's lines can be found on each service by its trace ID (section 5, "Logs").

This file is the design. Section 6 is the run book.

## 1. What it shows

- One download as a single trace across the client, director, cache and origin.
- A cache miss next to a cache hit.
- Several clients sharing one origin fetch.
- A failed download, and which hop failed.
- A download that skips the cache.
- The client, cache and origin finding the collector from the director, with no endpoint in their own configuration.
- Request rate, error rate and latency per service and per stage, derived from spans.
- Each service's own log lines for a download, found on that service by the download's trace ID.

## 2. Services

```
                 ┌────────────┐
                 │ exerciser  │  runs `pelican object get` in a loop
                 └─────┬──────┘
          traceparent  │
        ┌──────────────┼───────────────┐
        ▼              ▼               ▼
  ┌──────────┐   ┌──────────┐    ┌──────────┐
  │ director │   │  cache   │───►│  origin  │
  │ registry │   │ (Go)     │    │ (posixv2)│
  └────┬─────┘   └────┬─────┘    └────┬─────┘
       │  OTLP/HTTP   │               │
       └──────────────┴───────┬───────┘      each service keeps its
                              ▼              own log file (not collected)
                     ┌─────────────────┐
                     │ otel-collector  │
                     └───┬─────────┬───┘
              traces     │         │  span metrics
                         ▼         ▼
                  ┌────────┐  ┌────────────┐
                  │ jaeger │  │ prometheus │
                  └───┬────┘  └─────┬──────┘
                      └──────┬──────┘
                             ▼
                        ┌─────────┐
                        │ grafana │
                        └─────────┘
```

| Service          | What runs                                                        | Notes                                                                           |
| ---------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `director`       | `pelican-server serve --module director,registry`                | Sets `Federation.TracingEndpoint`, which it advertises.                         |
| `origin`         | `pelican-server origin serve` with `Origin.StorageType: posixv2` | Go-native, so it is traced. Exports `/demo` with public reads and direct reads. |
| `cache`          | `pelican-server cache serve` with `Cache.EnableV2: true`         | Go-native, so it is traced.                                                     |
| `exerciser`      | A shell loop around `pelican object get`                         | Sets `PELICAN_TRACING_ENABLED=true` and no endpoint.                            |
| `otel-collector` | OpenTelemetry Collector (contrib)                                | Receives OTLP and derives span metrics. It does not collect logs.               |
| `jaeger`         | Jaeger v2 (2.19), in-memory storage                              | Trace search and the trace view.                                                |
| `prometheus`     | Prometheus                                                       | Span metrics from the collector; scrapes each Pelican server's `/metrics`.      |
| `grafana`        | Grafana                                                          | Datasources for Jaeger and Prometheus, and three Pelican dashboards.            |

No XRootD is involved, because the Go-native origin and cache are the ones that can be traced.

All four Pelican services run one image, built from this repository by `Dockerfile` (Alpine, both binaries, no web UI).

## 3. Pelican configuration

Common to the three servers:

- `TLSSkipVerify: true`. Each server generates its own self-signed certificate.
- `Server.EnableUI: false`, so nothing waits for a web login.
- `Monitoring.MetricAuthorization: false`, so Prometheus can scrape `/metrics` without a token.
- `Registry.RequireOriginApproval: false` and `Registry.RequireCacheApproval: false`.
- `Logging.LogLocation` in `/var/log/pelican`. The services share that volume only so that `make pelican-logs` can follow every log at once; nothing collects from it.
- `Tracing.Enabled: true`.
- `Server.Hostname` set to the compose service name and `Server.WebPort: 8444`; the origin and cache find the federation through `Federation.DiscoveryUrl: https://director:8444`.
- `Server.SSRFProtection.SkipDefaultBlocks: true`, because the compose network uses private addresses.
- `Monitoring.EnablePrometheus: false`; `/metrics` is served without the embedded Prometheus.
- `Server.RegistrationCompletionLinkFile: ""`, which turns off the reminder to complete registrations.

Server-specific settings:

- Director: `Director.CacheSortMethod: random`, because there is no GeoIP database for distance sorting, and `Director.FilterCachesInErrorState: false`.
- Origin: export `/demo` from `/data/demo` with `PublicReads`, `Reads`, `DirectReads` and `Listings`; `Origin.DirectorTest: false`, because the director's upload test fails on a `posixv2` origin.
- Cache: `Cache.StorageLocation` on the cache's state volume, `LocalCache.Size: 1GB` so eviction starts long before the Docker disk fills, `Cache.FedTokenLocation` on the same volume, `Cache.DirectorTest: false` because the Go-native cache refuses the test's eviction request, and `Xrootd.Sitename: demo-cache`.

Only the director sets `Federation.TracingEndpoint: http://otel-collector:4318`. The origin, the cache and the exerciser have no endpoint configured and learn it from the director.

The servers keep their configuration directory (`/etc/pelican`) and state (`/var/lib/pelican`) on named volumes, so their keys, registrations and cached objects survive a restart.

## 4. The exerciser

A loop that picks a scenario by weight, runs it, and sleeps for a configurable interval. Each `pelican object get` is its own process and its own trace.

| Scenario  | What it does                                                      | What the trace shows                                                                                          |
| --------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `hit`     | Downloads one of a few fixed objects.                             | Cache hit; no origin span.                                                                                    |
| `miss`    | Writes a new object into the origin's storage, then downloads it. | Cache miss; director lookup by the cache; origin fetch.                                                       |
| `large`   | Downloads a new 100 MB object.                                    | Body time dominates; block fetches.                                                                           |
| `shared`  | Starts several downloads of one new object at once.               | One origin fetch; the other requests link to it.                                                              |
| `direct`  | Downloads with `?directread`.                                     | Client to director to origin, with no cache.                                                                  |
| `missing` | Downloads an object that does not exist.                          | An error trace, and the hop that returned it. The client fails before its GET, when its stat finds no object. |

Environment variables set the interval, the scenario weights and the object sizes (section 6). The exerciser shares the origin's storage volume so it can create objects. It logs one line per scenario, with the outcome, whether that outcome was the expected one, and the duration. Each client's own log goes to `client.log` on the log volume, where it stands in for the log a user's own `pelican object get` would leave on their machine. At the default level a client logs only warnings and errors; `EXERCISER_DEBUG=true` logs everything. It deletes its downloads after each run, large and shared objects right away, and other generated objects after `EXERCISER_RETAIN_MINUTES`.

## 5. Observability stack

**Collector.** One OTLP receiver. Traces go to Jaeger and to the span metrics connector. Span metrics go to Prometheus over its OTLP receiver. The span metrics connector adds the low-cardinality Pelican attributes as dimensions: `pelican.cache.result`, `pelican.director.redirect_target`, `pelican.attempt.number`, `pelican.namespace` and `http.response.status_code`. In Prometheus they are `traces_span_metrics_calls_total` and `traces_span_metrics_duration_milliseconds_bucket`, with labels `service_name`, `span_name`, `status_code` and each dimension with its dots turned into underscores. A transform step drops span attributes whose key names a credential and masks values that look like a token, as a second line of defence behind constraint 3 of the tracing design.

**Logs.** The collector has no log pipeline, because a real federation's collector could not reach its sites' log files either. When a request's span is sampled, the origin, the cache and the client write its `trace_id` and `span_id` on their request log lines; with tracing off, or for a trace that was sampled out, the lines are unchanged. The director's log lines carry its own request ID instead, which is the `pelican.job_id` attribute on its `director.redirect` span. To find one download's log lines, take its trace ID from Jaeger or Grafana and search each service's log for it, on that service: `make trace-logs id=<trace id>` does that for the cache, the origin and the client.

**Grafana.** Anonymous access without a login. Grafana 13 gives anonymous users the Viewer role only, so `viewers_can_edit` is set to let them use Explore. Datasources: Prometheus and Jaeger, wired so a metric links to example traces. Three dashboards, in the folder "Pelican", each linking to the other two.

"Pelican object downloads" is the overview and the home page:

- Download rate and error rate.
- Download duration, p50 and p95, by stage (`client.query_director`, `client.attempt`, …).
- Cache hit ratio, and request duration for hits against misses.
- Director redirects by target, and director time by stage.
- Origin request duration, authorize against read.
- Attempts by number and outcome.
- Recent traces.
- Pelican's own `/metrics`: scrape status and the director's redirect counter, which work without tracing.

"Pelican download lookup" shows everything recorded for one trace ID:

- A table of recent downloads to pick from, which a `key=value` attribute filter narrows; the trace ID can also be pasted from a log line.
- Counts of spans and services, and the total duration, for that download.
- The trace timeline, with every span's attributes and events.
- Time by service and stage, and a table with one row per span.
- The commands that find the download's log lines on each service, filled in with its trace ID.

"What Pelican tracing answers" makes the case for tracing, one question per row. Each row states the question, shows the closest thing today's metrics offer (often nothing), and shows the answer that spans give:

1. Where does a download's time go?
1. What does a cache miss cost?
1. Is a slow miss the cache's fault or the origin's?
1. Why did the director send a client where it did?
1. Which step of a failed download failed?
1. Is the origin slow to authorize or slow to read?
1. How much of a download is overhead around the transfer itself?
1. Which log lines belong to one download?

**Ports on the host.** Grafana 3000, Jaeger 16686, Prometheus 9090, director 18444. Each can be changed in `.env` or from the shell.

## 6. Running it

### Files

| Path                                               | What it is                                                                                            |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `compose.yaml`, `.env`                             | The services, and the image versions, host ports and exerciser settings.                              |
| `Dockerfile`, `Dockerfile.dockerignore`            | Builds `pelican` and `pelican-server` from this repository; the build context is the repository root. |
| `pelican/*.yaml`                                   | One configuration file per Pelican server.                                                            |
| `exerciser/exerciser.sh`                           | The download loop.                                                                                    |
| `otel-collector/config.yaml`                       | The OTLP receiver, span metrics, redaction, exporters.                                                |
| `prometheus/prometheus.yaml`, `jaeger/config.yaml` | Backends.                                                                                             |
| `grafana/`                                         | `grafana.ini`, the two datasources and the three dashboards.                                          |
| `Makefile`                                         | Shortcuts for the commands below.                                                                     |

### Requirements

Docker with Compose v2, on amd64 or arm64. The stack needs about 4.5 GB of memory. On disk it needs a few GB for images and another 3.5 GB for the Go module and build caches; on Docker Desktop that space comes out of the VM's disk, which is easy to fill. The first build downloads every Go module and takes a few minutes; later builds take seconds.

### Start

From this directory:

```bash
make up            # docker compose up -d --build
make ps            # every service "running", the Pelican ones and Prometheus "healthy"
make exerciser-logs
```

The exerciser waits until a download through the federation succeeds, then prints `federation is ready` and one line per scenario:

```
2026-11-16T17:46:20Z scenario=hit object=/demo/fixed/obj-1.bin outcome=ok expected=yes exit=0 duration_ms=149
2026-11-16T17:46:34Z scenario=large object=/demo/gen/large-1794851193-1039.bin outcome=ok expected=yes exit=0 duration_ms=1036 size_mb=100
```

`expected=no` is the line to look into; the `missing` scenario reports `outcome=failed expected=yes`.

If a host port is taken, set it from the shell or in `.env`, for example `GRAFANA_PORT=3001 make up`. Every port in the table below has a variable.

### Where to look

| What                                              | URL                                                                    | Variable          |
| ------------------------------------------------- | ---------------------------------------------------------------------- | ----------------- |
| Grafana, dashboard "Pelican object downloads"     | http://localhost:3000/                                                 | `GRAFANA_PORT`    |
| Grafana, dashboard "Pelican download lookup"      | http://localhost:3000/d/pelican-trace/pelican-download-lookup          | `GRAFANA_PORT`    |
| Grafana, dashboard "What Pelican tracing answers" | http://localhost:3000/d/pelican-questions/what-pelican-tracing-answers | `GRAFANA_PORT`    |
| Jaeger                                            | http://localhost:16686/                                                | `JAEGER_UI_PORT`  |
| Prometheus                                        | http://localhost:9090/                                                 | `PROMETHEUS_PORT` |
| Director (discovery document)                     | https://localhost:18444/.well-known/pelican-configuration              | `DIRECTOR_PORT`   |

What to look at first:

1. **One download as one trace.** In Jaeger pick service `pelican-client` and operation `client.transfer`, and open a trace. A `hit` trace stops at `cache.serve_object`; a `miss` trace continues through `cache.fetch_origin` to `pelican-origin`; a `direct` trace goes from the director straight to the origin; a `missing` trace is marked as an error. Tag search narrows it down, for example `pelican.cache.result=miss` or `error=true`.
1. **The numbers.** Open Grafana; its home page is the dashboard. Points on the duration panels are exemplars: clicking one opens its trace.
1. **Logs for a trace.** Logs stay on each service. Copy a trace ID from Jaeger or from "Recent downloads (traces)", then run `make trace-logs id=<trace id>`: it searches the cache's, the origin's and the client's logs, each on its own service. The lookup page's last section shows the same commands with the trace ID filled in. Going the other way, a trace ID copied from a log line (`trace_id=`) can be pasted into the lookup page's Trace ID box.
1. **What tracing adds.** Open "What Pelican tracing answers" and read down it: each row sets today's metric beside the answer from spans.
1. **The endpoint comes from the director.** `curl -ks https://localhost:18444/.well-known/pelican-configuration` shows `tracing_endpoint`; only `pelican/director.yaml` sets it.

The Pelican servers write their logs to files, so `docker compose logs director` shows almost nothing. `make pelican-logs` follows the files.

### Downloading by hand

```bash
docker compose exec exerciser pelican object get pelican://director:8444/demo/fixed/obj-1.bin /tmp/obj-1.bin
docker compose exec exerciser pelican object get 'pelican://director:8444/demo/fixed/obj-1.bin?directread' /tmp/obj-1.bin
docker compose exec exerciser sh -c 'echo hello > /data/demo/hello.txt'
```

The exerciser container has `PELICAN_TRACING_ENABLED=true` and `PELICAN_TLSSKIPVERIFY=true` set, so these are traced like the loop's downloads.

### Tuning the exerciser

Set these in `.env` (or the shell) and run `docker compose up -d exerciser`.

| Variable                   | Default | Meaning                                                               |
| -------------------------- | ------- | --------------------------------------------------------------------- |
| `EXERCISER_INTERVAL`       | `2`     | Seconds to sleep between scenarios.                                   |
| `EXERCISER_WEIGHT_HIT`     | `6`     | Relative weight of the `hit` scenario.                                |
| `EXERCISER_WEIGHT_MISS`    | `3`     | Weight of `miss`.                                                     |
| `EXERCISER_WEIGHT_LARGE`   | `1`     | Weight of `large`.                                                    |
| `EXERCISER_WEIGHT_SHARED`  | `1`     | Weight of `shared`.                                                   |
| `EXERCISER_WEIGHT_DIRECT`  | `2`     | Weight of `direct`.                                                   |
| `EXERCISER_WEIGHT_MISSING` | `1`     | Weight of `missing`. A weight of 0 turns a scenario off.              |
| `EXERCISER_HIT_OBJECTS`    | `5`     | Number of fixed objects that `hit` and `direct` pick from.            |
| `EXERCISER_SMALL_SIZE_KB`  | `512`   | Size of the fixed objects and of each `miss` object.                  |
| `EXERCISER_LARGE_SIZE_MB`  | `100`   | Size of each `large` object.                                          |
| `EXERCISER_SHARED_SIZE_MB` | `20`    | Size of each `shared` object.                                         |
| `EXERCISER_SHARED_CLIENTS` | `4`     | Concurrent downloads in `shared`.                                     |
| `EXERCISER_RETAIN_MINUTES` | `10`    | Age after which generated `miss` objects are deleted from the origin. |
| `EXERCISER_DEBUG`          | `false` | `true` runs each `pelican object get` with `--debug`.                 |

The script also reads `EXERCISER_GET_TIMEOUT` (seconds per download, default 300), which `compose.yaml` does not pass by default.

### After a code change

```bash
make up                          # rebuild the image and recreate the Pelican containers
make restart s="cache"           # or rebuild, and recreate only the services named
```

Only the changed packages are recompiled, because the Go module and build caches are BuildKit cache mounts. A build failure from a package someone else is changing shows up here first; the previous image keeps running until a build succeeds.

### Checking the stack

```bash
curl -s http://localhost:16686/api/services                       # services Jaeger has spans from
curl -s 'http://localhost:9090/api/v1/targets?state=active' | grep -o '"health":"[a-z]*"'   # three "up"
curl -s 'http://localhost:9090/api/v1/query?query=sum%20by%20(service_name,span_name)(traces_span_metrics_calls_total)'
curl -s http://localhost:3000/api/datasources/uid/pelican-traces/health   # also pelican-metrics
docker compose logs otel-collector | grep -v '	info	'           # collector problems
```

### Stopping

```bash
make down          # remove the containers; keys, registrations, cached objects, logs and dashboards stay
make clean         # also delete the volumes and the Pelican image
make clean-go-cache   # delete BuildKit's Go caches (shared with any other Go project built here)
```

### Known behaviour

- At start the director logs a "Server name mismatch" warning: it registers itself as `director:8444` and its site name is `director`. It has no effect here.
- With the embedded Prometheus off, the director's own server-load query (`/api/v1.0/prometheus/query`) gets a 404 every 15 seconds and the director logs the request. The demo's director sorts caches at random, so the load figure is not used.
