# OpenTelemetry tracing for object downloads

Status: implemented alongside this document. Scope: object **download** (GET, and the HEAD requests that accompany it) through the client, director, cache and origin. Out of scope: uploads, listings, deletes, third-party copy, the web UI and its APIs, and the inside of XRootD.

This folder holds:

- `README.md` (this file): the questions tracing must answer, and the design that answers them, service by service.
- `implementation-plan.md`: the work packages, their file ownership and their order, written so separate agents could work in parallel.
- `demo/`: a docker compose demo with a federation, an exerciser and an observability stack.

Section 11 lists where the implementation ended up differing from the first version of this design, and why. The rest of the document describes the code as built.

## 1. Constraints

1. **Additive only.** No existing behaviour changes. With `Tracing.Enabled: false` (the default) the new code paths reduce to a boolean check or a no-op span, no header is added to any request, and no network connection is opened.
1. **Tracing never fails a transfer.** Export errors are logged at debug level and dropped. Nothing on a request path waits on the collector.
1. **No secrets in spans.** Tokens appear in `Authorization` headers and in `authz` / `access_token` query parameters. Spans never record request headers or query strings, and error messages are scrubbed before they are recorded.
1. **`X-Pelican-JobId` is untouched.** It keeps its current meaning and its hand-written forwarding. Tracing records it as a span attribute where a request carries it.
1. **The global OpenTelemetry provider is not set.** Third-party libraries already in the build (Google Cloud storage, fosite, the embedded Prometheus) create spans against the global provider. Setting it would make them start emitting, which is a behaviour change, so Pelican keeps its providers private to the `tracing` package.

## 2. Questions tracing must answer

Every span and attribute in this design exists to answer one of these. Section 9 maps each question back to the spans that answer it.

### About one download

| #   | Question                                                                                                                                                                                                    |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | A download was slow. How did its time divide between federation discovery, the director query, getting a token, probing endpoints, waiting for the first byte, moving the body, and verifying the checksum? |
| Q2  | Which servers did the client try, in what order, and what did each attempt return?                                                                                                                          |
| Q3  | Why did the director send the client to this cache or origin? Which candidates did it have, how did it sort them, and where did it think the client was?                                                    |
| Q4  | Was it a cache hit or a miss? On a miss, what did the cache do to get the object and how long did each step take?                                                                                           |
| Q5  | Did this request wait on a fetch that another request had already started?                                                                                                                                  |
| Q6  | A download failed. Which hop failed, with what error, and was it retryable?                                                                                                                                 |
| Q7  | How long did the origin spend authorizing the request, and how long opening and reading storage?                                                                                                            |
| Q8  | Given a job ID or a log line, which trace is it? Given a trace, which log lines belong to it?                                                                                                               |
| Q9  | Did the director check with origins or caches (stat) for this request, which ones, and how long did that take?                                                                                              |

### About many downloads

These are answered by metrics that the collector derives from spans, or by querying stored traces.

| #   | Question                                                                                                       |
| --- | -------------------------------------------------------------------------------------------------------------- |
| Q10 | What share of total download time is overhead (discovery, director, token, probing) as opposed to moving data? |
| Q11 | Which caches have the worst time to first byte, and is the cache or its fetch from the origin the cause?       |
| Q12 | How often does the first attempt fail, and which servers cause the retries?                                    |
| Q13 | What is the cache hit ratio, and what does a miss cost in added time?                                          |
| Q14 | Does the director's first choice succeed, or do clients end up on a lower-ranked server?                       |
| Q15 | Where does the director spend its time: namespace matching, stat requests, or sorting?                         |
| Q16 | Did a release change any of these?                                                                             |

### Not answered

- What happens inside an XRootD-based origin or cache. No Pelican Go code runs on their data path, so they produce no spans and do not forward trace context (section 8.3).
- A complete trace for a client that does not opt in. Each traced server still records its own part, as separate traces.

## 3. Trace model

One download is one trace. The client starts it. Each hop passes the W3C `traceparent` header to the next, and each service reports its own spans, labelled with the trace ID and its parent span.

This is the tree the end-to-end test records for a download that misses the cache.

```
pelican-client     client.transfer                                    one per transfer job
                   ├─ client.discover_federation
                   │   └─ GET                                          only when not cached
                   ├─ client.query_director
                   │   └─ GET ──────────────► pelican-director   director.redirect
                   │                                              ├─ director.match_namespace
                   │                                              ├─ director.stat_servers     only when a stat is sent
                   │                                              │   └─ HEAD ──► origin / cache
                   │                                              └─ director.sort_servers
                   ├─ client.acquire_token                             only when a token is needed
                   └─ client.download_object                           one per object
                       ├─ client.sort_attempts
                       │   └─ GET / PROPFIND probes ──► cache
                       ├─ client.attempt                               one per endpoint tried
                       │   └─ GET ──────────► pelican-cache      cache.serve_object
                       │                                          └─ cache.resolve_object
                       │                                              └─ cache.fetch_origin      on a miss
                       │                                                  ├─ client.stat         the cache's embedded client
                       │                                                  │   ├─ GET ──► pelican-director   director.redirect
                       │                                                  │   └─ PROPFIND ──► origin
                       │                                                  └─ client.transfer
                       │                                                      └─ client.download_object
                       │                                                          ├─ client.attempt
                       │                                                          │   └─ GET ──► pelican-origin   origin.serve_object
                       │                                                          │                                ├─ origin.authorize
                       │                                                          │                                └─ origin.read
                       │                                                          └─ client.verify_checksum
                       │                                                              └─ HEAD ──► pelican-origin
                       └─ client.verify_checksum
                           └─ HEAD ──► pelican-cache
```

Four properties of this model matter for the implementation.

**Only a client process starts a trace of its own.** `pelican object get` and the transfer plugin start `client.transfer` as the root of a new trace. A server only continues the trace a request brings to it, or, for a request with no `traceparent`, records its own part of that request. Background work in a server (prestaging, cache fills, health tests) has no request behind it and records nothing.

**Service name follows the process role, not the package.** The cache fetches from the origin using Pelican's own `client` package. Those spans keep the `client.*` names but are reported under `service.name=pelican-cache`, because a span started with `tracing.Start` inherits the service of its parent span.

**A shared fetch has one parent and many links.** When several requests miss on the same object, the cache runs one origin fetch. The fetch span is a child of the request that started it. Every other request that joins it sets `pelican.cache.shared_fetch=true` on its `cache.resolve_object` span, with a span link to the fetch span.

**A span may outlive its parent.** The cache deliberately lets an origin fetch continue after the request that started it has gone. The fetch span carries the span identity of that request without its cancellation (`tracing.CarrySpan`).

## 4. Shared foundation: the `tracing` package

All services use one new package, `tracing/`. It imports only `config`, `param` and the OpenTelemetry modules, so `client`, `director`, `origin_serve`, `local_cache`, `launchers` and `cmd` can all import it without cycles.

### 4.1 Configuration

| Parameter                     | Type | Default | Components              | Meaning                                                                                             |
| ----------------------------- | ---- | ------- | ----------------------- | --------------------------------------------------------------------------------------------------- |
| `Tracing.Enabled`             | bool | `false` | all                     | Turn tracing on for this process.                                                                   |
| `Tracing.Endpoint`            | url  | none    | all                     | OTLP/HTTP endpoint this process exports to, for example `https://collector.example.org:4318`.       |
| `Tracing.SamplePercentage`    | int  | `100`   | all                     | Percentage of traces this process records.                                                          |
| `Tracing.TrustRemoteSampling` | bool | `false` | director, origin, cache | Whether a server follows the sampling decision in an incoming `traceparent`.                        |
| `Federation.TracingEndpoint`  | url  | none    | all                     | The federation's shared OTLP/HTTP endpoint. The director advertises it; everyone else discovers it. |

Environment variables follow the existing rule, so `Tracing.Enabled` is `PELICAN_TRACING_ENABLED`.

**Endpoint resolution**, first match wins:

1. `Tracing.Endpoint`.
1. The standard `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` environment variables, which the OTLP exporter reads itself.
1. `Federation.TracingEndpoint`, set locally or learned from federation discovery (section 6.4).

If tracing is enabled and no endpoint is found, spans are still created and context still propagates, so trace IDs reach logs and downstream services, but nothing is exported. Up to 2048 spans are held in case an endpoint arrives later.

**Sampling.** The decision is a deterministic function of the trace ID (`TraceIDRatioBased`), so every Pelican process with the same percentage records the same traces. By default a server applies its own percentage even when the incoming `traceparent` says "sampled". Otherwise any client could force every one of its requests to be recorded and flood the collector. `Tracing.TrustRemoteSampling: true` switches a server to the usual parent-based behaviour, for federations that trust their clients or for debugging.

### 4.2 API

```go
package tracing

// Service is the service.name a span is reported under.
type Service string

const (
	ServiceClient   Service = "pelican-client"
	ServiceDirector Service = "pelican-director"
	ServiceOrigin   Service = "pelican-origin"
	ServiceCache    Service = "pelican-cache"
	ServiceServer   Service = "pelican-server" // the default service of a server process
)

// Lifecycle.
func Init(ctx context.Context, defaultService Service) (stop func(context.Context) error, err error)
func Configure(opts Options) (stop func(context.Context) error, err error) // explicit exporter; tests
func Flush(ctx context.Context) error
func Shutdown(ctx context.Context) error
func Enabled() bool
func DefaultService() Service
func OfferEndpoint(endpoint string)

// Spans.
func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span)
func StartChild(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span)
func StartWithService(ctx context.Context, svc Service, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span)
func StartServer(r *http.Request, svc Service, name string) (*http.Request, trace.Span)
func EndServer(span trace.Span, statusCode int)
func EndServerDeferred(span trace.Span, w StatusReporter) // defer this; w reports the response status
func CarrySpan(dst, src context.Context) context.Context
func NoopSpan() trace.Span

// Outgoing HTTP.
func Client(c *http.Client) *http.Client
func Transport(rt http.RoundTripper) http.RoundTripper

// Errors and secrets.
func RecordError(span trace.Span, err error) // marks the span failed
func NoteError(span trace.Span, err error)   // attaches the error; status unchanged
func Scrub(s string) string

// Small shared decisions.
func IsDownloadMethod(method string) bool // GET or HEAD
func LogFields(ctx context.Context) log.Fields
func WithLogFields(entry *log.Entry, ctx context.Context) *log.Entry
func TraceID(ctx context.Context) string
```

- `Init` reads the `Tracing.*` parameters. It does nothing and returns a nil `stop` when `Tracing.Enabled` is false. `stop` shuts down the configuration that call installed and nothing else, so a server that exits late cannot turn off a newer configuration.
- `Start` inherits the service of the span already in `ctx`; with no span it uses the process default.
- `StartChild` starts a span only if `ctx` already holds one. With no span it returns `ctx` and a no-op span, so the caller can never start a trace of its own. Every server stage and every client helper that is not the trace's root uses it.
- `StartServer` extracts trace context from the request headers and starts a server-kind span.
- `EndServerDeferred` is how all three servers end their server span. Deferred directly, it ends the span with the status the response writer reports. If the handler is panicking it ends the span as a failed 500 and lets the panic continue with its original value. A 500 is what the server's recovery middleware sends when nothing has been written yet. Where there is no such middleware (the cache's unix socket) or the headers have already gone out, the client sees a dropped connection or a truncated response, and the span still says 500. The re-panic puts the helper's own frames at the top of the stack the recovery middleware logs; the original panic site is still in it. For a request that is not traced it returns at once and leaves a panic untouched.
- `CarrySpan` returns `dst` with the span from `src` attached. Deadlines, cancellation and other values of `src` are not carried.
- `Client` returns `c` itself when tracing is disabled.
- Shared attribute keys (`pelican.job_id`, `pelican.object.path`, `pelican.namespace`, `pelican.federation`, `pelican.transfer.bytes`) are constants in `tracing/attributes.go`.
- `tracing/tracingtest` provides `Setup(t)`, which installs an in-memory exporter with synchronous export, and helpers for asserting on spans.

### 4.3 Behaviour that every service relies on

- **HTTP client spans** are named after the method (`GET`, `HEAD`, `PROPFIND`). They record `http.request.method`, `server.address`, `server.port`, `url.full` with the query string and user info removed, and `http.response.status_code`. The span ends when the response body is closed or fully read, so for a download it covers the body. A client span is created only when the request's context already holds a span. A wrapped client never starts a trace on its own.
- **Server spans** are created by the service at its own entry point, not by an engine-wide middleware. Only object GET and HEAD are traced. Other methods, health-test objects under `/pelican/monitoring`, metrics scrapes and the web UI produce nothing. In a multi-module process (federation in a box) each request is still labelled with the right service.
- **A span is marked failed only when its own service failed.** On a server span the response status alone decides: `EndServer` marks it failed for a 5xx and not for a 4xx, which is the client's error. The error behind a response is attached with `NoteError`, as an `exception` event and an `error.type` attribute, without changing the status. `RecordError` is for spans that are not server spans: a client attempt, the cache's fetch from the origin, a director sort that errors out.
- **Attributes** use the `pelican.` prefix. Keys used by one service are constants in that service's own `tracing.go`.
- **Resource attributes**: `service.name`, `service.version` (the Pelican version, which answers Q16), `service.instance.id` and `host.name` (the server's hostname). `OTEL_RESOURCE_ATTRIBUTES` is honoured for extras.
- **Log correlation** is explicit. The origin, the cache and the client add `trace_id` and `span_id` to the per-request logger they already build. A trace that was sampled out adds nothing, because its ID would point at a trace that was never exported. Nothing is hooked into logrus globally.
- **Scrubbing** is the second line of defence. `Scrub` redacts `Bearer` and `Basic` credentials, token-bearing parameters in query and JSON forms, URL-encoded nested queries, and anything shaped like a JWT. It matches the shapes credentials travel in, and leaves alone a sentence that merely mentions a token, such as "failed to get token: no such file". Whatever follows `Bearer` or `Basic` is redacted however short it is, so "bearer token expired" loses a word; that is the safe way round.

### 4.4 Lifecycle

- **Servers**: `launchers.LaunchModules` calls `tracing.Init` after `config.InitServer` and before any routes are registered, with `ServiceServer` as the default service. If tracing started, it registers a task on the server's errgroup that calls `stop` at shutdown, bounded at five seconds, and it offers the federation's advertised endpoint once the server's own discovery has run. Tracing stops when the server's context is cancelled, which is after in-flight transfers have been given `Xrootd.ShutdownTimeout` to finish but at the same moment the web server begins its own ten-second drain. Spans of requests that end during that last drain are dropped.
- **Client commands**: `object get` and the transfer plugin call `client.InitTracing` after `config.InitClient`, and `client.FlushTracing` once the transfers have finished, before deciding the exit code. `FlushTracing` waits up to a second and a half for transfer spans that are still ending and then exports, all within two seconds, so a dead collector cannot delay a job by more than that.
- **Library callers** of the `client` package do nothing. If the host process has not initialised tracing, every span is a no-op.

## 5. Client

Process: the `pelican` binary (`object get`), the HTCondor transfer plugin, and the `client` package when a server embeds it.

### 5.1 Spans

| Span                         | Where                                                                       | Attributes                                                                                                                                                                                                                      |
| ---------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `client.transfer`            | Starts in `NewTransferJob`.                                                 | `pelican.object.path`, `pelican.federation`, `pelican.namespace`, `pelican.client.project`, `pelican.transfer.recursive`, `pelican.job_id` when the job has one; at the end `pelican.transfer.objects`                          |
| `client.discover_federation` | Around federation discovery in `NewTransferJob`.                            | `pelican.federation`                                                                                                                                                                                                            |
| `client.query_director`      | Around each director lookup. Not created for a federation with no director. | `pelican.director.endpoint`, `pelican.director.with_token`                                                                                                                                                                      |
| `client.acquire_token`       | Around token acquisition.                                                   | none; never the token                                                                                                                                                                                                           |
| `client.stat`                | Around `TransferEngine.Stat`, only under an existing span.                  | `pelican.object.path`                                                                                                                                                                                                           |
| `client.download_object`     | `downloadObject`, one per object.                                           | `pelican.object.path`, `pelican.transfer.bytes`, `pelican.transfer.attempts`                                                                                                                                                    |
| `client.sort_attempts`       | Endpoint probing and ordering.                                              | `pelican.attempt.candidates`                                                                                                                                                                                                    |
| `client.attempt`             | One per endpoint tried.                                                     | `pelican.attempt.number`, `pelican.attempt.endpoint`, `pelican.attempt.bytes`, `pelican.attempt.time_to_first_byte_ms`, `pelican.attempt.cache_age_s`, `pelican.attempt.server_version`, `pelican.attempt.retryable` on failure |
| `client.verify_checksum`     | Checksum fetch and comparison.                                              | none                                                                                                                                                                                                                            |

HTTP client spans appear under these wherever the client sends a request: discovery, the director query, probes, the download GET and the checksum HEAD.

### 5.2 When the transfer span starts and ends

**Start.** In a client process (`tracing.DefaultService()` is `pelican-client`) a download job with no span in its context starts a new trace. In any other process a job is traced only as a child of a span already in its context. That is what keeps the cache's background downloads silent.

**End.** The span ends at the first of these:

- Job creation fails.
- The engine holds every result of the job. Three one-line calls in the engine's result loop tell the job span when a result arrives, when one is delivered, and when the lookup has finished. Ending on arrival, not on delivery, matters: the cache cancels its context as soon as it has read its one result, and a span that ended on delivery could record that successful fetch as cancelled.
- The job's context is cancelled (`context.AfterFunc`). Without this, a batch that stops at its first failure, or a plugin run that is cancelled, would never end the span of a job that still had transfers in flight, and its child spans would be exported as orphans.

A job whose objects failed ends with error status ("N of M objects failed").

### 5.3 Context

The span must travel from job creation to the HTTP request.

| Place                             | Today                                                                                     | Change                                                                                                                                                           |
| --------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `doGet` (`client/main.go`)        | `NewTransferJob(context.Background(), …)`                                                 | Carry the caller's span onto that context with `tracing.CarrySpan`. Cancellation is unchanged.                                                                   |
| Transfer plugin (`cmd/plugin.go`) | `jobCtx := context.Background()`                                                          | Unchanged; the job span is the root.                                                                                                                             |
| `mergeCancel`                     | Keeps values from the job context only.                                                   | Nothing to change: the job span is put on the job context before the merge.                                                                                      |
| Director response cache           | Detaches cancellation, keeps values; concurrent lookups share the first caller's request. | Nothing to change. The director request is a child of whichever job asked first, and a cached answer shows as a `client.query_director` span with no HTTP child. |
| Token acquisition                 | Takes no context.                                                                         | The span wraps the call; requests inside it are not traced.                                                                                                      |

### 5.4 Notes

- **Time to first byte.** `TransferResult.TimeToFirstByte` is always zero for downloads today, because `downloadHTTP` never assigns its `timeToFirstByte` return value. That is an existing bug in the transfer results, and fixing it would change the contents of transfer ads, so this work leaves it alone. The span attribute is filled from the first-byte time that the progress writer already records.
- **Late endpoint.** `pelican object get pelican://federation/…` learns its federation from the URL. After discovery, a client process calls `tracing.OfferEndpoint` with the discovered `tracing_endpoint`. Spans created before that are held and exported once the endpoint is known. An embedded client in a server never offers: the server's launcher offers its own federation's endpoint. The first federation a client process discovers chooses the collector for every span in that process. A single `object get` that downloads from two federations sends both downloads' spans to the first federation's collector.
- **Job ID.** A plain `object get` sends no `X-Pelican-JobId`. The client sends one inside an HTCondor job (the job's `GlobalJobId`) or when a caller supplies a request ID.

## 6. Director

Process: `pelican-server` with the director module.

### 6.1 Spans

| Span                         | Where                                                                                                                                              | Attributes                                                                                                                                                                                                                            |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `director.redirect` (server) | Top of `redirectToCache` and `redirectToOrigin`. Both are reached from routes and from the shortcut middleware, so the span starts in the handler. | `pelican.job_id`, `pelican.object.path`, `pelican.namespace`, `pelican.director.redirect_target`, `pelican.director.chosen`, `pelican.director.candidates.caches`, `pelican.director.candidates.origins`, `http.response.status_code` |
| `director.match_namespace`   | Namespace lookup and the origin and cache filters in `getSortedAds`.                                                                               | `pelican.namespace`                                                                                                                                                                                                                   |
| `director.stat_servers`      | `generateAvailabilityMaps`, only when a stat is actually sent.                                                                                     | `pelican.director.stat.queried`, `pelican.director.stat.available`                                                                                                                                                                    |
| `director.sort_servers`      | `sortServerAds`, once for each kind of server sorted.                                                                                              | `pelican.director.sort_method`, `pelican.director.server_type`, `pelican.director.candidates`, `pelican.director.client_coordinate_source`                                                                                            |

- `pelican.director.redirect_target` is `cache` or `origin`: the kind of the first server in the response, which is where the client is actually sent.
- `pelican.director.chosen` lists the servers in the response as `host:port`, in the order and number of the `Link` header.
- `pelican.director.client_coordinate_source` is `header`, `override`, `maxmind`, `cached_random` or `random`.
- `pelican.job_id` is the request ID the director uses. It is the client's `X-Pelican-JobId` only when that value is a UUID; otherwise the director generates one.

The stat `HEAD` requests appear as HTTP client spans under `director.stat_servers`, and as server spans on a traced origin or cache. A missing `director.stat_servers` span means the director sent no stat for that request.

### 6.2 Context

The director's stages take a `*gin.Context` and never read the request context. Each stage starts its span from `ginCtx.Request.Context()`.

Two calls use `context.Background()` on purpose, because their work is cached and shared across requests: the sort context in `getSortedAds`, and the stat query in `generateAvailabilityMaps`. Both get the request's span attached with `tracing.CarrySpan`, which keeps their cancellation behaviour exactly as it is.

Two things show up in traces as a result of how the director already works:

- When the adaptive sort stats caches lazily, `director.stat_servers` is a sibling of the `director.sort_servers` span whose time window contains it, because the stat is given only the gin context.
- The stat pool refreshes a result that is about to expire using the context of the query that found it, which is cancelled when that query returns. Such a refresh appears as a cancelled `HEAD` under a `director.stat_servers` span that has already ended.

### 6.3 The director's decision

The director already computes `RedirectInfo` (client location, per-server coordinates and weights, sort method) for every request, and returns it only when `X-Pelican-Debug` is set. When the request's span is recording, the director adds that structure to `director.redirect` as a `director.decision` span event. This answers Q3 for every recorded request with no new computation.

The event is built from a copy. In the copy the client's IP address is masked the way the redirect metrics mask it (/24 for IPv4, /64 for IPv6), and the client's latitude and longitude are rounded to one decimal place, about 11 km. The structure returned to a debug client is not modified.

### 6.4 Advertising the collector endpoint

The director is where a federation's services are discovered, so it is where the collector endpoint is advertised.

**Mechanism.** The federation discovery document, `/.well-known/pelican-configuration`, gains one optional field:

```json
{
  "director_endpoint": "https://director.example.org",
  "namespace_registration_endpoint": "https://registry.example.org",
  "jwks_uri": "https://director.example.org/.well-known/issuer.jwks",
  "tracing_endpoint": "https://otel.example.org:4318"
}
```

- The field is `tracing_endpoint` on `pelican_url.FederationDiscovery`, with `omitempty`, so a director without the setting serves exactly the document it serves today, and older clients ignore the field.
- The federation operator sets `Federation.TracingEndpoint` on the director.
- `config.GetFederation` fills the field the way it fills the others: a local `Federation.TracingEndpoint` wins, otherwise the discovered value is used. The value is not rewritten to https, so an `http://` collector URL survives.
- Origins and caches already run discovery at start-up, and clients run it per federation. Both pass the result to `tracing.OfferEndpoint`.

**What it does not do.** Advertising an endpoint never turns tracing on. A client or server exports only if its own operator set `Tracing.Enabled: true`. The advertised endpoint is trusted to the same degree as the advertised director and registry URLs, which come from the same document.

**Alternatives considered.**

| Alternative                              | Why not                                                                                                     |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| A response header on every redirect      | The client needs the endpoint before its first request, and the header would be repeated on every redirect. |
| The response to a server's advertisement | That response carries no data today, and clients never see it.                                              |
| A new director API endpoint              | A second discovery mechanism for one value.                                                                 |

**Known gaps.**

- The collector accepts spans from anyone who can reach it. The OTLP exporter honours `OTEL_EXPORTER_OTLP_HEADERS`, so an operator can require a shared key on servers they run, but that does not help clients that learn the endpoint from discovery. Authenticating servers with their existing federation keys is future work.
- A server that has every federation URL set locally skips discovery, so it never learns the advertised endpoint. It needs `Tracing.Endpoint` or a local `Federation.TracingEndpoint`.

## 7. Cache

Process: `pelican-server` with the cache module and `Cache.EnableV2: true` (the Go-native cache), and the local cache module, which shares the same code.

### 7.1 Spans

| Span                          | Where                                                                                                                                                                                                     | Attributes                                                                                                                                            |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cache.serve_object` (server) | Top of `serveObject`, which serves both the TCP routes and the unix socket.                                                                                                                               | `pelican.job_id`, `pelican.object.path`, `pelican.cache.range_request`, `pelican.cache.result`, `pelican.transfer.bytes`, `http.response.status_code` |
| `cache.resolve_object`        | `resolveObject`: authorization, metadata lookup and the decision.                                                                                                                                         | `pelican.cache.decision`, `pelican.cache.shared_fetch` with a link to the fetch                                                                       |
| `cache.fetch_origin`          | A fetch from the origin: a shared whole-object download, a child of the `cache.resolve_object` that started it, or a fill of missing blocks, a child of the `cache.serve_object` whose reader started it. | `pelican.object.path`                                                                                                                                 |

- `pelican.cache.result` is `hit`, `miss`, `pass-through` (a response streamed through without being stored) or `hit-redirect` (a redirect to tier storage). It is the label `serveObject` already puts in its log line, so traces and logs agree.
- `pelican.transfer.bytes` is the object data the cache sent. A 304 and a redirect to tier storage carry none and record none.
- `pelican.cache.decision` is what resolving the object decided: `cached` (a record of the object exists), `revalidate`, `download` (a whole-object fetch), `range_init` (a range request for an unknown object, set up from a stat) or `denied`. It is not the hit-or-miss result. An object whose record exists is `cached` even while its blocks are still being fetched, which `pelican.cache.result` reports as a `miss`.

The fetch itself is done by the embedded client, so `client.stat`, `client.transfer` and their children appear under `cache.fetch_origin`, reported as `pelican-cache`.

A Pelican client probes a cache with a small range request before it downloads. For an object the cache does not have, that probe is resolved as `range_init`, and the blocks are then fetched by fills, one per gap a reader is in. So the usual miss from a real client shows two `cache.serve_object` spans, the probe and the download, each with a `cache.fetch_origin` fill beneath it, and a whole-object `download` only happens for a client that sends no range request first. A fill is recorded under the request whose reader started it and, like a whole-object download, keeps running on the cache's own context after that request has gone.

### 7.2 Context

| Place             | Today                                                                                                       | Change                                                                                                                                                                           |
| ----------------- | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `serveObject`     | Starts the fetch on `context.Background()` plus the request ID, because the fetch must outlive the request. | Also carry the request's span with `tracing.CarrySpan`.                                                                                                                          |
| `performDownload` | Derives the transfer's context from the cache-wide download context.                                        | Also carry the fetch span.                                                                                                                                                       |
| `downloadObject`  | Later callers wait on the first caller's download.                                                          | The first caller starts `cache.fetch_origin` before the download entry becomes visible and stores its span context on the entry. Waiters mark their `cache.resolve_object` span. |
| `startFill`       | Runs a fill on the cache-wide download context.                                                             | The request's span is kept on the object resolution the reader was built from, and attached to the fill's context.                                                               |

`cache.fetch_origin` ends in the goroutine that already retires the download entry, so it ends exactly once on every completion path, including a transfer handed to the block fetcher.

### 7.3 Limits

- **The unix-socket listener records no status code.** The response writer is never wrapped, gin's writer reports its status and a plain `net/http` writer does not, so a span from the unix socket ends without `http.response.status_code` and is not marked failed, unless its handler panics.
- **A HEAD on a miss stats the origin outside the request's trace.** `HeadObject` takes no context.
- **An `only-if-cached` request for an object that is not cached is marked failed.** The answer RFC 7234 prescribes is a 504, and a server span is failed by any 5xx.
- **A whole-object `cache.fetch_origin` is failed by an origin 404.** The fetch is the cache acting as a client, and it did not get the object; the client spans under it are failed for the same reason. The cache's own `cache.serve_object` answers 404 and is not failed. A fill's `cache.fetch_origin` is never marked failed: a fill that stops early has usually only lost its last reader, so its error is attached as an event.
- **Only joining a whole-object download sets `pelican.cache.shared_fetch`.** A request whose reads wait on blocks that another request's fill is writing is not marked, nor is one that joins a shared revalidation or range initialisation. Since real clients probe first, most shared misses are of the unmarked kind: such a request shows time in `cache.serve_object` with nothing beneath it.
- **`cache.fetch_origin` carries no byte count.** The embedded client's spans under it do.
- **`cache.serve_object` has no `pelican.namespace`.** The cache does not know the namespace an object belongs to.

## 8. Origin

Process: `pelican-server` with the origin module and a Go-native storage type (`posixv2`, `s3v2`, `httpsv2`, `globusv2`, `ssh`, `pstore`).

### 8.1 Spans

| Span                           | Where                                                                           | Attributes                                                                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `origin.serve_object` (server) | A middleware placed first in each export's route group.                         | `pelican.job_id`, `pelican.object.path`, `pelican.namespace` (the export's federation prefix), `pelican.origin.storage_type`, `pelican.transfer.bytes`, `http.response.status_code` |
| `origin.authorize`             | The token check in `authMiddleware`. It ends before the rest of the chain runs. | `pelican.origin.authorized`, `pelican.origin.token_count`; never the token                                                                                                          |
| `origin.read`                  | From the GET handler's dispatch until the response is written.                  | none                                                                                                                                                                                |

- `pelican.object.path` is computed the way the handler computes the path it serves: the export's prefix joined with the cleaned remainder of the request path.
- `pelican.transfer.bytes` is recorded only for object data: a GET answered 200 or 206 with an `ETag`. Error bodies and HTML directory listings are not counted, and an empty object records 0.
- `pelican.origin.authorized` is true exactly when the middleware lets the request through, including a public read with no token.

For the `httpsv2` backend, the upstream request is sent with a traced client, so it appears as an HTTP client span under `origin.read` and carries `traceparent`. The other backends (`s3v2`, `globusv2`, `ssh`, `pstore`) do not pass trace context upstream.

### 8.2 Context

The request context already flows from the handler into the backend's `OpenFile`. The middleware puts the span on the request before the existing middleware runs, so every later stage sees it.

### 8.3 XRootD-based origins and caches

With `Origin.StorageType: posix` (and `s3`, `https`, `globus`, `xroot`) or a cache without `Cache.EnableV2`, XRootD serves the data and no Pelican Go code runs per request. These servers produce no spans and do not forward `traceparent`.

A trace through one still shows the client's side in full: the director's decision, each attempt, time to first byte and body time. What is missing is the breakdown inside the server and, for a cache miss, the link to the origin's part. Carrying trace context through XRootD needs changes to the XRootD plugins and is future work.

## 9. How the questions are answered

| #   | Answered by                                                                                                                    |
| --- | ------------------------------------------------------------------------------------------------------------------------------ |
| Q1  | Durations of the children of `client.transfer` and `client.download_object`; `pelican.attempt.time_to_first_byte_ms`           |
| Q2  | The `client.attempt` spans in order, with endpoint, status and error                                                           |
| Q3  | `director.redirect` attributes, `director.sort_servers`, and the `director.decision` event                                     |
| Q4  | `pelican.cache.result`, `pelican.cache.decision`, and the `cache.fetch_origin` subtree                                         |
| Q5  | `pelican.cache.shared_fetch` on `cache.resolve_object`, and its link to the fetch; only for whole-object downloads (see below) |
| Q6  | The span with error status, its `error.type` and `exception` event, the HTTP status, and `pelican.attempt.retryable`           |
| Q7  | `origin.authorize` and `origin.read`                                                                                           |
| Q8  | `trace_id` in the origin's, cache's and client's request log lines; `pelican.job_id` where a request carries one (see below)   |
| Q9  | `director.stat_servers` and its `HEAD` children                                                                                |
| Q10 | Span metrics: duration of `client.download_object` against `client.attempt`                                                    |
| Q11 | Span metrics for `client.attempt` by endpoint; `cache.serve_object` against `cache.fetch_origin`                               |
| Q12 | Span metrics for `client.attempt` by `pelican.attempt.number` and status                                                       |
| Q13 | Span metrics for `cache.serve_object` by `pelican.cache.result`                                                                |
| Q14 | `pelican.attempt.number` of the successful attempt                                                                             |
| Q15 | Span metrics for the `director.*` spans                                                                                        |
| Q16 | Any of the above split by `service.version`                                                                                    |

Three answers are weaker than first intended.

**Q8, job ID.** The trace ID is the reliable join between services and logs. `pelican.job_id` is recorded wherever a request carries `X-Pelican-JobId`, but a plain `object get` sends none, and the director replaces an HTCondor job ID, which is not a UUID, with one it generates. So the job ID joins the client, cache and origin for HTCondor jobs, and does not join the director. The director's log lines carry its own request ID, which is the `pelican.job_id` on its span.

**Q5, shared fetches.** The marker covers requests that join a whole-object download. A request that waits on another request's fill of missing blocks, which is how misses from real clients are usually shared, is not marked (section 7.3).

**Q13, by namespace.** The cache's span has no namespace. The hit ratio by namespace comes from a trace query that joins `cache.serve_object` to the `pelican.namespace` on the client's or director's span in the same trace.

## 10. Testing

- **`tracing` package**: unit tests for enablement, endpoint resolution, the sampler's handling of remote parents, scrubbing, the HTTP client wrapper, server span extraction, the held-span exporter and the scoped `stop` function.
- **Each service**: unit tests that drive the instrumented path with `tracingtest.Setup` and assert on span names, parentage and key attributes. Each also asserts that with tracing disabled no `traceparent` header is sent and the response is unchanged, and that no token reaches any span.
- **End to end**: `e2e_fed_tests/tracing_test.go` runs a Go-native federation (`posixv2` origin, `Cache.EnableV2`), downloads an object twice, and asserts that the first download is one trace containing client, director, cache and origin spans, that the second is a cache hit with no origin span, and that no recorded attribute contains a token.

## 11. Decisions and deviations

What changed between the first version of this design and the code, and why.

**Dependencies.**

- The OTLP exporter is `otlptracehttp` v1.38.0 while `otel`, `otel/sdk` and `otel/trace` are v1.40.0. v1.38.0 is the release train `go.mod` already carried for `otlptrace`. v1.40.0 would have pulled minor bumps of `golang.org/x/crypto`, `x/net`, `x/text` and others, which an additive change should not cause.

**`tracing` package.**

- `Init` and `Configure` return a `stop` function scoped to their own configuration. A process-wide `Shutdown` let one test federation turn off tracing that a later one had started.
- `StartChild`, `NoteError`, `IsDownloadMethod`, `WithLogFields`, `NoopSpan` and `DefaultService` were added after review. Each replaced the same few lines written separately in two to four packages.
- The default service of a server is always `pelican-server`. The first version derived it from the enabled modules, but a server starts no spans without a parent, so the value named nothing.
- `tracingtest.Setup` does not nest and does not restore an earlier enabled state; it leaves tracing disabled at cleanup.

**Errors.**

- A server span is failed by its status code alone, and errors are attached with `NoteError`. The first implementation marked 4xx responses as failed in the director and the cache but not in the origin, which made unknown namespaces, expired tokens and missing objects look like server failures.
- All three servers end their server span with `EndServerDeferred`. The first implementation handled a panicking handler only in the origin, with a local flag; the director and the cache would have exported the span as a successful 200.

**Client.**

- `client.stat` is traced only under an existing span. `object get` stats before its job exists, and a lone stat span would be a trace of its own.
- A job starts a trace only in a client process (section 5.2). The first implementation started one whenever tracing was on, so every background download in a cache became a new trace.
- The transfer span ends when the engine holds every result or the job's context is cancelled (section 5.2), not when the job is retired.
- The transfer span is marked failed when any of its objects failed.

**Director.**

- 4xx outcomes are noted, not marked as failures. The handler attaches the error to `director.redirect`; the child spans do not repeat it.
- `director.stat_servers` exists only when a stat is sent.
- `pelican.director.redirect_target` is the kind of the first server in the response, not the route that was called.
- The decision event rounds the client's coordinates.
- The director adds no `trace_id` to its logs. Its log calls take no context, and they already carry the request ID that the span records.

**Cache.**

- `cache.fetch_origin` is a child of `cache.resolve_object`, where the download is started, and may outlive it.
- `pelican.cache.shared_fetch` and the link are on `cache.resolve_object`, not on `cache.serve_object`. Putting them on the request's top span needed a private context key to reach it from inside the download code.
- `pelican.cache.result` has the extra values `pass-through` and `hit-redirect`, and `pelican.cache.decision` the extra value `denied`.
- The decision for an object whose record exists is `cached`, not `hit`. Running the demo showed `decision=hit` beside `result=miss` on every download that followed a client's probe.
- Fills of missing blocks are recorded as `cache.fetch_origin` under the request that started them. The first implementation left them untraced as background work, and the demo showed that a miss from a real client then had a slow `cache.serve_object` with nothing beneath it and no origin span at all.
- The limits in section 7.3.

**Origin.**

- `origin.authorize` ends before the rest of the chain runs. The authorization middleware calls the rest of the chain from inside itself, so a deferred end would have measured the whole request.
- `origin.read` carries no attributes; the storage type is on its parent.
- `pelican.transfer.bytes` is recorded only for object data.
- `pelican.origin.storage_type` is the origin-wide setting.

## 12. Future work

- Trace context through XRootD-based origins and caches.
- Authenticating servers to a shared collector with their federation keys.
- Passing a context into the cache's `HeadObject` and the client's token acquisition, so their requests join the trace.
- Marking requests that wait on another request's fill, with a link to it.
- Trace propagation from the origin to S3, Globus and SSH backends.
- A namespace attribute on the cache's spans.
