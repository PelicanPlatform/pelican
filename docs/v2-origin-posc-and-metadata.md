# Origin POSC and Object-Metadata Upload (V2 Origin)

Status: design — implementation in progress Audience: Pelican origin developers and operators Scope: V2 (POSIXv2) origin only.

## Motivation

Two related capabilities are missing from the V2 origin today:

1. **Atomic write semantics on close.** A V2 origin streams an HTTP `PUT` directly to the destination path. A client that disconnects mid-write leaves a truncated object visible at its final name. There is no transactional boundary at which the object becomes visible to readers.
1. **Notifying an external metadata service.** Pelican deployments commonly need to publish object-level metadata (catalog, audit, search index, billing) outside of the origin. There is no built-in way to announce that an upload has been committed.

The XRootD-backed S3/HTTP plug-in already implements a "Persist On Successful Close" (POSC) pattern that solves (1) by writing to a hidden temporary file and renaming on close. We adopt the same model in the V2 origin, then layer (2) on top of POSC so that metadata is only ever published for objects that actually committed to storage.

## Requirements

| ID | Requirement | |-----|-----------------------------------------------------------------------------------------------------| | R1 | POSC and metadata upload are independent and independently configurable. | | R2 | POSC: an upload is visible to readers only after a successful close. | | R3 | POSC: a partial / failed / abandoned upload eventually disappears (background expiry). | | R4 | POSC: the temporary directory is invisible to clients (`Stat`, `ReadDir`, `Open`, `Rename`). | | R5 | Metadata publish must run *after* the data is durably committed. | | R6 | Transactional metadata mode: a publish failure surfaces as a transfer failure (non-2xx on the PUT). | | R7 | Eventually-consistent mode: the publish is durably enqueued before the client sees `2xx`. | | R8 | Eventually-consistent mode: retries with exponential backoff + jitter, bounded concurrency. | | R9 | The metadata service has health states: healthy / warning / error tied to publish age (configurable, default 4h / 24h). | | R10 | The callback receives a JWT signed with the origin's signing key, scope `pelican.metadata` plus the namespace. | | R11 | Each published event carries a stable UUID so the receiver can dedupe redelivered events. | | R12 | The outgoing webhook is JSON. Custom uploader-supplied metadata is conveyed *into* the origin via HTTP **Structured Field Values** (RFC 9651) on the upload request; on the way out, those fields are inlined into the webhook JSON alongside the auto-collected fields. | | R13 | Per-export overrides are honored for the metadata endpoint, mode, and any optional auth knobs. | | R14 | Worker checks the object still exists before retrying a publish; if the object was deleted out from under us, the row is dropped. | | R15 | Pelican's existing Prometheus pipeline exposes counters and gauges for queue depth, retries, failures, and oldest-pending age. | | R16 | An admin HTTP endpoint exposes the queue and supports operator deletion of stuck rows. | | R17 | The ETag for an object is taken from the storage backend (e.g. the WebDAV / OSS-computed ETag); the origin does not introduce its own hash algorithm choice. | | R18 | All new behavior is covered by tests with non-trivial coverage (unit + integration). |

## Non-goals

- We do not change the XRootD-backed origin. The XRootD plug-in already performs POSC via [`xrootd-s3-http`](https://github.com/PelicanPlatform/xrootd-s3-http).
- We do not implement a generic "upload event" pub/sub. The receiver is a single configured HTTP endpoint per export (or origin-wide default).
- We do not provide a query API for the eventually-consistent queue beyond an admin status endpoint and Prometheus metrics.
- We do not attempt to recover an upload across origin restarts — POSC temporary files written by a prior process are GC'd by the expiry thread; the client must retry the upload.

---

## Architecture

```
                ┌────────────────────────────────────────────────────┐
                │                 V2 Origin process                   │
                │                                                     │
   client ──PUT─▶  Gin → authMiddleware → webdav.Handler              │
                │              │                                      │
                │              ▼                                      │
                │   ┌─────────────────────────┐                       │
                │   │  webdav.FileSystem      │                       │
                │   │  (compositional layers) │                       │
                │   │                         │                       │
                │   │  multiuserFs            │  (Linux only)         │
                │   │   └─ poscFs  ◀──── new  │                       │
                │   │       └─ rateLimitFs    │                       │
                │   │           └─ autoMkdir  │                       │
                │   │               └─ rootFs │                       │
                │   └─────────────────────────┘                       │
                │              │                                      │
                │              ▼                                      │
                │   ┌─────────────────────────┐                       │
                │   │ Close pipeline          │                       │
                │   │  1. fsync data          │                       │
                │   │  2. POSC rename → final │                       │
                │   │  3. INSERT publish row  │  (always, both modes) │
                │   │  4. attempt publish     │                       │
                │   │     (mode-dependent)    │                       │
                │   └─────────────────────────┘                       │
                │              │                                      │
                │      ┌───────┴────────┐                             │
                │      ▼                ▼                             │
                │  transactional    eventually-consistent             │
                │  block on first   return now;                       │
                │  attempt          worker drains row                 │
                │      │                │                             │
                └──────┼────────────────┼─────────────────────────────┘
                       ▼                ▼
                   metadata         metadata
                   endpoint  ◀──── endpoint (with retries + jitter)
```

### Layer placement

The POSC layer is inserted into the existing webdav-filesystem composition chain *between* the multiuser and rate-limited layers:

- It must wrap the rate-limited / auto-mkdir / root layers because POSC needs to drive `Mkdir`/`Rename`/`Unlink` on those underlying layers.
- It must be wrapped by the multiuser layer so temp files inherit the `setuid/setgid` of the authenticated user.
- The metadata-publish hook lives inside the POSC `File.Close()` so it is unconditionally guarded by a successful rename.

If POSC is disabled but metadata publishing is enabled, a thin `closeNotifyFs` wraps the chain and runs the publish hook on `Close()` of any file opened with write intent (`O_CREATE` or `O_WRONLY` flags present). Without POSC, "successful close" is a strictly weaker guarantee — the file may have been observed by readers mid-stream — but the publish hook still runs only on `Close()` returning nil.

### POSC algorithm (V2 port)

The V2 implementation mirrors the C++ reference (see `xrootd-s3-http/src/Posc.cc`):

1. **Open with create/truncate intent** (`O_CREATE | O_TRUNC` or `O_CREATE | O_WRONLY`) is intercepted. The destination path is recorded; the file is *actually* opened at `<PoscPrefix>/<user>/in_progress.<unix>.<rand>` with `O_EXCL | O_CREATE`, mode `0600`.
   - If the per-user POSC subdirectory does not exist, it is created with mode `0700`.
   - Generation retries up to 10× on `EEXIST`.
1. **Open without create/truncate** falls through to the wrapped filesystem unchanged.
1. **Writes** record an updated mtime on the in-memory POSC handle (used by the keepalive thread, see below).
1. **Close** does, in order:
   1. `Close()` the underlying handle. On failure, unlink the temp file and return the underlying error.
   1. `Chmod` the temp file to the originally-requested mode.
   1. (Optional) compare actual size to advertised size (`Content-Length`). Mismatch ⇒ unlink + return EIO.
   1. `Rename` temp → final. If rename fails (e.g. EISDIR), unlink and preserve the underlying errno so it maps to a meaningful HTTP status.
   1. (If enabled) call the metadata-publish hook.
1. **Stat / ReadDir / Open / Rename / Mkdir / Remove** on any path inside the POSC prefix returns `ENOENT` (or `EIO` for `Mkdir`) so the temp area is invisible to clients.
1. **Background expiry thread** runs every 5s, walks `<PoscPrefix>/<user>/`, and unlinks `in_progress.*` files older than `Origin.Posc.FileTimeout` (default 1h). Long-running active uploads "touch" their temp file periodically (default every 19m) so they are not collected.

Note one V2 simplification: in the C++ implementation `Open` is split across `Create` and `Open`. The Go `webdav.FileSystem` uses a single `OpenFile`, so the staging logic is co-located. The C++ "skip Create when POSC will handle it" logic has no analog and is simply omitted.

### The publish event

After a successful POSC rename (or, if POSC is disabled, after the underlying `Close` returns nil) the close pipeline:

1. Builds an `ObjectCommit` event in memory:

   - `id` — UUIDv4 generated server-side. Stable across retries so receivers can dedupe redelivered events.
   - `type` — `object.committed` (this is the only type today; the field exists so we can add `object.deleted`, `object.updated`, etc. without a wire-protocol break).
   - `timestamp` — RFC 3339 time the event was generated.
   - `namespace` — the matching `Origin.Exports[*].FederationPrefix`.
   - `object` — see below.

1. Inserts that event into the local `metadata_publish_queue` table. This is **always** done — transactional and eventually-consistent modes share the same write-ahead log. The DB write happens *after* the POSC rename and *before* the first publish attempt, so a crash in that window leaves a recoverable row.

1. Hands the row off to the publisher. Transactional mode blocks on the first attempt; eventually-consistent mode returns immediately and lets the background worker take over.

This means the only difference between modes is whether the close returns a 2xx synchronously or whether it waits for the publish to land. The DB row, retry semantics, and Prometheus metrics are identical.

#### Wire format

The webhook is JSON, modeled after the GitHub / Stripe webhook conventions:

```
POST <Origin.Metadata.Endpoint>
Authorization: Bearer <jwt>
Content-Type: application/json
X-Pelican-Idempotency-Key: <uuid>
User-Agent: pelican-origin/<version>

{
  "id":        "8d9d5f3e-4f5b-4f1e-9c1f-2a8a7b1d6c43",
  "type":      "object.committed",
  "timestamp": "2026-04-29T13:14:15Z",
  "namespace": "/foo",
  "object": {
    "path":       "/foo/bar.dat",
    "size":       12345,
    "etag":       "\"d41d8cd98f00b204e9800998ecf8427e\"",
    "created_at": "2026-04-29T13:14:15Z",

    /* Custom uploader-supplied fields are inlined here, not nested
       under a separate "extra" key. They are namespaced by client
       convention only — Pelican does not validate or reserve names
       (other than refusing to overwrite the four built-in keys above). */
    "experiment": "atlas",
    "run_number": 4172,
    "is_test":    false
  }
}
```

The `X-Pelican-Idempotency-Key` header repeats `id`; receivers that prefer HTTP-level dedup get it for free, while receivers that consume the JSON body get it inline. (The well-known `Idempotency-Key` header is still an IETF draft, not an RFC; per Pelican convention non-RFC headers are namespaced with the `X-Pelican-` prefix so operators can tell at a glance which headers belong to Pelican.)

A 2xx response is success. Any other status (or transport error) is failure. Redirects (3xx) are followed up to 5 hops.

#### Custom metadata: from client to webhook

Clients pass custom metadata on the upload itself by adding a **Structured Fields dictionary** (RFC 9651) to the PUT request:

```
PUT /foo/bar.dat HTTP/1.1
X-Pelican-Object-Metadata: experiment="atlas", run_number=4172, is_test=?0
```

The header value is a single Structured-Fields *dictionary*. The origin parses it on `OpenFile`, retains the parsed value for the life of the upload, and inlines the keys into the `object` JSON field above. Type mapping:

| SFV type | JSON type | |---------------------|----------------------------------------------| | String | string | | Integer | number (integer) | | Decimal | number | | Boolean | boolean | | Token | string (the token) | | Byte sequence | string (base64-url, prefixed `:`) | | Date (RFC 9651) | string (RFC 3339) | | Inner list / parameters | dropped with a warning (v1) |

Reserved keys (`path`, `size`, `etag`, `created_at`) cannot be overridden by the client; if present they are silently ignored and a counter is incremented.

We deliberately use Structured Fields for the *input* path because:

- It survives intermediaries that fold/whitespace-canonicalize headers.
- It has a typed grammar, so a client passing `run_number=4172` round-trips as a JSON integer rather than a string `"4172"`.
- It avoids embedding JSON inside a header (escaping pain).

#### JWT

The bearer token is created via the existing `token.NewWLCGToken` configuration with:

- Issuer: this origin's URL (`Origin.Url`).
- Subject: this origin's URL (per existing convention).
- Audience: the metadata endpoint's URL.
- Lifetime: 5 minutes (configurable).
- `jti`: the event UUID (so JWT-level dedup tools can track replays).
- Scopes: `pelican.metadata` plus the namespace export's federation prefix (e.g. `pelican.metadata:/foo`).

Signing uses the origin's active issuer key (`config.GetIssuerPrivateJWK()`), the same key used to sign advertisement tokens.

`pelican.metadata` is a new top-level scope (see `docs/scopes.yaml`). Like `storage.read`, it accepts a path suffix to constrain the token to a specific namespace.

The JWT is the only authentication mechanism. There is no separate body signature: the receiver authenticates the source by validating the bearer JWT against the origin's published JWKS, then trusts the JSON body. If a deployment requires stronger guarantees they can front the metadata endpoint with mTLS at the network layer.

### Common close pipeline

Both modes share this pseudocode:

```
fileClose:
  POSC.rename()                    // commit on storage
  err := db.enqueue(event)         // durable WAL row
  if err != nil:
      remove(final_path)           // can't WAL → can't promise upload
      return EIO -> 500 to client
  err = publisher.attempt(row,     // mode == transactional? wait : enqueue
                          mode)
  switch mode:
    case transactional:
        if err != nil:
            // best-effort rollback
            remove(final_path)
            db.delete(row.id)
            return EIO -> 500 to client
        db.delete(row.id)
        return 200
    case eventual:
        // attempt() never returned a hard error; row stays in DB
        // even if the first attempt failed.
        return 200
```

The DB write is synchronous and must succeed before we 200. This keeps the user's "the upload succeeded" guarantee aligned with the durability of the publish queue: if the origin process dies between rename and INSERT, the row is missing and the object is "leaked" — same failure mode as the transactional rollback. The window is the duration of one SQLite WAL fsync.

### Transactional mode

`Origin.Metadata.Mode = "transactional"` (per-export overridable).

The first publish attempt is synchronous on the request goroutine. On failure the object is best-effort removed and the row deleted, and the client sees a 5xx. The transactional path does **not** retry — a slow metadata service should fail fast and let the client retry the entire PUT. Per-attempt timeout is `Origin.Metadata.RequestTimeout` (default 10s).

If `remove(final_path)` fails the rollback is incomplete: object is in storage, no metadata, no DB row. We log a warning and increment `pelican_origin_metadata_rollback_failed_total`. The next overwrite of the same path will re-publish; otherwise operators reconcile via the metadata service's own tooling.

### Eventually-consistent mode

`Origin.Metadata.Mode = "eventual"` (the default when the metadata feature is enabled).

The close returns 2xx as soon as the row is durably enqueued. A background pool of workers drains the queue:

```
forever:
    rows := db.claimDue(batch=N)
    for row in rows:
        // skip-if-deleted: keeps the queue from chasing ghosts
        if !storage.exists(row.namespace, row.object_path):
            db.delete(row.id)
            metric.objectDeleted.Inc()
            continue

        ok := publish(row.event)
        if ok:
            db.delete(row.id)
            metric.publishSuccess.Inc()
        else:
            db.scheduleRetry(row.id, backoff(row.attempts), errMsg)
            metric.publishFailure.Inc()
```

- **Skip-if-deleted:** before each retry we `Stat` the final object through the same filesystem chain the upload used. If the file is gone (admin deleted, expired, etc.) we drop the row. This keeps a permanently-deleted object from polluting the queue forever.
- **Backoff:** exponential starting at `Origin.Metadata.MinBackoff` (default 30s), capped at `Origin.Metadata.MaxBackoff` (default 30m), with full jitter (`sleep = rand(0, computed)`).
- **Concurrency:** `Origin.Metadata.MaxInflight` (default 4) workers.
- **Rate limit:** token bucket at `Origin.Metadata.RatePerSecond` (default 10) shared across workers.
- **No row is ever permanently failed.** It keeps retrying until it succeeds, or the object is deleted, or the operator deletes the row via the admin endpoint.

#### Health states

A row's "age" is `now - created_at` (the original event time, not the latest retry).

| Age range | Service health | |-------------------------------|---------------------| | < `WarnAfter` | healthy | | ≥ `WarnAfter` (default 4h) | warning | | ≥ `ErrorAfter` (default 24h) | error |

Health is computed across **all namespaces served by this origin** (the queue is shared across exports). Per-namespace age can be inspected via the admin endpoint and via labeled Prometheus metrics. An origin in `error` state does **not** refuse uploads — the metadata service health is decoupled from the data path.

---

## Data model

### Configuration parameters

All new parameters are added under `Origin.Posc.*` and `Origin.Metadata.*`.

| Parameter | Type | Default | Notes | |-----------------------------------|----------|--------------------|-------| | `Origin.Posc.Enabled` | bool | `false` | Master switch for V2 POSC. | | `Origin.Posc.Prefix` | filename | `<export>/.pelican-posc` | Per-export. Must be on same filesystem as the export. | | `Origin.Posc.FileTimeout` | duration | `1h` | Idle in-progress files older than this are GC'd. | | `Origin.Posc.KeepaliveInterval` | duration | `19m` | How often a still-active in-progress file is touched. | | `Origin.Metadata.Enabled` | bool | `false` | Master switch for object-commit publish. | | `Origin.Metadata.Endpoint` | url | (none) | URL we POST to. Required if Enabled. | | `Origin.Metadata.Mode` | string | `eventual` | `transactional` | `eventual`. | | `Origin.Metadata.RequestTimeout` | duration | `10s` | Per-attempt HTTP timeout. | | `Origin.Metadata.TokenLifetime` | duration | `5m` | JWT lifetime. | | `Origin.Metadata.MinBackoff` | duration | `30s` | Eventual mode only. | | `Origin.Metadata.MaxBackoff` | duration | `30m` | Eventual mode only. | | `Origin.Metadata.MaxInflight` | int | `4` | Worker concurrency. | | `Origin.Metadata.RatePerSecond` | float64 | `10` | Token-bucket rate. | | `Origin.Metadata.WarnAfter` | duration | `4h` | Health threshold (origin-wide). | | `Origin.Metadata.ErrorAfter` | duration | `24h` | Health threshold (origin-wide). |

The ETag is supplied by the storage backend (e.g. the WebDAV-computed ETag from the underlying afero/Os filesystem); the origin does not introduce its own hash-algorithm choice. There is no `HashAlgorithm` parameter.

#### Per-export overrides

The origin process serves multiple namespaces (one per `Origin.Exports[]` entry) but uses a **single** SQLite database and a **single** worker pool. Operators commonly want to send different namespaces to different metadata sinks; the per-export overrides make that possible while keeping the queue centralized.

In `Origin.Exports[].Metadata.*` the following are honored:

| Field | Notes | |------------|--------------------------------------------------------------------| | `Endpoint` | Per-export endpoint URL. Falls back to origin-wide `Origin.Metadata.Endpoint`. | | `Mode` | Per-export `transactional` or `eventual`. Falls back to origin-wide. | | `Enabled` | Per-export off-switch (default: inherits origin-wide). |

`MaxInflight`, `RatePerSecond`, `MinBackoff`, `MaxBackoff`, `WarnAfter`, `ErrorAfter`, `RequestTimeout`, and `TokenLifetime` are **origin-wide only** — they describe shared resources (the worker pool, the rate-limit bucket, the queue health gauge).

### Database schema

A new `metadata_publish_queue` table is added via Goose migration in `database/origin_migrations/`:

```sql
CREATE TABLE metadata_publish_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT    NOT NULL UNIQUE,         -- UUIDv4 from event
    namespace       TEXT    NOT NULL,                -- federation prefix
    object_path     TEXT    NOT NULL,                -- federation-relative path
    object_size     INTEGER NOT NULL,
    etag            TEXT    NOT NULL,                -- backend-supplied
    object_created  DATETIME NOT NULL,               -- mtime / commit time
    custom_fields   TEXT    NOT NULL DEFAULT '{}',   -- JSON object, inlined into webhook
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_mpq_due ON metadata_publish_queue(next_attempt_at);
CREATE INDEX idx_mpq_age ON metadata_publish_queue(created_at);
CREATE INDEX idx_mpq_ns  ON metadata_publish_queue(namespace);
```

Notes:

- We do **not** use a "status" column. Rows in the table are pending; successful rows are deleted. This keeps the hot index small.
- `event_id` is the UUIDv4 generated when the event was first built, unique-indexed for safety. It is what the receiver dedupes on.
- `next_attempt_at` is the worker's claim cursor: workers `SELECT ... WHERE next_attempt_at <= CURRENT_TIMESTAMP ORDER BY next_attempt_at LIMIT N`, then `UPDATE` to push `next_attempt_at` ahead by one backoff interval *before* attempting (preventing a duplicate worker picking up the same row).
- `created_at` is the original event time, not the row-insert time, so retries do not artificially reset health-state aging.
- `custom_fields` is a JSON object containing already-translated custom fields ready to be inlined into the webhook. The translation from Structured Fields (the input) to JSON (the storage and output representation) happens once, at enqueue time, so the worker treats the column as opaque text.

### In-memory state

- A singleton `*posc.FileSystem` per origin process tracks open in-progress files (linked list, `m_first/m_next` style — same as the C++ version) so the keepalive thread can `utimes` them.
- A singleton `*metadata.Publisher` owns the worker pool, the rate limiter, the HTTP client, the issuer-key cache, and the per-export endpoint table (built once at startup from `Origin.Exports`).

### Structured Fields parser (input only)

Pelican does not currently depend on a Structured Fields library. We will use [`github.com/dunglas/httpsfv`](https://pkg.go.dev/github.com/dunglas/httpsfv), which implements RFC 8941 / RFC 9651 and is small and well-tested. The parser is **input-only**: it converts the `X-Pelican-Object-Metadata` request header on incoming PUTs into the `custom_fields` JSON object. We do not emit Structured Fields on the outgoing webhook.

Public entry points (in `origin_serve/object_metadata_header.go`):

```go
// Parse the request header into a JSON-ready map. Returns an empty
// map if the header is absent. Returns an error if the header is
// malformed or contains reserved keys.
func ParseObjectMetadataHeader(value string) (map[string]any, error)

// Reserved keys that the client cannot override.
var ReservedCustomFieldKeys = []string{"path", "size", "etag", "created_at"}
```

---

## Observability

### Prometheus metrics

All metrics are prefixed `pelican_origin_metadata_`. Where labeled, the labels are: `namespace` (federation prefix) and `mode` (`transactional` | `eventual`).

| Metric | Type | Labels | Meaning | |-------------------------------------------------|-----------|-----------------------|------------------------------------------------------------------------| | `pelican_origin_metadata_events_enqueued_total` | counter | namespace, mode | Rows successfully inserted into the queue. | | `pelican_origin_metadata_publish_attempts_total`| counter | namespace, mode, outcome (`success`,`http_4xx`,`http_5xx`,`network`,`timeout`) | Per-attempt outcome count. | | `pelican_origin_metadata_publish_latency_seconds`| histogram| namespace, mode | End-to-end attempt latency. | | `pelican_origin_metadata_queue_depth` | gauge | namespace | Current pending rows. | | `pelican_origin_metadata_oldest_pending_seconds`| gauge | namespace | Age of the oldest pending row. | | `pelican_origin_metadata_health` | gauge | state (`healthy`,`warning`,`error`) | 0/1, exactly one state is 1 origin-wide. | | `pelican_origin_metadata_skipped_object_deleted_total`| counter | namespace | Rows dropped because the object was gone before publish succeeded. | | `pelican_origin_metadata_rollback_failed_total` | counter | namespace | Transactional rollback (object delete) failures. | | `pelican_origin_metadata_admin_deletes_total` | counter | namespace | Rows removed by an operator via the admin endpoint. | | `pelican_origin_posc_active_uploads` | gauge | (none) | In-progress POSC files currently open. | | `pelican_origin_posc_expired_total` | counter | (none) | Stale POSC temp files removed by the expiry thread. |

Latency, attempt count, and queue-depth gauges are updated under the publisher's lock. The age gauge is recomputed once per scrape from `SELECT MIN(created_at)`.

### Admin HTTP endpoint

A new authenticated admin API surface is added under `/api/v1.0/origin/metadata_queue` (gated by an existing Pelican admin scope; same gating as other origin admin APIs). This is a thin SQL-on-HTTP wrapper, not a CRUD UI.

| Method & path | Behavior | |--------------------------------------------------------|---------------------------------------------------------------------------------------| | `GET /api/v1.0/origin/metadata_queue` | List pending rows (paginated, filterable by `namespace`, sorted by `created_at`). | | `GET /api/v1.0/origin/metadata_queue/{event_id}` | Show a single row including `last_error` and `attempts`. | | `DELETE /api/v1.0/origin/metadata_queue/{event_id}` | Drop a single row (e.g. an operator has decided not to publish). | | `POST /api/v1.0/origin/metadata_queue/{event_id}/retry`| Force `next_attempt_at = now`, leaving `attempts` unchanged. Useful after fixing the receiver. | | `GET /api/v1.0/origin/metadata_queue/_health` | JSON view of the origin-wide health state and per-namespace age summary. |

The web UI status page consumes these endpoints to render a queue view; that view is a follow-up and not in scope for the initial PR.

---

## Failure modes & operator guidance

| Scenario | Behavior | |------------------------------------------------|---------------------------------------------------------------------------------------------------| | Origin crashes between rename and DB insert | Object exists in storage but no metadata. Caught only by external recon. Window is one fsync. | | Origin crashes after DB insert, before publish | Row in queue is durable; worker retries on next start. No data loss. | | Origin crashes mid-PUT (POSC enabled) | Temp file remains; expiry thread cleans it up after `FileTimeout`. | | Metadata endpoint 5xx, eventual mode | Row stays in queue, retried with backoff. Health gauge ages. | | Metadata endpoint 5xx, transactional mode | Origin returns 500 to client. Origin best-effort removes the object and the queue row. | | Metadata endpoint persistently 4xx (e.g. 401) | Same as 5xx — we do not distinguish. Operator must fix and `POST /retry` or `DELETE` manually. | | DB unavailable | Origin returns 500 to client (cannot durably enqueue). Object best-effort removed. | | Object deleted between commit and publish | On the next worker pass, `Stat` fails → row dropped, `skipped_object_deleted_total` incremented. | | Two origins sharing a DB | **Not supported.** The queue is single-writer; concurrent claims would race on `next_attempt_at`. The single origin may serve many namespaces / exports concurrently. | | Receiver receives the same `event_id` twice | Expected behavior under retry. Receivers must dedupe on `event_id` / `X-Pelican-Idempotency-Key`. |

## Test plan

The implementation will be tested at three layers:

1. **POSC unit tests** (`origin_serve/posc_test.go`):
   - Successful Open → Write → Close → object visible at final path.
   - Mid-stream client disconnect → no object visible at final path, temp file is cleaned by expiry thread.
   - `Stat` / `ReadDir` / `Open` / `Rename` / `Mkdir` against a path inside the POSC prefix all return `ENOENT` / `EIO`.
   - Rename to an existing directory returns `EISDIR`-equivalent error (HTTP 409) — not `EIO`.
   - Size-mismatch rejection (when `Content-Length` is provided).
   - Per-user POSC subdirectory is created with `0700`; another user's temp file is invisible.
   - Concurrent uploads of the same final path: exactly one wins, the loser sees the winning content (no torn writes).
1. **Metadata unit tests** (`origin_serve/metadata_test.go`):
   - Input header parser: SFV → JSON-ready map, including all supported types, reserved-key rejection, malformed-input errors.
   - JWT generation: scope is `pelican.metadata:/<namespace>`; `jti` equals event UUID; signature verifies under origin's public key.
   - DB enqueue: row content matches event; `event_id` is unique-indexed.
   - Transactional mode: 500 from receiver → 500 to client + object and queue row both removed; 200 → 200 to client + queue row removed.
   - Eventual mode: rows persist across worker restarts; attempts / `last_error` are updated correctly; backoff respects min/max and applies jitter; first attempt happens immediately.
   - Eventual mode: when the object has been deleted between commit and worker pass, the row is dropped and `skipped_object_deleted_total` increments.
   - Per-export endpoint: an upload to namespace `/A` posts to its override URL; namespace `/B` falls back to origin-wide URL.
   - Health gauge transitions healthy → warning → error at the right ages (using fake clock).
   - `event_id` is stable across retries (asserted via the receiver observing two attempts with identical UUIDs).
1. **Admin endpoint tests** (`origin_serve/metadata_admin_test.go`):
   - Auth: unauthenticated requests get 401; non-admin tokens get 403.
   - List, get, delete, retry happy paths.
   - Pagination + namespace filter.
   - `_health` endpoint returns the right state for the fake clock.
1. **End-to-end integration test** (`origin_serve/metadata_e2e_test.go`):
   - Spin up an origin against a temp directory + a `httptest.Server` receiver. PUT a file, assert the receiver got the expected JSON body (with custom fields inlined from `X-Pelican-Object-Metadata`) and the origin returned 200.
   - Stop the receiver, PUT a file in eventual mode, restart the receiver, assert the row drains and the receiver got exactly one (or, if a retry overlapped, two with the same `event_id`) POSTs.

The PR will not be marked ready until coverage of `origin_serve/posc*.go` and `origin_serve/metadata*.go` is at least at parity with the rest of the package.

## Open questions

- Should we support TLS client-cert auth to the metadata endpoint as an alternative to JWT? Filed as a follow-up; default is JWT only.
- Do we want a header-only signature instead of a full bearer JWT, to let the receiver verify without downloading the issuer's JWKS? We are punting on this until at least one consumer is written.

## Addendum: opaque-blob metadata via multipart upload

Status: design, not yet implemented. This section is layered on top of the original design — none of it is in tree yet, and nothing above changes shape. The existing `X-Pelican-Object-Metadata` header path stays. This addendum specifies the *opt-in* multipart form for consumers whose metadata is not key/value-shaped (the motivating case: XML documents).

### Why a separate path

The Structured-Fields header is great for "experiment=atlas, run_number=4172, is_test=?0" but breaks the moment a consumer wants to forward a 50 KB XML manifest. SFV doesn't model documents; even if we forced base64, header-size limits across the HTTP stack (stdlib net/http default 1 MB, common reverse-proxy caps ≈8–64 KB) mean we'd start dropping requests well before "reasonable XML metadata." We need a body-shaped channel for that data.

### Wire format

When a client wants to attach an opaque metadata blob to an upload, the upload `PUT` is sent as `multipart/form-data` (RFC 7578) with **exactly two parts, in this order**:

```
PUT /exp/data/run99.dat
Content-Type: multipart/form-data; boundary=BOUNDARY
Content-Length: <set by client; covers full body>

--BOUNDARY
Content-Disposition: form-data; name="metadata"
Content-Type: application/xml

<datasetSummary>
  <experiment>atlas</experiment>
  <runs>4170,4171,4172</runs>
</datasetSummary>
--BOUNDARY
Content-Disposition: form-data; name="object"
Content-Type: application/octet-stream

<bytes of run99.dat ...>
--BOUNDARY--
```

Rules:

- The boundary string is the client's choice and follows RFC 7578 / RFC 2046 syntax (Go's `mime/multipart.Writer` picks one automatically).
- The first part **must** have `Content-Disposition: form-data; name="metadata"`. Its `Content-Type` is the on-the-wire type of the blob (XML, JSON, CSV, opaque binary, …); the origin treats it as opaque bytes and forwards the type verbatim to the receiver.
- The second part **must** have `Content-Disposition: form-data; name="object"`. Its body is the file content. The origin streams this part straight through the POSC pipeline as if it had been the raw PUT body.
- Any other part name, any other order, or absence of either required part → **400 Bad Request**. Failing fast keeps the staging directory clean and the close-hook precondition ("we have all the metadata") true.

Order is non-negotiable because a multipart reader is one-pass forward: receiving the file body before the metadata would force the origin to buffer either GB of file bytes (memory) or the file to a sidecar (extra fsync round-trip) before the close-hook fires.

### Content-Type detection on the origin

The PUT entry point checks `Content-Type`:

| Incoming Content-Type | Path taken | |----------------------------|-------------------------------------------------------------| | `multipart/form-data; …` | Multipart parser (this addendum). | | anything else | Existing path: stdlib `webdav.Handler` reads `r.Body` raw. |

Header-based custom fields (`X-Pelican-Object-Metadata`) are honored on **either** path. They occupy a different slot in the webhook (see below), so there is no ambiguity if both are present on a multipart upload — the SFV fields inline into the `object` sub-object exactly as today, while the multipart blob lands in the new `metadata` sub-object.

### Reverse-direction: how the origin posts to the receiver

When the inbound upload was multipart-shaped, the outbound webhook to the metadata endpoint is also multipart so the consumer can process the blob without a base64 round-trip:

```
POST <Origin.Metadata.Endpoint>
Authorization: Bearer <jwt>
Content-Type: multipart/related; boundary=B; type="application/json"; start="<event>"
X-Pelican-Idempotency-Key: <event-uuid>
User-Agent: pelican-origin/<version>

--B
Content-ID: <event>
Content-Type: application/json

{
  "id": "...",
  "type": "object.committed",
  "timestamp": "...",
  "namespace": "/exp",
  "object": { "path": "/exp/data/run99.dat", "size": ..., "etag": ..., "created_at": ... },
  "metadata": {
    "content_type": "application/xml",
    "size": 12345
  }
}
--B
Content-ID: <metadata>
Content-Type: application/xml

<datasetSummary>…</datasetSummary>
--B--
```

We use `multipart/related` (RFC 2387) outbound — not `multipart/form-data` — because the receiver is treating the body as a compound document with a root (the JSON event) rather than as a set of form fields. The `start` parameter points at the root via its `Content-ID`.

When the inbound upload was *not* multipart, the outbound webhook is the same plain-JSON form as today (no behavior change for existing consumers).

### Database schema delta

The `metadata_publish_queue` table grows two columns:

```sql
ALTER TABLE metadata_publish_queue ADD COLUMN metadata_content_type TEXT NOT NULL DEFAULT '';
ALTER TABLE metadata_publish_queue ADD COLUMN metadata_body         BLOB NOT NULL DEFAULT X'';
```

Notes:

- For inserts where no multipart blob was supplied, both columns are empty strings / empty blobs. The worker observes this and posts the existing plain-JSON form.
- The blob is stored as a SQLite `BLOB`, capped in size by config (see below). 4 MB is the per-row hot limit; bigger blobs are rejected by the multipart middleware before they reach the queue.

### New configuration

| Parameter | Type | Default | Purpose | |------------------------------------------|----------|---------------|------------------------------------------------------------------------------------------------------| | `Origin.Metadata.AllowMultipart` | bool | `true` | When false, the origin rejects multipart-form PUTs with a 415 so an operator can keep raw-PUT only. | | `Origin.Metadata.MaxMetadataBytes` | bytecount| `4MB` | Hard cap on the size of the `metadata` part. Larger requests get a 413. | | `Origin.Metadata.MetadataPartName` | string | `metadata` | Reserved field name for the metadata part. Configurable in case a downstream consumer needs a different convention. | | `Origin.Metadata.ObjectPartName` | string | `object` | Same, for the object body part. |

### Client-side API delta

Two new transfer options join `WithObjectMetadata` / `WithObjectMetadataFile`:

```go
// Attach an opaque metadata blob from an in-memory byte slice.
// contentType is the on-the-wire Content-Type the receiver sees
// (e.g. "application/xml"). The upload PUT switches from raw to
// multipart/form-data.
func WithObjectMetadataBlob(body []byte, contentType string) TransferOption

// Sibling that reads the blob from a file path. The Content-Type
// is sniffed from the file extension (.xml ⇒ application/xml,
// .json ⇒ application/json, …) and may be overridden via
// WithObjectMetadataContentType.
func WithObjectMetadataBlobFile(path string) TransferOption

// Override the auto-sniffed content type from WithObjectMetadataBlobFile.
func WithObjectMetadataContentType(contentType string) TransferOption
```

The CLI gets one new flag:

```
pelican object put --metadata-body manifest.xml \
                   [--metadata-content-type application/xml] \
                   src dst
```

If `--metadata-body` and `--metadata-file` (header-form) are both supplied, the client errors out before any network I/O — exactly one opaque-blob source per upload.

### Coexistence with the existing header path

Both can be present on a single upload:

| `X-Pelican-Object-Metadata` | multipart `metadata` part | Webhook shape | |-----------------------------|---------------------------|----------------------------------------------------------------------------| | absent | absent | plain JSON, no `metadata` field | | present | absent | plain JSON, custom fields inline into `object` | | absent | present | `multipart/related` outbound; JSON event + opaque blob | | present | present | `multipart/related` outbound; JSON event has both inline custom fields AND a `metadata` sub-object pointing at the blob |

### Streaming bounds (the question that started this)

Multipart parsing is a one-pass stream:

- The metadata part is read into memory up to `MaxMetadataBytes`, then closed. If the first part's payload exceeds the cap, the middleware aborts with 413 *before* opening any staging file — no partial write hits disk.
- The object part is wrapped as an `io.Reader` and fed straight into the existing POSC `OpenFile → Write → Close` pipeline. Memory cost is bounded by Go's stdlib multipart buffering (currently a small bufio default per part) — independent of total upload size.
- `Content-Length` from the request still bounds the *total* PUT body, which the existing rate-limit / metrics layers honor. The POSC-side `expected_size` check we added in P2.7 is dropped for multipart uploads because the per-part length is not known from the request header alone; an operator who wants size guarantees on multipart uploads can re-introduce them by having the client send a custom `Content-Disposition` `size=` param and adding a middleware check.

### Server-side composition

The PUT entry point becomes a thin demultiplexer that runs *before* `webdav.Handler.ServeHTTP`:

```
handleRequest:
  if r.Method == PUT && contentTypeIsMultipart(r):
      partMeta, partObj, err := splitMultipartParts(r.Body, cfg)
      if err != nil: write the right 4xx and return
      stash partMeta in the request context (capped slurp)
      replace r.Body with partObj
      set r.Header["Content-Type"] = partObj's Content-Type
      delete r.Header["Content-Length"]   // unknown now
      r.TransferEncoding = ["chunked"]
  webdav.Handler.ServeHTTP(w, r)
```

The POSC close-hook reads `multipartMetadataFromContext(ctx)` to decide whether to attach the blob, and the metadata controller queues the blob alongside the existing event row.

### What is NOT in scope for this addendum

- Multiple metadata parts. v1 is one blob. Receivers wanting more structure can do their own internal split.
- WebDAV `MOVE`/`COPY` propagation of the metadata blob. Not supported; metadata is upload-time only.
- Director-side handling. The director is body-transparent; this is an origin-↔-client + origin-↔-receiver contract.
- POSC `oss.asize` parity for multipart. Documented as a follow-up knob, not a v1 deliverable.
- Synchronous validation of the metadata blob's content (XSD, JSON Schema, etc.). The origin treats it as opaque bytes; if a deployment wants validation, that lives on the receiver.

### Test plan (delta)

1. Client unit tests: option-construction, content-type sniffing on `WithObjectMetadataBlobFile`, mutual-exclusion check vs the header path.
1. Origin unit tests: the splitter rejects wrong ordering, missing parts, too-large `metadata`, and bad form-field names with the right 4xx code each time.
1. Origin unit tests: POSC pipeline still streams the object part straight through (no buffering surprise from the multipart layer).
1. E2E (mirrors `TestClientUploadWithObjectMetadata`): client posts a multipart upload with a synthetic XML blob, receiver gets a `multipart/related` POST whose second part is the same XML byte-for-byte.
1. E2E: an upload with both `X-Pelican-Object-Metadata` and a multipart `metadata` part is accepted and both surface in the outbound `multipart/related` webhook.

### Open questions for review

- Should `Origin.Metadata.AllowMultipart` default to `true` (opt-out) or `false` (opt-in)? Defaulting to true matches the "accept both" guidance and minimizes friction for operators; the flag is then a safety valve for deployments behind a proxy that rewrites `Content-Type`.
- `MaxMetadataBytes = 4 MB` is a guess. Real consumers' XML manifests are typically \<100 KB; 4 MB leaves slack but bounds worst-case row sizes in SQLite. Open to data.
- Should we store the blob inline in the queue table, or in a side-table keyed by `event_id`, or in a per-namespace filesystem path? Inline keeps the model simple at the cost of bigger row sizes on the hot path; a side-table is easy to add if blobs grow.

---

## Deferred / out-of-scope (PR-time documentation)

The following are explicitly out of scope for the initial PR but are called out here so reviewers can confirm intent and so future operators have a single place to look.

### Per-export overrides apply to the metadata feature only

`Origin.Metadata.Endpoint`, `Mode`, and `Enabled` may be overridden per-export (in `Origin.Exports[].Metadata.*`). All POSC settings (`Origin.Posc.*`) are origin-wide. Concurrency / rate-limit / back-off / health-threshold settings on the metadata side are also origin-wide because they describe shared resources (the worker pool, the rate-limit token bucket, the health gauge).

If a deployment needs per-export back-pressure, that's a follow-up.

### No web UI consumer yet

The admin endpoints under `/api/v1.0/origin_ui/metadata_queue/` are implemented and authenticated; no Pelican web UI page consumes them yet. Operators today can hit the endpoints with `curl` or any admin-token-bearing client. A queue-inspection page in the origin status UI is a natural follow-up.

### No startup-time reconciliation against the filesystem

Two crash windows are possible. (a) Origin dies between the POSC rename and the queue INSERT — the object is on disk with no row. (b) Origin dies between the INSERT and the first publish attempt — the row survives, and the worker drains it on next start. Today we handle (b) automatically; (a) is silently leaked and is left for an operator-initiated reconciliation tool. A startup-time scan that walks the filesystem and the queue and reports both directions of mismatch is a reasonable follow-up. (Issue tracker only — not a v1 deliverable.)

### No fsync between rename and reply

Matches the C++ POSC reference and POSIX defaults. Power-loss after the 2xx but before the kernel flushes the rename can leave the client believing a commit happened that's no longer visible. If a deployment cares about durability across host crashes, the recommended posture is filesystem-level barriers (eg ext4 default journaling) rather than per-syscall fsync, which would meaningfully slow down the upload path. This stance is identical to the C++ POSC's; the design doc reaffirms it here so it's not an issue per PR.

### New runtime dependency

`github.com/dunglas/httpsfv` (RFC 8941 / RFC 9651, MIT license, ~700 LOC, last release Sep 2024). Used only as the parser for the inbound `X-Pelican-Object-Metadata` header. Outbound webhook is plain JSON.

### Migration table name

`metadata_publish_queue`, unprefixed, matching the convention used by other origin-side migrations (`globus_collections`, `oidc_*`). No other component currently uses a table by that name.
