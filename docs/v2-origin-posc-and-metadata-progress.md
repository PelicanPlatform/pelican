# Progress — V2 Origin POSC + Metadata-on-Close

Working notes for the feature described in [`v2-origin-posc-and-metadata.md`](./v2-origin-posc-and-metadata.md). This is a scratchpad that survives between sessions; delete on merge.

## Reference

- Design doc: `docs/v2-origin-posc-and-metadata.md`.
- Pre-PR gap list: `docs/v2-origin-posc-and-metadata-gaps.md` — 17 items (3 P1, 4 P2, 4 P3, 6 P4). All known to me; none disputed by reviewer. Address before merge.
- POSC reference (C++): `/Users/bbockelm/projects/xrootd-s3-http/src/Posc.{cc,hh}`.
- V2 origin entry: `launchers/origin_serve.go::OriginServe()` → `OriginServeFinish()` → `origin_serve.InitializeHandlers()` / `RegisterHandlers()`.
- Filesystem composition: `origin_serve/filesystem.go::aferoFileSystem`, wrapped by `multiuser_fs.go`, `rate_limited_fs.go`, autoMkdir.
- Token signing: `token.NewWLCGToken().CreateToken()`. Example use: `server_utils/server_utils.go:476-485` (advertise token).
- Migrations: `database/origin_migrations/`, Goose-format SQL.
- Scopes: `docs/scopes.yaml` → regenerated to `token_scopes/token_scopes.go` via `generate/scope_generator.go`.

## Plan (in execution order)

| # | Task | Status | |----|-------------------------------------------------------------------|--------| | 1 | Survey codebase + POSC reference | done | | 2 | Design doc + reviewer feedback round 1 incorporated | done | | 3 | Progress doc (this file) | done | | 4 | Add `pelican.metadata` scope to `docs/scopes.yaml` + regen | done | | 5 | Add `Origin.Posc.*` and `Origin.Metadata.*` parameters | done | | 6 | Implement POSC layer for V2 origin | done | | 7 | Implement Structured-Fields parser (input only, header → JSON map)| done | | 8 | Add Goose migration for `metadata_publish_queue` table | done | | 9 | Implement metadata JWT minting (uses event UUID as `jti`) | done | | 10 | Implement publish queue DAO (insert / claimDue / scheduleRetry / delete) | done| | 11 | Implement transactional path (block on first attempt + rollback) | done | | 12 | Implement eventual worker (retry + jitter + skip-if-deleted) | done | | 13 | Wire Prometheus metrics | done | | 14 | Implement admin endpoint (`/api/v1.0/origin_ui/metadata_queue/...`)| done | | 15 | Tests (POSC unit, metadata unit, admin, e2e) | done | | 16 | `go vet ./...` clean + targeted test packages all pass | done | | 17 | Addendum: opaque-blob metadata via multipart upload (design only) | **design done, not implemented** |

## Decisions (reviewer-confirmed)

- POSC layer goes between multiuser and rate-limited layers. Multiuser must remain outermost so temp files inherit the right uid/gid.
- Outgoing webhook is JSON, modeled after GitHub-style webhooks.
  - Body is `{ id, type, timestamp, namespace, object: {...} }`.
  - Custom uploader-supplied fields are inlined into `object`, **not** nested under an `extra` key.
  - Header `X-Pelican-Idempotency-Key` repeats the event UUID. (Non-RFC headers are namespaced with `X-Pelican-` per project convention; the bare `Idempotency-Key` is still a draft.)
  - Header on the way *in* (uploader → origin) is `X-Pelican-Object-Metadata` and uses RFC 9651 Structured Fields.
- We use `github.com/dunglas/httpsfv` for the SFV parser. Input-only; outgoing webhook does not emit SFV.
- DB choice: SQLite via existing Goose migrations.
- Both modes (transactional + eventual) write through the `metadata_publish_queue` table — the table is a write-ahead log shared by both modes. The only difference is whether the close blocks on the first attempt.
- Each event has a UUIDv4 `event_id` (unique-indexed, used as `jti`, used as `X-Pelican-Idempotency-Key`) so receivers can dedupe redelivered events.
- Worker `Stat`s the final object before each retry; if the object is gone it drops the row (`skipped_object_deleted_total`).
- ETag comes from the storage backend; no `HashAlgorithm` config knob.
- Per-export overrides: `Endpoint`, `Mode`, `Enabled`. Concurrency / rate limit / health thresholds remain origin-wide.
- Prometheus metrics enumerated in design §Observability.
- Admin endpoint at `/api/v1.0/origin/metadata_queue` — list / get / delete / retry / `_health`.
- Eventually-consistent queue does not have a "status" column — successful rows are deleted. This keeps the index hot.
- A row that keeps failing keeps retrying; operators manage cleanup via the admin endpoint. Silent dropping is worse than a stuck queue.
- "Multiple origins, one DB" is unsupported (worker race); "one origin, multiple namespaces / exports" is fully supported.

## Things to be careful about

- The Goose migration timestamp must be > the largest existing one (`20260219120000_create_embedded_oidc_tables.sql`). Use `20260429nnnnnn`.
- `token_scopes.go` is generated. Edit `docs/scopes.yaml` then run `go generate ./...` (entry point: `generate/scope_generator.go`).
- The `ResourceScope` parser in `token_scopes` only allows path-suffix on a known whitelist. Adding `pelican.metadata` to that whitelist is required for the scope to round-trip correctly.
- `webdav.FileSystem` does not split Create from Open. The POSC staging-on-write logic needs to live entirely in `OpenFile()`.
- The afero file `Close` is the right hook — but `webdav.Handler` can call `Close` from arbitrary goroutines, so the publish hook must be re-entrant-safe (single-shot per file handle).
- HTTP requests in the close path must respect the request's context for cancellation, but use a separate timeout from the upload context so a slow client doesn't transfer its deadline to the metadata POST.
- The DB insert is on the request hot path. Use a single prepared statement and a one-row insert with explicit `event_id` so we don't pay parse cost per upload.
- The publisher's `Stat`-before-publish must use the same filesystem composition the request used (not the bare afero) so multiuser uid and root-jail constraints still apply.
- The worker pool's claim cursor must `UPDATE next_attempt_at = now + backoff` *before* the HTTP attempt — otherwise a second worker starting between claim and attempt could double-publish (which is fine for correctness but bad for receiver load).
- Don't reset `attempts` to 0 on a worker restart. The retry curve should be continuous across restarts.

## Stuck-points log

(empty — implementation completed in one pass; see the gaps doc for known issues that surfaced on review.)

## Implementation files added

- `origin_serve/posc.go` — POSC FS wrapper + expiry goroutine.
- `origin_serve/posc_test.go` — POSC unit tests (memfs + tempdir).
- `origin_serve/close_notify_fs.go` — fallback wrapper used when metadata is enabled but POSC is not.
- `origin_serve/object_metadata_header.go` — RFC 9651 SFV parser for the inbound `X-Pelican-Object-Metadata` header.
- `origin_serve/object_metadata_header_test.go` — SFV parser tests.
- `origin_serve/metadata_event.go` — in-memory event + JSON wire shape.
- `origin_serve/metadata_queue.go` — GORM-backed DAO over the `metadata_publish_queue` table.
- `origin_serve/metadata_publisher.go` — single-attempt HTTP publisher with JWT minting (`pelican.metadata:/<ns>` scope, event UUID as `jti`).
- `origin_serve/metadata_metrics.go` — Prometheus instruments.
- `origin_serve/metadata_controller.go` — orchestrator (transactional + eventual modes, deletion-aware retries, health gauges).
- `origin_serve/metadata_admin.go` — admin endpoints under `/api/v1.0/origin_ui/metadata_queue/*`.
- `origin_serve/metadata_test.go` — unit tests.
- `origin_serve/metadata_admin_test.go` — admin handler tests.
- `origin_serve/metadata_e2e_test.go` — POSC + metadata end-to-end.
- `database/origin_migrations/20260429120000_create_metadata_publish_queue.sql` — Goose migration.

## Implementation files modified

- `docs/scopes.yaml` — added `pelican.metadata`.
- `docs/parameters.yaml` — added `Origin.Posc.*` + `Origin.Metadata.*`.
- `config/resources/defaults.yaml` — defaults for new params.
- `generate/scope_generator.go` — pathable-scope whitelist.
- `token_scopes/token_scopes.go` — generated.
- `param/parameters.go`, `param/parameters_struct.go`, `swagger/pelican-swagger.yaml`, `web_ui/.../parameters.json` — regenerated artifacts.
- `server_utils/origin.go` — added `OriginExportMetadata` per-export override block.
- `origin_serve/handlers.go` — wired POSC + metadata controller + `X-Pelican-Object-Metadata` header parsing into the request path.
- `origin/origin_ui.go` — registered the metadata admin endpoints.

## Verified

- `go build ./...` clean.
- `go vet ./...` clean.
- `go test ./origin_serve/...` passes (~14s).
- Targeted runs of `./token_scopes`, `./param`, `./server_utils`, `./origin`, `./database`, `./launchers`, `./token` all pass.

## Next session

If revisiting, the natural follow-ups are:

- A web UI page that consumes `/_health` and the queue listing.
- Optional TLS client-cert auth alongside JWT.
- A "force-publish-now" admin verb that bypasses the rate limit for high-priority namespaces.
