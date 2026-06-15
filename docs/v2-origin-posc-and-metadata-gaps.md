# V2 Origin POSC + Metadata — Pre-PR Gap List

Status: **resolved** — every P1/P2/P3 item below has been addressed in code; P4 items are documented in the design doc's [Deferred / out-of-scope](./v2-origin-posc-and-metadata.md#deferred--out-of-scope-pr-time-documentation) section. This file is retained as a record of what surfaced on review and how each was closed.

Items are grouped by priority. P1 = will misbehave under realistic production traffic; P2 = correctness gap on a less-common path; P3 = test coverage gap that hid one of the above; P4 = reviewer fairness or operator documentation.

---

## P1 — production-blocking

### 1. Close-hook path is export-relative, not federation-relative

**Where:** [`origin_serve/metadata_controller.go`](../origin_serve/metadata_controller.go) in `CommitEventFromCloseHook` (the closure constructed for the POSC `SetCloseHook` registration).

**What's wrong:** The stdlib `webdav.Handler` strips its configured `Prefix` (the federation prefix) before calling `fs.OpenFile(ctx, name, …)`. So inside the POSC layer, `finalPath` for a `PUT /exp/data/run99.dat` request is `/data/run99.dat`, not `/exp/data/run99.dat`. My close hook emits the export-relative path verbatim into the webhook's `object.path`, which contradicts the federation-rooted shape promised in the design doc.

**Why our tests miss it:** `metadata_e2e_test.go` calls `posc.OpenFile(ctx, "/exp/data/run99.dat", …)` directly, bypassing the webdav handler's prefix stripping.

**Fix:** Two options:

1. In `CommitEventFromCloseHook`, prepend the namespace before building the event:
   ```go
   full := path.Clean(path.Join(namespace, finalPath))
   event := NewObjectCommitEvent(namespace, full, size, etag, mtime, custom)
   ```
1. Or change the e2e test to drive through a real `webdav.Handler` wired up with the export's `Prefix`, so the bug surfaces under test.

Do both. (1) is the actual fix; (2) prevents regression.

**Resolution (closed):** Both. The fix lives in a new `joinFederationPath` helper called from `CommitEventFromCloseHook`, covered by `TestJoinFederationPath`. A new `TestE2EWebdavHandler_PathIsFederationRooted` drives a real `webdav.Handler` with `Prefix="/exp"` and asserts the receiver sees `/exp/data/run99.dat` in the JSON body.

---

### 2. Worker `Stat` for skip-if-deleted goes through the multiuser layer

**Where:** [`origin_serve/handlers.go`](../origin_serve/handlers.go) construction of `metadataControllerOptions.FilesystemForExists` (it returns `webdavHandlers[ns].FileSystem`, which is the *outermost* wrapper).

**What's wrong:** The metadata-publish workers run in goroutines that have no `userInfo` on their context. When the worker calls `Stat(ctx, path)` to decide whether to skip-if-deleted, the multiuser layer (when enabled) attempts to map a missing user to a uid — best case it falls back to the origin process identity; worst case it errors out and we incorrectly conclude the object is gone, dropping a valid pending row.

**Fix:** Stash a *bypass-multiuser* handle when constructing the controller and use that for the worker's `Stat`. The cleanest seam is to capture the pre-multiuser `webdav.FileSystem` at the same time POSC is built and pass it down via `metadataControllerOptions`:

```go
existsFS := fs // captured immediately after the POSC layer is composed
// later …
fs, err = newMultiuserFileSystem(ctx, fs, …)
// pass existsFS to metadataControllerOptions.FilesystemForExists
```

**Resolution (closed):** `InitializeHandlers` now keeps a `preMultiuserFs` map keyed by federation prefix and populates it between the POSC wrap and the multiuser wrap. `metadataControllerOptions.FilesystemForExists` reads from that map, so the worker's skip-if-deleted `Stat` runs against the layer below multiuser.

---

### 3. Transactional rollback doesn't actually unlink the committed object

**Where:** [`origin_serve/posc.go`](../origin_serve/posc.go) — the `closeHook` invocation at the end of `poscFile.Close`.

**What's wrong:** By the time the close hook runs, POSC has already renamed the staging file into `finalPath`. If the hook returns an error (transactional publish failed), `Close` propagates the error to the caller — but the object stays on disk. The design doc explicitly says "the object is best-effort removed" in transactional rollback, and `metadataRollbackFailed_total` is wired up specifically to count the failures of *that* removal. As-shipped, the metric is unreachable.

**Fix:** Inside `poscFile.Close`, after the rename succeeds and the close hook returns non-nil:

```go
if err := f.fs.closeHook(f.ctx, final, info); err != nil {
    if rmErr := f.fs.inner.RemoveAll(f.ctx, final); rmErr != nil {
        // surface to metrics; controller can't, the layer below it must
        log.Warnf("POSC: rollback delete of %q failed: %v", final, rmErr)
        metadataRollbackFailed.WithLabelValues(<ns>).Inc()
    }
    return err
}
```

The `<ns>` is awkward at the POSC layer; pass it in via a closure parameter or add a tiny `MetricsHooks.IncRollbackFailure(ns string)`.

**Resolution (closed):** `poscFile.Close` now `RemoveAll`s the final path when `closeHook` returns non-nil. `PoscMetricsHooks` gained an `IncRollbackFailed` callback that the metadata package's `poscMetricsHooks(namespace)` factory wires to `metadataRollbackFailed.WithLabelValues(namespace)`. Covered by `TestPoscCloseHookFailureRollsBackFinal`, `TestPoscRollbackFailureFiresMetric`, and the updated `TestE2ETransactional_RollbackOn5xx`.

---

## P2 — correctness gaps on the long tail

### 4. POSC keepalive is a no-op

**Where:** [`origin_serve/posc.go`](../origin_serve/posc.go) `poscFile.touchIfStale`.

**What's wrong:** I `Stat` the staging file and call it good. `Stat` does not refresh the file's mtime — the C++ reference uses `Fctl_utimes`. The whole point of `touchOpenFiles` is to bump active upload mtimes so the expiry goroutine doesn't reap them. Today, an upload taking longer than `Origin.Posc.FileTimeout` (1h default) that pauses writing for ≥ `KeepaliveInterval` will be eaten.

**Fix:** Use `afero.Fs.Chtimes(name, now, now)` (every backend we care about implements it). Wrap with try-and-log: on failure, just log debug — the next write will keep the mtime fresh on its own.

```go
now := time.Now()
if chtFs, ok := f.fs.inner.(interface {
    Chtimes(string, time.Time, time.Time) error
}); ok {
    _ = chtFs.Chtimes(tempPath, now, now)
}
```

(Note: `webdav.FileSystem` doesn't expose Chtimes; we'd need to either plumb it through or hold a reference to the underlying `afero.Fs` from the POSC ctor.)

**Resolution (closed):** `poscFileSystem` gained an optional `touchFS` sibling (`afero.Fs`) plus a `SetTouchFS` setter. `InitializeHandlers` hands it `autoFs` (the underlying afero layer just below the webdav-adapter); `touchIfStale` calls `Chtimes(path, now, now)`. Covered by `TestPoscKeepaliveUpdatesMtime`.

---

### 5. Original-mode chmod was dropped

**Where:** [`origin_serve/posc.go`](../origin_serve/posc.go) `poscFile.Close` — there's a comment "We deliberately omit a Chmod step" that's wrong.

**What's wrong:** Staging files are opened with mode `0600`. After the rename, the final object inherits that mode. In non-multiuser deployments where the origin process is the only writer, every uploaded object lands at `0600` (other users can't read), regardless of what the client requested. The C++ reference chmods to the originally-requested `Mode` between Close and Rename.

**Fix:** Easiest path: open the staging file with the requested `perm` directly instead of `0600`. The reason the C++ uses 0600 is to make the file unreadable while it's mid-upload, but in our deployment model that's already enforced by the staging directory being inside `.pelican-posc/<user>/` with `0700`. So we can just use `perm` (falling back to `0644` if zero).

**Resolution (closed):** Implemented as described. POSC also now ensures the *final* path's parent directory exists before staging (an additional bug found while writing the perm test — without this fix, the rename would fail with ENOENT for any non-existing subdirectory). Covered by `TestPoscFinalPermMatchesRequested`.

---

### 6. ETag is computed by the origin, not provided by the backend

**Where:** [`origin_serve/metadata_controller.go`](../origin_serve/metadata_controller.go) `computeFallbackETag`.

**What's wrong:** The user explicitly asked for "the etag provided by the underlying origin backend." `computeFallbackETag` synthesizes `"<size>-<modtime>"` from a `FileInfo` — that's the origin computing an ETag, not the backend. For POSIXv2 + the stdlib `golang.org/x/net/webdav` package this happens to match what the WebDAV layer would emit on a GET response, but the contract was "use the backend's." For S3 / SSH backends (out of scope for this PR but in scope for the V2 origin) the real ETag would come from the backend protocol.

**Fix:** Either

1. Plumb an `ETag()` accessor through `webdav.FileSystem` / `OriginBackend` so the close hook reads it from the backend, and fall back to the size+mtime synthesis only when the backend declines, **or**
1. Acknowledge in the design doc that for POSIXv2 the origin *is* the backend and the synthesis is the canonical answer; revisit when S3/SSH grow POSC support.

Either is fine; pick one and document.

**Resolution (closed):** Did (1). Added a `backendETager` interface and a `backendETag(info, size, mtime)` helper that prefers `info.ETag(ctx)` when implemented and falls back to `synthesizeETag` otherwise. The synthesized form now matches the WebDAV-default `"<hex(mtime)><hex(size)>"` so a receiver who saw the object via GET sees the same ETag in the commit webhook. Covered by `TestBackendETagPrefersBackendValue` and `TestBackendETagFallsBackToSynthesized`.

---

### 7. POSC dropped the `oss.asize` size-verification step

**Where:** N/A — feature absent. The C++ reference checks, when `oss.asize` was set on Open, that the staged file's size matches before renaming and EIOs otherwise.

**What's wrong:** WebDAV PUT requests carry `Content-Length`. Today we'd accept and rename a short PUT silently. Low-impact (transport errors normally surface as a different failure first) but a guarantee the C++ reference offered that we don't.

**Fix:** Read `Content-Length` off the request in `extractObjectMetadataFromRequest`-style middleware, stash on context, and check in `poscFile.Close`. Not blocking for v1; document and file.

**Resolution (closed):** Implemented exactly as proposed. New `withExpectedContentLength` / `expectedContentLengthFromContext` context helpers; `extractObjectMetadataFromRequest` populates them on PUTs with positive `Content-Length`; `poscFile.Close` rejects on mismatch with EIO-style error and removes the staged file. Covered by `TestPoscContentLengthMismatchAborts` and `TestPoscContentLengthMatchCommits`.

---

## P3 — test gaps that hid the above

### 8. E2E tests bypass `webdav.Handler`

**Where:** [`origin_serve/metadata_e2e_test.go`](../origin_serve/metadata_e2e_test.go).

**What's wrong:** The tests call `posc.OpenFile` directly. The whole class of bugs caused by `webdav.Handler.Prefix` stripping (P1.1) is invisible.

**Fix:** Add a sibling test that builds a `webdav.Handler{FileSystem: posc, Prefix: "/exp"}`, wraps it in `httptest.NewServer`, and `PUT`s real bytes into it. The receiver assertion stays the same.

**Resolution (closed):** `TestE2EWebdavHandler_PathIsFederationRooted` does exactly this. It also exercises the request middleware and the custom-fields-from-header plumbing end to end.

---

### 9. In-memory sqlite shares cache across tests

**Where:** [`origin_serve/metadata_test.go`](../origin_serve/metadata_test.go) `newTestDB` — uses `file::memory:?cache=shared`, which is a single process-global database.

**What's wrong:** The current implementation depends on serial test execution and `t.Cleanup` table-drops. Anything that adds `t.Parallel()` or imports the helper into a test that *does* run parallel will see cross-contamination.

**Fix:** Generate a unique DSN per test:

```go
dsn := fmt.Sprintf("file:test%d_%s?mode=memory&cache=shared", os.Getpid(), t.Name())
```

The unique name makes the cache per-test; the cleanup is automatic when the last connection closes.

**Resolution (closed):** `newTestDB` now builds a per-test DSN combining `t.Name()` (slashes sanitized) and `time.Now().UnixNano()`, sets `MaxOpenConns(1)`, and registers a `t.Cleanup` that closes the underlying `*sql.DB` so the in-memory cache is torn down.

---

### 10. No test for `extractObjectMetadataFromRequest` middleware

**Where:** [`origin_serve/metadata_controller.go`](../origin_serve/metadata_controller.go).

**What's wrong:** This function is the *only* path that puts custom fields onto the close-hook's ctx. A breakage here would silently disappear the entire X-Pelican-Object-Metadata feature without any test failure. It's untested.

**Fix:** Add a two-line test against a synthetic `*http.Request`:

```go
req := httptest.NewRequest("PUT", "/x", nil)
req.Header.Set("X-Pelican-Object-Metadata", `experiment="atlas"`)
req2 := extractObjectMetadataFromRequest(req)
got := objectMetadataFromContext(req2.Context())
if got["experiment"] != "atlas" { … }
```

**Resolution (closed):** Four direct tests added:

- `TestExtractObjectMetadataFromRequest_HeaderAndContentLength`
- `TestExtractObjectMetadataFromRequest_NoHeaderNoContentLength`
- `TestExtractObjectMetadataFromRequest_MalformedHeaderStillAllowsRequest`
- `TestExtractObjectMetadataFromRequest_GetIgnoresContentLength`

---

### 11. No POSC + multiuser interaction test

**Where:** absent.

**What's wrong:** The design's whole reason for placing POSC *beneath* multiuser is so staging files inherit the request user's uid/gid. Nothing in the test suite verifies that property. If a future refactor reorders the wrapping, no test fails.

**Fix:** A small Linux-only integration test that runs the full chain (osRootFs → autoFs → poscFs → multiuserFs), `PUT`s as a synthetic user, and asserts the final on-disk file has that user's uid via `os.Stat`. Gate on `runtime.GOOS == "linux"` and `config.HasMultiuserCaps()`.

**Resolution (closed):** New `posc_multiuser_privileged_test.go` behind `//go:build linux` running `TestPrivileged_PoscBeneathMultiuser_OwnershipFollowsUser`. Uses the existing `test_utils.SkipUnlessPrivileged` / `SkipUnlessTestUsers` gates so it runs in the Pelican dev container and is skipped everywhere else.

---

## P4 — reviewer fairness & operator docs

These items did not require code changes; each is documented either in the design doc's [Deferred / out-of-scope](./v2-origin-posc-and-metadata.md#deferred--out-of-scope-pr-time-documentation) section, in the PR description, or both.

### 12. New dependency: `github.com/dunglas/httpsfv`

Call out in the PR description. Small (~700 LOC), MIT, implements RFC 8941 / RFC 9651, last release Sep 2024.

**Resolution (documented):** Listed in the design doc's Deferred section under "New runtime dependency." Repeat in the PR description.

### 13. Per-export overrides cover Metadata only, not POSC

POSC settings (`Prefix`, `FileTimeout`, `KeepaliveInterval`) are origin-wide. Design doc says so but the PR description should call this out so reviewers don't assume parity with `Origin.Metadata.*`.

**Resolution (documented):** Spelled out in the design doc's Deferred section under "Per-export overrides apply to the metadata feature only."

### 14. Web UI page is deferred

Admin HTTP endpoints exist; no UI consumes them yet. Progress doc lists this as a follow-up — the PR description should match.

**Resolution (documented):** Spelled out in the design doc's Deferred section under "No web UI consumer yet."

### 15. No startup-time reconciliation

The design names two crash windows: (a) rename → INSERT and (b) INSERT → first publish. We handle (b) (rows survive restarts and the worker drains them); we don't detect (a) at all. A startup scan that walks the filesystem and the queue and warns on mismatches would close this. Not blocking for v1 — file as a follow-up.

**Resolution (documented):** Spelled out in the design doc's Deferred section under "No startup-time reconciliation against the filesystem."

### 16. No fsync between rename and reply

Matches POSIX defaults and the C++ POSC reference. Power loss after the 2xx but before the kernel flushes can lose the rename. Worth explicit out-of-scope language in the design doc.

**Resolution (documented):** Spelled out in the design doc's Deferred section under "No fsync between rename and reply."

### 17. Table name `metadata_publish_queue` is unprefixed

Other origin tables in `database/origin_migrations/` are also unprefixed (`globus_collections`, `oidc_*`). Consistent — but worth a quick grep before merge to confirm no other component is planning a table by the same name.

**Resolution (documented):** Spelled out in the design doc's Deferred section under "Migration table name."

---

## How this list was generated

I read the in-tree code with fresh eyes after declaring the implementation done, and looked specifically for:

- Things that work in unit tests but would misbehave in the real HTTP request path (P1.1, P3.8).
- Behaviors the design promised but the implementation silently dropped (P1.3, P2.4, P2.5, P2.7).
- Subsystem-boundary mistakes — the worker accidentally inheriting the wrong layer's identity (P1.2).
- Tests that assert what I implemented rather than what I claimed to implement (P3.10, P3.11).
- Documentation gaps that would frustrate a reviewer (P4.\*).

If a future implementer adds new items here, please follow the "where / what's wrong / fix" format so each item stays actionable.
