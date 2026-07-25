# `pelican object get` / `put`: source/destination semantics

This note captures how the client library and CLI handle the cartesian product of {single vs. multiple sources} × {file vs. collection} × {recursive vs. not} for downloads (`get`) and uploads (`put`). It exists so future contributors have a single place to look when reasoning about "did I break someone's script?" and so the regression tests can be justified against a written contract instead of a Slack thread from six months ago.

If you change any of the behaviors below, please:

1. Update this document,
1. Update `cmd/object_transfer_semantics_test.go` (which asserts every row), and
1. Note the change in the PR description as an intentional break.

## Terminology

- **Collection** — a "directory" in the pelican namespace. The wire format is WebDAV; the storage backend calls them collections, so we do too. On the filesystem side, "directory" is synonymous.
- **Object** — a "file" in the pelican namespace (a leaf).
- **Recursive** — `--recursive` (`-r`) on the CLI, or the `recursive` bool parameter on `client.DoGet` / `client.DoPut`. Also settable via the `?recursive` query parameter on the URL.
- **Container target** — a destination path that names a container: an existing local directory (for `get`), or an existing remote collection (for `put`). For **non-recursive** single-object transfers, a container target triggers *filename inference* (source basename joined onto the destination). For **recursive** transfers, entries land **flat** under the destination — the source basename is NOT interposed. This follows the design decision recorded in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638) for `pelican object sync` (rows 2, 3, and 7 of the sync table): recursive transfers are `rsync`-flavored (`rsync -a src/ dst/`), not `cp -r`-flavored.

## `pelican object get REMOTE [REMOTE...] LOCAL`

Downloads a single object or a collection tree from the federation to the local filesystem.

### Single source, `--recursive=false`

| #   | Remote source is | Local destination        | Behavior                                                                                                                                                                                                                                                                                                         |
| --- | ---------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G1  | an object        | an existing regular file | Overwrite the local file (destination string is a filename).                                                                                                                                                                                                                                                     |
| G2  | an object        | an existing directory    | Filename inferred: object written to `LOCAL/basename(REMOTE)`.                                                                                                                                                                                                                                                   |
| G3  | an object        | a non-existent path      | Create the file at that path (destination string is a filename).                                                                                                                                                                                                                                                 |
| G4  | a collection     | existing directory       | Client library error: `remote object %q is a collection but recursive is not enabled`. Symmetric with the put-side directory guard P4. The library errors here rather than silently GET-ing the collection URL and writing whatever the origin serves for that GET into a local file named after the collection. |

Inference (row G2) and the G4 guard both happen inside `client.DoGet`, not at the CLI level. Callers of the library see them too.

### Single source, `--recursive=true`

| #   | Remote source is | Local destination     | Behavior                                                                                                                                                                                                                                 |
| --- | ---------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G5  | a collection     | an existing directory | Entries land **flat** under `LOCAL/…`. The collection basename is NOT interposed. Matches `rsync -a remote/ local/` and rows 2 and 3 of the sync design in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638). |
| G6  | a collection     | a non-existent path   | Destination path is created and entries land directly under it. Same flat rule as G5.                                                                                                                                                    |
| G7  | an object        | any                   | Effectively a single-item recursive walk — behaves like G1/G2/G3 for that one object.                                                                                                                                                    |

The G4 check does need to know whether the remote source is a collection, so `DoGet` issues a `client.DoStat` in the non-recursive container-target branch. The recursive path skips that stat entirely — every recursive `DoGet` (including every `pelican object sync` call) therefore pays no extra round trip.

How the non-recursive G4 stat handles caches: the stat routes through the same director query as the GET, so it can land on a cache endpoint — and XRootD caches return **409 Conflict** for `PROPFIND` on a collection (they don't serve directory listings). `client.statHttp` recognises the 409, wraps an `errStatOnCollectionAtCache` sentinel, and — when no host succeeded and at least one returned 409 — retries via the origin's `CollectionsUrl` (which does serve listings). That retry is bounded: the internal `statHttpImpl(alreadyFellBack bool)` runs at most one fallback level, so the two fallback branches (collections-only → default, and default-with-409 → collections-only) cannot ping-pong.

Stat errors are handled softly. `ErrObjectNotFound` from the source is left to the transfer machinery to surface with its own error; any *other* stat failure is propagated so the caller doesn't silently degrade G4 to G2 with the wrong local layout.

### Multiple sources

Only single-destination is supported: the last positional argument is the destination, everything before it is a source. When `len(sources) > 1`, `cmd/object_get.go` inspects the local destination up-front:

| #   | Local destination  | Behavior                                                                                     |
| --- | ------------------ | -------------------------------------------------------------------------------------------- |
| G8  | Existing directory | Each source individually goes through the single-source rules (G2 style: filename inferred). |
| G9  | Non-existent       | Fatal CLI error: `Destination does not exist`.                                               |
| G10 | Regular file       | Fatal CLI error: `Destination is not a directory`.                                           |

The multi-source pre-check is a CLI-level guard; the library (`client.DoGet`) is called once per source.

### Downstream callers

The G4 error lives in `client.DoGet` and applies to every caller of the library, including `cmd/object_sync.go` and `client_agent/transfer_manager.go`. In practice this only affects callers that were previously invoking a non-recursive get against what turned out to be a collection — a caller in that shape was silently corrupting output before, so the new error is uncovering a latent bug rather than breaking a working code path.

The G5/G6 recursive-get layout is unchanged relative to pre-PR `main`: entries land flat under the local destination. `pelican object sync <remote-coll> <local-dir>` and the client-agent's download path continue to land entries at `<local-dir>/…` — no basename interposition. This preserves the behaviour agreed in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638).

## `pelican object put LOCAL [LOCAL...] REMOTE`

Uploads a single object or a directory tree from the local filesystem to the federation.

### Single source, `--recursive=false`

| #   | Local source is | Remote destination            | Behavior                                                                                                                                                      |
| --- | --------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1  | a file          | a non-existent remote path    | Upload as-is (destination is treated as the target object URL).                                                                                               |
| P2  | a file          | an existing remote object     | `remote object already exists, upload aborted` (write-once semantic enforced by the origin).                                                                  |
| P3  | a file          | an existing remote collection | Filename inferred by the CLI (`cmd/object_put.go` pre-flights the destination with `client.DoStat`): uploaded to `REMOTE/basename(LOCAL)`. Symmetric with G2. |
| P4  | a directory     | any                           | Client library error: `local object %q is a directory but recursive is not enabled`.                                                                          |

### Single source, `--recursive=true`

| #   | Local source is | Remote destination            | Behavior                                                                                                                                                                                                                                                                                                                                  |
| --- | --------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P5  | a directory     | a non-existent remote path    | Tree uploaded; remote collection created at `REMOTE` and its contents populated.                                                                                                                                                                                                                                                          |
| P6  | a directory     | an existing remote collection | Tree contents uploaded **flat** into `REMOTE/…`. The local directory's basename is NOT interposed. Symmetric with G5 and matches row 7 of the sync design in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638). The CLI's filename-inference pre-flight is skipped for recursive puts to preserve this layout. |
| P7  | a file          | any                           | Recursive walk of a trivial tree; behaves like the single-file cases above for that one entry.                                                                                                                                                                                                                                            |

### Multiple sources

Same shape as get: the last positional argument is the remote destination. `cmd/object_put.go` pre-flights the destination with a single `client.DoStat` outside the source loop, then rewrites the per-file destination as needed:

| #   | Remote destination                                             | Behavior                                                                                                                                                                                                                                                                                                        |
| --- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P8  | Existing remote collection                                     | Each source uploaded to `REMOTE/basename(LOCAL_i)` (`cp`-style — no fatal per-source `already exists` on the second upload).                                                                                                                                                                                    |
| P9  | Non-existent remote path (`len(sources) > 1`)                  | Treated as a would-be collection; each source uploaded to `REMOTE/basename(LOCAL_i)`.                                                                                                                                                                                                                           |
| P10 | Existing remote object OR stat fails with a non-notFound error | Pre-flight is soft: stat failure is logged at debug and each source is passed through with the destination as-is. This preserves uploads on namespaces with write-only tokens or no `listings` capability, at the cost of surfacing the "already exists" per-source error at P2 semantics for existing objects. |

The pre-flight uses `client.DoStat`, which does **not** build a `TransferEngine` (`DoStat` was previously constructing a full engine on every call and shutting it down without ever using it; the setup was pure waste and is gone).

## Design principles the matrix follows

- **`get` and `put` are symmetric for object/collection type checks.** The library catches the "source type mismatched with recursive flag" cases (G4 / P4); the CLI catches "multi-source needs a container destination" (G8-G10 / P8-P10).
- **Non-recursive single-object transfers into a container-typed destination infer the filename.** G2 and P3 both follow `cp` / `scp` for the "singular object into an already existing container (that tab-completion filled in for me)" gesture explicitly endorsed in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638).
- **Recursive transfers into a container are `rsync`-flavored, not `cp -r`-flavored.** G5 and P6 both lay entries flat under the destination — the source basename is NOT interposed. This is the design decision recorded in discussion #1638 for `pelican object sync`; `get -r` / `put -r` inherit the same rule so that `object sync` and library callers (`client_agent`, embedders) see one consistent layout.
- **The library never invents container creation semantics that could surprise a scripting user.** `?recursive` and `--recursive` are the explicit opt-in for walking or expanding directory-typed sources; when absent, a directory source is a client-side error rather than a silent success or a strange partial upload.
- **Pre-flight stats fail soft on the put side, hard on the get side.** For put, stat failures don't imply the put will fail (write-only tokens, no `listings`), so the pre-flight logs at debug and falls through. For non-recursive get, non-`ErrObjectNotFound` stat failures propagate — the G4 decision cannot be made without knowing whether the source is a collection. Recursive get skips the stat entirely (no G4 check needed since the walker handles both shapes).

## Where the code lives

- `client.DoGet` (in `client/main.go`) — library-level get. The container-target branch stats the source only on the non-recursive path (for the G2/G4 decision) and leaves the recursive path (G5/G6) to the walker with the destination unchanged.
- `client.DoStat` (in `client/main.go`) — library-level stat. Uses `getDirectorInfoForPath` + `statHttp` directly; no `TransferEngine` is built.
- `client.statHttp` / `statHttpImpl` (in `client/handle_http.go`) — WebDAV `PROPFIND` with the bounded collections-only fallback described in the G4 note above.
- `client.DoPut` (in `client/main.go`) — library-level put, including the P4 "local source is a directory but recursive is false" guard.
- `cmd/object_get.go` — CLI wrapper for get. Adds the multi-source destination checks (rows G8-G10).
- `cmd/object_put.go` — CLI wrapper for put. Pre-flights the destination with a single `client.DoStat` outside the source loop, then rewrites the per-file destination for P3/P8/P9 only. Recursive uploads (`isRecursive=true`) skip the rewrite so P6 stays flat. Stat failures are soft (row P10).

## Where the tests live

`cmd/object_transfer_semantics_test.go` runs one POSIXv2-backed federation (no XRootD dependency) and asserts every row in the table above. The tests are structured as subtests named after the row IDs (`G1`, `P3`, ...) so a failure points directly at a documented expectation.
