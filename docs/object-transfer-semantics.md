# `pelican object get` / `put`: source/destination semantics

This note captures how the client library and CLI handle the cartesian product of {single vs. multiple sources} × {file vs. collection} × {recursive vs. not} for downloads (`get`) and uploads (`put`). It exists so future contributors have a single place to look when reasoning about "did I break someone's script?", and so the regression tests have a written contract to assert against.

If you change any of the behaviors below, please:

1. Update this document,
1. Update the corresponding test (see [Where the tests live](#where-the-tests-live)), and
1. Note the change in the PR description as an intentional break.

## Terminology

- **Collection** — a "directory" in the pelican namespace. The wire format is WebDAV; the storage backend calls them collections, so we do too. On the filesystem side, "directory" is synonymous.
- **Object** — a "file" in the pelican namespace (a leaf).
- **Recursive** — `--recursive` (`-r`) on the CLI, or the `recursive` bool parameter on `client.DoGet` / `client.DoPut`. Also settable via the `?recursive` query parameter on the URL.
- **Container target** — a destination path that names a container: an existing local directory (for `get`), or an existing remote collection (for `put`). For **non-recursive** single-object transfers, a container target triggers *filename inference* (source basename joined onto the destination). For **recursive** transfers, entries land **flat** under the destination — the source basename is NOT interposed. This follows the layout agreed for `pelican object sync` in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638), where syncing a collection into a local directory puts its entries directly in that directory, and syncing a local directory to a namespace prefix puts its files directly under that prefix: recursive transfers are `rsync`-flavored (`rsync -a src/ dst/`), not `cp -r`-flavored.

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

| #   | Remote source is | Local destination     | Behavior                                                                                                                                                                                                                        |
| --- | ---------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G5  | a collection     | an existing directory | Entries land **flat** under `LOCAL/…`. The collection basename is NOT interposed. Matches `rsync -a remote/ local/` and the sync layout agreed in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638). |
| G6  | a collection     | a non-existent path   | Destination path is created and entries land directly under it. Same flat rule as G5.                                                                                                                                           |
| G7  | an object        | any                   | Effectively a single-item recursive walk — behaves like G1/G2/G3 for that one object.                                                                                                                                           |

The G4 check does need to know whether the remote source is a collection, so `DoGet` issues a `client.DoStat` in the non-recursive container-target branch. The recursive path skips that stat entirely — every recursive `DoGet` (including every `pelican object sync` call) therefore pays no extra round trip.

How the non-recursive G4 stat handles caches: the stat routes through the same director query as the GET, so it can land on a cache endpoint — and XRootD caches return **409 Conflict** for `PROPFIND` on a collection (they don't serve directory listings). `client.statHttp` recognises the 409, wraps an `errStatOnCollectionAtCache` sentinel, and — when no host succeeded and at least one returned 409 — retries via the origin's `CollectionsUrl` (which does serve listings). That retry is bounded: the internal `statHttpImpl(alreadyFellBack bool)` runs at most one fallback level, so the two fallback branches (collections-only → default, and default-with-409 → collections-only) cannot ping-pong.

Stat errors: `ErrObjectNotFound` is left to the transfer machinery to surface with its own error. Every *other* stat failure is propagated, which means a non-recursive get into an existing local directory now fails against a source the client cannot stat at all — a namespace without `listings`, or an origin that refuses `PROPFIND`. That is deliberate: without knowing whether the source is a collection, the alternative is silently applying the G2 layout to a G4 source and writing a directory listing into a file. `get REMOTE ./file.txt` (a destination that is not an existing directory) does not enter this branch and is unaffected.

### Multiple sources

Only single-destination is supported: the last positional argument is the destination, everything before it is a source. When `len(sources) > 1`, `cmd/object_get.go` inspects the local destination up-front:

| #   | Local destination  | Behavior                                                                                     |
| --- | ------------------ | -------------------------------------------------------------------------------------------- |
| G8  | Existing directory | Each source individually goes through the single-source rules (G2 style: filename inferred). |
| G9  | Non-existent       | Fatal CLI error: `Destination does not exist`.                                               |
| G10 | Regular file       | Fatal CLI error: `Destination is not a directory`.                                           |

The multi-source pre-check is a CLI-level guard; the library (`client.DoGet`) is called once per source.

### Downstream callers

The G4 error lives in `client.DoGet` and applies to every caller of the library, including `cmd/object_sync.go` and `client_agent/transfer_manager.go`. A caller performing a non-recursive get of a collection into an existing directory now receives an error where it previously received a local file containing the WebDAV listing.

The G5/G6 recursive-get layout is what `pelican object sync <remote-coll> <local-dir>` and the client-agent download path depend on: entries land at `<local-dir>/…` with no basename interposition, per discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638). The G5 and P6 subtests each carry an explicit "must NOT nest under basename" assertion so a future `cp -r`-flavored refactor cannot quietly change it.

## `pelican object put LOCAL [LOCAL...] REMOTE`

Uploads a single object or a directory tree from the local filesystem to the federation.

### Single source, `--recursive=false`

| #      | Local source is | Remote destination            | Behavior                                                                                                                                                                                                           |
| ------ | --------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| P1     | a file          | a non-existent remote path    | Upload as-is (destination is treated as the target object URL).                                                                                                                                                    |
| P2     | a file          | an existing remote object     | `remote object already exists, upload aborted` (write-once semantic enforced by the origin).                                                                                                                       |
| P3-cli | a file          | an existing remote collection | Object name inferred by the CLI (`cmd/object_put.go` pre-flights the destination with `client.DoStat`): uploaded to `REMOTE/basename(LOCAL)`. Symmetric with G2.                                                   |
| P3-lib | a file          | an existing remote collection | `client.DoPut` infers nothing and surfaces the origin's `already exists`. Library callers get an error rather than a silent rewrite of the path they passed; the inference is a CLI affordance, not a library one. |
| P4     | a directory     | any                           | Client library error: `local object %q is a directory but recursive is not enabled`.                                                                                                                               |

### Single source, `--recursive=true`

| #   | Local source is | Remote destination            | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --- | --------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P5  | a directory     | a non-existent remote path    | Tree uploaded; remote collection created at `REMOTE` and its contents populated.                                                                                                                                                                                                                                                                                                                                           |
| P6  | a directory     | an existing remote collection | Tree contents uploaded **flat** into `REMOTE/…`. The local directory's basename is NOT interposed. Symmetric with G5 and matching the sync layout agreed in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638). The CLI skips its object-name inference for recursive puts to preserve this layout, and reads recursion from `?recursive` as well as from `-r` so both spellings take that path. |
| P7  | a file          | any                           | Recursive walk of a trivial tree; behaves like the single-file cases above for that one entry.                                                                                                                                                                                                                                                                                                                             |

### Multiple sources

Same shape as get: the last positional argument is the remote destination. `cmd/object_put.go` pre-flights the destination with a single `client.DoStat` outside the source loop, then rewrites the per-file destination as needed:

| #   | Remote destination                                             | Behavior                                                                                                                                                                                                                                                                                         |
| --- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| P8  | Existing remote collection                                     | Each source uploaded to `REMOTE/basename(LOCAL_i)` (`cp`-style — no fatal per-source `already exists` on the second upload).                                                                                                                                                                     |
| P9  | Non-existent remote path (`len(sources) > 1`)                  | Treated as a would-be collection; each source uploaded to `REMOTE/basename(LOCAL_i)`. Several sources mean the destination is a container whether or not the pre-flight ran, so `--dry-run` prints the same paths a real run would use.                                                          |
| P10 | Existing remote object OR stat fails with a non-notFound error | Pre-flight is soft: the failure is logged at debug and each source is passed through with the destination as-is. Uploads keep working on namespaces the stat cannot answer for, at the cost of `already exists` (P2) for a destination that is really a collection there — see the caveat below. |

The pre-flight is a convenience, so it is skipped whenever it cannot change the outcome: recursive uploads (P6 is flat regardless), `--pack` requests (the archive is named from the source), a destination that does not parse (`client.DoPut` reports that), and `--dry-run` (which must not touch the network).

It also runs with `client.WithStatUploadDestination(true)` and `client.WithAcquireToken(false)`. The first asks the Director with `PUT`, so the stat goes to origins that accept the write rather than to caches — a cache cannot answer for a namespace that grants writes without reads, and a GET-flavored query would hand the caller's write credential to every cache in the response. The second keeps the pre-flight from ever blocking a scripted upload on an interactive token acquisition.

**Caveat:** a namespace that grants writes but no `listings` cannot answer the pre-flight at all, so `put ./file.txt REMOTE_COLLECTION` still fails there with `already exists` (row P2). Row P3-cli holds only where the destination can be stat'ed.

## Design principles the matrix follows

- **`get` and `put` are symmetric for object/collection type checks.** The library catches the "source type mismatched with recursive flag" cases (G4 / P4); the CLI catches "multi-source needs a container destination" (G8-G10 / P8-P10).
- **Non-recursive single-object transfers into a container-typed destination infer the name.** G2 follows `cp` / `scp` for the "singular object into an already existing container (that tab-completion filled in for me)" gesture granted for the download direction in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638). P3-cli is the upload converse, which that discussion flagged as an error; it is allowed here per issue [#2946](https://github.com/PelicanPlatform/pelican/issues/2946), because the error users actually got — `remote object already exists` naming a collection they were not writing to — reads as a false statement about their own filename. The change is confined to the CLI: `client.DoPut` still errors (P3-lib), so no library caller silently acquires the new behavior.
- **Recursive transfers into a container are `rsync`-flavored, not `cp -r`-flavored.** G5 and P6 both lay entries flat under the destination — the source basename is NOT interposed. This is the layout agreed for `pelican object sync` in discussion [#1638](https://github.com/orgs/PelicanPlatform/discussions/1638); `get -r` / `put -r` inherit the same rule so that `object sync` and library callers (`client_agent`, embedders) see one consistent layout.
- **The library never invents container creation semantics that could surprise a scripting user.** `?recursive` and `--recursive` are the explicit opt-in for walking or expanding directory-typed sources; when absent, a directory source is a client-side error rather than a silent success or a strange partial upload. Both spellings must be read wherever recursion changes the layout, since `client.DoPut` and `client.DoGet` honor the query parameter regardless of the boolean they were passed.
- **An inferred name is validated, never just joined.** `path.Join` cleans its result, so a source basename of `..` would resolve to the parent of the collection the caller named and upload there without saying so. `cmd/object_put.go` refuses such a source instead of rewriting it.
- **Pre-flight stats fail soft on the put side, hard on the get side.** For put, a stat failure does not imply the put will fail (write-only tokens, no `listings`), so the pre-flight logs at debug and falls through. For non-recursive get, non-`ErrObjectNotFound` stat failures propagate — the G4 decision cannot be made without knowing whether the source is a collection, and guessing wrong corrupts the local layout. Recursive get skips the stat entirely (no G4 check needed since the walker handles both shapes).

## Where the code lives

- `client.DoGet` (in `client/main.go`) — library-level get. The container-target branch stats the source only on the non-recursive path (for the G2/G4 decision) and leaves the recursive path (G5/G6) to the walker with the destination unchanged.
- `client.DoStat` (in `client/main.go`) — library-level stat. Uses `getDirectorInfoForPath` + `statHttp` directly and builds no `TransferEngine`, so the cost is one Director query plus one `PROPFIND` round. Honors the same role-specific token options as a transfer, and `WithStatUploadDestination` for pre-flighting a write destination.
- `client.statHttp` / `statHttpImpl` (in `client/handle_http.go`) — WebDAV `PROPFIND` with the bounded collections-only fallback described in the G4 note above.
- `client.DoPut` (in `client/main.go`) — library-level put, including the P4 "local source is a directory but recursive is false" guard.
- `cmd/object_get.go` — CLI wrapper for get. Adds the multi-source destination checks (rows G8-G10).
- `cmd/object_put.go` — CLI wrapper for put. Pre-flights the destination with a single `client.DoStat` outside the source loop, then rewrites the per-source destination for P3-cli/P8/P9 only, via `inferRemoteObjectName`. Recursive uploads skip the rewrite so P6 stays flat. Stat failures are soft (row P10).

## Where the tests live

Subtests are named after the row IDs above, so a failure points directly at a documented expectation. Coverage is split by where the behavior is implemented:

| Test                                                                   | Rows covered                                                                                                   |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `cmd/object_transfer_semantics_test.go`: `TestObjectTransferSemantics` | G1-G6, P1, P2, P3-lib, P4, P5, P6 — the library-level rows, against one POSIXv2-backed federation              |
| `cmd/object_put_test.go`: `TestObjectPutSemanticsCLI`                  | P3-cli, P6 (via `?recursive`, and with several sources), P8, P9, P10 — the rows `cmd/object_put.go` implements |
| `cmd/object_put_test.go`: `TestInferRemoteObjectName`                  | The destination rewrite in isolation, including the sources it refuses                                         |
| `cmd/object_put_test.go`: `TestObjectPutToDirectoryInfersFilename`     | P3-cli end to end through an authenticated XRootD-backed origin                                                |

Rows **G7**, **G8**, **G9**, **G10**, and **P7** are documented but not yet asserted anywhere; G9 and G10 are `os.Exit` paths in `cmd/object_get.go`, which cannot be driven through `rootCmd` in-process. Adding coverage for them is welcome.

`TestObjectPutSemanticsCLI` and `TestInferRemoteObjectName` only assert successful command lines and pure-function behavior respectively, because `putMain` reports failure with `os.Exit`: an error path asserted through `rootCmd` would take the test binary down with it.
