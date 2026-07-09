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
- **Filename inference** — when the destination path names a *container* (existing local dir, or a remote collection when the PR-2970 semantics land), the transfer places the object at `<destination>/<basename(source)>` rather than treating the destination string as the object name itself.

## `pelican object get REMOTE [REMOTE...] LOCAL`

Downloads a single object or a collection tree from the federation to the local filesystem.

### Single source, `--recursive=false`

| #   | Remote source is | Local destination        | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --- | ---------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| G1  | an object        | an existing regular file | Overwrite the local file (destination string is a filename).                                                                                                                                                                                                                                                                                                                                                                                                       |
| G2  | an object        | an existing directory    | Filename inferred: object written to `LOCAL/basename(REMOTE)`.                                                                                                                                                                                                                                                                                                                                                                                                     |
| G3  | an object        | a non-existent path      | Create the file at that path (destination string is a filename).                                                                                                                                                                                                                                                                                                                                                                                                   |
| G4  | a collection     | any local state          | **Currently (main):** does NOT error. A single WebDAV GET runs against the collection URL and the local file `dest/basename(remote)` contains whatever the origin serves for that GET (typically a directory listing, not the collection's descendants). This is asymmetric with put's directory guard and is easily mistaken for a successful download. Locked down as-is; a future PR that wants to reject this case has a documented regression test to update. |

Inference (row G2) happens inside `client.DoGet`, not at the CLI level. Callers of the library see it too.

### Single source, `--recursive=true`

| #   | Remote source is | Local destination     | Behavior                                                                                                                                                                                                                                                                            |
| --- | ---------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G5  | a collection     | an existing directory | Entries placed **flat** under `LOCAL` — each entry keeps its name, but the collection name itself is NOT interposed as a subdirectory. This is asymmetric with `cp -r`. To get "unpack under a subdir named after the collection", add the collection basename to `LOCAL` yourself. |
| G6  | a collection     | a non-existent path   | Destination created, entries placed **flat** under it (same flatten behavior as G5).                                                                                                                                                                                                |
| G7  | an object        | any                   | Effectively a single-item recursive walk — behaves like G1/G2/G3 for that one object.                                                                                                                                                                                               |

### Multiple sources

Only single-destination is supported: the last positional argument is the destination, everything before it is a source. When `len(sources) > 1`, `cmd/object_get.go` inspects the local destination up-front:

| #   | Local destination  | Behavior                                                                                     |
| --- | ------------------ | -------------------------------------------------------------------------------------------- |
| G8  | Existing directory | Each source individually goes through the single-source rules (G2 style: filename inferred). |
| G9  | Non-existent       | Fatal CLI error: `Destination does not exist`.                                               |
| G10 | Regular file       | Fatal CLI error: `Destination is not a directory`.                                           |

The multi-source pre-check is a CLI-level guard; the library (`client.DoGet`) is called once per source.

## `pelican object put LOCAL [LOCAL...] REMOTE`

Uploads a single object or a directory tree from the local filesystem to the federation.

### Single source, `--recursive=false`

| #   | Local source is | Remote destination            | Behavior                                                                                                                                                                                                                            |
| --- | --------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1  | a file          | a non-existent remote path    | Upload as-is (destination is treated as the target object URL).                                                                                                                                                                     |
| P2  | a file          | an existing remote object     | `remote object already exists, upload aborted` (write-once semantic enforced by the origin).                                                                                                                                        |
| P3  | a file          | an existing remote collection | **Currently (main):** `remote object already exists, upload aborted` — no CLI-level inference. **After PR #2970 lands:** filename inferred, uploaded to `REMOTE/basename(LOCAL)`, matching the download G2 asymmetry the PR closes. |
| P4  | a directory     | any                           | Client library error: `local object %q is a directory but recursive is not enabled`.                                                                                                                                                |

### Single source, `--recursive=true`

| #   | Local source is | Remote destination            | Behavior                                                                                       |
| --- | --------------- | ----------------------------- | ---------------------------------------------------------------------------------------------- |
| P5  | a directory     | a non-existent remote path    | Tree uploaded; remote collection created at `REMOTE` and its contents populated.               |
| P6  | a directory     | an existing remote collection | Tree contents uploaded into `REMOTE` — each local entry keeps its name.                        |
| P7  | a file          | any                           | Recursive walk of a trivial tree; behaves like the single-file cases above for that one entry. |

### Multiple sources

Same shape as get: the last positional argument is the remote destination. Currently (main) `cmd/object_put.go` iterates sources and calls `client.DoPut` for each with the same destination URL, so:

| #   | Remote destination | Current behavior on main                                                                                                                                              |
| --- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P8  | Any single URL     | First upload may succeed; every subsequent upload sees `remote object already exists`. There is no CLI-level "destination must be a directory" precheck (unlike get). |

PR #2970 adds a `client.DoStat` up front to detect a remote collection (or a stat-miss on a URL treated as a "would-be directory" for multi-source puts) and rewrites the per-file destination to `REMOTE/basename(LOCAL_i)`.

## Design principles the matrix follows

- **`get` and `put` are symmetric for object/collection type checks.** The library catches the "source type mismatched with recursive flag" cases; the CLI catches "multi-source needs a container destination" for get and (with PR #2970) for put.
- **Filename inference is opt-in via container-typed destinations.** The destination is treated as a filename only when it does not name an existing container. This mirrors `cp` / `scp`.
- **The library never invents container creation semantics that could surprise a scripting user.** `?recursive` and `--recursive` are the explicit opt-in for walking or expanding directory-typed sources; when absent, a directory source is a client-side error rather than a silent success or a strange partial upload.

## Where the code lives

- `client.DoGet` (in `client/main.go`) — library-level get, including the local-destination-directory filename inference for a single source.
- `client.DoPut` (in `client/main.go`) — library-level put, including the "local source is a directory but recursive is false" guard.
- `cmd/object_get.go` — CLI wrapper for get. Adds the multi-source destination checks (rows G8-G10).
- `cmd/object_put.go` — CLI wrapper for put. Pre-PR #2970: has no destination-shape checks (row P8's behavior falls out of iterating the library call per source). Post-PR #2970: adds a `client.DoStat` to detect a remote collection and rewrites the per-file destination.

## Where the tests live

`cmd/object_transfer_semantics_test.go` runs one POSIXv2-backed federation (no XRootD dependency) and asserts every row in the table above. The tests are structured as subtests named after the row IDs (`G1`, `P3`, ...) so a failure points directly at a documented expectation.
