# Pelican Store (pstore) Design

## 1. Overview

`pstore` ("pelican store") is a new origin storage backend that uses the cache V2 data store as an origin's *primary* data store rather than as a cache.

Today the block store in `local_cache` is only reachable through `PersistentCache`, which couples it to download orchestration, HTTP revalidation, and LRU eviction. The store underneath — encrypted 4080-byte blocks, multi-directory spreading, chunking for large objects, a file-descriptor cache, and a BadgerDB metadata catalog that is itself encrypted at rest — is a general-purpose object store that happens to be used by a cache. `pstore` uses it directly, adds the one thing a cache never needed (a directory index), and exposes the result as an `afero.Fs` so it drops into the existing origin serving stack.

What an operator gets, relative to a POSIX origin:

- **Encryption at rest** for both data and metadata, keyed off the origin's issuer keys, with no filesystem-level encryption setup.
- **Atomic overwrite** without `Origin.EnableAtomicUploads`, rename-on-same-filesystem constraints, or a temp-upload directory.
- **O(1) checksums** on `Want-Digest` HEAD requests, computed once at ingest, instead of re-reading the object or depending on xattr support.
- **Multi-disk spreading** with per-directory size limits, without LVM or RAID.
- **Millions of small objects** without the per-directory scaling behavior of the underlying filesystem, since object data is content-addressed into a two-level hash tree and the namespace lives in BadgerDB.
- **Operational machinery an origin needs and a cache does not**: scheduled metadata backups, scheduled integrity checking that never deletes, a recovery export that does not need Pelican running, and a live administrative introspection API (§11).

What it deliberately does *not* do:

- No eviction. When the store reaches its configured size, writes fail with `ENOSPC` (HTTP 507) until something is deleted.
- No mid-file edits. Pelican has no partial-update semantics; objects are immutable and overwrite replaces the whole object.
- No version-addressed retrieval. Superseded object versions are garbage collected, not served (see §9).
- No path-based quotas. The store enforces a total capacity bound; per-path quotas will come from the LotMan work landing in `local_cache` (see §7.2).

### 1.1 Non-goals

- Replacing the cache's use of the block store. `local_cache` gains new API surface and a small number of deliberate behavior changes, all enumerated in §10.
- Multi-process or multi-host sharing of one store. Like the cache, a store is owned exclusively by one process.
- POSIX semantics beyond what WebDAV and the Pelican client actually exercise: no hard links, no symlinks, no per-file ownership, no partial writes.

## 2. Where it plugs in

```
   webdav.Handler                       (origin_serve/handlers.go, unchanged)
        │
   aferoFileSystem                      (origin_serve/filesystem.go)
        │   ── metrics, HTB rate limiting, multiuser wrapping, dir pagination,
        │      Content-Length hint (SizeHintFs), conditional writes
        │
   afero.Fs  ◄────────────────────────  pstore.FS            ← new
        │
   pstore.Store                                              ← new
        │   ── path index, generation/commit protocol, capacity, GC,
        │      checksums, fsck, backup, export
        │
   local_cache.StorageManager           (+ AppendWriter, pins, SetChooseDir)
   local_cache.CacheDB                  (+ DB, EnsureStoreMode, ReloadSalt)
```

`aferoFileSystem` in `origin_serve/filesystem.go` already adapts any `afero.Fs` into a `webdav.FileSystem` and layers on Prometheus metrics, HTB rate limiting, and directory pagination. Implementing `afero.Fs` is therefore the cheapest correct integration: `origin_serve/backend_pstore.go` is a `server_utils.OriginBackend` mirroring `localBackend` in `origin_serve/backend.go`, plus the store lifecycle (opening, sharing between exports, starting the janitor, backups, and integrity checks, and closing on server shutdown).

`CacheDB` and `StorageManager` are already constructible standalone — see `NewIntrospectAPI` in `local_cache/introspect.go` and the multi-directory tests in `local_cache/chunking_test.go` — and `EvictionManager` is opt-in, never started implicitly. "No eviction" is the default, not something that has to be removed.

### 2.1 Code layout

| Path                             | Contents                                                                                        |
| -------------------------------- | ----------------------------------------------------------------------------------------------- |
| `pstore/store.go`                | `Store` lifecycle: open/close, mode marker, DB + `StorageManager` wiring, namespace ops, rename |
| `pstore/index.go`                | `pd:` dirent encode/decode, key layout, lookup, list, subtree walk                              |
| `pstore/object.go`               | Generation minting, `instanceHash` derivation, ETag rendering                                   |
| `pstore/object_io.go`            | Write handle (three tiers, commit) and read handle                                              |
| `pstore/detached.go`             | Masking for subtrees unlinked but not yet drained (§9.1)                                        |
| `pstore/fs.go`                   | `afero.Fs` / `afero.File` adapter over the store, including `OpenFileSized`                     |
| `pstore/capacity.go`             | Reservation counters, directory placement, `ENOSPC` enforcement                                 |
| `pstore/gc.go`                   | `pg:` queue, janitor, inline and deferred subtree removal, reclamation                          |
| `pstore/checksum.go`             | Ingest digests and `Want-Digest` lookup (§11.1)                                                 |
| `pstore/fsck.go`                 | Consistency check and repair (§11.2)                                                            |
| `pstore/integrity.go`            | Scheduled index check and data scan (§11.3)                                                     |
| `pstore/backup.go`               | Catalog snapshot, restore, scheduled backups with retention (§11.4)                             |
| `pstore/backup_crypto.go`        | Snapshot compression, the recipient envelope, and AES-GCM sealing (§11.4)                       |
| `pstore/recover.go`              | Recovery export to plain files (§11.5)                                                          |
| `pstore/maintenance.go`          | Offline open for the CLI, read-only enforcement (§11.6)                                         |
| `pstore/errors.go`               | Sentinel errors and the status codes they map to                                                |
| `backup_keys/backup_keys.go`     | Issuer-key backup derivation, shared with the server database's backups (§11.4)                 |
| `local_cache/pin.go`             | Reader pin set, shared with the cache's eviction (§9)                                           |
| `origin_serve/backend_pstore.go` | `OriginBackend` adapter, checksummer, capacity reporter                                         |
| `origin_serve/storage_api.go`    | Administrative live-store HTTP API (§11.6)                                                      |
| `server_utils/origin_pstore.go`  | Export configuration and validation                                                             |
| `cmd/origin_pstore.go`           | `pelican-server origin pstore …` offline CLI                                                    |
| `cmd/origin_introspect.go`       | `pelican-server origin introspect …` client for the live API                                    |

`pstore` imports `local_cache` directly. The alternative — first extracting `database.go`, `storage.go`, `schema.go`, `encryption.go`, `chunking.go`, and `block_state.go` into a shared `blockstore/` package — is ~6k lines of mechanical churn across the cache and its tests for zero semantic change, and can be done later without touching `pstore` if the dependency weight becomes a problem.

## 3. Key layout

The store shares one BadgerDB with the same prefix namespace the cache uses. Two prefixes are new; the rest are reused unchanged.

| Prefix | Owner      | Contents                                         |
| ------ | ---------- | ------------------------------------------------ |
| `pd:`  | **new**    | Directory entries, keyed by parent path and name |
| `pg:`  | **new**    | Garbage queue: instances awaiting reclamation    |
| `m:`   | reused     | `CacheMetadata` per object version               |
| `s:`   | reused     | Roaring bitmap of written blocks                 |
| `d:`   | reused     | Inline data for objects below `InlineThreshold`  |
| `l:`   | reused     | Access-time index (see §8)                       |
| `u:`   | reused     | Byte usage per `(storageID, namespaceID)`        |
| `n:`   | reused     | Namespace prefix → `NamespaceID`                 |
| `di:`  | reused     | Storage directory ID → path mapping              |
| `e:`   | cache only | Latest-ETag pointer; `pstore` does not use it    |
| `pf:`  | cache only | Purge-first marks; `pstore` does not use it      |

A store and a cache must never open each other's database: the key spaces overlap by design and cross-opening would be silent corruption. `Store.Open` calls `CacheDB.EnsureStoreMode`, which writes and checks the `_mode` marker key (`KeyStoreMode`) and refuses to open a database whose marker disagrees. The `pd:`/`pg:` reservation is declared alongside the existing prefix constants in `local_cache/schema.go` (`PrefixDirent`, `PrefixGarbage`) so a future cache feature does not claim them.

## 4. The path index

### 4.1 Why path-keyed, keyed by parent

Two families of layout were considered: inode-style (dirents map a name to an inode ID; object identity is independent of path) and path-keyed (the key is derived from the entry's path).

Path-keyed wins because **path locality is what every bulk operation wants**. BadgerDB iterates in byte-sorted order, so path-derived keys put related entries next to each other and turn listings, `du`, quota recomputation, subtree fsck, and recursive delete into sequential scans. Under inode-style, entries are scattered in inode-allocation order and every one of those degrades into a recursive traversal of random seeks. Given that usage tracking and quotas are planned and are path-based (§7), this is decisive.

Within the path-keyed family there is a further choice, and it matters more than it first appears:

|                                | `pd:<full path>`                    | `pd:<parent>\x00<name>`       |
| ------------------------------ | ----------------------------------- | ----------------------------- |
| Direct children of a directory | **interleaved** with whole subtrees | **contiguous**                |
| Readdir cost                   | O(children + subdirs) LSM seeks     | one sequential scan, no seeks |
| Subtree                        | one contiguous range                | two contiguous ranges         |
| Sorted listing                 | needs a NUL-terminated marker trick | automatic                     |
| Empty directories              | need explicit marker records        | natural                       |

Keying by full path makes a subtree contiguous but scatters a *single directory's* children across it, because every descendant sorts between them. Readdir then has to seek over each subtree, and those are real LSM repositionings with no read-ahead benefit — a directory with 1,000 subdirectories costs 1,000 seeks.

Since listing one directory is the dominant operation, the store keys dirents by **parent path plus name**. Subtree scans become two contiguous ranges instead of one, which is immaterial for the background operations that use them.

The cost of path-keying in general is that renaming a directory is O(descendants) rather than O(1). That is acceptable here:

- The Pelican client never issues WebDAV `MOVE`. The origin routes it (in the route table built by `RegisterHandlers` in `origin_serve/handlers.go`, behind the `modify` authz scope), but it is reachable only from raw WebDAV clients.
- The existing S3 origin backend already implements `Rename` as a best-effort, explicitly non-atomic subtree copy-then-delete that physically moves every byte (`blobFileSystem.Rename` in `origin_serve/backend_blob.go`). `HTTPSv2` returns `ErrNotSupported` unless the upstream speaks WebDAV.
- `pstore`'s rename rewrites index keys and moves **zero bytes** (§4.4), so it is strictly better than the precedent it has to match.

### 4.2 Layout

```
pd:<parent path>\x00<name>  → dirent
```

Both files and directories are entries under their parent, so a directory needs no separate marker record and an empty directory is as real as any other entry. The root is a single fixed key. Parent paths are absolute with no trailing slash, except the root, which is `/`:

```
/a       (dir)     →  pd:/\x00a
/a.b     (file)    →  pd:/\x00a.b
/a0b     (file)    →  pd:/\x00a0b
/a/b     (dir)     →  pd:/a\x00b
/a/b/c   (file)    →  pd:/a/b\x00c
```

The dirent value is msgpack:

```go
type dirent struct {
    Type       uint8  `msgpack:"t"`   // file | dir
    Generation string `msgpack:"g"`   // hex; files only — see §5
    Size       int64  `msgpack:"s"`
    MTimeNanos int64  `msgpack:"m"`
    Mode       uint32 `msgpack:"o"`
}
```

Size, mtime, and the generation (which is also the ETag) are **denormalized into the dirent** so that a listing is one scan. Without this, a PROPFIND over a 10,000-entry directory would be 10,000 additional point lookups to fetch each child's `m:` record. The denormalized fields are rewritten only on commit, which is a transaction the write path performs anyway.

Because every key ends in the bare name, a directory's children sort by name with no special handling — files and directories interleave correctly and there is no terminator to reason about. The siblings `/a`, `/a.b`, and `/a0b` key as `pd:/\x00a`, `pd:/\x00a.b`, `pd:/\x00a0b` and come out as `a`, `a.b`, `a0b`.

NUL is chosen as the separator because it is forbidden in path components (§4.5), so it can never appear inside a parent path or a name. That validation is therefore load-bearing for key unambiguity, not merely defensive, and is tested directly.

Sorted output is a real benefit on the paginating path and a latent one otherwise: `pstore`'s `file.Readdir` serves a positive count straight from the index, one page per call, resuming from the last name returned and buffering nothing. `aferoFileSystem.Readdir` in the origin still calls `afero.ReadDir`, which buffers the whole directory via `Readdir(-1)` and re-sorts it by name, so the streaming property is only fully realised once that adapter is bypassed.

### 4.3 Operations

**Lookup / Stat** — split the path at its last `/` and do one point get on `pd:<parent>\x00<name>`. Size, mtime, and ETag come straight from the dirent, so `Stat` never touches `m:`.

**Open (read)** — dirent → generation → `instanceHash` (§5) → `m:` → `StorageManager.NewObjectReader`. Two gets, no path walk.

**Readdir** — prefix scan on `pd:<dir>\x00`. This yields **exactly** the direct children, already in name order: one sequential scan, no seeks, no filtering, and no subtree to skip over. Pagination is a matter of resuming the iterator.

**Subtree scan** — two contiguous ranges:

- `pd:<dir>\x00` — the direct children.
- prefix `pd:<dir>/` — everything deeper, since every node below the direct children has a *parent path* beginning with `<dir>/`.

For the root both collapse into a scan of the whole `pd:` space. Used by quota recompute, `du`, fsck, export, and recursive delete; all of them are order-independent, so splitting into two scans costs nothing.

Sibling prefixes cannot leak into either range. For `/a`, the deeper range is prefix `pd:/a/`; a sibling `/a-b`'s children key as `pd:/a-b\x00…`, which differs at `-` (0x2D) versus `/` (0x2F). `/a`'s own grandchildren key as `pd:/a/q\x00r` and match correctly.

**Mkdir** — write the entry under its parent. `MkdirAll` writes each missing ancestor.

Uploads to a fresh path work without an explicit `MKCOL` because `pstore.FS` creates missing parents itself, in `createSizedWithParents`. It deliberately does **not** use the origin's shared `autoCreateDirFs` wrapper (`origin_serve/filesystem.go`): that wrapper derives the parent with `filepath.Dir`, and a pstore path is a namespace path that is always slash-separated, so on Windows it would ask for a directory literally named `\a\b\c`. Doing it inside `pstore.FS` keeps the separator right on every platform.

### 4.4 Rename

Renaming a file is a single transaction: delete the old dirent, write the new one with the same value. Nothing else moves — object identity does not depend on the path (§5).

Renaming a directory walks both subtree ranges (§4.3) and rewrites each key with its parent-path component substituted (`moveSubtree` in `pstore/store.go`). Both ranges are sequential scans. No data file is touched, no bytes are copied, and no object metadata is rewritten: nothing in `m:` records the path.

The whole rename — the destination checks, the subtree rewrite, the old dirent's removal, and the new dirent's write — runs inside **one** `bdb.Update`, so a directory rename is atomic. A crash mid-rename leaves the store exactly as it was.

Atomicity has a size limit, which is BadgerDB's transaction size rather than anything in this design. Rather than discover it as an opaque transaction failure part-way through, `moveSubtree` bounds the descendant count at `renameSubtreeLimit` (50,000) and checks it during the **collect** phase, before anything is written: a subtree over the limit is refused with a typed `ErrNotSupported` carrying an actionable message, and the store is unchanged. Since the Pelican client never issues `MOVE`, this bound is reached only from raw WebDAV clients operating on very large trees, and the operator can move such a tree in pieces. If unbounded atomic rename is ever required, a rename journal record can be added without changing the layout.

### 4.5 Constraints

- Path components may not contain `/` or NUL, and `.`/`..` are rejected after `path.Clean`. This is enforced by `validatePath`/`cleanRelative` in `pstore/index.go` and covered by `TestValidatePath` and `TestCleanRelative` in `pstore/index_test.go`. Running the origin's existing `origin_serve/path_traversal_test.go` suite against `pstore` as well is intended but **not yet done**.
- A file and a directory may not share a name.
- Paths are **case-sensitive**. See §12.
- Export `StoragePrefix` is a logical root inside the store, not a filesystem path; validation must not `os.Stat` it (`PStoreOrigin.validateStoragePrefix` in `server_utils/origin_pstore.go`).

That last constraint is load-bearing beyond validation. `origin_serve` has host-filesystem fast paths that used to resolve any export's `StoragePrefix` with `os.OpenRoot`, on the assumption that it names a directory on this machine — true for POSIX, false for `pstore`, S3, HTTPS, and Globus alike. For a single-export pstore origin the natural `StoragePrefix` is `/`, and `os.OpenRoot("/")` succeeds: a browser GET became an HTML index of the *origin host's root directory*, and ETag/Last-Modified became an existence-and-mtime oracle for host files. The PUT path was worse, running checksum invalidation — which opens `O_RDWR` and strips xattrs — against unrelated local files. Backends now **opt in** to that resolution by implementing `localRootProvider` (`LocalStorageRoot() (*os.Root, error)`); anything that does not, `pstore` included, gets `errNotHostFilesystem` and the fast paths are skipped.

## 5. Object identity and generations

Every write mints a **generation**: 128 random bits, hex-encoded.

```
generation    = 128 random bits, minted per write
instanceHash  = HMAC(salt, "gen:" + generation)
ETag          = "<generation>"
```

The generation is the object version's identity, its HTTP ETag, and the input to its storage key. Because `instanceHash` derives from the generation *alone* and not from the path, `m:`, the block state, and the on-disk data file are all path-independent. That is what makes rename a pure index operation.

This is the same two-level structure the cache uses — a "latest version" pointer plus a per-version record — with the dirent playing the role of `e:`. Since the dirent must exist for listings regardless, folding the pointer into it costs one index and one lookup less than reusing `e:` would.

Data files remain hash-named on disk (`objects/xx/yy/rest`), so an attacker with the disks but not the master key still cannot tell what objects the store holds. Plaintext paths appear only in BadgerDB keys, and BadgerDB is encrypted at rest — `NewCacheDB` derives a separate database key from the master key via `DeriveDBKey` (`local_cache/database.go`). The catalog's plaintext exposure is the same shape the cache already had, which is why the metadata backup format is encrypted too (§11.4).

## 6. Write path

Objects are immutable. Pelican has no mid-file edits, so a write is always "create a complete new version, then swap it in".

1. `OpenFile` with any write flag returns a write handle. Seek-then-write returns `ENOTSUP`; writes must be sequential from offset 0.
1. Bytes accumulate in memory. Where they end up depends on how many arrive, or on the declared `Content-Length` when there is one — see the three tiers below.
1. A rolling checksum is computed over the stream at no extra I/O cost (§11.1).
1. On `Close` the content is materialised and, for streamed objects, `AppendWriter.Finalize()` (§10) records the true `ContentLength`, drops chunks the object never reached, and truncates the tail chunk file.
1. **Commit** — one BadgerDB transaction:
   - re-check the parent directory and any conditional-write precondition (§6.2);
   - write the dirent `pd:<parent>\x00<name>` with the new generation, size, and mtime;
   - if a previous generation existed, enqueue its `instanceHash` on `pg:`.

Committing the swap and enqueuing the superseded version in the *same* transaction is what makes overwrite crash-safe: there is no window in which an orphaned version is both unreachable from the index and absent from the garbage queue. Space can leak only if the janitor never runs, and fsck (§11.2) is a backstop rather than a requirement.

Aborting a write before `Close` — client disconnect, error — discards the partial instance and releases its capacity reservation, and never touches the dirent, so readers never observe it.

### 6.1 Three write tiers

How the content is materialised depends on how much of it actually arrives:

| Size               | Path                                                                              |
| ------------------ | --------------------------------------------------------------------------------- |
| ≤ `InlineMaxBytes` | `StorageManager.StoreInline` — data lives in the catalog                          |
| ≤ `spillThreshold` | buffered, then `InitDiskStorage` with the exact length and a single `WriteBlocks` |
| > `spillThreshold` | `AppendWriter` (§10), streamed, length known at the end                           |

`InlineMaxBytes` is `Origin.PStoreInlineMaxBytes`, defaulting to `local_cache.InlineThreshold`. `spillThreshold` and the chunk-size bounds are constants in `pstore/object_io.go`; treat those definitions as authoritative rather than repeating numbers here.

The middle tier exists for capacity, and is worth keeping. `AppendWriter` allocates whole chunks while streaming, so routing a small object through it would reserve a full chunk and hold that reservation until `Finalize` refunded the difference — enough to spuriously fail a write on a near-full store. Buffering to the spill threshold means only genuinely large objects take that path, where the overshoot is proportionally small. It also lets the common case allocate exactly once, at the right size, with no truncation.

The spill buffer is per in-flight write and cannot be evicted, so `spillThreshold` trades directly against write concurrency: a hundred concurrent uploads each hold up to that much. That is the reason it is set well below the smallest chunk the block store can encode.

**The streaming chunk size is chosen per write, not fixed** (`streamChunkSizeCodeFor` in `pstore/object_io.go`), and the reason is capacity rather than file count. `AppendWriter` pre-allocates and charges a whole chunk the moment a stream touches it, so the chunk size *is* the minimum free space some single directory must have before an object above the spill threshold can be accepted (§7). A fixed large chunk would therefore make a bounded store refuse objects it has ample room for. So:

- a **declared** length picks a chunk sized to the object, clamped between the block store's smallest encodable chunk and an upper cap — an object just past the spill threshold reserves megabytes rather than the largest chunk the encoding allows, while a genuinely large upload still gets large chunks, because a terabyte at the minimum chunk size would be half a million files and it needs the space anyway;
- an **undeclared** length (a chunked transfer-encoding PUT) falls back to `defaultStreamChunkSize`, a small multiple above the spill threshold. There is no way to size the chunk from the object, so this is a deliberate compromise: a store needs only that much headroom in some directory to accept an unknown-length object, at the cost of more chunk files for a very large one.

Keeping `minStreamChunkSize` within a small factor of `spillThreshold` is what makes the two tiers compose: crossing the spill threshold must not multiply the free space a write demands.

One consequence for the pre-flight capacity check (§7.1): `HasCapacityFor` models the **declared-length** path, because that is the only case in which it is consulted at all. An undeclared write assumes the default chunk size and therefore reserves more than a same-sized declared write would — a second reason, beyond the 507 mapping, that a client should send a `Content-Length` when it has one.

**The size hint.** Discovering the size by buffering is the fallback, not the normal case. `origin_serve` defines an optional interface

```go
type SizeHintFs interface {
    OpenFileSized(name string, flag int, perm os.FileMode, size int64) (afero.File, error)
}
```

in `origin_serve/filesystem.go`, and `aferoFileSystem.OpenFile` uses it when the backing `afero.Fs` implements it. `afero.Fs` has no context and no size argument, so without this a backend cannot see the `Content-Length` the WebDAV handler already has; the hint travels down through the request context (`ContextWithContentLength`) and out through this interface. `autoCreateDirFs` forwards it, so wrapping does not silently drop it.

`pstore.FS.OpenFileSized` passes the hint to `Store.CreateSized`, which picks the streaming tier immediately when the declared size is at or above `spillThreshold` — so a large upload never buffers first. The hint is advisory: the object is stored at whatever length actually arrives, and a wrong or absent hint (a chunked-encoding PUT declares `-1`) costs only the buffering it would have avoided. Any origin backend that can do better with a known length can implement the same interface.

### 6.2 Conditional writes

Because commit is already a compare-and-swap on the dirent, RFC 7232 conditional PUTs are nearly free and worth having:

- `If-Match: "<generation>"` — commit only if the dirent still holds that generation, else 412. Protects concurrent writers from lost updates.
- `If-None-Match: *` — commit only if no dirent exists, else 412. Create-only.

The handler evaluates preconditions for every backend before the write begins, which is inherently a stat-then-write race: two concurrent `If-None-Match: *` PUTs can both observe an absent object and both commit. `origin_serve` therefore defines a second optional interface, `ConditionalWriteFs` (`OpenFileConditional`), which carries the parsed precondition down to a backend that can re-check it *inside* its commit transaction. `WriteHandle.RequireAbsent` and `WriteHandle.RequireGeneration` are that re-check for `pstore`, and they are evaluated in the same `bdb.Update` that installs the dirent, so the race is closed rather than narrowed.

**Two forms cannot be closed this way and stay best-effort on the early check:**

- `If-Match: *` asserts that the target *exists*, not that it holds a particular version. There is no version to compare at commit, so the commit-time condition has nothing to test.
- A multi-tag entity-tag list is a *membership* test. The commit-time condition carries one tag, because that is what a compare-and-swap on a single dirent can express.

Both are vanishingly rare from real clients, and both still fail correctly under the pre-write check; what they lack is atomicity against a concurrent writer. A single-tag `If-Match` and `If-None-Match: *` — the two forms anything actually sends — are fully atomic.

Two writers that reach commit simultaneously can also collide in BadgerDB itself. That surfaces as `pstore.ErrConflict`, which is retryable and distinct from a precondition failure: the write did not lose a race on *content*, it lost one on the transaction.

## 7. Capacity

There is no eviction: `EvictionManager` is never constructed, and the `l:` index is maintained for access time only (§8).

**Capacity** is bounded by `StorageDirConfig.MaxSize` per storage directory — the same structure and parser `LocalCache.StorageDirs` uses (`StorageDirConfig` and `ParseStorageDirsValue` in `local_cache/schema.go`). Counters live in memory, seeded from the catalog's persisted usage at startup; a store owns its directories exclusively for its lifetime, so an in-process count is exact and costs no writes on the hot path.

An **unset `MaxSize` makes that directory unbounded**, and one unbounded directory makes the store as a whole unbounded — the aggregate ceiling is the sum of the configured limits, or zero (meaning no ceiling) if any directory has none. This differs from the cache, which auto-detects a directory's size from the filesystem when the limit is unset; a store that silently adopted the filesystem's size would start refusing writes at a boundary the operator never chose. `docs/parameters.yaml` states the same rule under `Origin.PStoreStorageDirs`.

Enforcement has **two** conditions, and checking only the first is not enough:

- the aggregate must have room; and
- some individual directory must have room for the **placement unit** — one chunk for a streamed object, the whole footprint for anything smaller — because the block store lays each chunk down whole in a single directory. Without the second check a write can pass an aggregate test with plenty of total headroom and then fail against a directory that is individually full.

`pstore` controls placement rather than guessing at it: `Store.Open` installs `capacityTracker.chooseDir` through `StorageManager.SetChooseDir`, replacing the block store's default round-robin. Round-robin ignores how full each directory is, so a store spanning a small disk and a large one walks straight into the small one; the replacement prefers the directory with the most absolute headroom, and treats an unbounded directory as having unlimited headroom.

Inline objects are charged to `StorageIDInline` rather than to a storage directory. They still occupy disk — in the catalog — so they count toward the aggregate; tracking them is what keeps a store from being filled without limit by objects that are each below the inline threshold. They carry no ceiling of their own and are excluded from the per-directory placement check.

A write reserves its projected on-disk footprint as it grows (`WriteHandle.ensureReserved`) and settles up at commit, attributing the real bytes to whichever directories the block store chose (`CacheMetadata.PerDirectoryBytes`). Over-reservation is refunded; a failed or aborted write releases everything it claimed. Exceeding either ceiling returns `syscall.ENOSPC`.

### 7.1 Getting a 507 out of the WebDAV handler

Getting a 507 to the client takes more than returning `ENOSPC`, for two reasons.

`origin_serve`'s `MapToHTTPStatus` handled `EDQUOT` but not `ENOSPC`, so the canonical out-of-space error fell through to string matching and surfaced as a 500 — for every backend, not just this one.

The mapping now lives in `statusForBackendError` (`origin_serve/error_handling.go`), which is the single place a backend sentinel becomes a status:

| Error                                      | Status                   |
| ------------------------------------------ | ------------------------ |
| `ENOSPC`, `EDQUOT`                         | 507 Insufficient Storage |
| `pstore.ErrPreconditionFailed`             | 412 Precondition Failed  |
| `pstore.ErrDraining`, `pstore.ErrConflict` | 409 Conflict             |
| `fs.ErrPermission`                         | 403 Forbidden            |
| `fs.ErrExist` on a conditional write       | 412 Precondition Failed  |

The two 409s share a meaning worth spelling out — *this will work if you try again shortly* — which is far more useful to a client than the 500 an opaque index-transaction error would otherwise produce.

More awkwardly, `golang.org/x/net/webdav` reports *any* copy, stat, or close failure during a PUT as `405 Method Not Allowed`. A client receiving that would conclude the origin does not support PUT at all, rather than that the store is full. The handler offers no hook to distinguish the cases, and the `Logger` callback fires after the status has already been written.

So the origin refuses the request before the handler ever runs. `server_utils.CapacityReporter` is an optional interface that a fixed-size backend implements to answer "will `n` bytes fit"; the PUT path consults it and returns 507 with a reason. `pstoreBackend.HasCapacityFor` forwards to `Store.HasCapacityFor`. Backends that grow on demand do not implement it and are unaffected.

Two limits:

- The check needs a declared `Content-Length`. A chunked-encoding PUT has no length to test, runs until the write fails, and still surfaces as 405. Fixing that means changing how write errors are reported for every backend, which is out of scope here.
- The check is advisory. A concurrent write can consume the headroom between the check and the reservation, so the store enforces its own limit independently; the pre-flight only improves the common case.

### 7.2 Path-based quotas are out of scope

`pstore` exposes **no quota API** in this design. Path-based usage tracking and quotas will arrive separately, from the in-flight work bringing the LotMan logic into `local_cache`. `lotman/` already models what is needed — a hierarchical, path-scoped lot tree (`lotman/lot_tree.go`) with scoped queries and purge policies (`lotman/timeline.go`, `lotman/lotman_api.go`) — so `pstore` should consume that rather than grow a parallel mechanism.

Two constraints are recorded here so the index does not have to change later:

- **Enforcement will be write-time, not lazy recompute.** Writes are refused when they would exceed a lot, rather than violations being detected on a later pass. Path-keying helps directly: a write already holds the full path string, so identifying the enclosing lots is a string operation against an in-memory lot tree with zero database reads. What needs design is the *accounting* side — whether ancestor byte counts are maintained synchronously (O(depth) writes per object) or held by LotMan itself.
- **Bootstrapping lots needs its own design** and is not attempted here: deciding how lots are created for an existing store, how they map onto exports and federation prefixes, and what happens to paths covered by no lot.

What `pstore` contributes toward that work, at no extra cost:

- The subtree ranges of §4.3 make per-lot recomputation and initial population a pair of sequential scans rather than a traversal.
- Per-export accounting is already possible: `u:` is keyed by `NamespaceID`, and the `n:` index maps a prefix to one. A store currently registers a single namespace covering the whole store, because capacity is enforced store-wide; splitting it per export is a change to `resolveNamespaceID` and nothing else.

One open item for that design: `lotman` is currently Linux-only (`lotman/lot_tree.go` and its siblings build under `linux && !ppc64le`, with `lotman/lotman.go` as the stub for everything else). Whether `pstore` quotas inherit that restriction depends on how much of the logic the `local_cache` port reimplements in Go.

## 8. Access time

The `l:` LRU index and `CacheDB.UpdateLRU` are kept, purely to provide access times. `UpdateLRU` (`local_cache/database.go`) is one transaction doing a metadata read-modify-write plus a delete-old/set-new key pair, debounced against `CacheMetadata.LastAccessTime`; in steady state a read pays one get and skips the writes. `pstore` debounces at `atimeDebounce` (`pstore/store.go`).

Access time is deliberately not surfaced through `FileInfo`: it lives on the object's `m:` record rather than its dirent, so reporting it from `Stat` would add a metadata read to every lookup to answer a question almost no caller asks. `Store.AccessTime` exposes it, and `pelican-server origin pstore stat` prints it.

This also gives `l:<storageID>:<namespaceID>:<ts>:<instanceHash>` as a time-ordered index, so "the N coldest objects" would be a bounded scan from one end rather than a full sort. **No such report is implemented** — there is no CLI subcommand and no API route for it — but the index it would need is already maintained, so adding one is a scan and a formatter.

Note what such a report would still be missing. `l:` is keyed by `instanceHash`, and **the store keeps no reverse mapping from an instance back to its path**: `CacheMetadata.SourceURL` is a cache field and `pstore` never writes it, so resolving cold objects to paths means walking `pd:` and building the mapping in memory. That is a sequential scan bounded by the number of objects, which is acceptable for a report, but it is a real cost and is the reason no such report exists yet.

## 9. Deletion and garbage collection

Three things produce garbage: overwrite (the superseded version), aborted writes, and deletion.

**Delete a file** — remove its dirent and enqueue its `instanceHash` on `pg:`, in one transaction.

**Delete a directory** — `RemoveAll` first tries to remove the whole subtree *inline*, in the same transaction that unlinks the directory from its parent (`deleteSubtreeInline` in `pstore/gc.go`), queueing each file's version for reclamation as it goes. The bound is deliberately the same batch size the janitor uses: a removal the janitor would finish in one pass may as well complete immediately. This covers nearly every real removal.

Only a subtree too large for one transaction is deferred: the directory's own dirent is unlinked, making the subtree unreachable at once, and its root is enqueued on `pg:` for the janitor to drain. Deletion does not need to be atomic — a partially drained subtree must simply be invisible — so this is crash-safe without a journal.

Finishing inline matters for more than latency. A detached subtree leaves its descendants in the index under keys that the same paths would reuse, so re-creating the tree before the drain completes would put new entries exactly where the drain is about to delete. Removing inline closes that window entirely, which is why the case §9.1 describes is rare in practice.

### 9.1 Detached subtrees must be masked explicitly

Unlinking the directory is **not** on its own enough to make the subtree unreachable. This is a direct consequence of path-derived keys, and it is the one place where the layout's cheapness has a cost that must be paid back explicitly.

Under an inode index, descendants become unreachable the instant the parent's entry is gone, because reaching them requires walking through it. Here a lookup is a single point get computed from the path — which is precisely why listing a directory is cheap (§4.3) — and it never consults ancestors. So a descendant's key outlives its parent: after a deferred `RemoveAll("/tree")`, the key for `/tree/a/b/deep` is still present and still directly addressable.

Verifying ancestors on every lookup would cost O(depth) gets on the hot path, which is the cost path-keying exists to avoid. Instead the store keeps the set of detached roots in memory (`detachedSet` in `pstore/detached.go`) and tests candidate paths against it. The set is empty except while a drain is in progress and holds one entry per deferred `RemoveAll`, so the check is an atomic load in the common case and a handful of string comparisons otherwise — and only on paths that should not resolve anyway. It is rebuilt from the `pg:` queue at open, so a store that stopped mid-drain does not expose a half-deleted tree when it comes back.

Every path resolution goes through this check: `Stat`, `List`, opening for read or write, and the parent-directory checks in `Mkdir`, `MkdirAll`, and `Create`.

**Reads inside a draining subtree report "not found"; writes report a distinct, retryable error.** Masking a read as `ErrNotExist` is correct — the object is gone. Masking a *create* the same way is not: the descendants still occupy the keys the new entries would use, and the drain will delete whatever it finds there, so a silently accepted write would be silently lost. `Create`, `Mkdir`, and `MkdirAll` therefore return `ErrDraining` (`pstore/errors.go`), which `statusForBackendError` in `origin_serve/error_handling.go` maps to **409 Conflict** — so a client can retry rather than treat the path as permanently broken or, worse, believe the write landed. The wait is bounded: the janitor accelerates while a backlog exists (§9.2), and only subtrees too large to remove inline are ever in this state.

### 9.2 The janitor

The janitor drains `pg:` in the background. For an object version it calls `StorageManager.DeleteIfUnpinned`, which removes the data files and releases the `u:` usage counters; for a detached subtree it removes a bounded batch of dirents per pass, queueing each file's version as it goes, and drops the queue entry once the subtree is empty.

Its interval adapts to the backlog. Each sweep handles a bounded batch, so a fixed period would put a ceiling on how fast space can come back — deleting a tree of a million objects at one batch per resting period would take days, during which the store stays full and refuses writes. A sweep that fills its batch halves the wait, down to a floor; a sweep that does not steps back toward the resting period. Reclamation therefore accelerates exactly when there is something to reclaim and idles otherwise.

**Reader pinning is mandatory, independent of any versioning feature.** Plain overwrite already lets the janitor reap an instance a reader is using. `refCountedFile` keeps the file descriptor alive across unlink on POSIX, but deleting `m:`, the data key, and the block state out from under a live `ObjectReader` breaks it. `local_cache/pin.go` therefore pins each `instanceHash` for the lifetime of its readers — `NewObjectReader` takes the pin itself, so there is no window between opening and being protected — and the janitor skips pinned entries and retries them on a later pass.

Old versions are **not retrievable**. HTTP has no standard mechanism for requesting a specific historical ETag: `If-None-Match` is a negative precondition, `If-Match` returns 412 on mismatch rather than serving the named version, and RFC 7089 Memento is datetime-addressed and far heavier than this warrants. Rather than build a version index that nothing can address, superseded versions are garbage collected immediately. Nothing in the layout precludes adding retention later — it would be a new prefix plus a Pelican-specific addressing extension.

## 10. Changes to `local_cache`

Most of this is additive, but not all of it. The behavior changes are listed second, with their upgrade impact, because an operator upgrading a *cache* is affected by them even though they have no pstore.

**Additive:**

1. `AppendWriter` (`local_cache/append_writer.go`) — a streaming append helper over `InitLazyChunkedStorage`/`AllocateChunk`, so the write path does not have to reimplement chunk-crossing logic. `Finalize()` takes no arguments and returns `(*CacheMetadata, error)`: it flushes the buffered tail, records the true `ContentLength`, drops chunks the object never reached, and truncates the tail chunk file, refunding the over-allocation. It writes through `SetMetadata` rather than `MergeMetadata` because the merge-semantics comment on `CacheMetadata` (`local_cache/schema.go`) classifies `ChunkSizeCode` and `ChunkLocations` as **set-once**, so merging a trimmed chunk table over the allocated one would be rejected as a set-once violation rather than applied. (`MergeMetadata` is in `local_cache/database.go`.)
1. Reader pinning (`local_cache/pin.go`) — a pin set on `StorageManager`, taken automatically by `NewObjectReader`, plus `DeleteIfUnpinned` and `IsObjectPinned`. It lives beside `NewObjectReader` and `Delete` because those are the two operations that must agree; a pin taken in a consumer could always be taken a moment too late.
1. `CacheDB.DB()` — direct BadgerDB access for a sibling subsystem that needs read-your-writes transactions spanning several keys and prefix iteration with seeks. Callers must confine themselves to prefixes they own and must call `EnsureStoreMode` first.
1. `CacheDB.EnsureStoreMode` and the `_mode` marker key, so a store and a cache cannot cross-open a database.
1. `CacheDB.ReloadSalt`, so a restored catalog's hash salt replaces the one cached at open (§11.4).
1. `StorageManager.SetChooseDir`, so a consumer without an `EvictionManager` can still control directory placement (§7).
1. `ParseStorageDirsValue`, factored out of the `LocalCache.StorageDirs` parser so `Origin.PStoreStorageDirs` accepts the same two formats.
1. `local_cache/checksum_format.go` — `ChecksumAlgorithmName`, `ParseChecksumAlgorithm`, `FormatChecksumValue`, `FormatDigestEntry`, `FormatDigestHeader`, and `NewChecksumHasher`, so the origin cannot drift from the value the cache would report for the same bytes.
1. Documentation of the `pd:`/`pg:` prefix reservation next to the existing prefix constants.

**Existing behavior that changed:**

1. **`normalizeURL` folds only the scheme and host, never the path** (`local_cache/schema.go`), per RFC 3986 §6.2.2.1. Folding the path collapsed `/ns/Data.txt` and `/ns/data.txt` onto one cache entry, so a request for either returned whichever had been fetched most recently. The host is folded with IDNA rather than `strings.ToLower`, so the Unicode and punycode spellings of an internationalized name reach the same hash; a port is split off and preserved, and IP literals are left alone. See §12.
1. **`StorageManager.EvictByLRU` gained a skip predicate and a fourth return value.** It now passes `pins.isPinned` down to `CacheDB.EvictByLRU` (whose signature gained the predicate and a skipped count) and reports how many candidates were spared. `EvictionManager.evictFromNamespace` changed signature to carry the count through, and both `checkAndEvict` and `forcePurgeToTargets` now stop a pass that freed nothing instead of looping until their timeout. **Upgrade impact:** none for an operator. A cache spares objects under a live reader that it would previously have deleted mid-transfer, and logs `skippedInUse` when it does.
1. **`formatDigestHeader` and `ConsistencyChecker.createHasher` were extracted** into `local_cache/checksum_format.go` and now delegate. Pure refactor; the emitted header is unchanged.
1. **`StorageManager.Close` no longer hangs on a read-only manager.** `ttlcache.Stop()` is an unbuffered send its `Start` loop receives, and `NewStorageManagerReadOnly` never spawns those loops, so stopping them blocked forever. This affected `pelican cache introspect` before pstore existed. **Upgrade impact:** a hang on exit goes away.

**Announcing schema changes.** `_mode` says who owns a database; `_schema` (`KeySchemaVersion`, `CurrentSchemaVersion`) says what layout it uses. It is stamped when a database is created, and checked at open: a database written by a build with a *newer* schema is refused with both versions named, because reading a newer layout under older rules is exactly the corruption the marker exists to prevent. A database with no marker predates versioning and is adopted at the current version, so deployed caches keep starting. `migrateSchema` is the seam a future bump hooks into. The object-hash derivation in this branch changed once without such a marker to announce it, which is the gap `_schema` closes for the next one.

Downgrade is safe in both directions that matter. An older build ignores the unknown `_mode` key, and `EnsureStoreMode` **adopts** a pre-existing unmarked cache database rather than refusing it (`local_cache/database.go`), so upgrading a running cache is a no-op at startup. The asymmetry is deliberate: an unmarked *non-empty* database can only be a legacy cache, since pstore always writes the marker, so it is adopted as a cache and refused as a pstore.

**The permanent coupling this creates:** `CacheMetadata` and the block layout now have two consumers. Concretely, the set-once classification of the chunking fields is now load-bearing for `pstore`'s streaming write, and the block-level checksum machinery is shared. `pstore`'s tests run in the same CI, which is the mitigation.

## 11. Integrity, backup, and recovery

An origin cannot re-fetch what it loses. Every design decision in this section follows from that one asymmetry with the cache.

### 11.1 Checksums at ingest

A rolling checksum over the write stream costs no extra I/O and is stored in `CacheMetadata.Checksums` (`pstore/checksum.go`). MD5, SHA-1, and CRC32C are recorded for every object; the set is fixed rather than configurable, because computing one later would mean re-reading the object, which is the cost this exists to avoid.

`Want-Digest` responses then become a metadata read instead of a full object re-read — a concrete advantage over the POSIX backend's xattr scheme, which depends on filesystem xattr support and on the checksum having been computed at some earlier point. Because the digests belong to the *version* rather than the path, an overwrite cannot leave a stale checksum behind the way an mtime-validated xattr cache can. Naming and encoding come from `local_cache/checksum_format.go`, so the origin cannot report a different string than the cache would for the same bytes.

The checksummer is selected by the storage-type switch that builds each export's backend in `origin_serve/handlers.go`; `pstoreBackend.Checksummer` returns `pstoreChecksummer`, and the POSIX backend's xattr scheme is not involved.

### 11.2 fsck

`Store.Fsck` (`pstore/fsck.go`) walks the index rather than the storage directories, so it is bounded by the number of objects rather than by their size, and it reports before it repairs.

**It is streaming and bounded in memory, deliberately.** A consistency check that needs the whole index resident is a check that stops being runnable exactly when a store gets big enough to need one. So neither the scan nor the comparison holds a whole-index view: `scanIndexBatched` and `scanMetadataHashes` reopen a read transaction every few thousand keys rather than pinning one for the duration — which also keeps a long check from holding back BadgerDB's compaction — and the one comparison that genuinely needs a set in memory, "which object versions does no entry refer to", is partitioned over hex prefixes of the instance-hash space against a **memory budget** rather than against the object count. A store too large for one pass degrades in scan time, not in footprint. The partitioning is exposed as an option, which is what lets the hourly scheduled check rotate through a fraction of the keyspace per pass (§11.3) instead of choosing between full coverage and affordability.

It checks:

- every dirent's generation resolves to an `m:` record whose write completed; an entry with no metadata is *dangling*, and one whose `Completed` is zero is an *incomplete write*;

- every `m:` record is reachable from `pd:` — the index walk builds the set of reachable `instanceHash`es and a metadata scan diffs the catalog against it. (Reachability is computed from generations, not from any recorded path: `pstore` writes no `SourceURL`, and there is no reverse mapping from an instance back to a path.)

  **Unreachable is not the same as abandoned**, and conflating the two would make fsck delete live uploads. A version that a write is building right now is also unreachable from the index — the dirent does not exist until commit. Three conditions must therefore all hold before a version is called an orphan: it is not on the `pg:i:` reclamation queue, it has no `aw:` append intent recorded against it, and its `Completed` timestamp is non-zero and older than `MinAge` (default five minutes; `FsckNoGracePeriod` waives it for tests and for an operator who has stopped the origin). Anything that fails only the age or intent test lands in a separate **`PendingInstances`** bucket, which is reported and **never repaired** — the honest answer for "this looks unreferenced but may simply be young".

  Note also that `pg:i:` now carries two meanings: as well as versions awaiting reclamation, an entry may be a tombstone for a write still in flight. Consumers of that queue must respect reader pins and re-read state rather than assuming an entry is safe to free on sight.

- orphans are enqueued on `pg:` when repairing, rather than deleted inline, so reclamation goes through the one path that respects reader pins.

- usage counters agree with reality. This deliberately does **not** use `CacheDB.ComputeActualUsage`: that sums raw `ContentLength`, whereas the counters are charged `CalculateFileSize` — the on-disk size including each block's authentication tag. Comparing the two reports phantom drift of exactly the MAC overhead on every healthy store. fsck instead totals `CacheMetadata.PerDirectoryBytes`, which yields the same quantity the counters hold and is what the write and reclaim paths already use.

- with `--deep`, stored checksums are verified against the data, through `local_cache.ConsistencyChecker.VerifyObject`. This is the only check that detects at-rest corruption, because everything else reads only the catalog.

`--repair` unlinks dangling entries, queues orphans for the janitor, and corrects the catalog's usage counters before reseeding the in-memory ones from them. `PendingInstances` is never acted on.

fsck is a backstop, not a load-bearing part of correctness: every mutation that makes data unreachable also queues it for reclamation in the same transaction.

### 11.3 Scheduled integrity checks

`pstore/integrity.go` runs two passes on independent schedules, because they cost very different amounts:

| Pass        | Parameter                         | Default | Cost                   |
| ----------- | --------------------------------- | ------- | ---------------------- |
| Index check | `Origin.PStoreIndexCheckInterval` | 1h      | catalog only           |
| Data scan   | `Origin.PStoreDataScanInterval`   | 24h     | reads every block back |

`Origin.PStoreDataScanRate` (default 100MB/s) caps the verification read rate so the scan does not compete with serving. Zero disables either pass.

Both intervals are a **minimum gap between the end of one pass and the start of the next**, not a fixed cadence. A data scan of a large store can legitimately take longer than its own interval, and a ticker would then start the next pass the moment the previous one finished, verifying continuously. A pass that outlasts its interval is logged at warn level so the operator can see that the configured frequency is not achievable at this store's size.

The index check is `Fsck` in report-only mode; findings are logged at error level, because an inconsistent index means some object is either unreachable or holding space nothing accounts for. Because the orphan comparison is the expensive part (§11.2), the hourly check rotates through **one sixteenth of the instance-hash space per pass**, so the whole store is covered roughly daily at a fraction of the memory a single full pass would need — full coverage over time rather than a choice between full coverage and affordability. The data scan reuses the cache's `ConsistencyChecker.RunDataScan` for the reading and rate limiting, and reports how many objects *this pass* found mismatching (the checker's statistics are cumulative, so the count is taken as a difference).

**Neither pass modifies anything, and for a pstore that is not a tuning choice but a correctness requirement.** This is the sharpest example of why a cache's integrity machinery cannot simply be reused by an origin. The cache's scan **deletes** an object whose data no longer matches its checksums, and for a cache that is not merely acceptable but correct: the next request re-fetches it and the object is repaired. An origin has no upstream, so the identical code path destroys the only copy — and with it the only record of the object's path, size, and checksums, after which `fsck --repair` would reclassify the surviving entry as dangling and remove that too. One flipped bit would become two deletions and a silently shorter namespace.

The behavior is therefore pinned in code rather than by convention: `ConsistencyConfig.PreserveCorruptObjects` keeps the corrupt object, and `SkipChecksumBackfill` suppresses the one other write the scan would make (recording checksums for an object that has none). Both are set centrally by `newPStoreScanConfig`, which exists as a function rather than a literal at each call site precisely so that a future caller cannot forget them. The cache's own behavior is unchanged — it still deletes and re-fetches, because that is right for a cache.

Repair stays a deliberate operator action through `pelican-server origin pstore fsck --repair`, because the right response to a corrupt object is a judgement call — restore it, re-ingest it, or accept the loss — and not one a background task should be making at three in the morning.

### 11.4 Metadata backup and restore

For a cache, losing the database is an inconvenience: every object in it can be fetched again. For an origin it is data loss. The block files are named by hash and encrypted, and everything needed to interpret them — the namespace, each object's data key, its size, its checksums — lives in the catalog. A store whose catalog is gone is a directory of unreadable bytes.

So the catalog is backed up separately from the data, and far more often than its size would suggest is necessary. It is small (megabytes against terabytes of objects) and BadgerDB can stream a consistent snapshot of it at a fixed read timestamp while the origin is running, so a periodic backup costs almost nothing and is coherent even while writes continue.

**Every backup is complete.** BadgerDB can emit only what changed since a given version, but a base-plus-incremental chain is unrestorable here: `Restore` refuses a store that already holds objects, which is exactly what applying an increment on top of a base would require. An incremental that cannot be restored is not a backup, so there is no incremental mode. The catalog is small enough that this costs little.

**Scheduling.** `Store.StartBackups` (`pstore/backup.go`) writes a timestamped file into `Origin.PStoreMetadataBackupLocation` and prunes the oldest beyond `Origin.PStoreMetadataBackupsToKeep` (default 24). `Origin.PStoreMetadataBackupInterval` (default 6h) is measured **from the end of one snapshot to the start of the next**, not as a fixed cadence: a snapshot of a large catalog can take a while, and a fixed ticker would start the next one the moment a slow pass finished, leaving the origin snapshotting continuously. A pass that outlasts its own interval is logged at warn level, which is the operator's signal that the interval is tighter than the store's size allows. The interval is spaced rather than hourly because a snapshot is not merely a list of names: objects below `Origin.PStoreInlineMaxBytes` live in the catalog itself (§5.3), so a store holding many small objects has a catalog with all of their *contents* in it, and every snapshot is complete rather than incremental. Retention multiplies whatever that costs. Keeping several allows rolling *back* to a point before a corruption rather than only forward from the most recent. Each pass writes to a `.partial` name and renames on success, so a crash mid-write never leaves a truncated file that looks usable. A failed pass is logged and retried at the next interval: a backup problem must not take the origin down. An empty location disables the whole thing.

**Encryption is unconditional.** BadgerDB's backup is a *logical* dump: values come back decrypted, so a raw snapshot is cleartext. It contains every object path, all the metadata, and the hash salt that makes on-disk filenames unguessable — writing that to a backup directory would undo the at-rest protection the store exists to provide. `pstore/backup_crypto.go` seals every snapshot with AES-256-GCM, and there is no code path that writes one any other way: `Store.BackupEncrypted` is the only exported writer, and it fails when it has nothing to seal to. An earlier design made encryption conditional on the operator having created a key and warned at startup when they had not; a startup warning is the weakest possible control for a file that leaks the whole namespace, and the failure it guards against is silent and permanent.

**There are three levels of key, and any one of them opens an archive.** That is the shape of the scheme, and it exists because a recovery happens on whatever the operator still has, which cannot be known when the backup is written.

| Level | What it is                                | Where it comes from                                                                                          | What it opens                |
| ----- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------- |
| 1     | The origin's **issuer keys** (the master) | Already on the origin; nothing to create                                                                     | Everything this origin wrote |
| 2     | The **backup key** (the intermediate)     | `HKDF-SHA256(issuer key PKCS8, info = LabelPStore)`                                                          | Everything this origin wrote |
| 3     | The **per-file key**                      | `HKDF-SHA256(ikm = backup key, salt = the file's salt, info = "pelican pstore metadata backup file key v1")` | Exactly one archive          |

**Level 2: the backup key.** `backup_keys.DeriveKeyPair` runs HKDF-SHA256 over the PKCS8 encoding of an issuer JWK and reads out a Curve25519 private key; `ScalarBaseMult` gives the public half. The info string is the *label*, which is the whole point of the shared package: `backup_keys.LabelPStore` (`pelican-pstore-backup`) and `backup_keys.LabelDatabase` (`pelican-backup-encryption`) derive unrelated keys from the same issuer key, so escrowing a pstore backup key with a custodian does not also hand them the server database's backups, and vice versa. `LabelDatabase` is frozen — it is baked into every database backup ever written — and `backup_keys` carries a known-vector test asserting so, because a refactor that changed the derivation would round-trip perfectly through its own tests while making every existing archive undecryptable.

The derivation is one-way, so a leaked backup key does not yield the issuer key behind it.

**Level 3: a key per archive.** The body is encrypted under a key belonging to that snapshot alone: HKDF-SHA256 over the backup key, salted with 32 random bytes drawn for that snapshot and stored in its header, under an info label distinct from the one that produced the backup key so the two levels are domain-separated. This is what makes it possible to hand out *one* backup. Giving somebody the level-2 key gives them the whole series; giving them a file's own key gives them that file, and reveals nothing about any other — the salts are independent, and HKDF is one-way in the input key material.

It is also what keeps the nonce safe. With a key unique per archive the chunk nonce only has to be unique *within* one, so it can be a pure counter.

**The backup key travels inside the archive, encrypted.** Each recipient gets its own envelope block — a NaCl box, sealed to itself so the private key alone opens it — carrying the archive's backup key, and any one of them opens it. This is the same multi-recipient shape `database/backup.go` uses, and it is what makes **key rotation free**: an archive written while an old and a new key were both live still opens after the old one is retired, and an archive written before the new key existed is still opened by the old one wherever it survives. When nothing available opens an archive, `pstore.ErrNoMatchingKey` reports the key IDs it *was* sealed to, which is the only thing that tells an operator what to go and find.

The archive's backup key is the one derived from the first issuer key in sorted order, and it is itself one of the recipients. That detail makes the level-2 recovery path uniform: whichever escrowed backup key an operator produces, it opens *its own* envelope block, which yields the archive's backup key, which derives the per-file key. When the key produced happens to be the archive's own, that block hands it straight back — so there is one code path rather than a special case for "the operator has the right one of several backup keys".

**The three ways in**, all exercised independently by `TestThreeWaysToOpenASnapshot`:

```
an issuer key   → derive its key pair → open the envelope → the backup key
                  → HKDF with the salt in the header → the per-file key → decrypt
a backup key    → open the envelope with it → the archive's backup key
                  → HKDF with the salt in the header → the per-file key → decrypt
a per-file key  → decrypt.  No derivation, no envelope, no issuer key present.
```

**Disaster recovery, and handing out one archive.** `pelican-server origin pstore metadata-backup-key` re-derives and prints a key rather than generating one, so running it twice on the same origin prints the same answer and an operator can file it away. With no argument it prints the **level-2 backup key**, whose 32 bytes restore any backup on a machine that has never held this origin's issuer keys (`pstore metadata-restore --key-file`). That answers the objection that motivated the original design: a backup outlives the machine it came from and usually leaves it, so it must not depend on keys that live only on that host. Deriving rather than generating gets that property *and* removes the secret an operator could fail to create.

Given a **backup file**, the same command instead prints **that file's own key**: it reads the salt out of the named file and re-derives level 3, using the origin's issuer keys or — with `--key-file` — an escrowed backup key, so an operator holding only the escrowed key can still produce a specific file's key without the issuer keys ever being present. `pstore metadata-restore --file-key` consumes it. The two forms are deliberately hard to confuse: the output on stderr says which key it just printed and what that key does *not* open, because handing over the backup key when one file's key was meant is a silent over-disclosure of the whole series.

There is deliberately **no configuration knob for the backup key**. The hierarchy leaves nothing for one to do: the escrowed level-2 key covers custody off the host, and the level-3 key covers giving a single archive away. A standing parameter would only add a second place for a secret to be mislaid. `pelican-server origin pstore metadata-backup --key-file` seals a one-off archive to a supplied key, which is an explicit operator action rather than configuration.

Object *contents* are not exposed by any of this — each object's data key is stored already wrapped by the master key, so the block files stay protected even if a snapshot leaks. The namespace is what needs covering.

**Format.** The snapshot is **compressed and then sealed**, which is the only order that works: ciphertext is incompressible, so compressing afterwards would achieve nothing, and a catalog of repetitive path strings and structurally similar records compresses extremely well. (The usual objection to compress-then-encrypt is a length side channel under adaptively chosen plaintext; a snapshot is written once, from data the attacker does not control interactively, with no oracle to query.)

The file begins with a **versioned magic header** (`PELICAN-PSTORE-BACKUP\x00` plus a version byte, currently `\x01`), so a file that is not a snapshot, or is in a version this build does not read, is refused with something better than a decryption failure — the family prefix is matched rather than the exact version, so a snapshot whose version this build does not read is refused by number instead of being called corrupt. The magic is followed by the **32-byte salt** and then the **recipient envelope**: a count, and per recipient a key ID and the sealed backup key.

The body is a sequence of sealed fixed-size chunks, each carrying its sealed length. Every chunk is bound to its position by the counter in its nonce and to *this* archive by the **whole header — magic, salt, and every envelope block — passed as additional authenticated data**; the terminating chunk is marked in both the framing and the nonce. So reordering, dropping, truncating, or splicing chunks between archives is detected rather than silently producing a short restore; the salt cannot be swapped, which would otherwise silently change which key the file claims to want; and recipients cannot be stripped, added, or lifted from another archive. `TestHeaderIsBoundToTheBody` splices each of those three regions between two same-shaped archives and requires every one to be refused. Chunking keeps memory flat for a snapshot of any size; the snapshot is piped from BadgerDB through the compressor to the sealer rather than buffered.

One container version exists. The version byte is carried anyway so that a future format change has a mechanism already in place: a file whose version this build does not read is refused by number rather than decoded, which `TestAnUnsupportedFormatVersionIsRefused` pins along with the agreement between the magic's trailing byte and `backupFormatVersion`.

**Restore.** `Store.Restore` is the single entry point for every archive the project has written, sealed or not: it reads the container from the file's own magic, so an operator never has to know which release produced the snapshot they are holding. It refuses a store that already holds objects: restoring over live records would interleave two namespaces rather than replace one. **The store must be reopened afterwards** — a restore replaces the whole database, including everything a store reads once at open and then caches: the hash salt every instance hash is derived from, and the storage-ID-to-directory mapping. `Restore` calls `ReloadSalt` and rebuilds the detached set so that a caller inspecting the namespace immediately afterwards sees the right thing, but reading object data requires a fresh open.

**A failed restore is not a no-op, and cannot be unwound.** BadgerDB's loader writes as it reads, so a snapshot that turns out to be damaged part-way through leaves records in the directory *and* leaves the transaction watermark short of the timestamps it already wrote — so the handle blocks on the next read and the directory holds a fragment of a namespace. Nothing in `pstore` can undo either. What it can do is say so: the error tells the operator that the directory must be **discarded** and the restore started again into a fresh one, rather than letting a retry into the same directory build a chimera out of two catalogs. This is also the reason both containers verify eagerly — most damage is caught before a single record is written, and damage caught late at least reports what state it left behind. An operator should know this *before* a recovery, not during one.

**A backup is only useful alongside two other things**, and the CLI and parameter documentation both say so rather than letting an operator discover it during a recovery:

- the **block files**, which ordinary filesystem backup tools handle; and
- **`masterkey.json`** in the store directory, which wraps the key everything is encrypted under. It is itself encrypted under the origin's issuer keys, so those must survive too.

The normal recovery is therefore: restore a metadata backup into a fresh directory that already holds the block files and `masterkey.json`, then point the origin at it — or export from it (§11.5).

### 11.5 Recovery export

A store is not something an operator can read with ordinary tools, so the recovery path is part of the product rather than an exercise left to whoever is having the bad day. `Store.Export` (`pstore/recover.go`), driven by `pelican-server origin pstore export --to <dir>`, writes a subtree out as plain files in a normal directory tree: no Pelican, no origin, no client, just the data.

It runs against a store opened for maintenance (§11.6), pages through listings rather than materialising them, and **continues past objects it cannot read**, collecting them in a report — on a damaged store, recovering most of the data and being told exactly what was lost is far more useful than stopping at the first bad block. `--verify` checks each object against its recorded checksums as it is written, so a recovery does not quietly reproduce corrupt data; `--dry-run` reports what would be written. Destinations are created exclusively, so a recovery never silently overwrites what is already there, and every destination path is re-checked against the export root, because a recovery may be run against a damaged or hand-edited catalog.

### 11.6 Introspection: offline CLI and live API

There are two, because they answer different questions.

**Offline.** `pstore.OpenMaintenance` (`pstore/maintenance.go`) backs `pelican-server origin pstore {ls, stat, du, fsck, digest, metadata-backup, metadata-restore, export}`. The origin must be stopped: BadgerDB takes a directory lock on open, and a consistency check racing a live origin's writes would not mean anything. When writes are not allowed, every mutating entry point refuses in Go, so an inspection command cannot modify the store even by mistake. This deliberately does not use BadgerDB's `ReadOnly` mode — that takes a shared flock rather than an exclusive one, which buys no concurrency against a running origin, fails outright on some platforms, and would block `fsck --repair`.

An inspection command takes a read-only mode check that never writes and so never adopts an unmarked database: a CLI pointed at the wrong directory should say so rather than claim it.

**Live.** Because the database holds an exclusive lock while the origin runs, "what is in there right now" can only be answered by the running process. `origin_serve/storage_api.go` mounts, under `/api/v1.0/origin/storage/pstore`, four **administrator-only** routes: `ls/*path`, `stat/*path`, `digest/*path`, and `usage`. `cmd/origin_introspect.go` is the client (`pelican-server origin introspect …`).

The path is chosen so the scope is obvious: this describes the storage backend, not the origin's role in a federation. Nothing here serves objects, participates in discovery, or is reachable by a federation client. Registering nothing at all when the backend is not a pstore is deliberate — a 404 tells an operator that this origin has no such interface, which is better than a route that exists and always fails.

Only operations that are meaningful against a moving target are exposed. Listing, stat, usage, and digests all describe a moment and are honest about it. A consistency check is not: scanning an index while it is being rewritten produces findings indistinguishable from real ones, so fsck stays offline where its answers mean something. Repair is likewise absent — changing a store underneath a running origin is not something to offer over HTTP.

### 11.7 Metrics

The collectors live in `metrics/pstore.go`, `promauto`-registered at init like the rest of the package, and are fed from `pstore` at the points below. Registration is process-wide, which is what makes it safe for several exports to share one store — they do — and for a process to run both a cache and an origin.

There is deliberately no `store` label. `Origin.PStoreLocation` is a single process-wide parameter, so a server process has exactly one store; the offline CLI opens its own, in a process nothing scrapes. Storage directories are owned exclusively by one store, so the `directory` label is unambiguous regardless.

| Metric                                                                                                                                                                                                   | Type          | Fed from                                               |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------------------------------------------------------ |
| `pelican_pstore_used_bytes`, `pelican_pstore_limit_bytes`                                                                                                                                                | gauge         | `Store.Open`, then every janitor sweep                 |
| `pelican_pstore_directory_used_bytes{directory}`, `pelican_pstore_directory_limit_bytes{directory}`                                                                                                      | gauge         | the same, per storage directory plus `(inline)`        |
| `pelican_pstore_objects`                                                                                                                                                                                 | gauge         | the index check's entry walk                           |
| `pelican_pstore_scheduled_passes_total{pass}`, `..._pass_failures_total{pass}`, `..._pass_last_success_timestamp_seconds{pass}`, `..._pass_last_duration_seconds{pass}`, `..._pass_overruns_total{pass}` | counter/gauge | `passObserver`, around all three scheduled loops       |
| `pelican_pstore_metadata_backup_last_size_bytes`                                                                                                                                                         | gauge         | `snapshotOnce`, after the rename publishes             |
| `pelican_pstore_data_scan_mismatches_total`, `..._objects_total`, `..._bytes_total`                                                                                                                      | counter       | the checker's stats, differenced per pass              |
| `pelican_pstore_fsck_findings{kind}`                                                                                                                                                                     | gauge         | end of every `FsckWith`                                |
| `pelican_pstore_reclamation_pending{kind}`, `pelican_pstore_detached_subtrees`                                                                                                                           | gauge         | the janitor, once per resting interval                 |
| `pelican_pstore_reclaimed_objects_total`, `..._bytes_total`, `pelican_pstore_abandoned_writes_reclaimed_total`                                                                                           | counter       | each `RunGC` sweep                                     |
| `pelican_pstore_writes_total{tier}`                                                                                                                                                                      | counter       | `WriteHandle.Close`, from the tier `materialize` chose |
| `pelican_pstore_write_failures_total{reason}`, `pelican_pstore_write_conflict_retries_total`                                                                                                             | counter       | `HasCapacityFor`, `ensureReserved`, `install`          |

Four constraints shaped this, and they are worth stating because they are what a future addition has to respect.

**A gauge describes a level, so it must be right after a restart rather than after the first event.** The capacity gauges are published at the end of `Store.Open`, from the figures `newCapacityTracker` has just recovered from the catalog. Left to the write path they would read zero for however long it took the next PUT to arrive — precisely the window in which somebody restarting a full origin looks at the dashboard.

**Nothing is measured on a serving path, and nothing is measured with a syscall.** The capacity gauges are republished by the janitor, which runs whether or not anything is happening, so an idle store stays current and a busy one pays nothing; `chooseDir` and the reservation fast path are untouched. The one measurement that is not already in memory is the reclamation backlog, a keys-only scan of the `pg:` prefix — free on a healthy store, proportional to the backlog on a sick one, which is exactly the case that also makes the janitor sweep four times a second. So it is rate-limited to the resting interval rather than taken per sweep, and the gauge is at most that stale.

**The queue depth is counted to the end.** `collectGarbage` stops at `janitorBatchSize` because it holds what it collects; `queueDepth` holds nothing and reports the real number. A count saturating at the batch size would make a queue of half a million look identical to a stable one of five hundred — the two cases the gauge exists to tell apart.

**Failure to observe is never failure to serve.** A backlog measurement that errors leaves the gauge at its previous value rather than publishing a zero that would read as "the backlog cleared", and logs at debug.

**The `pelican_cache_data_scan_*` overlap is resolved at the source.** pstore's scheduled data scan is `local_cache.ConsistencyChecker.RunDataScan`, which is also the cache's, so an origin used to report its integrity scan under cache-named series — and a process running both added the two together with no way to separate them. `ConsistencyConfig.SuppressCacheMetrics`, set by `newPStoreScanConfig`, stops the checker from touching those collectors; the checker's own `ConsistencyStats` are unaffected, and `observeDataScan` differences them into `pelican_pstore_data_scan_*` at the end of each pass. Nothing is counted twice, and nothing is lost except granularity: the cache updates its counters after every object, while these step once per completed pass. `pelican_pstore_scheduled_pass_last_success_timestamp_seconds{pass="data_scan"}` is what says a pass is in progress or stuck.

Two label sets are narrower than they look, on purpose. `pelican_pstore_fsck_findings` is one gauge per class rather than one series per finding: the findings are paths, and a store with a hundred thousand dangling entries would otherwise put a hundred thousand series into the registry at the moment it can least afford it. And within that family, `orphaned_instances` and `pending_instances` are per *examined slice* of the instance-hash space, not store-wide totals, because the scheduled index check covers one sixteenth per pass to bound its memory (§11.3); publishing them only from an exhaustive pass would leave them frozen forever in a server process.

## 12. Path case sensitivity

Object paths are case-sensitive. `/ns/Data.txt` and `/ns/data.txt` are different objects, on every backend Pelican serves and therefore here.

This is easy to get wrong in a hashing layer: case-folding the whole URL collapses two case-variant paths onto one cache entry, and a request for either returns whichever was fetched most recently. Only the scheme and host may be folded — those are case-insensitive per RFC 3986 §6.2.2.1 — and the path never. The host folding is IDNA rather than a plain lowercase, so an internationalized name hashes the same however it is spelled; see §10.

`pstore` is structurally immune to a repeat, because an object's storage key derives from its generation rather than its path (§5); a path only ever indexes an entry. But `validatePath` and the key encoding still assume exact bytes, so any future normalization added to the index must fold nothing in the path.

## 13. Configuration

New storage type `pstore`:

- `server_structs.OriginStoragePStore` added to `ParseOriginStorageType`.
- `UsesXRootD()` returns false.

### 13.1 `SupportsSelfTest()`

`SupportsSelfTest()` (`server_structs/origin.go`) gates the origin's write-read self-test probe. It has exactly two non-test call sites, and both are that probe:

- `config/config.go` — disables `Origin.SelfTest` and `Origin.DirectorTest` at startup for backends that cannot accept it.
- `director/director.go` — forces `DisableDirectorTest` on the advertised ad for the same reason.

It returns true for `posix`, `posixv2`, and `pstore`. The probe writes a small object and reads it back, which needs a local writable backend, not a POSIX one — which is why the predicate is named for what it decides rather than for a family of backends. `server_structs/origin_test.go` pins the truth table.

Two adjacent gates are separate and unaffected:

- **Atomic uploads (POSC)** gate on a direct `ost != OriginStoragePosix` equality in `config/config.go`. `pstore` is correctly rejected there, and that is the desired outcome — `pstore` has native atomic overwrite (§6) and must not use the rename-based POSC machinery.
- **The xattr checksummer** is not gated by a predicate at all; it is selected by the storage-type switch that picks `newLocalBackend` in `origin_serve/handlers.go`. `pstore` supplies its own checksummer (§11.1).

### 13.2 Parameters

Added to `docs/parameters.yaml`, with the generated param files regenerated:

| Parameter                             | Meaning                                                         |
| ------------------------------------- | --------------------------------------------------------------- |
| `Origin.PStoreLocation`               | Store root: catalog, and data unless `PStoreStorageDirs` is set |
| `Origin.PStoreStorageDirs`            | Multi-directory form; same schema as `LocalCache.StorageDirs`   |
| `Origin.PStoreInlineMaxBytes`         | Inline-vs-disk threshold (§6.1)                                 |
| `Origin.PStoreMetadataBackupLocation` | Directory receiving scheduled metadata backups (§11.4)          |
| `Origin.PStoreMetadataBackupInterval` | How often a metadata backup is written                          |
| `Origin.PStoreMetadataBackupsToKeep`  | Retention count, oldest pruned first                            |
| `Origin.PStoreIndexCheckInterval`     | Scheduled catalog-only consistency check (§11.3)                |
| `Origin.PStoreDataScanInterval`       | Scheduled read-back verification of every object                |
| `Origin.PStoreDataScanRate`           | Read rate cap for the data scan                                 |

There is no total-size or reserved-space parameter: capacity comes from the per-directory `MaxSize` values in `Origin.PStoreStorageDirs` (§7).

Either `Origin.PStoreLocation` or `Origin.PStoreStorageDirs` must be set when the storage type is `pstore`; `PStoreOrigin.validateExtra` refuses the configuration otherwise. Export configuration lives in `server_utils/origin_pstore.go`, following `origin_s3v2.go`. `StoragePrefix` defaults to `/` and is validated as a logical path only.

## 14. Testing

- **Unit** — index operations and key ordering (`pstore/index_test.go`), namespace operations and pagination (`store_test.go`), the write tiers, conditional writes, abort, rename, detached subtrees and recreation while draining (`object_io_test.go`), the afero adapter including `Readdir` pagination and `Stat` on an open write handle (`fs_test.go`), capacity and `ENOSPC` including per-directory placement (`capacity_test.go`), ingest checksums and fsck against deliberately corrupted state (`checksum_fsck_test.go`), offline maintenance (`maintenance_test.go`), and backup, restore, retention, and export (`backup_test.go`).
- **`local_cache`** — `append_writer_test.go` covers the streaming writer including over-allocation refund; `pin_test.go` covers reader pinning and the eviction skip; `schema_test.go` pins the case-sensitivity fix.
- **`origin_serve`** — `backend_pstore_test.go` covers serving through WebDAV, PROPFIND, storage prefixes, parent auto-creation, capacity reporting, and `ENOSPC` → 507; `storage_api_test.go` covers the live API including admin gating; `preconditions_test.go` covers conditional-write parsing.
- **Concurrency** — `TestConcurrentWritesStayWithinTheCeiling` (sixteen in-flight writers against a bounded store, checking the reservation accounting never lets the ceiling be crossed and never leaks a reservation), `TestConcurrentOverwriteAndOpenNeverFailsSpuriously` (two thousand opens against a live overwriter with the janitor running — the pin/GC race), and `TestConcurrentWritesToOnePathElectOneWinner` (eight racing writers, exactly one winner) in `pstore`; `TestConcurrentConditionalWritesElectOneWinner` and `TestConcurrentCreateOnlyPutsElectOneWinner` in `origin_serve`, which exercise the same property through the WebDAV handler. `TestReaderSurvivesOverwrite` and `TestGCReclaimsSupersededVersionOnceUnpinned` cover the sequential forms.
- **Reuse** — `origin_serve/pstore_serving_test.go` and `origin_serve/storage_api_authz_test.go` drive `pstore` through the origin's real serving and authorization stack. The pre-existing `directory_listing_test.go` and `path_traversal_test.go` suites are still **not** wired to `pstore`; `pstore` has its own path-constraint tests (`TestValidatePath`, `TestCleanRelative`, `TestSiblingPrefixIsolation`), so this is redundancy not yet taken rather than a gap in coverage.
- **e2e** — `e2e_fed_tests/pstore_test.go` runs a federation with `Origin.StorageType: pstore` covering upload, download, an object past the spill threshold, overwrite, stat, list, and delete through the Pelican client.

## 15. Follow-on design needed

**Lot bootstrapping.** Before path-based quotas can be enforced, a separate design has to settle how lots are created for an existing store, how they map onto exports and federation prefixes, what happens to paths covered by no lot, and whether ancestor byte accounting is maintained synchronously by `pstore` or owned by LotMan. `lotman` being Linux-only (§7.2) belongs to that design too.
