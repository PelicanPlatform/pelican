/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

// Storage cache: a webdav.FileSystem layer that keeps a local-disk copy of
// objects fetched from a remote origin backend (S3/blob, HTTPS, Globus).
//
// The cache exists to avoid repeated egress from the remote provider: an
// origin physically located outside the provider (e.g. outside AWS) pays for
// every byte read from the backend, so a large local disk can absorb repeat
// reads.
//
// Freshness follows the standard Cache-Control rules (see the cache_control
// package, shared with the Pelican local cache): the backend's own
// Cache-Control — an S3 object's metadata or an HTTPS response header —
// governs how long a copy may be served with no upstream interaction at all.
// When the backend supplies no directives, Origin.StorageCacheDefaultMaxAge
// applies, jittered per object.  That same setting also caps how much
// freshness a backend may claim for itself, so whoever can write an object's
// metadata cannot pin it in the cache indefinitely.  Only once a copy goes
// stale does the layer revalidate: one upstream stat compares validators, and
// a match renews the freshness window without refetching.  no-store / private
// responses bypass the cache; no-cache responses are cached but revalidated on
// (almost) every use.
//
// Fetches are decoupled from the requesting client: the upstream-to-disk copy
// runs in its own goroutine at full speed, while the client reads from the
// growing local file at its own pace.  A slow or disconnected client never
// stalls (or cancels) the fetch, so the cache still ends up with a complete
// copy that later readers reuse.  Concurrent readers of the same object share
// a single upstream fetch.
//
// Two access patterns deliberately opt out of that copy, because for them it
// would cost far more egress than it saves:
//
//   - Content-type sniffing.  net/http's ServeContent reads the first few
//     hundred bytes of a file purely to guess a MIME type, and does so even
//     for a HEAD request.  A reader whose last handle closes without having
//     read past that prefix retires the copy instead of finishing it, so a
//     HEAD costs a brief partial read rather than the whole object.  (The
//     WebDAV PROPFIND handler sniffs the same way, but asks the FileInfo for a
//     content type first; this layer answers, so a listing never opens its
//     entries at all.)
//   - Forward seeks past what the copy has written (i.e. range requests).
//     Waiting for a sequential copy to reach the requested offset would turn a
//     small ranged read into a whole-object transfer, so those reads go
//     directly to the backend, and a range request on its own does not start a
//     copy.
//
// The layer is a performance optimization, never a dependency: when the cache
// disk is full, unwritable, or already saturated with concurrent fetches,
// requests fall through to the backend instead of failing.
package origin_serve

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/cache_control"
	"github.com/pelicanplatform/pelican/server_utils"
)

const (
	// storageCacheEvictTargetNum/Den give the fraction of the configured
	// maximum size that eviction drives usage down to once the maximum is
	// exceeded (9/10 = 90%).
	storageCacheEvictTargetNum = 9
	storageCacheEvictTargetDen = 10

	// storageCacheJanitorInterval is how often the eviction and orphan
	// reclamation passes run.
	storageCacheJanitorInterval = time.Minute

	// storageCacheCopyBufSize is the buffer used for the upstream-to-disk copy.
	storageCacheCopyBufSize = 1 << 20

	// storageCacheSniffLen matches net/http's sniffLen: the number of bytes
	// ServeContent and the WebDAV PROPFIND handler read to guess a
	// Content-Type.  Reads no larger than this at offset zero are treated as
	// content sniffing rather than as the start of a transfer.
	storageCacheSniffLen = 512

	// storageCacheStallTimeout is how long a fetch may make no progress before
	// it is abandoned.  Without it a hung backend connection would wedge the
	// object for every subsequent reader, since they all coalesce onto the
	// in-flight fetch.
	storageCacheStallTimeout = 5 * time.Minute

	// storageCacheStallCheckInterval is how often the stall watchdog samples
	// a fetch's progress.
	storageCacheStallCheckInterval = 30 * time.Second

	// storageCacheOrphanGrace is how old a data file with no sidecar must be
	// before a periodic sweep reclaims it.  The grace period keeps the sweep
	// from racing a fetch that was registered after the sweep listed the tree.
	storageCacheOrphanGrace = time.Hour

	// storageCacheEnumerationCap bounds the object list a directory mutation
	// buffers while unrolling a subtree invalidation, and
	// storageCacheMaxEnumDepth bounds how deep the walk recurses.  Beyond
	// either, invalidation falls back to the sidecar scan: at that scale the
	// mutation itself dwarfs a pass over the cache, and the scan needs no
	// per-path memory.
	storageCacheEnumerationCap = 65536
	storageCacheMaxEnumDepth   = 64
)

// storageCacheDataFileRe matches the data-file names this layer generates,
// "<64 hex path hash>-<16 hex generation>.data".  A sidecar's DataFile field
// is read back from disk and used as a path component, so it is validated
// against this pattern rather than trusted: a hand-edited or corrupted sidecar
// must not be able to name a file elsewhere in the cache tree.
var storageCacheDataFileRe = regexp.MustCompile(`^[0-9a-f]{64}-[0-9a-f]{16}\.data$`)

// cacheEntryMeta is the JSON sidecar recorded next to each cached data file.
// Its presence marks the data file as complete; it is written only after the
// full object has been copied from the upstream backend.  The sidecar's file
// mtime doubles as the entry's last-access time for LRU eviction.
type cacheEntryMeta struct {
	// Path is the object path within the export.  It identifies the entry for
	// subtree invalidation, and seeds the per-object freshness jitter.
	Path string `json:"path"`
	// Validator is the value compared against the upstream's current
	// validator to decide whether the copy is still current.
	Validator string `json:"validator"`
	// ETag is the client-visible upstream ETag, empty when the upstream did
	// not expose one to clients (in which case the webdav default, derived
	// from the preserved size and mtime, applies — exactly as it would for an
	// uncached read of the same backend).
	ETag string `json:"etag,omitempty"`
	// CacheControl is the backend's raw Cache-Control value for the object,
	// captured at fetch/revalidation time; it governs how long the copy is
	// fresh (empty means the configured default policy applies).
	CacheControl string `json:"cacheControl,omitempty"`
	// LastValidatedUnixNano records when the copy was last confirmed current
	// (at fetch completion or by a successful revalidation).  Freshness is
	// measured from this instant.
	LastValidatedUnixNano int64 `json:"lastValidatedUnixNano"`
	// Size and ModTimeUnixNano preserve the upstream object metadata so
	// responses served from the cache are indistinguishable from responses
	// served from the backend.
	Size            int64 `json:"size"`
	ModTimeUnixNano int64 `json:"modTimeUnixNano"`
	// DataFile is the base name of the entry's data file, in the same
	// directory as the sidecar.  See storageCacheDataFileRe.
	DataFile string `json:"dataFile"`
}

func (m *cacheEntryMeta) fileInfo(name string) *cachedFileInfo {
	return &cachedFileInfo{
		name:    path.Base(name),
		size:    m.Size,
		modTime: time.Unix(0, m.ModTimeUnixNano),
		etag:    m.ETag,
	}
}

// valid reports whether a sidecar read back from disk is self-consistent
// enough to serve.  Anything else is treated as a miss and refetched.
func (m *cacheEntryMeta) valid() bool {
	return m.Size >= 0 && storageCacheDataFileRe.MatchString(m.DataFile)
}

// ---------------------------------------------------------------------------
// storageCache — shared manager for the on-disk cache
// ---------------------------------------------------------------------------

// storageCache owns the cache directory tree, the in-flight fetch registry,
// and the eviction janitor.  A single instance is shared by every export's
// caching layer so the configured size bound applies to the tree as a whole.
type storageCache struct {
	fs      afero.Fs
	ctx     context.Context // server-lifetime context bounding detached fetches
	maxSize int64           // 0 or negative means unbounded

	// policy is the freshness configuration derived from the
	// Origin.StorageCache* settings.
	policy cache_control.Policy

	// fetchSem bounds concurrent upstream-to-disk copies.  Each copy holds a
	// goroutine, a backend connection, and a copy buffer, so an unbounded
	// count would let one client's request burst exhaust memory and run up an
	// arbitrary provider bill.  A request that cannot get a slot is served
	// straight from the backend instead of queueing.
	fetchSem chan struct{}

	// mu guards the fetch registry and each fetch's registry-visible state
	// (readers, started, superseded, retired).  It is never held across
	// filesystem I/O: every request that misses the cache passes through it.
	mu      sync.Mutex
	fetches map[string]*cacheFetch // keyed by the entry's meta-file path

	// installMu serializes installing a completed fetch's sidecar against
	// invalidating an entry, so a fetch cannot resurrect content that a
	// concurrent mutation just dropped.  It is separate from mu precisely
	// because it *is* held across disk I/O; only mutations and fetch
	// completions contend for it, never cache lookups.
	installMu sync.Mutex
}

// newStorageCache prepares the cache root directory, opens a symlink-safe
// filesystem rooted there, reclaims any orphans left by a previous process,
// and starts the janitor.  The janitor and any in-flight fetches stop when ctx
// is done.
func newStorageCache(ctx context.Context, location string, maxSize int64, defaultMaxAge time.Duration, revalidationJitter int, maxConcurrentFetches int) (*storageCache, error) {
	if err := os.MkdirAll(location, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage cache directory %s: %w", location, err)
	}
	// MkdirAll leaves an existing directory's mode alone, so a cache pointed
	// at a pre-existing shared path (a scratch area, /tmp/...) could be
	// writable by other local users.  Anyone who can write here can plant a
	// sidecar and choose the bytes this origin serves, so refuse to start.
	info, err := os.Stat(location)
	if err != nil {
		return nil, fmt.Errorf("failed to stat storage cache directory %s: %w", location, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("storage cache location %s is not a directory", location)
	}
	// Windows permission bits don't carry this meaning, and os.Chmod there only
	// toggles the read-only attribute, so the check is POSIX-only.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode&0022 != 0 {
			// The directory already existed with loose permissions, or was
			// created under a permissive umask.  Tighten it rather than trust
			// it: anyone who can write here can plant a sidecar and choose the
			// bytes this origin serves.  The origin owns this directory, so
			// narrowing it is exactly what MkdirAll would have done had it
			// been the one to create it.
			if err := os.Chmod(location, 0700); err != nil {
				return nil, fmt.Errorf("storage cache directory %s is group- or world-writable (mode %04o) "+
					"and could not be tightened to 0700: %w", location, mode, err)
			}
			if info, err = os.Stat(location); err != nil {
				return nil, fmt.Errorf("failed to stat storage cache directory %s: %w", location, err)
			}
			if newMode := info.Mode().Perm(); newMode&0022 != 0 {
				return nil, fmt.Errorf("storage cache directory %s is still group- or world-writable "+
					"(mode %04o) after tightening; refusing to cache where other local users can write",
					location, newMode)
			}
			log.Warningf("Storage cache directory %s had mode %04o; tightened to 0700 so other local users "+
				"cannot inject cache entries", location, mode)
		}
	}
	// Fail at startup rather than turning every request into a 500 later.
	probe := path.Join(location, ".pelican-storage-cache-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0600); err != nil {
		return nil, fmt.Errorf("storage cache directory %s is not writable: %w", location, err)
	}
	if err := os.Remove(probe); err != nil {
		log.Debugf("Storage cache: failed to remove write probe %s: %v", probe, err)
	}

	rootFs, err := server_utils.NewOsRootFs(location)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage cache directory %s: %w", location, err)
	}
	if maxConcurrentFetches <= 0 {
		maxConcurrentFetches = 1
	}
	c := &storageCache{
		fs:      rootFs,
		ctx:     ctx,
		maxSize: maxSize,
		policy: cache_control.Policy{
			DefaultMaxAge: defaultMaxAge,
			JitterPercent: revalidationJitter,
			// A backend may shorten its objects' freshness but not extend it
			// beyond the operator's configured window.
			MaxFreshness: defaultMaxAge,
		},
		fetchSem: make(chan struct{}, maxConcurrentFetches),
		fetches:  make(map[string]*cacheFetch),
	}
	// Nothing is registered yet, so every data file without a sidecar is a
	// leftover from a previous process and can go immediately.
	c.pruneOrphans(0)
	return c, nil
}

// isFresh reports whether a completed cache entry may be served without any
// upstream interaction, per its recorded Cache-Control directives (or the
// configured default policy when the backend supplied none).
func (c *storageCache) isFresh(meta *cacheEntryMeta) bool {
	// A zero default max-age means "revalidate every read".  Honour that
	// literally: a backend-supplied max-age must not be able to re-enable
	// serving without an upstream check.
	if c.policy.DefaultMaxAge <= 0 {
		return false
	}
	lastValidated := time.Unix(0, meta.LastValidatedUnixNano)
	cd := cache_control.Parse(meta.CacheControl)
	return !cd.IsStaleFor(lastValidated, c.policy, meta.Path)
}

// newLayer returns the caching webdav.FileSystem for one export, scoped to its
// own subdirectory.  backendID identifies the storage the export is served
// from (type, endpoint, prefix); folding it into the scope means that
// repointing an export at different storage cannot serve entries cached from
// the old one.
func (c *storageCache) newLayer(federationPrefix, backendID string, upstream webdav.FileSystem) *storageCacheFS {
	sum := sha256.Sum256([]byte(federationPrefix + "\x00" + backendID))
	sanitized := strings.ReplaceAll(strings.Trim(federationPrefix, "/"), "/", "_")
	if sanitized == "" {
		sanitized = "root"
	}
	return &storageCacheFS{
		cache:    c,
		upstream: upstream,
		scope:    fmt.Sprintf("%s.%s", sanitized, hex.EncodeToString(sum[:8])),
	}
}

// attachFetch registers a reader on the in-flight fetch for the entry, if one
// is live.  Finding the fetch and taking the reference happen under the same
// lock that retires fetches, so a fetch can never be discarded (and its data
// file unlinked) between a caller finding it and attaching to it.
func (c *storageCache) attachFetch(metaRel string) *cacheFetch {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.fetches[metaRel]
	if f == nil || f.retired {
		return nil
	}
	f.readers++
	return f
}

// registerFetch publishes a newly prepared fetch, or attaches to the one that
// won a concurrent race.  The returned bool reports whether f itself was
// registered; when it is false the caller must discard the data file it
// pre-created.  Either way the returned fetch has a reader registered.
func (c *storageCache) registerFetch(f *cacheFetch) (*cacheFetch, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing := c.fetches[f.metaRel]; existing != nil && !existing.retired {
		existing.readers++
		return existing, false
	}
	f.readers = 1
	c.fetches[f.metaRel] = f
	return f, true
}

func (c *storageCache) unregisterFetch(f *cacheFetch) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fetches[f.metaRel] == f {
		delete(c.fetches, f.metaRel)
	}
}

// metaTempName returns a unique temporary name alongside the sidecar.
func metaTempName(metaRel string) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	return metaRel + "." + hex.EncodeToString(suffix) + ".tmp", nil
}

// writeMeta serializes the sidecar through a temporary file and a rename, so a
// reader never observes a half-written sidecar and a crash mid-update leaves
// the previous one intact.  The fresh mtime doubles as an LRU touch.
func (c *storageCache) writeMeta(metaRel string, meta *cacheEntryMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmp, err := metaTempName(metaRel)
	if err != nil {
		return err
	}
	if err := afero.WriteFile(c.fs, tmp, data, 0600); err != nil {
		return err
	}
	if err := c.fs.Rename(tmp, metaRel); err != nil {
		if rmErr := c.fs.Remove(tmp); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Debugf("Storage cache: failed to remove temporary sidecar %s: %v", tmp, rmErr)
		}
		return err
	}
	return nil
}

// readMeta loads and validates a sidecar.  Any problem — missing, unreadable,
// malformed, or naming a data file it has no business naming — reads as a
// miss, so the entry is simply refetched.
func (c *storageCache) readMeta(metaRel string) *cacheEntryMeta {
	data, err := afero.ReadFile(c.fs, metaRel)
	if err != nil {
		return nil
	}
	var meta cacheEntryMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil
	}
	if !meta.valid() {
		log.Warningf("Storage cache: ignoring malformed sidecar %s", metaRel)
		return nil
	}
	return &meta
}

// touch bumps the entry's last-access marker (the meta file's mtime).
func (c *storageCache) touch(metaRel string) {
	now := time.Now()
	if err := c.fs.Chtimes(metaRel, now, now); err != nil {
		log.Debugf("Storage cache: failed to update access time for %s: %v", metaRel, err)
	}
}

// invalidate drops the completed entry (sidecar first so a concurrent reader
// never sees a sidecar pointing at a deleted data file).
func (c *storageCache) invalidate(metaRel string) {
	meta := c.readMeta(metaRel)
	if err := c.fs.Remove(metaRel); err != nil && !os.IsNotExist(err) {
		log.Debugf("Storage cache: failed to remove meta %s: %v", metaRel, err)
	}
	if meta != nil && meta.DataFile != "" {
		dataRel := path.Join(path.Dir(metaRel), meta.DataFile)
		if err := c.fs.Remove(dataRel); err != nil && !os.IsNotExist(err) {
			log.Debugf("Storage cache: failed to remove data file %s: %v", dataRel, err)
		}
	}
}

// supersedeFetch marks any in-flight fetch for the entry as superseded so it
// won't install its (pre-mutation) result as a completed entry.  Callers hold
// installMu, which is what makes the supersede-then-invalidate sequence atomic
// against a fetch's check-then-install.
func (c *storageCache) supersedeFetch(metaRel string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f := c.fetches[metaRel]; f != nil {
		f.superseded = true
	}
}

// invalidateEntry is the notification hook for a single-object mutation
// through the origin (PUT, DELETE, rename endpoint): it supersedes any
// in-flight fetch and removes the completed entry.
func (c *storageCache) invalidateEntry(metaRel string) {
	c.installMu.Lock()
	defer c.installMu.Unlock()
	c.supersedeFetch(metaRel)
	c.invalidate(metaRel)
}

func (c *storageCache) runJanitor() {
	ticker := time.NewTicker(storageCacheJanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.pruneOrphans(storageCacheOrphanGrace)
			c.evictOnce()
		}
	}
}

// inFlightMetaPaths snapshots the sidecar paths that currently have a fetch
// registered, so sweeps can skip entries under construction.
func (c *storageCache) inFlightMetaPaths() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	inFlight := make(map[string]bool, len(c.fetches))
	for metaRel := range c.fetches {
		inFlight[metaRel] = true
	}
	return inFlight
}

// metaPathForData maps "<hash>-<generation>.data" to its "<hash>.meta"
// sidecar in the same directory.  It returns "" for names that don't match the
// layout, which are left alone.
func metaPathForData(dataRel string) string {
	base := path.Base(dataRel)
	if !storageCacheDataFileRe.MatchString(base) {
		return ""
	}
	idx := strings.IndexByte(base, '-')
	return path.Join(path.Dir(dataRel), base[:idx]+".meta")
}

// pruneOrphans removes data files that no sidecar refers to and no fetch is
// writing: leftovers from a process that died mid-fetch.  Reclaiming them is
// deliberately independent of the size bound, because the default cache is
// unbounded and would otherwise accumulate them forever.
//
// Only files older than grace are considered, so a periodic sweep cannot race
// a fetch registered after the tree listing began.  A zero grace is for
// startup, when no fetch exists yet.
func (c *storageCache) pruneOrphans(grace time.Duration) {
	inFlight := c.inFlightMetaPaths()
	cutoff := time.Now().Add(-grace)

	var orphans []string
	err := afero.Walk(c.fs, ".", func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".tmp"):
			// A sidecar temp file left by an interrupted rename.
			if info.ModTime().Before(cutoff) {
				orphans = append(orphans, p)
			}
		case strings.HasSuffix(p, ".data"):
			if info.ModTime().After(cutoff) {
				return nil
			}
			metaRel := metaPathForData(p)
			if metaRel == "" || inFlight[metaRel] {
				return nil
			}
			if _, statErr := c.fs.Stat(metaRel); statErr == nil {
				return nil // a live sidecar refers to this generation
			}
			orphans = append(orphans, p)
		}
		return nil
	})
	if err != nil {
		log.Warningf("Storage cache: orphan scan failed: %v", err)
		return
	}
	for _, p := range orphans {
		if err := c.fs.Remove(p); err != nil && !os.IsNotExist(err) {
			log.Debugf("Storage cache: failed to remove orphan %s: %v", p, err)
			continue
		}
		log.Debugf("Storage cache: reclaimed orphaned file %s", p)
	}
}

// evictOnce scans the cache tree and, when total data-file usage exceeds the
// configured maximum, removes least-recently-accessed entries until usage
// falls below the eviction target.  Entries with an in-flight fetch are never
// evicted.
func (c *storageCache) evictOnce() {
	if c.maxSize <= 0 {
		return
	}

	type entry struct {
		dataRel string
		metaRel string
		size    int64
		access  time.Time
	}

	metaTimes := make(map[string]time.Time)
	var entries []entry
	var total int64
	err := afero.Walk(c.fs, ".", func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".meta"):
			metaTimes[p] = info.ModTime()
		case strings.HasSuffix(p, ".data"):
			total += info.Size()
			entries = append(entries, entry{dataRel: p, size: info.Size()})
		}
		return nil
	})
	if err != nil {
		log.Warningf("Storage cache: eviction scan failed: %v", err)
		return
	}
	if total <= c.maxSize {
		return
	}

	inFlight := c.inFlightMetaPaths()

	target := c.maxSize / storageCacheEvictTargetDen * storageCacheEvictTargetNum
	victims := entries[:0]
	for _, e := range entries {
		e.metaRel = metaPathForData(e.dataRel)
		if e.metaRel == "" || inFlight[e.metaRel] {
			continue
		}
		e.access = metaTimes[e.metaRel] // zero time for orphans: evicted first
		victims = append(victims, e)
	}
	sort.Slice(victims, func(i, j int) bool { return victims[i].access.Before(victims[j].access) })

	for _, v := range victims {
		if total <= target {
			break
		}
		if err := c.fs.Remove(v.metaRel); err != nil && !os.IsNotExist(err) {
			log.Debugf("Storage cache: eviction failed to remove %s: %v", v.metaRel, err)
		}
		if err := c.fs.Remove(v.dataRel); err != nil && !os.IsNotExist(err) {
			// The bytes are still on disk, so don't credit them as reclaimed;
			// the orphan sweep will pick the file up later.
			log.Debugf("Storage cache: eviction failed to remove %s: %v", v.dataRel, err)
			continue
		}
		total -= v.size
		log.Debugf("Storage cache: evicted %s (%d bytes)", v.dataRel, v.size)
	}
	log.Debugf("Storage cache: eviction pass complete; usage now %d bytes (max %d)", total, c.maxSize)
}

// ---------------------------------------------------------------------------
// storageCacheFS — the per-export webdav.FileSystem layer
// ---------------------------------------------------------------------------

type storageCacheFS struct {
	cache    *storageCache
	upstream webdav.FileSystem
	scope    string
}

// entryPaths maps an object path to its cache-relative sidecar path and
// containing directory.  Entries are content-addressed by the SHA-256 of the
// object path so arbitrary object names never produce hostile disk paths.
func (l *storageCacheFS) entryPaths(name string) (metaRel, hashDir, hash string) {
	sum := sha256.Sum256([]byte(path.Clean("/" + name)))
	hash = hex.EncodeToString(sum[:])
	hashDir = path.Join(l.scope, "objects", hash[:2])
	metaRel = path.Join(hashDir, hash+".meta")
	return
}

// passthrough abandons the cache for this request and serves straight from the
// backend.  The cache is an optimization: a full disk, an unwritable
// directory, or a saturated fetch pool must degrade throughput, not
// availability.
func (l *storageCacheFS) passthrough(ctx context.Context, name string, flag int, perm os.FileMode, reason string, err error) (webdav.File, error) {
	if err != nil {
		log.Warningf("Storage cache: %s for %s (%v); serving directly from the backend", reason, name, err)
	} else {
		log.Debugf("Storage cache: %s for %s; serving directly from the backend", reason, name)
	}
	return l.upstream.OpenFile(ctx, name, flag, perm)
}

func (l *storageCacheFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return l.upstream.Mkdir(ctx, name, perm)
}

func (l *storageCacheFS) RemoveAll(ctx context.Context, name string) error {
	// Enumerate the subtree before the upstream deletes it (afterwards it can
	// no longer be listed); invalidate after the operation, and regardless of
	// its result: a partial failure may still have removed some descendants.
	targets, enumerated := l.enumerateSubtree(ctx, name)
	err := l.upstream.RemoveAll(ctx, name)
	l.invalidateSubtreeEntries(name, targets, enumerated)
	return err
}

func (l *storageCacheFS) Rename(ctx context.Context, oldName, newName string) error {
	// Both prefixes need invalidation: the source moves away, and the
	// destination may have held objects that are now overwritten.
	oldTargets, oldEnumerated := l.enumerateSubtree(ctx, oldName)
	newTargets, newEnumerated := l.enumerateSubtree(ctx, newName)
	err := l.upstream.Rename(ctx, oldName, newName)
	l.invalidateSubtreeEntries(oldName, oldTargets, oldEnumerated)
	l.invalidateSubtreeEntries(newName, newTargets, newEnumerated)
	return err
}

// enumerateSubtree lists the object paths currently under name in the backend,
// so a directory mutation can be unrolled into exact per-object invalidations
// — O(subtree) instead of a scan of every cached sidecar.  The listing is
// metadata-only (no data egress) and mirrors the one a blob backend's
// RemoveAll performs internally, so it covers exactly the objects the mutation
// affects.  Cached entries for objects that already vanished from the backend
// out-of-band are not the mutation's responsibility; the normal
// freshness/revalidation cycle retires them.
//
// Returns (paths, true) on success.  Returns (nil, false) when the backend
// cannot enumerate (e.g. a plain-HTTP upstream with no listing support) or the
// subtree exceeds the enumeration cap or depth limit; callers then fall back
// to the sidecar scan, which is authoritative over the cache's own contents.
func (l *storageCacheFS) enumerateSubtree(ctx context.Context, name string) ([]string, bool) {
	clean := path.Clean("/" + name)
	info, err := l.upstream.Stat(ctx, clean)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing (visible) upstream: only the exact entry could need
			// dropping.
			return []string{clean}, true
		}
		return nil, false
	}
	if !info.IsDir() {
		return []string{clean}, true
	}

	errCapExceeded := errors.New("enumeration cap exceeded")
	errTooDeep := errors.New("enumeration depth limit exceeded")
	paths := []string{clean}
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if depth > storageCacheMaxEnumDepth {
			return errTooDeep
		}
		f, err := l.upstream.OpenFile(ctx, dir, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		for {
			ents, rdErr := f.Readdir(1024)
			for _, e := range ents {
				// A backend that lists "." or ".." (or an empty name) would
				// otherwise send this walk into unbounded recursion.
				switch e.Name() {
				case "", ".", "..":
					continue
				}
				child := path.Join(dir, e.Name())
				if child == dir {
					continue
				}
				// Count directories against the cap too: a prefix made of
				// millions of empty "directories" costs just as much to walk
				// as one made of objects.
				if len(paths) >= storageCacheEnumerationCap {
					return errCapExceeded
				}
				if e.IsDir() {
					paths = append(paths, child)
					if err := walk(child, depth+1); err != nil {
						return err
					}
					continue
				}
				paths = append(paths, child)
			}
			if rdErr == io.EOF || (rdErr == nil && len(ents) == 0) {
				return nil
			}
			if rdErr != nil {
				return rdErr
			}
		}
	}
	if err := walk(clean, 0); err != nil {
		log.Debugf("Storage cache: subtree enumeration of %s failed (%v); falling back to sidecar scan", clean, err)
		return nil, false
	}
	return paths, true
}

// invalidateSubtreeEntries is the notification hook for mutations whose target
// may be a directory.  In-flight fetches under the subtree are always
// superseded first (an in-memory registry sweep) so none installs
// pre-mutation content afterwards.  Completed entries are then dropped: per
// enumerated path when the subtree could be listed, otherwise by scanning the
// export's sidecars (each records its object path).
func (l *storageCacheFS) invalidateSubtreeEntries(name string, targets []string, enumerated bool) {
	clean := path.Clean("/" + name)
	childPrefix := clean
	if childPrefix != "/" {
		childPrefix += "/"
	}
	matches := func(objPath string) bool {
		return objPath == clean || strings.HasPrefix(objPath, childPrefix)
	}

	c := l.cache
	c.installMu.Lock()
	defer c.installMu.Unlock()

	// Supersede in-flight fetches first (see supersedeFetch for ordering).
	scopePrefix := l.scope + "/"
	c.mu.Lock()
	for metaRel, f := range c.fetches {
		if strings.HasPrefix(metaRel, scopePrefix) && matches(f.meta.Path) {
			f.superseded = true
		}
	}
	c.mu.Unlock()

	if enumerated {
		for _, p := range targets {
			metaRel, _, _ := l.entryPaths(p)
			c.invalidate(metaRel)
		}
		return
	}

	// Fallback: drop every completed entry whose recorded path is in the
	// subtree.  O(total cached entries), used only when the backend can't tell
	// us what lives under the prefix.
	objectsDir := path.Join(l.scope, "objects")
	walkErr := afero.Walk(c.fs, objectsDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(p, ".meta") {
			return nil
		}
		if meta := c.readMeta(p); meta != nil && matches(meta.Path) {
			c.invalidate(p)
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		log.Debugf("Storage cache: subtree invalidation scan for %s failed: %v", clean, walkErr)
	}
}

// Stat serves the preserved upstream metadata for fresh cache entries so
// HEAD-style probes cost no upstream round-trip; anything else (stale entries,
// misses, directories) is delegated to the backend.
//
// Results are wrapped so they carry a Content-Type.  Without one, a PROPFIND
// opens every file it lists and reads its first bytes to sniff a type, which
// through this layer would mean touching the backend for every object in a
// directory.
func (l *storageCacheFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	metaRel, _, _ := l.entryPaths(name)
	if meta := l.cache.readMeta(metaRel); meta != nil && l.cache.isFresh(meta) {
		l.cache.touch(metaRel)
		return meta.fileInfo(name), nil
	}
	info, err := l.upstream.Stat(ctx, name)
	if err != nil || info == nil || info.IsDir() {
		return info, err
	}
	return contentTypedInfo{info}, nil
}

func (l *storageCacheFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	// Writes pass straight through to the backend.  Blob uploads only commit
	// on Close, so the returned handle is wrapped to invalidate the cached
	// copy (and supersede any in-flight fetch) at that point: the old copy
	// keeps serving during the upload, and the first read after the commit
	// revalidates against the backend's new state.
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		wf, err := l.upstream.OpenFile(ctx, name, flag, perm)
		if err != nil {
			return nil, err
		}
		metaRel, _, _ := l.entryPaths(name)
		return &writeThroughFile{File: wf, cache: l.cache, metaRel: metaRel}, nil
	}

	metaRel, hashDir, hash := l.entryPaths(name)

	// An in-flight fetch for this object serves everyone; attach to it.
	if f := l.cache.attachFetch(metaRel); f != nil {
		if reader, attachErr := newFetchReader(ctx, f); attachErr == nil {
			return reader, nil
		} else {
			// The data file went away (a racing retirement); drop the
			// reference and fall through to a fresh fetch.
			f.detach(0, 0)
			log.Debugf("Storage cache: could not attach to in-flight fetch of %s: %v", name, attachErr)
		}
	}

	// A fresh completed entry is served with no upstream interaction at all —
	// this is the common repeat-read path that avoids both egress and
	// metadata round-trips.
	meta := l.cache.readMeta(metaRel)
	if meta != nil && l.cache.isFresh(meta) {
		if file, openErr := l.cache.fs.Open(path.Join(hashDir, meta.DataFile)); openErr == nil {
			l.cache.touch(metaRel)
			return &cacheHitFile{File: file, info: meta.fileInfo(name)}, nil
		}
		// Sidecar present but data unreadable (e.g. eviction race): fall
		// through and treat as a miss.
	}

	// Stale or missing: revalidate with a single upstream stat.  The stat is
	// metadata-only, so this costs no data egress.
	info, err := l.upstream.Stat(ctx, name)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		dir, err := l.upstream.OpenFile(ctx, name, flag, perm)
		if err != nil {
			return nil, err
		}
		return &contentTypedDir{File: dir}, nil
	}

	validator, clientVisibleETag := upstreamValidator(ctx, info)
	cacheControl := upstreamCacheControl(info)

	// no-store / private responses must not be persisted: drop any existing
	// copy (superseding a concurrently registered fetch, if any) and stream
	// straight from the backend.
	if cd := cache_control.Parse(cacheControl); !cd.ShouldStore() {
		if meta != nil {
			l.cache.invalidateEntry(metaRel)
		}
		return l.upstream.OpenFile(ctx, name, flag, perm)
	}

	// Revalidated: the validator still matches, so renew the freshness window
	// (and pick up any Cache-Control change) and serve locally.
	oldDataFile := ""
	if meta != nil {
		if meta.Validator == validator {
			meta.CacheControl = cacheControl
			meta.LastValidatedUnixNano = time.Now().UnixNano()
			if wErr := l.cache.writeMeta(metaRel, meta); wErr != nil {
				log.Warningf("Storage cache: failed to renew metadata for %s: %v", metaRel, wErr)
			}
			if file, openErr := l.cache.fs.Open(path.Join(hashDir, meta.DataFile)); openErr == nil {
				return &cacheHitFile{File: file, info: meta.fileInfo(name)}, nil
			}
			// Data unreadable despite matching validator: refetch.
		}
		oldDataFile = meta.DataFile
	}

	// Miss (or stale): fetch from the backend into the cache.  Take a fetch
	// slot first; when the pool is saturated, serve from the backend rather
	// than queueing behind other transfers.
	select {
	case l.cache.fetchSem <- struct{}{}:
	default:
		return l.passthrough(ctx, name, flag, perm, "fetch pool saturated", nil)
	}
	releaseSlot := func() { <-l.cache.fetchSem }

	gen := make([]byte, 8)
	if _, err := rand.Read(gen); err != nil {
		releaseSlot()
		return nil, fmt.Errorf("failed to generate cache file name: %w", err)
	}
	etag := ""
	if clientVisibleETag {
		etag = validator
	}
	dataFile := fmt.Sprintf("%s-%s.data", hash, hex.EncodeToString(gen))
	f := &cacheFetch{
		cache:   l.cache,
		name:    name,
		metaRel: metaRel,
		dataRel: path.Join(hashDir, dataFile),
		meta: cacheEntryMeta{
			Path:                  path.Clean("/" + name),
			Validator:             validator,
			ETag:                  etag,
			CacheControl:          cacheControl,
			LastValidatedUnixNano: time.Now().UnixNano(),
			Size:                  info.Size(),
			ModTimeUnixNano:       info.ModTime().UnixNano(),
			DataFile:              dataFile,
		},
		releaseSlot: releaseSlot,
		open: func(fetchCtx context.Context) (webdav.File, error) {
			return l.upstream.OpenFile(fetchCtx, name, os.O_RDONLY, 0)
		},
	}
	if oldDataFile != "" {
		f.oldDataRel = path.Join(hashDir, oldDataFile)
	}
	f.cond = sync.NewCond(&f.mu)

	// Create the (empty) data file before publishing the fetch, so every
	// reader that attaches can open a handle immediately.  Doing this outside
	// the registry lock keeps disk latency off the path of every other
	// request; the generation suffix makes the name unique, so a fetch that
	// loses the registration race simply removes the file it made.
	if err := l.cache.fs.MkdirAll(hashDir, 0700); err != nil {
		releaseSlot()
		return l.passthrough(ctx, name, flag, perm, "cannot create cache directory", err)
	}
	if file, err := l.cache.fs.OpenFile(f.dataRel, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600); err != nil {
		releaseSlot()
		return l.passthrough(ctx, name, flag, perm, "cannot create cache file", err)
	} else if err := file.Close(); err != nil {
		releaseSlot()
		return l.passthrough(ctx, name, flag, perm, "cannot create cache file", err)
	}

	winner, mine := l.cache.registerFetch(f)
	if !mine {
		releaseSlot()
		if rmErr := l.cache.fs.Remove(f.dataRel); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Debugf("Storage cache: failed to remove raced cache file %s: %v", f.dataRel, rmErr)
		}
	}
	reader, err := newFetchReader(ctx, winner)
	if err != nil {
		winner.detach(0, 0)
		return l.passthrough(ctx, name, flag, perm, "cannot open cache file for read", err)
	}
	return reader, nil
}

// upstreamValidator extracts the consistency validator for an upstream
// FileInfo: the backend's own ETag when it exposes one, otherwise the same
// size/mtime-derived tag the origin uses for local files.
//
// The boolean reports whether the validator is an ETag the backend also
// exposes to clients (via webdav.ETager).  Only those are re-served from the
// cache; a backend that keeps its ETag internal must keep looking the same
// through the cache as without it, or the ETag a client sees would flip
// between two formats depending on whether the object happened to be cached.
//
// Weak ETags are rejected outright.  "W/" means the backend considers two
// different payloads equivalent, which is exactly the comparison a cache must
// not make, and RFC 7232 forbids using them for the range requests these
// responses support.
func upstreamValidator(ctx context.Context, info os.FileInfo) (string, bool) {
	if et, ok := info.(webdav.ETager); ok {
		if v, err := et.ETag(ctx); err == nil && isStrongETag(v) {
			return v, true
		}
	}
	// gowebdav's FileInfo (the WebDAV-mode HTTPS and Globus backends) exposes
	// its ETag through a context-free method of its own.
	if et, ok := info.(interface{ ETag() string }); ok {
		if v := et.ETag(); isStrongETag(v) {
			return v, false
		}
	}
	switch sys := info.Sys().(type) {
	case *BlobFileSysInfo:
		if isStrongETag(sys.ETag) {
			return sys.ETag, false
		}
	case *HTTPSFileSysInfo:
		if isStrongETag(sys.ETag) {
			return sys.ETag, false
		}
	}
	return computeETag(info), false
}

func isStrongETag(v string) bool {
	return v != "" && !strings.HasPrefix(v, "W/") && !strings.HasPrefix(v, "w/")
}

// upstreamCacheControl extracts the backend's Cache-Control value for the
// object, when the backend surfaces one (S3 object metadata, HTTPS response
// header).  Empty means the configured default freshness policy applies.
func upstreamCacheControl(info os.FileInfo) string {
	switch sys := info.Sys().(type) {
	case *BlobFileSysInfo:
		return sys.CacheControl
	case *HTTPSFileSysInfo:
		return sys.CacheControl
	}
	return ""
}

// ---------------------------------------------------------------------------
// cacheFetch — a single upstream-to-disk copy, shared by all readers
// ---------------------------------------------------------------------------

type cacheFetch struct {
	cache       *storageCache
	name        string
	metaRel     string
	dataRel     string
	oldDataRel  string // superseded data file removed once the new copy lands
	meta        cacheEntryMeta
	open        func(ctx context.Context) (webdav.File, error)
	releaseSlot func() // returns this fetch's slot to the concurrency pool

	// mu and cond guard the copy's progress.
	mu      sync.Mutex
	cond    *sync.Cond
	written int64
	done    bool
	err     error

	// The following are guarded by storageCache.mu, not by mu above.
	started  bool
	retired  bool
	readers  int
	consumed bool // a reader wanted real bytes, not just a content-type sniff
	// superseded is set when the object is mutated through the origin while
	// this fetch is in flight.  A superseded fetch still streams to its
	// attached readers, but must not install its result as a completed cache
	// entry: the bytes it is copying predate the mutation, yet its validation
	// timestamp would look fresh.
	superseded bool
	cancel     context.CancelFunc
}

// ensureStarted launches the copy goroutine exactly once.  The copy runs under
// the cache's server-lifetime context, not any request context, so a slow or
// disconnected client never cancels it.
func (f *cacheFetch) ensureStarted() {
	c := f.cache
	c.mu.Lock()
	if f.started || f.retired {
		c.mu.Unlock()
		return
	}
	f.started = true
	ctx, cancel := context.WithCancel(c.ctx)
	f.cancel = cancel
	c.mu.Unlock()
	go f.run(ctx)
}

// detach releases one reader's reference.  maxOffset is the furthest offset
// that reader actually read to (seeks don't count) and finalOffset is where it
// ended up; together they decide whether the copy is worth finishing.
func (f *cacheFetch) detach(maxOffset, finalOffset int64) {
	c := f.cache
	c.mu.Lock()
	f.readers--
	// Distinguish a client that actually wanted bytes from net/http's
	// content-type sniff.  ServeContent reads the first sniff-length bytes and
	// then rewinds to zero; on a HEAD it stops there, leaving a reader that
	// read only the prefix and ended back at the start.  Anything else —
	// reading past the prefix, or stopping part-way through — is a real
	// transfer, and its copy is allowed to finish even after the client goes
	// away.  A handle that never read at all (a pure metadata probe) is not a
	// transfer either.
	if maxOffset > storageCacheSniffLen || (maxOffset > 0 && finalOffset != 0) {
		f.consumed = true
	}
	// Finishing a whole-object copy on behalf of a sniff would be exactly the
	// egress this layer exists to avoid.  A fetch that never started is always
	// retired: there is no copy to preserve, and leaving it registered would
	// strand its pool slot and its empty data file forever — the case a reader
	// that only ever range-bypassed would otherwise hit, since it counts as
	// having consumed bytes without ever starting the copy.
	//
	// Whether the copy already finished is deliberately not consulted here:
	// f.done belongs to the fetch's own mutex, and reading it under this one
	// would race.  Retiring a fetch that has just completed is harmless — the
	// started branch below only cancels a context and drops a registry entry
	// that finish() removes anyway, and run() re-checks f.retired under this
	// same lock before installing, so a sidecar is never left pointing at a
	// data file that got cleaned up.
	retire := f.readers <= 0 && (!f.started || !f.consumed)
	if !retire {
		c.mu.Unlock()
		return
	}
	f.retired = true
	if c.fetches[f.metaRel] == f {
		delete(c.fetches, f.metaRel)
	}
	started, cancel := f.started, f.cancel
	c.mu.Unlock()

	if started {
		// The copy goroutine owns the data file and the pool slot from here;
		// cancelling makes it unwind through abort().
		if cancel != nil {
			cancel()
		}
		return
	}
	f.releaseSlot()
	if err := c.fs.Remove(f.dataRel); err != nil && !os.IsNotExist(err) {
		log.Debugf("Storage cache: failed to remove unused cache file %s: %v", f.dataRel, err)
	}
}

// watchStall aborts a fetch that stops making progress.  Readers coalesce onto
// the in-flight fetch, so a wedged backend connection would otherwise block
// every future request for the object until the server shut down.
func (f *cacheFetch) watchStall(ctx context.Context, cancel context.CancelFunc) {
	ticker := time.NewTicker(storageCacheStallCheckInterval)
	defer ticker.Stop()
	last := int64(-1)
	stalledFor := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.mu.Lock()
			written, done := f.written, f.done
			f.mu.Unlock()
			if done {
				return
			}
			if written != last {
				last, stalledFor = written, 0
				continue
			}
			stalledFor += storageCacheStallCheckInterval
			if stalledFor >= storageCacheStallTimeout {
				log.Warningf("Storage cache: fetch of %s made no progress for %s; abandoning it",
					f.name, storageCacheStallTimeout)
				cancel()
				return
			}
		}
	}
}

func (f *cacheFetch) run(ctx context.Context) {
	defer f.releaseSlot()

	// stallCancel both unblocks a wedged read and stops the watchdog; the
	// deferred call makes the watchdog exit as soon as the copy returns rather
	// than lingering until its next tick.
	stallCtx, stallCancel := context.WithCancel(ctx)
	defer stallCancel()
	go f.watchStall(stallCtx, stallCancel)

	src, err := f.open(stallCtx)
	if err != nil {
		f.abort(fmt.Errorf("storage cache: upstream open of %s failed: %w", f.name, err))
		return
	}
	defer src.Close()

	// The (empty) data file was created when the fetch was registered.
	dst, err := f.cache.fs.OpenFile(f.dataRel, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		f.abort(fmt.Errorf("storage cache: failed to open cache file: %w", err))
		return
	}

	buf := make([]byte, storageCacheCopyBufSize)
	var copied int64 // this goroutine's private view of f.written
	for {
		// Never write more than the object was said to hold: a backend that
		// streams more than it advertised would otherwise fill the cache
		// filesystem before the size check below ever ran.  One byte past the
		// advertised length is still read, so an oversized object is reported
		// as an error rather than silently truncated to fit.
		if room := f.meta.Size - copied + 1; room < int64(len(buf)) {
			if room < 1 {
				room = 1
			}
			buf = buf[:room]
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				dst.Close()
				f.abort(fmt.Errorf("storage cache: write to cache file failed: %w", writeErr))
				return
			}
			copied += int64(n)
			f.mu.Lock()
			f.written = copied
			f.cond.Broadcast()
			f.mu.Unlock()
			if copied > f.meta.Size {
				dst.Close()
				f.abort(fmt.Errorf("storage cache: upstream %s returned more than the %d bytes it reported",
					f.name, f.meta.Size))
				return
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			dst.Close()
			f.abort(fmt.Errorf("storage cache: upstream read of %s failed: %w", f.name, readErr))
			return
		}
	}
	if err := dst.Close(); err != nil {
		f.abort(fmt.Errorf("storage cache: failed to finalize cache file: %w", err))
		return
	}

	// The size was captured at revalidation time; a mismatch means the object
	// changed (or was truncated) mid-fetch, so the copy cannot be trusted and
	// readers must see an error rather than a silent short read.
	if copied != f.meta.Size {
		f.abort(fmt.Errorf("storage cache: fetched %d bytes for %s but upstream reported %d", copied, f.name, f.meta.Size))
		return
	}

	// Install the completed entry.  installMu makes the superseded check and
	// the sidecar write atomic with respect to a mutation's
	// supersede-then-invalidate, so either the flag is seen here (no install),
	// or the sidecar lands before the invalidation sweep and is removed by it.
	c := f.cache
	c.installMu.Lock()
	c.mu.Lock()
	superseded := f.superseded || f.retired
	c.mu.Unlock()
	var installErr error
	if !superseded {
		installErr = c.writeMeta(f.metaRel, &f.meta)
	}
	c.installMu.Unlock()

	if superseded {
		log.Debugf("Storage cache: fetch of %s was superseded; discarding", f.name)
		if err := c.fs.Remove(f.dataRel); err != nil && !os.IsNotExist(err) {
			log.Debugf("Storage cache: failed to remove superseded fetch file %s: %v", f.dataRel, err)
		}
		// Attached readers already hold open handles and drain normally.
		f.finish(nil)
		return
	}
	if installErr != nil {
		f.abort(fmt.Errorf("storage cache: failed to write metadata: %w", installErr))
		return
	}
	if f.oldDataRel != "" {
		if err := c.fs.Remove(f.oldDataRel); err != nil && !os.IsNotExist(err) {
			log.Debugf("Storage cache: failed to remove superseded data file %s: %v", f.oldDataRel, err)
		}
	}
	f.finish(nil)
}

// abort discards the partial cache file and reports err to readers.  The
// registry entry is removed before the file is unlinked, so no request can
// find this fetch and then fail to open its data file.
func (f *cacheFetch) abort(err error) {
	f.cache.unregisterFetch(f)
	if rmErr := f.cache.fs.Remove(f.dataRel); rmErr != nil && !os.IsNotExist(rmErr) {
		log.Debugf("Storage cache: failed to remove partial cache file %s: %v", f.dataRel, rmErr)
	}
	f.finish(err)
}

func (f *cacheFetch) finish(err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Warningf("%v", err)
	}
	f.mu.Lock()
	f.done = true
	f.err = err
	f.cond.Broadcast()
	f.mu.Unlock()
	f.cache.unregisterFetch(f)
}

// ---------------------------------------------------------------------------
// fetchReader — a client's view of an in-flight (or lazily started) fetch
// ---------------------------------------------------------------------------

type fetchReader struct {
	fetch  *cacheFetch
	reqCtx context.Context

	mu        sync.Mutex
	file      afero.File
	closed    bool
	offset    int64
	maxOffset int64
	// bypass is a direct backend handle used when this reader has moved past
	// what the shared copy has written; see fetchReader.Read.
	bypass webdav.File
}

// newFetchReader attaches a reader to the fetch, opening its own handle on the
// shared data file up front.  Holding the handle from the start guarantees the
// reader can deliver every byte the fetch reports as written, even if the
// fetch aborts (and unlinks the file) mid-stream.
//
// The caller must already have registered the reader with attachFetch or
// registerFetch; on error it must call detach.
func newFetchReader(reqCtx context.Context, f *cacheFetch) (*fetchReader, error) {
	file, err := f.cache.fs.Open(f.dataRel)
	if err != nil {
		return nil, fmt.Errorf("storage cache: failed to open cache file for read: %w", err)
	}
	return &fetchReader{fetch: f, reqCtx: reqCtx, file: file}, nil
}

func (r *fetchReader) advance(n int) {
	r.offset += int64(n)
	if r.offset > r.maxOffset {
		r.maxOffset = r.offset
	}
}

// Read serves bytes from the cache file, waiting for the fetch goroutine to
// make progress when the reader has caught up.  The wait is interruptible by
// the request context so a departed client releases its handler goroutine,
// while the fetch itself keeps running.
func (r *fetchReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}

	f := r.fetch

	if r.bypass != nil {
		n, err := r.bypass.Read(p)
		r.advance(n)
		return n, err
	}

	f.mu.Lock()
	written, done := f.written, f.done
	f.mu.Unlock()

	// A forward seek past what the copy has written means a range request.
	// Waiting for a sequential copy to reach that offset would transfer the
	// whole object to deliver a slice of it, so read directly instead.  The
	// shared copy is deliberately not started here: one ranged request is no
	// reason to pull an entire object.
	if !done && r.offset > written {
		if src, err := r.openBypass(r.offset); err == nil {
			r.bypass = src
			n, readErr := src.Read(p)
			r.advance(n)
			return n, readErr
		} else {
			log.Debugf("Storage cache: ranged backend read of %s at %d failed (%v); waiting on the shared copy",
				f.name, r.offset, err)
		}
	}

	f.ensureStarted()

	stop := context.AfterFunc(r.reqCtx, func() {
		f.mu.Lock()
		f.cond.Broadcast()
		f.mu.Unlock()
	})
	defer stop()

	f.mu.Lock()
	for !f.done && f.written <= r.offset && r.reqCtx.Err() == nil {
		f.cond.Wait()
	}
	written, ferr := f.written, f.err
	f.mu.Unlock()

	if err := r.reqCtx.Err(); err != nil {
		return 0, err
	}
	if r.offset >= written {
		if ferr != nil {
			return 0, ferr
		}
		return 0, io.EOF
	}

	n := written - r.offset
	if n > int64(len(p)) {
		n = int64(len(p))
	}
	read, err := r.file.ReadAt(p[:n], r.offset)
	r.advance(read)
	if err == io.EOF && read > 0 {
		err = nil
	}
	return read, err
}

// openBypass returns a backend handle positioned at off.
func (r *fetchReader) openBypass(off int64) (webdav.File, error) {
	src, err := r.fetch.open(r.reqCtx)
	if err != nil {
		return nil, err
	}
	if _, err := src.Seek(off, io.SeekStart); err != nil {
		src.Close()
		return nil, err
	}
	return src, nil
}

// Seek repositions the reader without blocking; the object size is already
// known from the revalidation stat, so size probes (Seek to end) return
// immediately even before any bytes have been fetched.
func (r *fetchReader) Seek(offset int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = r.offset + offset
	case io.SeekEnd:
		next = r.fetch.meta.Size + offset
	default:
		return 0, fmt.Errorf("invalid seek whence %d", whence)
	}
	if next < 0 {
		return 0, fmt.Errorf("negative seek offset")
	}
	// Any repositioning invalidates a backend handle opened for a previous
	// offset; the next Read re-establishes one if it is still warranted.
	if r.bypass != nil && next != r.offset {
		if err := r.bypass.Close(); err != nil {
			log.Debugf("Storage cache: failed to close backend read handle: %v", err)
		}
		r.bypass = nil
	}
	r.offset = next
	return next, nil
}

func (r *fetchReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	err := r.file.Close()
	r.file = nil
	if r.bypass != nil {
		if bErr := r.bypass.Close(); bErr != nil {
			log.Debugf("Storage cache: failed to close backend read handle: %v", bErr)
		}
		r.bypass = nil
	}
	r.fetch.detach(r.maxOffset, r.offset)
	return err
}

func (r *fetchReader) Stat() (os.FileInfo, error) {
	return r.fetch.meta.fileInfo(r.fetch.name), nil
}

func (r *fetchReader) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write not supported on cached read file")
}

func (r *fetchReader) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on file")
}

// ---------------------------------------------------------------------------
// writeThroughFile — invalidation hook for origin-side writes
// ---------------------------------------------------------------------------

// writeThroughFile wraps an upstream write handle so the cached copy is
// dropped when the upload commits (blob backends finalize on Close).  The
// invalidation runs on success and failure alike — a failed streaming upload
// may still have altered the backend object — and supersedes any in-flight
// fetch so pre-write content can't be installed with a fresh timestamp.
type writeThroughFile struct {
	webdav.File
	cache   *storageCache
	metaRel string
	once    sync.Once
}

func (w *writeThroughFile) Close() error {
	err := w.File.Close()
	w.once.Do(func() { w.cache.invalidateEntry(w.metaRel) })
	return err
}

// ---------------------------------------------------------------------------
// cacheHitFile — serves a completed cache entry directly from disk
// ---------------------------------------------------------------------------

type cacheHitFile struct {
	afero.File
	info os.FileInfo
}

// Stat reports the preserved upstream metadata, not the local file's, so ETags
// and Last-Modified are identical whether the response is served from the
// cache or the backend.
func (f *cacheHitFile) Stat() (os.FileInfo, error) { return f.info, nil }

func (f *cacheHitFile) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write not supported on cached read file")
}

func (f *cacheHitFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on file")
}

// ---------------------------------------------------------------------------
// content-type wrappers — keep PROPFIND from opening every object
// ---------------------------------------------------------------------------

// contentTypedInfo adds a Content-Type to an upstream FileInfo.  The WebDAV
// PROPFIND handler asks a FileInfo for its content type first and only falls
// back to opening the file and sniffing its first bytes when the FileInfo
// can't say — which, over this layer, would mean a backend round trip (and,
// without the sniff carve-out in fetchReader.Read, an object fetch) for every
// file in a listing.
type contentTypedInfo struct {
	os.FileInfo
}

func (fi contentTypedInfo) ContentType(_ context.Context) (string, error) {
	if ct := mime.TypeByExtension(path.Ext(fi.Name())); ct != "" {
		return ct, nil
	}
	return "application/octet-stream", nil
}

// ETag forwards to the wrapped FileInfo so wrapping doesn't change the ETag a
// client sees.  Backends that expose no ETag get webdav's default, as before.
func (fi contentTypedInfo) ETag(ctx context.Context) (string, error) {
	if et, ok := fi.FileInfo.(webdav.ETager); ok {
		return et.ETag(ctx)
	}
	return "", webdav.ErrNotImplemented
}

// contentTypedDir wraps a backend directory handle so the entries a PROPFIND
// lists carry content types for the same reason.
type contentTypedDir struct {
	webdav.File
}

func (d *contentTypedDir) Readdir(count int) ([]os.FileInfo, error) {
	infos, err := d.File.Readdir(count)
	for i, fi := range infos {
		if fi != nil && !fi.IsDir() {
			infos[i] = contentTypedInfo{fi}
		}
	}
	return infos, err
}

// ---------------------------------------------------------------------------
// cachedFileInfo — upstream metadata preserved across the cache
// ---------------------------------------------------------------------------

type cachedFileInfo struct {
	name    string
	size    int64
	modTime time.Time
	etag    string
}

func (fi *cachedFileInfo) Name() string       { return fi.name }
func (fi *cachedFileInfo) Size() int64        { return fi.size }
func (fi *cachedFileInfo) Mode() os.FileMode  { return 0644 }
func (fi *cachedFileInfo) ModTime() time.Time { return fi.modTime }
func (fi *cachedFileInfo) IsDir() bool        { return false }
func (fi *cachedFileInfo) Sys() interface{}   { return nil }

// ETag exposes the upstream's ETag when the backend exposed one to clients;
// otherwise the webdav handler falls back to its default (size/mtime)
// computation, which matches the backend's behaviour since both values are
// preserved.
func (fi *cachedFileInfo) ETag(_ context.Context) (string, error) {
	if fi.etag != "" {
		return fi.etag, nil
	}
	return "", webdav.ErrNotImplemented
}

// ContentType keeps PROPFIND from opening the object; see contentTypedInfo.
func (fi *cachedFileInfo) ContentType(_ context.Context) (string, error) {
	if ct := mime.TypeByExtension(path.Ext(fi.name)); ct != "" {
		return ct, nil
	}
	return "application/octet-stream", nil
}

// ---------------------------------------------------------------------------
// cachedBackend — OriginBackend wrapper installing the caching filesystem
// ---------------------------------------------------------------------------

type cachedBackend struct {
	inner server_utils.OriginBackend
	fs    webdav.FileSystem
	cache *storageCache
	layer *storageCacheFS
}

func newCachedBackend(inner server_utils.OriginBackend, layer *storageCacheFS) *cachedBackend {
	return &cachedBackend{inner: inner, fs: layer, cache: layer.cache, layer: layer}
}

func (b *cachedBackend) CheckAvailability() error      { return b.inner.CheckAvailability() }
func (b *cachedBackend) FileSystem() webdav.FileSystem { return b.fs }

func (b *cachedBackend) Checksummer() server_utils.OriginChecksummer {
	inner := b.inner.Checksummer()
	if inner == nil {
		return nil
	}
	return &cachedChecksummer{inner: inner, layer: b.layer}
}

// cachedChecksummer suppresses the Digest header for objects being served from
// the cache.
//
// The backend computes digests from the object as it exists upstream right
// now, but a fresh cache entry is served from the copy taken when it was
// fetched.  If the object changed out-of-band in the meantime the two
// disagree, and a client that checks the digest against the body it received
// sees corruption rather than staleness.  Reporting no digest is honest: the
// origin cannot vouch for one without reading the object it is not reading.
type cachedChecksummer struct {
	inner server_utils.OriginChecksummer
	layer *storageCacheFS
}

func (c *cachedChecksummer) GetDigests(relativePath string, wantDigest string) ([]string, error) {
	metaRel, _, _ := c.layer.entryPaths(relativePath)
	if meta := c.layer.cache.readMeta(metaRel); meta != nil && c.layer.cache.isFresh(meta) {
		return nil, nil
	}
	return c.inner.GetDigests(relativePath, wantDigest)
}
