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
// reads.  Consistency follows the standard ETag revalidation rules: every
// read stats the upstream backend (a metadata-only operation with no data
// egress) and serves the local copy only when the upstream validator — the
// provider's ETag when available, otherwise a size/mtime-derived tag — still
// matches the one recorded when the copy was fetched.
//
// Freshness follows the same Cache-Control infrastructure the Pelican local
// cache uses (local_cache.CacheDirectives): the backend's Cache-Control —
// S3 object metadata or the upstream HTTPS response header — governs how
// long a copy may be served with no upstream interaction at all.  When the
// backend supplies no directives, a configurable default freshness lifetime
// applies (Origin.StorageCacheDefaultMaxAge, jittered per object like
// LocalCache.DefaultMaxAge).  Only once a copy goes stale does the layer
// revalidate: one upstream stat compares validators, and a match simply
// renews the freshness window without refetching.  no-store / private
// responses bypass the cache entirely; no-cache responses are cached but
// revalidated on (almost) every use.
//
// Fetches are decoupled from the requesting client: the upstream-to-disk
// copy runs in its own goroutine at full speed, while the client reads from
// the growing local file at its own pace.  A slow or disconnected client
// never stalls (or cancels) the fetch, so the cache always ends up with a
// complete copy that later readers can reuse.  Concurrent readers of the
// same object share a single upstream fetch.
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
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/server_utils"
)

const (
	// storageCacheEvictTarget is the fraction of the configured maximum size
	// eviction drives usage down to once the maximum is exceeded.
	storageCacheEvictTargetNum = 9
	storageCacheEvictTargetDen = 10

	// storageCacheJanitorInterval is how often the eviction pass runs.
	storageCacheJanitorInterval = time.Minute

	// storageCacheCopyBufSize is the buffer used for the upstream-to-disk copy.
	storageCacheCopyBufSize = 1 << 20
)

// cacheEntryMeta is the JSON sidecar recorded next to each cached data file.
// Its presence marks the data file as complete; it is written only after the
// full object has been copied from the upstream backend.  The sidecar's file
// mtime doubles as the entry's last-access time for LRU eviction.
type cacheEntryMeta struct {
	// Path is the object path within the export (for operator debugging).
	Path string `json:"path"`
	// Validator is the value compared against the upstream's current
	// validator to decide whether the copy is still current.
	Validator string `json:"validator"`
	// ETag is the client-visible upstream ETag, empty when the upstream did
	// not supply one (in which case the webdav default, derived from the
	// preserved size and mtime, applies).
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
	Size            int64  `json:"size"`
	ModTimeUnixNano int64  `json:"modTimeUnixNano"`
	DataFile        string `json:"dataFile"`
}

func (m *cacheEntryMeta) fileInfo(name string) *cachedFileInfo {
	return &cachedFileInfo{
		name:    path.Base(name),
		size:    m.Size,
		modTime: time.Unix(0, m.ModTimeUnixNano),
		etag:    m.ETag,
	}
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

	// defaultMaxAge is the freshness lifetime applied when the backend
	// supplies no Cache-Control freshness information; <= 0 means no default
	// freshness (every read revalidates).  revalidationJitter is the percent
	// of deterministic per-object jitter applied to defaultMaxAge, matching
	// the LocalCache.RevalidationJitter semantics.
	defaultMaxAge      time.Duration
	revalidationJitter int

	mu      sync.Mutex
	fetches map[string]*cacheFetch // keyed by the entry's meta-file path
}

// newStorageCache creates the cache root directory (if needed), opens a
// symlink-safe afero filesystem rooted there, and starts the eviction
// janitor.  The janitor and any in-flight fetches stop when ctx is done.
func newStorageCache(ctx context.Context, location string, maxSize int64, defaultMaxAge time.Duration, revalidationJitter int) (*storageCache, error) {
	if err := os.MkdirAll(location, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage cache directory %s: %w", location, err)
	}
	rootFs, err := server_utils.NewOsRootFs(location)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage cache directory %s: %w", location, err)
	}
	c := &storageCache{
		fs:                 rootFs,
		ctx:                ctx,
		maxSize:            maxSize,
		defaultMaxAge:      defaultMaxAge,
		revalidationJitter: revalidationJitter,
		fetches:            make(map[string]*cacheFetch),
	}
	go c.runJanitor()
	return c, nil
}

// newStorageCacheWithFs is the constructor used by tests: it accepts an
// arbitrary afero filesystem and does not start the janitor.
func newStorageCacheWithFs(ctx context.Context, fs afero.Fs, maxSize int64, defaultMaxAge time.Duration, revalidationJitter int) *storageCache {
	return &storageCache{
		fs:                 fs,
		ctx:                ctx,
		maxSize:            maxSize,
		defaultMaxAge:      defaultMaxAge,
		revalidationJitter: revalidationJitter,
		fetches:            make(map[string]*cacheFetch),
	}
}

// isFresh reports whether a completed cache entry may be served without any
// upstream interaction, per its recorded Cache-Control directives (or the
// configured default policy when the backend supplied none).
func (c *storageCache) isFresh(meta *cacheEntryMeta) bool {
	lastValidated := time.Unix(0, meta.LastValidatedUnixNano)
	cd := local_cache.ParseCacheControl(meta.CacheControl)
	return !cd.IsStaleFor(lastValidated, c.defaultMaxAge, c.revalidationJitter)
}

// newLayer returns the caching webdav.FileSystem for one export, scoped to
// its own subdirectory so objects from different exports never collide.
func (c *storageCache) newLayer(federationPrefix string, upstream webdav.FileSystem) *storageCacheFS {
	sum := sha256.Sum256([]byte(federationPrefix))
	sanitized := strings.ReplaceAll(strings.Trim(federationPrefix, "/"), "/", "_")
	if sanitized == "" {
		sanitized = "root"
	}
	return &storageCacheFS{
		cache:    c,
		upstream: upstream,
		scope:    fmt.Sprintf("%s.%s", sanitized, hex.EncodeToString(sum[:4])),
	}
}

func (c *storageCache) lookupFetch(metaRel string) *cacheFetch {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches[metaRel]
}

// getOrStartFetch returns the in-flight fetch for the entry, registering the
// provided one when none exists.  The winning fetch is returned; a losing
// (raced) fetch is discarded without side effects since fetches start lazily.
// Registering a fetch also creates its (empty) data file, so every attached
// reader can open a handle immediately — bytes already copied stay readable
// even if the fetch later aborts and unlinks the file.
func (c *storageCache) getOrStartFetch(f *cacheFetch) (*cacheFetch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing := c.fetches[f.metaRel]; existing != nil {
		return existing, nil
	}
	if err := c.fs.MkdirAll(path.Dir(f.dataRel), 0700); err != nil {
		return nil, fmt.Errorf("storage cache: failed to create cache directory: %w", err)
	}
	file, err := c.fs.OpenFile(f.dataRel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("storage cache: failed to create cache file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("storage cache: failed to create cache file: %w", err)
	}
	c.fetches[f.metaRel] = f
	return f, nil
}

// releaseUnstarted is called when the last reader of a never-started fetch
// closes: the registration and the empty data file are discarded so
// metadata-only opens (HEAD requests) leave nothing behind.
func (c *storageCache) releaseUnstarted(f *cacheFetch) {
	c.mu.Lock()
	if c.fetches[f.metaRel] == f {
		delete(c.fetches, f.metaRel)
	}
	c.mu.Unlock()
	if err := c.fs.Remove(f.dataRel); err != nil && !os.IsNotExist(err) {
		log.Debugf("Storage cache: failed to remove unused cache file %s: %v", f.dataRel, err)
	}
}

func (c *storageCache) unregisterFetch(metaRel string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.fetches, metaRel)
}

// writeMeta serializes the sidecar; the fresh mtime doubles as an LRU touch.
func (c *storageCache) writeMeta(metaRel string, meta *cacheEntryMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return afero.WriteFile(c.fs, metaRel, data, 0600)
}

func (c *storageCache) readMeta(metaRel string) *cacheEntryMeta {
	data, err := afero.ReadFile(c.fs, metaRel)
	if err != nil {
		return nil
	}
	var meta cacheEntryMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		// A torn write (e.g. crash mid-update) reads as a miss; the entry
		// will be refetched and the sidecar rewritten.
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
// never sees a sidecar pointing at a deleted data file's replacement).
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
// won't install its (pre-mutation) result as a completed entry.  Must be
// called BEFORE invalidate: the ordering guarantees that a fetch either sees
// the flag (and skips installing) or installed its sidecar beforehand, in
// which case the subsequent invalidate removes it.
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
			c.evictOnce()
		}
	}
}

// evictOnce scans the cache tree and, when total data-file usage exceeds the
// configured maximum, removes least-recently-accessed entries until usage
// falls below the eviction target.  Entries with an in-flight fetch are
// never evicted; data files with no sidecar and no in-flight fetch are
// orphans (crash leftovers) and are evicted first.
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

	c.mu.Lock()
	inFlight := make(map[string]bool, len(c.fetches))
	for metaRel := range c.fetches {
		inFlight[metaRel] = true
	}
	c.mu.Unlock()

	target := c.maxSize / storageCacheEvictTargetDen * storageCacheEvictTargetNum
	victims := entries[:0]
	for _, e := range entries {
		// Data files are named "<hash>-<generation>.data"; the sidecar is
		// "<hash>.meta" in the same directory.
		base := path.Base(e.dataRel)
		if idx := strings.IndexByte(base, '-'); idx > 0 {
			e.metaRel = path.Join(path.Dir(e.dataRel), base[:idx]+".meta")
		}
		if inFlight[e.metaRel] {
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
		if v.metaRel != "" {
			if err := c.fs.Remove(v.metaRel); err != nil && !os.IsNotExist(err) {
				log.Debugf("Storage cache: eviction failed to remove %s: %v", v.metaRel, err)
			}
		}
		if err := c.fs.Remove(v.dataRel); err != nil && !os.IsNotExist(err) {
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

// storageCacheEnumerationCap bounds the object list a directory mutation
// buffers while unrolling a subtree invalidation.  Beyond this, invalidation
// falls back to the sidecar scan: at that scale the mutation itself dwarfs a
// pass over the cache, and the scan needs no per-path memory.
const storageCacheEnumerationCap = 65536

// enumerateSubtree lists the object paths currently under name in the
// backend, so a directory mutation can be unrolled into exact per-object
// invalidations — O(subtree) instead of a scan of every cached sidecar.
// The listing is metadata-only (no data egress) and mirrors the one a blob
// backend's RemoveAll performs internally, so it covers exactly the objects
// the mutation affects.  Cached entries for objects that already vanished
// from the backend out-of-band are not the mutation's responsibility; the
// normal freshness/revalidation cycle retires them.
//
// Returns (paths, true) on success.  Returns (nil, false) when the backend
// cannot enumerate (e.g. a plain-HTTP upstream with no listing support) or
// the subtree exceeds storageCacheEnumerationCap; callers then fall back to
// the sidecar scan, which is authoritative over the cache's own contents.
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
	paths := []string{clean}
	var walk func(dir string) error
	walk = func(dir string) error {
		f, err := l.upstream.OpenFile(ctx, dir, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		for {
			ents, rdErr := f.Readdir(1024)
			for _, e := range ents {
				child := path.Join(dir, e.Name())
				if e.IsDir() {
					if err := walk(child); err != nil {
						return err
					}
					continue
				}
				if len(paths) >= storageCacheEnumerationCap {
					return errCapExceeded
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
	if err := walk(clean); err != nil {
		log.Debugf("Storage cache: subtree enumeration of %s failed (%v); falling back to sidecar scan", clean, err)
		return nil, false
	}
	return paths, true
}

// invalidateSubtreeEntries is the notification hook for mutations whose
// target may be a directory.  In-flight fetches under the subtree are always
// superseded first (an in-memory registry sweep) so none installs
// pre-mutation content afterwards.  Completed entries are then dropped: per
// enumerated path when the subtree could be listed, otherwise by scanning
// the export's sidecars (each records its object path).
func (l *storageCacheFS) invalidateSubtreeEntries(name string, targets []string, enumerated bool) {
	clean := path.Clean("/" + name)
	childPrefix := clean
	if childPrefix != "/" {
		childPrefix += "/"
	}
	matches := func(objPath string) bool {
		return objPath == clean || strings.HasPrefix(objPath, childPrefix)
	}

	// Supersede in-flight fetches first (see supersedeFetch for ordering).
	c := l.cache
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
	// subtree.  O(total cached entries), used only when the backend can't
	// tell us what lives under the prefix.
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
// HEAD-style probes cost no upstream round-trip; anything else (stale
// entries, misses, directories) is delegated to the backend.
func (l *storageCacheFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	metaRel, _, _ := l.entryPaths(name)
	if meta := l.cache.readMeta(metaRel); meta != nil && l.cache.isFresh(meta) {
		return meta.fileInfo(name), nil
	}
	return l.upstream.Stat(ctx, name)
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

	// An in-flight fetch for this object serves everyone; attach to it.  If
	// the attach races with the fetch being discarded (its last reader closed
	// before it started), fall through and register a fresh fetch.
	if f := l.cache.lookupFetch(metaRel); f != nil {
		if reader, attachErr := newFetchReader(ctx, f); attachErr == nil {
			return reader, nil
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
		return l.upstream.OpenFile(ctx, name, flag, perm)
	}

	validator, explicitETag := upstreamValidator(ctx, info)
	cacheControl := upstreamCacheControl(info)

	// no-store / private responses must not be persisted: drop any existing
	// copy (superseding a concurrently registered fetch, if any) and stream
	// straight from the backend.
	if cd := local_cache.ParseCacheControl(cacheControl); !cd.ShouldStore() {
		if meta != nil {
			l.cache.invalidateEntry(metaRel)
		}
		return l.upstream.OpenFile(ctx, name, flag, perm)
	}

	// Revalidated: the validator still matches, so renew the freshness
	// window (and pick up any Cache-Control change) and serve locally.
	oldDataFile := ""
	if meta != nil {
		if meta.Validator == validator {
			meta.CacheControl = cacheControl
			meta.LastValidatedUnixNano = time.Now().UnixNano()
			if wErr := l.cache.writeMeta(metaRel, meta); wErr != nil {
				log.Debugf("Storage cache: failed to renew metadata for %s: %v", metaRel, wErr)
			}
			if file, openErr := l.cache.fs.Open(path.Join(hashDir, meta.DataFile)); openErr == nil {
				return &cacheHitFile{File: file, info: meta.fileInfo(name)}, nil
			}
			// Data unreadable despite matching validator: refetch.
		}
		oldDataFile = meta.DataFile
	}

	// Miss (or stale): fetch from the backend into the cache.  The fetch
	// starts lazily on the first Read so metadata-only opens (HEAD requests,
	// size probes) never trigger data egress.
	gen := make([]byte, 8)
	if _, err := rand.Read(gen); err != nil {
		return nil, fmt.Errorf("failed to generate cache file name: %w", err)
	}
	etag := ""
	if explicitETag {
		etag = validator
	}
	f := &cacheFetch{
		cache:   l.cache,
		name:    name,
		metaRel: metaRel,
		dataRel: path.Join(hashDir, fmt.Sprintf("%s-%s.data", hash, hex.EncodeToString(gen))),
		meta: cacheEntryMeta{
			Path:                  path.Clean("/" + name),
			Validator:             validator,
			ETag:                  etag,
			CacheControl:          cacheControl,
			LastValidatedUnixNano: time.Now().UnixNano(),
			Size:                  info.Size(),
			ModTimeUnixNano:       info.ModTime().UnixNano(),
			DataFile:              fmt.Sprintf("%s-%s.data", hash, hex.EncodeToString(gen)),
		},
		oldDataRel: "",
		open: func(fetchCtx context.Context) (webdav.File, error) {
			return l.upstream.OpenFile(fetchCtx, name, os.O_RDONLY, 0)
		},
	}
	if oldDataFile != "" {
		f.oldDataRel = path.Join(hashDir, oldDataFile)
	}
	f.cond = sync.NewCond(&f.mu)
	f, err = l.cache.getOrStartFetch(f)
	if err != nil {
		return nil, err
	}
	return newFetchReader(ctx, f)
}

// upstreamValidator extracts the consistency validator for an upstream
// FileInfo: the backend's own ETag when it exposes one (webdav.ETager or the
// backend-specific Sys() payloads), otherwise the same size/mtime-derived
// tag the origin uses for local files.  The boolean reports whether the
// validator is a genuine upstream ETag (and therefore client-visible).
func upstreamValidator(ctx context.Context, info os.FileInfo) (string, bool) {
	if et, ok := info.(webdav.ETager); ok {
		if v, err := et.ETag(ctx); err == nil && v != "" {
			return v, true
		}
	}
	switch sys := info.Sys().(type) {
	case *BlobFileSysInfo:
		if sys.ETag != "" {
			return sys.ETag, true
		}
	case *HTTPSFileSysInfo:
		if sys.ETag != "" {
			return sys.ETag, true
		}
	}
	return computeETag(info), false
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
	cache      *storageCache
	name       string
	metaRel    string
	dataRel    string
	oldDataRel string // superseded data file removed once the new copy lands
	meta       cacheEntryMeta
	open       func(ctx context.Context) (webdav.File, error)

	mu      sync.Mutex
	cond    *sync.Cond
	started bool
	readers int
	written int64
	done    bool
	err     error

	// superseded is set (under storageCache.mu, NOT this mutex) when the
	// object is mutated through the origin while this fetch is in flight.
	// A superseded fetch still streams to its attached readers, but must not
	// install its result as a completed cache entry: the bytes it is copying
	// predate the mutation, yet its validation timestamp would look fresh.
	superseded bool
}

// ensureStarted launches the copy goroutine exactly once.  The copy runs
// under the cache's server-lifetime context, not any request context, so a
// slow or disconnected client never cancels it.
func (f *cacheFetch) ensureStarted() {
	f.mu.Lock()
	if f.started {
		f.mu.Unlock()
		return
	}
	f.started = true
	f.mu.Unlock()
	go f.run()
}

func (f *cacheFetch) run() {
	src, err := f.open(f.cache.ctx)
	if err != nil {
		f.finish(fmt.Errorf("storage cache: upstream open of %s failed: %w", f.name, err))
		return
	}
	defer src.Close()

	// The (empty) data file was created when the fetch was registered.
	dst, err := f.cache.fs.OpenFile(f.dataRel, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		f.finish(fmt.Errorf("storage cache: failed to create cache file: %w", err))
		return
	}

	buf := make([]byte, storageCacheCopyBufSize)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				dst.Close()
				f.abort(fmt.Errorf("storage cache: write to cache file failed: %w", writeErr))
				return
			}
			f.mu.Lock()
			f.written += int64(n)
			f.cond.Broadcast()
			f.mu.Unlock()
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

	// The size was captured at revalidation time; a mismatch means the
	// object changed (or was truncated) mid-fetch, so the copy cannot be
	// trusted and readers must see an error rather than a silent short read.
	f.mu.Lock()
	written := f.written
	f.mu.Unlock()
	if written != f.meta.Size {
		f.abort(fmt.Errorf("storage cache: fetched %d bytes for %s but upstream reported %d", written, f.name, f.meta.Size))
		return
	}

	// Install the completed entry.  The superseded check and the sidecar
	// write happen under the registry lock so they are atomic with respect
	// to supersedeFetch: either the flag is seen here (no install), or the
	// sidecar lands before the mutation's invalidation sweep and is removed
	// by it.
	f.cache.mu.Lock()
	superseded := f.superseded
	var installErr error
	if !superseded {
		installErr = f.cache.writeMeta(f.metaRel, &f.meta)
	}
	f.cache.mu.Unlock()
	if superseded {
		log.Debugf("Storage cache: fetch of %s was superseded by a write; discarding", f.name)
		if err := f.cache.fs.Remove(f.dataRel); err != nil && !os.IsNotExist(err) {
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
		if err := f.cache.fs.Remove(f.oldDataRel); err != nil && !os.IsNotExist(err) {
			log.Debugf("Storage cache: failed to remove superseded data file %s: %v", f.oldDataRel, err)
		}
	}
	f.finish(nil)
}

// abort discards the partial cache file and reports err to readers.
func (f *cacheFetch) abort(err error) {
	if rmErr := f.cache.fs.Remove(f.dataRel); rmErr != nil && !os.IsNotExist(rmErr) {
		log.Debugf("Storage cache: failed to remove partial cache file %s: %v", f.dataRel, rmErr)
	}
	f.finish(err)
}

func (f *cacheFetch) finish(err error) {
	if err != nil {
		log.Warningf("%v", err)
	}
	f.mu.Lock()
	f.done = true
	f.err = err
	f.cond.Broadcast()
	f.mu.Unlock()
	f.cache.unregisterFetch(f.metaRel)
}

// ---------------------------------------------------------------------------
// fetchReader — a client's view of an in-flight (or lazily started) fetch
// ---------------------------------------------------------------------------

type fetchReader struct {
	fetch  *cacheFetch
	reqCtx context.Context

	mu     sync.Mutex
	file   afero.File
	closed bool
	offset int64
}

// newFetchReader attaches a reader to the fetch, opening its own handle on
// the shared data file up front.  Holding the handle from the start
// guarantees the reader can deliver every byte the fetch reports as written,
// even if the fetch aborts (and unlinks the file) mid-stream.
func newFetchReader(reqCtx context.Context, f *cacheFetch) (*fetchReader, error) {
	file, err := f.cache.fs.Open(f.dataRel)
	if err != nil {
		return nil, fmt.Errorf("storage cache: failed to open cache file for read: %w", err)
	}
	f.mu.Lock()
	f.readers++
	f.mu.Unlock()
	return &fetchReader{fetch: f, reqCtx: reqCtx, file: file}, nil
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
	r.offset += int64(read)
	if err == io.EOF && read > 0 {
		err = nil
	}
	return read, err
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

	// If no reader ever triggered the fetch and this was the last handle
	// (typical for HEAD requests), discard the pending fetch so the registry
	// and disk don't accumulate never-used entries.
	f := r.fetch
	f.mu.Lock()
	f.readers--
	discard := f.readers == 0 && !f.started
	f.mu.Unlock()
	if discard {
		f.cache.releaseUnstarted(f)
	}
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

// Stat reports the preserved upstream metadata, not the local file's, so
// ETags and Last-Modified are identical whether the response is served from
// the cache or the backend.
func (f *cacheHitFile) Stat() (os.FileInfo, error) { return f.info, nil }

func (f *cacheHitFile) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write not supported on cached read file")
}

func (f *cacheHitFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on file")
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

// ETag exposes the upstream's ETag when one was recorded; otherwise the
// webdav handler falls back to its default (size/mtime) computation, which
// matches the backend's behaviour since both values are preserved.
func (fi *cachedFileInfo) ETag(_ context.Context) (string, error) {
	if fi.etag != "" {
		return fi.etag, nil
	}
	return "", webdav.ErrNotImplemented
}

// ---------------------------------------------------------------------------
// cachedBackend — OriginBackend wrapper installing the caching filesystem
// ---------------------------------------------------------------------------

type cachedBackend struct {
	inner server_utils.OriginBackend
	fs    webdav.FileSystem
}

func newCachedBackend(inner server_utils.OriginBackend, fs webdav.FileSystem) *cachedBackend {
	return &cachedBackend{inner: inner, fs: fs}
}

func (b *cachedBackend) CheckAvailability() error      { return b.inner.CheckAvailability() }
func (b *cachedBackend) FileSystem() webdav.FileSystem { return b.fs }
func (b *cachedBackend) Checksummer() server_utils.OriginChecksummer {
	return b.inner.Checksummer()
}
