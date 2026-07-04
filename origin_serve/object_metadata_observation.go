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

// File object_metadata_observation.go is the Stat-path glue between
// the aferoFileSystem wrappers and the object-metadata DAO. It owns:
//
//   1. The in-memory LRU cache that absorbs repeat-Stat traffic so
//      most reads incur zero DB work.
//   2. The "listing mode" context flag and helpers, used by the
//      gin middleware to mark PROPFIND-with-Depth>=1 requests as
//      "directory enumeration; do not observe individual entries."
//   3. The handle{Stat,ENOENT,Delete,Rename} entry points each
//      aferoFileSystem method calls — they do the cache lookup,
//      compare etags, and enqueue best-effort observation writes
//      through the batcher.

package origin_serve

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
)

// ============================================================
// Listing-mode context flag
// ============================================================

// listingModeKey is the context key the HTTP middleware sets when
// the request is a directory-enumeration PROPFIND. The Stat path
// reads this and short-circuits *before* any cache/SELECT/enqueue —
// listing 100k objects must stay as cheap as it is today.
type listingModeKey struct{}

// withListingMode flags ctx as belonging to a directory-enumeration
// request. Returned ctx is suitable for use as the request context
// for downstream handlers.
func withListingMode(ctx context.Context) context.Context {
	return context.WithValue(ctx, listingModeKey{}, true)
}

// isListingMode returns true iff withListingMode was called on this
// (or an ancestor of this) ctx.
func isListingMode(ctx context.Context) bool {
	v, _ := ctx.Value(listingModeKey{}).(bool)
	return v
}

// ============================================================
// In-memory LRU cache
// ============================================================

// observationCacheKey is the cache key — a (namespace, federation-
// rooted-path) tuple. Keys are namespaced so a multi-export origin
// cannot accidentally collide paths between namespaces.
type observationCacheKey struct {
	Namespace string
	Path      string
}

// observationCacheEntry holds just enough state to decide whether
// the backend's current ETag matches what we last recorded.
type observationCacheEntry struct {
	// ETag last seen by us, exactly as the backend reported it.
	ETag string
	// LastSeenAt is when we wrote this entry. Not load-bearing for
	// correctness (the cache is event-invalidated, not TTL'd) but
	// useful for diagnostics.
	LastSeenAt time.Time
}

// observationCache wraps the project-standard ttlcache with our
// tuple key translation. ttlcache supports both LRU-style capacity
// eviction and per-entry TTL; we use LRU only — entries have no
// TTL, since invalidation is event-driven (RecordCommit / Delete /
// Rename each Invalidate the key explicitly). Defaults to 16k
// entries — at ~48 bytes/entry that's <1 MiB resident.
//
// Using ttlcache here (rather than golang-lru) keeps cache-library
// usage consistent with the rest of Pelican (director, broker,
// metrics, identity, pelican_url all use ttlcache).
type observationCache struct {
	inner *ttlcache.Cache[observationCacheKey, observationCacheEntry]
}

func newObservationCache(size int) *observationCache {
	if size <= 0 {
		size = 16 * 1024
	}
	c := ttlcache.New[observationCacheKey, observationCacheEntry](
		ttlcache.WithCapacity[observationCacheKey, observationCacheEntry](uint64(size)),
		// Per-entry TTL is meaningless for an event-invalidated
		// cache — disable touch-on-hit so a hot key doesn't burn
		// CPU bumping its expiry timer.
		ttlcache.WithDisableTouchOnHit[observationCacheKey, observationCacheEntry](),
	)
	// Note: we do NOT call c.Start(). The background expiration
	// goroutine only matters when TTL is in use; LRU capacity
	// eviction happens inline on Set.
	return &observationCache{inner: c}
}

func (c *observationCache) Get(ns, p string) (observationCacheEntry, bool) {
	if c == nil {
		return observationCacheEntry{}, false
	}
	item := c.inner.Get(observationCacheKey{Namespace: ns, Path: p})
	if item == nil {
		return observationCacheEntry{}, false
	}
	return item.Value(), true
}

func (c *observationCache) Set(ns, p, etag string) {
	if c == nil {
		return
	}
	c.inner.Set(observationCacheKey{Namespace: ns, Path: p}, observationCacheEntry{
		ETag:       etag,
		LastSeenAt: time.Now(),
	}, ttlcache.NoTTL)
}

// Invalidate is called by the durable write paths (RecordCommit,
// RecordDelete, RecordRename) so a subsequent read does NOT see a
// stale cached value. Without this, the next Stat after a delete
// would see a non-empty cache entry, decide "etag matches" against
// the now-empty backend, and... well, actually the backend would
// have returned ENOENT, so the cache hit short-circuit wouldn't
// fire. But it's good hygiene.
func (c *observationCache) Invalidate(ns, p string) {
	if c == nil {
		return
	}
	c.inner.Delete(observationCacheKey{Namespace: ns, Path: p})
}

// ============================================================
// Observation glue (the bit aferoFileSystem.Stat calls)
// ============================================================

// observationConfig is a per-export bundle: the namespace this
// aferoFileSystem serves, the DAO, the cache, and the per-namespace
// TrackExtra toggle. Nil when TrackAccess is off for the namespace.
type observationConfig struct {
	namespace  string
	trackExtra bool
	dao        *objectMetadataDAO
	cache      *observationCache

	// accessDebouncer is shared origin-wide (its key carries the
	// namespace, so one instance handles every export). nil when
	// access tracking is disabled.
	accessDebouncer *accessDebouncer

	// Counter (atomic) for cache hits; useful for testing the fast
	// path. Updated by handleStat; not exposed to metrics directly
	// — the metrics package can read this if it wants a precise
	// "cache hit rate" number, but in practice the storage layer
	// metrics already capture the cost difference indirectly.
	cacheHits atomic.Int64
}

// handleStatSuccess is called after a successful backend Stat. It
// runs the change-detection ladder:
//
//   - cache hit + etag matches → fast path; nothing to do
//   - cache hit + etag differs → enqueue external_modify
//   - cache miss + live row matches → cache; nothing to do
//   - cache miss + live row differs → enqueue external_modify
//   - cache miss + no row → enqueue external_observe
//
// All enqueues are best-effort. Callers must check listing-mode
// themselves before calling here (we keep this layer dumb about
// listing-mode so it remains testable without a request context).
func (o *observationConfig) handleStatSuccess(ctx context.Context, fedPath string, info os.FileInfo) {
	if o == nil || info == nil {
		return
	}
	etag := BackendETag(info)
	size := info.Size()
	mtime := info.ModTime()

	// Every successful Stat counts as an "access" — record it via
	// the debouncer so a hot file doesn't generate one UPDATE per
	// GET. The debouncer's periodic flush picks up the latest
	// observed timestamp per key.
	if o.accessDebouncer != nil {
		o.accessDebouncer.Note(o.namespace, fedPath, time.Now())
	}

	if entry, ok := o.cache.Get(o.namespace, fedPath); ok {
		if entry.ETag == etag {
			o.cacheHits.Add(1)
			objMetaCacheHits.WithLabelValues(o.namespace).Inc()
			return
		}
		// Cache says we knew a different etag; record an
		// external_modify against the *cached* value (faster than
		// re-reading the live row, and the cache mirrors the live
		// row's etag at our last write).
		objMetaCacheHits.WithLabelValues(o.namespace).Inc()
		o.recordExternalChange(ctx, fedPath, size, etag, mtime)
		o.cache.Set(o.namespace, fedPath, etag)
		return
	}

	objMetaCacheMisses.WithLabelValues(o.namespace).Inc()
	// Cache miss: consult the live row.
	live, err := o.dao.LookupLive(ctx, o.namespace, fedPath)
	if err != nil {
		log.Debugf("object-metadata observation: LookupLive(%s,%s) failed: %v", o.namespace, fedPath, err)
		return
	}
	if live == nil {
		o.recordExternalObserve(ctx, fedPath, size, etag, mtime)
		o.cache.Set(o.namespace, fedPath, etag)
		return
	}
	if live.ETag == etag {
		// Live row already in sync with backend; just warm cache.
		o.cache.Set(o.namespace, fedPath, etag)
		return
	}
	o.recordExternalChange(ctx, fedPath, size, etag, mtime)
	o.cache.Set(o.namespace, fedPath, etag)
}

// handleENOENT runs the external_delete branch: if we have a record
// of this path (live cache entry OR a live DAO row) and the backend
// says it's gone, snapshot the prior state and soft-delete.
//
// We deliberately do NOT short-circuit on cache miss alone, because
// the cache is bounded (LRU). An object that was committed long
// ago — past the cache's working set — could be deleted out-of-band
// and never observed: the next Stat would see ENOENT, find a cold
// cache, and return without firing. The fix is to also LookupLive
// when the cache misses. Cost: one indexed SELECT per ENOENT that
// passes the cache. ENOENTs against a hot cache (typo'd GETs) stay
// cheap because the cache invalidate on prior delete leaves them
// permanently absent.
func (o *observationConfig) handleENOENT(ctx context.Context, fedPath string) {
	if o == nil {
		return
	}
	if _, ok := o.cache.Get(o.namespace, fedPath); !ok {
		// Cold cache: ask the DAO whether we have a row for this
		// path. Only pay the SELECT once per ENOENT; if there's
		// no row, no observation is needed.
		live, err := o.dao.LookupLive(ctx, o.namespace, fedPath)
		if err != nil {
			log.Debugf("object-metadata observation: LookupLive on ENOENT(%s,%s) failed: %v", o.namespace, fedPath, err)
			return
		}
		if live == nil {
			return
		}
		// Fall through to RecordExternalDelete below.
	}
	// Cache hit or DAO row present; either way, the backend now
	// disagrees. Drop the cache entry and record the delete.
	o.cache.Invalidate(o.namespace, fedPath)
	if err := o.dao.RecordExternalDelete(ctx, o.namespace, fedPath); err != nil {
		log.Debugf("object-metadata observation: RecordExternalDelete(%s,%s) failed: %v", o.namespace, fedPath, err)
		return
	}
	objMetaExternalChanges.WithLabelValues(o.namespace, string(ObjectEventExternalDelete)).Inc()
}

func (o *observationConfig) recordExternalObserve(ctx context.Context, fedPath string, size int64, etag string, mtime time.Time) {
	in := ObjectMetadataEventInput{
		Namespace:    o.namespace,
		ObjectPath:   fedPath,
		Size:         size,
		ETag:         etag,
		EtagSource:   EtagSourceBackend,
		BackendMtime: mtime,
		// Actor unknown — no token context on background-init
		// observations. The TODO(actor) work will fill these in
		// from request context where available.
	}
	if err := o.dao.RecordExternalObserve(ctx, in); err != nil {
		log.Debugf("object-metadata observation: RecordExternalObserve(%s,%s) failed: %v", o.namespace, fedPath, err)
		return
	}
	objMetaExternalChanges.WithLabelValues(o.namespace, string(ObjectEventExternalObserve)).Inc()
}

func (o *observationConfig) recordExternalChange(ctx context.Context, fedPath string, size int64, etag string, mtime time.Time) {
	in := ObjectMetadataEventInput{
		Namespace:    o.namespace,
		ObjectPath:   fedPath,
		Size:         size,
		ETag:         etag,
		EtagSource:   EtagSourceBackend,
		BackendMtime: mtime,
	}
	if err := o.dao.RecordExternalChange(ctx, in); err != nil {
		log.Debugf("object-metadata observation: RecordExternalChange(%s,%s) failed: %v", o.namespace, fedPath, err)
		return
	}
	objMetaExternalChanges.WithLabelValues(o.namespace, string(ObjectEventExternalModify)).Inc()
}

// closeHookFn is the close-hook function signature used everywhere a
// POSC- or closeNotifyFs- shaped wrapper needs to install one. The
// signature mirrors poscFileSystem.closeHook so callers can pass any
// of {nil, RecordCommitCloseHook, metadataController.CommitEventFromCloseHook,
// composeCloseHooks(...)} without having to spell the full func type.
type closeHookFn = func(ctx context.Context, finalPath string, info os.FileInfo) error

// composeCloseHooks merges any number of close hooks into a single
// closure. Hooks fire in the order they appear in the argument list;
// nil hooks are silently skipped. The composed function returns the
// LAST hook's return value verbatim — including nil. Earlier hooks'
// errors are intentionally discarded.
//
// Convention for callers: put the hook whose error you care about
// last. Best-effort hooks (tracking, audit, debounced atime) go
// earlier so their errors are unconditionally swallowed by the
// final hook's return. The single hook whose failure must surface
// (publish, in our case) goes last.
//
// Returns nil iff every argument is nil — saves the caller a length
// check at the install site.
//
// Extracted from the inline closure in InitializeHandlers so the
// ordering / error-isolation contract is unit-testable.
func composeCloseHooks(hooks ...closeHookFn) closeHookFn {
	// Compact: drop nil entries up front so the hot-path closure
	// doesn't pay for nil checks on every fire.
	live := hooks[:0]
	for _, h := range hooks {
		if h != nil {
			live = append(live, h)
		}
	}
	switch len(live) {
	case 0:
		return nil
	case 1:
		return live[0]
	}
	// Capture into a fresh slice so the closure doesn't share
	// storage with the input slice.
	chain := append([]closeHookFn(nil), live...)
	return func(ctx context.Context, finalPath string, info os.FileInfo) error {
		var ret error
		for _, h := range chain {
			// Every hook fires; the final assignment wins
			// (including nil, which overwrites earlier errors —
			// that's the "best-effort earlier hook" property the
			// callers depend on).
			ret = h(ctx, finalPath, info)
		}
		return ret
	}
}

// RecordCommitCloseHook returns a closure suitable as a POSC / close-
// notify close hook that funnels the commit through the DAO's
// durable RecordCommit path. The closure pulls the actor (token sub)
// and custom-field extra map from the request context — both set by
// the upstream middlewares (authMiddleware, extractObjectMetadataFromRequest).
//
// Returned hook is nil-safe: if dao is nil it's a no-op.
func RecordCommitCloseHook(dao *objectMetadataDAO, namespace string, trackExtra bool) func(ctx context.Context, finalPath string, info os.FileInfo) error {
	if dao == nil {
		return func(context.Context, string, os.FileInfo) error { return nil }
	}
	return func(ctx context.Context, finalPath string, info os.FileInfo) error {
		var size int64
		var mtime time.Time
		if info != nil {
			size = info.Size()
			mtime = info.ModTime()
		}
		etag := BackendETag(info)
		// Source attribution:
		//   - empty etag → origin (we'd fill in nothing the
		//     backend didn't give us anyway)
		//   - POSC's poscDigestFileInfo wrapper → origin (the
		//     digest was computed by POSC's EtagPolicy, not the
		//     backend; visible to callers in this discriminator)
		//   - otherwise → backend (the storage layer's own ETag,
		//     whether real or synthesised)
		src := EtagSourceBackend
		if etag == "" {
			src = EtagSourceOrigin
		}
		if _, ok := info.(poscDigestFileInfo); ok {
			src = EtagSourceOrigin
		}
		fedPath := joinFederationPath(namespace, finalPath)
		// Invalidate the observation cache: a subsequent Stat
		// should re-warm against the freshly-committed etag, not
		// the previous value.
		// (Cache lives on the observationConfig the aferoFS
		// holds; we don't have it here. The Stat path itself will
		// notice the etag has changed and update on next access —
		// which is functionally equivalent.)
		var custom map[string]any
		if cm := objectMetadataFromContext(ctx); cm != nil {
			custom = map[string]any(cm)
		}
		return dao.RecordCommit(ctx, ObjectMetadataEventInput{
			Namespace:    namespace,
			ObjectPath:   fedPath,
			Size:         size,
			ETag:         etag,
			EtagSource:   src,
			BackendMtime: mtime,
			Actor:        usernameFromContext(ctx),
			Extra:        custom,
			TrackExtra:   trackExtra,
			// Populated by the TPC handler before it OpenFiles the
			// destination; "" for direct PUTs (which will store
			// NULL, clearing any stale value from a prior TPC).
			SourceEtag: sourceEtagFromContext(ctx),
		})
	}
}
