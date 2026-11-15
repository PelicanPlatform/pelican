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

// Storage cache: a webdav.FileSystem layer that keeps local copies of
// objects read from a remote origin backend (S3, HTTPS, Globus).
//
// An origin outside its storage provider pays egress for every byte it reads
// from the backend, so a local disk can absorb repeat reads.  The copies live
// in the cache server's block store (local_cache.SourcedCache), which fetches
// each object's blocks as readers need them, shares one fetch among the
// readers of an object, pins every fetch to the version's entity tag so a
// copy never mixes two versions, verifies every block it reads back, and
// evicts least-recently-used objects.  This layer decides what the store is
// asked for: which version of an object is current, when a copy may be served
// without asking the backend, and when an origin-side write has made one
// stale.
//
// Freshness follows the standard Cache-Control rules (the cache_control
// package): the backend's own Cache-Control -- an S3 object's metadata or an
// HTTPS response header -- says how long a copy may be served without asking
// the backend.  Without one, Origin.StorageCacheDefaultMaxAge applies,
// jittered per object; it also caps what a backend may claim, so whoever can
// write an object's metadata cannot pin it in the cache.  A stale copy is
// revalidated with one metadata request; if the entity tag still matches it
// is served again, and otherwise the new version is cached in its place.
// no-store and private objects are never cached.
//
// Only objects whose backend reports a strong entity tag are cached, since
// that is what pins each block fetch to one version.  Requests for others go
// straight to the backend.
//
// The layer is an optimization, never a dependency: when the cache cannot
// serve a request, or is already fetching as much as it may, the request
// goes straight to the backend.
package origin_serve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/cache_control"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/server_utils"
)

const (
	// storageCacheMutationWindow is how long the cache remembers an
	// origin-side write.  A backend stat older than this is never used to
	// publish a version, so the window bounds how long the memory is needed;
	// see storageCache.publish.
	storageCacheMutationWindow = 10 * time.Minute

	// storageCacheEnumerationCap bounds the object list a directory mutation
	// buffers while unrolling a subtree invalidation, and
	// storageCacheMaxEnumDepth bounds how deep the walk recurses.  Beyond
	// either, invalidation falls back to a scan of the cache.
	storageCacheEnumerationCap = 65536
	storageCacheMaxEnumDepth   = 64
)

// versionRangeReader is a backend filesystem that can read part of one
// version of an object; see local_cache.BlockSource.  The cache layers only
// backends that implement it.
type versionRangeReader interface {
	ReadVersionRange(ctx context.Context, name string, w io.Writer, start, end int64, etag string) error
}

// storageCacheConfig is what newStorageCache takes from Origin.StorageCache*.
type storageCacheConfig struct {
	Dir                  string
	MaxSize              uint64 // 0 sizes the cache to its filesystem
	DefaultMaxAge        time.Duration
	JitterPercent        int
	MaxConcurrentFetches int
}

// storageCache is shared by every export's layer, so one size bound covers
// them all.
type storageCache struct {
	store  *local_cache.SourcedCache
	policy cache_control.Policy

	// fetchSem bounds the backend reads filling the cache.  A request for
	// an object not fully cached when it is full goes to the backend
	// instead of queueing.
	fetchSem chan struct{}

	// mu guards mutations, and orders publishing a version against an
	// origin-side write; see publish.
	mu        sync.Mutex
	mutations []storageCacheMutation
}

// storageCacheMutation records that a write through this origin changed an
// object, or everything below a directory.
type storageCacheMutation struct {
	scope   string
	path    string
	subtree bool
	at      time.Time
}

func (m storageCacheMutation) covers(scope, p string) bool {
	if m.scope != scope {
		return false
	}
	if p == m.path {
		return true
	}
	return m.subtree && (m.path == "/" || strings.HasPrefix(p, m.path+"/"))
}

// newStorageCache opens the cache.  It is closed when ctx is done; egrp runs
// its background work.
func newStorageCache(ctx context.Context, egrp *errgroup.Group, cfg storageCacheConfig) (*storageCache, error) {
	store, err := local_cache.OpenSourcedCache(ctx, egrp, local_cache.SourcedCacheConfig{
		Dir:     cfg.Dir,
		MaxSize: cfg.MaxSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open the storage cache in %s: %w", cfg.Dir, err)
	}
	egrp.Go(func() error {
		<-ctx.Done()
		return store.Close()
	})
	return &storageCache{
		store: store,
		policy: cache_control.Policy{
			DefaultMaxAge: cfg.DefaultMaxAge,
			JitterPercent: cfg.JitterPercent,
			// A backend may shorten its objects' freshness but not extend it
			// beyond the operator's configured window.
			MaxFreshness: cfg.DefaultMaxAge,
		},
		fetchSem: make(chan struct{}, max(cfg.MaxConcurrentFetches, 1)),
	}, nil
}

// isFresh reports whether a copy may be served without asking the backend.
func (c *storageCache) isFresh(meta *local_cache.CacheMetadata) bool {
	// A zero default max-age means "revalidate every read".  Honour that
	// literally: a backend-supplied max-age must not re-enable serving
	// without an upstream check.
	if c.policy.DefaultMaxAge <= 0 {
		return false
	}
	return !meta.GetCacheDirectives().IsStaleFor(meta.LastValidated, c.policy, meta.SourceURL)
}

// noteMutation records that a write through this origin has changed p (and,
// with subtree, everything below it), so that no backend stat taken before
// now can publish a version of it.
func (c *storageCache) noteMutation(scope, p string, subtree bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneMutationsLocked()
	c.mutations = append(c.mutations, storageCacheMutation{scope: scope, path: p, subtree: subtree, at: time.Now()})
}

func (c *storageCache) pruneMutationsLocked() {
	cutoff := time.Now().Add(-storageCacheMutationWindow)
	kept := c.mutations[:0]
	for _, m := range c.mutations {
		if m.at.After(cutoff) {
			kept = append(kept, m)
		}
	}
	c.mutations = kept
}

// publish makes version etag of the object at p current, as a backend stat
// sent at statSent reported it, and reports whether it did.
//
// It does not if a write through this origin changed the object since the
// stat was sent: the stat may describe the object before the write, and
// publishing it would undo the write's invalidation.  A write records itself
// (noteMutation) before it drops the cached pointer, and this checks the
// record and publishes under the same lock, so either the write's record is
// seen here or its drop comes after the publication.  A stat older than the
// window over which writes are remembered is refused outright.
func (c *storageCache) publish(scope, p, key, etag string, statSent time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneMutationsLocked()
	if time.Since(statSent) >= storageCacheMutationWindow {
		return false, nil
	}
	for _, m := range c.mutations {
		if m.covers(scope, p) && !m.at.Before(statSent) {
			return false, nil
		}
	}
	return c.store.Publish(key, etag, statSent)
}

// newLayer returns the caching filesystem for one export.  backendID names
// the storage the export reads (type, endpoint, prefix); it is part of the
// scope every object is cached under, so repointing an export at other
// storage cannot serve copies made from the old.
func (c *storageCache) newLayer(federationPrefix, backendID string, upstream webdav.FileSystem) (*storageCacheFS, error) {
	ranger, ok := upstream.(versionRangeReader)
	if !ok {
		return nil, fmt.Errorf("the storage backend of %s cannot be cached", federationPrefix)
	}
	sum := sha256.Sum256([]byte(federationPrefix + "\x00" + backendID))
	scope := hex.EncodeToString(sum[:8])
	ns, err := c.store.Namespace(scope)
	if err != nil {
		return nil, err
	}
	// Only the HTTPS backend in plain-HTTP mode shows clients the backend's
	// entity tag; the rest let the WebDAV handler derive one from size and
	// modification time.  Copies must look the same either way.
	httpsFS, isHTTPS := upstream.(*httpsFileSystem)
	return &storageCacheFS{
		cache:      c,
		upstream:   upstream,
		ranger:     ranger,
		scope:      scope,
		namespace:  ns,
		exposeETag: isHTTPS && httpsFS.backendMode == BackendModeHTTP,
	}, nil
}

// ---------------------------------------------------------------------------
// storageCacheFS -- the per-export webdav.FileSystem layer
// ---------------------------------------------------------------------------

type storageCacheFS struct {
	cache      *storageCache
	upstream   webdav.FileSystem
	ranger     versionRangeReader
	scope      string
	namespace  local_cache.NamespaceID
	exposeETag bool
}

// key names an object in the cache.  It is a URL only because the store
// keys objects by one.
func (l *storageCacheFS) key(p string) string {
	return (&url.URL{Scheme: "origin-cache", Host: l.scope, Path: p}).String()
}

func cleanObjectPath(name string) string {
	return path.Clean("/" + name)
}

// lookupFresh returns the object's copy if it may be served without asking
// the backend.
func (l *storageCacheFS) lookupFresh(p string) (local_cache.InstanceHash, *local_cache.CacheMetadata) {
	ih, meta, err := l.cache.store.Lookup(l.key(p))
	if err != nil {
		log.Warningf("Storage cache: lookup of %s failed: %v", p, err)
		return "", nil
	}
	if meta == nil || !l.cache.isFresh(meta) {
		return "", nil
	}
	return ih, meta
}

func (l *storageCacheFS) fileInfo(p string, meta *local_cache.CacheMetadata) *cachedFileInfo {
	fi := &cachedFileInfo{
		name:    path.Base(p),
		size:    meta.ContentLength,
		modTime: meta.LastModified,
	}
	if l.exposeETag {
		fi.etag = meta.ETag
	}
	return fi
}

// passthrough serves a request straight from the backend.
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
	// Enumerate the subtree before the backend deletes it, and invalidate
	// afterwards whatever the result: a partial failure may still have
	// removed some of it.
	targets, enumerated := l.enumerateSubtree(ctx, name)
	err := l.upstream.RemoveAll(ctx, name)
	l.invalidateSubtree(name, targets, enumerated)
	return err
}

func (l *storageCacheFS) Rename(ctx context.Context, oldName, newName string) error {
	// The source moves away, and the destination may have held objects that
	// are now overwritten.
	oldTargets, oldEnumerated := l.enumerateSubtree(ctx, oldName)
	newTargets, newEnumerated := l.enumerateSubtree(ctx, newName)
	err := l.upstream.Rename(ctx, oldName, newName)
	l.invalidateSubtree(oldName, oldTargets, oldEnumerated)
	l.invalidateSubtree(newName, newTargets, newEnumerated)
	return err
}

// invalidate drops the copy of one object that a write has changed.
func (l *storageCacheFS) invalidate(name string) {
	p := cleanObjectPath(name)
	l.cache.noteMutation(l.scope, p, false)
	if err := l.cache.store.Forget(l.key(p)); err != nil {
		log.Warningf("Storage cache: failed to drop %s after a write: %v", p, err)
	}
}

// invalidateSubtree drops the copies under a directory a mutation changed:
// per enumerated path when the subtree could be listed, otherwise by scanning
// the cache.
func (l *storageCacheFS) invalidateSubtree(name string, targets []string, enumerated bool) {
	p := cleanObjectPath(name)
	l.cache.noteMutation(l.scope, p, true)
	var err error
	if enumerated {
		for _, t := range targets {
			if err = l.cache.store.Forget(l.key(t)); err != nil {
				break
			}
		}
	} else {
		prefix := l.key(p)
		if p != "/" {
			if err = l.cache.store.Forget(prefix); err == nil {
				prefix += "/"
			}
		}
		if err == nil {
			_, err = l.cache.store.ForgetPrefix(prefix)
		}
	}
	if err != nil {
		log.Warningf("Storage cache: failed to drop copies under %s after a change: %v", p, err)
	}
}

// enumerateSubtree lists the object paths under name in the backend, so a
// directory mutation can be unrolled into per-object invalidations instead of
// a scan of the whole cache.  The listing is metadata-only.
//
// It returns (paths, true) on success, and (nil, false) when the backend
// cannot enumerate (e.g. a plain-HTTP upstream with no listing support) or the
// subtree exceeds the enumeration cap or depth limit; callers then fall back
// to the scan.
func (l *storageCacheFS) enumerateSubtree(ctx context.Context, name string) ([]string, bool) {
	clean := cleanObjectPath(name)
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
				// millions of empty "directories" costs as much to walk as
				// one made of objects.
				if len(paths) >= storageCacheEnumerationCap {
					return errCapExceeded
				}
				paths = append(paths, child)
				if e.IsDir() {
					if err := walk(child, depth+1); err != nil {
						return err
					}
				}
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
		log.Debugf("Storage cache: subtree enumeration of %s failed (%v); falling back to a scan", clean, err)
		return nil, false
	}
	return paths, true
}

// Stat answers from a fresh copy without asking the backend; otherwise it
// asks the backend, and renews the copy if the backend still has its
// version.
//
// Results carry a Content-Type: without one, a PROPFIND opens every file it
// lists and reads its first bytes to sniff one.
func (l *storageCacheFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	p := cleanObjectPath(name)
	if _, meta := l.lookupFresh(p); meta != nil {
		return l.fileInfo(p, meta), nil
	}
	statSent := time.Now()
	info, err := l.upstream.Stat(ctx, name)
	if err != nil || info == nil || info.IsDir() {
		return info, err
	}
	if etag, ok := sourceETag(info); ok {
		if ih, meta, err := l.cache.store.Lookup(l.key(p)); err == nil && meta != nil && meta.ETag == etag && meta.ContentLength == info.Size() {
			if err := l.cache.store.Revalidated(ih, upstreamCacheControl(info), statSent); err != nil {
				log.Debugf("Storage cache: failed to renew %s: %v", p, err)
			}
		}
	}
	return contentTypedInfo{info}, nil
}

func (l *storageCacheFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	// Writes pass through.  The copy is dropped when the write ends (a blob
	// upload commits on Close), successfully or not, since a failed upload
	// may still have changed the object; the old copy serves until then.
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		wf, err := l.upstream.OpenFile(ctx, name, flag, perm)
		if err != nil {
			return nil, err
		}
		return &writeThroughFile{File: wf, onClose: func() { l.invalidate(name) }}, nil
	}

	p := cleanObjectPath(name)
	key := l.key(p)

	// A fresh copy is served with no backend request at all: the common
	// repeat read, which costs neither egress nor a metadata round trip.
	if ih, meta := l.lookupFresh(p); meta != nil {
		if f, err := l.open(ctx, ih, meta, p); err == nil {
			return f, nil
		} else {
			log.Debugf("Storage cache: cannot read the copy of %s: %v", p, err)
		}
	}

	// Stale or missing: one metadata request says which version is current.
	statSent := time.Now()
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
	cacheControl := upstreamCacheControl(info)
	if !cache_control.Parse(cacheControl).ShouldStore() {
		// no-store / private: keep no copy.
		if err := l.cache.store.Forget(key); err != nil {
			log.Debugf("Storage cache: failed to drop %s: %v", p, err)
		}
		return l.upstream.OpenFile(ctx, name, flag, perm)
	}
	etag, ok := sourceETag(info)
	if !ok {
		return l.passthrough(ctx, name, flag, perm, "no strong entity tag", nil)
	}

	ih, meta, err := l.cache.store.Lookup(key)
	if err != nil {
		return l.passthrough(ctx, name, flag, perm, "lookup failed", err)
	}
	if meta != nil && meta.ETag == etag && meta.ContentLength == info.Size() {
		// Revalidated: the backend still has the cached version.
		if err := l.cache.store.Revalidated(ih, cacheControl, statSent); err != nil {
			log.Debugf("Storage cache: failed to renew %s: %v", p, err)
		}
	} else {
		previous := ih
		ih, meta, err = l.cache.store.Init(key, l.namespace, local_cache.SourceObject{
			Size:         info.Size(),
			ETag:         etag,
			LastModified: info.ModTime(),
			CacheControl: cacheControl,
		}, statSent)
		if err != nil {
			return l.passthrough(ctx, name, flag, perm, "cannot make room", err)
		}
		applied, err := l.cache.publish(l.scope, p, key, etag, statSent)
		if err != nil {
			return l.passthrough(ctx, name, flag, perm, "cannot record the version", err)
		}
		if !applied {
			// A write changed the object since the stat, or a later stat
			// was published first; either way this one may be stale.
			return l.passthrough(ctx, name, flag, perm, "the object changed while it was looked up", nil)
		}
		if previous != "" && previous != ih {
			l.cache.store.Discard(previous)
		}
	}

	if complete, _ := l.cache.store.Complete(ih); !complete && len(l.cache.fetchSem) == cap(l.cache.fetchSem) {
		return l.passthrough(ctx, name, flag, perm, "fetch pool saturated", nil)
	}
	f, err := l.open(ctx, ih, meta, p)
	if err != nil {
		return l.passthrough(ctx, name, flag, perm, "cannot read the copy", err)
	}
	return f, nil
}

// open returns a reader of the copy, fetching what it lacks.
func (l *storageCacheFS) open(ctx context.Context, ih local_cache.InstanceHash, meta *local_cache.CacheMetadata, p string) (webdav.File, error) {
	info := l.fileInfo(p, meta)
	if meta.ContentLength == 0 {
		return &cachedReadFile{ReadSeekCloser: nopReadSeekCloser{strings.NewReader("")}, info: info}, nil
	}
	rr, err := l.cache.store.NewReader(ih, &storageCacheSource{cache: l.cache, ranger: l.ranger, name: p}, l.key(p))
	if err != nil {
		return nil, err
	}
	// Reads take the request's context, so a client that goes away stops
	// waiting; any background fill goes on for a while without it.
	rr.SetReadContext(ctx)
	if hint, ok := ctx.Value(readHintKey{}).(readHint); ok {
		switch {
		case hint.method == http.MethodHead:
			// A HEAD reads no body.
			rr.LimitFill(nil)
		case hint.rangeHeader != "" && !hint.conditionalRange:
			// Fill only the ranges asked for, so a few bytes of a large
			// object do not fetch the rest of it.  (A malformed range
			// starts no fill.)  When If-Range fails the whole object is
			// sent, so with If-Range the whole object may be filled.
			ranges, err := local_cache.ParseRangeHeader(hint.rangeHeader, meta.ContentLength)
			if err != nil {
				ranges = nil
			}
			rr.LimitFill(ranges)
		}
	}
	return &cachedReadFile{ReadSeekCloser: rr, info: info}, nil
}

// sourceETag returns the backend's own strong entity tag for an object, if
// it has one.  A weak tag ("W/") marks payloads the backend considers
// equivalent, not identical, and cannot pin a ranged read to one version.
func sourceETag(info os.FileInfo) (string, bool) {
	var etag string
	if et, ok := info.(webdav.ETager); ok {
		etag, _ = et.ETag(context.Background())
	} else if et, ok := info.(interface{ ETag() string }); ok {
		// gowebdav's FileInfo (the WebDAV-mode HTTPS and Globus backends).
		etag = et.ETag()
	} else {
		switch sys := info.Sys().(type) {
		case *BlobFileSysInfo:
			etag = sys.ETag
		case *HTTPSFileSysInfo:
			etag = sys.ETag
		}
	}
	if etag == "" || strings.HasPrefix(etag, "W/") || strings.HasPrefix(etag, "w/") {
		return "", false
	}
	return etag, true
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

// storageCacheSource is where the store fetches an object's blocks: ranged
// reads of its backend, bounded by the cache's fetch pool.
type storageCacheSource struct {
	cache  *storageCache
	ranger versionRangeReader
	name   string
}

func (s *storageCacheSource) ReadRange(ctx context.Context, w io.Writer, start, end int64, etag string) error {
	select {
	case s.cache.fetchSem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.cache.fetchSem }()
	return s.ranger.ReadVersionRange(ctx, s.name, w, start, end, etag)
}

// ---------------------------------------------------------------------------
// Request hints
// ---------------------------------------------------------------------------

// readHint is what the layer needs to know of a read request that the
// webdav.FileSystem interface does not carry: whether it reads a body, and
// which bytes of it.  It travels in the request context, as the
// content-length hint for uploads does.
type readHint struct {
	method           string
	rangeHeader      string
	conditionalRange bool
}

type readHintKey struct{}

// withReadHint attaches a GET or HEAD request's read hint to its context.
func withReadHint(req *http.Request) *http.Request {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return req
	}
	return req.WithContext(context.WithValue(req.Context(), readHintKey{}, readHint{
		method:           req.Method,
		rangeHeader:      req.Header.Get("Range"),
		conditionalRange: req.Header.Get("If-Range") != "",
	}))
}

// ---------------------------------------------------------------------------
// Files and file information
// ---------------------------------------------------------------------------

// writeThroughFile runs onClose once the write it wraps has ended.
type writeThroughFile struct {
	webdav.File
	onClose func()
	once    sync.Once
}

func (w *writeThroughFile) Close() error {
	err := w.File.Close()
	w.once.Do(w.onClose)
	return err
}

// cachedReadFile serves a copy, reporting the backend's metadata for it.
type cachedReadFile struct {
	io.ReadSeekCloser
	info os.FileInfo
}

func (f *cachedReadFile) Stat() (os.FileInfo, error) { return f.info, nil }

func (f *cachedReadFile) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write not supported on cached read file")
}

func (f *cachedReadFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on file")
}

type nopReadSeekCloser struct{ io.ReadSeeker }

func (nopReadSeekCloser) Close() error { return nil }

// contentTypedInfo adds a Content-Type to an upstream FileInfo.  The WebDAV
// handler asks a FileInfo for its content type first and only falls back to
// opening the file and sniffing its first bytes when the FileInfo can't say --
// which, over this layer, would mean a backend round trip for every file in
// a listing.
type contentTypedInfo struct {
	os.FileInfo
}

func (fi contentTypedInfo) ContentType(_ context.Context) (string, error) {
	return contentTypeByName(fi.Name()), nil
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

func contentTypeByName(name string) string {
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// cachedFileInfo is the backend's metadata for a copy.
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

// ETag exposes the backend's entity tag when the backend shows it to
// clients; otherwise the WebDAV handler derives its default from the
// preserved size and modification time, as it does for the backend.
func (fi *cachedFileInfo) ETag(_ context.Context) (string, error) {
	if fi.etag != "" {
		return fi.etag, nil
	}
	return "", webdav.ErrNotImplemented
}

// ContentType keeps PROPFIND and GET from opening the object to sniff one.
func (fi *cachedFileInfo) ContentType(_ context.Context) (string, error) {
	return contentTypeByName(fi.name), nil
}

// ---------------------------------------------------------------------------
// cachedBackend -- OriginBackend wrapper installing the caching filesystem
// ---------------------------------------------------------------------------

type cachedBackend struct {
	inner server_utils.OriginBackend
	layer *storageCacheFS
}

func newCachedBackend(inner server_utils.OriginBackend, layer *storageCacheFS) *cachedBackend {
	return &cachedBackend{inner: inner, layer: layer}
}

func (b *cachedBackend) CheckAvailability() error      { return b.inner.CheckAvailability() }
func (b *cachedBackend) FileSystem() webdav.FileSystem { return b.layer }

// Uncached returns the backend the cache is layered over, for a caller that
// must see the storage as it is now -- a write's preconditions, say.
func (b *cachedBackend) Uncached() server_utils.OriginBackend { return b.inner }

func (b *cachedBackend) Checksummer() server_utils.OriginChecksummer {
	inner := b.inner.Checksummer()
	if inner == nil {
		return nil
	}
	return &cachedChecksummer{inner: inner, layer: b.layer}
}

// cachedChecksummer suppresses the Digest header for objects served from a
// fresh copy.
//
// The backend computes digests of the object as it is now, but the copy was
// taken when it was fetched.  Had the object changed since, the two would
// disagree, and a client checking the digest against the body it received
// would see corruption rather than staleness.  Reporting no digest is honest:
// the origin cannot vouch for one without reading the object it is not
// reading.
type cachedChecksummer struct {
	inner server_utils.OriginChecksummer
	layer *storageCacheFS
}

func (c *cachedChecksummer) GetDigests(relativePath string, wantDigest string) ([]string, error) {
	if _, meta := c.layer.lookupFresh(cleanObjectPath(relativePath)); meta != nil {
		return nil, nil
	}
	return c.inner.GetDigests(relativePath, wantDigest)
}

// uncachedBackend returns the storage a backend serves, beneath any cache.
func uncachedBackend(backend server_utils.OriginBackend) server_utils.OriginBackend {
	if b, ok := backend.(interface {
		Uncached() server_utils.OriginBackend
	}); ok {
		return b.Uncached()
	}
	return backend
}
