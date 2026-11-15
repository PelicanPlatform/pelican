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

package origin_serve

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/server_utils"
)

// ---------------------------------------------------------------------------
// fake upstream -- an instrumented webdav.FileSystem standing in for a remote
// backend, with the ranged, version-pinned reads the cache fills from.
// ---------------------------------------------------------------------------

type fakeObject struct {
	content      []byte
	etag         string
	cacheControl string
	modTime      time.Time
}

type fakeUpstream struct {
	mu         sync.Mutex
	objects    map[string]*fakeObject
	statCount  map[string]int
	openCount  map[string]int
	rangeReads map[string]int
	rangeBytes map[string]int64

	// statHook, when set, runs inside Stat before it answers, with the
	// answer already decided: a test uses it to change the object while a
	// stat that saw the old one is in flight.
	statHook func(name string)

	// failListing simulates a backend with no directory enumeration (e.g. a
	// plain-HTTP upstream): Readdir on directories returns an error.
	failListing bool
	// failWriteClose simulates an upload that fails at commit time.
	failWriteClose bool
	// infoStyle selects which real backend's FileInfo shape Stat and
	// Readdir return.
	infoStyle infoStyle
}

func newFakeUpstream() *fakeUpstream {
	return &fakeUpstream{
		objects:    make(map[string]*fakeObject),
		statCount:  make(map[string]int),
		openCount:  make(map[string]int),
		rangeReads: make(map[string]int),
		rangeBytes: make(map[string]int64),
	}
}

func (u *fakeUpstream) put(name, content, etag string) {
	u.putCC(name, content, etag, "")
}

// putCC stores an object that advertises the given Cache-Control value.
func (u *fakeUpstream) putCC(name, content, etag, cacheControl string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.objects[name] = &fakeObject{content: []byte(content), etag: etag, cacheControl: cacheControl, modTime: time.Now().Truncate(time.Second)}
}

func (u *fakeUpstream) opens(name string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.openCount[name]
}

func (u *fakeUpstream) stats(name string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.statCount[name]
}

func (u *fakeUpstream) ranged(name string) (reads int, bytes int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.rangeReads[name], u.rangeBytes[name]
}

// fakeUpstreamInfo models a blob (s3v2) backend's FileInfo: the ETag is
// reachable only through Sys(), never exposed to clients as a webdav.ETager.
type fakeUpstreamInfo struct {
	name         string
	size         int64
	modTime      time.Time
	etag         string
	cacheControl string
	isDir        bool
}

// etagerUpstreamInfo models the HTTPS backend's FileInfo in plain-HTTP mode,
// which implements webdav.ETager and so shows its ETag to clients.
type etagerUpstreamInfo struct {
	*fakeUpstreamInfo
}

func (fi etagerUpstreamInfo) ETag(_ context.Context) (string, error) {
	if fi.etag != "" {
		return fi.etag, nil
	}
	return "", webdav.ErrNotImplemented
}

// gowebdavUpstreamInfo models gowebdav's FileInfo, used by the HTTPS and
// Globus backends in WebDAV mode: it carries an ETag through a context-free
// method of its own and returns nil from Sys().
type gowebdavUpstreamInfo struct {
	*fakeUpstreamInfo
}

func (fi gowebdavUpstreamInfo) ETag() string     { return fi.etag }
func (fi gowebdavUpstreamInfo) Sys() interface{} { return nil }

type infoStyle int

const (
	infoStyleBlob     infoStyle = iota // s3v2: ETag via Sys() only
	infoStyleETager                    // httpsv2: ETag via webdav.ETager
	infoStyleGoWebdav                  // WebDAV mode: ETag via ETag() string
)

func (u *fakeUpstream) wrapInfo(fi *fakeUpstreamInfo) os.FileInfo {
	switch u.infoStyle {
	case infoStyleETager:
		return etagerUpstreamInfo{fi}
	case infoStyleGoWebdav:
		return gowebdavUpstreamInfo{fi}
	default:
		return fi
	}
}

func (fi *fakeUpstreamInfo) Name() string { return fi.name }
func (fi *fakeUpstreamInfo) Size() int64  { return fi.size }
func (fi *fakeUpstreamInfo) Mode() os.FileMode {
	if fi.isDir {
		return os.ModeDir | 0755
	}
	return 0644
}
func (fi *fakeUpstreamInfo) ModTime() time.Time { return fi.modTime }
func (fi *fakeUpstreamInfo) IsDir() bool        { return fi.isDir }
func (fi *fakeUpstreamInfo) Sys() interface{} {
	if fi.etag != "" || fi.cacheControl != "" {
		return &BlobFileSysInfo{ETag: fi.etag, CacheControl: fi.cacheControl}
	}
	return nil
}

func (u *fakeUpstream) infoOf(name string, obj *fakeObject) os.FileInfo {
	return u.wrapInfo(&fakeUpstreamInfo{name: path.Base(name), size: int64(len(obj.content)), modTime: obj.modTime, etag: obj.etag, cacheControl: obj.cacheControl})
}

type fakeUpstreamFile struct {
	*bytes.Reader
	info os.FileInfo
}

func (f *fakeUpstreamFile) Close() error                { return nil }
func (f *fakeUpstreamFile) Write(_ []byte) (int, error) { return 0, fmt.Errorf("read-only fake") }
func (f *fakeUpstreamFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("not a directory")
}
func (f *fakeUpstreamFile) Stat() (os.FileInfo, error) { return f.info, nil }

// fakeWriteFile buffers writes and commits them to the upstream on Close.
type fakeWriteFile struct {
	upstream *fakeUpstream
	name     string
	buf      bytes.Buffer
}

func (f *fakeWriteFile) Write(p []byte) (int, error) { return f.buf.Write(p) }
func (f *fakeWriteFile) Close() error {
	f.upstream.mu.Lock()
	failClose := f.upstream.failWriteClose
	f.upstream.mu.Unlock()
	if failClose {
		return fmt.Errorf("upload failed at commit")
	}
	f.upstream.put(f.name, f.buf.String(), fmt.Sprintf("%q", f.buf.String()))
	return nil
}
func (f *fakeWriteFile) Read(_ []byte) (int, error)           { return 0, fmt.Errorf("write-only") }
func (f *fakeWriteFile) Seek(_ int64, _ int) (int64, error)   { return 0, fmt.Errorf("write-only") }
func (f *fakeWriteFile) Readdir(_ int) ([]os.FileInfo, error) { return nil, fmt.Errorf("not a dir") }
func (f *fakeWriteFile) Stat() (os.FileInfo, error)           { return nil, fmt.Errorf("write-only") }

func (u *fakeUpstream) Mkdir(_ context.Context, _ string, _ os.FileMode) error { return nil }

// RemoveAll deletes the named object and, directory-style, everything
// beneath it.
func (u *fakeUpstream) RemoveAll(_ context.Context, name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.objects, name)
	prefix := name + "/"
	for k := range u.objects {
		if strings.HasPrefix(k, prefix) {
			delete(u.objects, k)
		}
	}
	return nil
}

// Rename moves the named object and any directory-style descendants.
func (u *fakeUpstream) Rename(_ context.Context, oldName, newName string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if obj, ok := u.objects[oldName]; ok {
		u.objects[newName] = obj
		delete(u.objects, oldName)
	}
	prefix := oldName + "/"
	for k, obj := range u.objects {
		if strings.HasPrefix(k, prefix) {
			u.objects[newName+"/"+strings.TrimPrefix(k, prefix)] = obj
			delete(u.objects, k)
		}
	}
	return nil
}

func (u *fakeUpstream) Stat(_ context.Context, name string) (os.FileInfo, error) {
	u.mu.Lock()
	u.statCount[name]++
	var info os.FileInfo
	if obj, ok := u.objects[name]; ok {
		info = u.infoOf(name, obj)
	} else if u.hasChildrenLocked(name) {
		info = &fakeUpstreamInfo{name: path.Base(name), isDir: true, modTime: time.Now()}
	}
	hook := u.statHook
	u.mu.Unlock()
	if hook != nil {
		hook(name)
	}
	if info == nil {
		return nil, os.ErrNotExist
	}
	return info, nil
}

// hasChildrenLocked reports whether any object lives under name+"/".
func (u *fakeUpstream) hasChildrenLocked(name string) bool {
	prefix := name + "/"
	for k := range u.objects {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func (u *fakeUpstream) OpenFile(_ context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		return &fakeWriteFile{upstream: u, name: name}, nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if obj, ok := u.objects[name]; ok {
		u.openCount[name]++
		return &fakeUpstreamFile{Reader: bytes.NewReader(obj.content), info: u.infoOf(name, obj)}, nil
	}
	if u.hasChildrenLocked(name) {
		prefix := name + "/"
		seenDirs := make(map[string]bool)
		var entries []os.FileInfo
		for k, obj := range u.objects {
			rest, ok := strings.CutPrefix(k, prefix)
			if !ok {
				continue
			}
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				if d := rest[:i]; !seenDirs[d] {
					seenDirs[d] = true
					entries = append(entries, &fakeUpstreamInfo{name: d, isDir: true})
				}
			} else {
				entries = append(entries, u.infoOf(rest, obj))
			}
		}
		return &fakeDirFile{name: name, entries: entries, failRead: u.failListing}, nil
	}
	return nil, os.ErrNotExist
}

// ReadVersionRange is the backend's ranged, version-pinned read.
func (u *fakeUpstream) ReadVersionRange(_ context.Context, name string, w io.Writer, start, end int64, etag string) error {
	u.mu.Lock()
	obj, ok := u.objects[name]
	u.rangeReads[name]++
	if !ok || obj.etag != etag {
		u.mu.Unlock()
		return local_cache.ErrSourceVersionChanged
	}
	chunk := obj.content[start : end+1]
	u.rangeBytes[name] += int64(len(chunk))
	u.mu.Unlock()
	_, err := w.Write(chunk)
	return err
}

// fakeDirFile serves paginated directory listings (or fails, to exercise
// the no-enumeration fallback).
type fakeDirFile struct {
	name     string
	entries  []os.FileInfo
	offset   int
	failRead bool
}

func (f *fakeDirFile) Readdir(count int) ([]os.FileInfo, error) {
	if f.failRead {
		return nil, fmt.Errorf("listing not supported")
	}
	if f.offset >= len(f.entries) {
		return nil, io.EOF
	}
	if count <= 0 {
		r := f.entries[f.offset:]
		f.offset = len(f.entries)
		return r, nil
	}
	end := min(f.offset+count, len(f.entries))
	r := f.entries[f.offset:end]
	f.offset = end
	return r, nil
}

func (f *fakeDirFile) Close() error                       { return nil }
func (f *fakeDirFile) Read(_ []byte) (int, error)         { return 0, fmt.Errorf("is a directory") }
func (f *fakeDirFile) Write(_ []byte) (int, error)        { return 0, fmt.Errorf("is a directory") }
func (f *fakeDirFile) Seek(_ int64, _ int) (int64, error) { return 0, fmt.Errorf("is a directory") }
func (f *fakeDirFile) Stat() (os.FileInfo, error) {
	return &fakeUpstreamInfo{name: path.Base(f.name), isDir: true}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestStorageCache opens a cache in a fresh directory, closed when the
// test ends.
func newTestStorageCache(t *testing.T, maxAge time.Duration) *storageCache {
	t.Helper()
	local_cache.InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(t.Context())
	egrp, _ := errgroup.WithContext(ctx)
	cache, err := newStorageCache(ctx, egrp, storageCacheConfig{
		Dir:                  t.TempDir(),
		MaxSize:              1 << 30,
		DefaultMaxAge:        maxAge,
		JitterPercent:        0,
		MaxConcurrentFetches: 8,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})
	return cache
}

// newTestCacheLayer layers a cache over upstream; maxAge 0 revalidates
// every read.
func newTestCacheLayer(t *testing.T, upstream webdav.FileSystem, maxAge time.Duration) (*storageCache, *storageCacheFS) {
	t.Helper()
	cache := newTestStorageCache(t, maxAge)
	layer, err := cache.newLayer("/test", "backend", upstream)
	require.NoError(t, err)
	return cache, layer
}

func readAllViaLayer(t *testing.T, layer webdav.FileSystem, name string) string {
	t.Helper()
	f, err := layer.OpenFile(t.Context(), name, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(data)
}

func writeViaLayer(t *testing.T, layer webdav.FileSystem, name, content string) error {
	t.Helper()
	f, err := layer.OpenFile(t.Context(), name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte(content))
	require.NoError(t, err)
	return f.Close()
}

// isCached reports whether the layer holds a published copy of name.
func isCached(t *testing.T, layer *storageCacheFS, name string) bool {
	t.Helper()
	_, meta, err := layer.cache.store.Lookup(layer.key(cleanObjectPath(name)))
	require.NoError(t, err)
	return meta != nil
}

// serveViaHandler serves a request through the WebDAV handler over layer,
// the way the origin does.
func serveViaHandler(t *testing.T, layer webdav.FileSystem, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	handler := &webdav.Handler{FileSystem: layer, LockSystem: webdav.NewMemLS()}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withReadHint(req.WithContext(t.Context())))
	return rec
}

func multiBlockContent(size int) string {
	var sb strings.Builder
	for i := 0; sb.Len() < size; i++ {
		fmt.Fprintf(&sb, "%08d|", i)
	}
	return sb.String()[:size]
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestStorageCacheMissThenHit(t *testing.T) {
	upstream := newFakeUpstream()
	content := multiBlockContent(100_000)
	upstream.put("/obj", content, `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	require.Equal(t, content, readAllViaLayer(t, layer, "/obj"))
	reads, n := upstream.ranged("/obj")
	assert.Positive(t, reads)
	assert.Equal(t, int64(len(content)), n, "a miss fetches the object once")
	statsAfterMiss := upstream.stats("/obj")

	require.Equal(t, content, readAllViaLayer(t, layer, "/obj"))
	reads2, n2 := upstream.ranged("/obj")
	assert.Equal(t, reads, reads2, "a fresh hit reads nothing from the backend")
	assert.Equal(t, n, n2)
	assert.Equal(t, statsAfterMiss, upstream.stats("/obj"), "a fresh hit does not even stat the backend")
	assert.Zero(t, upstream.opens("/obj"), "nothing is served straight from the backend")
}

func TestStorageCacheZeroLengthObject(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/empty", "", `"e-0"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	require.Equal(t, "", readAllViaLayer(t, layer, "/empty"))
	require.Equal(t, "", readAllViaLayer(t, layer, "/empty"))
	assert.True(t, isCached(t, layer, "/empty"))
	assert.Zero(t, upstream.opens("/empty"))
}

func TestStorageCacheRevalidation(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "version one", `"e-1"`)
	// Every read revalidates.
	_, layer := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "version one", readAllViaLayer(t, layer, "/obj"))
	_, fetched := upstream.ranged("/obj")
	require.Equal(t, "version one", readAllViaLayer(t, layer, "/obj"))
	_, fetchedAgain := upstream.ranged("/obj")
	assert.Equal(t, fetched, fetchedAgain, "an unchanged object is revalidated, not fetched again")
	assert.Equal(t, 2, upstream.stats("/obj"))

	upstream.put("/obj", "version two", `"e-2"`)
	require.Equal(t, "version two", readAllViaLayer(t, layer, "/obj"))
}

func TestStorageCacheFreshCopyIgnoresOutOfBandChanges(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "version one", `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	require.Equal(t, "version one", readAllViaLayer(t, layer, "/obj"))
	upstream.put("/obj", "version two", `"e-2"`)
	assert.Equal(t, "version one", readAllViaLayer(t, layer, "/obj"),
		"a change made directly in the backend is seen once the copy goes stale")
}

func TestStorageCacheWriteInvalidates(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "version one", `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	require.Equal(t, "version one", readAllViaLayer(t, layer, "/obj"))
	require.NoError(t, writeViaLayer(t, layer, "/obj", "version two"))
	assert.False(t, isCached(t, layer, "/obj"))
	assert.Equal(t, "version two", readAllViaLayer(t, layer, "/obj"))
}

func TestStorageCacheFailedWriteStillInvalidates(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "version one", `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	require.Equal(t, "version one", readAllViaLayer(t, layer, "/obj"))
	upstream.failWriteClose = true
	require.Error(t, writeViaLayer(t, layer, "/obj", "version two"))
	assert.False(t, isCached(t, layer, "/obj"), "a failed upload may still have changed the object")
}

// A read whose stat saw the object before a write through the origin must
// not publish that version after the write has dropped the copy: that would
// serve the old bytes, fresh, until they went stale.
func TestStorageCacheStatRacingAWriteDoesNotRepublish(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "version one", `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	var once sync.Once
	upstream.statHook = func(name string) {
		if name != "/obj" {
			return
		}
		once.Do(func() {
			// The stat has seen version one; now a write lands.
			require.NoError(t, writeViaLayer(t, layer, "/obj", "version two"))
		})
	}

	// The racing read is served -- from the backend -- but caches nothing
	// stale.
	got := readAllViaLayer(t, layer, "/obj")
	assert.Contains(t, []string{"version one", "version two"}, got)
	upstream.statHook = nil
	assert.Equal(t, "version two", readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, "version two", readAllViaLayer(t, layer, "/obj"))
}

func TestStorageCachePublishRefusesAStatOlderThanAWrite(t *testing.T) {
	cache, layer := newTestCacheLayer(t, newFakeUpstream(), time.Hour)
	statSent := time.Now()
	layer.invalidate("/dir/obj")
	applied, err := cache.publish(layer.scope, "/dir/obj", layer.key("/dir/obj"), `"e-1"`, statSent)
	require.NoError(t, err)
	assert.False(t, applied)

	// A write to a directory covers what is below it, and nothing beside it.
	statSent = time.Now()
	layer.invalidateSubtree("/dir", nil, false)
	applied, err = cache.publish(layer.scope, "/dir/obj", layer.key("/dir/obj"), `"e-1"`, statSent)
	require.NoError(t, err)
	assert.False(t, applied)
	applied, err = cache.publish(layer.scope, "/directory", layer.key("/directory"), `"e-1"`, statSent)
	require.NoError(t, err)
	assert.True(t, applied)

	// A stat sent after the write publishes.
	applied, err = cache.publish(layer.scope, "/dir/obj", layer.key("/dir/obj"), `"e-1"`, time.Now())
	require.NoError(t, err)
	assert.True(t, applied)

	// A stat older than the window writes are remembered for never does.
	applied, err = cache.publish(layer.scope, "/other", layer.key("/other"), `"e-1"`, time.Now().Add(-storageCacheMutationWindow))
	require.NoError(t, err)
	assert.False(t, applied)
}

func TestStorageCacheRemoveAndRenameInvalidate(t *testing.T) {
	for _, failListing := range []bool{false, true} {
		t.Run(fmt.Sprintf("failListing=%v", failListing), func(t *testing.T) {
			upstream := newFakeUpstream()
			upstream.put("/dir/a", "a", `"a"`)
			upstream.put("/dir/sub/b", "b", `"b"`)
			upstream.put("/dirx", "x", `"x"`)
			upstream.put("/src/c", "c", `"c"`)
			upstream.put("/dst/c", "old c", `"old-c"`)
			_, layer := newTestCacheLayer(t, upstream, time.Hour)
			for _, name := range []string{"/dir/a", "/dir/sub/b", "/dirx", "/src/c", "/dst/c"} {
				readAllViaLayer(t, layer, name)
				require.True(t, isCached(t, layer, name), name)
			}
			upstream.failListing = failListing

			require.NoError(t, layer.RemoveAll(t.Context(), "/dir"))
			assert.False(t, isCached(t, layer, "/dir/a"))
			assert.False(t, isCached(t, layer, "/dir/sub/b"))
			assert.True(t, isCached(t, layer, "/dirx"), "a sibling sharing the prefix is untouched")

			require.NoError(t, layer.Rename(t.Context(), "/src", "/dst"))
			assert.False(t, isCached(t, layer, "/src/c"))
			assert.False(t, isCached(t, layer, "/dst/c"), "the destination's old object is gone")
			assert.Equal(t, "c", readAllViaLayer(t, layer, "/dst/c"))
		})
	}
}

func TestStorageCacheNoStoreBypasses(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "cached", `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "cached", readAllViaLayer(t, layer, "/obj"))
	require.True(t, isCached(t, layer, "/obj"))

	upstream.putCC("/obj", "private data", `"e-2"`, "no-store")
	require.Equal(t, "private data", readAllViaLayer(t, layer, "/obj"))
	assert.False(t, isCached(t, layer, "/obj"), "a copy is dropped once the object is no-store")
	require.Equal(t, "private data", readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, 2, upstream.opens("/obj"), "no-store objects are always read from the backend")
}

func TestStorageCacheNeedsAStrongETag(t *testing.T) {
	for name, etag := range map[string]string{"none": "", "weak": `W/"e-1"`} {
		t.Run(name, func(t *testing.T) {
			upstream := newFakeUpstream()
			upstream.put("/obj", "content", etag)
			_, layer := newTestCacheLayer(t, upstream, time.Hour)

			require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
			require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
			assert.False(t, isCached(t, layer, "/obj"))
			assert.Equal(t, 2, upstream.opens("/obj"))
		})
	}
}

func TestStorageCacheReadsEveryETagShape(t *testing.T) {
	for name, style := range map[string]infoStyle{"blob": infoStyleBlob, "etager": infoStyleETager, "gowebdav": infoStyleGoWebdav} {
		t.Run(name, func(t *testing.T) {
			upstream := newFakeUpstream()
			upstream.infoStyle = style
			upstream.put("/obj", "content", `"e-1"`)
			_, layer := newTestCacheLayer(t, upstream, time.Hour)

			require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
			assert.True(t, isCached(t, layer, "/obj"))
		})
	}
}

// A range request fetches the blocks it covers, not the object, and a HEAD
// fetches at most the first block.
func TestStorageCacheRangeAndHeadFetchOnlyWhatTheyRead(t *testing.T) {
	upstream := newFakeUpstream()
	content := multiBlockContent(2 << 20)
	// No extension: the content type cannot come from the name.
	upstream.put("/data", content, `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	head := serveViaHandler(t, layer, httptest.NewRequest(http.MethodHead, "/data", nil))
	require.Equal(t, http.StatusOK, head.Code)
	_, n := upstream.ranged("/data")
	// http.ServeContent sniffs the first 512 bytes for a content type,
	// even for a HEAD, which costs the first block.
	assert.LessOrEqual(t, n, int64(local_cache.BlockDataSize), "a HEAD reads at most the first block")
	before := n

	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	req.Header.Set("Range", "bytes=1000000-1000099")
	rec := serveViaHandler(t, layer, req)
	require.Equal(t, http.StatusPartialContent, rec.Code)
	assert.Equal(t, content[1000000:1000100], rec.Body.String())
	_, n = upstream.ranged("/data")
	assert.LessOrEqual(t, n-before, int64(2*local_cache.BlockDataSize), "a small range fetches its blocks, not the object")

	full := serveViaHandler(t, layer, httptest.NewRequest(http.MethodGet, "/data", nil))
	require.Equal(t, http.StatusOK, full.Code)
	assert.Equal(t, content, full.Body.String())
	_, n = upstream.ranged("/data")
	assert.Less(t, n, int64(len(content))+int64(2*local_cache.BlockDataSize),
		"the blocks already fetched are not fetched again")
}

// The cache's file information must not differ from the backend's, so that
// a client sees the same ETag and Last-Modified either way.
func TestStorageCacheHitLooksLikeTheBackend(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "content", `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	uncached := serveViaHandler(t, upstream, httptest.NewRequest(http.MethodGet, "/obj", nil))
	readAllViaLayer(t, layer, "/obj")
	cached := serveViaHandler(t, layer, httptest.NewRequest(http.MethodGet, "/obj", nil))
	require.Equal(t, http.StatusOK, cached.Code)
	for _, h := range []string{"ETag", "Last-Modified", "Content-Length"} {
		assert.Equal(t, uncached.Header().Get(h), cached.Header().Get(h), h)
	}

	// A backend that shows its ETag to clients is shown through the cache.
	layer.exposeETag = true
	info, err := layer.Stat(t.Context(), "/obj")
	require.NoError(t, err)
	etag, err := info.(webdav.ETager).ETag(t.Context())
	require.NoError(t, err)
	assert.Equal(t, `"e-1"`, etag)
}

func TestStorageCacheFetchPoolSaturationFallsThrough(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "content", `"e-1"`)
	cache, layer := newTestCacheLayer(t, upstream, time.Hour)

	for range cap(cache.fetchSem) {
		cache.fetchSem <- struct{}{}
	}
	require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, 1, upstream.opens("/obj"), "a full fetch pool sends the read to the backend")
	for range cap(cache.fetchSem) {
		<-cache.fetchSem
	}
	require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, 1, upstream.opens("/obj"))
}

func TestStorageCacheScopesAreSeparate(t *testing.T) {
	a, b := newFakeUpstream(), newFakeUpstream()
	a.put("/obj", "from a", `"e-1"`)
	b.put("/obj", "from b", `"e-1"`)
	cache := newTestStorageCache(t, time.Hour)
	layerA, err := cache.newLayer("/test", "backend-a", a)
	require.NoError(t, err)
	layerB, err := cache.newLayer("/test", "backend-b", b)
	require.NoError(t, err)

	require.Equal(t, "from a", readAllViaLayer(t, layerA, "/obj"))
	assert.Equal(t, "from b", readAllViaLayer(t, layerB, "/obj"),
		"an export repointed at other storage does not see the old storage's copies")
}

func TestStorageCacheNotFound(t *testing.T) {
	_, layer := newTestCacheLayer(t, newFakeUpstream(), time.Hour)
	_, err := layer.OpenFile(t.Context(), "/missing", os.O_RDONLY, 0)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// The WebDAV handler asks a FileInfo for its content type and only falls
// back to opening the file and sniffing its first bytes when the FileInfo
// cannot say.  Through this layer that would mean a backend round trip for
// every file in a listing, so every FileInfo the layer hands out must answer.
func TestStorageCacheStatCarriesContentType(t *testing.T) {
	// Register the extension rather than trusting the host's MIME database.
	const knownExt, knownType = ".pelican-known", "application/x-pelican-test"
	require.NoError(t, mime.AddExtensionType(knownExt, knownType))
	contentTypeOf := func(t *testing.T, info os.FileInfo) string {
		t.Helper()
		ct, ok := info.(webdav.ContentTyper)
		require.True(t, ok, "FileInfo must implement webdav.ContentTyper")
		got, err := ct.ContentType(t.Context())
		require.NoError(t, err)
		return got
	}

	upstream := newFakeUpstream()
	upstream.put("/dir/file.pelican-known", "hello", `"e-1"`)
	upstream.put("/dir/blob", "hello", `"e-2"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	info, err := layer.Stat(t.Context(), "/dir/file.pelican-known")
	require.NoError(t, err)
	assert.Equal(t, knownType, contentTypeOf(t, info))
	info, err = layer.Stat(t.Context(), "/dir/blob")
	require.NoError(t, err)
	assert.Equal(t, "application/octet-stream", contentTypeOf(t, info))

	readAllViaLayer(t, layer, "/dir/file.pelican-known")
	info, err = layer.Stat(t.Context(), "/dir/file.pelican-known")
	require.NoError(t, err)
	assert.IsType(t, &cachedFileInfo{}, info)
	assert.Equal(t, knownType, contentTypeOf(t, info))

	dir, err := layer.OpenFile(t.Context(), "/dir", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer dir.Close()
	entries, err := dir.Readdir(-1)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, e := range entries {
		contentTypeOf(t, e)
	}
}

// stubChecksummer stands in for a backend's digest support and counts how
// often it is consulted.
type stubChecksummer struct {
	mu    sync.Mutex
	calls int
}

func (s *stubChecksummer) GetDigests(relativePath string, wantDigest string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return []string{"md5=" + relativePath + ";" + wantDigest}, nil
}

func (s *stubChecksummer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// stubBackend is a minimal OriginBackend for wiring tests.
type stubBackend struct {
	fs          webdav.FileSystem
	checksummer server_utils.OriginChecksummer
}

func (b *stubBackend) CheckAvailability() error                    { return nil }
func (b *stubBackend) FileSystem() webdav.FileSystem               { return b.fs }
func (b *stubBackend) Checksummer() server_utils.OriginChecksummer { return b.checksummer }

// A backend's digest describes the object as it is now, not the copy, so
// no digest is reported while a fresh copy is served.
func TestStorageCacheDigestSuppressedOnFreshHit(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "digest me", `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)

	inner := &stubChecksummer{}
	summer := &cachedChecksummer{inner: inner, layer: layer}
	digests, err := summer.GetDigests("/obj", "md5")
	require.NoError(t, err)
	assert.Equal(t, []string{"md5=/obj;md5"}, digests)

	require.Equal(t, "digest me", readAllViaLayer(t, layer, "/obj"))
	digests, err = summer.GetDigests("/obj", "md5")
	require.NoError(t, err)
	assert.Nil(t, digests, "a fresh copy does not carry the backend's digest")
	assert.Equal(t, 1, inner.callCount())

	assert.Nil(t, newCachedBackend(&stubBackend{fs: upstream}, layer).Checksummer(),
		"a backend without checksums does not gain one")
}

// A write's preconditions are judged against the storage, not a copy that
// may be older than the object the write would replace.
func TestStorageCachePreconditionsSeeTheBackend(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.infoStyle = infoStyleETager
	upstream.put("/obj", "version one", `"e-1"`)
	_, layer := newTestCacheLayer(t, upstream, time.Hour)
	layer.exposeETag = true
	backend := newCachedBackend(&stubBackend{fs: upstream}, layer)

	readAllViaLayer(t, layer, "/obj")
	upstream.put("/obj", "version two", `"e-2"`)
	etag, exists, err := currentEntityTag(t.Context(), backend, "/obj")
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, `"e-2"`, etag)
}

// ---------------------------------------------------------------------------
// subtree enumeration guards
// ---------------------------------------------------------------------------

type pathologicalMode int

const (
	// pathSelfRef: every directory reports a subdirectory of the same name.
	pathSelfRef pathologicalMode = iota
	// pathDotsOnly: listings contain only ".", ".." and an empty name.
	pathDotsOnly
	// pathWide: one flat listing far larger than the enumeration cap.
	pathWide
)

// pathologicalUpstream wraps the ordinary fake with a directory that lists
// itself, or lists nothing but self-references, or lists more entries than
// the enumeration cap allows.
type pathologicalUpstream struct {
	*fakeUpstream
	dir  string
	mode pathologicalMode
}

func (u *pathologicalUpstream) isSyntheticDir(name string) bool {
	if name == u.dir {
		return true
	}
	if u.mode != pathSelfRef {
		return false
	}
	rest, ok := strings.CutPrefix(name, u.dir+"/")
	if !ok {
		return false
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg != "loop" {
			return false
		}
	}
	return true
}

func (u *pathologicalUpstream) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if u.isSyntheticDir(name) {
		return &fakeUpstreamInfo{name: path.Base(name), isDir: true, modTime: time.Now()}, nil
	}
	return u.fakeUpstream.Stat(ctx, name)
}

func (u *pathologicalUpstream) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	isWrite := flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0
	if isWrite || !u.isSyntheticDir(name) {
		return u.fakeUpstream.OpenFile(ctx, name, flag, perm)
	}
	if u.mode == pathWide {
		return &wideDirFile{remaining: storageCacheEnumerationCap + 10}, nil
	}
	entries := []os.FileInfo{
		&fakeUpstreamInfo{name: ".", isDir: true},
		&fakeUpstreamInfo{name: "..", isDir: true},
		&fakeUpstreamInfo{name: "", isDir: true},
	}
	if u.mode == pathSelfRef {
		entries = append(entries, &fakeUpstreamInfo{name: "loop", isDir: true})
	}
	return &fakeDirFile{name: name, entries: entries}, nil
}

// wideDirFile fabricates an arbitrarily long flat listing without
// materializing it.
type wideDirFile struct {
	remaining int
}

func (f *wideDirFile) Readdir(count int) ([]os.FileInfo, error) {
	if f.remaining <= 0 {
		return nil, io.EOF
	}
	if count <= 0 || count > f.remaining {
		count = f.remaining
	}
	entries := make([]os.FileInfo, 0, count)
	for i := 0; i < count; i++ {
		entries = append(entries, &fakeUpstreamInfo{name: fmt.Sprintf("f%d", f.remaining-i)})
	}
	f.remaining -= count
	return entries, nil
}

func (f *wideDirFile) Close() error                       { return nil }
func (f *wideDirFile) Read(_ []byte) (int, error)         { return 0, fmt.Errorf("is a directory") }
func (f *wideDirFile) Write(_ []byte) (int, error)        { return 0, fmt.Errorf("is a directory") }
func (f *wideDirFile) Seek(_ int64, _ int) (int64, error) { return 0, fmt.Errorf("is a directory") }
func (f *wideDirFile) Stat() (os.FileInfo, error) {
	return &fakeUpstreamInfo{name: "wide", isDir: true}, nil
}

// A subtree walk is driven by a listing the backend controls, so it is
// bounded in depth and breadth; when it gives up, invalidation falls back to
// scanning the cache.
func TestStorageCacheEnumerationGuards(t *testing.T) {
	for name, mode := range map[string]pathologicalMode{"self-referential": pathSelfRef, "too wide": pathWide} {
		t.Run(name, func(t *testing.T) {
			base := newFakeUpstream()
			base.put("/loop/obj", "cached content", `"e-1"`)
			base.put("/elsewhere", "unrelated", `"e-2"`)
			upstream := &pathologicalUpstream{fakeUpstream: base, dir: "/loop", mode: mode}
			_, layer := newTestCacheLayer(t, upstream, time.Hour)
			readAllViaLayer(t, layer, "/loop/obj")
			readAllViaLayer(t, layer, "/elsewhere")

			paths, ok := layer.enumerateSubtree(t.Context(), "/loop")
			assert.False(t, ok)
			assert.Nil(t, paths)

			require.NoError(t, layer.RemoveAll(t.Context(), "/loop"))
			assert.False(t, isCached(t, layer, "/loop/obj"), "the fallback scan drops the copy")
			assert.True(t, isCached(t, layer, "/elsewhere"))
		})
	}

	t.Run("dot entries are not children", func(t *testing.T) {
		base := newFakeUpstream()
		base.put("/loop/obj", "cached content", `"e-1"`)
		upstream := &pathologicalUpstream{fakeUpstream: base, dir: "/loop", mode: pathDotsOnly}
		_, layer := newTestCacheLayer(t, upstream, time.Hour)
		paths, ok := layer.enumerateSubtree(t.Context(), "/loop")
		assert.True(t, ok)
		assert.Equal(t, []string{"/loop"}, paths)
	})
}
