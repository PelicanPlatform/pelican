//go:build !windows

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
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/cache_control"
	"github.com/pelicanplatform/pelican/server_utils"
)

// ---------------------------------------------------------------------------
// fake upstream — an instrumented webdav.FileSystem standing in for a remote
// backend (S3/HTTPS).  Reads can be gated so tests control fetch progress
// without timing assumptions.
// ---------------------------------------------------------------------------

type fakeObject struct {
	content      []byte
	etag         string
	cacheControl string
	modTime      time.Time

	// When set, each Read must receive a byte allowance from the channel
	// before returning data; closing the channel removes the gate.
	gate chan int

	// When failAfter >= 0, reads at or beyond that offset return the
	// upstream's configured read error instead of data.
	failAfter int
}

type fakeUpstream struct {
	mu        sync.Mutex
	objects   map[string]*fakeObject
	statCount map[string]int
	openCount map[string]int
	readErr   map[string]error // fail reads at the given path after gate bytes

	// failListing simulates a backend with no directory enumeration (e.g. a
	// plain-HTTP upstream): Readdir on directories returns an error.
	failListing bool
	// failWriteClose simulates an upload that fails at commit time.
	failWriteClose bool
	// infoStyle selects which real backend's FileInfo shape Stat/Readdir
	// return, since upstreamValidator treats the three differently.
	infoStyle infoStyle
}

func newFakeUpstream() *fakeUpstream {
	return &fakeUpstream{
		objects:   make(map[string]*fakeObject),
		statCount: make(map[string]int),
		openCount: make(map[string]int),
		readErr:   make(map[string]error),
	}
}

func (u *fakeUpstream) put(name, content, etag string) {
	u.putCC(name, content, etag, "")
}

// putCC stores an object that advertises the given Cache-Control value.
func (u *fakeUpstream) putCC(name, content, etag, cacheControl string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.objects[name] = &fakeObject{content: []byte(content), etag: etag, cacheControl: cacheControl, modTime: time.Now(), failAfter: -1}
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

// fakeUpstreamInfo models a blob (s3v2) backend's FileInfo: the ETag is
// reachable only through Sys(), never exposed to clients as a webdav.ETager.
// See etagerUpstreamInfo for the httpsv2 shape.
type fakeUpstreamInfo struct {
	name         string
	size         int64
	modTime      time.Time
	etag         string
	cacheControl string
	isDir        bool
}

// etagerUpstreamInfo models the HTTPS (httpsv2) backend's FileInfo, which does
// implement webdav.ETager and therefore shows its ETag to clients.  The two
// shapes take different branches of upstreamValidator, and the cache is
// required to reproduce whichever ETag the backend itself would have served.
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

// infoStyle selects which backend's FileInfo shape the fake presents.
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

type fakeUpstreamFile struct {
	upstream *fakeUpstream
	name     string
	obj      *fakeObject
	offset   int
	pending  int // bytes granted by the gate but not yet consumed
}

func (f *fakeUpstreamFile) Read(p []byte) (int, error) {
	if f.obj.failAfter >= 0 && f.offset >= f.obj.failAfter {
		f.upstream.mu.Lock()
		failErr := f.upstream.readErr[f.name]
		f.upstream.mu.Unlock()
		return 0, failErr
	}
	if f.offset >= len(f.obj.content) {
		return 0, io.EOF
	}
	limit := len(p)
	if f.obj.gate != nil {
		for f.pending == 0 {
			granted, ok := <-f.obj.gate
			if !ok {
				f.obj.gate = nil
				f.pending = len(f.obj.content) // gate removed: no further limits
				break
			}
			f.pending += granted
		}
		if limit > f.pending {
			limit = f.pending
		}
	}
	if f.obj.failAfter >= 0 && f.offset+limit > f.obj.failAfter {
		limit = f.obj.failAfter - f.offset
	}
	n := copy(p[:limit], f.obj.content[f.offset:])
	f.offset += n
	f.pending -= n
	return n, nil
}

func (f *fakeUpstreamFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		f.offset = int(offset)
	case io.SeekCurrent:
		f.offset += int(offset)
	case io.SeekEnd:
		f.offset = len(f.obj.content) + int(offset)
	}
	return int64(f.offset), nil
}

func (f *fakeUpstreamFile) Close() error { return nil }
func (f *fakeUpstreamFile) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("read-only fake")
}
func (f *fakeUpstreamFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("not a directory")
}
func (f *fakeUpstreamFile) Stat() (os.FileInfo, error) {
	return f.upstream.wrapInfo(&fakeUpstreamInfo{name: path.Base(f.name), size: int64(len(f.obj.content)), modTime: f.obj.modTime, etag: f.obj.etag, cacheControl: f.obj.cacheControl}), nil
}

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
	defer u.mu.Unlock()
	u.statCount[name]++
	if obj, ok := u.objects[name]; ok {
		return u.wrapInfo(&fakeUpstreamInfo{name: path.Base(name), size: int64(len(obj.content)), modTime: obj.modTime, etag: obj.etag, cacheControl: obj.cacheControl}), nil
	}
	// Directory-style: the path is a prefix of stored keys.
	if u.hasChildrenLocked(name) {
		return &fakeUpstreamInfo{name: path.Base(name), isDir: true, modTime: time.Now()}, nil
	}
	return nil, os.ErrNotExist
}

// hasChildrenLocked reports whether any object lives under name+"/".
// Caller must hold u.mu.
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
		return &fakeUpstreamFile{upstream: u, name: name, obj: obj}, nil
	}
	// Directory-style: build the immediate-children listing.
	if u.hasChildrenLocked(name) {
		prefix := name + "/"
		seenDirs := make(map[string]bool)
		var entries []os.FileInfo
		for k, obj := range u.objects {
			if !strings.HasPrefix(k, prefix) {
				continue
			}
			rest := strings.TrimPrefix(k, prefix)
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				if d := rest[:i]; !seenDirs[d] {
					seenDirs[d] = true
					entries = append(entries, &fakeUpstreamInfo{name: d, isDir: true})
				}
			} else {
				entries = append(entries, u.wrapInfo(&fakeUpstreamInfo{name: rest, size: int64(len(obj.content)), modTime: obj.modTime, etag: obj.etag, cacheControl: obj.cacheControl}))
			}
		}
		return &fakeDirFile{name: name, entries: entries, failRead: u.failListing}, nil
	}
	return nil, os.ErrNotExist
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
	end := f.offset + count
	if end > len(f.entries) {
		end = len(f.entries)
	}
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

// newStorageCacheWithFs builds a cache over an arbitrary afero filesystem and
// does not start the janitor.  Production code goes through newStorageCache,
// which owns the real directory, its permission checks, and the janitor.
func newStorageCacheWithFs(ctx context.Context, fs afero.Fs, maxSize int64, defaultMaxAge time.Duration, revalidationJitter int) *storageCache {
	return &storageCache{
		fs:      fs,
		ctx:     ctx,
		maxSize: maxSize,
		policy: cache_control.Policy{
			DefaultMaxAge: defaultMaxAge,
			JitterPercent: revalidationJitter,
			MaxFreshness:  defaultMaxAge,
		},
		fetchSem: make(chan struct{}, testCacheFetchConcurrency),
		fetches:  make(map[string]*cacheFetch),
	}
}

// testCacheFetchConcurrency is generous enough that the fetch pool never
// becomes an incidental variable; the tests that care about saturation build
// their own cache with a smaller pool.
const testCacheFetchConcurrency = 16

// newTestCacheLayer builds a cache layer with a 24h default freshness and no
// jitter, so freshness behavior in tests is deterministic: entries fetched
// during the test are always fresh unless the object's Cache-Control (or a
// hand-edited sidecar timestamp) says otherwise.
func newTestCacheLayer(t *testing.T, upstream webdav.FileSystem, maxSize int64) (*storageCache, *storageCacheFS, afero.Fs) {
	t.Helper()
	cache, layer, fs, _ := newTestCacheLayerWithPolicy(t, upstream, maxSize, 24*time.Hour, 0)
	return cache, layer, fs
}

// newTestCacheLayerWithPolicy is newTestCacheLayer with an explicit freshness
// policy, and also returns the cancel func so a test can shut the cache down
// mid-flight.
func newTestCacheLayerWithPolicy(t *testing.T, upstream webdav.FileSystem, maxSize int64, defaultMaxAge time.Duration, jitter int) (*storageCache, *storageCacheFS, afero.Fs, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	memFs := afero.NewMemMapFs()
	cache := newStorageCacheWithFs(ctx, memFs, maxSize, defaultMaxAge, jitter)
	layer := cache.newLayer("/test", "test-backend", upstream)
	return cache, layer, memFs, cancel
}

// lookupFetch returns the in-flight fetch for an entry without registering a
// reader on it.  Tests use it to observe fetch state; production code always
// goes through attachFetch, which takes a reference atomically.
func (c *storageCache) lookupFetch(metaRel string) *cacheFetch {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches[metaRel]
}

// rewriteMetaLastValidated backdates a completed entry's validation time so
// tests can force staleness without sleeping.
func rewriteMetaLastValidated(t *testing.T, cache *storageCache, metaRel string, when time.Time) {
	t.Helper()
	meta := cache.readMeta(metaRel)
	require.NotNil(t, meta)
	meta.LastValidatedUnixNano = when.UnixNano()
	require.NoError(t, cache.writeMeta(metaRel, meta))
}

func readAllViaLayer(t *testing.T, layer *storageCacheFS, name string) string {
	t.Helper()
	f, err := layer.OpenFile(context.Background(), name, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(data)
}

// waitFetchDone blocks (via the fetch's condition variable, no polling) until
// the given fetch finishes, returning its terminal error.
func waitFetchDone(f *cacheFetch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for !f.done {
		f.cond.Wait()
	}
	return f.err
}

func countDataFiles(t *testing.T, fs afero.Fs) int {
	t.Helper()
	count := 0
	require.NoError(t, afero.Walk(fs, ".", func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && strings.HasSuffix(p, ".data") {
			count++
		}
		return nil
	}))
	return count
}

// filesWithSuffix lists every file in the cache tree whose name ends in
// suffix, so tests can assert on (the absence of) temporary files.
func filesWithSuffix(t *testing.T, fs afero.Fs, suffix string) []string {
	t.Helper()
	var found []string
	require.NoError(t, afero.Walk(fs, ".", func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && strings.HasSuffix(p, suffix) {
			found = append(found, p)
		}
		return nil
	}))
	return found
}

// fetchStarted reports whether a fetch's copy goroutine has been launched,
// read under the lock that guards the field (never by touching it directly,
// which would race the fetch itself).
func fetchStarted(cache *storageCache, f *cacheFetch) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return f.started
}

// fetchWritten reports how many bytes the shared copy has committed to disk.
func fetchWritten(f *cacheFetch) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.written
}

// newTestCacheOverFs builds a layer over a caller-supplied cache filesystem,
// for the tests that need the cache's own storage to misbehave.
func newTestCacheOverFs(t *testing.T, fs afero.Fs, upstream webdav.FileSystem) (*storageCache, *storageCacheFS) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cache := newStorageCacheWithFs(ctx, fs, 0, 24*time.Hour, 0)
	return cache, cache.newLayer("/test", "test-backend", upstream)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// A first read populates the cache from the upstream; a second read is served
// locally, with the upstream consulted only for revalidation (Stat), never
// for data (OpenFile).
func TestStorageCacheMissThenHit(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/foo/bar.txt", "hello world", `"etag-1"`)
	_, layer, _ := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "hello world", readAllViaLayer(t, layer, "/foo/bar.txt"))
	require.Equal(t, 1, upstream.opens("/foo/bar.txt"))

	// Reading to EOF guarantees the fetch completed and the sidecar was
	// written, so the second read must be a pure cache hit — and since the
	// entry is still fresh, not even a metadata request goes upstream.
	require.Equal(t, "hello world", readAllViaLayer(t, layer, "/foo/bar.txt"))
	require.Equal(t, 1, upstream.opens("/foo/bar.txt"), "second read should not open the upstream")
	require.Equal(t, 1, upstream.stats("/foo/bar.txt"), "fresh entry should be served without revalidation")

	// The hit preserves the upstream's metadata.
	f, err := layer.OpenFile(context.Background(), "/foo/bar.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()
	info, err := f.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(len("hello world")), info.Size())
}

// The ETag a client sees must not depend on whether the object happened to be
// cached.  A backend that exposes its ETag to clients (httpsv2, via
// webdav.ETager) has it reproduced from the cache; one that keeps it internal
// (s3v2, where it reaches this layer only through Sys()) must keep looking the
// same through the cache, letting the webdav handler derive its usual
// size/mtime ETag rather than suddenly revealing the provider's.
func TestStorageCacheETagMatchesBackendShape(t *testing.T) {
	// clientETag reports the ETag a webdav handler would send for info, and
	// whether the FileInfo supplied one at all.
	clientETag := func(t *testing.T, info os.FileInfo) (string, bool) {
		t.Helper()
		et, ok := info.(webdav.ETager)
		if !ok {
			return "", false
		}
		v, err := et.ETag(context.Background())
		if err == webdav.ErrNotImplemented {
			return "", false
		}
		require.NoError(t, err)
		return v, true
	}

	for _, tc := range []struct {
		name        string
		style       infoStyle
		wantVisible bool
	}{
		{"blob backend keeps its ETag internal", infoStyleBlob, false},
		{"https backend exposes its ETag", infoStyleETager, true},
		{"webdav-mode backend keeps its ETag internal", infoStyleGoWebdav, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newFakeUpstream()
			upstream.infoStyle = tc.style
			upstream.put("/obj", "payload", `"etag-1"`)
			_, layer, _ := newTestCacheLayer(t, upstream, 0)

			// What the backend itself would have served.
			backendInfo, err := upstream.Stat(context.Background(), "/obj")
			require.NoError(t, err)
			backendETag, backendHas := clientETag(t, backendInfo)

			require.Equal(t, "payload", readAllViaLayer(t, layer, "/obj"))

			cachedInfo, err := layer.Stat(context.Background(), "/obj")
			require.NoError(t, err)
			cachedETag, cachedHas := clientETag(t, cachedInfo)

			assert.Equal(t, tc.wantVisible, backendHas, "test's model of the backend")
			assert.Equal(t, backendHas, cachedHas, "cache changed whether an ETag is exposed")
			assert.Equal(t, backendETag, cachedETag, "cache changed the ETag value")
		})
	}
}

// The cache directory must not be writable by other local users: anyone who
// can write there can plant a sidecar and choose the bytes this origin serves.
// A directory created under a permissive umask (or one that already existed
// with loose permissions) is tightened rather than rejected, since the origin
// owns it -- CI containers routinely run with umask 000, and refusing to start
// would be a hard failure on something we can simply fix.
func TestStorageCacheTightensDirectoryPermissions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	loc := path.Join(t.TempDir(), "cache")
	require.NoError(t, os.MkdirAll(loc, 0777))
	require.NoError(t, os.Chmod(loc, 0777)) // defeat the ambient umask
	info, err := os.Stat(loc)
	require.NoError(t, err)
	require.NotZero(t, info.Mode().Perm()&0022, "test needs a world-writable directory to start from")

	cache, err := newStorageCache(ctx, loc, 0, time.Hour, 0, 4)
	require.NoError(t, err, "a loose cache directory should be tightened, not rejected")
	require.NotNil(t, cache)

	info, err = os.Stat(loc)
	require.NoError(t, err)
	assert.Zero(t, info.Mode().Perm()&0022, "directory should no longer be group- or world-writable")
}

// A cache location that is not a directory, or cannot be written, must fail at
// startup rather than turning every later request into an error.
func TestStorageCacheRejectsUnusableLocation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	notADir := path.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0600))
	_, err := newStorageCache(ctx, notADir, 0, time.Hour, 0, 4)
	require.Error(t, err)

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permissions")
	}
	readOnly := path.Join(t.TempDir(), "ro")
	require.NoError(t, os.MkdirAll(readOnly, 0500))
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0700) })
	_, err = newStorageCache(ctx, readOnly, 0, time.Hour, 0, 4)
	require.Error(t, err, "an unwritable cache directory must fail at startup")
}

// A pure range read takes the backend-bypass path and never starts the shared
// copy, so nothing else will ever clean up its registration.  It must release
// its fetch-pool slot and the empty data file it reserved on close; otherwise
// enough range-only reads permanently exhaust the pool and every later miss
// falls through to the backend uncached.
func TestStorageCacheRangeReadDoesNotLeakSlot(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", strings.Repeat("z", 4096), `"etag-1"`)
	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	f, err := layer.OpenFile(context.Background(), "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)
	_, err = f.Seek(1000, io.SeekStart)
	require.NoError(t, err)
	buf := make([]byte, 200)
	_, err = io.ReadFull(f, buf)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	metaRel, _, _ := layer.entryPaths("/obj")
	assert.Nil(t, cache.lookupFetch(metaRel), "fetch left registered")
	assert.Equal(t, 0, len(cache.fetchSem), "fetch pool slot leaked")
	assert.Equal(t, 0, countDataFiles(t, memFs), "empty data file left behind")
}

// A weak ETag says the backend considers two different payloads equivalent,
// which is exactly the comparison a cache must not make.  Such a validator is
// rejected: the entry falls back to a size/mtime validator, so a same-size
// rewrite that keeps the weak tag is still noticed via the modification time.
func TestStorageCacheRejectsWeakETag(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.infoStyle = infoStyleETager
	upstream.putCC("/obj", "version one", `W/"weak"`, "max-age=0")
	cache, layer, _ := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "version one", readAllViaLayer(t, layer, "/obj"))

	metaRel, _, _ := layer.entryPaths("/obj")
	meta := cache.readMeta(metaRel)
	require.NotNil(t, meta)
	assert.NotEqual(t, `W/"weak"`, meta.Validator, "weak ETag used as a validator")
	assert.Empty(t, meta.ETag, "weak ETag re-served to clients")

	// The same weak tag on different content must not read as unchanged.
	upstream.putCC("/obj", "version two!", `W/"weak"`, "max-age=0")
	assert.Equal(t, "version two!", readAllViaLayer(t, layer, "/obj"))
}

// When a stale entry's upstream object changed (new ETag), the cached copy is
// discarded and refetched; the superseded data file is cleaned up.  Objects
// advertising max-age=0 are stale on every read, so each read revalidates.
func TestStorageCacheRevalidation(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.putCC("/obj", "version one", `"etag-1"`, "max-age=0")
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "version one", readAllViaLayer(t, layer, "/obj"))
	upstream.putCC("/obj", "version two!", `"etag-2"`, "max-age=0")

	require.Equal(t, "version two!", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 2, upstream.opens("/obj"))
	assert.Equal(t, 1, countDataFiles(t, memFs), "superseded data file should be removed")

	// And with the same ETag again: revalidation (a stat) but no refetch.
	require.Equal(t, "version two!", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 2, upstream.opens("/obj"))
	require.Equal(t, 3, upstream.stats("/obj"), "max-age=0 must revalidate on every read")
}

// Opening a file and probing metadata (Stat, Seek-to-end) must not trigger a
// data fetch from the upstream: HEAD requests stay egress-free.
func TestStorageCacheLazyFetch(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "some content", `"etag-1"`)
	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	f, err := layer.OpenFile(context.Background(), "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)
	info, err := f.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(len("some content")), info.Size())
	size, err := f.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(len("some content")), size)
	require.NoError(t, f.Close())

	assert.Equal(t, 0, upstream.opens("/obj"), "metadata-only access should not fetch data")

	// Closing the never-read handle discards the pending fetch entirely: no
	// registry entry and no leftover data file.
	metaRel, _, _ := layer.entryPaths("/obj")
	assert.Nil(t, cache.lookupFetch(metaRel))
	assert.Equal(t, 0, countDataFiles(t, memFs))
}

// Two concurrent readers of the same object share one upstream fetch.
func TestStorageCacheCoalescing(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "shared content", `"etag-1"`)
	_, layer, _ := newTestCacheLayer(t, upstream, 0)

	fA, err := layer.OpenFile(context.Background(), "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer fA.Close()
	fB, err := layer.OpenFile(context.Background(), "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer fB.Close()

	var wg sync.WaitGroup
	results := make([]string, 2)
	for i, f := range []webdav.File{fA, fB} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := io.ReadAll(f)
			assert.NoError(t, err)
			results[i] = string(data)
		}()
	}
	wg.Wait()

	assert.Equal(t, "shared content", results[0])
	assert.Equal(t, "shared content", results[1])
	assert.Equal(t, 1, upstream.opens("/obj"), "concurrent readers should share one fetch")
}

// A client that reads part of the object and disconnects does not stop the
// fetch: the upstream copy runs to completion and later reads are cache hits.
func TestStorageCacheFetchSurvivesClientDisconnect(t *testing.T) {
	content := strings.Repeat("x", 1000) + strings.Repeat("y", 1000)
	upstream := newFakeUpstream()
	upstream.put("/obj", content, `"etag-1"`)
	gate := make(chan int)
	upstream.objects["/obj"].gate = gate

	cache, layer, _ := newTestCacheLayer(t, upstream, 0)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	f, err := layer.OpenFile(reqCtx, "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)

	// Let the fetch deliver the first 100 bytes and read them as the client.
	go func() { gate <- 100 }()
	buf := make([]byte, 100)
	n, err := io.ReadFull(f, buf)
	require.NoError(t, err)
	require.Equal(t, 100, n)
	require.Equal(t, content[:100], string(buf))

	// Grab the in-flight fetch, then disconnect the client.
	metaRel, _, _ := layer.entryPaths("/obj")
	fetch := cache.lookupFetch(metaRel)
	require.NotNil(t, fetch)
	cancelReq()
	_, err = f.Read(buf)
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, f.Close())

	// Release the rest of the object; the detached fetch must finish cleanly.
	close(gate)
	require.NoError(t, waitFetchDone(fetch))

	// The completed entry now serves hits with no additional upstream opens.
	require.Equal(t, content, readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, 1, upstream.opens("/obj"))
}

// A reader that outpaces the upstream blocks until bytes arrive, then
// continues — the buffering pipeline decouples the two speeds.
func TestStorageCacheSlowUpstreamFastClient(t *testing.T) {
	content := "abcdefghij"
	upstream := newFakeUpstream()
	upstream.put("/obj", content, `"etag-1"`)
	gate := make(chan int)
	upstream.objects["/obj"].gate = gate

	_, layer, _ := newTestCacheLayer(t, upstream, 0)
	f, err := layer.OpenFile(context.Background(), "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	done := make(chan string)
	go func() {
		data, err := io.ReadAll(f)
		assert.NoError(t, err)
		done <- string(data)
	}()

	// Dribble the object out in three unequal chunks.
	gate <- 3
	gate <- 5
	close(gate)
	assert.Equal(t, content, <-done)
}

// An upstream failure mid-fetch propagates an error (not a silent short
// read) and leaves no sidecar behind, so the next read refetches.
func TestStorageCacheFetchErrorPropagates(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "will fail", `"etag-1"`)
	gate := make(chan int)
	upstream.objects["/obj"].gate = gate
	upstream.objects["/obj"].failAfter = 4
	upstream.readErr["/obj"] = fmt.Errorf("upstream connection reset")

	_, layer, memFs := newTestCacheLayer(t, upstream, 0)
	f, err := layer.OpenFile(context.Background(), "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	// Allow a partial delivery; the read after the granted bytes fails.
	go func() { gate <- 4 }()
	data, err := io.ReadAll(f)
	require.Error(t, err)
	require.Contains(t, err.Error(), "connection reset")
	assert.Equal(t, "will", string(data), "bytes before the failure are still delivered")

	// No sidecar may exist for the failed fetch.
	metaRel, _, _ := layer.entryPaths("/obj")
	exists, err := afero.Exists(memFs, metaRel)
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Equal(t, 0, countDataFiles(t, memFs), "partial data file should be cleaned up")
}

// A write through the layer drops the cached copy so a subsequent read
// revalidates and refetches the new content.
func TestStorageCacheWriteInvalidates(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "original", `"etag-1"`)
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "original", readAllViaLayer(t, layer, "/obj"))

	w, err := layer.OpenFile(context.Background(), "/obj", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = w.Write([]byte("replaced"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	metaRel, _, _ := layer.entryPaths("/obj")
	exists, err := afero.Exists(memFs, metaRel)
	require.NoError(t, err)
	assert.False(t, exists, "write should invalidate the cache entry")

	require.Equal(t, "replaced", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 2, upstream.opens("/obj"))
}

// Deleting or renaming an object invalidates its cache entry.
func TestStorageCacheRemoveAndRenameInvalidate(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/a", "content a", `"etag-a"`)
	upstream.put("/b", "content b", `"etag-b"`)
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	readAllViaLayer(t, layer, "/a")
	readAllViaLayer(t, layer, "/b")
	require.Equal(t, 2, countDataFiles(t, memFs))

	require.NoError(t, layer.RemoveAll(context.Background(), "/a"))
	metaA, _, _ := layer.entryPaths("/a")
	exists, _ := afero.Exists(memFs, metaA)
	assert.False(t, exists)

	require.NoError(t, layer.Rename(context.Background(), "/b", "/c"))
	metaB, _, _ := layer.entryPaths("/b")
	exists, _ = afero.Exists(memFs, metaB)
	assert.False(t, exists)
}

// Eviction removes least-recently-accessed entries until usage drops below
// the target watermark; in-flight fetches are exempt.
func TestStorageCacheEviction(t *testing.T) {
	upstream := newFakeUpstream()
	for i := 0; i < 4; i++ {
		upstream.put(fmt.Sprintf("/obj%d", i), strings.Repeat("z", 100), fmt.Sprintf(`"etag-%d"`, i))
	}
	// Max size fits two objects comfortably but not four.
	cache, layer, memFs := newTestCacheLayer(t, upstream, 250)

	base := time.Now().Add(-time.Hour)
	for i := 0; i < 4; i++ {
		readAllViaLayer(t, layer, fmt.Sprintf("/obj%d", i))
		// Stamp distinct access times (oldest first) deterministically.
		metaRel, _, _ := layer.entryPaths(fmt.Sprintf("/obj%d", i))
		require.NoError(t, memFs.Chtimes(metaRel, base.Add(time.Duration(i)*time.Minute), base.Add(time.Duration(i)*time.Minute)))
	}
	require.Equal(t, 4, countDataFiles(t, memFs))

	cache.evictOnce()

	// Target is 90% of 250 = 225, so two 100-byte entries survive.
	require.Equal(t, 2, countDataFiles(t, memFs))
	// The survivors are the most recently accessed ones.
	for i, wantSurvive := range []bool{false, false, true, true} {
		metaRel, _, _ := layer.entryPaths(fmt.Sprintf("/obj%d", i))
		exists, err := afero.Exists(memFs, metaRel)
		require.NoError(t, err)
		assert.Equal(t, wantSurvive, exists, "obj%d survival", i)
	}

	// Evicted entries are refetched on demand.
	require.Equal(t, strings.Repeat("z", 100), readAllViaLayer(t, layer, "/obj0"))
	require.Equal(t, 2, upstream.opens("/obj0"))
}

// Objects without an upstream ETag fall back to the size/mtime validator and
// still cache correctly.
func TestStorageCacheNoETagFallback(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "no etag here", "")
	_, layer, _ := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "no etag here", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, "no etag here", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 1, upstream.opens("/obj"), "unchanged object should be a hit without an ETag")

	// The served info must not invent a client-visible ETag.
	f, err := layer.OpenFile(context.Background(), "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()
	info, err := f.Stat()
	require.NoError(t, err)
	etager, ok := info.(webdav.ETager)
	require.True(t, ok)
	_, err = etager.ETag(context.Background())
	assert.ErrorIs(t, err, webdav.ErrNotImplemented)
}

// While an entry is fresh it is served with zero upstream interaction —
// no data open and no metadata stat — even if the upstream object has been
// deleted in the meantime (standard HTTP caching semantics).
func TestStorageCacheFreshServesWithoutStat(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "cache me", `"etag-1"`)
	_, layer, _ := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "cache me", readAllViaLayer(t, layer, "/obj"))
	require.NoError(t, upstream.RemoveAll(context.Background(), "/obj"))

	// Fresh window (24h default, no jitter): served locally despite the
	// upstream deletion.
	require.Equal(t, "cache me", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 1, upstream.stats("/obj"))
	require.Equal(t, 1, upstream.opens("/obj"))

	// The layer's Stat is also answered from the fresh entry.
	info, err := layer.Stat(context.Background(), "/obj")
	require.NoError(t, err)
	assert.Equal(t, int64(len("cache me")), info.Size())
	require.Equal(t, 1, upstream.stats("/obj"))
}

// A stale entry whose validator still matches is renewed in place: one stat,
// no refetch, and the entry becomes fresh again.
func TestStorageCacheStaleRevalidationRenews(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "steady content", `"etag-1"`)
	cache, layer, _ := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "steady content", readAllViaLayer(t, layer, "/obj"))

	// Backdate the validation time beyond the 24h default freshness.
	metaRel, _, _ := layer.entryPaths("/obj")
	rewriteMetaLastValidated(t, cache, metaRel, time.Now().Add(-48*time.Hour))

	// Stale → revalidate (stat #2) → validator matches → served locally.
	require.Equal(t, "steady content", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 2, upstream.stats("/obj"))
	require.Equal(t, 1, upstream.opens("/obj"), "matching validator must not refetch")

	// The renewal reset the freshness window: no further stats needed.
	require.Equal(t, "steady content", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 2, upstream.stats("/obj"))

	meta := cache.readMeta(metaRel)
	require.NotNil(t, meta)
	assert.Greater(t, meta.LastValidatedUnixNano, time.Now().Add(-time.Hour).UnixNano(),
		"revalidation should bump the validation timestamp")
}

// Objects marked no-store (or private) bypass the cache entirely: every read
// streams from the backend and nothing is persisted.
func TestStorageCacheNoStoreBypasses(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.putCC("/obj", "sensitive", `"etag-1"`, "no-store")
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "sensitive", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, "sensitive", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 2, upstream.opens("/obj"), "no-store must stream from the backend every time")

	assert.Equal(t, 0, countDataFiles(t, memFs))
	metaRel, _, _ := layer.entryPaths("/obj")
	exists, err := afero.Exists(memFs, metaRel)
	require.NoError(t, err)
	assert.False(t, exists, "no-store must not persist a sidecar")
}

// An object that later turns no-store has its previously cached copy dropped.
func TestStorageCacheNoStoreDropsExistingEntry(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.putCC("/obj", "cacheable", `"etag-1"`, "max-age=0")
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "cacheable", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 1, countDataFiles(t, memFs))

	upstream.putCC("/obj", "now sensitive", `"etag-2"`, "no-store")
	require.Equal(t, "now sensitive", readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, 0, countDataFiles(t, memFs), "no-store must purge the stale local copy")
}

// Deleting a directory through the origin invalidates every cached
// descendant immediately — no waiting for freshness to lapse.
func TestStorageCacheDirRemoveInvalidatesDescendants(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/dir/a", "content a", `"etag-a"`)
	upstream.put("/dir/b", "content b", `"etag-b"`)
	upstream.put("/other", "content o", `"etag-o"`)
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	readAllViaLayer(t, layer, "/dir/a")
	readAllViaLayer(t, layer, "/dir/b")
	readAllViaLayer(t, layer, "/other")
	require.Equal(t, 3, countDataFiles(t, memFs))

	require.NoError(t, layer.RemoveAll(context.Background(), "/dir"))

	// The descendants' entries are gone; the unrelated entry survives.
	require.Equal(t, 1, countDataFiles(t, memFs))
	for _, p := range []string{"/dir/a", "/dir/b"} {
		metaRel, _, _ := layer.entryPaths(p)
		exists, err := afero.Exists(memFs, metaRel)
		require.NoError(t, err)
		assert.False(t, exists, "entry for %s should be invalidated", p)
	}

	// A read now reflects the deletion instead of serving a fresh copy.
	_, err := layer.OpenFile(context.Background(), "/dir/a", os.O_RDONLY, 0)
	assert.ErrorIs(t, err, os.ErrNotExist)

	// The unrelated object still serves from cache.
	require.Equal(t, "content o", readAllViaLayer(t, layer, "/other"))
	require.Equal(t, 1, upstream.opens("/other"))
}

// Renaming a directory invalidates cached descendants under both the old and
// the new name.
func TestStorageCacheDirRenameInvalidatesDescendants(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/src/a", "alpha", `"etag-a"`)
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	readAllViaLayer(t, layer, "/src/a")
	require.NoError(t, layer.Rename(context.Background(), "/src", "/dst"))

	require.Equal(t, 0, countDataFiles(t, memFs))
	_, err := layer.OpenFile(context.Background(), "/src/a", os.O_RDONLY, 0)
	assert.ErrorIs(t, err, os.ErrNotExist)
	require.Equal(t, "alpha", readAllViaLayer(t, layer, "/dst/a"))
}

// A write racing an in-flight fetch supersedes it: the fetch still streams
// the pre-write bytes to its attached readers, but must not install them as
// a fresh cache entry afterwards.
func TestStorageCacheWriteSupersedesInFlightFetch(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "old content", `"etag-old"`)
	gate := make(chan int)
	upstream.objects["/obj"].gate = gate

	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	f, err := layer.OpenFile(context.Background(), "/obj", os.O_RDONLY, 0)
	require.NoError(t, err)

	// Start the fetch and let a few bytes through.
	go func() { gate <- 3 }()
	buf := make([]byte, 3)
	_, err = io.ReadFull(f, buf)
	require.NoError(t, err)

	metaRel, _, _ := layer.entryPaths("/obj")
	fetch := cache.lookupFetch(metaRel)
	require.NotNil(t, fetch)

	// Overwrite the object through the origin while the fetch is running.
	w, err := layer.OpenFile(context.Background(), "/obj", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = w.Write([]byte("new content!"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Let the fetch finish; the attached reader drains the OLD snapshot...
	close(gate)
	rest, err := io.ReadAll(f)
	require.NoError(t, err)
	require.Equal(t, "old content", string(buf)+string(rest))
	require.NoError(t, f.Close())
	require.NoError(t, waitFetchDone(fetch))

	// ...but nothing was installed: no sidecar, no data file.
	assert.Nil(t, cache.readMeta(metaRel))
	assert.Equal(t, 0, countDataFiles(t, memFs))

	// The next read fetches the post-write content.
	require.Equal(t, "new content!", readAllViaLayer(t, layer, "/obj"))
}

// Enumeration-based unrolling recurses through nested directories and only
// touches entries under the deleted prefix.
func TestStorageCacheDirRemoveNested(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/dir/a", "a", `"e-a"`)
	upstream.put("/dir/sub/b", "bb", `"e-b"`)
	upstream.put("/dir/sub/deep/c", "ccc", `"e-c"`)
	upstream.put("/keep", "keep", `"e-k"`)
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	for _, p := range []string{"/dir/a", "/dir/sub/b", "/dir/sub/deep/c", "/keep"} {
		readAllViaLayer(t, layer, p)
	}
	require.Equal(t, 4, countDataFiles(t, memFs))

	require.NoError(t, layer.RemoveAll(context.Background(), "/dir"))

	require.Equal(t, 1, countDataFiles(t, memFs))
	require.Equal(t, "keep", readAllViaLayer(t, layer, "/keep"))
	require.Equal(t, 1, upstream.opens("/keep"))
}

// When the backend cannot enumerate a directory, invalidation falls back to
// scanning the cache's own sidecars and still drops every descendant.
func TestStorageCacheDirRemoveFallbackScan(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/dir/a", "a content", `"e-a"`)
	upstream.put("/keep", "keep", `"e-k"`)
	upstream.failListing = true
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)

	readAllViaLayer(t, layer, "/dir/a")
	readAllViaLayer(t, layer, "/keep")

	require.NoError(t, layer.RemoveAll(context.Background(), "/dir"))

	metaRel, _, _ := layer.entryPaths("/dir/a")
	exists, err := afero.Exists(memFs, metaRel)
	require.NoError(t, err)
	assert.False(t, exists, "fallback scan should invalidate the descendant")
	keepMeta, _, _ := layer.entryPaths("/keep")
	exists, err = afero.Exists(memFs, keepMeta)
	require.NoError(t, err)
	assert.True(t, exists, "unrelated entry must survive the fallback scan")
}

// Deleting a directory supersedes in-flight fetches beneath it: attached
// readers drain the old snapshot, but nothing is installed, and subsequent
// reads see the deletion.
func TestStorageCacheDirRemoveSupersedesInFlightFetch(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/dir/obj", "doomed content", `"e-1"`)
	gate := make(chan int)
	upstream.objects["/dir/obj"].gate = gate

	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	f, err := layer.OpenFile(context.Background(), "/dir/obj", os.O_RDONLY, 0)
	require.NoError(t, err)
	go func() { gate <- 3 }()
	buf := make([]byte, 3)
	_, err = io.ReadFull(f, buf)
	require.NoError(t, err)

	metaRel, _, _ := layer.entryPaths("/dir/obj")
	fetch := cache.lookupFetch(metaRel)
	require.NotNil(t, fetch)

	require.NoError(t, layer.RemoveAll(context.Background(), "/dir"))

	close(gate)
	rest, err := io.ReadAll(f)
	require.NoError(t, err)
	require.Equal(t, "doomed content", string(buf)+string(rest))
	require.NoError(t, f.Close())
	require.NoError(t, waitFetchDone(fetch))

	assert.Nil(t, cache.readMeta(metaRel))
	assert.Equal(t, 0, countDataFiles(t, memFs))
	_, err = layer.OpenFile(context.Background(), "/dir/obj", os.O_RDONLY, 0)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// The old copy keeps serving (from cache) while an overwrite is uploading;
// the entry is dropped exactly when the upload commits.
func TestStorageCacheWriteCommitSemantics(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "old", `"e-old"`)
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)
	require.Equal(t, "old", readAllViaLayer(t, layer, "/obj"))

	w, err := layer.OpenFile(context.Background(), "/obj", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = w.Write([]byte("new"))
	require.NoError(t, err)

	// Upload in progress: reads still serve the old copy, from cache.
	require.Equal(t, "old", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 1, upstream.opens("/obj"))

	require.NoError(t, w.Close())
	metaRel, _, _ := layer.entryPaths("/obj")
	exists, err := afero.Exists(memFs, metaRel)
	require.NoError(t, err)
	assert.False(t, exists, "commit must invalidate the entry")
	require.Equal(t, "new", readAllViaLayer(t, layer, "/obj"))
}

// A failed upload still invalidates: the backend's state is unknown, so the
// next read must revalidate rather than trust the pre-write copy blindly.
func TestStorageCacheFailedWriteStillInvalidates(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "old", `"e-old"`)
	upstream.failWriteClose = true
	_, layer, memFs := newTestCacheLayer(t, upstream, 0)
	require.Equal(t, "old", readAllViaLayer(t, layer, "/obj"))

	w, err := layer.OpenFile(context.Background(), "/obj", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = w.Write([]byte("partial"))
	require.NoError(t, err)
	require.Error(t, w.Close())

	metaRel, _, _ := layer.entryPaths("/obj")
	exists, err := afero.Exists(memFs, metaRel)
	require.NoError(t, err)
	assert.False(t, exists, "failed commit must still invalidate")

	// Upstream is unchanged (the fake never committed), so the next read
	// revalidates and refetches the same content.
	require.Equal(t, "old", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 2, upstream.opens("/obj"))
}

// Renaming onto a destination that already has cached objects invalidates
// the destination subtree too — the cached pre-rename destination content
// must not keep serving.
func TestStorageCacheRenameInvalidatesDestination(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/src/a", "source", `"e-s"`)
	upstream.put("/dst/a", "dest-old", `"e-d"`)
	_, layer, _ := newTestCacheLayer(t, upstream, 0)

	require.Equal(t, "dest-old", readAllViaLayer(t, layer, "/dst/a"))
	require.NoError(t, layer.Rename(context.Background(), "/src", "/dst"))
	require.Equal(t, "source", readAllViaLayer(t, layer, "/dst/a"))
}

// A missing object propagates the upstream's not-found error.
func TestStorageCacheNotFound(t *testing.T) {
	upstream := newFakeUpstream()
	_, layer, _ := newTestCacheLayer(t, upstream, 0)
	_, err := layer.OpenFile(context.Background(), "/missing", os.O_RDONLY, 0)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// net/http's ServeContent reads the first sniff-length bytes of a file purely
// to guess a Content-Type — even for a HEAD request — and then rewinds.  The
// layer must recognize that pattern and retire the copy instead of finishing
// it: otherwise a HEAD on a multi-gigabyte object would pull the whole thing
// out of the provider, which is exactly the egress this layer exists to avoid.
func TestStorageCacheSniffDoesNotFetchWholeObject(t *testing.T) {
	content := strings.Repeat("s", 4096)
	upstream := newFakeUpstream()
	upstream.put("/sniffed", content, `"e-1"`)
	upstream.put("/fully-read", content, `"e-2"`)
	gate := make(chan int)
	upstream.objects["/sniffed"].gate = gate

	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	f, err := layer.OpenFile(context.Background(), "/sniffed", os.O_RDONLY, 0)
	require.NoError(t, err)

	// The ServeContent sniff: read exactly sniffLen bytes, then seek back.
	go func() { gate <- storageCacheSniffLen }()
	buf := make([]byte, storageCacheSniffLen)
	_, err = io.ReadFull(f, buf)
	require.NoError(t, err)
	require.Equal(t, content[:storageCacheSniffLen], string(buf))

	metaRel, _, _ := layer.entryPaths("/sniffed")
	fetch := cache.lookupFetch(metaRel)
	require.NotNil(t, fetch)

	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Closing the sniffing handle retires the fetch immediately.
	assert.Nil(t, cache.lookupFetch(metaRel), "a sniff should retire the fetch")

	// Let the retired copy unwind (the fake backend does not honour the
	// cancelled context) and confirm it installs nothing.
	close(gate)
	require.NoError(t, waitFetchDone(fetch))
	assert.Nil(t, cache.readMeta(metaRel), "a sniff must not install a cache entry")
	assert.Equal(t, 0, countDataFiles(t, memFs), "a sniff must leave no data file behind")

	// Contrast: a real read of the whole object does install an entry, which
	// then serves subsequent reads.
	require.Equal(t, content, readAllViaLayer(t, layer, "/fully-read"))
	fullMeta, _, _ := layer.entryPaths("/fully-read")
	assert.NotNil(t, cache.readMeta(fullMeta), "a full read should install a cache entry")
	assert.Equal(t, 1, countDataFiles(t, memFs))
	require.Equal(t, content, readAllViaLayer(t, layer, "/fully-read"))
	assert.Equal(t, 1, upstream.opens("/fully-read"), "the second full read should be a cache hit")
}

// The sniff carve-out must not swallow real transfers: a client that reads
// some bytes and goes away without rewinding is a partial download, not a
// content-type probe, so its copy still runs to completion and lands in the
// cache.  (Regression guard for the client-disconnect behaviour: the retire
// rule keys on "read only the prefix *and* ended back at zero".)
func TestStorageCachePartialReadWithoutRewindFinishesCopy(t *testing.T) {
	content := strings.Repeat("p", 4096)
	upstream := newFakeUpstream()
	upstream.put("/partial", content, `"e-1"`)
	gate := make(chan int)
	upstream.objects["/partial"].gate = gate

	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	f, err := layer.OpenFile(context.Background(), "/partial", os.O_RDONLY, 0)
	require.NoError(t, err)

	go func() { gate <- 100 }()
	buf := make([]byte, 100)
	_, err = io.ReadFull(f, buf)
	require.NoError(t, err)
	require.Equal(t, content[:100], string(buf))

	metaRel, _, _ := layer.entryPaths("/partial")
	fetch := cache.lookupFetch(metaRel)
	require.NotNil(t, fetch)

	// No rewind: just close, as a disconnecting client would.
	require.NoError(t, f.Close())
	assert.NotNil(t, cache.lookupFetch(metaRel), "a partial download must not retire the copy")

	close(gate)
	require.NoError(t, waitFetchDone(fetch))

	meta := cache.readMeta(metaRel)
	require.NotNil(t, meta, "the abandoned copy should still install an entry")
	assert.Equal(t, int64(len(content)), meta.Size)
	assert.Equal(t, 1, countDataFiles(t, memFs))

	// The completed copy now serves hits without touching the backend again.
	require.Equal(t, content, readAllViaLayer(t, layer, "/partial"))
	assert.Equal(t, 1, upstream.opens("/partial"))
}

// A range request must not drag the whole object through the cache: a reader
// positioned past what the shared copy has written goes straight to the
// backend, and a ranged read on its own never starts a copy at all.  Waiting
// for a sequential copy to reach the offset would turn a small ranged read
// into a whole-object transfer.
func TestStorageCacheRangeReadBypassesSharedCopy(t *testing.T) {
	content := strings.Repeat("a", 500) + strings.Repeat("b", 1500)
	upstream := newFakeUpstream()
	upstream.put("/ranged", content, `"e-1"`)
	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	f, err := layer.OpenFile(context.Background(), "/ranged", os.O_RDONLY, 0)
	require.NoError(t, err)

	// Nothing has been written by the copy (it has not even started), so this
	// offset is necessarily past it — no gating needed to observe the state.
	metaRel, _, _ := layer.entryPaths("/ranged")
	fetch := cache.lookupFetch(metaRel)
	require.NotNil(t, fetch)
	require.False(t, fetchStarted(cache, fetch), "opening a file must not start a copy")

	off, err := f.Seek(1000, io.SeekStart)
	require.NoError(t, err)
	require.Equal(t, int64(1000), off)
	buf := make([]byte, 200)
	_, err = io.ReadFull(f, buf)
	require.NoError(t, err)

	// The ranged read returns the right slice...
	assert.Equal(t, content[1000:1200], string(buf))
	// ...directly from the backend, without starting the shared copy.
	assert.False(t, fetchStarted(cache, fetch), "a range request must not start a whole-object copy")
	assert.Zero(t, fetchWritten(fetch), "no bytes should have been copied into the cache")
	assert.Equal(t, 1, upstream.opens("/ranged"), "exactly one backend handle, for the range itself")
	assert.Nil(t, cache.readMeta(metaRel), "a range request must not install an entry")

	require.NoError(t, f.Close())
	assert.Nil(t, cache.readMeta(metaRel), "closing a ranged reader must not install an entry")

	// Seeking back and reading from the start is a sequential transfer again,
	// and does populate the cache.
	f2, err := layer.OpenFile(context.Background(), "/ranged", os.O_RDONLY, 0)
	require.NoError(t, err)
	data, err := io.ReadAll(f2)
	require.NoError(t, err)
	require.NoError(t, f2.Close())
	assert.Equal(t, content, string(data))
	assert.NotNil(t, cache.readMeta(metaRel), "a sequential read should populate the cache")
	assert.Equal(t, content, readAllViaLayer(t, layer, "/ranged"))
	assert.GreaterOrEqual(t, countDataFiles(t, memFs), 1)
}

// The fetch pool bounds how many upstream-to-disk copies run at once.  A
// request that cannot get a slot must be served straight from the backend
// rather than queueing behind unrelated transfers: the cache is an
// optimization, never a dependency.
func TestStorageCacheFetchPoolSaturationFallsThrough(t *testing.T) {
	slowContent := strings.Repeat("s", 1000)
	upstream := newFakeUpstream()
	upstream.put("/slow", slowContent, `"e-s"`)
	upstream.put("/other", "other content", `"e-o"`)
	gate := make(chan int)
	upstream.objects["/slow"].gate = gate

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	memFs := afero.NewMemMapFs()
	cache := newStorageCacheWithFs(ctx, memFs, 0, 24*time.Hour, 0)
	cache.fetchSem = make(chan struct{}, 1) // room for exactly one copy
	layer := cache.newLayer("/test", "test-backend", upstream)

	f, err := layer.OpenFile(ctx, "/slow", os.O_RDONLY, 0)
	require.NoError(t, err)

	// Start the copy and leave it mid-flight, holding the only slot.
	go func() { gate <- 10 }()
	buf := make([]byte, 10)
	_, err = io.ReadFull(f, buf)
	require.NoError(t, err)

	slowMeta, _, _ := layer.entryPaths("/slow")
	fetch := cache.lookupFetch(slowMeta)
	require.NotNil(t, fetch)
	require.True(t, fetchStarted(cache, fetch))

	// A different object cannot get a slot; it must still be served correctly.
	require.Equal(t, "other content", readAllViaLayer(t, layer, "/other"))
	assert.Equal(t, 1, upstream.opens("/other"))
	otherMeta, _, _ := layer.entryPaths("/other")
	assert.Nil(t, cache.readMeta(otherMeta), "a saturated-pool read must not install an entry")

	// Let the held fetch finish and give its slot back.
	close(gate)
	rest, err := io.ReadAll(f)
	require.NoError(t, err)
	require.Equal(t, slowContent, string(buf)+string(rest))
	require.NoError(t, f.Close())
	require.NoError(t, waitFetchDone(fetch))

	// Acquiring the semaphore blocks until the finished fetch releases its
	// slot, so this waits for the pool to drain without polling.
	cache.fetchSem <- struct{}{}
	<-cache.fetchSem

	// With a slot available the same object is cached normally: falling
	// through is a transient degradation, not a permanent one.
	require.Equal(t, "other content", readAllViaLayer(t, layer, "/other"))
	assert.NotNil(t, cache.readMeta(otherMeta), "the pool freed up; the read should now be cached")
}

// createFailingFs allows everything except creating files, standing in for a
// cache disk that has filled up mid-operation.  It exercises the layer's
// "cannot create cache file" fallback rather than the "cannot create cache
// directory" one a read-only filesystem hits first.
type createFailingFs struct {
	afero.Fs
}

func (fs createFailingFs) Create(_ string) (afero.File, error) {
	return nil, fmt.Errorf("no space left on device")
}

func (fs createFailingFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if flag&os.O_CREATE != 0 {
		return nil, fmt.Errorf("no space left on device")
	}
	return fs.Fs.OpenFile(name, flag, perm)
}

// A cache that cannot write must degrade throughput, not availability: every
// read still returns the backend's bytes.  The repeated reads also guard the
// fetch-pool bookkeeping — a failure path that forgot to return its slot would
// wedge the layer after the pool's worth of failures.
func TestStorageCacheUnwritableCacheFailsOpen(t *testing.T) {
	for _, tc := range []struct {
		name string
		fs   func() afero.Fs
	}{
		{"read-only cache filesystem", func() afero.Fs { return afero.NewReadOnlyFs(afero.NewMemMapFs()) }},
		{"cache disk full", func() afero.Fs { return createFailingFs{afero.NewMemMapFs()} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newFakeUpstream()
			upstream.put("/obj", "backend payload", `"e-1"`)
			cache, layer := newTestCacheOverFs(t, tc.fs(), upstream)

			// More reads than the fetch pool has slots: if a failure path
			// leaked its slot the later reads would still succeed (they fall
			// through), so also check the registry stays clean.
			for i := 0; i < testCacheFetchConcurrency+4; i++ {
				require.Equal(t, "backend payload", readAllViaLayer(t, layer, "/obj"))
			}
			assert.Equal(t, testCacheFetchConcurrency+4, upstream.opens("/obj"),
				"every read should be served from the backend")

			metaRel, _, _ := layer.entryPaths("/obj")
			assert.Nil(t, cache.lookupFetch(metaRel), "a failed fetch must not stay registered")
			assert.Nil(t, cache.readMeta(metaRel))

			// The pool must be empty again; acquiring every slot proves it
			// without polling (it would block otherwise).
			for i := 0; i < testCacheFetchConcurrency; i++ {
				cache.fetchSem <- struct{}{}
			}
			for i := 0; i < testCacheFetchConcurrency; i++ {
				<-cache.fetchSem
			}
		})
	}
}

// A data file with no sidecar is a leftover from a process that died
// mid-fetch; nothing will ever reference it again, so it must be reclaimed
// independently of the size bound (the default cache is unbounded and would
// otherwise accumulate them forever).  Files that a live sidecar or a
// registered fetch owns must survive.
func TestStorageCachePruneOrphans(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/live", "live content", `"e-l"`)
	upstream.put("/pending", "pending content", `"e-p"`)
	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	// A completed entry: sidecar plus data file.
	require.Equal(t, "live content", readAllViaLayer(t, layer, "/live"))
	liveMeta, liveDir, _ := layer.entryPaths("/live")
	meta := cache.readMeta(liveMeta)
	require.NotNil(t, meta)
	liveData := path.Join(liveDir, meta.DataFile)

	// A stray data file in the layout the cache generates, with no sidecar.
	orphanDir := path.Join(layer.scope, "objects", "aa")
	orphan := path.Join(orphanDir, strings.Repeat("a", 64)+"-"+strings.Repeat("b", 16)+".data")
	require.NoError(t, memFs.MkdirAll(orphanDir, 0700))
	require.NoError(t, afero.WriteFile(memFs, orphan, []byte("leftover"), 0600))

	// A sidecar temp file left behind by an interrupted rename, backdated so
	// it is older than the (zero) grace period.
	staleTmp := path.Join(orphanDir, strings.Repeat("a", 64)+".meta.0011223344556677.tmp")
	require.NoError(t, afero.WriteFile(memFs, staleTmp, []byte("{}"), 0600))
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, memFs.Chtimes(staleTmp, old, old))

	// A registered (not yet started) fetch owns its data file; the sweep must
	// not race it away.
	pendingHandle, err := layer.OpenFile(context.Background(), "/pending", os.O_RDONLY, 0)
	require.NoError(t, err)
	pendingMeta, _, _ := layer.entryPaths("/pending")
	pendingFetch := cache.lookupFetch(pendingMeta)
	require.NotNil(t, pendingFetch)

	cache.pruneOrphans(0)

	exists, err := afero.Exists(memFs, orphan)
	require.NoError(t, err)
	assert.False(t, exists, "a data file with no sidecar should be reclaimed")
	exists, err = afero.Exists(memFs, staleTmp)
	require.NoError(t, err)
	assert.False(t, exists, "an abandoned sidecar temp file should be reclaimed")
	exists, err = afero.Exists(memFs, liveData)
	require.NoError(t, err)
	assert.True(t, exists, "a data file with a live sidecar must survive")
	exists, err = afero.Exists(memFs, pendingFetch.dataRel)
	require.NoError(t, err)
	assert.True(t, exists, "an in-flight fetch's data file must survive")

	require.NoError(t, pendingHandle.Close())

	// The grace period protects recently created files even without a sidecar.
	require.NoError(t, afero.WriteFile(memFs, orphan, []byte("leftover"), 0600))
	freshTmp := path.Join(orphanDir, strings.Repeat("c", 64)+".meta.8899aabbccddeeff.tmp")
	require.NoError(t, afero.WriteFile(memFs, freshTmp, []byte("{}"), 0600))
	cache.pruneOrphans(time.Hour)
	for _, p := range []string{orphan, freshTmp} {
		exists, err = afero.Exists(memFs, p)
		require.NoError(t, err)
		assert.True(t, exists, "%s is inside the grace period and must survive", p)
	}

	// The cached entry still serves after the sweeps.
	require.Equal(t, "live content", readAllViaLayer(t, layer, "/live"))
	assert.Equal(t, 1, upstream.opens("/live"))
}

// A sidecar is read back from disk and its DataFile becomes a path component,
// so it is validated rather than trusted: a corrupted (or hand-planted)
// sidecar must read as a miss and be refetched, never as a licence to serve
// bytes from somewhere else in the tree.
func TestStorageCacheMalformedSidecarIsAMiss(t *testing.T) {
	validData := strings.Repeat("c", 64) + "-" + strings.Repeat("d", 16) + ".data"
	for _, tc := range []struct {
		name string
		body string
	}{
		{"data file escapes the cache tree", `{"path":"/obj","size":5,"dataFile":"../../escape.data"}`},
		{"data file is an absolute path", `{"path":"/obj","size":5,"dataFile":"/etc/passwd"}`},
		{"data file does not match the layout", `{"path":"/obj","size":5,"dataFile":"whatever.data"}`},
		{"negative size", fmt.Sprintf(`{"path":"/obj","size":-1,"dataFile":%q}`, validData)},
		{"not json at all", `this is not json`},
		{"empty data file", `{"path":"/obj","size":5}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newFakeUpstream()
			upstream.put("/obj", "real content", `"e-1"`)
			cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

			metaRel, hashDir, _ := layer.entryPaths("/obj")
			require.NoError(t, memFs.MkdirAll(hashDir, 0700))
			require.NoError(t, afero.WriteFile(memFs, metaRel, []byte(tc.body), 0600))

			// Plant a file where a traversing sidecar would point, so serving
			// it would be visible.
			require.NoError(t, afero.WriteFile(memFs, "escape.data", []byte("planted"), 0600))

			assert.Nil(t, cache.readMeta(metaRel), "a malformed sidecar must read as a miss")

			// The read refetches from the backend rather than serving anything
			// the sidecar named.
			require.Equal(t, "real content", readAllViaLayer(t, layer, "/obj"))
			assert.Equal(t, 1, upstream.opens("/obj"))

			// ...and replaces the bad sidecar with a well-formed one.
			meta := cache.readMeta(metaRel)
			require.NotNil(t, meta)
			assert.True(t, storageCacheDataFileRe.MatchString(meta.DataFile))

			planted, err := afero.ReadFile(memFs, "escape.data")
			require.NoError(t, err)
			assert.Equal(t, "planted", string(planted), "the cache must not have written outside its layout")
		})
	}
}

// The sidecar is what marks a data file complete, so it is written through a
// temporary file and a rename: a reader must never observe a half-written
// sidecar, and a crash mid-update must not litter the tree with temp files
// (which would otherwise be reclaimed only after the orphan grace period).
func TestStorageCacheWriteMetaIsAtomic(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "content", `"e-1"`)
	cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

	metaRel, hashDir, hash := layer.entryPaths("/obj")
	require.NoError(t, memFs.MkdirAll(hashDir, 0700))

	meta := &cacheEntryMeta{
		Path:                  "/obj",
		Validator:             `"e-1"`,
		Size:                  7,
		ModTimeUnixNano:       time.Now().UnixNano(),
		LastValidatedUnixNano: time.Now().UnixNano(),
		DataFile:              hash + "-" + strings.Repeat("0", 16) + ".data",
	}
	require.NoError(t, cache.writeMeta(metaRel, meta))

	got := cache.readMeta(metaRel)
	require.NotNil(t, got, "the sidecar must be readable immediately after the write")
	assert.Equal(t, *meta, *got)
	assert.Empty(t, filesWithSuffix(t, memFs, ".tmp"), "writeMeta left a temporary file behind")

	// Overwriting an existing sidecar is equally clean.
	meta.Size = 11
	require.NoError(t, cache.writeMeta(metaRel, meta))
	got = cache.readMeta(metaRel)
	require.NotNil(t, got)
	assert.Equal(t, int64(11), got.Size)
	assert.Empty(t, filesWithSuffix(t, memFs, ".tmp"))

	// And so is the write a completed fetch performs.
	require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
	assert.NotNil(t, cache.readMeta(metaRel))
	assert.Empty(t, filesWithSuffix(t, memFs, ".tmp"), "a completed fetch left a temporary file behind")
}

// Origin.StorageCacheDefaultMaxAge of zero means "revalidate on every read".
// A backend must not be able to opt out of that with a long max-age of its
// own: whoever can write an object's metadata would otherwise pin it in the
// cache for as long as they liked.
func TestStorageCacheZeroDefaultMaxAgeAlwaysRevalidates(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.putCC("/obj", "content", `"e-1"`, "max-age=3600")
	_, layer, _, _ := newTestCacheLayerWithPolicy(t, upstream, 0, 0, 0)

	require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 1, upstream.stats("/obj"))
	require.Equal(t, 1, upstream.opens("/obj"))

	require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, 2, upstream.stats("/obj"), "a zero default max-age must revalidate every read")
	assert.Equal(t, 1, upstream.opens("/obj"), "an unchanged validator must not refetch the data")

	// The metadata path honours it too.
	_, err := layer.Stat(context.Background(), "/obj")
	require.NoError(t, err)
	assert.Equal(t, 3, upstream.stats("/obj"), "Stat must also revalidate")
}

// The configured default max-age doubles as a ceiling on the freshness a
// backend may claim for itself, so an object whose metadata says "cache me for
// ten years" is still revalidated once the operator's window lapses.
func TestStorageCacheBackendMaxAgeCappedByDefault(t *testing.T) {
	upstream := newFakeUpstream()
	// max-age=87600h, i.e. ten years.
	upstream.putCC("/obj", "content", `"e-1"`, "max-age=315360000")
	cache, layer, _, _ := newTestCacheLayerWithPolicy(t, upstream, 0, time.Hour, 0)

	require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
	require.Equal(t, 1, upstream.stats("/obj"))
	metaRel, _, _ := layer.entryPaths("/obj")

	// Well inside the configured hour: served with no upstream interaction.
	rewriteMetaLastValidated(t, cache, metaRel, time.Now().Add(-30*time.Minute))
	require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, 1, upstream.stats("/obj"), "within the cap the copy is still fresh")

	// Past the configured hour, but far inside the backend's claim.
	rewriteMetaLastValidated(t, cache, metaRel, time.Now().Add(-2*time.Hour))
	require.Equal(t, "content", readAllViaLayer(t, layer, "/obj"))
	assert.Equal(t, 2, upstream.stats("/obj"), "the backend's max-age must be capped by the configured default")
	assert.Equal(t, 1, upstream.opens("/obj"), "revalidation alone must not refetch the data")
}

// Freshness jitter is seeded per object, not merely per validation instant:
// objects fetched together must not all expire at the same moment and send a
// synchronized burst of revalidations at the backend.
func TestStorageCacheFreshnessJitterIsPerObject(t *testing.T) {
	lastValidated := time.Unix(1_700_000_000, 0)
	const maxAge = time.Hour
	const jitter = 50

	a := cache_control.FreshnessFor(lastValidated, maxAge, jitter, "/exports/data/a.txt")
	b := cache_control.FreshnessFor(lastValidated, maxAge, jitter, "/exports/data/b.txt")
	assert.NotEqual(t, a, b, "objects validated together must not share a freshness window")
	assert.Equal(t, a, cache_control.FreshnessFor(lastValidated, maxAge, jitter, "/exports/data/a.txt"),
		"the same object must get the same window every time")

	// Jitter only ever shortens the operator's window.
	for _, v := range []time.Duration{a, b} {
		assert.GreaterOrEqual(t, v, maxAge/2)
		assert.LessOrEqual(t, v, maxAge)
	}
	assert.Equal(t, maxAge, cache_control.FreshnessFor(lastValidated, maxAge, 0, "/exports/data/a.txt"),
		"no jitter must give the full window")
}

// Cache entries are scoped by federation prefix and by backend identity.  Two
// exports that happen to serve the same object path must not read each other's
// copies, and repointing an export at different storage must not serve entries
// cached from the old one.
func TestStorageCacheScopeIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	memFs := afero.NewMemMapFs()
	cache := newStorageCacheWithFs(ctx, memFs, 0, 24*time.Hour, 0)

	upA := newFakeUpstream()
	upA.put("/obj", "from export A", `"e-a"`)
	upB := newFakeUpstream()
	upB.put("/obj", "from export B", `"e-b"`)
	upC := newFakeUpstream()
	upC.put("/obj", "from other backend", `"e-c"`)

	layerA := cache.newLayer("/exports/a", "backend-1", upA)
	layerB := cache.newLayer("/exports/b", "backend-1", upB)
	layerC := cache.newLayer("/exports/a", "backend-2", upC)

	metaA, _, _ := layerA.entryPaths("/obj")
	metaB, _, _ := layerB.entryPaths("/obj")
	metaC, _, _ := layerC.entryPaths("/obj")
	assert.NotEqual(t, metaA, metaB, "different federation prefixes must not share an entry")
	assert.NotEqual(t, metaA, metaC, "different backends must not share an entry")

	require.Equal(t, "from export A", readAllViaLayer(t, layerA, "/obj"))
	assert.Nil(t, cache.readMeta(metaB), "populating one export must not populate another")
	assert.Nil(t, cache.readMeta(metaC), "populating one backend must not populate another")

	// Each layer goes to its own upstream, and each caches independently.
	require.Equal(t, "from export B", readAllViaLayer(t, layerB, "/obj"))
	require.Equal(t, "from other backend", readAllViaLayer(t, layerC, "/obj"))
	assert.Equal(t, 1, upA.opens("/obj"))
	assert.Equal(t, 1, upB.opens("/obj"))
	assert.Equal(t, 1, upC.opens("/obj"))

	require.Equal(t, "from export A", readAllViaLayer(t, layerA, "/obj"))
	require.Equal(t, "from export B", readAllViaLayer(t, layerB, "/obj"))
	require.Equal(t, "from other backend", readAllViaLayer(t, layerC, "/obj"))
	assert.Equal(t, 1, upA.opens("/obj"), "each scope should serve its own cached copy")
	assert.Equal(t, 1, upB.opens("/obj"))
	assert.Equal(t, 1, upC.opens("/obj"))

	// Invalidating one scope leaves the others alone.
	require.NoError(t, layerA.RemoveAll(ctx, "/obj"))
	assert.Nil(t, cache.readMeta(metaA))
	assert.NotNil(t, cache.readMeta(metaB))
	assert.NotNil(t, cache.readMeta(metaC))
}

// pathologicalMode selects the shape of a backend listing that a subtree walk
// must not trust.
type pathologicalMode int

const (
	// pathSelfRef: every directory reports a subdirectory of the same name,
	// so a naive walk recurses forever.
	pathSelfRef pathologicalMode = iota
	// pathDotsOnly: listings contain only ".", ".." and an empty name, which
	// a naive walk would follow back into the directory it is already in.
	pathDotsOnly
	// pathWide: one flat listing far larger than the enumeration cap.
	pathWide
)

// pathologicalUpstream wraps the ordinary fake with a directory that lists
// itself, or lists nothing but self-references, or lists more entries than the
// enumeration cap allows.
type pathologicalUpstream struct {
	*fakeUpstream
	dir  string
	mode pathologicalMode
}

// isSyntheticDir reports whether name is the pathological directory or (in
// self-referential mode) one of the endless "loop" descendants it claims.
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
		u.mu.Lock()
		u.statCount[name]++
		u.mu.Unlock()
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
	// Entries a walk must skip rather than recurse into.
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
// materializing it, so the enumeration cap can be exercised cheaply.
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

// A subtree walk drives off a listing the backend controls, so it must be
// bounded in both depth and breadth: a self-referential (or merely enormous)
// prefix must not hang the mutation or exhaust memory.  When the walk gives
// up, invalidation still has to be correct — it falls back to scanning the
// cache's own sidecars, which is authoritative over what is cached.
func TestStorageCacheEnumerationGuards(t *testing.T) {
	t.Run("self-referential listing falls back to the sidecar scan", func(t *testing.T) {
		base := newFakeUpstream()
		base.put("/loop/obj", "cached content", `"e-1"`)
		base.put("/elsewhere", "unrelated", `"e-2"`)
		upstream := &pathologicalUpstream{fakeUpstream: base, dir: "/loop", mode: pathSelfRef}
		cache, layer, memFs := newTestCacheLayer(t, upstream, 0)

		require.Equal(t, "cached content", readAllViaLayer(t, layer, "/loop/obj"))
		require.Equal(t, "unrelated", readAllViaLayer(t, layer, "/elsewhere"))

		// The walk must bottom out rather than recurse without bound.
		paths, ok := layer.enumerateSubtree(context.Background(), "/loop")
		assert.False(t, ok, "an unbounded listing must not be reported as enumerated")
		assert.Nil(t, paths)

		// ...and the mutation still drops the cached descendant.
		require.NoError(t, layer.RemoveAll(context.Background(), "/loop"))
		metaRel, _, _ := layer.entryPaths("/loop/obj")
		assert.Nil(t, cache.readMeta(metaRel), "the fallback scan should drop the entry")
		assert.Equal(t, 1, countDataFiles(t, memFs), "only the unrelated entry should remain")

		keepMeta, _, _ := layer.entryPaths("/elsewhere")
		assert.NotNil(t, cache.readMeta(keepMeta), "an unrelated entry must survive")
	})

	t.Run("dot entries are not children", func(t *testing.T) {
		base := newFakeUpstream()
		base.put("/loop/obj", "cached content", `"e-1"`)
		upstream := &pathologicalUpstream{fakeUpstream: base, dir: "/loop", mode: pathDotsOnly}
		_, layer, _ := newTestCacheLayer(t, upstream, 0)

		// "." / ".." / "" must be skipped, so the walk terminates and reports
		// only the directory itself.
		paths, ok := layer.enumerateSubtree(context.Background(), "/loop")
		assert.True(t, ok, "a listing of only dot entries is enumerable")
		assert.Equal(t, []string{"/loop"}, paths)
	})

	t.Run("listing beyond the enumeration cap falls back", func(t *testing.T) {
		base := newFakeUpstream()
		base.put("/wide/obj", "cached content", `"e-1"`)
		upstream := &pathologicalUpstream{fakeUpstream: base, dir: "/wide", mode: pathWide}
		cache, layer, _ := newTestCacheLayer(t, upstream, 0)

		require.Equal(t, "cached content", readAllViaLayer(t, layer, "/wide/obj"))

		paths, ok := layer.enumerateSubtree(context.Background(), "/wide")
		assert.False(t, ok, "a listing past the cap must not be reported as enumerated")
		assert.Nil(t, paths)

		require.NoError(t, layer.RemoveAll(context.Background(), "/wide"))
		metaRel, _, _ := layer.entryPaths("/wide/obj")
		assert.Nil(t, cache.readMeta(metaRel), "the fallback scan should drop the entry")
	})
}

// The WebDAV PROPFIND handler asks a FileInfo for its content type and only
// falls back to opening the file and sniffing its first bytes when the
// FileInfo cannot say.  Through this layer that fallback would mean a backend
// round trip (and an object fetch) for every file in a listing, so every
// FileInfo this layer hands out must answer.  Wrapping must not otherwise
// change what the backend would have reported — in particular the ETag.
func TestStorageCacheStatCarriesContentType(t *testing.T) {
	// Register the extension this test relies on rather than trusting the
	// host's MIME database: Go's builtin table does not cover .txt, so on a
	// container without /etc/mime.types TypeByExtension(".txt") is empty.
	const knownExt, knownType = ".pelican-known", "application/x-pelican-test"
	require.NoError(t, mime.AddExtensionType(knownExt, knownType))

	contentTypeOf := func(t *testing.T, info os.FileInfo) string {
		t.Helper()
		ct, ok := info.(webdav.ContentTyper)
		require.True(t, ok, "FileInfo must implement webdav.ContentTyper so PROPFIND never opens the object")
		got, err := ct.ContentType(context.Background())
		require.NoError(t, err)
		return got
	}

	t.Run("uncached stat answers without opening the object", func(t *testing.T) {
		upstream := newFakeUpstream()
		upstream.put("/dir/file.pelican-known", "hello", `"e-1"`)
		upstream.put("/dir/blob.pelican-unknown", "hello", `"e-2"`)
		_, layer, _ := newTestCacheLayer(t, upstream, 0)

		info, err := layer.Stat(context.Background(), "/dir/file.pelican-known")
		require.NoError(t, err)
		assert.Equal(t, knownType, contentTypeOf(t, info))

		info, err = layer.Stat(context.Background(), "/dir/blob.pelican-unknown")
		require.NoError(t, err)
		assert.Equal(t, "application/octet-stream", contentTypeOf(t, info),
			"an unknown extension must still get a type")

		assert.Equal(t, 0, upstream.opens("/dir/file.pelican-known"), "answering a content type must not open the object")
		assert.Equal(t, 0, upstream.opens("/dir/blob.pelican-unknown"))
	})

	t.Run("cached stat answers too", func(t *testing.T) {
		upstream := newFakeUpstream()
		upstream.put("/file.pelican-known", "hello", `"e-1"`)
		upstream.put("/blob.pelican-unknown", "hello", `"e-2"`)
		_, layer, _ := newTestCacheLayer(t, upstream, 0)

		require.Equal(t, "hello", readAllViaLayer(t, layer, "/file.pelican-known"))
		require.Equal(t, "hello", readAllViaLayer(t, layer, "/blob.pelican-unknown"))

		info, err := layer.Stat(context.Background(), "/file.pelican-known")
		require.NoError(t, err)
		assert.Equal(t, knownType, contentTypeOf(t, info))
		info, err = layer.Stat(context.Background(), "/blob.pelican-unknown")
		require.NoError(t, err)
		assert.Equal(t, "application/octet-stream", contentTypeOf(t, info))
	})

	t.Run("listed entries answer too", func(t *testing.T) {
		upstream := newFakeUpstream()
		upstream.put("/dir/file.pelican-known", "hello", `"e-1"`)
		upstream.put("/dir/sub/nested.pelican-known", "hello", `"e-2"`)
		_, layer, _ := newTestCacheLayer(t, upstream, 0)

		dir, err := layer.OpenFile(context.Background(), "/dir", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer dir.Close()
		entries, err := dir.Readdir(-1)
		require.NoError(t, err)
		require.Len(t, entries, 2)
		for _, e := range entries {
			if e.IsDir() {
				continue // directories are never sniffed
			}
			assert.Equal(t, knownType, contentTypeOf(t, e))
		}
	})

	t.Run("the wrapper preserves the backend's ETag", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			style   infoStyle
			wantTag string
		}{
			{"https backend exposes its ETag", infoStyleETager, `"e-1"`},
			{"blob backend keeps its ETag internal", infoStyleBlob, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				upstream := newFakeUpstream()
				upstream.infoStyle = tc.style
				upstream.put("/file.pelican-known", "hello", `"e-1"`)
				_, layer, _ := newTestCacheLayer(t, upstream, 0)

				info, err := layer.Stat(context.Background(), "/file.pelican-known")
				require.NoError(t, err)
				etager, ok := info.(webdav.ETager)
				require.True(t, ok)
				got, err := etager.ETag(context.Background())
				if tc.wantTag == "" {
					assert.ErrorIs(t, err, webdav.ErrNotImplemented,
						"the wrapper must not invent an ETag the backend does not expose")
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tc.wantTag, got)
			})
		}
	})
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

// A backend computes digests from the object as it exists upstream right now,
// but a fresh cache entry is served from the copy taken when it was fetched.
// If the object changed out-of-band the two disagree, and a client checking
// the digest against the body it received would see corruption rather than
// staleness — so no digest is reported while a fresh copy is being served.
func TestStorageCacheDigestSuppressedOnFreshHit(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.put("/obj", "digest me", `"e-1"`)
	cache, layer, _ := newTestCacheLayer(t, upstream, 0)

	inner := &stubChecksummer{}
	summer := &cachedChecksummer{inner: inner, layer: layer}

	// Nothing cached: the backend's digest describes what the client will get.
	digests, err := summer.GetDigests("/obj", "md5")
	require.NoError(t, err)
	assert.Equal(t, []string{"md5=/obj;md5"}, digests)
	assert.Equal(t, 1, inner.callCount())

	// Fresh cache entry: no digest at all.
	require.Equal(t, "digest me", readAllViaLayer(t, layer, "/obj"))
	digests, err = summer.GetDigests("/obj", "md5")
	require.NoError(t, err)
	assert.Nil(t, digests, "a fresh cache hit must not carry the backend's digest")
	assert.Equal(t, 1, inner.callCount(), "the backend must not even be consulted")

	// Stale entry: the next read revalidates against the backend, so the
	// backend's digest applies again.
	metaRel, _, _ := layer.entryPaths("/obj")
	rewriteMetaLastValidated(t, cache, metaRel, time.Now().Add(-48*time.Hour))
	digests, err = summer.GetDigests("/obj", "md5")
	require.NoError(t, err)
	assert.Equal(t, []string{"md5=/obj;md5"}, digests)
	assert.Equal(t, 2, inner.callCount())

	// The wrapper is only installed when the backend has digest support.
	assert.Nil(t, newCachedBackend(&stubBackend{fs: layer}, layer).Checksummer(),
		"a backend without checksums must not gain one")
	wrapped := newCachedBackend(&stubBackend{fs: layer, checksummer: inner}, layer).Checksummer()
	require.NotNil(t, wrapped)
	assert.IsType(t, &cachedChecksummer{}, wrapped)
}
