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

type fakeUpstreamInfo struct {
	name         string
	size         int64
	modTime      time.Time
	etag         string
	cacheControl string
	isDir        bool
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
	return &fakeUpstreamInfo{name: path.Base(f.name), size: int64(len(f.obj.content)), modTime: f.obj.modTime, etag: f.obj.etag, cacheControl: f.obj.cacheControl}, nil
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
		return &fakeUpstreamInfo{name: path.Base(name), size: int64(len(obj.content)), modTime: obj.modTime, etag: obj.etag, cacheControl: obj.cacheControl}, nil
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
				entries = append(entries, &fakeUpstreamInfo{name: rest, size: int64(len(obj.content)), modTime: obj.modTime, etag: obj.etag, cacheControl: obj.cacheControl})
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

// newTestCacheLayer builds a cache layer with a 24h default freshness and no
// jitter, so freshness behavior in tests is deterministic: entries fetched
// during the test are always fresh unless the object's Cache-Control (or a
// hand-edited sidecar timestamp) says otherwise.
func newTestCacheLayer(t *testing.T, upstream webdav.FileSystem, maxSize int64) (*storageCache, *storageCacheFS, afero.Fs) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	memFs := afero.NewMemMapFs()
	cache := newStorageCacheWithFs(ctx, memFs, maxSize, 24*time.Hour, 0)
	layer := cache.newLayer("/test", upstream)
	return cache, layer, memFs
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

	// The hit is served with the upstream's ETag and metadata preserved.
	f, err := layer.OpenFile(context.Background(), "/foo/bar.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer f.Close()
	info, err := f.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(len("hello world")), info.Size())
	etager, ok := info.(webdav.ETager)
	require.True(t, ok)
	etag, err := etager.ETag(context.Background())
	require.NoError(t, err)
	assert.Equal(t, `"etag-1"`, etag)
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
