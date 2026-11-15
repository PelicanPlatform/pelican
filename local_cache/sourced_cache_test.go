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

package local_cache

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// fakeBlockSource serves versions of one object from memory and counts what
// it serves.
type fakeBlockSource struct {
	mu       sync.Mutex
	versions map[string][]byte
	current  string
	// truncate, when positive, ends every read after that many bytes
	// without an error.
	truncate int

	bytesServed atomic.Int64
	reads       atomic.Int64
}

func newFakeBlockSource(etag string, data []byte) *fakeBlockSource {
	return &fakeBlockSource{versions: map[string][]byte{etag: data}, current: etag}
}

func (s *fakeBlockSource) replace(etag string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[etag] = data
	s.current = etag
}

func (s *fakeBlockSource) ReadRange(ctx context.Context, w io.Writer, start, end int64, etag string) error {
	s.reads.Add(1)
	s.mu.Lock()
	data, current, truncate := s.versions[etag], s.current, s.truncate
	s.mu.Unlock()
	if etag != current {
		return errors.Wrapf(ErrSourceVersionChanged, "now %s", current)
	}
	chunk := data[start : end+1]
	if truncate > 0 && truncate < len(chunk) {
		chunk = chunk[:truncate]
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := w.Write(chunk)
	s.bytesServed.Add(int64(n))
	return err
}

func testData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}
	return data
}

func openTestSourcedCache(t *testing.T, dir string) *SourcedCache {
	t.Helper()
	InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, _ := errgroup.WithContext(ctx)
	c, err := OpenSourcedCache(ctx, egrp, SourcedCacheConfig{Dir: dir, MaxSize: 1 << 30})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// publishTestObject records and publishes version etag of key, of size
// bytes.
func publishTestObject(t *testing.T, c *SourcedCache, key, etag string, size int) InstanceHash {
	t.Helper()
	ns, err := c.Namespace("test")
	require.NoError(t, err)
	now := time.Now()
	ih, meta, err := c.Init(key, ns, SourceObject{Size: int64(size), ETag: etag}, now)
	require.NoError(t, err)
	require.Equal(t, int64(size), meta.ContentLength)
	applied, err := c.Publish(key, etag, now)
	require.NoError(t, err)
	require.True(t, applied)
	return ih
}

func readAllFrom(t *testing.T, c *SourcedCache, ih InstanceHash, src BlockSource) []byte {
	t.Helper()
	rr, err := c.NewReader(ih, src, "test")
	require.NoError(t, err)
	defer rr.Close()
	rr.SetReadContext(t.Context())
	got, err := io.ReadAll(rr)
	require.NoError(t, err)
	return got
}

func TestSourcedCacheFillsOnceAndServesFromDisk(t *testing.T) {
	c := openTestSourcedCache(t, t.TempDir())
	data := testData(300_000)
	src := newFakeBlockSource(`"v1"`, data)
	const key = "test://scope/obj"
	ih := publishTestObject(t, c, key, `"v1"`, len(data))

	assert.Equal(t, data, readAllFrom(t, c, ih, src))
	served := src.bytesServed.Load()
	assert.Equal(t, int64(len(data)), served, "the first read fetches the object once")

	found, meta, err := c.Lookup(key)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, ih, found)

	assert.Equal(t, data, readAllFrom(t, c, ih, src))
	assert.Equal(t, served, src.bytesServed.Load(), "a second read is served from disk")
}

func TestSourcedCacheLimitedFillFetchesOnlyTheRange(t *testing.T) {
	c := openTestSourcedCache(t, t.TempDir())
	data := testData(4 << 20)
	src := newFakeBlockSource(`"v1"`, data)
	ih := publishTestObject(t, c, "test://scope/big", `"v1"`, len(data))

	rr, err := c.NewReader(ih, src, "test")
	require.NoError(t, err)
	defer rr.Close()
	rr.SetReadContext(t.Context())

	// A 100-byte range in the middle of the object.
	const off = 2_000_000
	rr.LimitFill([]RangeRequest{{Start: off, End: off + 99}})
	_, err = rr.Seek(off, io.SeekStart)
	require.NoError(t, err)
	buf := make([]byte, 100)
	_, err = io.ReadFull(rr, buf)
	require.NoError(t, err)
	assert.Equal(t, data[off:off+100], buf)
	assert.LessOrEqual(t, src.bytesServed.Load(), int64(2*BlockDataSize),
		"a small range fetches its blocks, not the object")

	// What http.ServeContent does to sniff a content type: read the
	// first 512 bytes with no range to fill.
	rr2, err := c.NewReader(ih, src, "test")
	require.NoError(t, err)
	defer rr2.Close()
	rr2.SetReadContext(t.Context())
	rr2.LimitFill(nil)
	before := src.bytesServed.Load()
	_, err = io.ReadFull(rr2, buf[:100])
	require.NoError(t, err)
	assert.LessOrEqual(t, src.bytesServed.Load()-before, int64(BlockDataSize))
}

func TestSourcedCacheDropsAVersionTheSourceReplaced(t *testing.T) {
	c := openTestSourcedCache(t, t.TempDir())
	data := testData(50_000)
	src := newFakeBlockSource(`"v1"`, data)
	const key = "test://scope/changing"
	ih := publishTestObject(t, c, key, `"v1"`, len(data))

	src.replace(`"v2"`, testData(60_000))
	rr, err := c.NewReader(ih, src, "test")
	require.NoError(t, err)
	rr.SetReadContext(t.Context())
	_, err = io.ReadAll(rr)
	require.Error(t, err, "no bytes of another version are served")
	require.NoError(t, rr.Close())

	require.Eventually(t, func() bool {
		meta, err := c.storage.GetMetadata(ih)
		return err == nil && meta == nil
	}, 5*time.Second, 10*time.Millisecond, "the version that can never be completed is dropped")
}

func TestSourcedCacheShortSourceReadIsNotSuccess(t *testing.T) {
	c := openTestSourcedCache(t, t.TempDir())
	data := testData(50_000)
	src := newFakeBlockSource(`"v1"`, data)
	src.truncate = 1000
	ih := publishTestObject(t, c, "test://scope/short", `"v1"`, len(data))

	rr, err := c.NewReader(ih, src, "test")
	require.NoError(t, err)
	defer rr.Close()
	rr.SetReadContext(t.Context())
	rr.LimitFill(nil)
	_, err = io.ReadAll(rr)
	require.Error(t, err)
	complete, err := c.storage.IsComplete(ih)
	require.NoError(t, err)
	assert.False(t, complete)
}

func TestSourcedCachePublishKeepsTheLaterObservation(t *testing.T) {
	c := openTestSourcedCache(t, t.TempDir())
	const key = "test://scope/obj"
	t0 := time.Now()
	applied, err := c.Publish(key, `"new"`, t0.Add(time.Second))
	require.NoError(t, err)
	require.True(t, applied)
	applied, err = c.Publish(key, `"old"`, t0)
	require.NoError(t, err)
	assert.False(t, applied, "an older observation does not replace a newer one")
}

func TestSourcedCacheRevalidatedReplacesDirectives(t *testing.T) {
	c := openTestSourcedCache(t, t.TempDir())
	ns, err := c.Namespace("test")
	require.NoError(t, err)
	t0 := time.Now()
	ih, meta, err := c.Init("test://scope/cc", ns, SourceObject{Size: 10, ETag: `"v1"`, CacheControl: "no-cache, max-age=60"}, t0)
	require.NoError(t, err)
	require.NotZero(t, meta.CCFlags)

	require.NoError(t, c.Revalidated(ih, "", t0.Add(time.Second)))
	meta, err = c.storage.GetMetadata(ih)
	require.NoError(t, err)
	assert.Zero(t, meta.CCFlags, "a directive the source dropped is dropped")
	assert.Zero(t, meta.CCMaxAge)

	require.NoError(t, c.Revalidated(ih, "no-store", t0))
	meta, err = c.storage.GetMetadata(ih)
	require.NoError(t, err)
	assert.Zero(t, meta.CCFlags, "an older confirmation changes nothing")
	assert.True(t, meta.LastValidated.Equal(t0.Add(time.Second)) || meta.LastValidated.After(t0))
}

func TestSourcedCacheForget(t *testing.T) {
	c := openTestSourcedCache(t, t.TempDir())
	publishTestObject(t, c, "test://scope/dir/a", `"a"`, 10)
	publishTestObject(t, c, "test://scope/dir/b", `"b"`, 10)
	publishTestObject(t, c, "test://scope/other", `"o"`, 10)

	require.NoError(t, c.Forget("test://scope/other"))
	_, meta, err := c.Lookup("test://scope/other")
	require.NoError(t, err)
	assert.Nil(t, meta)

	n, err := c.ForgetPrefix("test://scope/dir/")
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	for _, key := range []string{"test://scope/dir/a", "test://scope/dir/b"} {
		_, meta, err := c.Lookup(key)
		require.NoError(t, err)
		assert.Nil(t, meta, key)
	}
}

func TestSourcedCacheRefusesAForeignDirectory(t *testing.T) {
	InitIssuerKeyForTests(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "precious"), []byte("data"), 0600))
	egrp, _ := errgroup.WithContext(t.Context())
	_, err := OpenSourcedCache(t.Context(), egrp, SourcedCacheConfig{Dir: dir, MaxSize: 1 << 30})
	require.Error(t, err)
	_, err = os.Stat(filepath.Join(dir, "precious"))
	assert.NoError(t, err)
}

func TestSourcedCacheStartsAfreshWhenItsKeyIsGone(t *testing.T) {
	dir := t.TempDir()
	c := openTestSourcedCache(t, dir)
	const key = "test://scope/obj"
	publishTestObject(t, c, key, `"v1"`, 10)
	require.NoError(t, c.Close())

	// Every key that wrapped the master key has been rotated out.
	path := filepath.Join(dir, masterKeyFileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var mk MasterKeyFile
	require.NoError(t, json.Unmarshal(raw, &mk))
	rotated := MasterKeyFile{Keys: map[string][]byte{}}
	for _, v := range mk.Keys {
		rotated.Keys["rotated-out"] = v
	}
	raw, err = json.Marshal(rotated)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))

	c = openTestSourcedCache(t, dir)
	_, meta, err := c.Lookup(key)
	require.NoError(t, err)
	assert.Nil(t, meta, "the cache started empty")
	assert.FileExists(t, filepath.Join(dir, sourcedCacheMarker))
}

func TestSourcedCacheSharesAFillBetweenReaders(t *testing.T) {
	c := openTestSourcedCache(t, t.TempDir())
	data := testData(1 << 20)
	src := newFakeBlockSource(`"v1"`, data)
	ih := publishTestObject(t, c, "test://scope/shared", `"v1"`, len(data))

	var wg sync.WaitGroup
	results := make([][]byte, 4)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = readAllFrom(t, c, ih, src)
		}()
	}
	wg.Wait()
	for _, got := range results {
		assert.True(t, bytes.Equal(data, got))
	}
	// Readers that start together may each fetch a little before they see
	// one another's fill, but not the object each.
	assert.Less(t, src.bytesServed.Load(), int64(2*len(data)))
}
