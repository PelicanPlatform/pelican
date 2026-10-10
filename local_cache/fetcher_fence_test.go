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

package local_cache

import (
	"bytes"
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
)

// versionedOrigin serves one object under an entity tag the test can change,
// as an origin whose object is replaced in place.
type versionedOrigin struct {
	data     []byte
	etag     atomic.Pointer[string]
	requests atomic.Int32
}

func newVersionedOrigin(size int, etag string) *versionedOrigin {
	o := &versionedOrigin{data: make([]byte, size)}
	for i := range o.data {
		o.data[i] = byte(i % 251)
	}
	o.etag.Store(&etag)
	return o
}

func (o *versionedOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.requests.Add(1)
	w.Header().Set("ETag", *o.etag.Load())
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(o.data))
}

// fetcherFenceEnv is a cache in front of a versionedOrigin, holding the
// origin's object as an empty disk instance -- as a range read of an
// uncached object leaves it before it reads -- with a fetcher made for it.
type fetcherFenceEnv struct {
	*stubFedCache
	origin *versionedOrigin
	hash   InstanceHash
	meta   *CacheMetadata
	bf     *BlockFetcherV2
}

func newFetcherFenceEnv(t *testing.T) *fetcherFenceEnv {
	t.Helper()
	const etag = `"v1"`
	origin := newVersionedOrigin(4<<20, etag)
	env := &fetcherFenceEnv{stubFedCache: newStubFedCache(t, origin), origin: origin}
	pelicanURL := env.pc.normalizePath("/test/obj.bin")
	env.hash = env.pc.db.InstanceHash(etag, env.pc.db.ObjectHash(pelicanURL))
	var diskID StorageID
	for id := range env.pc.storage.GetDirs() {
		diskID = id
	}
	_, err := env.pc.storage.InitDiskStorage(context.Background(), env.hash, int64(len(origin.data)), diskID, 1)
	require.NoError(t, err)
	require.NoError(t, env.pc.storage.MergeMetadata(env.hash, &CacheMetadata{ETag: etag, SourceURL: pelicanURL}))
	env.meta, err = env.pc.storage.GetMetadata(env.hash)
	require.NoError(t, err)

	env.bf, err = NewBlockFetcherV2(env.pc.storage, env.hash, pelicanURL, "", env.pc.fedTokenAsProvider(), env.pc.te,
		BlockFetcherV2Config{PrefetchTimeout: time.Minute})
	require.NoError(t, err)
	t.Cleanup(env.bf.Close)
	return env
}

// refetch deletes the instance and makes it again under the same hash, as a
// fetch of the same version after a deletion does.
func (e *fetcherFenceEnv) refetch(t *testing.T) {
	t.Helper()
	require.NoError(t, e.pc.storage.Delete(e.hash))
	_, err := e.pc.storage.InitDiskStorage(context.Background(), e.hash, e.meta.ContentLength, e.meta.StorageID, e.meta.NamespaceID)
	require.NoError(t, err)
}

// requireSuccessorUntouched checks that the instance under the hash is the
// one refetch made -- not the fetcher's -- and that the fetcher's verdict
// reached neither its record nor its block state.
func (e *fetcherFenceEnv) requireSuccessorUntouched(t *testing.T) {
	t.Helper()
	meta, err := e.pc.storage.GetMetadata(e.hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "the fetch dropped the new instance of the object")
	assert.NotEqual(t, e.meta.DataKey, meta.DataKey, "the instance under the hash must be the new one")
	state, err := e.pc.storage.GetSharedBlockState(e.hash)
	require.NoError(t, err)
	assert.NotSame(t, e.bf.blockState, state)
	assert.NoError(t, state.Condemned(), "the fetch condemned the new instance")
	assert.Zero(t, state.GetCardinality(), "the fetch wrote blocks of the new instance")
}

// TestFillOfADeletedInstanceDropsNothingOfItsSuccessor checks that a fill
// whose data is condemned -- here because the origin replaced the object --
// drops only the instance it wrote: if that was deleted, and the same
// version fetched again under the same hash, before the fill's verdict, the
// new instance keeps its record and its block state is not condemned, while
// the fill's own readers, holding the old instance's state, are told.
func TestFillOfADeletedInstanceDropsNothingOfItsSuccessor(t *testing.T) {
	env := newFetcherFenceEnv(t)
	replaced := `"v2"`
	env.origin.etag.Store(&replaced)
	fired := false
	env.bf.beforeDrop = func() {
		fired = true
		env.refetch(t)
	}

	err := env.bf.Fill(context.Background(), 2, 3)
	require.ErrorIs(t, err, client.ErrObjectVersionChanged)
	require.True(t, fired, "the fill must have reached its verdict")
	assert.ErrorIs(t, env.bf.blockState.Condemned(), client.ErrObjectVersionChanged,
		"the readers of the fill's own instance must learn the verdict")
	env.requireSuccessorUntouched(t)
	assert.Zero(t, env.pc.storage.fences.size(), "the fill must leave the fence")
}

// TestFetcherOfADeletedInstanceFetchesNothingForItsSuccessor checks a fetcher
// made for an instance that has since been deleted and fetched again under
// the same hash: a fill it starts afterwards is for an instance that is gone,
// so it fetches nothing, writes nothing, and -- though the origin would now
// refuse it as replaced -- neither condemns nor drops the new instance.
func TestFetcherOfADeletedInstanceFetchesNothingForItsSuccessor(t *testing.T) {
	env := newFetcherFenceEnv(t)
	env.refetch(t)
	replaced := `"v2"`
	env.origin.etag.Store(&replaced)
	before := env.origin.requests.Load()

	err := env.bf.Fill(context.Background(), 0, 1)
	require.ErrorIs(t, err, errInstanceDeleted)
	assert.Equal(t, before, env.origin.requests.Load(), "a fill for a deleted instance must not fetch")
	env.requireSuccessorUntouched(t)
	assert.Zero(t, env.pc.storage.fences.size(), "the fill must leave the fence")
}
