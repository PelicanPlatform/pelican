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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// stallingTierBackend wraps a tiering target's backend for tests.  While
// stall is set, a read of a body it opened blocks until the read's context
// ends, signalling held, or until the test releases the stall, when the
// read goes on; while changed is set, every open reports that the target no
// longer holds the copy that was uploaded.  While holdPuts is set, an upload
// blocks until its context ends; closedDuringPut records the backend being
// closed while one was blocked.
type stallingTierBackend struct {
	TierBackend
	stall           atomic.Bool
	changed         atomic.Bool
	holdPuts        atomic.Bool
	putsHeld        atomic.Int32
	closedDuringPut atomic.Bool
	// stalled counts the reads blocked now.
	stalled  atomic.Int32
	held     chan struct{}
	released chan struct{}
	release  func()
}

func newStallingTierBackend(inner TierBackend) *stallingTierBackend {
	b := &stallingTierBackend{TierBackend: inner, held: make(chan struct{}, 16), released: make(chan struct{})}
	b.release = sync.OnceFunc(func() {
		b.stall.Store(false)
		close(b.released)
	})
	return b
}

func (b *stallingTierBackend) OpenRange(ctx context.Context, key string, offset int64, expect *TierObjectInfo) (io.ReadCloser, error) {
	if b.changed.Load() {
		return nil, errors.Wrapf(ErrTierObjectChanged, "%s (test)", key)
	}
	body, err := b.TierBackend.OpenRange(ctx, key, offset, expect)
	if err != nil {
		return nil, err
	}
	return &stallingTierBody{ReadCloser: body, ctx: ctx, b: b}, nil
}

func (b *stallingTierBackend) Put(ctx context.Context, key, contentType string, size int64, body io.Reader) (TierObjectInfo, error) {
	if b.holdPuts.Load() && key != tierProbeKey {
		b.putsHeld.Add(1)
		defer b.putsHeld.Add(-1)
		<-ctx.Done()
		return TierObjectInfo{}, ctx.Err()
	}
	return b.TierBackend.Put(ctx, key, contentType, size, body)
}

func (b *stallingTierBackend) Close() error {
	if b.putsHeld.Load() > 0 {
		b.closedDuringPut.Store(true)
	}
	return b.TierBackend.Close()
}

type stallingTierBody struct {
	io.ReadCloser
	ctx context.Context
	b   *stallingTierBackend
}

func (r *stallingTierBody) Read(p []byte) (int, error) {
	if r.b.stall.Load() {
		r.b.stalled.Add(1)
		defer r.b.stalled.Add(-1)
		select {
		case r.b.held <- struct{}{}:
		default:
		}
		select {
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		case <-r.b.released:
		}
	}
	return r.ReadCloser.Read(p)
}

// memTierCache is a cache server with one ordinary tiering target, held in
// memory, whose backend the test controls.  The in-memory backend cannot
// sign URLs, so the cache proxies every read of a tiered object.
type memTierCache struct {
	pc      *PersistentCache
	ctx     context.Context
	srv     *httptest.Server
	backend *stallingTierBackend
	tierID  StorageID
	diskID  StorageID
}

func newMemTierCache(t *testing.T) *memTierCache {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(context.Background())
	egrp, _ := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})

	// Stub federation so NewPersistentCache resolves offline.
	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: "https://cache.example:8443",
		DirectorEndpoint:  "https://cache.example:8443",
	})
	setTierTargets(t, []interface{}{
		map[string]interface{}{"ProviderURL": "mem://", "Prefix": "cache", "MaxSize": "1GB"},
	})
	require.NoError(t, param.Cache_TieringThreshold.Set("1KB"))

	var backend *stallingTierBackend
	wrapTierBackendForTest = func(inner TierBackend) TierBackend {
		backend = newStallingTierBackend(inner)
		return backend
	}
	t.Cleanup(func() { wrapTierBackendForTest = nil })

	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	wrapTierBackendForTest = nil
	require.NotNil(t, backend)
	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAd{{
		Path: "/test",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}}))

	env := &memTierCache{pc: pc, ctx: ctx, backend: backend}
	for id := range pc.storage.tierTargets {
		env.tierID = id
	}
	for id := range pc.storage.GetDirs() {
		env.diskID = id
	}
	require.False(t, pc.storage.getTierTarget(env.tierID).canRedirect, "an in-memory target cannot redirect")
	env.srv = httptest.NewServer(http.HandlerFunc(pc.serveObject))
	t.Cleanup(env.srv.Close)
	// Registered last, so it runs first: a read the test left stalled must
	// not hold up the server's or the cache's close.
	t.Cleanup(backend.release)
	return env
}

// putObject caches a fresh copy of the object at path as a fetch would,
// and waits for the uploader -- which a completed object is queued for --
// to tier it.  Each call makes a new instance, under the same hash.
func (e *memTierCache) putObject(t *testing.T, path string, data []byte) (InstanceHash, *CacheMetadata) {
	t.Helper()
	pc := e.pc
	normalized := pc.normalizePath(path)
	objectHash := pc.db.ObjectHash(normalized)
	etag := "etag-" + path
	hash := pc.db.InstanceHash(etag, objectHash)

	_, err := pc.storage.InitDiskStorage(e.ctx, hash, int64(len(data)), e.diskID, pc.getNamespaceID(path))
	require.NoError(t, err)
	// Merged, not rewritten: once the object is complete the uploader may
	// be relocating it.
	require.NoError(t, pc.db.MergeMetadata(hash, &CacheMetadata{
		ETag:          etag,
		SourceURL:     normalized,
		LastValidated: time.Now(),
		CCMaxAge:      3600,
	}))
	require.NoError(t, pc.db.SetLatestETag(objectHash, etag, time.Now()))
	require.NoError(t, pc.storage.WriteBlocks(hash, 0, data))

	var meta *CacheMetadata
	require.Eventually(t, func() bool {
		meta, err = pc.storage.GetMetadata(hash)
		return err == nil && meta != nil && meta.StorageID == e.tierID
	}, 15*time.Second, 10*time.Millisecond, "the object should be tiered")
	return hash, meta
}

// TestTierProxiedReadOfAGoneClientEndsItsRequest checks that a read the
// cache proxies from a tiering target gives up when its client goes, as a
// read from local storage does: a read stalled on the target ends, and the
// object's pin is released, rather than both lasting until the target
// answers.
func TestTierProxiedReadOfAGoneClientEndsItsRequest(t *testing.T) {
	env := newMemTierCache(t)
	const path = "/test/tiered/proxied.bin"
	hash, _ := env.putObject(t, path, tierProxyTestData(4*BlockDataSize))

	env.backend.stall.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.srv.URL+path, nil)
	require.NoError(t, err)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errCh <- err
	}()
	select {
	case <-env.backend.held:
	case <-time.After(20 * time.Second):
		t.Fatal("the proxied read never reached the target")
	}
	require.True(t, env.pc.storage.IsObjectPinned(hash), "a proxied read pins its object")

	cancel()
	<-errCh
	require.Eventually(t, func() bool {
		return env.backend.stalled.Load() == 0 && !env.pc.storage.IsObjectPinned(hash)
	}, 10*time.Second, 10*time.Millisecond, "the read of a client that has gone should end")
}

// TestTierChangedCopyDropsOnlyTheCopyItRead checks that a proxied read that
// finds its tiered copy changed drops the object only if the object's entry
// still describes that copy.  If the object was deleted and the same version
// fetched -- and tiered -- again under the same hash while the read was
// open, the change seen in the old copy says nothing against the new one,
// which must be kept; a read of the new copy that finds it changed drops it.
func TestTierChangedCopyDropsOnlyTheCopyItRead(t *testing.T) {
	env := newMemTierCache(t)
	const path = "/test/tiered/changed.bin"
	data := tierProxyTestData(4 * BlockDataSize)
	hash, first := env.putObject(t, path, data)

	drops := make(chan bool, 1)
	env.pc.afterTierChangeDrop = func(_ InstanceHash, dropped bool) { drops <- dropped }
	readChanged := func() bool {
		t.Helper()
		rc, err := env.pc.Get(env.ctx, path, "")
		require.NoError(t, err)
		defer rc.Close()
		return readChangedAfter(t, env, rc, drops, nil)
	}

	// A read of the first copy is open when the object is deleted and
	// fetched, and tiered, again; then it finds its copy changed.
	rc, err := env.pc.Get(env.ctx, path, "")
	require.NoError(t, err)
	var second *CacheMetadata
	dropped := readChangedAfter(t, env, rc, drops, func() {
		require.NoError(t, env.pc.storage.Delete(hash))
		_, second = env.putObject(t, path, data)
	})
	require.NoError(t, rc.Close())
	require.NotEqual(t, first.DataKey, second.DataKey, "the object must have been made again")
	assert.False(t, dropped, "a change seen in a deleted copy must not drop its successor")
	meta, err := env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "the new copy was dropped")
	assert.Equal(t, second.DataKey, meta.DataKey)

	// A read of the new copy that finds it changed drops it.
	assert.True(t, readChanged(), "a read that finds its own copy changed must drop it")
	meta, err = env.pc.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, meta, "the changed copy should be dropped")
}

// readChangedAfter runs between, if set, then reads rc with the target
// reporting every copy changed, and returns whether the read dropped the
// object.
func readChangedAfter(t *testing.T, env *memTierCache, rc io.Reader, drops <-chan bool, between func()) bool {
	t.Helper()
	if between != nil {
		between()
	}
	env.backend.changed.Store(true)
	defer env.backend.changed.Store(false)
	_, err := io.ReadAll(rc)
	require.Error(t, err, "a changed copy must not be served")
	select {
	case dropped := <-drops:
		return dropped
	case <-time.After(20 * time.Second):
		t.Fatal("the read's verdict on the changed copy never ran")
		return false
	}
}

// tierProxyTestData is n bytes of test data.
func tierProxyTestData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i % 241)
	}
	return data
}

// TestTierCacheCloseStopsUploadsFirst: closing the cache stops the tiering
// uploader, and waits for it, before the tiering targets are closed -- so an
// upload in flight is abandoned rather than failed against a closed backend,
// and is not counted against the object.
func TestTierCacheCloseStopsUploadsFirst(t *testing.T) {
	env := newMemTierCache(t)
	env.backend.holdPuts.Store(true)
	pc := env.pc
	const path = "/test/tiered/closing.bin"
	data := tierProxyTestData(4 * BlockDataSize)
	normalized := pc.normalizePath(path)
	objectHash := pc.db.ObjectHash(normalized)
	hash := pc.db.InstanceHash("etag-closing", objectHash)
	_, err := pc.storage.InitDiskStorage(env.ctx, hash, int64(len(data)), env.diskID, pc.getNamespaceID(path))
	require.NoError(t, err)
	require.NoError(t, pc.db.MergeMetadata(hash, &CacheMetadata{ETag: "etag-closing", SourceURL: normalized}))
	require.NoError(t, pc.db.SetLatestETag(objectHash, "etag-closing", time.Now()))
	require.NoError(t, pc.storage.WriteBlocks(hash, 0, data))
	require.Eventually(t, func() bool { return env.backend.putsHeld.Load() > 0 },
		15*time.Second, 10*time.Millisecond, "the uploader should start tiering the object")

	require.NoError(t, pc.Close())
	assert.False(t, env.backend.closedDuringPut.Load(), "the target was closed under an upload in flight")
	assert.Zero(t, env.backend.putsHeld.Load(), "Close returned with an upload still in flight")
	pc.tierUploader.inflightMu.Lock()
	assert.Zero(t, pc.tierUploader.failures[hash], "an abandoned upload is not a failed attempt")
	pc.tierUploader.inflightMu.Unlock()
	assert.Zero(t, pc.storage.getTierTarget(env.tierID).probeFailures.Load(),
		"an abandoned upload does not probe, and fail, the target")
}
