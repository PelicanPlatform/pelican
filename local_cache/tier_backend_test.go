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
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
)

// These tests need neither minio nor symlinks, so unlike the rest of the
// tiering suite they also run on Windows.

// tierTestEnv bundles the pieces needed to exercise tiering.  It lives here,
// in a file built on every platform, so the backend-agnostic tests can share
// it with the minio-backed suite.
type tierTestEnv struct {
	db       *CacheDB
	storage  *StorageManager
	eviction *EvictionManager
	uploader *tierUploader
	target   *tierTarget
	tierID   StorageID
	diskID   StorageID
}

// newMemTierEnv wires a tiering environment against the in-memory blob
// driver instead of minio.  Nothing in the tiering pipeline knows which
// backend it is talking to, so this exercises the whole path with no external
// service -- and, because memblob cannot sign URLs, it is also the case where
// the cache must fall back to proxying.
func newMemTierEnv(t *testing.T, ctx context.Context) *tierTestEnv {
	t.Helper()
	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(func() { storage.Close() })

	targetCfg := TierTargetConfig{ProviderURL: "mem://", Prefix: "cache", MaxSize: 1 << 30}
	registered, err := storage.RegisterTierTargets(ctx, []TierTargetConfig{targetCfg})
	require.NoError(t, err)
	require.Len(t, registered, 1)

	env := &tierTestEnv{db: db, storage: storage}
	for id := range registered {
		env.tierID = id
	}
	env.target = storage.getTierTarget(env.tierID)
	require.NotNil(t, env.target)
	for id := range storage.GetDirs() {
		env.diskID = id
	}
	env.eviction = NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: map[StorageID]EvictionDirConfig{
			env.diskID: {MaxSize: 1 << 30},
			env.tierID: {MaxSize: targetCfg.MaxSize, NoPlacement: true},
		},
	})
	env.uploader = newTierUploader(db, storage, env.eviction, 1024)
	return env
}

// TestTierOnNonRedirectingBackend is the payoff of keeping the tiering
// pipeline backend-agnostic: the same uploader, metadata relocation and
// listing run against a completely different driver, with no S3 and no
// external service at all.
//
// It also covers the capability half of the design.  memblob cannot sign
// URLs, so the target reports that it cannot redirect and the cache has to
// serve the bytes itself -- which is what any backend without a URL-signing
// mechanism will do.
func TestTierOnNonRedirectingBackend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnv(t, ctx)

	assert.False(t, env.target.canRedirect,
		"an in-memory backend cannot sign URLs, so the cache must proxy")
	assert.True(t, env.target.redirectSendsCredentials("cache.example.org"),
		"a target that cannot redirect must never be judged safe to redirect to")

	data := make([]byte, 2*BlockDataSize+321)
	for i := range data {
		data[i] = byte(i % 251)
	}
	hash := InstanceHash(fmt.Sprintf("%064d", 21))
	nsID := NamespaceID(1)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)
	fileSize := CalculateFileSize(int64(len(data)))

	require.NoError(t, env.uploader.processObject(ctx, hash))

	// Metadata moved to the tier target and the local copy was released.
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, env.tierID, meta.StorageID)
	_, statErr := os.Stat(env.storage.getObjectPathForDir(env.diskID, hash))
	assert.True(t, os.IsNotExist(statErr), "the local copy should be released")
	diskUsage, err := env.db.GetUsage(env.diskID, nsID)
	require.NoError(t, err)
	assert.Zero(t, diskUsage)
	tierUsage, err := env.db.GetUsage(env.tierID, nsID)
	require.NoError(t, err)
	assert.Equal(t, fileSize, tierUsage)

	// The bytes read back through the backend-agnostic stream, whole and
	// ranged -- this is what the proxy serving path uses.
	stream := newTierObjectStream(ctx, env.target, hash, int64(len(data)))
	defer stream.Close()
	fetched, err := io.ReadAll(stream)
	require.NoError(t, err)
	assert.Equal(t, data, fetched)

	ranged := newTierObjectStream(ctx, env.target, hash, int64(len(data)))
	defer ranged.Close()
	_, err = ranged.Seek(int64(BlockDataSize), io.SeekStart)
	require.NoError(t, err)
	buf := make([]byte, 64)
	_, err = io.ReadFull(ranged, buf)
	require.NoError(t, err)
	assert.Equal(t, data[BlockDataSize:BlockDataSize+64], buf)

	// Asking for a redirect URL fails loudly rather than returning a URL the
	// client could not use.
	_, err = env.target.redirectURL(ctx, hash, time.Minute, nil)
	assert.Error(t, err, "a backend that cannot sign must not return a URL")

	// The listing the consistency sweep relies on sees exactly the object
	// -- not the identity object, and with the prefix stripped.
	seen := map[InstanceHash]int64{}
	require.NoError(t, env.target.listObjects(ctx, func(h InstanceHash, size int64, _ time.Time) error {
		seen[h] = size
		return nil
	}))
	assert.Equal(t, map[InstanceHash]int64{hash: int64(len(data))}, seen)

	// Deletion reaches the backend, and deleting again is not an error.
	require.NoError(t, env.target.deleteObject(ctx, hash))
	exists, err := env.target.objectExists(ctx, hash)
	require.NoError(t, err)
	assert.False(t, exists)
	assert.NoError(t, env.target.deleteObject(ctx, hash), "deletes must be idempotent")
}

// TestTierIntentsArePaged: a long outage can leave an intent behind for every
// object whose upload failed, so intents are walked a page at a time rather
// than loaded at once.  Every intent must be visited exactly once, across
// page boundaries and while the callback deletes the ones it visits.
func TestTierIntentsArePaged(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnv(t, ctx)

	const n = 2*tierIntentPage + 7
	for i := 0; i < n; i++ {
		require.NoError(t, env.db.SetTierUploadIntent(InstanceHash(fmt.Sprintf("%064d", i)),
			&TierUploadIntent{TargetStorageID: env.tierID, Size: 1}))
	}

	seen := make(map[InstanceHash]int, n)
	var previous InstanceHash
	require.NoError(t, env.uploader.forEachIntent(ctx, func(h InstanceHash, _ *TierUploadIntent) error {
		seen[h]++
		assert.Greater(t, h, previous, "intents are visited in hash order")
		previous = h
		return env.db.DeleteTierUploadIntent(h)
	}))
	assert.Len(t, seen, n)
	for h, count := range seen {
		assert.Equal(t, 1, count, "intent %s visited more than once", h)
	}
	rest, err := env.db.ListTierUploadIntents("", tierIntentPage)
	require.NoError(t, err)
	assert.Empty(t, rest)
}

// blockingDeleteBackend stalls every Delete until released, standing in for a
// tiering target that has stopped answering.
type blockingDeleteBackend struct {
	TierBackend
	entered chan struct{}
	release chan struct{}
}

func (b blockingDeleteBackend) Delete(ctx context.Context, key string) error {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.TierBackend.Delete(ctx, key)
}

// TestTierStartDoesNotWaitForRecovery: recovery makes a remote call per
// leftover intent, so with a target that has stopped answering, a cache that
// recovered on its startup path would never come up.  Start must return while
// recovery is still blocked, and the uploads must start only after it ends.
func TestTierStartDoesNotWaitForRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnv(t, ctx)

	// An upload that never committed: recovery deletes its remote copy,
	// refunds the charge and re-queues the object.
	hash := InstanceHash(fmt.Sprintf("%064d", 77))
	data := make([]byte, 4*BlockDataSize)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, NamespaceID(1))
	require.NoError(t, env.db.SetTierUploadIntent(hash, &TierUploadIntent{
		TargetStorageID: env.tierID, Size: int64(len(data)), NamespaceID: 1,
	}))

	blocking := blockingDeleteBackend{
		TierBackend: env.target.backend,
		entered:     make(chan struct{}, 1),
		release:     make(chan struct{}),
	}
	env.target.backend = blocking

	egrp, egrpCtx := errgroup.WithContext(ctx)
	require.NoError(t, env.uploader.Start(egrpCtx, egrp), "Start returns while recovery is still running")
	defer func() {
		cancel()
		_ = egrp.Wait()
	}()

	<-blocking.entered // recovery is stuck on the target
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Equal(t, env.diskID, meta.StorageID, "nothing is uploaded while recovery is unsettled")

	close(blocking.release)
	require.Eventually(t, func() bool {
		meta, err := env.storage.GetMetadata(hash)
		return err == nil && meta != nil && meta.StorageID == env.tierID
	}, 10*time.Second, 20*time.Millisecond, "once recovery ends, the re-queued object is tiered")
}

// failingPutBackend fails uploads -- of every key, or, with objectsOnly, of
// cache objects but not the liveness probe's -- standing in for a target that
// is down and for one that works but rejects particular objects.
type failingPutBackend struct {
	TierBackend
	objectsOnly bool
}

func (b failingPutBackend) Put(ctx context.Context, key, contentType string, size int64, body io.Reader) (TierObjectInfo, error) {
	if b.objectsOnly && key == tierProbeKey {
		return b.TierBackend.Put(ctx, key, contentType, size, body)
	}
	return TierObjectInfo{}, errors.New("injected upload failure")
}

// TestTierLivenessProbe: a target that stops accepting writes is taken out
// of rotation and reported through the health framework -- a warning at
// first, degraded once it keeps failing -- and put back when it recovers.
func TestTierLivenessProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnv(t, ctx)
	working := env.target.backend
	label := env.target.metricLabel()

	require.NoError(t, env.target.probe(ctx))
	env.uploader.publishHealth()
	assert.True(t, env.target.healthy.Load())
	assert.Equal(t, 1.0, testutil.ToFloat64(tierTargetUp.WithLabelValues(label)))
	status, err := metrics.GetComponentStatus(metrics.Cache_TieringStorage)
	require.NoError(t, err)
	assert.Equal(t, metrics.StatusOK.String(), status)

	env.target.backend = failingPutBackend{TierBackend: working}
	require.Error(t, env.target.probe(ctx))
	env.uploader.publishHealth()
	assert.False(t, env.target.healthy.Load())
	assert.Nil(t, env.uploader.chooseTarget(1), "a failing target is not chosen for uploads")
	assert.Equal(t, 0.0, testutil.ToFloat64(tierTargetUp.WithLabelValues(label)))
	status, err = metrics.GetComponentStatus(metrics.Cache_TieringStorage)
	require.NoError(t, err)
	assert.Equal(t, metrics.StatusWarning.String(), status, "one failure may be a blip")

	for i := 1; i < tierProbeDegradedAfter; i++ {
		require.Error(t, env.target.probe(ctx))
	}
	env.uploader.publishHealth()
	status, err = metrics.GetComponentStatus(metrics.Cache_TieringStorage)
	require.NoError(t, err)
	assert.Equal(t, metrics.StatusDegraded.String(), status)

	env.target.backend = working
	require.NoError(t, env.target.probe(ctx))
	env.uploader.publishHealth()
	assert.True(t, env.target.healthy.Load())
	assert.NotNil(t, env.uploader.chooseTarget(1))
	status, err = metrics.GetComponentStatus(metrics.Cache_TieringStorage)
	require.NoError(t, err)
	assert.Equal(t, metrics.StatusOK.String(), status)
}

// TestTierGivesUpOnAnObject: an object that keeps failing to upload while its
// target is otherwise fine is retried a bounded number of times and then left
// on local storage, instead of costing a full upload attempt on every rescan
// forever.  Failures while the target itself is down are not held against it.
func TestTierGivesUpOnAnObject(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newMemTierEnv(t, ctx)
	working := env.target.backend

	hash := InstanceHash(fmt.Sprintf("%064d", 91))
	data := make([]byte, 4*BlockDataSize)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, NamespaceID(1))

	// Target down: the probe fails, so nothing is counted.
	env.target.backend = failingPutBackend{TierBackend: working}
	require.Error(t, env.uploader.processObject(ctx, hash))
	assert.False(t, env.uploader.givenUp(hash))
	assert.Equal(t, 0, env.uploader.failures[hash])
	require.NoError(t, env.uploader.processObject(ctx, hash), "with no healthy target, uploads wait")

	// Target up but refusing this object: every failure counts.
	env.target.backend = failingPutBackend{TierBackend: working, objectsOnly: true}
	require.NoError(t, env.target.probe(ctx))
	abandoned := testutil.ToFloat64(tierUploadsAbandonedTotal)
	for i := 0; i < tierMaxUploadAttempts; i++ {
		require.Error(t, env.uploader.processObject(ctx, hash))
	}
	assert.True(t, env.uploader.givenUp(hash))
	assert.Equal(t, abandoned+1, testutil.ToFloat64(tierUploadsAbandonedTotal))

	// Given up: no further attempts, even once the target would accept it,
	// and the rescan no longer queues it.
	env.target.backend = working
	require.NoError(t, env.uploader.processObject(ctx, hash))
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Equal(t, env.diskID, meta.StorageID, "the object stays on local storage")
	queued, _ := env.uploader.backfillScan(ctx)
	assert.Zero(t, queued)
}
