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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// setTierTargets configures the Cache.TieringTargets parameter through the
// param API (rather than touching viper directly) for tests.
func setTierTargets(t *testing.T, targets []interface{}) {
	t.Helper()
	require.NoError(t, param.Cache_TieringTargets.Set(targets))
}

func TestParseTierTargetsConfig(t *testing.T) {
	t.Run("Unset", func(t *testing.T) {
		server_utils.ResetTestState()
		targets, err := ParseTierTargetsConfig()
		require.NoError(t, err)
		assert.Nil(t, targets)
	})

	t.Run("Valid", func(t *testing.T) {
		server_utils.ResetTestState()
		setTierTargets(t, []interface{}{
			map[string]interface{}{
				"ServiceUrl": "https://s3.example.com",
				"Bucket":     "pelican-cache",
				"Prefix":     "/objects/",
				"MaxSize":    "10GB",
			},
		})
		targets, err := ParseTierTargetsConfig()
		require.NoError(t, err)
		require.Len(t, targets, 1)
		assert.Equal(t, "https://s3.example.com", targets[0].ServiceUrl)
		assert.Equal(t, "pelican-cache", targets[0].Bucket)
		assert.Equal(t, "objects", targets[0].Prefix, "prefix should be slash-trimmed")
		assert.Equal(t, "us-east-1", targets[0].Region, "region should default")
		assert.Equal(t, "path", targets[0].UrlStyle, "url style should default")
		assert.Equal(t, uint64(10*1024*1024*1024), targets[0].MaxSize)
		assert.Equal(t, "s3://s3.example.com/pelican-cache/objects", targets[0].DisplayURL())
	})

	t.Run("MissingBucket", func(t *testing.T) {
		server_utils.ResetTestState()
		setTierTargets(t, []interface{}{
			map[string]interface{}{
				"ServiceUrl": "https://s3.example.com",
				"MaxSize":    "10GB",
			},
		})
		_, err := ParseTierTargetsConfig()
		require.ErrorContains(t, err, "Bucket")
	})

	t.Run("MissingMaxSize", func(t *testing.T) {
		server_utils.ResetTestState()
		setTierTargets(t, []interface{}{
			map[string]interface{}{
				"ServiceUrl": "https://s3.example.com",
				"Bucket":     "b",
			},
		})
		_, err := ParseTierTargetsConfig()
		require.ErrorContains(t, err, "MaxSize")
	})

	t.Run("KeyfilesMustBePaired", func(t *testing.T) {
		server_utils.ResetTestState()
		setTierTargets(t, []interface{}{
			map[string]interface{}{
				"ServiceUrl":    "https://s3.example.com",
				"Bucket":        "b",
				"MaxSize":       "1GB",
				"AccessKeyfile": "/etc/access",
			},
		})
		_, err := ParseTierTargetsConfig()
		require.ErrorContains(t, err, "must be set together")
	})
}

func TestTierKeyLayout(t *testing.T) {
	hash := InstanceHash("42561abfe18be8fca1dcd5b6ac0f6b6d42561abfe18be8fca1dcd5b6ac0f6b6d")
	target := &tierTarget{cfg: TierTargetConfig{Bucket: "b", Prefix: "objects"}}

	// Keys are prefix-relative even when a prefix is configured: the backend
	// applies it on write and strips it on list (blob.PrefixedBucket), so
	// nothing above the backend has to account for one.
	key := target.objectKey(hash)
	assert.Equal(t, "42/56/1abfe18be8fca1dcd5b6ac0f6b6d42561abfe18be8fca1dcd5b6ac0f6b6d", key)
	assert.Equal(t, hash, target.hashFromKey(key))

	// The leading bytes of the key are the leading bytes of the hash, which
	// is what makes a key-ordered listing also a hash-ordered one and lets
	// the consistency sweep merge-join it against metadata.
	lower := target.objectKey(InstanceHash("0" + string(hash)[1:]))
	assert.Less(t, lower, key, "key order must follow hash order")

	// Non-object keys are ignored rather than mistaken for objects.
	for _, notAnObject := range []string{
		tierIdentityKey,
		tierRedirectProbeKey,
		"42/56/not-hex-suffix",
		"42/56",
		"4/256/1abfe18be8fca1dcd5b6ac0f6b6d42561abfe18be8fca1dcd5b6ac0f6b6d",
	} {
		assert.Equal(t, InstanceHash(""), target.hashFromKey(notAnObject), "key %q", notAnObject)
	}
}

// setupTierTestEnv starts minio, registers one S3 target alongside one local
// directory, and wires an eviction manager + uploader (no background
// goroutines are started; tests drive the pieces synchronously).
func setupTierTestEnv(t *testing.T, ctx context.Context) *tierTestEnv {
	test_utils.SkipIfNoMinio(t)
	endpoint, accessKey, secretKey := test_utils.StartMinio(t, "pelican-cache-test")

	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()

	keyDir := t.TempDir()
	accessKeyfile := filepath.Join(keyDir, "access")
	secretKeyfile := filepath.Join(keyDir, "secret")
	require.NoError(t, os.WriteFile(accessKeyfile, []byte(accessKey+"\n"), 0600))
	require.NoError(t, os.WriteFile(secretKeyfile, []byte(secretKey+"\n"), 0600))

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(func() { storage.Close() })

	targetCfg := TierTargetConfig{
		ServiceUrl:    endpoint,
		Region:        "us-east-1",
		Bucket:        "pelican-cache-test",
		Prefix:        "cache",
		UrlStyle:      "path",
		AccessKeyfile: accessKeyfile,
		SecretKeyfile: secretKeyfile,
		MaxSize:       1 << 30,
	}
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
	require.NotEqual(t, env.diskID, env.tierID)

	env.eviction = NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: map[StorageID]EvictionDirConfig{
			env.diskID: {MaxSize: 1 << 30},
			env.tierID: {MaxSize: targetCfg.MaxSize, NoPlacement: true},
		},
	})
	env.uploader = newTierUploader(db, storage, env.eviction, 1024)
	return env
}

func TestTierLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	data := make([]byte, 3*BlockDataSize+123) // multi-block, above the 1KB threshold
	for i := range data {
		data[i] = byte(i % 251)
	}
	hash := InstanceHash(fmt.Sprintf("%064d", 1))
	nsID := NamespaceID(1)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)
	fileSize := CalculateFileSize(int64(len(data)))

	// Tier the object to S3.
	require.NoError(t, env.uploader.processObject(ctx, hash))

	// Metadata now points at the S3 target and the intent is gone.
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, env.tierID, meta.StorageID)
	intents, err := env.db.ListTierUploadIntents()
	require.NoError(t, err)
	assert.Empty(t, intents)

	// The local file is gone; usage moved from the directory to the bucket.
	localPath := env.storage.getObjectPathForDir(env.diskID, hash)
	_, statErr := os.Stat(localPath)
	assert.True(t, os.IsNotExist(statErr), "local file should be deleted after tiering")
	diskUsage, err := env.db.GetUsage(env.diskID, nsID)
	require.NoError(t, err)
	assert.Zero(t, diskUsage)
	tierUsage, err := env.db.GetUsage(env.tierID, nsID)
	require.NoError(t, err)
	assert.Equal(t, fileSize, tierUsage)

	// The bucket object is the plaintext content.
	stream, err := env.target.openStream(ctx, hash, 0)
	require.NoError(t, err)
	fetched, err := io.ReadAll(stream)
	stream.Close()
	require.NoError(t, err)
	assert.Equal(t, data, fetched)

	// Ranged reads through the proxy-mode stream work.
	objStream := newTierObjectStream(ctx, env.target, hash, int64(len(data)))
	defer objStream.Close()
	_, err = objStream.Seek(int64(BlockDataSize), io.SeekStart)
	require.NoError(t, err)
	buf := make([]byte, 100)
	_, err = io.ReadFull(objStream, buf)
	require.NoError(t, err)
	assert.Equal(t, data[BlockDataSize:BlockDataSize+100], buf)

	// A pre-signed URL serves the object without credentials.
	presigned, err := env.target.redirectURL(ctx, hash, 5*time.Minute)
	require.NoError(t, err)
	resp, err := http.Get(presigned)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, data, body)

	// A fresh presign stamp protects the object from eviction...
	require.NoError(t, env.db.UpdateLRU(hash, 0)) // create the LRU entry under the S3 storage ID
	env.db.setRedirectHold(time.Hour)
	require.NoError(t, env.db.RecordRedirectIssued(hash))
	evicted, _, _, err := env.storage.EvictByLRU(env.tierID, nsID, 0, 0)
	require.NoError(t, err)
	assert.Empty(t, evicted, "presign hold should block eviction")

	// ...and once the hold lapses, eviction removes DB entry and bucket object.
	env.db.setRedirectHold(time.Nanosecond)
	evicted, _, _, err = env.storage.EvictByLRU(env.tierID, nsID, 0, 0)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	exists, err := env.target.objectExists(ctx, hash)
	require.NoError(t, err)
	assert.False(t, exists, "bucket object should be deleted on eviction")
	meta, err = env.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, meta)
}

// TestTierChunkedObject verifies that a large chunked object — whose
// data is spread across multiple local directories in multiple chunk files —
// migrates to S3 as a single flattened blob, with every local chunk file
// removed and each contributing directory's usage released.  Large objects
// are exactly the ones chunking splits up, so this is the primary tiering
// case once chunking is enabled.
func TestTierChunkedObject(t *testing.T) {
	test_utils.SkipIfNoMinio(t)
	endpoint, accessKey, secretKey := test_utils.StartMinio(t, "pelican-cache-chunked")
	InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir1, dir2, dbDir := t.TempDir(), t.TempDir(), t.TempDir()
	keyDir := t.TempDir()
	accessKeyfile := filepath.Join(keyDir, "access")
	secretKeyfile := filepath.Join(keyDir, "secret")
	require.NoError(t, os.WriteFile(accessKeyfile, []byte(accessKey), 0600))
	require.NoError(t, os.WriteFile(secretKeyfile, []byte(secretKey), 0600))

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(func() { storage.Close() })

	registered, err := storage.RegisterTierTargets(ctx, []TierTargetConfig{{
		ServiceUrl:    endpoint,
		Region:        "us-east-1",
		Bucket:        "pelican-cache-chunked",
		Prefix:        "cache",
		UrlStyle:      "path",
		AccessKeyfile: accessKeyfile,
		SecretKeyfile: secretKeyfile,
		MaxSize:       1 << 30,
	}})
	require.NoError(t, err)
	require.Len(t, registered, 1)
	var tierID StorageID
	for id := range registered {
		tierID = id
	}
	target := storage.getTierTarget(tierID)
	require.NotNil(t, target)

	dirCfgs := map[StorageID]EvictionDirConfig{tierID: {MaxSize: 1 << 30, NoPlacement: true}}
	for id := range storage.GetDirs() {
		dirCfgs[id] = EvictionDirConfig{MaxSize: 1 << 30}
	}
	eviction := NewEvictionManager(db, storage, EvictionConfig{DirConfigs: dirCfgs})
	uploader := newTierUploader(db, storage, eviction, 1024)

	// A two-chunk object; the chunks round-robin across dir1 and dir2.
	chunkSizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	chunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	objectSize := chunkSize*2 - 37 // just under two full chunks
	data := make([]byte, objectSize)
	for i := range data {
		data[i] = byte(i % 251)
	}
	nsID := NamespaceID(7)
	hash := InstanceHash(fmt.Sprintf("%064x", 0xC0FFEE))

	meta, err := storage.InitLazyChunkedStorage(ctx, hash, objectSize, chunkSizeCode)
	require.NoError(t, err)
	chunkCount := CalculateChunkCount(objectSize, chunkSizeCode)
	require.GreaterOrEqual(t, chunkCount, 2, "test needs a multi-chunk object")
	for i := 0; i < chunkCount; i++ {
		meta, err = storage.AllocateChunk(ctx, hash, meta, i)
		require.NoError(t, err)
	}
	require.NoError(t, storage.WriteBlocks(hash, 0, data))
	meta.Completed = time.Now().Add(-10 * time.Minute)
	meta.NamespaceID = nsID
	require.NoError(t, storage.SetMetadata(hash, meta))
	require.True(t, meta.IsChunked())

	// Record chunk file paths so we can confirm every one is removed.
	var chunkPaths []string
	for i := 0; i < chunkCount; i++ {
		sid := meta.GetChunkStorageID(i)
		chunkPaths = append(chunkPaths, storage.getChunkPath(sid, hash, i))
	}

	// Tier the chunked object.
	require.NoError(t, uploader.processObject(ctx, hash))

	// Metadata is now a single flattened S3 object.
	got, err := storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, tierID, got.StorageID)
	assert.False(t, got.IsChunked(), "relocation must flatten the chunk layout")
	assert.Equal(t, objectSize, got.ContentLength)

	// Every local chunk file is gone and each directory's usage is released.
	for _, p := range chunkPaths {
		_, statErr := os.Stat(p)
		assert.Truef(t, os.IsNotExist(statErr), "chunk file should be deleted: %s", p)
	}
	for id := range storage.GetDirs() {
		usage, err := db.GetUsage(id, nsID)
		require.NoError(t, err)
		assert.Zerof(t, usage, "disk usage should be released for storage %d", id)
	}
	tierUsage, err := db.GetUsage(tierID, nsID)
	require.NoError(t, err)
	assert.Equal(t, CalculateFileSize(objectSize), tierUsage)

	// The bucket holds the full contiguous plaintext object.
	stream, err := target.openStream(ctx, hash, 0)
	require.NoError(t, err)
	fetched, err := io.ReadAll(stream)
	stream.Close()
	require.NoError(t, err)
	assert.Equal(t, data, fetched)

	// No upload intent left behind.
	intents, err := db.ListTierUploadIntents()
	require.NoError(t, err)
	assert.Empty(t, intents)
}

func TestTierSkipsSmallAndInlineObjects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	t.Run("BelowThreshold", func(t *testing.T) {
		data := []byte("small object below the threshold")
		hash := InstanceHash(fmt.Sprintf("%064d", 2))
		storeTestObject(t, ctx, env.storage, hash, data, env.diskID, 1)

		require.NoError(t, env.uploader.processObject(ctx, hash))

		meta, err := env.storage.GetMetadata(hash)
		require.NoError(t, err)
		require.NotNil(t, meta)
		assert.Equal(t, env.diskID, meta.StorageID, "small object must stay local")
	})

	t.Run("Inline", func(t *testing.T) {
		// An inline object lives in BadgerDB, not on a storage directory, so
		// there is nothing to upload even if it were large enough.  Give it a
		// content length above the threshold to prove the inline check, not
		// the size check, is what excludes it.
		data := []byte("inline object")
		hash := InstanceHash(fmt.Sprintf("%064d", 3))
		meta := &CacheMetadata{
			ETag:          "inline-etag",
			ContentLength: int64(len(data)),
			NamespaceID:   1,
			Completed:     time.Now().Add(-10 * time.Minute),
			LastValidated: time.Now(),
		}
		require.NoError(t, env.storage.StoreInline(ctx, hash, meta, data))

		stored, err := env.storage.GetMetadata(hash)
		require.NoError(t, err)
		require.NotNil(t, stored)
		require.True(t, stored.IsInline(), "object should be stored inline")
		assert.False(t, env.uploader.eligible(stored), "an inline object is never a tiering candidate")

		require.NoError(t, env.uploader.processObject(ctx, hash))
		stored, err = env.storage.GetMetadata(hash)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Equal(t, StorageIDInline, stored.StorageID, "inline object must stay inline")
	})
}

// TestTierRelocationMovesLRUEntry pins the LRU bookkeeping that relocation
// depends on: the index entry has to move from the local storage ID to the
// bucket's, keeping its access timestamp, or the object becomes invisible to
// eviction on its new target (and leaves a phantom entry behind on the old
// one).  The rest of the suite stores objects without ever recording an
// access, which leaves LastAccessTime zero and skips this path entirely.
func TestTierRelocationMovesLRUEntry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	data := make([]byte, 2*BlockDataSize)
	hash := InstanceHash(fmt.Sprintf("%064d", 11))
	nsID := NamespaceID(3)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)

	// Record an access so the object has an LRU entry to move.
	require.NoError(t, env.db.UpdateLRU(hash, 0))
	before, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.False(t, before.LastAccessTime.IsZero(), "access time should be recorded")
	require.True(t, lruKeyExists(t, env.db, env.diskID, nsID, before.LastAccessTime, hash),
		"the object should start in the local LRU index")

	require.NoError(t, env.uploader.processObject(ctx, hash))

	after, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.Equal(t, env.tierID, after.StorageID)
	assert.Equal(t, before.LastAccessTime.UnixNano(), after.LastAccessTime.UnixNano(),
		"relocation must preserve the access time, not reset the object's LRU position")
	assert.False(t, lruKeyExists(t, env.db, env.diskID, nsID, before.LastAccessTime, hash),
		"the local LRU entry must be gone")
	assert.True(t, lruKeyExists(t, env.db, env.tierID, nsID, before.LastAccessTime, hash),
		"the object must appear in the S3 target's LRU index")
}

// TestTierDefersReleaseWhileReaderOpen covers the window between an
// object completing and a client finishing with it: tiering must not delete
// the local copy a reader is working from.  A chunked object is used because
// its reads reopen chunk files by path, so an early unlink breaks the transfer
// outright rather than surviving on an already-open descriptor.
func TestTierDefersReleaseWhileReaderOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	data := make([]byte, 3*BlockDataSize+7)
	for i := range data {
		data[i] = byte(i % 251)
	}
	hash := InstanceHash(fmt.Sprintf("%064d", 12))
	nsID := NamespaceID(4)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)
	localPath := env.storage.getObjectPathForDir(env.diskID, hash)

	// A client is part-way through the object.
	reader, err := env.storage.NewObjectReader(hash)
	require.NoError(t, err)
	head := make([]byte, BlockDataSize)
	_, err = io.ReadFull(reader, head)
	require.NoError(t, err)

	require.NoError(t, env.uploader.processObject(ctx, hash))

	// The bucket copy is authoritative, but the local file survives while the
	// reader holds it -- and the reader can still finish.
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.Equal(t, env.tierID, meta.StorageID, "relocation should still commit")
	_, statErr := os.Stat(localPath)
	require.NoError(t, statErr, "local file must survive while a reader holds the object")

	rest, err := io.ReadAll(reader)
	require.NoError(t, err, "the in-flight read must not be broken by tiering")
	assert.Equal(t, data[BlockDataSize:], rest)
	require.NoError(t, reader.Close())

	// The intent is kept so the cleanup can be retried, and the retry pass
	// finishes it once the reader is gone.
	intents, err := env.db.ListTierUploadIntents()
	require.NoError(t, err)
	require.Contains(t, intents, hash, "the deferred cleanup must stay recorded")

	env.uploader.finishDeferredReleases(ctx)

	_, statErr = os.Stat(localPath)
	assert.True(t, os.IsNotExist(statErr), "local file should be removed once unpinned")
	intents, err = env.db.ListTierUploadIntents()
	require.NoError(t, err)
	assert.Empty(t, intents, "the intent should be cleared after cleanup completes")
	diskUsage, err := env.db.GetUsage(env.diskID, nsID)
	require.NoError(t, err)
	assert.Zero(t, diskUsage, "the deferred release must still refund the local capacity")
}

// TestTierUploaderRecoveryAccounting covers the two recovery branches that run
// after a relocation has committed.  Both are pure accounting: getting them
// wrong silently drives a usage counter away from reality, which shows up much
// later as a bucket that will not fill or one that never drains.
func TestTierUploaderRecoveryAccounting(t *testing.T) {
	t.Run("ObjectDeletedAfterRelocation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		env := setupTierTestEnv(t, ctx)

		nsID := NamespaceID(5)
		hash := InstanceHash(fmt.Sprintf("%064d", 13))
		size := int64(4 * BlockDataSize)

		// The state a crash leaves behind when the object was deleted after
		// its relocation committed: the deletion already refunded the bucket
		// charge, so recovery must not refund it a second time.
		require.NoError(t, env.db.SetTierUploadIntent(hash, &TierUploadIntent{
			TargetStorageID:   env.tierID,
			OriginalStorageID: env.diskID,
			Key:               env.target.objectKey(hash),
			Size:              size,
			NamespaceID:       nsID,
			StartedAt:         time.Now().Add(-time.Minute),
			RelocatedAt:       time.Now().Add(-30 * time.Second),
		}))

		require.NoError(t, env.uploader.recover(ctx))

		tierUsage, err := env.db.GetUsage(env.tierID, nsID)
		require.NoError(t, err)
		assert.Zero(t, tierUsage, "recovery must not refund a charge the deletion already returned")
		intents, err := env.db.ListTierUploadIntents()
		require.NoError(t, err)
		assert.Empty(t, intents)
	})

	t.Run("LocalCleanupUnfinished", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		env := setupTierTestEnv(t, ctx)

		data := make([]byte, 2*BlockDataSize)
		hash := InstanceHash(fmt.Sprintf("%064d", 14))
		nsID := NamespaceID(6)
		storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)
		localPath := env.storage.getObjectPathForDir(env.diskID, hash)
		fileSize := CalculateFileSize(int64(len(data)))

		// Relocation committed, local cleanup did not: the object is on the
		// bucket, the local file and its charge are still there.
		require.NoError(t, env.db.AddUsage(env.tierID, nsID, fileSize))
		require.NoError(t, env.db.SetTierUploadIntent(hash, &TierUploadIntent{
			TargetStorageID:   env.tierID,
			OriginalStorageID: env.diskID,
			Key:               env.target.objectKey(hash),
			Size:              int64(len(data)),
			NamespaceID:       nsID,
			StartedAt:         time.Now().Add(-time.Minute),
			RelocatedAt:       time.Now().Add(-30 * time.Second),
		}))
		_, err := env.db.RelocateObject(hash, env.tierID)
		require.NoError(t, err)

		require.NoError(t, env.uploader.recover(ctx))

		_, statErr := os.Stat(localPath)
		assert.True(t, os.IsNotExist(statErr), "the leftover local file should be removed")
		diskUsage, err := env.db.GetUsage(env.diskID, nsID)
		require.NoError(t, err)
		assert.Zero(t, diskUsage, "the local charge must be refunded, not leaked")
		tierUsage, err := env.db.GetUsage(env.tierID, nsID)
		require.NoError(t, err)
		assert.Equal(t, fileSize, tierUsage, "the bucket charge belongs to the object and must remain")
	})
}

// TestTierConcurrentWorkers runs several workers at one object, the way
// repeated completion notifications can.  Exactly one may tier it, and the
// bucket copy must survive: an earlier version of the in-flight guard let the
// losing worker delete the winner's object.
func TestTierConcurrentWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	data := make([]byte, 2*BlockDataSize)
	for i := range data {
		data[i] = byte(i % 251)
	}
	hash := InstanceHash(fmt.Sprintf("%064d", 15))
	nsID := NamespaceID(7)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = env.uploader.processObject(ctx, hash)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		assert.NoError(t, err, "worker %d", i)
	}

	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, env.tierID, meta.StorageID)

	// The object is in the bucket exactly once, with the right bytes, and the
	// bucket is charged for exactly one copy.
	stream, err := env.target.openStream(ctx, hash, 0)
	require.NoError(t, err)
	fetched, err := io.ReadAll(stream)
	stream.Close()
	require.NoError(t, err)
	assert.Equal(t, data, fetched, "the surviving bucket object must hold the real bytes")

	tierUsage, err := env.db.GetUsage(env.tierID, nsID)
	require.NoError(t, err)
	assert.Equal(t, CalculateFileSize(int64(len(data))), tierUsage,
		"only one worker's charge may stick")
	intents, err := env.db.ListTierUploadIntents()
	require.NoError(t, err)
	assert.Empty(t, intents)
}

// TestEvictionDrainsPastHeldNamespace covers the interaction between presign
// holds and the eviction driver.  A namespace whose LRU head is entirely held
// must not stop the storage target from draining: if it did, a bucket over its
// high-water mark would never recover, and tiering would stop as soon as no
// target had room.  Driving checkAndEvict (rather than EvictByLRU directly) is
// the point -- the namespace-selection loop is where the starvation lives.
func TestEvictionDrainsPastHeldNamespace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	data := make([]byte, 2*BlockDataSize)
	fileSize := CalculateFileSize(int64(len(data)))

	// Two namespaces on the bucket.  The greedier one is entirely protected by
	// presign holds; the other is evictable.
	heldNS, freeNS := NamespaceID(21), NamespaceID(22)
	var heldHashes []InstanceHash
	for i := 0; i < 3; i++ {
		h := InstanceHash(fmt.Sprintf("%064d", 30+i))
		storeTestObject(t, ctx, env.storage, h, data, env.diskID, heldNS)
		require.NoError(t, env.uploader.processObject(ctx, h))
		require.NoError(t, env.db.UpdateLRU(h, 0))
		heldHashes = append(heldHashes, h)
	}
	freeHash := InstanceHash(fmt.Sprintf("%064d", 40))
	storeTestObject(t, ctx, env.storage, freeHash, data, env.diskID, freeNS)
	require.NoError(t, env.uploader.processObject(ctx, freeHash))
	require.NoError(t, env.db.UpdateLRU(freeHash, 0))

	env.db.setRedirectHold(time.Hour)
	for _, h := range heldHashes {
		require.NoError(t, env.db.RecordRedirectIssued(h))
	}

	// Rebuild the eviction manager with a limit that forces it to evict: the
	// bucket now holds four objects and may keep one.
	eviction := NewEvictionManager(env.db, env.storage, EvictionConfig{
		DirConfigs: map[StorageID]EvictionDirConfig{
			env.diskID: {MaxSize: 1 << 30},
			env.tierID: {MaxSize: uint64(fileSize) * 4, HighWaterPercentage: 30, LowWaterPercentage: 20, NoPlacement: true},
		},
	})
	eviction.recalculateDirUsage()
	eviction.checkAndEvict()

	// The held namespace is untouched, and the evictable one was drained
	// rather than skipped along with it.
	for _, h := range heldHashes {
		meta, err := env.storage.GetMetadata(h)
		require.NoError(t, err)
		assert.NotNil(t, meta, "an object under a presign hold must survive eviction")
	}
	meta, err := env.storage.GetMetadata(freeHash)
	require.NoError(t, err)
	assert.Nil(t, meta, "eviction must move past the held namespace and drain the evictable one")
}

// TestContainedObjectPath pins the containment rule every object path goes
// through.  Instance hashes are HMAC hex today and so cannot traverse, but the
// path is derived from a client-supplied URL and the check is what makes that
// safe regardless of who supplies the hash later.
func TestContainedObjectPath(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "srv", "cache", "objects")

	t.Run("NormalHashLayout", func(t *testing.T) {
		hash := InstanceHash("42561abfe18be8fca1dcd5b6ac0f6b6d42561abfe18be8fca1dcd5b6ac0f6b6d")
		got := containedObjectPath(root, GetInstanceStoragePath(hash))
		assert.Equal(t, filepath.Join(root, "42", "56", "1abfe18be8fca1dcd5b6ac0f6b6d42561abfe18be8fca1dcd5b6ac0f6b6d"), got)
	})

	t.Run("ShortSyntheticHash", func(t *testing.T) {
		// The DB-level tests use readable hashes; those stay inside the
		// directory and must keep working.
		got := containedObjectPath(root, GetInstanceStoragePath(InstanceHash("abc")))
		assert.Equal(t, filepath.Join(root, "abc"), got)
	})

	t.Run("TraversalIsRefused", func(t *testing.T) {
		for _, relative := range []string{
			"../../../etc/passwd",
			"aa/bb/../../../../etc/passwd",
			filepath.Join("..", "sibling-dir", "object"),
		} {
			assert.Empty(t, containedObjectPath(root, relative),
				"a path escaping the storage directory must be refused: %q", relative)
		}
	})

	t.Run("EmptyDirectoryIsRefused", func(t *testing.T) {
		assert.Empty(t, containedObjectPath("", "aa/bb/cc"))
	})
}

// lruKeyExists reports whether the LRU index holds the exact entry for an
// object on a storage target.
func lruKeyExists(t *testing.T, db *CacheDB, sid StorageID, nsID NamespaceID, ts time.Time, hash InstanceHash) bool {
	t.Helper()
	var found bool
	require.NoError(t, db.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(LRUKey(sid, nsID, ts, hash))
		if err == nil {
			found = true
			return nil
		}
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	}))
	return found
}

func TestTierTargetIdentityStable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	// Re-register against the same database and bucket: the storage ID
	// must be re-associated via the bucket identity object, not reassigned.
	cfg := env.target.cfg
	registered, err := env.storage.RegisterTierTargets(ctx, []TierTargetConfig{cfg})
	require.NoError(t, err)
	require.Len(t, registered, 1)
	for id := range registered {
		assert.Equal(t, env.tierID, id)
	}
}

func TestTierUploaderRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)

	data := make([]byte, 8192)
	hash := InstanceHash(fmt.Sprintf("%064d", 3))
	nsID := NamespaceID(1)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)
	fileSize := CalculateFileSize(int64(len(data)))

	// Simulate a crash mid-upload: usage charged, intent recorded, object
	// bytes (fully) uploaded — but the relocation never committed.
	require.NoError(t, env.db.AddUsage(env.tierID, nsID, fileSize))
	require.NoError(t, env.db.SetTierUploadIntent(hash, &TierUploadIntent{
		TargetStorageID:   env.tierID,
		OriginalStorageID: env.diskID,
		Key:               env.target.objectKey(hash),
		Size:              int64(len(data)),
		NamespaceID:       nsID,
		StartedAt:         time.Now(),
	}))
	require.NoError(t, env.target.uploadObject(ctx, hash, "", int64(len(data)), newZeroReader(len(data))))

	require.NoError(t, env.uploader.recover(ctx))

	// The uncommitted bucket object is removed, the charge refunded, the
	// intent dropped, and the object re-queued for upload.
	exists, err := env.target.objectExists(ctx, hash)
	require.NoError(t, err)
	assert.False(t, exists, "uncommitted upload should be deleted during recovery")
	tierUsage, err := env.db.GetUsage(env.tierID, nsID)
	require.NoError(t, err)
	assert.Zero(t, tierUsage)
	intents, err := env.db.ListTierUploadIntents()
	require.NoError(t, err)
	assert.Empty(t, intents)
	select {
	case queued := <-env.uploader.queue:
		assert.Equal(t, hash, queued)
	default:
		t.Fatal("expected the recovered object to be re-queued for tiering")
	}
}

// TestTierRedirectDropsAuthorizationCrossHost pins the safety property that
// makes the S3 presigned-URL redirect safe by default: a spec-compliant
// HTTP client — specifically the one Pelican itself uses (config.GetClient,
// which sets no CheckRedirect) — does NOT forward the Authorization header
// to the redirect target when that target is a different hostname, as a
// real S3 provider always is.  The cross-host redirect is exactly what the
// cache issues in tryTierRedirect, so this guarantees a client's bearer token
// is never disclosed to the S3 endpoint.
//
// The same-hostname case (different port) shows the converse, and is why the
// cache cannot simply redirect everything: net/http compares hostnames and
// ignores ports, so an endpoint co-located with the cache does receive the
// header.  redirectRetainsAuthorization is what detects that arrangement --
// including the subdomain form, which this loopback-only test cannot stage --
// and tryTierRedirect proxies those targets instead.  See
// TestRedirectRetainsAuthorization.
func TestTierRedirectDropsAuthorizationCrossHost(t *testing.T) {
	// s3Backend stands in for the S3 provider (the redirect target); it
	// records whether the Authorization header survived the hop.
	var sawAuth string
	s3Backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer s3Backend.Close()
	backendURL, err := url.Parse(s3Backend.URL)
	require.NoError(t, err)

	// cache stands in for the cache endpoint; it 307s to the "S3 provider"
	// on a chosen hostname, mirroring http.Redirect in tryTierRedirect.
	var redirectHost string // set per subtest
	cache := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := *backendURL
		target.Host = redirectHost + ":" + backendURL.Port()
		http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
	}))
	defer cache.Close()

	// The Pelican client's redirect policy: config.GetClient sets no
	// CheckRedirect, so this mirrors exactly how a real transfer follows the
	// cache's redirect.  (Use a bare client with the same policy to avoid
	// pulling in TLS/federation setup.)
	client := &http.Client{}

	tests := []struct {
		name         string
		redirectHost string
		wantStripped bool
	}{
		// A real S3 provider is always a different hostname than the cache.
		{"cross-host (real S3)", "localhost", true},
		// Documents the residual same-hostname exposure.
		{"same-host different-port", "127.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sawAuth = ""
			redirectHost = tt.redirectHost
			req, err := http.NewRequest(http.MethodGet, cache.URL, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer super-secret-token")
			resp, err := client.Do(req)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if tt.wantStripped {
				assert.Empty(t, sawAuth,
					"Authorization must be stripped on the cross-host redirect to S3")
			} else {
				assert.Equal(t, "Bearer super-secret-token", sawAuth,
					"a same-hostname redirect preserves Authorization, which is what the guard is for")
			}
		})
	}
}

// TestRedirectRetainsAuthorization pins the guard that decides whether an S3
// target may be served by redirect at all.  It has to match net/http's rule
// (isDomainOrSubdomain), and the subdomain cases are the ones worth pinning:
// an endpoint like s3.cache.example.org beside a cache on cache.example.org
// keeps the client's Authorization header, and getting this wrong hands
// federation tokens to the object store.
func TestRedirectRetainsAuthorization(t *testing.T) {
	tests := []struct {
		name       string
		dest       string
		cache      string
		wantRetain bool
	}{
		{"unrelated host", "https://s3.amazonaws.com", "cache.example.org", false},
		{"same host", "https://cache.example.org", "cache.example.org", true},
		{"same host, different port", "https://cache.example.org:9000", "cache.example.org", true},
		{"endpoint is a subdomain of the cache", "https://s3.cache.example.org", "cache.example.org", true},
		{"virtual-host bucket under a subdomain", "https://bucket.s3.cache.example.org", "cache.example.org", true},
		{"cache is a subdomain of the endpoint", "https://example.org", "cache.example.org", false},
		{"shared suffix but not a subdomain", "https://s3-cache.example.org", "cache.example.org", false},
		{"sibling subdomains", "https://s3.example.org", "cache.example.org", false},
		{"IP literal endpoint", "https://192.0.2.10:9000", "cache.example.org", false},
		{"case and trailing dot folded", "https://S3.CACHE.example.org", "cache.example.org", true},
		{"unknown cache host is treated as unsafe", "https://s3.amazonaws.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantRetain, redirectRetainsAuthorization(tt.dest, tt.cache))
		})
	}
}

// TestTierRedirectServing is a handler-level end-to-end test: it stands up a
// real persistent cache with an S3 target (minio), lets the tiering
// pipeline move a completed object into the bucket, and asserts that a GET
// through serveObject is answered with a 307 to a working pre-signed URL —
// and with the proxied bytes when redirect is disabled.
func TestTierRedirectServing(t *testing.T) {
	test_utils.SkipIfNoMinio(t)
	endpoint, accessKey, secretKey := test_utils.StartMinio(t, "pelican-redirect-test")

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

	keyDir := t.TempDir()
	accessKeyfile := filepath.Join(keyDir, "access")
	secretKeyfile := filepath.Join(keyDir, "secret")
	require.NoError(t, os.WriteFile(accessKeyfile, []byte(accessKey), 0600))
	require.NoError(t, os.WriteFile(secretKeyfile, []byte(secretKey), 0600))

	setTierTargets(t, []interface{}{
		map[string]interface{}{
			"ServiceUrl":    endpoint,
			"Bucket":        "pelican-redirect-test",
			"Prefix":        "cache",
			"MaxSize":       "1GB",
			"AccessKeyfile": accessKeyfile,
			"SecretKeyfile": secretKeyfile,
		},
	})
	require.NoError(t, param.Cache_TieringThreshold.Set("1KB"))

	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	require.NotNil(t, pc.tierUploader, "uploader should be wired when S3 targets are configured")

	var tierID StorageID
	for id := range pc.storage.tierTargets {
		tierID = id
	}

	// Inject a public namespace so the tokenless GET authorizes.
	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAd{{
		Path: "/test",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}}))

	// Store an object; the completion hook enqueues it for tiering and a
	// background worker moves it into the bucket.
	const objectPath = "/test/redirected_object.bin"
	const etag = "redirect-test-etag"
	normalized := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(normalized)
	instanceHash := pc.db.InstanceHash(etag, objectHash)
	var diskID StorageID
	for id := range pc.storage.GetDirs() {
		diskID = id
	}
	data := bytes.Repeat([]byte("s3-redirect-test-data\n"), 700) // ~15 KiB
	storeTestObject(t, ctx, pc.storage, instanceHash, data, diskID, NamespaceID(1))
	require.NoError(t, pc.db.SetLatestETag(objectHash, etag, time.Now()))

	// Nudge the queue directly (storeTestObject bypasses some completion
	// paths) and wait for the relocation to land.
	pc.tierUploader.MaybeEnqueue(instanceHash)
	require.Eventually(t, func() bool {
		meta, err := pc.storage.GetMetadata(instanceHash)
		return err == nil && meta != nil && meta.StorageID == tierID
	}, 15*time.Second, 50*time.Millisecond, "object should be tiered to the S3 target")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pc.serveObject(w, r)
	}))
	t.Cleanup(srv.Close)

	// Default mode: the GET is answered with a 307 to a pre-signed URL.
	noRedirectClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noRedirectClient.Get(srv.URL + objectPath)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	location := resp.Header.Get("Location")
	require.NotEmpty(t, location)
	assert.Contains(t, location, "pelican-redirect-test", "redirect should point at the bucket")
	assert.Contains(t, location, "X-Amz-Signature", "redirect should be pre-signed")

	// The pre-signed URL serves the object bytes without credentials.
	resp, err = http.Get(location)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, data, body)

	// A default http.Client follows the redirect transparently.
	resp, err = http.Get(srv.URL + objectPath)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, data, body)

	// Range requests survive the redirect (the client re-applies Range to
	// the pre-signed URL and S3 honors it).
	req, err := http.NewRequest(http.MethodGet, srv.URL+objectPath, nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=100-199")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	assert.Equal(t, data[100:200], body)

	// With redirect disabled, the same GET proxies the bytes through the
	// cache (S3 stream mode) with a plain 200.
	require.NoError(t, param.Cache_TieringDisableRedirect.Set(true))
	t.Cleanup(func() { _ = param.Cache_TieringDisableRedirect.Set(false) })
	resp, err = noRedirectClient.Get(srv.URL + objectPath)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "proxy-mode GET failed: %s", string(body))
	assert.Equal(t, data, body)

	// Proxy-mode range request is served by the cache itself.
	req, err = http.NewRequest(http.MethodGet, srv.URL+objectPath, nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=4000-4999")
	resp, err = noRedirectClient.Do(req)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	assert.Equal(t, data[4000:5000], body)

	// The credential check runs against the redirect host the target reported
	// at startup, before a URL is minted.  A URL that comes back pointing
	// anywhere else must not be handed out on the strength of a check made
	// about somewhere else; the cache proxies instead.
	t.Run("RedirectToUnprobedHostIsRefused", func(t *testing.T) {
		require.NoError(t, param.Cache_TieringDisableRedirect.Set(false))
		t.Cleanup(func() { _ = param.Cache_TieringDisableRedirect.Set(true) })

		target := pc.storage.getTierTarget(tierID)
		require.NotNil(t, target)
		original := target.backend
		target.backend = fixedURLBackend{TierBackend: original, url: "https://elsewhere.example.net/k"}
		t.Cleanup(func() { target.backend = original })

		resp, err := noRedirectClient.Get(srv.URL + objectPath)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"a URL for an unprobed host must be proxied, not redirected to")
		assert.Empty(t, resp.Header.Get("Location"))
		assert.Equal(t, data, body)
	})

	// A target that hands out a non-HTTP URL is gated on the client saying it
	// can follow one.  Make the target look like one whose storage the client
	// shares -- it reports file:// at startup and mints file:// URLs -- and
	// check both directions.  Everything else about it is unchanged, so a
	// request that is refused the redirect still gets its bytes.
	t.Run("FileRedirectRequiresClientOptIn", func(t *testing.T) {
		require.NoError(t, param.Cache_TieringDisableRedirect.Set(false))
		t.Cleanup(func() { _ = param.Cache_TieringDisableRedirect.Set(true) })

		target := pc.storage.getTierTarget(tierID)
		require.NotNil(t, target)
		original, scheme, host := target.backend, target.redirectScheme, target.redirectHost
		target.backend = fixedURLBackend{TierBackend: original, url: "file:///srv/shared/objects/obj.dat"}
		target.redirectScheme, target.redirectHost = "file", ""
		t.Cleanup(func() {
			target.backend, target.redirectScheme, target.redirectHost = original, scheme, host
		})

		// No advertisement: the file:// URL must not be sent, and the cache
		// serves the object itself.
		plainResp, err := noRedirectClient.Get(srv.URL + objectPath)
		require.NoError(t, err)
		plainBody, err := io.ReadAll(plainResp.Body)
		plainResp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, plainResp.StatusCode,
			"without the advertisement the cache must serve the bytes itself")
		assert.Equal(t, data, plainBody)

		// Advertised: the redirect is issued.  (That a file:// destination
		// raises no Authorization concern is covered by
		// TestRedirectSendsCredentials.)
		optIn, err := http.NewRequest(http.MethodGet, srv.URL+objectPath, nil)
		require.NoError(t, err)
		optIn.Header.Set(server_structs.AcceptRedirectHeader, server_structs.RedirectSchemeFile)
		optInResp, err := noRedirectClient.Do(optIn)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, optInResp.Body)
		optInResp.Body.Close()
		assert.Equal(t, http.StatusTemporaryRedirect, optInResp.StatusCode)
		assert.Equal(t, "file:///srv/shared/objects/obj.dat", optInResp.Header.Get("Location"))
	})

	// The redirect stamped a presign hold: eviction must skip the object.
	evicted, _, _, err := pc.storage.EvictByLRU(tierID, NamespaceID(1), 0, 0)
	require.NoError(t, err)
	assert.Empty(t, evicted, "presign hold should protect the object from eviction")
}

// fixedURLBackend wraps a real backend but hands out a fixed redirect URL,
// so a test can make the target point somewhere other than it reported at
// startup.  Everything else is delegated, so the proxy path still works.
type fixedURLBackend struct {
	TierBackend
	url string
}

func (f fixedURLBackend) RedirectURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return f.url, nil
}

// TestClientAcceptsRedirectScheme covers the advertisement parser, including
// the forms a client might reasonably send.
func TestClientAcceptsRedirectScheme(t *testing.T) {
	tests := []struct {
		name   string
		header string
		scheme string
		want   bool
	}{
		{"exact", "file", "file", true},
		{"list", "file, unix", "unix", true},
		{"padded", "  file  ", "file", true},
		{"case-insensitive", "FILE", "file", true},
		{"absent", "", "file", false},
		{"different scheme", "unix", "file", false},
		{"empty scheme never matches", "file", "", false},
		{"substring must not match", "filesystem", "file", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://cache.example.org/ns/obj", nil)
			if tt.header != "" {
				r.Header.Set(server_structs.AcceptRedirectHeader, tt.header)
			}
			assert.Equal(t, tt.want, clientAcceptsRedirectScheme(r, tt.scheme))
		})
	}
}

// TestRedirectSendsCredentials covers the scheme half of the decision: the
// host comparison only means something for a destination the client will
// make an HTTP request to.
func TestRedirectSendsCredentials(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		host   string
		cache  string
		want   bool
	}{
		{"unrelated https host", "https", "s3.amazonaws.com", "cache.example.org", false},
		{"subdomain of the cache", "https", "s3.cache.example.org", "cache.example.org", true},
		{"plain http subdomain", "http", "s3.cache.example.org", "cache.example.org", true},
		// The client reads a file:// URL locally; no request is made to a
		// host, so there is no header on the wire to forward.
		{"file URL", "file", "", "cache.example.org", false},
		// Nothing was learned at startup: fail closed so the caller proxies.
		{"unknown destination", "", "", "cache.example.org", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &tierTarget{redirectScheme: tt.scheme, redirectHost: tt.host}
			assert.Equal(t, tt.want, target.redirectSendsCredentials(tt.cache))
		})
	}
}

// newZeroReader returns a reader yielding n zero bytes.
func newZeroReader(n int) io.Reader {
	return io.LimitReader(zeroReader{}, int64(n))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestTierConsistencySweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupTierTestEnv(t, ctx)
	nsID := NamespaceID(1)

	checker := NewConsistencyChecker(env.db, env.storage, ConsistencyConfig{
		MinAgeForCleanup: 0, // disable the grace period for the test
	})

	// A valid tiered object that must survive both sweeps.
	keepData := make([]byte, 4096)
	keepHash := InstanceHash(fmt.Sprintf("%064d", 4))
	storeTestObject(t, ctx, env.storage, keepHash, keepData, env.diskID, nsID)
	require.NoError(t, env.uploader.processObject(ctx, keepHash))

	// A stray bucket object with no metadata.
	strayHash := InstanceHash(fmt.Sprintf("%064d", 5))
	require.NoError(t, env.target.uploadObject(ctx, strayHash, "", 128, newZeroReader(128)))

	// An S3-resident DB entry whose bucket object is missing.
	ghostHash := InstanceHash(fmt.Sprintf("%064d", 6))
	require.NoError(t, env.db.SetMetadata(ghostHash, &CacheMetadata{
		ContentLength: 2048,
		SourceURL:     "pelican://example.com/ghost",
		StorageID:     env.tierID,
		NamespaceID:   nsID,
		Completed:     time.Now().Add(-time.Hour),
	}))

	// The regular metadata scan must NOT treat S3-resident entries as
	// orphaned DB entries (they have no local chunk files by design).
	require.NoError(t, checker.RunMetadataScan(ctx, nil))
	meta, err := env.storage.GetMetadata(keepHash)
	require.NoError(t, err)
	require.NotNil(t, meta, "metadata scan must not delete S3-resident entries")
	assert.Equal(t, env.tierID, meta.StorageID)

	// The S3 sweep removes the stray bucket object and the ghost DB entry
	// while leaving the valid object alone.
	require.NoError(t, checker.RunTierScan(ctx))

	exists, err := env.target.objectExists(ctx, strayHash)
	require.NoError(t, err)
	assert.False(t, exists, "stray bucket object should be removed")

	ghostMeta, err := env.storage.GetMetadata(ghostHash)
	require.NoError(t, err)
	assert.Nil(t, ghostMeta, "DB entry without a bucket object should be removed")

	exists, err = env.target.objectExists(ctx, keepHash)
	require.NoError(t, err)
	assert.True(t, exists, "valid tiered object should survive the sweep")
	meta, err = env.storage.GetMetadata(keepHash)
	require.NoError(t, err)
	require.NotNil(t, meta)
}
