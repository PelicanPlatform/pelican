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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeInlineVersion stores one version of a named object inline, as a
// completed fetch of a small object would, and records it as the latest.
func (env *posixTierEnv) storeInlineVersion(t *testing.T, ctx context.Context, sourceURL, etag string, data []byte) InstanceHash {
	t.Helper()
	hash := env.db.InstanceHash(etag, env.db.ObjectHash(sourceURL))
	meta := &CacheMetadata{SourceURL: sourceURL, ETag: etag, NamespaceID: NamespaceID(1)}
	require.NoError(t, env.storage.StoreInline(ctx, hash, meta, data))
	require.NoError(t, env.db.SetLatestETag(env.db.ObjectHash(sourceURL), etag, time.Now()))
	return hash
}

// TestTierAllObjects: a shared-filesystem target with AllObjects takes every
// object it may hold -- below the threshold, inline, even empty -- and the
// cache then keeps no local copy of it.  Without the flag, such objects stay
// local; with it, private objects still do.
func TestTierAllObjects(t *testing.T) {
	small := bytes.Repeat([]byte("s"), 512) // below the uploader's 1024-byte threshold
	tiny := []byte("tiny object, kept inline")

	t.Run("WithoutTheFlagSmallObjectsStayLocal", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		env := newPosixTierEnv(t, ctx, TierTargetConfig{})
		env.public["/public"] = true
		var enqueued []InstanceHash
		env.storage.onObjectComplete = func(h InstanceHash) { enqueued = append(enqueued, h) }

		onDisk := env.storeVersion(t, ctx, "pelican://fed/public/small.bin", "e", small, time.Now())
		inline := env.storeInlineVersion(t, ctx, "pelican://fed/public/tiny.txt", "e", tiny)
		assert.NotContains(t, enqueued, inline, "no target takes inline objects, so the uploader is not told of them")
		for _, hash := range []InstanceHash{onDisk, inline} {
			require.NoError(t, env.uploader.processObject(ctx, hash))
			meta, err := env.storage.GetMetadata(hash)
			require.NoError(t, err)
			assert.NotEqual(t, env.tierID, meta.StorageID)
		}
	})

	t.Run("WithTheFlagEverythingMayGo", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		env := newPosixTierEnv(t, ctx, TierTargetConfig{AllObjects: true})
		env.public["/public"] = true
		var enqueued []InstanceHash
		env.storage.onObjectComplete = func(h InstanceHash) { enqueued = append(enqueued, h) }

		onDisk := env.storeVersion(t, ctx, "pelican://fed/public/small.bin", "e", small, time.Now())
		inline := env.storeInlineVersion(t, ctx, "pelican://fed/public/tiny.txt", "e", tiny)
		empty := env.storeInlineVersion(t, ctx, "pelican://fed/public/empty", "e", nil)
		private := env.storeInlineVersion(t, ctx, "pelican://fed/private/tiny.txt", "e", tiny)
		assert.Contains(t, enqueued, inline, "a completed inline object is offered to the uploader")

		inlineUsage, err := env.db.GetUsage(StorageIDInline, NamespaceID(1))
		require.NoError(t, err)
		for name, tc := range map[string]struct {
			hash InstanceHash
			data []byte
		}{
			"names/public/small.bin": {onDisk, small},
			"names/public/tiny.txt":  {inline, tiny},
			"names/public/empty":     {empty, nil},
		} {
			require.NoError(t, env.uploader.processObject(ctx, tc.hash), name)
			meta, err := env.storage.GetMetadata(tc.hash)
			require.NoError(t, err)
			require.Equal(t, env.tierID, meta.StorageID, "%s is tiered", name)
			got, err := env.readName(t, name)
			require.NoError(t, err, name)
			assert.Equal(t, len(tc.data), len(got), name)
			assert.Equal(t, string(tc.data), string(got), name)
		}

		// The inline objects' local copies -- their inline data -- are gone,
		// and their charge against inline storage is returned.
		for _, hash := range []InstanceHash{inline, empty} {
			data, err := env.db.GetInlineData(hash)
			require.NoError(t, err)
			assert.Nil(t, data, "the inline copy of a tiered object is released")
		}
		after, err := env.db.GetUsage(StorageIDInline, NamespaceID(1))
		require.NoError(t, err)
		assert.Equal(t, inlineUsage-int64(len(tiny)), after)

		// Size is no reason to expose a private object.
		require.NoError(t, env.uploader.processObject(ctx, private))
		meta, err := env.storage.GetMetadata(private)
		require.NoError(t, err)
		assert.Equal(t, StorageIDInline, meta.StorageID, "a private object stays in the cache")
	})

	t.Run("OnlyOnASharedFilesystem", func(t *testing.T) {
		cfg := TierTargetConfig{ProviderURL: "s3://bucket", MaxSize: 1, AllObjects: true}
		assert.ErrorContains(t, cfg.validate(), "AllObjects")
	})
}

// TestDeleteRelocatedInlineDataSparesANewCopy: releasing the inline copy a
// tiered object left behind must not remove the inline data of a copy of the
// same version fetched again after the tiered one was deleted.
func TestDeleteRelocatedInlineDataSparesANewCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{AllObjects: true})
	env.public["/public"] = true

	hash := env.storeInlineVersion(t, ctx, "pelican://fed/public/again.txt", "e", []byte("fetched again"))
	require.NoError(t, env.db.DeleteRelocatedInlineData(hash))
	data, err := env.db.GetInlineData(hash)
	require.NoError(t, err)
	assert.NotNil(t, data, "the inline data of a live inline object is not the tiered copy's")
}
