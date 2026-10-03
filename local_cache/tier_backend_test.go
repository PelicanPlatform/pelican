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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// These tests need neither minio nor symlinks, so unlike the rest of the
// tiering suite they also run on Windows.

// TestTierNotFoundClassification pins the error shapes that must read as "the
// object is absent".  gocloud.dev classifies S3 errors by API error code
// alone, so a bare 404 surfaced as an HTTP response error -- which several
// S3-compatible services produce -- comes back from it as Unknown.  Treating
// that as a hard failure would make deletes non-idempotent and leave the
// consistency sweep unable to reconcile the entry it was checking, so
// isTierNotFound has to recognise it even after gocloud has wrapped it.
func TestTierNotFoundClassification(t *testing.T) {
	bare404 := &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusNotFound}},
		Err:      errors.New("unparsable error body"),
	}}
	bare500 := &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}},
		Err:      errors.New("server error"),
	}}
	// gocloud wraps driver errors in its own type, which unwraps; %w stands
	// in for that wrapping.
	wrap := func(err error) error { return fmt.Errorf("blob (key %q): %w", "42/56/x", err) }

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"typed NoSuchKey", wrap(&s3types.NoSuchKey{}), true},
		{"typed NotFound", wrap(&s3types.NotFound{}), true},
		{"bare 404 response", wrap(bare404), true},
		{"generic API error coded 404", wrap(&smithy.GenericAPIError{Code: "404"}), true},
		{"generic API error coded NotFound", wrap(&smithy.GenericAPIError{Code: "NotFound"}), true},
		{"server error is not absence", wrap(bare500), false},
		{"access denied is not absence", wrap(&smithy.GenericAPIError{Code: "AccessDenied"}), false},
		{"unrelated error", errors.New("connection reset"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isTierNotFound(tt.err))
		})
	}
}

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
	_, err = env.target.redirectURL(ctx, hash, time.Minute)
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
