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
	"testing"
	"time"

	"github.com/spf13/viper"
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

func TestParseS3TargetsConfig(t *testing.T) {
	t.Run("Unset", func(t *testing.T) {
		viper.Reset()
		targets, err := ParseS3TargetsConfig()
		require.NoError(t, err)
		assert.Nil(t, targets)
	})

	t.Run("Valid", func(t *testing.T) {
		viper.Reset()
		viper.Set("Cache.S3StorageTargets", []interface{}{
			map[string]interface{}{
				"ServiceUrl": "https://s3.example.com",
				"Bucket":     "pelican-cache",
				"Prefix":     "/objects/",
				"MaxSize":    "10GB",
			},
		})
		targets, err := ParseS3TargetsConfig()
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
		viper.Reset()
		viper.Set("Cache.S3StorageTargets", []interface{}{
			map[string]interface{}{
				"ServiceUrl": "https://s3.example.com",
				"MaxSize":    "10GB",
			},
		})
		_, err := ParseS3TargetsConfig()
		require.ErrorContains(t, err, "Bucket")
	})

	t.Run("MissingMaxSize", func(t *testing.T) {
		viper.Reset()
		viper.Set("Cache.S3StorageTargets", []interface{}{
			map[string]interface{}{
				"ServiceUrl": "https://s3.example.com",
				"Bucket":     "b",
			},
		})
		_, err := ParseS3TargetsConfig()
		require.ErrorContains(t, err, "MaxSize")
	})

	t.Run("KeyfilesMustBePaired", func(t *testing.T) {
		viper.Reset()
		viper.Set("Cache.S3StorageTargets", []interface{}{
			map[string]interface{}{
				"ServiceUrl":    "https://s3.example.com",
				"Bucket":        "b",
				"MaxSize":       "1GB",
				"AccessKeyfile": "/etc/access",
			},
		})
		_, err := ParseS3TargetsConfig()
		require.ErrorContains(t, err, "must be set together")
	})
}

func TestS3KeyLayout(t *testing.T) {
	hash := InstanceHash("42561abfe18be8fca1dcd5b6ac0f6b6d42561abfe18be8fca1dcd5b6ac0f6b6d")

	t.Run("WithPrefix", func(t *testing.T) {
		target := &s3Target{cfg: S3TargetConfig{Bucket: "b", Prefix: "objects"}}
		key := target.objectKey(hash)
		assert.Equal(t, "objects/42/56/1abfe18be8fca1dcd5b6ac0f6b6d42561abfe18be8fca1dcd5b6ac0f6b6d", key)
		assert.Equal(t, hash, target.hashFromKey(key))
		assert.Equal(t, InstanceHash(""), target.hashFromKey("other/42/56/rest"))
		assert.Equal(t, InstanceHash(""), target.hashFromKey(target.keyForStoragePath(s3IdentityKey)))
	})

	t.Run("NoPrefix", func(t *testing.T) {
		target := &s3Target{cfg: S3TargetConfig{Bucket: "b"}}
		key := target.objectKey(hash)
		assert.Equal(t, "42/56/1abfe18be8fca1dcd5b6ac0f6b6d42561abfe18be8fca1dcd5b6ac0f6b6d", key)
		assert.Equal(t, hash, target.hashFromKey(key))
		assert.Equal(t, InstanceHash(""), target.hashFromKey(".pelican-cache-id"))
		assert.Equal(t, InstanceHash(""), target.hashFromKey("42/56/not-hex-suffix"))
	})
}

// s3TestEnv bundles the pieces needed to exercise tiering against minio.
type s3TestEnv struct {
	db       *CacheDB
	storage  *StorageManager
	eviction *EvictionManager
	uploader *s3Uploader
	target   *s3Target
	s3ID     StorageID
	diskID   StorageID
}

// setupS3TestEnv starts minio, registers one S3 target alongside one local
// directory, and wires an eviction manager + uploader (no background
// goroutines are started; tests drive the pieces synchronously).
func setupS3TestEnv(t *testing.T, ctx context.Context) *s3TestEnv {
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

	targetCfg := S3TargetConfig{
		ServiceUrl:    endpoint,
		Region:        "us-east-1",
		Bucket:        "pelican-cache-test",
		Prefix:        "cache",
		UrlStyle:      "path",
		AccessKeyfile: accessKeyfile,
		SecretKeyfile: secretKeyfile,
		MaxSize:       1 << 30,
	}
	registered, err := storage.RegisterS3Targets(ctx, []S3TargetConfig{targetCfg})
	require.NoError(t, err)
	require.Len(t, registered, 1)

	env := &s3TestEnv{db: db, storage: storage}
	for id := range registered {
		env.s3ID = id
	}
	env.target = storage.getS3Target(env.s3ID)
	require.NotNil(t, env.target)
	for id := range storage.GetDirs() {
		env.diskID = id
	}
	require.NotEqual(t, env.diskID, env.s3ID)

	env.eviction = NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: map[StorageID]EvictionDirConfig{
			env.diskID: {MaxSize: 1 << 30},
			env.s3ID:   {MaxSize: targetCfg.MaxSize, NoPlacement: true},
		},
	})
	env.uploader = newS3Uploader(db, storage, env.eviction, 1024)
	return env
}

func TestS3TieringLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupS3TestEnv(t, ctx)

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
	assert.Equal(t, env.s3ID, meta.StorageID)
	intents, err := env.db.ListS3UploadIntents()
	require.NoError(t, err)
	assert.Empty(t, intents)

	// The local file is gone; usage moved from the directory to the bucket.
	localPath := env.storage.getObjectPathForDir(env.diskID, hash)
	_, statErr := os.Stat(localPath)
	assert.True(t, os.IsNotExist(statErr), "local file should be deleted after tiering")
	diskUsage, err := env.db.GetUsage(env.diskID, nsID)
	require.NoError(t, err)
	assert.Zero(t, diskUsage)
	s3Usage, err := env.db.GetUsage(env.s3ID, nsID)
	require.NoError(t, err)
	assert.Equal(t, fileSize, s3Usage)

	// The bucket object is the plaintext content.
	stream, err := env.target.openStream(ctx, hash, 0)
	require.NoError(t, err)
	fetched, err := io.ReadAll(stream)
	stream.Close()
	require.NoError(t, err)
	assert.Equal(t, data, fetched)

	// Ranged reads through the proxy-mode stream work.
	objStream := newS3ObjectStream(ctx, env.target, hash, int64(len(data)))
	defer objStream.Close()
	_, err = objStream.Seek(int64(BlockDataSize), io.SeekStart)
	require.NoError(t, err)
	buf := make([]byte, 100)
	_, err = io.ReadFull(objStream, buf)
	require.NoError(t, err)
	assert.Equal(t, data[BlockDataSize:BlockDataSize+100], buf)

	// A pre-signed URL serves the object without credentials.
	presigned, err := env.target.presignGet(ctx, hash, 5*time.Minute)
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
	env.db.SetPresignHold(time.Hour)
	require.NoError(t, env.db.RecordPresignIssued(hash))
	evicted, _, err := env.storage.EvictByLRU(env.s3ID, nsID, 0, 0)
	require.NoError(t, err)
	assert.Empty(t, evicted, "presign hold should block eviction")

	// ...and once the hold lapses, eviction removes DB entry and bucket object.
	env.db.SetPresignHold(time.Nanosecond)
	evicted, _, err = env.storage.EvictByLRU(env.s3ID, nsID, 0, 0)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	exists, err := env.target.objectExists(ctx, hash)
	require.NoError(t, err)
	assert.False(t, exists, "bucket object should be deleted on eviction")
	meta, err = env.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, meta)
}

func TestS3TieringSkipsSmallAndInlineObjects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupS3TestEnv(t, ctx)

	data := []byte("small object below the threshold")
	hash := InstanceHash(fmt.Sprintf("%064d", 2))
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, 1)

	require.NoError(t, env.uploader.processObject(ctx, hash))

	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, env.diskID, meta.StorageID, "small object must stay local")
}

func TestS3TargetIdentityStable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupS3TestEnv(t, ctx)

	// Re-register against the same database and bucket: the storage ID
	// must be re-associated via the bucket identity object, not reassigned.
	cfg := env.target.cfg
	registered, err := env.storage.RegisterS3Targets(ctx, []S3TargetConfig{cfg})
	require.NoError(t, err)
	require.Len(t, registered, 1)
	for id := range registered {
		assert.Equal(t, env.s3ID, id)
	}
}

func TestS3UploaderRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupS3TestEnv(t, ctx)

	data := make([]byte, 8192)
	hash := InstanceHash(fmt.Sprintf("%064d", 3))
	nsID := NamespaceID(1)
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, nsID)
	fileSize := CalculateFileSize(int64(len(data)))

	// Simulate a crash mid-upload: usage charged, intent recorded, object
	// bytes (fully) uploaded — but the relocation never committed.
	require.NoError(t, env.db.AddUsage(env.s3ID, nsID, fileSize))
	require.NoError(t, env.db.SetS3UploadIntent(hash, &S3UploadIntent{
		TargetStorageID:   env.s3ID,
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
	s3Usage, err := env.db.GetUsage(env.s3ID, nsID)
	require.NoError(t, err)
	assert.Zero(t, s3Usage)
	intents, err := env.db.ListS3UploadIntents()
	require.NoError(t, err)
	assert.Empty(t, intents)
	select {
	case queued := <-env.uploader.queue:
		assert.Equal(t, hash, queued)
	default:
		t.Fatal("expected the recovered object to be re-queued for tiering")
	}
}

// TestS3RedirectDropsAuthorizationCrossHost pins the safety property that
// makes the S3 presigned-URL redirect safe by default: a spec-compliant
// HTTP client — specifically the one Pelican itself uses (config.GetClient,
// which sets no CheckRedirect) — does NOT forward the Authorization header
// to the redirect target when that target is a different hostname, as a
// real S3 provider always is.  The cross-host redirect is exactly what the
// cache issues in tryS3Redirect, so this guarantees a client's bearer token
// is never disclosed to the S3 endpoint.
//
// The same-hostname case (different port) is included to document the one
// residual exposure: Go strips by hostname, not port, so an S3 endpoint
// co-located on the cache's own hostname would receive the header.  That is
// the case tryS3Redirect's doc comment warns about and Cache.S3DisableRedirect
// exists to mitigate.
func TestS3RedirectDropsAuthorizationCrossHost(t *testing.T) {
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
	// on a chosen hostname, mirroring http.Redirect in tryS3Redirect.
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
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if tt.wantStripped {
				assert.Empty(t, sawAuth,
					"Authorization must be stripped on the cross-host redirect to S3")
			} else {
				assert.Equal(t, "Bearer super-secret-token", sawAuth,
					"same-hostname redirect preserves Authorization (documents the residual risk)")
			}
		})
	}
}

// TestS3RedirectServing is a handler-level end-to-end test: it stands up a
// real persistent cache with an S3 target (minio), lets the tiering
// pipeline move a completed object into the bucket, and asserts that a GET
// through serveObject is answered with a 307 to a working pre-signed URL —
// and with the proxied bytes when redirect is disabled.
func TestS3RedirectServing(t *testing.T) {
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

	viper.Set("Cache.S3StorageTargets", []interface{}{
		map[string]interface{}{
			"ServiceUrl":    endpoint,
			"Bucket":        "pelican-redirect-test",
			"Prefix":        "cache",
			"MaxSize":       "1GB",
			"AccessKeyfile": accessKeyfile,
			"SecretKeyfile": secretKeyfile,
		},
	})
	require.NoError(t, param.Cache_S3UploadThreshold.Set("1KB"))

	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	require.NotNil(t, pc.s3Uploader, "uploader should be wired when S3 targets are configured")

	var s3ID StorageID
	for id := range pc.storage.s3Targets {
		s3ID = id
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
	pc.s3Uploader.MaybeEnqueue(instanceHash)
	require.Eventually(t, func() bool {
		meta, err := pc.storage.GetMetadata(instanceHash)
		return err == nil && meta != nil && meta.StorageID == s3ID
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
	require.NoError(t, param.Cache_S3DisableRedirect.Set(true))
	t.Cleanup(func() { _ = param.Cache_S3DisableRedirect.Set(false) })
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

	// The redirect stamped a presign hold: eviction must skip the object.
	evicted, _, err := pc.storage.EvictByLRU(s3ID, NamespaceID(1), 0, 0)
	require.NoError(t, err)
	assert.Empty(t, evicted, "presign hold should protect the object from eviction")
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

func TestS3ConsistencySweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := setupS3TestEnv(t, ctx)
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
		StorageID:     env.s3ID,
		NamespaceID:   nsID,
		Completed:     time.Now().Add(-time.Hour),
	}))

	// The regular metadata scan must NOT treat S3-resident entries as
	// orphaned DB entries (they have no local chunk files by design).
	require.NoError(t, checker.RunMetadataScan(ctx, nil))
	meta, err := env.storage.GetMetadata(keepHash)
	require.NoError(t, err)
	require.NotNil(t, meta, "metadata scan must not delete S3-resident entries")
	assert.Equal(t, env.s3ID, meta.StorageID)

	// The S3 sweep removes the stray bucket object and the ghost DB entry
	// while leaving the valid object alone.
	require.NoError(t, checker.RunS3Scan(ctx))

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
