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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestTierWebDAVServing runs the whole tiering lifecycle against the fake
// dCache door: an object is tiered to it over WebDAV, a GET is answered with a
// redirect carrying a macaroon the door accepts, and once the cache no longer
// holds a usable root macaroon the same GET is proxied instead.
func TestTierWebDAVServing(t *testing.T) {
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

	door := newFakeDCache(t)
	tokenFile := filepath.Join(t.TempDir(), "dcache.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(fakeDCacheToken+"\n"), 0600))
	setTierTargets(t, []interface{}{
		map[string]interface{}{
			"WebDavUrl": door.url("/data"),
			"Prefix":    "pelican",
			"TokenFile": tokenFile,
			"MaxSize":   "1GB",
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
	require.NotNil(t, pc.tierUploader)

	var tierID StorageID
	for id := range pc.storage.tierTargets {
		tierID = id
	}
	target := pc.storage.getTierTarget(tierID)
	require.True(t, target.canRedirect, "the door issues macaroons, so the target can redirect")
	assert.Equal(t, 1.0, testutil.ToFloat64(tierRedirectCapable.WithLabelValues(target.metricLabel())))

	// Inject a public namespace so the tokenless GET authorizes.
	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAd{{
		Path: "/test",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}}))

	const objectPath = "/test/dcache_object.bin"
	const etag = "dcache-test-etag"
	objectHash := pc.db.ObjectHash(pc.normalizePath(objectPath))
	instanceHash := pc.db.InstanceHash(etag, objectHash)
	var diskID StorageID
	for id := range pc.storage.GetDirs() {
		diskID = id
	}
	data := bytes.Repeat([]byte("tiered to dCache\n"), 1000)
	storeTestObject(t, ctx, pc.storage, instanceHash, data, diskID, NamespaceID(1))
	require.NoError(t, pc.db.SetLatestETag(objectHash, etag, time.Now()))
	// Carry the origin's ETag, as a fetched object would.  Merge it in rather
	// than rewriting the whole record: storing the object already fired the
	// completion hook, so an upload may be relocating the object right now,
	// and writing back a copy read before that relocation would point the
	// metadata at the local copy the upload has just deleted.
	require.NoError(t, pc.db.MergeMetadata(instanceHash, &CacheMetadata{ETag: etag}))

	pc.tierUploader.MaybeEnqueue(instanceHash)
	require.Eventually(t, func() bool {
		meta, err := pc.storage.GetMetadata(instanceHash)
		return err == nil && meta != nil && meta.StorageID == tierID
	}, 15*time.Second, 50*time.Millisecond, "object should be tiered to the WebDAV target")
	meta, err := pc.storage.GetMetadata(instanceHash)
	require.NoError(t, err)
	require.NotNil(t, meta.Remote)
	assert.NotEmpty(t, meta.Remote.ETag, "the entity tag the door reported is recorded")

	srv := httptest.NewServer(http.HandlerFunc(pc.serveObject))
	t.Cleanup(srv.Close)
	noRedirectClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// The GET is redirected to the door with a macaroon.
	resp, err := noRedirectClient.Get(srv.URL + objectPath)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, door.srv.Listener.Addr().String(), location.Host)
	assert.Equal(t, "/data/pelican/"+GetInstanceStoragePath(instanceHash), location.Path)
	require.NotEmpty(t, location.Query().Get("authz"))

	// A plain client follows it and the door serves the bytes, having
	// verified the macaroon.
	_, readsBefore, _ := door.stats()
	resp, err = http.Get(srv.URL + objectPath)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, data, body)
	_, readsAfter, caveats := door.stats()
	assert.Equal(t, readsBefore+1, readsAfter, "the door authorized the read with the macaroon")
	assert.Contains(t, caveats, "activity:DOWNLOAD")

	// Once the root macaroon is no longer good for a whole redirect -- the
	// door stopped issuing them and the last one ran down -- the cache
	// proxies the object instead, reading it with its own token.
	backend, ok := target.backend.(*webdavTierBackend)
	require.True(t, ok)
	current := backend.macaroons.root.Load()
	require.NotNil(t, current)
	backend.macaroons.root.Store(&rootMacaroon{m: current.m, scope: current.scope, expiry: time.Now().Add(time.Minute)})

	proxied := testutil.ToFloat64(tierRequestsTotal.WithLabelValues(target.metricLabel(), tierServedByProxy))
	resp, err = noRedirectClient.Get(srv.URL + objectPath)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "an expired root macaroon must fall back to proxying: %s", body)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, data, body)
	assert.Equal(t, proxied+1, testutil.ToFloat64(tierRequestsTotal.WithLabelValues(target.metricLabel(), tierServedByProxy)))

	// Proxied ranges are pinned to the recorded entity tag and served too.
	req, err := http.NewRequest(http.MethodGet, srv.URL+objectPath, nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=4000-4999")
	resp, err = noRedirectClient.Do(req)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	assert.Equal(t, data[4000:5000], body)
}
