//go:build linux

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package local_cache_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

// Create five 1MB files.  Trigger a purge, ensuring that the cleanup is
// done according to LRU
func TestPurge(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	tmpDir := t.TempDir()

	server_utils.ResetTestState()
	require.NoError(t, param.Set("LocalCache.Size", "5MB"))
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	size := 0
	for idx := 0; idx < 5; idx++ {
		log.Debugln("Will write origin file", filepath.Join(ft.Exports[0].StoragePrefix, fmt.Sprintf("hello_world.txt.%d", idx)))
		fp, err := os.OpenFile(filepath.Join(ft.Exports[0].StoragePrefix, fmt.Sprintf("hello_world.txt.%d", idx)), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		require.NoError(t, err)
		size = test_utils.WriteBigBuffer(t, fp, 1)
	}
	require.NotEqual(t, 0, size)

	for idx := 0; idx < 5; idx++ {
		tr, err := client.DoGet(ctx, fmt.Sprintf("pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt.%d", idx),
			filepath.Join(tmpDir, fmt.Sprintf("hello_world.txt.%d", idx)), false, client.WithCaches(cacheUrl))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(size), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)
	}

	// Size of the cache should be just small enough that the 5th file triggers LRU deletion of the first.
	// Eviction happens asynchronously, so we need to wait for it to complete.
	socketPath := param.LocalCache_Socket.GetString()

	// Wait for eviction to complete - file 0 should be evicted
	require.Eventually(t, func() bool {
		exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, "/test/hello_world.txt.0")
		return err == nil && !exists
	}, 10*time.Second, 100*time.Millisecond, "Expected file 0 to be evicted due to LRU")

	// Verify files 1-4 still exist
	for idx := 1; idx < 5; idx++ {
		objectPath := fmt.Sprintf("/test/hello_world.txt.%d", idx)
		exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, objectPath)
		require.NoError(t, err)
		assert.True(t, exists, "Expected file %d to exist", idx)
	}
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a config.Reset for good measure. Keeps our env squeaky clean!
		server_utils.ResetTestState()
	})
}

// Create four 1MB files (above low-water mark).  Force a purge, ensuring that the cleanup is
// done according to LRU
func TestForcePurge(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	tmpDir := t.TempDir()

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	require.NoError(t, param.Set("LocalCache.Size", "5MB"))
	// Decrease the low water mark so invoking purge will result in 3 files in the cache.
	require.NoError(t, param.Set("LocalCache.LowWaterMarkPercentage", "80"))
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = time.Duration(time.Minute)
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	tokConf.AddScopes(token_scopes.Localcache_Purge)

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}
	tr := config.GetTransport()
	_, err = utils.MakeRequest(ft.Ctx, tr, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge", "POST", nil, map[string]string{"Authorization": "Bearer abcd"})
	assert.Error(t, err)
	require.Equal(t, fmt.Sprintf("The POST attempt to %s/api/v1.0/localcache/purge resulted in status code 403", param.Server_ExternalWebUrl.GetString()), err.Error())

	// Populate the cache with our test files
	size := 0
	for idx := 0; idx < 4; idx++ {
		log.Debugln("Will write origin file", filepath.Join(ft.Exports[0].StoragePrefix, fmt.Sprintf("hello_world.txt.%d", idx)))
		fp, err := os.OpenFile(filepath.Join(ft.Exports[0].StoragePrefix, fmt.Sprintf("hello_world.txt.%d", idx)), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		require.NoError(t, err)
		size = test_utils.WriteBigBuffer(t, fp, 1)
	}
	require.NotEqual(t, 0, size)

	for idx := 0; idx < 4; idx++ {
		tr, err := client.DoGet(ctx, fmt.Sprintf("pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt.%d", idx),
			filepath.Join(tmpDir, fmt.Sprintf("hello_world.txt.%d", idx)), false, client.WithCaches(cacheUrl))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(size), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)
	}

	// Size of the cache should be large enough that purge hasn't fired yet.
	socketPath := param.LocalCache_Socket.GetString()
	for idx := 0; idx < 4; idx++ {
		objectPath := fmt.Sprintf("/test/hello_world.txt.%d", idx)
		exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, objectPath)
		require.NoError(t, err)
		assert.True(t, exists, "Expected file %d to exist before purge", idx)
	}

	_, err = utils.MakeRequest(ft.Ctx, tr, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge", "POST", nil, map[string]string{"Authorization": "Bearer " + token})
	require.NoError(t, err)

	// Low water mark is small enough that a force purge will delete a file.
	// Wait for eviction to complete - file 0 should be evicted
	require.Eventually(t, func() bool {
		exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, "/test/hello_world.txt.0")
		return err == nil && !exists
	}, 10*time.Second, 100*time.Millisecond, "Expected file 0 to be evicted after purge")

	// Verify files 1-3 still exist
	for idx := 1; idx < 4; idx++ {
		objectPath := fmt.Sprintf("/test/hello_world.txt.%d", idx)
		exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, objectPath)
		require.NoError(t, err)
		assert.True(t, exists, "Expected file %d to exist after purge", idx)
	}
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a config.Reset for good measure. Keeps our env squeaky clean!
		server_utils.ResetTestState()
	})
}

// TestPurgeFirst verifies that PersistentCache correctly prioritizes purging files
// marked as PURGEFIRST during the purge routine.
//
// The test creates 5 test files and downloads them through the cache. File-1 is then
// marked PURGEFIRST via the API. The purge is triggered, and the test verifies that
// file-1 (marked PURGEFIRST) is evicted before the oldest file (file-2) by LRU order.
func TestPurgeFirst(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	tmpDir := t.TempDir()

	// Use a small cache size to trigger eviction
	require.NoError(t, param.Set("LocalCache.Size", "5MB"))
	// Set low water mark so that purge will actually delete files
	require.NoError(t, param.Set("LocalCache.LowWaterMarkPercentage", "50"))
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	// Create 4 x 1MB files on the origin
	size := 0
	for idx := 0; idx < 4; idx++ {
		log.Debugln("Will write origin file", filepath.Join(ft.Exports[0].StoragePrefix, fmt.Sprintf("hello_world.txt.%d", idx)))
		fp, err := os.OpenFile(filepath.Join(ft.Exports[0].StoragePrefix, fmt.Sprintf("hello_world.txt.%d", idx)), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		require.NoError(t, err)
		size = test_utils.WriteBigBuffer(t, fp, 1)
	}
	require.NotEqual(t, 0, size)

	// Download all files through the cache
	for idx := 0; idx < 4; idx++ {
		tr, err := client.DoGet(ctx, fmt.Sprintf("pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt.%d", idx),
			filepath.Join(tmpDir, fmt.Sprintf("hello_world.txt.%d", idx)), false, client.WithCaches(cacheUrl))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(size), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)
	}

	// Verify all files are in cache
	socketPath := param.LocalCache_Socket.GetString()
	for idx := 0; idx < 4; idx++ {
		objectPath := fmt.Sprintf("/test/hello_world.txt.%d", idx)
		exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, objectPath)
		require.NoError(t, err)
		assert.True(t, exists, "Expected file %d to exist before purge-first", idx)
	}

	// Create token with proper scopes
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = time.Minute
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	tokConf.AddScopes(token_scopes.Localcache_Purge)

	tok, err := tokConf.CreateToken()
	require.NoError(t, err)

	// Mark file 2 (not the oldest) as purge-first via API
	tr := config.GetTransport()
	body := map[string]interface{}{"Path": "/test/hello_world.txt.2"}
	_, err = utils.MakeRequest(ctx, tr, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge_first", "POST", body, map[string]string{"Authorization": "Bearer " + tok})
	require.NoError(t, err)

	// Trigger a purge
	_, err = utils.MakeRequest(ctx, tr, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge", "POST", nil, map[string]string{"Authorization": "Bearer " + tok})
	require.NoError(t, err)

	// File 2 should be evicted first (purge-first), not file 0 (oldest by LRU)
	// With 4x1MB files and 50% low water mark (2.5MB), we expect 2 files to be evicted
	// File 2 should definitely be gone (purge-first), and file 0 should be gone (oldest LRU)

	// Wait for eviction to complete - file 2 (purge-first) should be evicted
	require.Eventually(t, func() bool {
		exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, "/test/hello_world.txt.2")
		return err == nil && !exists
	}, 10*time.Second, 100*time.Millisecond, "Expected file 2 (purge-first) to be evicted")

	// File 0 should also be evicted (oldest LRU)
	exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, "/test/hello_world.txt.0")
	require.NoError(t, err)
	assert.False(t, exists, "Expected file 0 to be evicted")

	// Files 1 and 3 should still exist
	for _, idx := range []int{1, 3} {
		objectPath := fmt.Sprintf("/test/hello_world.txt.%d", idx)
		exists, err := local_cache.CheckCacheObjectIsCached(ctx, socketPath, objectPath)
		require.NoError(t, err)
		assert.True(t, exists, "Expected file %d to exist", idx)
	}

	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		server_utils.ResetTestState()
	})
}
