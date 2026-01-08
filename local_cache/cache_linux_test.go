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
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
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
	for idx := 0; idx < 5; idx++ {
		func() {
			fp, err := os.Open(filepath.Join(param.LocalCache_DataLocation.GetString(), "test", fmt.Sprintf("hello_world.txt.%d.DONE", idx)))
			if idx == 0 {
				log.Errorln("Error:", err)
				assert.ErrorIs(t, err, os.ErrNotExist)
			} else {
				assert.NoError(t, err)
			}
			defer fp.Close()
		}()
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
	for idx := 0; idx < 4; idx++ {
		func() {
			fp, err := os.Open(filepath.Join(param.LocalCache_DataLocation.GetString(), "test", fmt.Sprintf("hello_world.txt.%d.DONE", idx)))
			assert.NoError(t, err)
			defer fp.Close()
		}()
	}

	_, err = utils.MakeRequest(ft.Ctx, tr, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge", "POST", nil, map[string]string{"Authorization": "Bearer " + token})
	require.NoError(t, err)

	// Low water mark is small enough that a force purge will delete a file.
	for idx := 0; idx < 4; idx++ {
		func() {
			fp, err := os.Open(filepath.Join(param.LocalCache_DataLocation.GetString(), "test", fmt.Sprintf("hello_world.txt.%d.DONE", idx)))
			if idx == 0 {
				assert.ErrorIs(t, err, os.ErrNotExist)
			} else {
				assert.NoError(t, err)
			}
			defer fp.Close()
		}()
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

// TestPurgeFirst verifies that LocalCache correctly reconstructs its in-memory state from files
// in the data location and prioritizes purging files marked PURGEFIRST during the purge routine.
//
// The test creates 5 test files (2MB each) in order from file-1 through file-5. File-5 is marked PURGEFIRST
// by manually adding a sentinel file before LocalCache is started, and file-1 is marked PURGEFIRST via the API.
// The purge is triggered with the low water mark set at 5MB, and the test asserts that three files are purged:
// file-1 and file-5 (PURGEFIRST), and file-2 (the oldest among the remaining non-PURGEFIRST files).
func TestPurgeFirst(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	configDir := t.TempDir()
	require.NoError(t, param.Set("ConfigDir", configDir))
	// Set RuntimeDir to avoid race conditions with parallel tests using shared /run/pelican
	require.NoError(t, param.Set(param.RuntimeDir.GetName(), configDir))

	test_utils.MockFederationRoot(t, nil, nil)

	dataDir := t.TempDir()
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "debug"))
	require.NoError(t, param.Set(param.LocalCache_DataLocation.GetName(), dataDir))
	require.NoError(t, param.Set(param.LocalCache_Size.GetName(), "10MB"))
	require.NoError(t, param.Set(param.LocalCache_LowWaterMarkPercentage.GetName(), "50"))
	require.NoError(t, param.Set(param.Server_StartupTimeout.GetName(), "10s"))
	require.NoError(t, param.Set(param.Server_AdvertisementInterval.GetName(), "10m"))
	require.NoError(t, param.Set(param.Server_AdLifetime.GetName(), "10m"))

	// Create test files and sentinel files
	testFiles := []struct {
		name         string
		isPurgeFirst bool
	}{
		{"file1.txt", false},
		{"file2.txt", false},
		{"file3.txt", false},
		{"file4.txt", false},
		{"file5.txt", true},
	}

	testNsDir := filepath.Join(dataDir, "test")
	require.NoError(t, os.MkdirAll(testNsDir, 0755))

	twoMBData := make([]byte, 2*1024*1024) // 2 MB of zeroed bytes
	for _, tf := range testFiles {
		dataFilePath := filepath.Join(testNsDir, tf.name)
		err := os.WriteFile(dataFilePath, twoMBData, 0644)
		require.NoError(t, err)

		sentinelFilePath := dataFilePath + ".DONE"
		err = os.WriteFile(sentinelFilePath, []byte(""), 0644)
		require.NoError(t, err)

		if tf.isPurgeFirst {
			sentinelFilePath := dataFilePath + ".PURGEFIRST"
			err = os.WriteFile(sentinelFilePath, []byte(""), 0644)
			require.NoError(t, err)
		}
	}

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	_, _, err := launchers.LaunchModules(ctx, server_structs.LocalCacheType)
	require.NoError(t, err)
	// Create token with proper scopes
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = time.Minute
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	tokConf.AddScopes(token_scopes.Localcache_Purge)

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	// Make API call to mark /test/file1.txt as purge first
	tr := config.GetTransport()
	body := map[string]interface{}{"Path": "/test/file1.txt"}

	_, err = utils.MakeRequest(ctx, tr, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge_first", "POST", body, map[string]string{"Authorization": "Bearer " + token})
	require.NoError(t, err)

	// Verify the sentinel .PURGEFIRST file exists
	expectedSentinel := filepath.Join(testNsDir, "file1.txt.PURGEFIRST")
	_, statErr := os.Stat(expectedSentinel)
	assert.NoError(t, statErr, "Expected .PURGEFIRST sentinel file not found")

	_, err = utils.MakeRequest(ctx, tr, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge", "POST", nil, map[string]string{"Authorization": "Bearer " + token})
	require.NoError(t, err)

	deletedFiles := []string{
		"file1.txt", "file1.txt.DONE", "file1.txt.PURGEFIRST",
		"file5.txt", "file5.txt.DONE", "file5.txt.PURGEFIRST",
		"file5.txt", "file2.txt.DONE",
	}

	for _, fname := range deletedFiles {
		_, err := os.Stat(filepath.Join(testNsDir, fname))
		assert.ErrorIs(t, err, os.ErrNotExist, "Expected %s to be deleted", fname)
	}

	existingFiles := []string{
		"file3.txt", "file3.txt.DONE",
		"file4.txt", "file4.txt.DONE",
	}

	for _, fname := range existingFiles {
		_, err := os.Stat(filepath.Join(testNsDir, fname))
		assert.NoError(t, err, "Expected %s to exist", fname)
	}

	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		server_utils.ResetTestState()
	})
}
