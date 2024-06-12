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
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

// Create five 1MB files.  Trigger a purge, ensuring that the cleanup is
// done according to LRU
func TestPurge(t *testing.T) {
	tmpDir := t.TempDir()

	viper.Reset()
	viper.Set("LocalCache.Size", "5MB")
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
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})
}

// Create four 1MB files (above low-water mark).  Force a purge, ensuring that the cleanup is
// done according to LRU
func TestForcePurge(t *testing.T) {
	tmpDir := t.TempDir()

	viper.Reset()
	viper.Set("LocalCache.Size", "5MB")
	// Decrease the low water mark so invoking purge will result in 3 files in the cache.
	viper.Set("LocalCache.LowWaterMarkPercentage", "80")
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

	_, err = utils.MakeRequest(ft.Ctx, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge", "POST", nil, map[string]string{"Authorization": "Bearer abcd"})
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

	_, err = utils.MakeRequest(ft.Ctx, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/localcache/purge", "POST", nil, map[string]string{"Authorization": "Bearer " + token})
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
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})
}
