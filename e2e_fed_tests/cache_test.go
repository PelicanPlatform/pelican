//go:build !windows

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package fed_tests

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// Test that token maintenance for the cache works as expected -- we never
// want to let the on-disk token expire.
func TestCacheFedTokMaint(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Spin up the full fed so that our cache server can get the token from the director
	require.NoError(t, param.Set(param.Director_FedTokenLifetime.GetName(), "12s"))
	oldMinTokRate := cache.MinFedTokenTickerRate
	defer func() {
		cache.MinFedTokenTickerRate = oldMinTokRate
	}()
	cache.MinFedTokenTickerRate = 1 * time.Second
	_ = fed_test_utils.NewFedTest(t, bothPubNamespaces)

	// Run the token maintenance routine for two periods and make sure
	// the cache token on disk is never older than 4s (1/3 the configured lifetime)
	ctx := context.Background()
	ctx, cancel, egrp := test_utils.TestContext(ctx, t)
	defer cancel()
	cacheServer := cache.CacheServer{}

	// Give this "cache" instance a unique location so it doesn't compete with the fed test cache token
	require.NoError(t, param.Set(param.Cache_FedTokenLocation.GetName(), filepath.Join(t.TempDir(), t.Name()+"_fedtok")))
	cache.LaunchFedTokManager(ctx, egrp, &cacheServer, nil, nil, nil)
	tokFile := cacheServer.GetFedTokLocation()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.After(24 * time.Second)
	for {
		select {
		case <-ticker.C:
			info, err := os.Stat(tokFile)
			require.NoError(t, err, "Failed to stat token file")
			age := time.Since(info.ModTime())
			if age > (4*time.Second + 500*time.Millisecond) { // build in a little slop
				t.Fatalf("Token file age exceeded 4s: %v", age)
			}
		case <-timeout:
			return
		}
	}
}

// Validate CacheServe behavior: if Cache.Url has an existing port, it is preserved
func TestCacheServe_PreservesExistingPort(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Set Cache.Url to include an existing port
	require.NoError(t, param.Set(param.Cache_Url.GetName(), "https://example.com:8442"))

	// Launch the federation (starts CacheServe among others)
	_ = fed_test_utils.NewFedTest(t, bothPubNamespaces)

	// After startup, Cache.Url should remain with the original port
	finalURL := viper.GetString(param.Cache_Url.GetName())
	finalPort := viper.GetInt(param.Cache_Port.GetName())

	assert.Equal(t, "https://example.com:8442", finalURL, "Cache.Url should preserve existing port")
	assert.NotEqual(t, 0, finalPort, "Cache.Port should be set by CacheServe")
}

// Validate CacheServe behavior: if Cache.Url lacks a port, one is added
func TestCacheServe_AddsPortWhenMissing(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Ensure Cache.Url has no explicit port
	require.NoError(t, param.Set(param.Cache_Url.GetName(), "https://example.com"))

	// Launch the federation (starts CacheServe among others)
	_ = fed_test_utils.NewFedTest(t, bothPubNamespaces)

	// After startup, Cache.Url should include a port
	finalURL := viper.GetString(param.Cache_Url.GetName())
	finalPort := viper.GetInt(param.Cache_Port.GetName())

	assert.NotEqual(t, 0, finalPort, "Cache.Port should be set by CacheServe")
	assert.Contains(t, finalURL, ":", "Cache.Url should include a port")
}
