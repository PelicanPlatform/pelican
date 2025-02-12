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
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/spf13/viper"
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
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Spin up the full fed so that our cache server can get the token from the director
	viper.Set(param.Director_FedTokenLifetime.GetName(), "12s")
	_ = fed_test_utils.NewFedTest(t, bothPubNamespaces)
	// Now unset this to prove the cache maint thread is using token lifetime, and not
	// a value the maintenance thread gets from viper.
	viper.Set(param.Director_FedTokenLifetime.GetName(), nil)

	// Run the token maintenance routine for two periods and make sure
	// the cache token on disk is never older than 4s (1/3 the configured lifetime)
	ctx := context.Background()
	ctx, cancel, egrp := test_utils.TestContext(ctx, t)
	defer cancel()
	cacheServer := cache.CacheServer{}
	cache.LaunchFedTokManager(ctx, egrp, &cacheServer)
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
			if age > 4*time.Second {
				t.Fatalf("Token file age exceeded 4s: %v", age)
			}
		case <-timeout:
			return
		}
	}
}
