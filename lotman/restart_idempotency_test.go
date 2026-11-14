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

package lotman

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestInitLotmanIsPathIdempotent covers what the other restart-simulation tests
// do not: that re-running InitLotman against an existing database leaves the
// lots' *paths* alone.
//
// Paths read back from the database carry a lot_name; paths derived from config
// do not. When that field participated in the diff, every stored path looked
// like a removal plus an addition of a different path, which the update planner
// folded into a "rename" onto itself -- add (no-op) then remove. Every lot lost
// every path on the second InitLotman, so monitoring and all admin-configured
// lots silently fell through to the zero-quota `default` lot on the first
// restart. Asserting InitLotman returns true, as the existing restart tests do,
// does not catch it: the wipe is a successful no-op as far as the caller knows.
func TestInitLotmanIsPathIdempotent(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	server := getMockDiscoveryHost()
	defer server.Close()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))

	issuerURL, _ := url.Parse("https://issuer.example/")
	ads := []server_structs.NamespaceAd{
		{Path: "/foo", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
	}

	require.NoError(t, param.Cache_FilesMaxSize.Set("100g"))
	success, cleanup := setupLotmanFromConf(t, false, "LotmanRestartIdempotency", server.URL, ads)
	defer cleanup()
	require.True(t, success, "initial InitLotman must succeed")

	// Snapshot every lot's paths after the first boot.
	names, err := ListAllLots()
	require.NoError(t, err)
	require.NotEmpty(t, names)

	pathsBefore := map[string][]LotPath{}
	for _, name := range names {
		lot, err := GetLot(name, false)
		require.NoError(t, err, "getting lot %s", name)
		pathsBefore[name] = lot.Paths
	}
	// The fixture must actually exercise the bug: at least one lot has to hold a
	// path, or this test would pass against the broken code too.
	held := 0
	for _, paths := range pathsBefore {
		held += len(paths)
	}
	require.NotZero(t, held, "fixture must produce at least one lot path to be meaningful")

	// Second boot against the same LotHome, exactly as a service restart would.
	require.True(t, InitLotman(ads), "InitLotman must succeed on restart")

	for _, name := range names {
		lot, err := GetLot(name, false)
		require.NoError(t, err, "lot %s disappeared across restart", name)
		assert.ElementsMatch(t, pathsBefore[name], lot.Paths,
			"lot %s changed its paths across a restart: %v -> %v", name, pathsBefore[name], lot.Paths)
	}

	// And resolution still works: a path that resolved to a real lot before must
	// not now fall through to `default`.
	for name, paths := range pathsBefore {
		if name == "default" || len(paths) == 0 {
			continue
		}
		owners, err := GetLotsFromDir(paths[0].Path, false, time.Now().UnixMilli())
		require.NoError(t, err, "resolving %s", paths[0].Path)
		assert.NotEqual(t, []string{"default"}, owners,
			"path %s (owned by lot %s) fell through to the default lot after a restart", paths[0].Path, name)
	}
}
