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

package fed_tests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestObjectEvictV2NotShadowedByDirector is the end-to-end regression for the
// director ShortcutMiddleware fix.  This harness co-locates the director and a
// persistent (V2) cache on one web engine, so before the fix the director's
// ShortcutMiddleware rewrote GET /pelican/api/v1.0/evict into an object redirect
// and the director's namespace resolver returned a 404 ("no origins found for
// the requested namespace '/pelican/api/v1.0/evict'") before the cache's handler
// ran.  With the fix the request reaches the cache's evict handler.
//
// The cache may still reject the request with its own authorization error in
// this harness; what this test guards is that the request is NOT swallowed by
// the director — i.e., the routing regression does not recur.
func TestObjectEvictV2NotShadowedByDirector(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, `Origin:
  StorageType: posixv2
  Exports:
    - StoragePrefix: "/"
      FederationPrefix: "/test"
      Capabilities: ["PublicReads", "DirectReads", "Listings"]
`)
	tkn := getTempTokenForTest(t)

	writeTestFile(t, ft, "v2evict.bin", 4096)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/v2evict.bin", tkn)
	require.Equal(t, 200, fetchFromCache(t, ft, cacheURL, nil).statusCode)

	objURL := fmt.Sprintf("pelican://%s:%d/test/v2evict.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	msg, err := client.DoEvict(ft.Ctx, objURL, true, client.WithToken(tkn))
	t.Logf("V2 DoEvict -> msg=%q err=%v", msg, err)

	if err != nil {
		require.NotContains(t, err.Error(), "no origins found for the requested namespace",
			"evict request was shadowed by the director's ShortcutMiddleware "+
				"(the /pelican/api/v1.0/ skip regressed)")
	}
}
