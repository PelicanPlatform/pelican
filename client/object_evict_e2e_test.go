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

// Edge-case end-to-end coverage for `pelican object evict` (client.DoEvict),
// layered on the same proven federation harness as TestDoEvict.
//
// TestDoEvict already covers the happy paths (immediate + default eviction of a
// cached object).  This file adds the edge cases that only surface through the
// full client path: authorization enforcement and evicting a path that was
// never cached.
package client_test

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// mintScopedToken creates a token with exactly the given resource scopes,
// signed by the issuer keys currently in effect (i.e. those already registered
// by a prior getTempToken call in the same test).  It deliberately does NOT
// reset IssuerKeysDirectory, so the resulting token is trusted by the
// federation just like the one getTempToken returns.
func mintScopedToken(t *testing.T, scopes ...token_scopes.TokenScope) string {
	t.Helper()
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tc := token.NewWLCGToken()
	tc.Lifetime = time.Minute
	tc.Issuer = issuer
	tc.Subject = "origin"
	tc.AddAudienceAny()
	tc.AddScopes(scopes...)
	tok, err := tc.CreateToken()
	require.NoError(t, err)
	return tok
}

func TestObjectEvictEdgeCases(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	testFileContent := "evict-edge-content"
	tempFile, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	_, err = tempFile.WriteString(testFileContent)
	require.NoError(t, err)
	tempFile.Close()

	// getTempToken sets up (and registers) the issuer keys, and returns a token
	// with storage.read + storage.modify on "/".  mintScopedToken below reuses
	// the same issuer keys.
	tempToken, _ := getTempToken(t)
	defer tempToken.Close()
	require.NoError(t, param.Logging_DisableProgressBars.Set(true))

	export := fed.Exports[0]
	fileName := filepath.Base(tempFile.Name())
	objectURL := fmt.Sprintf("pelican://%s:%s%s/evict_edge/%s",
		param.Server_Hostname.GetString(),
		strconv.Itoa(param.Server_WebPort.GetInt()),
		export.FederationPrefix, fileName)

	// Upload the file and prestage it into the cache so there is a real object
	// to evict.  (Authorization is enforced before eviction, so the
	// unauthorized case below does not depend on cache residency.)
	_, err = client.DoCopy(fed.Ctx, tempFile.Name(), objectURL, false, client.WithTokenLocation(tempToken.Name()))
	require.NoError(t, err)
	_, err = client.DoPrestage(fed.Ctx, objectURL, client.WithTokenLocation(tempToken.Name()))
	require.NoError(t, err)

	// CHARACTERIZATION (documents current behavior, not the desired posture):
	//
	// The client requests, and the Go LocalCache handler enforces, storage.modify
	// for eviction (local_cache/prestage_evict_api.go:495).  The production
	// XRootD cache evict endpoint, however, currently accepts a storage.read-only
	// token — it does not reject the destructive operation for lack of
	// storage.modify.  This subtest pins that observed behavior so a future
	// change that tightens enforcement (returning 403) is deliberate and visible.
	// See the accompanying report: evict authorization is inconsistent between
	// the XRootD and Go cache implementations.
	t.Run("read-only-token-currently-accepted-by-xrootd", func(t *testing.T) {
		readOnly := mintScopedToken(t, mustScope(t, token_scopes.Wlcg_Storage_Read, "/"))
		msg, evictErr := client.DoEvict(fed.Ctx, objectURL, true, client.WithToken(readOnly))
		t.Logf("read-only evict -> msg=%q err=%v", msg, evictErr)
		require.NoError(t, evictErr, "observed: XRootD cache currently accepts a read-only token for eviction")
		require.Contains(t, msg, "eviction successful")
	})

	t.Run("cache-override-is-honored", func(t *testing.T) {
		// Point eviction at an unreachable cache via the preferred-caches
		// override (the mechanism the --cache flag feeds).  Before --cache
		// support DoEvict ignored this and used the director's cache (which
		// would succeed); now it must target the overridden cache and fail to
		// connect — proving the override actually reaches the eviction path.
		// The success case is covered by the other subtests + TestDoEvict,
		// which evict via the director-selected cache.
		bogus, parseErr := url.Parse("https://127.0.0.1:1")
		require.NoError(t, parseErr)
		_, evictErr := client.DoEvict(fed.Ctx, objectURL, true,
			client.WithTokenLocation(tempToken.Name()), client.WithCaches(bogus))
		require.Error(t, evictErr, "evict must target the overridden (unreachable) cache, proving --cache is honored")
		t.Logf("override evict error (expected): %v", evictErr)
	})

	t.Run("multiple-caches-are-all-contacted", func(t *testing.T) {
		// Two specific caches via the override.  Both are unreachable, so the
		// eviction must be attempted against each and the aggregated error must
		// name both and report "2 of 2" — proving the multi-cache loop and the
		// per-cache summary.
		bogusA, err := url.Parse("https://127.0.0.1:1")
		require.NoError(t, err)
		bogusB, err := url.Parse("https://127.0.0.1:2")
		require.NoError(t, err)

		_, evictErr := client.DoEvict(fed.Ctx, objectURL, true,
			client.WithTokenLocation(tempToken.Name()),
			client.WithCaches(bogusA, bogusB))
		require.Error(t, evictErr)
		msg := evictErr.Error()
		t.Logf("multi-cache evict error: %v", evictErr)
		require.Contains(t, msg, "2 of 2 cache(s)", "both specified caches should be counted")
		require.Contains(t, msg, "127.0.0.1:1", "first cache should appear in the per-cache summary")
		require.Contains(t, msg, "127.0.0.1:2", "second cache should appear in the per-cache summary")
	})

	t.Run("multiple-caches-mixed-success-and-failure", func(t *testing.T) {
		// One unreachable cache plus the "+" fallback, which appends the
		// director-provided (real) cache(s).  The eviction must be attempted
		// against both: the bogus one FAILS while the real one succeeds.  Since
		// at least one failed, DoEvict returns an error whose summary shows both
		// outcomes.
		bogus, err := url.Parse("https://127.0.0.1:1")
		require.NoError(t, err)
		plus, err := url.Parse("+")
		require.NoError(t, err)

		_, evictErr := client.DoEvict(fed.Ctx, objectURL, true,
			client.WithTokenLocation(tempToken.Name()),
			client.WithCaches(bogus, plus))
		require.Error(t, evictErr, "a mixed batch with one unreachable cache should surface a failure")
		msg := evictErr.Error()
		t.Logf("mixed multi-cache evict error: %v", evictErr)
		require.Contains(t, msg, "127.0.0.1:1", "the unreachable cache should be reported")
		require.Contains(t, msg, "eviction successful",
			"the real (director-provided) cache reached via the '+' fallback should have succeeded")
	})

	t.Run("evict-never-cached-path-is-safe", func(t *testing.T) {
		// A path under an authorized namespace that was never pulled into the
		// cache.  Eviction should complete without error (idempotent / safe).
		ghostURL := fmt.Sprintf("pelican://%s:%s%s/evict_edge/never_cached_%s",
			param.Server_Hostname.GetString(),
			strconv.Itoa(param.Server_WebPort.GetInt()),
			export.FederationPrefix, fileName)

		msg, evictErr := client.DoEvict(fed.Ctx, ghostURL, true, client.WithTokenLocation(tempToken.Name()))
		require.NoError(t, evictErr, "evicting a never-cached path should not error")
		t.Logf("evict of never-cached path returned: %q", msg)
	})
}

// mustScope builds a resource scope or fails the test.
func mustScope(t *testing.T, action token_scopes.TokenScope, resource string) token_scopes.TokenScope {
	t.Helper()
	rs, err := action.Path(resource)
	require.NoError(t, err)
	return rs
}
