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

package issuer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/param"
)

// setupAuthzTemplates configures Issuer.AuthorizationTemplates and compiles
// them into rules that CalculateAllowedScopes can use.
func setupAuthzTemplates(t *testing.T, templates []map[string]interface{}) {
	t.Helper()
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})
	require.NoError(t, param.Set("Issuer.AuthorizationTemplates", templates))
	require.NoError(t, oa4mp.InitAuthzRules())
}

func TestCalculateUserScopes(t *testing.T) {
	t.Run("GroupToScopeMapping", func(t *testing.T) {
		// Configure rules that map groups to storage scopes.
		//   - group /collab/analysis gets read on /data/analysis
		//   - group /collab/production gets read+write on /data/production
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data/analysis",
				"groups":  []string{"/collab/analysis"},
			},
			{
				"actions": []string{"read", "write"},
				"prefix":  "/data/production",
				"groups":  []string{"/collab/production"},
			},
		})

		// User in the analysis group should receive storage.read:/data/analysis
		scopes, groups := CalculateUserScopes("alice", "alice", []string{"/collab/analysis"})
		assert.Contains(t, scopes, "storage.read:/data/analysis")
		assert.NotContains(t, scopes, "storage.modify:/data/production")
		assert.Contains(t, groups, "/collab/analysis")

		// User in both groups should receive scopes from both rules
		scopes, groups = CalculateUserScopes("bob", "bob", []string{"/collab/analysis", "/collab/production"})
		assert.Contains(t, scopes, "storage.read:/data/analysis")
		assert.Contains(t, scopes, "storage.read:/data/production")
		assert.Contains(t, scopes, "storage.modify:/data/production")
		assert.Contains(t, groups, "/collab/analysis")
		assert.Contains(t, groups, "/collab/production")

		// User with no matching groups should receive nothing
		scopes, _ = CalculateUserScopes("eve", "eve", []string{"/collab/other"})
		assert.Empty(t, scopes)
	})

	t.Run("UserSpecificMapping", func(t *testing.T) {
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read", "write"},
				"prefix":  "/home/$USER",
				"users":   []string{"alice"},
			},
		})

		scopes, _ := CalculateUserScopes("alice", "alice", nil)
		assert.Contains(t, scopes, "storage.read:/home/alice")
		assert.Contains(t, scopes, "storage.modify:/home/alice")

		scopes, _ = CalculateUserScopes("bob", "bob", nil)
		assert.Empty(t, scopes, "bob should not match a rule restricted to alice")
	})

	t.Run("GroupWithGroupExpansion", func(t *testing.T) {
		// When the prefix contains $GROUP, each matching group generates
		// its own scope hierarchy.
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/projects/$GROUP",
				"groups":  []string{"/physics", "/biology"},
			},
		})

		scopes, groups := CalculateUserScopes("alice", "alice", []string{"/physics", "/biology"})
		assert.Contains(t, scopes, "storage.read:/projects/%2Fphysics")
		assert.Contains(t, scopes, "storage.read:/projects/%2Fbiology")
		assert.Contains(t, groups, "/physics")
		assert.Contains(t, groups, "/biology")
	})

	t.Run("EmptyRules", func(t *testing.T) {
		setupAuthzTemplates(t, nil)

		scopes, groups := CalculateUserScopes("alice", "alice", []string{"/collab"})
		assert.Empty(t, scopes)
		assert.Empty(t, groups)
	})
}

func TestFilterRequestedScopes(t *testing.T) {
	t.Run("StandardScopesAlwaysAllowed", func(t *testing.T) {
		// Even without any authorization templates, standard OIDC/WLCG
		// scopes should be returned.
		setupAuthzTemplates(t, nil)

		filtered := FilterRequestedScopes(
			[]string{"openid", "offline_access", "wlcg", "profile", "email"},
			"alice", "alice", nil,
		)
		assert.ElementsMatch(t, []string{"openid", "offline_access", "wlcg", "profile", "email"}, filtered)
	})

	t.Run("FilterStorageScopes", func(t *testing.T) {
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data",
				"groups":  []string{"/readers"},
			},
		})

		// User in the group requests both allowed and disallowed scopes
		filtered := FilterRequestedScopes(
			[]string{"openid", "storage.read:/data", "storage.modify:/data"},
			"alice", "alice", []string{"/readers"},
		)
		assert.Contains(t, filtered, "openid")
		assert.Contains(t, filtered, "storage.read:/data")
		assert.NotContains(t, filtered, "storage.modify:/data")
	})

	t.Run("HierarchicalScopeMatching", func(t *testing.T) {
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/",
			},
		})

		// storage.read:/ covers storage.read:/foo/bar hierarchically
		filtered := FilterRequestedScopes(
			[]string{"storage.read:/foo/bar"},
			"alice", "alice", nil,
		)
		assert.Contains(t, filtered, "storage.read:/foo/bar")
	})

	t.Run("HierarchicalScopeBoundary", func(t *testing.T) {
		// Verify that path matching is component-based, not just prefix-based.
		// storage.read:/data should NOT cover storage.read:/data-extra
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data",
				"groups":  []string{"/readers"},
			},
		})

		filtered := FilterRequestedScopes(
			[]string{"storage.read:/data", "storage.read:/data/sub", "storage.read:/data-extra"},
			"alice", "alice", []string{"/readers"},
		)
		assert.Contains(t, filtered, "storage.read:/data", "exact match should be allowed")
		assert.Contains(t, filtered, "storage.read:/data/sub", "sub-path should be allowed")
		assert.NotContains(t, filtered, "storage.read:/data-extra",
			"storage.read:/data should NOT cover storage.read:/data-extra (not a path-component boundary)")
	})

	t.Run("BroadScopeExpansion", func(t *testing.T) {
		// When a user requests a scope broader than what's permitted,
		// substitute in all narrower allowed scopes.
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data/analysis",
				"groups":  []string{"/collab/analysis"},
			},
			{
				"actions": []string{"read"},
				"prefix":  "/data/production",
				"groups":  []string{"/collab/production"},
			},
			{
				"actions": []string{"write"},
				"prefix":  "/data/production",
				"groups":  []string{"/collab/production"},
			},
		})

		// User in both groups requests storage.read:/ — too broad to grant
		// directly, but should expand to the two permitted read paths.
		filtered := FilterRequestedScopes(
			[]string{"openid", "storage.read:/"},
			"alice", "alice", []string{"/collab/analysis", "/collab/production"},
		)
		assert.Contains(t, filtered, "openid")
		assert.Contains(t, filtered, "storage.read:/data/analysis",
			"should expand broad scope to permitted narrower scope")
		assert.Contains(t, filtered, "storage.read:/data/production",
			"should expand broad scope to permitted narrower scope")
		assert.NotContains(t, filtered, "storage.read:/",
			"the original broad scope should NOT appear")
		assert.NotContains(t, filtered, "storage.modify:/data/production",
			"write scope should not appear when read was requested")
	})

	t.Run("BroadScopePartialExpansion", func(t *testing.T) {
		// When the broad scope overlaps with only a subset of allowed scopes.
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data/analysis",
				"groups":  []string{"/collab"},
			},
			{
				"actions": []string{"read"},
				"prefix":  "/other/stuff",
				"groups":  []string{"/collab"},
			},
		})

		// Request storage.read:/data — should only pull in /data/analysis,
		// NOT /other/stuff (which is not under /data).
		filtered := FilterRequestedScopes(
			[]string{"storage.read:/data"},
			"alice", "alice", []string{"/collab"},
		)
		assert.Contains(t, filtered, "storage.read:/data/analysis")
		assert.NotContains(t, filtered, "storage.read:/other/stuff",
			"should not expand to scopes outside the requested path hierarchy")
	})

	t.Run("BroadScopeNoMatch", func(t *testing.T) {
		// When the broad scope has no narrower allowed children, it's dropped.
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data",
				"groups":  []string{"/collab"},
			},
		})

		filtered := FilterRequestedScopes(
			[]string{"storage.modify:/"},
			"alice", "alice", []string{"/collab"},
		)
		assert.Empty(t, filtered, "no matching narrower scopes → empty result")
	})

	t.Run("NoDuplicatesFromOverlappingExpansion", func(t *testing.T) {
		// If the user requests both storage.read:/ and storage.read:/data,
		// and only storage.read:/data is allowed, the result should contain
		// it once (from the exact match) and not again from the expansion.
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data",
				"groups":  []string{"/collab"},
			},
		})

		filtered := FilterRequestedScopes(
			[]string{"storage.read:/", "storage.read:/data"},
			"alice", "alice", []string{"/collab"},
		)
		// Count occurrences
		count := 0
		for _, s := range filtered {
			if s == "storage.read:/data" {
				count++
			}
		}
		assert.Equal(t, 1, count, "storage.read:/data should appear exactly once")
	})
}
