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
	require.NoError(t, param.Issuer_AuthorizationTemplates.Set(templates))
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

func TestCleanScopePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Plain scope unchanged", "openid", "openid"},
		{"No traversal unchanged", "storage.read:/data/foo", "storage.read:/data/foo"},
		{"DotDot resolved", "storage.read:/data/bar/../baz", "storage.read:/data/baz"},
		{"Multiple DotDot", "storage.read:/a/b/c/../../d", "storage.read:/a/d"},
		{"Trailing slash cleaned", "storage.read:/data/foo/", "storage.read:/data/foo"},
		{"Dot cleaned", "storage.read:/data/./foo", "storage.read:/data/foo"},
		{"Root stays root", "storage.read:/", "storage.read:/"},
		{"Empty path component", "storage.read:", "storage.read:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, cleanScopePath(tt.input))
		})
	}
}

func TestPathTraversalPrevention(t *testing.T) {
	// Regression tests for path traversal via ".." in scope paths.
	// Before the fix, "storage.read:/foo/bar/../baz" would pass an
	// authorization check for "storage.read:/foo/bar" because the raw
	// string starts with "/foo/bar", but the path resolves to "/foo/baz".

	t.Run("TraversalBlockedInFilter", func(t *testing.T) {
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data/private",
				"groups":  []string{"/readers"},
			},
		})

		// This path resolves to /data/secret, which is NOT under /data/private
		filtered := FilterRequestedScopes(
			[]string{"storage.read:/data/private/../secret"},
			"alice", "alice", []string{"/readers"},
		)
		assert.NotContains(t, filtered, "storage.read:/data/private/../secret",
			"raw traversal scope must not be granted")
		assert.NotContains(t, filtered, "storage.read:/data/secret",
			"resolved traversal scope must not be granted (outside allowed path)")
	})

	t.Run("TraversalResolvingToAllowedPath", func(t *testing.T) {
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data",
				"groups":  []string{"/readers"},
			},
		})

		// /data/sub/../file resolves to /data/file which IS under /data
		filtered := FilterRequestedScopes(
			[]string{"storage.read:/data/sub/../file"},
			"alice", "alice", []string{"/readers"},
		)
		// The traversal should be cleaned and the scope should be granted
		// as storage.read:/data/file (not the raw ".." form)
		assert.Contains(t, filtered, "storage.read:/data/file",
			"traversal resolving within allowed path should be granted in clean form")
		assert.NotContains(t, filtered, "storage.read:/data/sub/../file",
			"raw traversal form must never appear in granted scopes")
	})

	t.Run("URLEncodedTraversal", func(t *testing.T) {
		setupAuthzTemplates(t, []map[string]interface{}{
			{
				"actions": []string{"read"},
				"prefix":  "/data/private",
				"groups":  []string{"/readers"},
			},
		})

		// URL-encoded ".." (%2e%2e) should also be caught
		filtered := FilterRequestedScopes(
			[]string{"storage.read:/data/private/%2e%2e/secret"},
			"alice", "alice", []string{"/readers"},
		)
		assert.NotContains(t, filtered, "storage.read:/data/private/%2e%2e/secret",
			"URL-encoded traversal must not bypass checks")
		assert.NotContains(t, filtered, "storage.read:/data/secret",
			"resolved URL-encoded traversal must not be granted outside allowed path")
	})

	t.Run("MatchHierarchicalRejectsTraversal", func(t *testing.T) {
		allowed := []string{"storage.read:/foo/bar"}

		// /foo/bar/../baz resolves to /foo/baz — NOT under /foo/bar
		assert.False(t, matchHierarchical("storage.read:/foo/bar/../baz", allowed),
			"traversal escaping allowed path must be rejected")

		// /foo/bar/../bar/file resolves to /foo/bar/file — IS under /foo/bar
		assert.True(t, matchHierarchical("storage.read:/foo/bar/../bar/file", allowed),
			"traversal resolving within allowed path should match")
	})

	t.Run("CollectNarrowerRejectsTraversal", func(t *testing.T) {
		// Ensure that requesting a broad scope with ".." doesn't collect
		// scopes outside the resolved path.
		allowed := []string{
			"storage.read:/data/public",
			"storage.read:/secret",
		}

		// storage.read:/data/public/../../ resolves to storage.read:/
		// which would be broader than /secret — but /secret should NOT
		// be returned because the request's resolved path is /, and
		// collectNarrowerScopes is only called when the request is
		// broader. The allowed scopes themselves are clean.
		result := collectNarrowerScopes("storage.read:/data/public/../../", allowed)
		// Resolves to storage.read:/ which is broader than both,
		// so both should appear (this is correct behavior — the user
		// asked for / which covers everything, and we return what they're allowed)
		assert.Contains(t, result, "storage.read:/data/public")
		assert.Contains(t, result, "storage.read:/secret")
	})
}
