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

package api_token

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/token_scopes"
)

// withMockEffectiveScopes installs a fake EffectiveScopesForUser
// hook for the duration of the subtest, then restores whatever was
// there before. Every test that exercises the intersection has to
// either install a mock or run with the hook unset; sharing this
// helper keeps the housekeeping out of the assertions.
func withMockEffectiveScopes(t *testing.T, fn func(userID string) []token_scopes.TokenScope) {
	t.Helper()
	prev := EffectiveScopesForUser
	EffectiveScopesForUser = fn
	t.Cleanup(func() { EffectiveScopesForUser = prev })
}

// TestIntersectWithUserScopes pins the contract that the intersection:
//   - passes through every NON-user-grantable scope unchanged (data-plane
//     wlcg/scitokens, inter-server scopes, web_ui.access etc. are pure
//     bearer-token authority, not derivative of any user role),
//   - keeps user-grantable scopes only when the creator's CURRENT
//     effective set still contains them (so a permission revocation
//     immediately reaches into already-issued API tokens),
//   - leaves capabilities untouched when the token has no recorded
//     creator (legacy rows minted before CreatedBy was added),
//   - drops every user-grantable scope when the hook is unset (a
//     binary that linked api_token but never wired the hook can't
//     prove the creator's authority — fail closed).
func TestIntersectWithUserScopes(t *testing.T) {
	t.Run("passes through non-user-grantable scopes unchanged", func(t *testing.T) {
		withMockEffectiveScopes(t, func(string) []token_scopes.TokenScope {
			// Creator has no management scopes at all. Every
			// non-management capability should still pass through.
			return nil
		})
		caps := []string{
			token_scopes.WebUi_Access.String(),
			token_scopes.Monitoring_Scrape.String(),
			token_scopes.Pelican_Advertise.String(),
			token_scopes.Wlcg_Storage_Read.String(),
		}
		got := intersectWithUserScopes(caps, "u-alice")
		assert.ElementsMatch(t, caps, got,
			"data-plane and inter-server scopes are bearer-token authority — they MUST survive the intersection regardless of the user's current role")
	})

	t.Run("drops user-grantable scopes the creator no longer has", func(t *testing.T) {
		withMockEffectiveScopes(t, func(uid string) []token_scopes.TokenScope {
			assert.Equal(t, "u-alice", uid, "the hook receives the token's CreatedBy")
			return []token_scopes.TokenScope{
				token_scopes.Server_CollectionAdmin,
			}
		})
		caps := []string{
			token_scopes.Server_WebAdmin.String(),        // creator no longer has — drop
			token_scopes.Server_UserAdmin.String(),       // creator no longer has — drop
			token_scopes.Server_CollectionAdmin.String(), // still has — keep
			token_scopes.WebUi_Access.String(),           // not user-grantable — keep
		}
		got := intersectWithUserScopes(caps, "u-alice")
		want := []string{
			token_scopes.Server_CollectionAdmin.String(),
			token_scopes.WebUi_Access.String(),
		}
		sort.Strings(got)
		sort.Strings(want)
		assert.Equal(t, want, got,
			"user-grantable scopes that the creator no longer holds must be filtered out, while non-grantable scopes survive")
	})

	t.Run("creator with no scopes loses every user-grantable capability", func(t *testing.T) {
		withMockEffectiveScopes(t, func(string) []token_scopes.TokenScope { return nil })
		caps := []string{
			token_scopes.Server_WebAdmin.String(),
			token_scopes.Server_UserAdmin.String(),
			token_scopes.Server_CollectionAdmin.String(),
		}
		got := intersectWithUserScopes(caps, "u-bob")
		assert.Empty(t, got,
			"a deleted/inactive user (hook returns nil) loses every user-grantable scope on every API token they minted")
	})

	t.Run("empty createdBy leaves capabilities untouched", func(t *testing.T) {
		withMockEffectiveScopes(t, func(string) []token_scopes.TokenScope {
			// Hook would drop everything if invoked.
			return nil
		})
		caps := []string{
			token_scopes.Server_WebAdmin.String(),
			token_scopes.WebUi_Access.String(),
		}
		got := intersectWithUserScopes(caps, "")
		assert.ElementsMatch(t, caps, got,
			"a row minted before the CreatedBy column existed has no creator to intersect against — pre-existing semantics apply")
	})

	t.Run("nil hook drops every user-grantable scope", func(t *testing.T) {
		// No hook installed. The function fails closed: it cannot
		// prove the creator still holds management scopes, so it
		// strips them. Non-grantable scopes still pass through.
		withMockEffectiveScopes(t, nil)
		caps := []string{
			token_scopes.Server_WebAdmin.String(),
			token_scopes.WebUi_Access.String(),
			token_scopes.Wlcg_Storage_Read.String(),
		}
		got := intersectWithUserScopes(caps, "u-carol")
		want := []string{
			token_scopes.WebUi_Access.String(),
			token_scopes.Wlcg_Storage_Read.String(),
		}
		sort.Strings(got)
		sort.Strings(want)
		assert.Equal(t, want, got,
			"with no hook wired, a binary cannot tell whether a creator still has a given user-grantable scope — must fail closed for those")
	})

	t.Run("unknown scope strings are treated as non-grantable and pass through", func(t *testing.T) {
		// Defensive: a scope name we don't recognize (perhaps from
		// a future server version) shouldn't be silently dropped
		// just because it's missing from the IsUserGrantable list.
		// IsUserGrantable returns false for unknown names, so they
		// fall into the pass-through branch.
		withMockEffectiveScopes(t, func(string) []token_scopes.TokenScope { return nil })
		caps := []string{"some.future.scope"}
		got := intersectWithUserScopes(caps, "u-dan")
		assert.Equal(t, caps, got)
	})
}

// TestValidateScopesForCreator pins the create-time companion to
// intersectWithUserScopes. The verify path is already covered above;
// here we assert that the create path REJECTS a request that asks for
// a user-grantable scope the creator doesn't have, so the persisted
// audit row never lies about authority. Edge cases mirror the verify
// path (empty userID, nil hook, non-grantable pass-through) so the
// two stay coherent.
func TestValidateScopesForCreator(t *testing.T) {
	t.Run("creator holds every requested user-grantable scope", func(t *testing.T) {
		withMockEffectiveScopes(t, func(string) []token_scopes.TokenScope {
			return []token_scopes.TokenScope{
				token_scopes.Server_WebAdmin,
				token_scopes.Server_UserAdmin,
				token_scopes.Server_CollectionAdmin,
			}
		})
		err := validateScopesForCreator([]string{
			token_scopes.Server_UserAdmin.String(),
			token_scopes.Monitoring_Scrape.String(),
		}, "u-alice")
		assert.NoError(t, err)
	})

	t.Run("rejects user-grantable scopes the creator does not hold", func(t *testing.T) {
		withMockEffectiveScopes(t, func(string) []token_scopes.TokenScope {
			return []token_scopes.TokenScope{token_scopes.Server_CollectionAdmin}
		})
		err := validateScopesForCreator([]string{
			token_scopes.Server_UserAdmin.String(), // not held — must error
			token_scopes.Server_WebAdmin.String(),  // not held — must error
			token_scopes.Server_CollectionAdmin.String(),
			token_scopes.Monitoring_Scrape.String(),
		}, "u-alice")
		require.Error(t, err)
		assert.Contains(t, err.Error(), token_scopes.Server_UserAdmin.String())
		assert.Contains(t, err.Error(), token_scopes.Server_WebAdmin.String())
		assert.NotContains(t, err.Error(), token_scopes.Server_CollectionAdmin.String(),
			"a scope the creator DOES hold must not appear in the rejection list")
		assert.NotContains(t, err.Error(), token_scopes.Monitoring_Scrape.String(),
			"non-user-grantable bearer-token scopes must never trigger a creator-authority rejection")
	})

	t.Run("non-user-grantable scopes pass without consulting creator", func(t *testing.T) {
		withMockEffectiveScopes(t, func(string) []token_scopes.TokenScope { return nil })
		err := validateScopesForCreator([]string{
			token_scopes.Monitoring_Scrape.String(),
			token_scopes.Wlcg_Storage_Read.String(),
			token_scopes.Pelican_Advertise.String(),
		}, "u-alice")
		assert.NoError(t, err,
			"data-plane and inter-server scopes are bearer-token authority — granted by an admin, not derived from a user role")
	})

	t.Run("empty createdBy is permissive — legacy/system caller", func(t *testing.T) {
		withMockEffectiveScopes(t, func(string) []token_scopes.TokenScope { return nil })
		err := validateScopesForCreator([]string{
			token_scopes.Server_UserAdmin.String(),
		}, "")
		assert.NoError(t, err,
			"with no creator, there's nothing to intersect against — same posture as Verify on legacy rows")
	})

	t.Run("nil hook fails closed for user-grantable scopes", func(t *testing.T) {
		withMockEffectiveScopes(t, nil)
		err := validateScopesForCreator([]string{
			token_scopes.Server_UserAdmin.String(),
		}, "u-alice")
		require.Error(t, err)
		assert.Contains(t, err.Error(), token_scopes.Server_UserAdmin.String(),
			"a binary that linked api_token but never wired the hook can't prove creator authority — must reject management scopes")
	})

	t.Run("nil hook still allows non-grantable scopes", func(t *testing.T) {
		withMockEffectiveScopes(t, nil)
		err := validateScopesForCreator([]string{
			token_scopes.Monitoring_Scrape.String(),
		}, "u-alice")
		assert.NoError(t, err,
			"the fail-closed posture is per-scope: bearer-token authority isn't derived from any user role, so the hook isn't required to authorize it")
	})
}
