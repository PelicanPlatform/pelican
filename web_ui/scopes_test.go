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

package web_ui

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// setupScopesTestDB clears global config state, then attaches an
// in-memory SQLite to database.ServerDatabase so
// EffectiveScopesForIdentity (which reads database.ServerDatabase) sees
// the same instance the test populates.
//
// Order matters: server_utils.ResetTestState calls
// database.ShutdownDB(), so it has to run BEFORE we open the new DB —
// otherwise it would close the freshly-opened one. The cleanup
// restores the prior ServerDatabase pointer for the same reason
// (other tests in the package may have parked a working handle there).
func setupScopesTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	prev := database.ServerDatabase
	server_utils.ResetTestState()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&database.User{},
		&database.Group{},
		&database.GroupMember{},
		&database.UserScope{},
		&database.GroupScope{},
	))
	require.NoError(t, database.AutoMigrateCredentialsForTests(db))

	database.ServerDatabase = db
	t.Cleanup(func() { database.ServerDatabase = prev })
	return db
}

func contains(scopes []token_scopes.TokenScope, target token_scopes.TokenScope) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// (Param state is cleared inside setupScopesTestDB via ResetTestState
// — keeping a single entry-point keeps the close-then-open ordering
// invariant in one place.)

func TestEffectiveScopesForIdentity(t *testing.T) {
	t.Run("empty identity returns empty", func(t *testing.T) {
		setupScopesTestDB(t)
		got := EffectiveScopesForIdentity(UserIdentity{})
		assert.Empty(t, got)
	})

	t.Run("builtin admin username gets admin (and implications)", func(t *testing.T) {
		setupScopesTestDB(t)

		got := EffectiveScopesForIdentity(UserIdentity{Username: "admin"})
		assert.True(t, contains(got, token_scopes.Server_Admin))
		assert.True(t, contains(got, token_scopes.Server_UserAdmin),
			"server.admin must imply server.user_admin")
		assert.True(t, contains(got, token_scopes.Server_CollectionAdmin),
			"server.admin must imply server.collection_admin")
	})

	t.Run("UIAdminUsers username match grants admin", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{"alice"}))

		got := EffectiveScopesForIdentity(UserIdentity{
			Username: "alice", ID: "u-alice",
		})
		assert.True(t, contains(got, token_scopes.Server_Admin))

		// Same user with a non-matching username doesn't get the scope —
		// catches accidental ID/Sub matching regressions.
		none := EffectiveScopesForIdentity(UserIdentity{
			Username: "bob", ID: "u-alice", Sub: "alice",
		})
		assert.False(t, contains(none, token_scopes.Server_Admin),
			"admin lists must match Username, never ID or Sub")
	})

	t.Run("AdminGroups match grants admin via cookie groups", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_AdminGroups.Set([]string{"sysadmins"}))

		got := EffectiveScopesForIdentity(UserIdentity{
			Username: "carol", ID: "u-carol", Groups: []string{"sysadmins"},
		})
		assert.True(t, contains(got, token_scopes.Server_Admin))
	})

	t.Run("UserAdmin / CollectionAdmin variants don't auto-imply admin", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_UserAdminUsers.Set([]string{"dan"}))

		got := EffectiveScopesForIdentity(UserIdentity{
			Username: "dan", ID: "u-dan",
		})
		assert.True(t, contains(got, token_scopes.Server_UserAdmin))
		assert.False(t, contains(got, token_scopes.Server_Admin),
			"the user_admin → admin direction must NOT be implied")
		assert.False(t, contains(got, token_scopes.Server_CollectionAdmin),
			"user_admin must not imply collection_admin")
	})

	t.Run("DB-stored grants combine with config grants and dedupe", func(t *testing.T) {
		db := setupScopesTestDB(t)
		require.NoError(t, db.Create(&database.User{
			ID: "u-eve", Username: "eve", Sub: "eve", Issuer: "local",
		}).Error)
		require.NoError(t, database.GrantUserScope(db, "u-eve",
			token_scopes.Server_CollectionAdmin, database.CreatorSelf()))

		// Eve also picks up user_admin via config.
		require.NoError(t, param.Server_UserAdminUsers.Set([]string{"eve"}))

		got := EffectiveScopesForIdentity(UserIdentity{
			Username: "eve", ID: "u-eve",
		})
		assert.True(t, contains(got, token_scopes.Server_CollectionAdmin))
		assert.True(t, contains(got, token_scopes.Server_UserAdmin))

		// No duplicates — counted because the API contract is a set.
		seen := map[token_scopes.TokenScope]int{}
		for _, s := range got {
			seen[s]++
		}
		for s, n := range seen {
			assert.LessOrEqualf(t, n, 1, "scope %s appears %d times", s, n)
		}
	})

	t.Run("Removing config name immediately revokes the scope", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{"frank"}))

		identity := UserIdentity{Username: "frank", ID: "u-frank"}
		require.True(t, contains(EffectiveScopesForIdentity(identity), token_scopes.Server_Admin),
			"sanity: frank should be admin while listed")

		// Take frank back off the config list; per the design contract
		// (no config-to-DB backfill) this MUST take effect immediately.
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{}))
		got := EffectiveScopesForIdentity(identity)
		assert.False(t, contains(got, token_scopes.Server_Admin),
			"removing a name from the config must revoke the privilege live")
	})
}

func TestCheckHelpersConsultEffectiveScopes(t *testing.T) {
	setupScopesTestDB(t)

	t.Run("CheckAdmin true for builtin admin", func(t *testing.T) {
		ok, _ := CheckAdmin(UserIdentity{Username: "admin"})
		assert.True(t, ok)
	})

	t.Run("CheckAdmin true via UIAdminUsers", func(t *testing.T) {
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{"alice"}))
		ok, _ := CheckAdmin(UserIdentity{Username: "alice", ID: "u-alice"})
		assert.True(t, ok)
	})

	t.Run("CheckAdmin false when Username doesn't match (ID/Sub equality is irrelevant)", func(t *testing.T) {
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{"alice"}))
		// ID == "alice" must NOT elevate; this catches the security
		// regression CheckAdmin used to have.
		ok, _ := CheckAdmin(UserIdentity{Username: "bob", ID: "alice", Sub: "alice"})
		assert.False(t, ok)
	})

	t.Run("CheckUserAdmin true via admin implication", func(t *testing.T) {
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{"alice"}))
		ok, _ := CheckUserAdmin(UserIdentity{Username: "alice"})
		assert.True(t, ok, "admin must satisfy CheckUserAdmin via implication")
	})

	t.Run("CheckCollectionAdmin true via admin implication", func(t *testing.T) {
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{"alice"}))
		ok, _ := CheckCollectionAdmin(UserIdentity{Username: "alice"})
		assert.True(t, ok)
	})

	t.Run("CheckUserAdmin true via UserAdminUsers but CheckAdmin remains false", func(t *testing.T) {
		require.NoError(t, param.Server_UserAdminUsers.Set([]string{"dan"}))
		ok, _ := CheckUserAdmin(UserIdentity{Username: "dan"})
		assert.True(t, ok)
		full, _ := CheckAdmin(UserIdentity{Username: "dan"})
		assert.False(t, full, "user-admin must not auto-promote to system admin")
	})
}

// TestCheckHelpersHonorAdminGroupsConfig pins the audit gap noted in
// the OIDC-group propagation review: a user whose ONLY admin signal
// is membership in a group named in the *_AdminGroups config (with
// the membership asserted via the cookie's wlcg.groups claim — i.e.
// no DB user_scopes / group_scopes row, no UIAdminUsers username
// match) must still pass the corresponding Check*Admin helper.
//
// We exercise each *Groups config independently so a regression in
// any one of them surfaces as a failure tied to that specific config
// key, rather than the bundle test failing with a single line that
// hides which path broke.
func TestCheckHelpersHonorAdminGroupsConfig(t *testing.T) {
	t.Run("AdminGroups via cookie groups grants CheckAdmin (and via implication, the rest)", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_AdminGroups.Set([]string{"sysadmins"}))

		identity := UserIdentity{
			Username: "carol",
			ID:       "u-carol",
			Groups:   []string{"sysadmins"},
		}
		// Web admin on the strength of the AdminGroups match alone.
		ok, _ := CheckAdmin(identity)
		assert.True(t, ok, "AdminGroups membership asserted via cookie groups must satisfy CheckAdmin")
		// Implication chain: admin → user_admin AND collection_admin.
		// This is the integration the audit specifically called out:
		// Server.AdminGroups feeds into the collection-admin gate via
		// the implication, not via a direct collection_admin grant.
		ua, _ := CheckUserAdmin(identity)
		assert.True(t, ua, "admin (from AdminGroups) must imply user_admin via Check helpers")
		ca, _ := CheckCollectionAdmin(identity)
		assert.True(t, ca, "admin (from AdminGroups) must imply collection_admin via Check helpers")
	})

	t.Run("UserAdminGroups via cookie groups grants only CheckUserAdmin", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_UserAdminGroups.Set([]string{"useradmins"}))

		identity := UserIdentity{
			Username: "erin",
			ID:       "u-erin",
			Groups:   []string{"useradmins"},
		}
		ua, _ := CheckUserAdmin(identity)
		assert.True(t, ua)
		// user_admin must NOT promote to admin or collection_admin —
		// the implication arrow only points downward from admin.
		full, _ := CheckAdmin(identity)
		assert.False(t, full, "user_admin must not promote to admin")
		ca, _ := CheckCollectionAdmin(identity)
		assert.False(t, ca, "user_admin must not promote to collection_admin")
	})

	t.Run("CollectionAdminGroups via cookie groups grants only CheckCollectionAdmin", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_CollectionAdminGroups.Set([]string{"colladmins"}))

		identity := UserIdentity{
			Username: "frank",
			ID:       "u-frank",
			Groups:   []string{"colladmins"},
		}
		ca, _ := CheckCollectionAdmin(identity)
		assert.True(t, ca)
		// Same containment as above, the other direction.
		full, _ := CheckAdmin(identity)
		assert.False(t, full, "collection_admin must not promote to admin")
		ua, _ := CheckUserAdmin(identity)
		assert.False(t, ua, "collection_admin must not promote to user_admin")
	})

	t.Run("Cookie group not matching any config name confers nothing", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_AdminGroups.Set([]string{"sysadmins"}))

		// Same shape as the success case but the asserted group name
		// differs from the configured one — guards against accidental
		// loose-prefix / case-insensitive matching regressions.
		identity := UserIdentity{
			Username: "greta",
			ID:       "u-greta",
			Groups:   []string{"SYSADMINS", "sysadmins-readonly"},
		}
		ok, _ := CheckAdmin(identity)
		assert.False(t, ok, "config-group match must be exact / case-sensitive")
	})

	t.Run("Removing the config group revokes the privilege immediately", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_AdminGroups.Set([]string{"sysadmins"}))

		identity := UserIdentity{
			Username: "henry",
			ID:       "u-henry",
			Groups:   []string{"sysadmins"},
		}
		require.True(t, mustCheckCollectionAdmin(identity),
			"sanity: should be admin while listed")

		// Per the design contract (no config-to-DB backfill) clearing
		// the AdminGroups list must take effect immediately, even for
		// the implication-derived collection_admin.
		require.NoError(t, param.Server_AdminGroups.Set([]string{}))
		assert.False(t, mustCheckCollectionAdmin(identity),
			"removing the AdminGroups entry must revoke the implied collection_admin live")
	})
}

// mustCheckCollectionAdmin is a tiny helper that drops the message
// return value at call sites where only the bool matters. Keeps the
// "live revocation" test legible.
func mustCheckCollectionAdmin(identity UserIdentity) bool {
	ok, _ := CheckCollectionAdmin(identity)
	return ok
}
