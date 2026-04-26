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

	t.Run("builtin admin username gets web_admin (and implications)", func(t *testing.T) {
		setupScopesTestDB(t)

		got := EffectiveScopesForIdentity(UserIdentity{Username: "admin"})
		assert.True(t, contains(got, token_scopes.Server_WebAdmin))
		assert.True(t, contains(got, token_scopes.Server_UserAdmin),
			"server.web_admin must imply server.user_admin")
		assert.True(t, contains(got, token_scopes.Server_CollectionAdmin),
			"server.web_admin must imply server.collection_admin")
	})

	t.Run("UIAdminUsers username match grants web_admin", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{"alice"}))

		got := EffectiveScopesForIdentity(UserIdentity{
			Username: "alice", ID: "u-alice",
		})
		assert.True(t, contains(got, token_scopes.Server_WebAdmin))

		// Same user with a non-matching username doesn't get the scope —
		// catches accidental ID/Sub matching regressions.
		none := EffectiveScopesForIdentity(UserIdentity{
			Username: "bob", ID: "u-alice", Sub: "alice",
		})
		assert.False(t, contains(none, token_scopes.Server_WebAdmin),
			"admin lists must match Username, never ID or Sub")
	})

	t.Run("AdminGroups match grants web_admin via cookie groups", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_AdminGroups.Set([]string{"sysadmins"}))

		got := EffectiveScopesForIdentity(UserIdentity{
			Username: "carol", ID: "u-carol", Groups: []string{"sysadmins"},
		})
		assert.True(t, contains(got, token_scopes.Server_WebAdmin))
	})

	t.Run("UserAdmin / CollectionAdmin variants don't auto-imply web_admin", func(t *testing.T) {
		setupScopesTestDB(t)
		require.NoError(t, param.Server_UserAdminUsers.Set([]string{"dan"}))

		got := EffectiveScopesForIdentity(UserIdentity{
			Username: "dan", ID: "u-dan",
		})
		assert.True(t, contains(got, token_scopes.Server_UserAdmin))
		assert.False(t, contains(got, token_scopes.Server_WebAdmin),
			"the user_admin → web_admin direction must NOT be implied")
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
		require.True(t, contains(EffectiveScopesForIdentity(identity), token_scopes.Server_WebAdmin),
			"sanity: frank should be admin while listed")

		// Take frank back off the config list; per the design contract
		// (no config-to-DB backfill) this MUST take effect immediately.
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{}))
		got := EffectiveScopesForIdentity(identity)
		assert.False(t, contains(got, token_scopes.Server_WebAdmin),
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

	t.Run("CheckUserAdmin true via web_admin implication", func(t *testing.T) {
		require.NoError(t, param.Server_UIAdminUsers.Set([]string{"alice"}))
		ok, _ := CheckUserAdmin(UserIdentity{Username: "alice"})
		assert.True(t, ok, "web_admin must satisfy CheckUserAdmin via implication")
	})

	t.Run("CheckCollectionAdmin true via web_admin implication", func(t *testing.T) {
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
