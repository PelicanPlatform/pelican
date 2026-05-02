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

package database

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/token_scopes"
)

// scopeContains returns true when the slice contains the supplied
// scope. Defined locally so the test reads "the scope set should
// contain X" without callers needing to write a loop each time.
func scopeContains(scopes []token_scopes.TokenScope, target token_scopes.TokenScope) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// seedScopeFixtures creates a stable set of users and groups for the
// scope-resolution tests. Returns identifiers callers index with so
// each subtest stays focused on the assertion rather than setup.
type scopeFixtures struct {
	aliceID   string // direct grant target
	bobID     string // member of "ops" group
	carolID   string // OIDC-asserted member of "ops" (no DB membership row)
	danID     string // unrelated user, no grants
	opsID     string // group ID
	opsName   string // group name (used by OIDC assertion)
	otherName string // group present in DB but with no scopes — sanity case
}

func seedScopeFixtures(t *testing.T, db *gorm.DB) scopeFixtures {
	t.Helper()
	users := []User{
		{ID: "u-alice", Username: "alice", Sub: "alice", Issuer: "local", Status: UserStatusActive},
		{ID: "u-bob", Username: "bob", Sub: "bob", Issuer: "local", Status: UserStatusActive},
		{ID: "u-carol", Username: "carol", Sub: "carol", Issuer: "local", Status: UserStatusActive},
		{ID: "u-dan", Username: "dan", Sub: "dan", Issuer: "local", Status: UserStatusActive},
	}
	for i := range users {
		require.NoError(t, db.Create(&users[i]).Error)
	}

	ops := Group{ID: "g-ops", Name: "ops", CreatedBy: "u-alice", OwnerID: "u-alice"}
	other := Group{ID: "g-other", Name: "other", CreatedBy: "u-alice", OwnerID: "u-alice"}
	require.NoError(t, db.Create(&ops).Error)
	require.NoError(t, db.Create(&other).Error)

	require.NoError(t, db.Create(&GroupMember{
		GroupID: "g-ops", UserID: "u-bob", AddedBy: "u-alice",
	}).Error)

	return scopeFixtures{
		aliceID:   "u-alice",
		bobID:     "u-bob",
		carolID:   "u-carol",
		danID:     "u-dan",
		opsID:     "g-ops",
		opsName:   "ops",
		otherName: "other",
	}
}

func TestEffectiveScopes(t *testing.T) {
	t.Run("empty for unknown user with no external groups", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		seedScopeFixtures(t, db)

		got, err := EffectiveScopes(db, "no-such-user", nil)
		require.NoError(t, err)
		assert.Empty(t, got, "user without any scope source should return zero scopes")
	})

	t.Run("nil userID + no external groups returns nil cleanly", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		got, err := EffectiveScopes(db, "", nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("direct user_scopes grant surfaces", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)
		require.NoError(t, GrantUserScope(db, fx.aliceID,
			token_scopes.Server_UserAdmin, CreatorSelf()))

		got, err := EffectiveScopes(db, fx.aliceID, nil)
		require.NoError(t, err)
		assert.True(t, scopeContains(got, token_scopes.Server_UserAdmin))
		assert.False(t, scopeContains(got, token_scopes.Server_Admin),
			"granting user_admin must NOT imply admin (implication is admin -> others)")
	})

	t.Run("group_scopes via DB membership", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)
		require.NoError(t, GrantGroupScope(db, fx.opsID,
			token_scopes.Server_CollectionAdmin, CreatorSelf()))

		got, err := EffectiveScopes(db, fx.bobID, nil)
		require.NoError(t, err)
		assert.True(t, scopeContains(got, token_scopes.Server_CollectionAdmin),
			"bob is a row-member of ops; should inherit ops's scopes")

		// Dan isn't in the group; should not see the scope.
		got2, err := EffectiveScopes(db, fx.danID, nil)
		require.NoError(t, err)
		assert.Empty(t, got2)
	})

	t.Run("group_scopes via OIDC-asserted name only", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)
		require.NoError(t, GrantGroupScope(db, fx.opsID,
			token_scopes.Server_CollectionAdmin, CreatorSelf()))

		// Carol has NO group_members row; the OIDC cookie asserted ops.
		got, err := EffectiveScopes(db, fx.carolID, []string{fx.opsName})
		require.NoError(t, err)
		assert.True(t, scopeContains(got, token_scopes.Server_CollectionAdmin),
			"OIDC-asserted membership must confer the group's scopes")
	})

	t.Run("OIDC-asserted name not matching any group is ignored", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)

		got, err := EffectiveScopes(db, fx.danID, []string{"phantom-group"})
		require.NoError(t, err)
		assert.Empty(t, got,
			"a name that doesn't resolve to a real group must not synthesize scopes")
	})

	t.Run("union dedupes across direct + group sources", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)

		require.NoError(t, GrantUserScope(db, fx.bobID,
			token_scopes.Server_UserAdmin, CreatorSelf()))
		require.NoError(t, GrantGroupScope(db, fx.opsID,
			token_scopes.Server_UserAdmin, CreatorSelf()))

		got, err := EffectiveScopes(db, fx.bobID, []string{fx.opsName})
		require.NoError(t, err)

		count := 0
		for _, s := range got {
			if s == token_scopes.Server_UserAdmin {
				count++
			}
		}
		assert.Equal(t, 1, count, "scope returned by 3 paths should dedupe to 1 entry")
	})

	t.Run("ungrantable scope stored historically is filtered out", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)

		// Bypass the public Grant* helpers (which validate) and write
		// a row directly — simulating either an older row from before
		// the allow-list was tightened or a concurrent admin tool
		// that stored an unsupported scope.
		require.NoError(t, db.Create(&UserScope{
			UserID: fx.aliceID,
			Scope:  token_scopes.Wlcg_Storage_Read,
		}).Error)

		got, err := EffectiveScopes(db, fx.aliceID, nil)
		require.NoError(t, err)
		assert.False(t, scopeContains(got, token_scopes.Wlcg_Storage_Read),
			"data-plane scope must be filtered out by IsUserGrantable")
	})

	t.Run("revoke removes only the named row", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)
		require.NoError(t, GrantUserScope(db, fx.aliceID,
			token_scopes.Server_UserAdmin, CreatorSelf()))
		require.NoError(t, GrantUserScope(db, fx.aliceID,
			token_scopes.Server_CollectionAdmin, CreatorSelf()))

		require.NoError(t, RevokeUserScope(db, fx.aliceID, token_scopes.Server_UserAdmin))

		got, err := EffectiveScopes(db, fx.aliceID, nil)
		require.NoError(t, err)
		assert.False(t, scopeContains(got, token_scopes.Server_UserAdmin))
		assert.True(t, scopeContains(got, token_scopes.Server_CollectionAdmin),
			"revoke must remove only the named scope, not the user's other grants")
	})

	t.Run("revoke of a nonexistent grant returns ErrRecordNotFound", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)
		err := RevokeUserScope(db, fx.aliceID, token_scopes.Server_Admin)
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound),
			"revoke of a never-granted scope is a 'noop revoke' and must signal that to the caller")
	})

	t.Run("grant rejects ungrantable scope", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)
		err := GrantUserScope(db, fx.aliceID, token_scopes.Wlcg_Storage_Read, CreatorSelf())
		assert.ErrorIs(t, err, ErrUngrantableScope,
			"data-plane scopes must not be persistable through the management API")

		// And nothing was written.
		rows, err2 := ListUserScopes(db, fx.aliceID)
		require.NoError(t, err2)
		assert.Empty(t, rows)
	})

	t.Run("grant rejects empty user/group ID", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		assert.Error(t, GrantUserScope(db, "", token_scopes.Server_UserAdmin, CreatorSelf()))
		assert.Error(t, GrantGroupScope(db, "", token_scopes.Server_UserAdmin, CreatorSelf()))
	})

	t.Run("HasEffectiveScope is consistent with EffectiveScopes", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedScopeFixtures(t, db)
		require.NoError(t, GrantGroupScope(db, fx.opsID,
			token_scopes.Server_UserAdmin, CreatorSelf()))

		assert.True(t, HasEffectiveScope(db, fx.bobID, nil, token_scopes.Server_UserAdmin))
		assert.False(t, HasEffectiveScope(db, fx.bobID, nil, token_scopes.Server_Admin))
		assert.False(t, HasEffectiveScope(db, fx.danID, nil, token_scopes.Server_UserAdmin))
	})
}

func TestGrantUserScopeIdempotent(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedScopeFixtures(t, db)
	require.NoError(t, GrantUserScope(db, fx.aliceID,
		token_scopes.Server_UserAdmin, CreatorSelf()))
	// Granting the same scope a second time must NOT error.
	require.NoError(t, GrantUserScope(db, fx.aliceID,
		token_scopes.Server_UserAdmin, CreatorSelf()))

	rows, err := ListUserScopes(db, fx.aliceID)
	require.NoError(t, err)
	assert.Len(t, rows, 1, "idempotent grant must keep a single row")
}

func TestGrantGroupScopeIdempotent(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedScopeFixtures(t, db)
	require.NoError(t, GrantGroupScope(db, fx.opsID,
		token_scopes.Server_CollectionAdmin, CreatorSelf()))
	require.NoError(t, GrantGroupScope(db, fx.opsID,
		token_scopes.Server_CollectionAdmin, CreatorSelf()))

	rows, err := ListGroupScopes(db, fx.opsID)
	require.NoError(t, err)
	assert.Len(t, rows, 1)
}
