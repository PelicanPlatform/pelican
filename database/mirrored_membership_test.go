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

// A mirrored membership is a CACHED authorization fact, which is the
// same shape as the bug this branch exists to remove — authority
// outliving what it was derived from. What keeps it honest is a single
// asymmetry, and these tests pin it:
//
//	freshness gates GRANTING, not existence.
//
// A stale copy must not hand out access, and must still be visible to a
// check that asks whether an account might HOLD a privilege — because
// there, treating a stale copy as absence is what opens the guard.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// ageMembership backdates a mirrored membership's asserted_at, standing
// in for "the provider last said this a long time ago".
func ageMembership(t *testing.T, db *gorm.DB, groupID, userID string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	res := db.Model(&GroupMember{}).
		Where("group_id = ? AND user_id = ?", groupID, userID).
		Update("asserted_at", when)
	require.NoError(t, res.Error)
	require.EqualValues(t, 1, res.RowsAffected)
}

func withMembershipTTL(t *testing.T, ttl time.Duration) {
	t.Helper()
	prev := param.Issuer_AssertedGroupMembershipTTL.GetDuration()
	t.Cleanup(func() { require.NoError(t, param.Issuer_AssertedGroupMembershipTTL.Set(prev)) })
	require.NoError(t, param.Issuer_AssertedGroupMembershipTTL.Set(ttl))
}

func TestMirroredMembershipFreshnessGatesGranting(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	withMembershipTTL(t, time.Hour)

	alice := mkUser(t, db, "u-alice", "alice")
	owner := mkUser(t, db, "u-owner", "owner")
	coll := mkCollection(t, db, "c1", "data", owner.ID)

	require.NoError(t, EnsureAssertedGroups(db, GroupSourceOIDC, []string{"ops"}))
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
	require.NoError(t, GrantCollectionAcl(db, coll.ID, owner.Username, owner.ID, nil,
		"ops", AclRoleRead, nil, false))
	require.NoError(t, GrantGroupScope(db, ops.ID, token_scopes.Server_CollectionAdmin, CreatorSelf()))

	t.Run("a fresh copy grants", func(t *testing.T) {
		// No asserted group names passed: this is the offline case —
		// deciding about a user who is not the one making the request.
		assert.NoError(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID, nil,
			token_scopes.Collection_Read))
		scopes, err := EffectiveScopes(db, alice.ID, nil)
		require.NoError(t, err)
		assert.Contains(t, scopes, token_scopes.Server_CollectionAdmin)
	})

	t.Run("a stale copy does not", func(t *testing.T) {
		ageMembership(t, db, ops.ID, alice.ID, 2*time.Hour)

		assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID, nil,
			token_scopes.Collection_Read), ErrForbidden,
			"a membership the provider has not confirmed inside the TTL must not hand out access")
		scopes, err := EffectiveScopes(db, alice.ID, nil)
		require.NoError(t, err)
		assert.NotContains(t, scopes, token_scopes.Server_CollectionAdmin)
	})

	t.Run("the caller's own live assertion is never gated by the TTL", func(t *testing.T) {
		// The copy is stale, but alice is here and her token says "ops".
		// The TTL bounds a cache, not the provider speaking directly.
		assert.NoError(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID,
			[]string{"ops"}, token_scopes.Collection_Read))
	})

	t.Run("a stale copy is kept, not deleted", func(t *testing.T) {
		names, err := GroupNamesForRestrictionCheck(db, alice.ID)
		require.NoError(t, err)
		assert.Contains(t, names, "ops",
			"a restricting check must still see it; expiry governs granting, not retention")
	})

	t.Run("re-asserting revives it", func(t *testing.T) {
		require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
		assert.NoError(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID, nil,
			token_scopes.Collection_Read))
	})

	t.Run("a TTL of zero disables mirrored memberships as an authz input", func(t *testing.T) {
		withMembershipTTL(t, 0)
		assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID, nil,
			token_scopes.Collection_Read), ErrForbidden)
		// ...while an administrator's own membership is unaffected: it
		// is not a cached fact and does not expire.
		require.NoError(t, AddGroupMember(db, ops.ID, owner.ID, owner.ID, true))
		assert.NoError(t, validateACL(db, reload(t, db, coll.ID), owner.Username, owner.ID, nil,
			token_scopes.Collection_Read))
	})
}

// The motivating offline case: a share's data-plane scopes are clamped
// by what the SHARE OWNER can currently do on the parent collection,
// computed at token-mint time with no session for that owner. Before
// memberships were mirrored, an owner whose access came from an asserted
// group was invisible there and the share silently stopped working.
func TestMirroredMembershipRestoresTheShareOwnerClamp(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	withMembershipTTL(t, time.Hour)

	alice := mkUser(t, db, "u-alice", "alice")
	parentOwner := mkUser(t, db, "u-owner", "owner")
	parent := mkCollection(t, db, "c-parent", "parent", parentOwner.ID)

	// Alice's access to the parent is via an asserted group, and she is
	// not the one asking — the mint path passes no group names.
	require.NoError(t, EnsureAssertedGroups(db, GroupSourceOIDC, []string{"ops"}))
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
	require.NoError(t, GrantCollectionAcl(db, parent.ID, parentOwner.Username, parentOwner.ID, nil,
		"ops", AclRoleWrite, nil, false))

	assert.Equal(t, AclRole(""), EffectiveCollectionRole(db, reload(t, db, parent.ID), alice.ID, ""),
		"with nothing mirrored there is no record of alice's access, so the clamp kills the share")

	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
	assert.Equal(t, AclRoleWrite, EffectiveCollectionRole(db, reload(t, db, parent.ID), alice.ID, ""),
		"a mirrored membership is what lets the clamp see asserted access")

	ageMembership(t, db, ops.ID, alice.ID, 2*time.Hour)
	assert.Equal(t, AclRole(""), EffectiveCollectionRole(db, reload(t, db, parent.ID), alice.ID, ""),
		"and it stops counting once stale, rather than propping the share up forever")
}

func TestMirroredMembershipCannotBeRemovedLocally(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	fx := seedGroupAuthzFixtures(t, db)

	require.NoError(t, EnsureAssertedGroups(db, GroupSourceOIDC, []string{"asserted-team"}))
	var team Group
	require.NoError(t, db.First(&team, "name = ?", "asserted-team").Error)
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, fx.memberID, []string{"asserted-team"}))

	// Neither the member nor an administrator can remove it: the
	// provider still asserts it, so the row would simply come back.
	assert.ErrorIs(t, LeaveGroup(db, team.ID, fx.memberID), ErrMembershipNotLocal)
	assert.ErrorIs(t, RemoveGroupMember(db, team.ID, fx.memberID, fx.ownerID, true), ErrMembershipNotLocal)

	var n int64
	require.NoError(t, db.Model(&GroupMember{}).
		Where("group_id = ? AND user_id = ?", team.ID, fx.memberID).Count(&n).Error)
	assert.EqualValues(t, 1, n)

	// A Pelican membership in the same group is removable as always.
	require.NoError(t, AddGroupMember(db, team.ID, fx.strangerID, fx.ownerID, true))
	assert.NoError(t, RemoveGroupMember(db, team.ID, fx.strangerID, fx.ownerID, true))
}
