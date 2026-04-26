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
)

// groupAuthzFixtures sets up a small cast for the ownership /
// management / deletion tests:
//
//	owner       — owns "ops"
//	admin       — assigned as group_admin (admin_type=user) on "ops"
//	groupAdmin  — member of "ops-admins"; ops's admin_type=group/admin_id=ops-admins
//	member      — member of "ops" with no admin role
//	stranger    — unrelated user
//
// Two groups are created: "ops" (owned by owner; admin tracked via
// adminType+adminID; populated via group_members) and "ops-admins"
// (owned by owner). Each subtest can assert how each role's privileges
// shake out for the relevant operation.
type groupAuthzFixtures struct {
	ownerID, adminID, groupAdminID, memberID, strangerID string
	opsID, opsAdminsID                                   string
	opsName, opsAdminsName                               string
}

func seedGroupAuthzFixtures(t *testing.T, db *gorm.DB) groupAuthzFixtures {
	t.Helper()
	users := []User{
		{ID: "u-owner", Username: "owner", Sub: "owner", Issuer: "local", Status: UserStatusActive},
		{ID: "u-admin", Username: "alice-admin", Sub: "alice-admin", Issuer: "local", Status: UserStatusActive},
		{ID: "u-gadmin", Username: "carol-gadmin", Sub: "carol-gadmin", Issuer: "local", Status: UserStatusActive},
		{ID: "u-member", Username: "dave-member", Sub: "dave-member", Issuer: "local", Status: UserStatusActive},
		{ID: "u-stranger", Username: "eve-stranger", Sub: "eve-stranger", Issuer: "local", Status: UserStatusActive},
	}
	for i := range users {
		require.NoError(t, db.Create(&users[i]).Error)
	}

	// "ops-admins" — admins-by-membership for the ops group.
	opsAdmins := Group{
		ID: "g-ops-admins", Name: "ops-admins",
		CreatedBy: "u-owner", OwnerID: "u-owner",
	}
	require.NoError(t, db.Create(&opsAdmins).Error)
	require.NoError(t, db.Create(&GroupMember{
		GroupID: "g-ops-admins", UserID: "u-gadmin", AddedBy: "u-owner",
	}).Error)

	// "ops" — primary fixture. admin_type=user/admin_id points at the
	// user-typed admin; we'll flip to group-typed in the subtests
	// that need it.
	ops := Group{
		ID: "g-ops", Name: "ops",
		CreatedBy: "u-owner", OwnerID: "u-owner",
		AdminType: AdminTypeUser, AdminID: "u-admin",
	}
	require.NoError(t, db.Create(&ops).Error)
	require.NoError(t, db.Create(&GroupMember{
		GroupID: "g-ops", UserID: "u-member", AddedBy: "u-owner",
	}).Error)

	return groupAuthzFixtures{
		ownerID: "u-owner", adminID: "u-admin", groupAdminID: "u-gadmin",
		memberID: "u-member", strangerID: "u-stranger",
		opsID: "g-ops", opsAdminsID: "g-ops-admins",
		opsName: "ops", opsAdminsName: "ops-admins",
	}
}

// TestCanManageGroup walks through every role's view of the
// "can manage members and invite links" capability.
func TestCanManageGroup(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)

	loadOps := func(t *testing.T) *Group {
		t.Helper()
		var g Group
		require.NoError(t, db.First(&g, "id = ?", fx.opsID).Error)
		return &g
	}

	t.Run("owner can manage", func(t *testing.T) {
		assert.True(t, CanManageGroup(db, loadOps(t), fx.ownerID, false))
	})

	t.Run("user-typed group admin can manage", func(t *testing.T) {
		assert.True(t, CanManageGroup(db, loadOps(t), fx.adminID, false))
	})

	t.Run("group-typed admin: member of admin group can manage", func(t *testing.T) {
		// Switch ops's admin to the admin-group form for this case.
		require.NoError(t, db.Model(&Group{}).Where("id = ?", fx.opsID).
			Updates(map[string]interface{}{
				"admin_type": AdminTypeGroup,
				"admin_id":   fx.opsAdminsID,
			}).Error)
		assert.True(t, CanManageGroup(db, loadOps(t), fx.groupAdminID, false))
		// Restore the user-typed admin shape so later subtests start clean.
		require.NoError(t, db.Model(&Group{}).Where("id = ?", fx.opsID).
			Updates(map[string]interface{}{
				"admin_type": AdminTypeUser,
				"admin_id":   fx.adminID,
			}).Error)
	})

	t.Run("plain member cannot manage", func(t *testing.T) {
		assert.False(t, CanManageGroup(db, loadOps(t), fx.memberID, false),
			"membership alone must not confer management privileges")
	})

	t.Run("stranger cannot manage", func(t *testing.T) {
		assert.False(t, CanManageGroup(db, loadOps(t), fx.strangerID, false))
	})

	t.Run("system admin always can", func(t *testing.T) {
		assert.True(t, CanManageGroup(db, loadOps(t), fx.strangerID, true),
			"isSystemAdmin=true must short-circuit to allow")
	})
}

// TestCanSeeGroup covers the read-side gate: who can see the group at
// all. Includes the OIDC-asserted-name path that the design contract
// requires for federated group membership.
func TestCanSeeGroup(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)

	var ops Group
	require.NoError(t, db.First(&ops, "id = ?", fx.opsID).Error)

	t.Run("owner sees", func(t *testing.T) {
		assert.True(t, CanSeeGroup(db, &ops, fx.ownerID, false, nil))
	})
	t.Run("admin sees", func(t *testing.T) {
		assert.True(t, CanSeeGroup(db, &ops, fx.adminID, false, nil))
	})
	t.Run("DB-row member sees", func(t *testing.T) {
		assert.True(t, CanSeeGroup(db, &ops, fx.memberID, false, nil))
	})
	t.Run("OIDC-asserted member sees", func(t *testing.T) {
		// Stranger has no DB membership; the cookie asserted "ops".
		assert.True(t, CanSeeGroup(db, &ops, fx.strangerID, false, []string{fx.opsName}),
			"a wlcg.groups assertion of an existing group's name confers visibility")
	})
	t.Run("OIDC asserting a non-existent group does NOT confer visibility on a different group", func(t *testing.T) {
		assert.False(t, CanSeeGroup(db, &ops, fx.strangerID, false, []string{"phantom"}))
	})
	t.Run("plain stranger cannot see", func(t *testing.T) {
		assert.False(t, CanSeeGroup(db, &ops, fx.strangerID, false, nil))
	})
	t.Run("system admin always sees", func(t *testing.T) {
		assert.True(t, CanSeeGroup(db, &ops, fx.strangerID, true, nil))
	})
}

// TestUpdateGroupAuthz: name changes are system-admin-only; display
// name and description are owner-or-admin-or-system-admin.
func TestUpdateGroupAuthz(t *testing.T) {
	t.Run("name change requires system admin", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		newName := "ops-renamed"

		// Owner — not enough.
		err := UpdateGroup(db, fx.opsID, &newName, nil, nil, fx.ownerID, false)
		assert.ErrorIs(t, err, ErrForbidden,
			"the group's owner must NOT be allowed to rename the group")

		// System admin — allowed.
		require.NoError(t,
			UpdateGroup(db, fx.opsID, &newName, nil, nil, fx.strangerID, true))

		var g Group
		require.NoError(t, db.First(&g, "id = ?", fx.opsID).Error)
		assert.Equal(t, newName, g.Name)
	})

	t.Run("display name change owner-allowed", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		dn := "Operations Team"
		require.NoError(t, UpdateGroup(db, fx.opsID, nil, &dn, nil, fx.ownerID, false))
	})

	t.Run("display name change rejected for stranger", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		dn := "I should not be allowed"
		err := UpdateGroup(db, fx.opsID, nil, &dn, nil, fx.strangerID, false)
		assert.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("display name change rejected for plain member", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		dn := "Members shouldn't"
		err := UpdateGroup(db, fx.opsID, nil, &dn, nil, fx.memberID, false)
		assert.ErrorIs(t, err, ErrForbidden,
			"plain membership must not confer the right to edit the group label")
	})

	t.Run("name change rejects reserved 'user-' prefix", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		bad := "user-foo"
		err := UpdateGroup(db, fx.opsID, &bad, nil, nil, fx.strangerID, true)
		assert.ErrorIs(t, err, ErrReservedGroupPrefix)
	})

	t.Run("name change rejects invalid identifier", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		bad := "ops/admin"
		err := UpdateGroup(db, fx.opsID, &bad, nil, nil, fx.strangerID, true)
		assert.ErrorIs(t, err, ErrInvalidIdentifier,
			"slashes are banned in group names")
	})
}

// TestUpdateGroupOwnershipAuthz: ONLY the owner (or system admin) may
// reassign ownership or admin. Group admins cannot.
func TestUpdateGroupOwnershipAuthz(t *testing.T) {
	t.Run("group admin cannot transfer ownership", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		err := UpdateGroupOwnership(db, fx.opsID, &fx.adminID, nil, nil, fx.adminID, false)
		assert.ErrorIs(t, err, ErrForbidden,
			"a group admin (not owner) must not be able to transfer ownership")
	})

	t.Run("owner can transfer ownership", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		// Add member as the new owner candidate (must be a real user).
		require.NoError(t,
			UpdateGroupOwnership(db, fx.opsID, &fx.memberID, nil, nil, fx.ownerID, false))
		var g Group
		require.NoError(t, db.First(&g, "id = ?", fx.opsID).Error)
		assert.Equal(t, fx.memberID, g.OwnerID)
	})

	t.Run("system admin can transfer ownership", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		require.NoError(t,
			UpdateGroupOwnership(db, fx.opsID, &fx.memberID, nil, nil, fx.strangerID, true))
	})

	t.Run("transfer to a non-existent user errors out", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		bogus := "u-does-not-exist"
		err := UpdateGroupOwnership(db, fx.opsID, &bogus, nil, nil, fx.ownerID, false)
		assert.Error(t, err,
			"server must reject an ownership transfer pointed at a non-existent user")
	})
}

// TestDeleteGroupAuthz: only the owner or a system admin can delete.
func TestDeleteGroupAuthz(t *testing.T) {
	t.Run("group admin cannot delete", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		err := DeleteGroup(db, fx.opsID, fx.adminID, false)
		assert.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("plain member cannot delete", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		err := DeleteGroup(db, fx.opsID, fx.memberID, false)
		assert.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("owner can delete", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		require.NoError(t, DeleteGroup(db, fx.opsID, fx.ownerID, false))
		// Group is gone.
		var g Group
		err := db.First(&g, "id = ?", fx.opsID).Error
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
		// And memberships are cleaned up.
		var count int64
		require.NoError(t, db.Model(&GroupMember{}).Where("group_id = ?", fx.opsID).Count(&count).Error)
		assert.Zero(t, count)
	})

	t.Run("system admin can delete a group they don't own", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		require.NoError(t, DeleteGroup(db, fx.opsID, fx.strangerID, true))
	})
}

// TestLeaveGroupOwnerGuard: a group's owner cannot just leave —
// they'd orphan the group.
func TestLeaveGroupOwnerGuard(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)

	t.Run("owner cannot leave", func(t *testing.T) {
		// First make the owner a member; LeaveGroup keys off member rows.
		require.NoError(t, db.Create(&GroupMember{
			GroupID: fx.opsID, UserID: fx.ownerID, AddedBy: fx.ownerID,
		}).Error)
		err := LeaveGroup(db, fx.opsID, fx.ownerID)
		assert.ErrorIs(t, err, ErrForbidden,
			"owner must transfer ownership before leaving")
	})

	t.Run("non-owner member can leave", func(t *testing.T) {
		require.NoError(t, LeaveGroup(db, fx.opsID, fx.memberID))
		// Verify membership was removed.
		var count int64
		require.NoError(t, db.Model(&GroupMember{}).
			Where("group_id = ? AND user_id = ?", fx.opsID, fx.memberID).
			Count(&count).Error)
		assert.Zero(t, count)
	})

	t.Run("non-member leaving returns NotFound", func(t *testing.T) {
		err := LeaveGroup(db, fx.opsID, fx.strangerID)
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
	})
}

// TestAddRemoveGroupMemberAuthz: only owners/admins/system-admins
// can mutate the membership list.
func TestAddRemoveGroupMemberAuthz(t *testing.T) {
	t.Run("plain member cannot add others", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		err := AddGroupMember(db, fx.opsID, fx.strangerID, fx.memberID, false)
		assert.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("group admin can add", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		require.NoError(t, AddGroupMember(db, fx.opsID, fx.strangerID, fx.adminID, false))
	})

	t.Run("owner can add", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		require.NoError(t, AddGroupMember(db, fx.opsID, fx.strangerID, fx.ownerID, false))
	})

	t.Run("adding nonexistent user errors out", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		err := AddGroupMember(db, fx.opsID, "u-bogus", fx.ownerID, false)
		assert.Error(t, err)
	})

	t.Run("plain member cannot remove others", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		err := RemoveGroupMember(db, fx.opsID, fx.memberID, fx.strangerID, false)
		assert.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("admin can remove", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		require.NoError(t, RemoveGroupMember(db, fx.opsID, fx.memberID, fx.adminID, false))
	})
}

// TestDeleteUserAuthz: a user can delete themselves; otherwise the
// caller must be a system admin (the user-admin path lives in the
// HTTP handler — DeleteUser itself only knows "is this caller a
// system admin?").
func TestDeleteUserAuthz(t *testing.T) {
	t.Run("self-delete allowed", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		require.NoError(t, DeleteUser(db, fx.strangerID, fx.strangerID, false))
	})

	t.Run("non-self non-admin denied", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		err := DeleteUser(db, fx.memberID, fx.strangerID, false)
		assert.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("system admin can delete any user", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		fx := seedGroupAuthzFixtures(t, db)
		require.NoError(t, DeleteUser(db, fx.memberID, fx.strangerID, true))
	})
}

// (User-creation, rename, and identifier-validation coverage lives in
// users_test.go alongside the rest of the user-CRUD suite.)
