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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// The tests in this file cover rename handling for the name-keyed
// collection ACL model:
//
//   - renaming a group rewrites its collection_acls rows to the new name,
//     so nothing is left orphaned for the next claimant; if the new name
//     already appears as an ACL target the rename is refused with
//     ErrACLGrantCollision and nothing moves
//   - renaming a user does the same for the synthesised personal group
//     "user-<username>"
//   - deleting after a rename still cleans up (the rows now sit under the
//     current name)
//   - creating a group whose name already appears as an ACL target (an
//     IdP-asserted group with no local row) is refused with
//     ErrACLGrantCollision

// seedACL plants a name-keyed grant, creating the owning collection row
// on first use (collection_acls.collection_id carries a FK in the
// AutoMigrated test schema).
func seedACL(t *testing.T, db *gorm.DB, collectionID, groupID string, role AclRole, grantedBy string) {
	t.Helper()
	var coll Collection
	require.NoError(t, db.Where(Collection{ID: collectionID}).Attrs(Collection{
		Name:      collectionID,
		Owner:     "test-owner",
		OwnerID:   "test-owner",
		Namespace: "/" + collectionID,
	}).FirstOrCreate(&coll).Error)
	require.NoError(t, db.Create(&CollectionACL{
		CollectionID: collectionID,
		GroupID:      groupID,
		Role:         role,
		GrantedBy:    grantedBy,
	}).Error)
}

func aclRows(t *testing.T, db *gorm.DB, groupID string) []CollectionACL {
	t.Helper()
	var rows []CollectionACL
	require.NoError(t, db.Where("group_id = ?", groupID).Order("collection_id, role").Find(&rows).Error)
	return rows
}

// ---------- group rename ----------

func TestUpdateGroupRenameMigratesACLGrants(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)

	seedACL(t, db, "c1", fx.opsName, AclRoleRead, "u-owner")
	seedACL(t, db, "c1", fx.opsName, AclRoleWrite, "u-owner")
	seedACL(t, db, "c2", fx.opsName, AclRoleRead, "u-owner")
	// An unrelated group's grant must be untouched by the rename.
	seedACL(t, db, "c1", fx.opsAdminsName, AclRoleRead, "u-owner")

	newName := "ops-renamed"
	require.NoError(t, UpdateGroup(db, fx.opsID, &newName, nil, nil, nil, fx.strangerID, true, true))

	assert.Empty(t, aclRows(t, db, fx.opsName), "no grant may remain under the vacated name")
	migrated := aclRows(t, db, newName)
	require.Len(t, migrated, 3)
	assert.Equal(t, "c1", migrated[0].CollectionID)
	assert.Equal(t, AclRoleRead, migrated[0].Role)
	assert.Equal(t, "c1", migrated[1].CollectionID)
	assert.Equal(t, AclRoleWrite, migrated[1].Role)
	assert.Equal(t, "c2", migrated[2].CollectionID)
	assert.Equal(t, AclRoleRead, migrated[2].Role)
	assert.Len(t, aclRows(t, db, fx.opsAdminsName), 1, "unrelated group's grant must survive")

	// The member's effective ACL groups follow the rename, so their
	// access is preserved rather than silently lost.
	groups := ExpandCallerACLGroups(db, "dave-member", fx.memberID, nil)
	assert.Contains(t, groups, newName)
	assert.NotContains(t, groups, fx.opsName)

	// The vacated name is now free: anybody may create a group with it,
	// and doing so inherits nothing.
	reclaimed, err := CreateGroup(db, fx.opsName, "", "", Creator{UserID: fx.strangerID}, "", false)
	require.NoError(t, err)
	require.NoError(t, db.Create(&GroupMember{GroupID: reclaimed.ID, UserID: fx.strangerID, AddedBy: fx.strangerID}).Error)
	strangerGroups := ExpandCallerACLGroups(db, "eve-stranger", fx.strangerID, nil)
	assert.Contains(t, strangerGroups, fx.opsName)
	assert.Empty(t, aclRows(t, db, fx.opsName), "reclaimed name must hold no grants")
}

func TestUpdateGroupRenameRefusesCollidingGrants(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)

	newName := "ops-renamed"
	seedACL(t, db, "c1", fx.opsName, AclRoleRead, "from-old")
	seedACL(t, db, "c2", fx.opsName, AclRoleRead, "from-old")
	// The new name already appears as an ACL target (e.g. granted to an
	// IdP-asserted group of that name). Any such row blocks the rename,
	// whether or not it overlaps the old name's grants.
	seedACL(t, db, "c1", newName, AclRoleRead, "from-new")
	seedACL(t, db, "c3", newName, AclRoleWrite, "from-new")

	err := UpdateGroup(db, fx.opsID, &newName, nil, nil, nil, fx.strangerID, true, true)
	require.ErrorIs(t, err, ErrACLGrantCollision)
	assert.Contains(t, err.Error(), "read on collection c1", "error must name the existing grants")
	assert.Contains(t, err.Error(), "write on collection c3")

	// The whole rename rolled back: group name unchanged, no rows moved.
	var g Group
	require.NoError(t, db.First(&g, "id = ?", fx.opsID).Error)
	assert.Equal(t, fx.opsName, g.Name)
	assert.Len(t, aclRows(t, db, fx.opsName), 2)
	assert.Len(t, aclRows(t, db, newName), 2)

	// Revoking the existing grants unblocks the rename.
	require.NoError(t, db.Where("group_id = ?", newName).Delete(&CollectionACL{}).Error)
	require.NoError(t, UpdateGroup(db, fx.opsID, &newName, nil, nil, nil, fx.strangerID, true, true))
	assert.Empty(t, aclRows(t, db, fx.opsName))
	assert.Len(t, aclRows(t, db, newName), 2)
}

func TestUpdateGroupNonRenameLeavesACLsAlone(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)
	seedACL(t, db, "c1", fx.opsName, AclRoleRead, "u-owner")

	dn := "Ops Team"
	require.NoError(t, UpdateGroup(db, fx.opsID, nil, &dn, nil, nil, fx.ownerID, false, false))
	// Rename to the same name is a no-op for ACLs too.
	same := fx.opsName
	require.NoError(t, UpdateGroup(db, fx.opsID, &same, nil, nil, nil, fx.strangerID, true, true))

	assert.Len(t, aclRows(t, db, fx.opsName), 1)
}

func TestDeleteGroupAfterRenameCleansMigratedGrants(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)
	seedACL(t, db, "c1", fx.opsName, AclRoleRead, "u-owner")

	newName := "ops-renamed"
	require.NoError(t, UpdateGroup(db, fx.opsID, &newName, nil, nil, nil, fx.strangerID, true, true))
	require.NoError(t, DeleteGroup(db, fx.opsID, fx.ownerID, false))

	assert.Empty(t, aclRows(t, db, fx.opsName))
	assert.Empty(t, aclRows(t, db, newName))
}

// ---------- group creation ----------

func TestCreateGroupRefusesNameWithExistingACLGrants(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)

	// Grants issued to an IdP-asserted group that has no local row.
	seedACL(t, db, "c1", "cms-users", AclRoleRead, "u-owner")
	seedACL(t, db, "c2", "cms-users", AclRoleWrite, "u-owner")

	_, err := CreateGroup(db, "cms-users", "", "", Creator{UserID: fx.strangerID}, "", false)
	require.ErrorIs(t, err, ErrACLGrantCollision)
	assert.Contains(t, err.Error(), "read on collection c1")
	assert.Contains(t, err.Error(), "write on collection c2")

	var count int64
	require.NoError(t, db.Model(&Group{}).Where("name = ?", "cms-users").Count(&count).Error)
	assert.Zero(t, count, "no group row may be created")
	assert.Len(t, aclRows(t, db, "cms-users"), 2, "the IdP group's grants are untouched")

	// Revoking the grants frees the name.
	require.NoError(t, db.Where("group_id = ?", "cms-users").Delete(&CollectionACL{}).Error)
	_, err = CreateGroup(db, "cms-users", "", "", Creator{UserID: fx.strangerID}, "", false)
	require.NoError(t, err)
}

// ---------- user rename ----------

func TestRenameUserMigratesPersonalACLGrants(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	seedACL(t, db, "c1", "user-alice", AclRoleRead, "admin")
	seedACL(t, db, "c1", "user-alice", AclRoleWrite, "admin")
	// Somebody else's personal grant must be untouched.
	seedACL(t, db, "c1", "user-bob", AclRoleRead, "admin")

	require.NoError(t, RenameUser(db, u.ID, "alicia", localIssuerForTests))

	assert.Empty(t, aclRows(t, db, "user-alice"))
	assert.Len(t, aclRows(t, db, "user-alicia"), 2)
	assert.Len(t, aclRows(t, db, "user-bob"), 1)

	// The renamed user keeps matching their grants via the synthesised
	// personal group ...
	assert.Contains(t, ExpandCallerACLGroups(db, "alicia", u.ID, nil), "user-alicia")

	// ... and the vacated username can be claimed by a fresh account
	// without inheriting anything.
	fresh, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	assert.NotEqual(t, u.ID, fresh.ID)
	assert.Empty(t, aclRows(t, db, "user-alice"))
}

func TestRenameUserRefusesCollidingPersonalGrants(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	seedACL(t, db, "c1", "user-alice", AclRoleRead, "from-old")
	seedACL(t, db, "c2", "user-alice", AclRoleRead, "from-old")
	// A grant already sitting under the target personal-group name, on
	// a collection the user has no grant on — it still blocks.
	seedACL(t, db, "c9", "user-alicia", AclRoleRead, "from-new")

	err = RenameUser(db, u.ID, "alicia", localIssuerForTests)
	require.ErrorIs(t, err, ErrACLGrantCollision)
	assert.Contains(t, err.Error(), "read on collection c9")

	// Rolled back: username and sub unchanged, no rows moved.
	got, err := GetUserByID(db, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Username)
	assert.Equal(t, "alice", got.Sub)
	assert.Len(t, aclRows(t, db, "user-alice"), 2)
	assert.Len(t, aclRows(t, db, "user-alicia"), 1)

	// Revoking the existing grant unblocks the rename.
	require.NoError(t, db.Where("group_id = ?", "user-alicia").Delete(&CollectionACL{}).Error)
	require.NoError(t, RenameUser(db, u.ID, "alicia", localIssuerForTests))
	assert.Empty(t, aclRows(t, db, "user-alice"))
	assert.Len(t, aclRows(t, db, "user-alicia"), 2)
}

func TestDeleteUserAfterRenameCleansMigratedGrants(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	seedACL(t, db, "c1", "user-alice", AclRoleRead, "admin")

	require.NoError(t, RenameUser(db, u.ID, "alicia", localIssuerForTests))
	require.NoError(t, DeleteUser(db, u.ID, "admin", true))

	assert.Empty(t, aclRows(t, db, "user-alice"))
	assert.Empty(t, aclRows(t, db, "user-alicia"))
}
