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

// Regression coverage for issues #3752 and #3753: the collection tables
// used to mix name-keyed and ID-keyed references, so a username or group
// name that changed hands carried its authority with it. Every test here
// asserts the property that replaced that model — an authorization
// decision only ever matches on an immutable ID — from the outside, by
// exercising the same entry points the HTTP layer calls.
//
// These are pinning tests, not smoke tests. Each property below was
// checked against the pre-fix code by porting it to that API and running
// it on the parent commit, where every one of them fails, reproducing
// the reported behavior:
//
//	TestOwnershipTransferRemovesPreviousOwner
//	    the previous owner still passes the owner check after a PATCH
//	    transfer, and can still delete the collection (#3753)
//	TestReclaimedUsernameInheritsNoCollections
//	    a fresh account claiming a released username owns the deleted
//	    account's collections and sees them in its listing (#3753)
//	TestRenamedUserKeepsGrantsAndLeavesNothingBehind
//	    a renamed user LOSES their personal grants, and the next holder
//	    of the vacated username GAINS them (#3752)
//	TestRenamedGroupKeepsGrantsAndVacatedNameInheritsNothing
//	    likewise for a renamed group: its members lose access and anyone
//	    who re-creates a group with the old name inherits it (#3752)
//	TestGrantCollectionAclSubjectResolution
//	    an ACL target matching no group and no user is stored verbatim,
//	    which is what makes the reclaim above pay off (#3752)
//	TestDeleteGroupAfterRenameClearsGrants
//	    the grant survives the group's deletion because the cleanup
//	    matched on the group's current name (#3752)
//
// If you change how principals are matched, re-run that check rather
// than trusting these to still be load-bearing.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/token_scopes"
)

func mkUser(t *testing.T, db *gorm.DB, id, username string) *User {
	t.Helper()
	// Sub is derived from the ID, not the username: these tests hand
	// the same username to different accounts, and the IdP subject is
	// what actually identifies a person.
	u := &User{
		ID: id, Username: username, Sub: id + "@idp",
		Issuer: "https://idp.example", Status: UserStatusActive,
	}
	require.NoError(t, db.Create(u).Error)
	return u
}

func mkCollection(t *testing.T, db *gorm.DB, id, name, ownerID string) *Collection {
	t.Helper()
	c, err := CreateCollection(db, name, "", ownerID, "/"+name, VisibilityPrivate)
	require.NoError(t, err)
	return c
}

func reload(t *testing.T, db *gorm.DB, id string) *Collection {
	t.Helper()
	var c Collection
	require.NoError(t, db.Preload("ACLs").First(&c, "id = ?", id).Error)
	return &c
}

// #3753: transferring ownership must actually take authority away from
// the previous owner. Under the old model UpdateCollection wrote
// owner_id while the authorization check still accepted a match on the
// `owner` username column, so the previous owner kept full control —
// including the ability to transfer the collection back.
func TestOwnershipTransferRemovesPreviousOwner(t *testing.T) {
	db := setupCollectionTestDB(t)
	alice := mkUser(t, db, "u-alice", "alice")
	bob := mkUser(t, db, "u-bob", "bob")
	coll := mkCollection(t, db, "c1", "data", alice.ID)

	require.NoError(t, UpdateCollection(db, coll.ID, alice.Username, alice.ID, nil,
		nil, nil, nil, &bob.ID, nil, nil, false))

	after := reload(t, db, coll.ID)
	assert.Equal(t, bob.ID, after.OwnerID)

	assert.False(t, CallerIsCollectionOwner(db, after, alice.Username, alice.ID),
		"the previous owner must not still pass the owner check")
	assert.ErrorIs(t, validateACL(db, after, alice.Username, alice.ID, nil, token_scopes.Collection_Read),
		ErrForbidden, "the previous owner keeps no residual access")
	assert.ErrorIs(t, DeleteCollection(db, after.ID, alice.Username, alice.ID, nil, false),
		ErrForbidden, "and certainly cannot delete it")

	assert.True(t, CallerIsCollectionOwner(db, after, bob.Username, bob.ID))
}

// #3753: a deleted account's username can be reused, and the new
// account must inherit nothing. Previously `collections.owner` still
// held the string "alice", so whoever next held that username owned
// every collection the original had left behind.
func TestReclaimedUsernameInheritsNoCollections(t *testing.T) {
	db := setupCollectionTestDB(t)
	alice := mkUser(t, db, "u-alice", "alice")
	coll := mkCollection(t, db, "c1", "data", alice.ID)
	// A personal grant on a second collection, to cover the ACL half of
	// the same problem.
	other := mkUser(t, db, "u-other", "other")
	shared := mkCollection(t, db, "c2", "shared", other.ID)
	require.NoError(t, GrantCollectionAcl(db, shared.ID, other.Username, other.ID, nil,
		"user-alice", AclRoleWrite, nil, false))

	require.NoError(t, DeleteUser(db, alice.ID, alice.ID, false))

	// The username is free again; a different person claims it.
	impostor := mkUser(t, db, "u-impostor", "alice")
	require.NotEqual(t, alice.ID, impostor.ID)

	assert.False(t, CallerIsCollectionOwner(db, reload(t, db, coll.ID), "alice", impostor.ID),
		"a new holder of a released username must not inherit the old account's collections")
	assert.ErrorIs(t, validateACL(db, reload(t, db, shared.ID), "alice", impostor.ID, nil, token_scopes.Collection_Read),
		ErrForbidden, "nor its personal ACL grants")

	list, err := ListCollections(db, "alice", impostor.ID, nil, false)
	require.NoError(t, err)
	assert.Empty(t, list)
}

// #3752: renaming a user must not orphan their personal grants — the
// grant follows the account because it was never keyed on the name —
// and must not leave anything behind under the vacated username.
func TestRenamedUserKeepsGrantsAndLeavesNothingBehind(t *testing.T) {
	db := setupCollectionTestDB(t)
	owner := mkUser(t, db, "u-owner", "owner")
	alice := mkUser(t, db, "u-alice", "alice")
	coll := mkCollection(t, db, "c1", "data", owner.ID)
	require.NoError(t, GrantCollectionAcl(db, coll.ID, owner.Username, owner.ID, nil,
		"user-alice", AclRoleRead, nil, false))

	require.NoError(t, RenameUser(db, alice.ID, "alicia", localIssuerForTests))

	assert.NoError(t, validateACL(db, reload(t, db, coll.ID), "alicia", alice.ID, nil, token_scopes.Collection_Read),
		"the renamed account keeps its grant; nothing had to be migrated")

	newcomer := mkUser(t, db, "u-newcomer", "alice")
	assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), "alice", newcomer.ID, nil, token_scopes.Collection_Read),
		ErrForbidden, "the vacated username carries no grant to its next holder")
}

// #3752, group half: renaming a group carries its grants (they point at
// the ID), and re-creating a group under the vacated name inherits
// nothing.
func TestRenamedGroupKeepsGrantsAndVacatedNameInheritsNothing(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)
	coll := mkCollection(t, db, "c1", "data", fx.ownerID)
	require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
		fx.opsName, AclRoleWrite, nil, false))

	// dave-member is in "ops" and can write.
	assert.NoError(t, validateACL(db, reload(t, db, coll.ID), "dave-member", fx.memberID, nil, token_scopes.Collection_Modify))

	newName := "ops-renamed"
	require.NoError(t, UpdateGroup(db, fx.opsID, &newName, nil, nil, nil, fx.ownerID, true, true))

	assert.NoError(t, validateACL(db, reload(t, db, coll.ID), "dave-member", fx.memberID, nil, token_scopes.Collection_Modify),
		"a rename is a display change; the grant points at the group's ID")

	// A stranger grabs the freed name and joins their own group.
	reclaimed, err := CreateGroup(db, fx.opsName, "", "", Creator{UserID: fx.strangerID}, "", false)
	require.NoError(t, err)
	require.NoError(t, db.Create(&GroupMember{GroupID: reclaimed.ID, UserID: fx.strangerID, AddedBy: fx.strangerID}).Error)

	assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), "eve-stranger", fx.strangerID, nil, token_scopes.Collection_Read),
		ErrForbidden, "reclaiming the name must not reclaim the grants")

	// And the caller's *asserted* group names go through the same
	// resolution, so asserting "ops" gets the stranger's group, not the
	// renamed one.
	assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), "eve-stranger", fx.strangerID, []string{fx.opsName}, token_scopes.Collection_Read),
		ErrForbidden)
}

// Deleting a group clears its grants even when it was renamed first —
// the old cleanup matched on the group's current name and so missed
// rows orphaned by an earlier rename.
func TestDeleteGroupAfterRenameClearsGrants(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)
	coll := mkCollection(t, db, "c1", "data", fx.ownerID)
	require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
		fx.opsName, AclRoleRead, nil, false))

	newName := "ops-renamed"
	require.NoError(t, UpdateGroup(db, fx.opsID, &newName, nil, nil, nil, fx.ownerID, true, true))
	require.NoError(t, DeleteGroup(db, fx.opsID, fx.ownerID, false))

	assert.Empty(t, reload(t, db, coll.ID).ACLs)
}

func TestGrantCollectionAclSubjectResolution(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)
	coll := mkCollection(t, db, "c1", "data", fx.ownerID)

	t.Run("refuses a name that matches no group and no user", func(t *testing.T) {
		err := GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			"cms-production", AclRoleRead, nil, false)
		assert.ErrorIs(t, err, ErrUnknownACLSubject,
			"storing an unresolvable name is what let a later claimant inherit the grant")
		assert.Empty(t, reload(t, db, coll.ID).ACLs)
	})

	t.Run("accepts a group by name or by ID and stores the ID either way", func(t *testing.T) {
		require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			fx.opsName, AclRoleRead, nil, false))
		require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			fx.opsAdminsID, AclRoleWrite, nil, false))

		acls := reload(t, db, coll.ID).ACLs
		require.Len(t, acls, 2)
		for _, a := range acls {
			assert.Equal(t, ACLSubjectGroup, a.SubjectType)
			assert.Equal(t, fx.ownerID, a.GrantedBy, "granted_by records the granting User.ID")
		}
	})

	t.Run("the sentinel and personal forms round-trip through the display fields", func(t *testing.T) {
		require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			AllAuthenticatedUsersACLGroup, AclRoleRead, nil, false))
		require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			"user-dave-member", AclRoleRead, nil, false))

		acls, err := GetCollectionAcls(db, coll.ID, "owner", fx.ownerID, nil, false)
		require.NoError(t, err)
		labels := map[string]ACLSubjectType{}
		for _, a := range acls {
			labels[a.GroupID] = a.SubjectType
		}
		assert.Equal(t, ACLSubjectAuthenticated, labels[AllAuthenticatedUsersACLGroup])
		assert.Equal(t, ACLSubjectUser, labels["user-dave-member"],
			"a personal grant renders as user-<current username> even though it is stored by ID")
		assert.Equal(t, ACLSubjectGroup, labels[fx.opsName])
	})

	t.Run("revoking by the listed groupId works, and so does revoking by subject", func(t *testing.T) {
		require.NoError(t, RevokeCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			"user-dave-member", AclRoleRead, false))
		require.NoError(t, RevokeCollectionAclBySubject(db, coll.ID, "owner", fx.ownerID, nil,
			ACLSubjectAuthenticated, "", AclRoleRead, false))

		for _, a := range reload(t, db, coll.ID).ACLs {
			assert.Equal(t, ACLSubjectGroup, a.SubjectType)
		}
	})
}

// OwnerID is the only ownership handle, so a PATCH that names a
// nonexistent user would strand the collection as surely as an empty
// one would. Both are refused.
func TestUpdateCollectionRejectsUnusableOwner(t *testing.T) {
	db := setupCollectionTestDB(t)
	alice := mkUser(t, db, "u-alice", "alice")
	coll := mkCollection(t, db, "c1", "data", alice.ID)

	empty := ""
	assert.Error(t, UpdateCollection(db, coll.ID, alice.Username, alice.ID, nil,
		nil, nil, nil, &empty, nil, nil, false))

	bogus := "u-does-not-exist"
	err := UpdateCollection(db, coll.ID, alice.Username, alice.ID, nil,
		nil, nil, nil, &bogus, nil, nil, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not name an active user")

	assert.Equal(t, alice.ID, reload(t, db, coll.ID).OwnerID)
}
