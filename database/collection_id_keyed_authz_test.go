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
		ACLSubjectRef("user-alice"), AclRoleWrite, nil, false))

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
		ACLSubjectRef("user-alice"), AclRoleRead, nil, false))

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
		ACLSubjectRef(fx.opsName), AclRoleWrite, nil, false))

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
		ACLSubjectRef(fx.opsName), AclRoleRead, nil, false))

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
			ACLSubjectRef("cms-production"), AclRoleRead, nil, false)
		assert.ErrorIs(t, err, ErrUnknownACLSubject,
			"storing an unresolvable name is what let a later claimant inherit the grant")
		assert.Empty(t, reload(t, db, coll.ID).ACLs)
	})

	t.Run("each space has its own entry point and both store the ID", func(t *testing.T) {
		require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			ACLSubjectRef(fx.opsName), AclRoleRead, nil, false))
		require.NoError(t, GrantCollectionAclBySubject(db, coll.ID, "owner", fx.ownerID, nil,
			ACLSubject{Type: ACLSubjectGroup, ID: fx.opsAdminsID}, AclRoleWrite, nil, false))

		acls := reload(t, db, coll.ID).ACLs
		require.Len(t, acls, 2)
		for _, a := range acls {
			assert.Equal(t, ACLSubjectGroup, a.SubjectType)
			assert.Equal(t, fx.ownerID, a.GrantedBy, "granted_by records the granting User.ID")
		}
	})

	t.Run("the sentinel and personal forms round-trip through the display fields", func(t *testing.T) {
		require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			ACLSubjectRef(AllAuthenticatedUsersACLGroup), AclRoleRead, nil, false))
		require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			ACLSubjectRef("user-dave-member"), AclRoleRead, nil, false))

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
			ACLSubjectRef("user-dave-member"), AclRoleRead, false))
		require.NoError(t, RevokeCollectionAclBySubject(db, coll.ID, "owner", fx.ownerID, nil,
			ACLSubject{Type: ACLSubjectAuthenticated}, AclRoleRead, false))

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

// Names and IDs are different spaces, and which one a value belongs to
// is carried by its TYPE rather than inferred from how it looks. An
// earlier version of this branch inferred it from the shape of the
// string, which is a guess — and a guess at a security boundary is a
// vulnerability waiting for the input that fools it. Group creation is
// open to any authenticated user, so a group NAMED after another
// principal's ID was enough to intercept grants addressed to that ID.
func TestNameSpaceAndIDSpaceAreDisjoint(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)
	victim := mkUser(t, db, "a1b2c3d4", "victim")
	coll := mkCollection(t, db, "c1", "data", fx.ownerID)

	// Hygiene, not a control: nothing resolves a handle by its shape any
	// more (see the subtests below), but keeping names and IDs visually
	// distinct removes a class of human error in logs and config.
	t.Run("a group cannot be named like an ID", func(t *testing.T) {
		_, err := CreateGroup(db, victim.ID, "", "", Creator{UserID: fx.strangerID}, "", false)
		assert.ErrorIs(t, err, ErrInvalidIdentifier)
		// Nor can an admin rename an existing group into the ID space.
		slugName := "0badf00d"
		assert.ErrorIs(t, UpdateGroup(db, fx.opsID, &slugName, nil, nil, nil, fx.ownerID, true, true),
			ErrInvalidIdentifier)
		// Nor can a user be renamed into it.
		assert.ErrorIs(t, RenameUser(db, victim.ID, "0badf00d", localIssuerForTests), ErrInvalidIdentifier)
	})

	t.Run("the name space never consults IDs", func(t *testing.T) {
		// This is the property that replaced deciding by shape: an ID
		// handed to the name-space resolver does not resolve, because no
		// group is NAMED that. It cannot be silently misrouted to a
		// group whose name happens to look like an ID, because names are
		// never compared against IDs at all.
		_, err := ResolveACLSubjectRef(db, ACLSubjectRef(fx.opsID))
		assert.ErrorIs(t, err, ErrUnknownACLSubject, "a group ID is not a group name")
		_, err = ResolveACLSubjectRef(db, ACLSubjectRef(victim.ID))
		assert.ErrorIs(t, err, ErrUnknownACLSubject, "nor is a user ID")
		assert.ErrorIs(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			ACLSubjectRef(victim.ID), AclRoleRead, nil, false), ErrUnknownACLSubject)

		// A group name resolves, and lands on that group.
		subject, err := ResolveACLSubjectRef(db, ACLSubjectRef(fx.opsName))
		require.NoError(t, err)
		assert.Equal(t, ACLSubject{Type: ACLSubjectGroup, ID: fx.opsID}, subject)
	})

	t.Run("the ID space names its kind and never consults names", func(t *testing.T) {
		// The counterpart: an ID-space reference says which table it is
		// in, so there is nothing to infer.
		subject, err := LookupACLSubject(db, ACLSubject{Type: ACLSubjectGroup, ID: fx.opsID})
		require.NoError(t, err)
		assert.Equal(t, fx.opsID, subject.ID)

		_, err = LookupACLSubject(db, ACLSubject{Type: ACLSubjectGroup, ID: fx.opsName})
		assert.ErrorIs(t, err, ErrUnknownACLSubject, "a group name is not a group ID")

		// A user by ID works here and only here.
		subject, err = LookupACLSubject(db, ACLSubject{Type: ACLSubjectUser, ID: victim.ID})
		require.NoError(t, err)
		assert.Equal(t, ACLSubjectUser, subject.Type)

		// And mixing the kinds up is caught rather than silently
		// resolved against the wrong table.
		_, err = LookupACLSubject(db, ACLSubject{Type: ACLSubjectUser, ID: fx.opsID})
		assert.ErrorIs(t, err, ErrUnknownACLSubject, "a group ID is not a user ID")
	})

	t.Run("the personal form still lands on the user", func(t *testing.T) {
		require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
			ACLSubjectRef(PersonalACLGroupPrefix+victim.Username), AclRoleRead, nil, false))
		acls := reload(t, db, coll.ID).ACLs
		require.Len(t, acls, 1)
		assert.Equal(t, ACLSubjectUser, acls[0].SubjectType)
		assert.Equal(t, victim.ID, acls[0].SubjectID)
	})
}

// A Group.ID is an authorization handle, so it must never come back.
// DeleteGroup is a soft delete for that reason, and it clears every
// reference that would otherwise survive the group and be inherited by
// whatever next held the ID.
func TestDeleteGroupIsSoftAndExhaustive(t *testing.T) {
	db := setupCollectionTestDB(t)
	fx := seedGroupAuthzFixtures(t, db)
	coll := mkCollection(t, db, "c1", "data", fx.ownerID)

	// Wire the group into every place that can reference it.
	require.NoError(t, GrantCollectionAcl(db, coll.ID, "owner", fx.ownerID, nil,
		ACLSubjectRef(fx.opsName), AclRoleWrite, nil, false))
	require.NoError(t, GrantGroupScope(db, fx.opsID, token_scopes.Server_CollectionAdmin, CreatorSelf()))
	require.NoError(t, db.Model(&Collection{}).Where("id = ?", coll.ID).
		Update("admin_id", fx.opsID).Error)
	require.NoError(t, db.Model(&Group{}).Where("id = ?", fx.opsAdminsID).
		Updates(map[string]interface{}{"admin_id": fx.opsID, "admin_type": AdminTypeGroup}).Error)

	require.NoError(t, DeleteGroup(db, fx.opsID, fx.ownerID, false))

	t.Run("the row is tombstoned, not removed", func(t *testing.T) {
		// Gone from every ordinary query...
		assert.ErrorIs(t, db.First(&Group{}, "id = ?", fx.opsID).Error, gorm.ErrRecordNotFound)
		// ...but still occupying its ID, so no later group can be
		// minted with it and inherit anything this cleanup missed.
		var n int64
		require.NoError(t, db.Unscoped().Model(&Group{}).Where("id = ?", fx.opsID).Count(&n).Error)
		assert.EqualValues(t, 1, n)
		assert.Error(t, db.Create(&Group{ID: fx.opsID, Name: "reused-id", CreatedBy: fx.ownerID}).Error,
			"the tombstone must keep the ID spent")
	})

	t.Run("every reference to it is cleared", func(t *testing.T) {
		assert.Empty(t, reload(t, db, coll.ID).ACLs)

		scopes, err := ListGroupScopes(db, fx.opsID)
		require.NoError(t, err)
		assert.Empty(t, scopes, "a group's scopes must not outlive it")

		var adminID string
		require.NoError(t, db.Table("collections").Select("admin_id").
			Where("id = ?", coll.ID).Scan(&adminID).Error)
		assert.Empty(t, adminID, "a collection must not be left naming an administrator that no longer exists")

		var sibling Group
		require.NoError(t, db.First(&sibling, "id = ?", fx.opsAdminsID).Error)
		assert.Empty(t, sibling.AdminID)
		assert.Empty(t, string(sibling.AdminType))

		var members int64
		require.NoError(t, db.Model(&GroupMember{}).Where("group_id = ?", fx.opsID).Count(&members).Error)
		assert.Zero(t, members)
	})

	t.Run("the name is released and the replacement inherits nothing", func(t *testing.T) {
		// Unlike the ID, the name is free again — nothing keys on it.
		replacement, err := CreateGroup(db, fx.opsName, "", "", Creator{UserID: fx.strangerID}, "", false)
		require.NoError(t, err)
		assert.NotEqual(t, fx.opsID, replacement.ID)

		require.NoError(t, db.Create(&GroupMember{
			GroupID: replacement.ID, UserID: fx.strangerID, AddedBy: fx.strangerID,
		}).Error)
		assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), "eve-stranger", fx.strangerID,
			[]string{fx.opsName}, token_scopes.Collection_Read), ErrForbidden)

		scopes, err := ListGroupScopes(db, replacement.ID)
		require.NoError(t, err)
		assert.Empty(t, scopes)
	})
}
