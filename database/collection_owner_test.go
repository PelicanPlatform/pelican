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

	"github.com/pelicanplatform/pelican/token_scopes"
)

// applyPartialUserIndexes replaces the AutoMigrate-generated (non-partial)
// user uniqueness indexes with the partial ones production carries
// (migrations 20260503120000 and 20260812000000), so that a soft-deleted
// account releases its username and (sub, issuer) for reuse exactly as
// it does on a real deployment.
func applyPartialUserIndexes(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, stmt := range []string{
		`DROP INDEX IF EXISTS idx_user_username_live`,
		`DROP INDEX IF EXISTS idx_user_sub_issuer`,
		`CREATE UNIQUE INDEX idx_user_username_live ON users (username) WHERE deleted_at IS NULL`,
		`CREATE UNIQUE INDEX idx_user_sub_issuer ON users (sub, issuer) WHERE deleted_at IS NULL`,
	} {
		require.NoError(t, db.Exec(stmt).Error)
	}
}

// The tests in this file pin the rule that collection ownership is
// decided by collections.owner_id (the immutable User.ID) and never by
// the legacy collections.owner username column. Usernames are mutable
// and reusable, so a username match would let:
//
//   - the previous owner keep control after a PATCH ownership transfer
//   - a new account that claims a soft-deleted user's name inherit
//     every collection that user owned
//   - whoever next holds a renamed user's old name gain owner authority
//
// See the "Username fallback enables extended access to transferred
// namespace" report.

func collectionIDs(cs []Collection) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

func TestOwnerChecksIgnoreLegacyUsername(t *testing.T) {
	coll := &Collection{ID: "c1", Owner: "alice", OwnerID: "u-alice"}

	// Same username, different account: not the owner.
	assert.False(t, CallerIsCollectionOwner(coll, "alice", "u-impostor"))
	assert.False(t, CallerIsCollectionOwner(coll, "alice", ""))
	assert.False(t, CallerIsCollectionOwnerOrAdmin(nil, coll, "alice", "u-impostor", nil))
	assert.Empty(t, EffectiveCollectionRole(nil, coll, "u-impostor", "alice"))
	assert.ErrorIs(t, validateACL(nil, coll, "alice", "u-impostor", nil, token_scopes.Collection_Read), ErrForbidden)

	// Matching ID under any username: the owner.
	assert.True(t, CallerIsCollectionOwner(coll, "renamed", "u-alice"))
	assert.True(t, CallerIsCollectionOwnerOrAdmin(nil, coll, "", "u-alice", nil))
	assert.Equal(t, AclRoleOwner, EffectiveCollectionRole(nil, coll, "u-alice", ""))
	assert.NoError(t, validateACL(nil, coll, "", "u-alice", nil, token_scopes.Collection_Delete))

	// A row that never got an owner_id confers ownership on nobody.
	legacy := &Collection{ID: "c2", Owner: "alice"}
	assert.False(t, CallerIsCollectionOwner(legacy, "alice", "u-alice"))
}

func TestUpdateCollectionTransferRevokesPreviousOwner(t *testing.T) {
	db := setupCollectionTestDB(t)
	alice, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	bob, err := CreateLocalUser(db, "bob", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	coll, err := CreateCollection(db, "shared", "", alice.Username, alice.ID, "/data/shared", VisibilityPrivate)
	require.NoError(t, err)

	// Alice hands the collection to Bob via the direct PATCH path.
	require.NoError(t, UpdateCollection(db, coll.ID, alice.Username, alice.ID, nil, nil, nil, nil, &bob.ID, nil, nil, false))

	got, err := GetCollection(db, coll.ID, bob.Username, bob.ID, nil, false)
	require.NoError(t, err)
	assert.Equal(t, bob.ID, got.OwnerID)
	assert.Equal(t, "bob", got.Owner, "audit username must follow the transfer")

	// The previous owner has no authority left: cannot read, delete,
	// or take the collection back, and no longer sees it listed.
	_, err = GetCollection(db, coll.ID, alice.Username, alice.ID, nil, false)
	assert.ErrorIs(t, err, ErrForbidden)
	assert.ErrorIs(t, DeleteCollection(db, coll.ID, alice.Username, alice.ID, nil, false), ErrForbidden)
	assert.ErrorIs(t, UpdateCollection(db, coll.ID, alice.Username, alice.ID, nil, nil, nil, nil, &alice.ID, nil, nil, false), ErrForbidden)
	listed, err := ListCollections(db, alice.Username, alice.ID, nil, false)
	require.NoError(t, err)
	assert.NotContains(t, collectionIDs(listed), coll.ID)

	// The new owner has full authority.
	listed, err = ListCollections(db, bob.Username, bob.ID, nil, false)
	require.NoError(t, err)
	assert.Contains(t, collectionIDs(listed), coll.ID)
	require.NoError(t, DeleteCollection(db, coll.ID, bob.Username, bob.ID, nil, false))
}

func TestUpdateCollectionTransferRequiresExistingUser(t *testing.T) {
	db := setupCollectionTestDB(t)
	alice, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	coll, err := CreateCollection(db, "shared", "", alice.Username, alice.ID, "/data/shared", VisibilityPrivate)
	require.NoError(t, err)

	ghost := "u-does-not-exist"
	err = UpdateCollection(db, coll.ID, alice.Username, alice.ID, nil, nil, nil, nil, &ghost, nil, nil, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not refer to an existing user")

	got, err := GetCollection(db, coll.ID, alice.Username, alice.ID, nil, false)
	require.NoError(t, err)
	assert.Equal(t, alice.ID, got.OwnerID, "a failed transfer must leave ownership untouched")
}

func TestDeletedUsernameReuseDoesNotInheritCollections(t *testing.T) {
	db := setupCollectionTestDB(t)
	applyPartialUserIndexes(t, db)
	alice, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	coll, err := CreateCollection(db, "home", "", alice.Username, alice.ID, "/data/alice", VisibilityPrivate)
	require.NoError(t, err)

	// Soft-delete releases the username; DeleteUser does not touch the
	// collection row, so its audit `owner` still says "alice".
	require.NoError(t, DeleteUser(db, alice.ID, "admin", true))
	newAlice, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	require.NotEqual(t, alice.ID, newAlice.ID)

	var row Collection
	require.NoError(t, db.First(&row, "id = ?", coll.ID).Error)
	assert.Equal(t, "alice", row.Owner)

	_, err = GetCollection(db, coll.ID, newAlice.Username, newAlice.ID, nil, false)
	assert.ErrorIs(t, err, ErrForbidden)
	assert.ErrorIs(t, DeleteCollection(db, coll.ID, newAlice.Username, newAlice.ID, nil, false), ErrForbidden)
	listed, err := ListCollections(db, newAlice.Username, newAlice.ID, nil, false)
	require.NoError(t, err)
	assert.NotContains(t, collectionIDs(listed), coll.ID)
}

func TestRenamedUserKeepsCollectionsAndOldNameIsNotClaimable(t *testing.T) {
	db := setupCollectionTestDB(t)
	alice, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	coll, err := CreateCollection(db, "home", "", alice.Username, alice.ID, "/data/alice", VisibilityPrivate)
	require.NoError(t, err)

	require.NoError(t, RenameUser(db, alice.ID, "alicia", localIssuerForTests))
	newAlice, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)

	// The renamed user keeps ownership through her stable ID ...
	got, err := GetCollection(db, coll.ID, "alicia", alice.ID, nil, false)
	require.NoError(t, err)
	assert.Equal(t, alice.ID, got.OwnerID)
	listed, err := ListCollections(db, "alicia", alice.ID, nil, false)
	require.NoError(t, err)
	assert.Contains(t, collectionIDs(listed), coll.ID)

	// ... and the account that now holds her old username gets nothing,
	// even though the audit column still reads "alice".
	_, err = GetCollection(db, coll.ID, newAlice.Username, newAlice.ID, nil, false)
	assert.ErrorIs(t, err, ErrForbidden)
	assert.ErrorIs(t, DeleteCollection(db, coll.ID, newAlice.Username, newAlice.ID, nil, false), ErrForbidden)
	listed, err = ListCollections(db, newAlice.Username, newAlice.ID, nil, false)
	require.NoError(t, err)
	assert.NotContains(t, collectionIDs(listed), coll.ID)
}

func TestListCollectionSharesIgnoresLegacyUsername(t *testing.T) {
	db := setupCollectionTestDB(t)
	require.NoError(t, db.Create(&Collection{
		ID: "p1", Name: "parent", Owner: "alice", OwnerID: "u-alice",
		Namespace: "/data/parent", Visibility: VisibilityPrivate, EnableSharing: true,
	}).Error)
	require.NoError(t, db.Create(&Collection{
		ID: "s1", Name: "share", Owner: "alice", OwnerID: "u-alice",
		Namespace: "/data/parent/x", Visibility: VisibilityPrivate, ParentCollectionID: "p1",
	}).Error)

	shares, err := ListCollectionShares(db, "p1", "alice", "u-alice", nil, false)
	require.NoError(t, err)
	assert.Equal(t, []string{"s1"}, collectionIDs(shares))

	shares, err = ListCollectionShares(db, "p1", "alice", "u-impostor", nil, false)
	require.NoError(t, err)
	assert.Empty(t, shares, "a same-named account must not see another user's shares")
}
