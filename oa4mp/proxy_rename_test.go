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

package oa4mp

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
)

// newRenameTestDB builds the full user/group/collection schema so the
// tests below can drive the real create/rename/membership helpers and
// then observe what the token path (GetUserCollectionScopes) mints.
func newRenameTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&database.Collection{},
		&database.CollectionACL{},
		&database.User{},
		&database.Group{},
		&database.GroupMember{},
		&database.UserScope{},
		&database.GroupScope{},
	))
	require.NoError(t, database.AutoMigrateCredentialsForTests(db))
	return db
}

func storageScopesFor(scopes []string, namespace string) []string {
	out := []string{}
	for _, s := range scopes {
		for _, prefix := range []string{"storage.read:", "storage.modify:", "storage.create:"} {
			if s == prefix+namespace {
				out = append(out, s)
			}
		}
	}
	return out
}

// TestGetUserCollectionScopes_RenamedGroupGrantsFollowTheGroup replays
// the "group stomping" scenario from the ACL name-reuse report end to
// end through the token-minting path:
//
//  1. group alpha-writers holds write on a collection
//  2. an admin renames it to alpha-editors
//  3. an unrelated user creates a new group called alpha-writers and
//     joins it
//
// The new alpha-writers must mint no storage scopes for the collection,
// and the members of the renamed group must keep theirs.
func TestGetUserCollectionScopes_RenamedGroupGrantsFollowTheGroup(t *testing.T) {
	db := newRenameTestDB(t)
	const ns = "/data/alpha"
	seedCollection(t, db, "col-alpha", ns)

	admin, err := database.CreateLocalUser(db, "admin", "", "https://local.test", database.Creator{UserID: "admin"})
	require.NoError(t, err)
	member, err := database.CreateLocalUser(db, "dave", "", "https://local.test", database.Creator{UserID: admin.ID})
	require.NoError(t, err)
	attacker, err := database.CreateLocalUser(db, "eve", "", "https://local.test", database.Creator{UserID: admin.ID})
	require.NoError(t, err)

	writers, err := database.CreateGroup(db, "alpha-writers", "Alpha Writers", "", database.Creator{UserID: admin.ID}, "", false)
	require.NoError(t, err)
	require.NoError(t, db.Create(&database.GroupMember{GroupID: writers.ID, UserID: member.ID, AddedBy: admin.ID}).Error)
	// Grant through the real path (resolves the group slug to its name).
	require.NoError(t, database.GrantCollectionAcl(db, "col-alpha", admin.Username, admin.ID, nil, writers.ID, database.AclRoleWrite, nil, true))

	// Baseline: the member mints full rwx, the attacker mints nothing.
	scopes, matched, err := GetUserCollectionScopes(db, member.Username, member.ID, nil, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"storage.read:" + ns, "storage.modify:" + ns, "storage.create:" + ns}, storageScopesFor(scopes, ns))
	assert.Contains(t, matched, "alpha-writers")
	scopes, _, err = GetUserCollectionScopes(db, attacker.Username, attacker.ID, nil, "")
	require.NoError(t, err)
	assert.Empty(t, storageScopesFor(scopes, ns))

	// Step 2: admin renames the group.
	newName := "alpha-editors"
	require.NoError(t, database.UpdateGroup(db, writers.ID, &newName, nil, nil, nil, admin.ID, true, true))

	// Step 3: the attacker claims the vacated name and joins their group.
	stomped, err := database.CreateGroup(db, "alpha-writers", "", "", database.Creator{UserID: attacker.ID}, "", false)
	require.NoError(t, err)
	require.NoError(t, db.Create(&database.GroupMember{GroupID: stomped.ID, UserID: attacker.ID, AddedBy: attacker.ID}).Error)

	scopes, matched, err = GetUserCollectionScopes(db, attacker.Username, attacker.ID, nil, "")
	require.NoError(t, err)
	assert.Empty(t, storageScopesFor(scopes, ns), "reclaimed group name must not inherit the original group's grants")
	assert.NotContains(t, matched, "alpha-writers")

	scopes, matched, err = GetUserCollectionScopes(db, member.Username, member.ID, nil, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"storage.read:" + ns, "storage.modify:" + ns, "storage.create:" + ns}, storageScopesFor(scopes, ns),
		"members of the renamed group must keep their access")
	assert.Contains(t, matched, "alpha-editors")
	assert.NotContains(t, matched, "alpha-writers")

	// A cookie that still asserts the OLD group name (issued before the
	// rename) must not match anything either.
	scopes, _, err = GetUserCollectionScopes(db, attacker.Username, attacker.ID, []string{"alpha-writers"}, "")
	require.NoError(t, err)
	assert.Empty(t, storageScopesFor(scopes, ns))
}

// TestGetUserCollectionScopes_RenamedUserGrantsFollowTheUser replays
// the "username stomping" scenario: alice holds personal (user-alice)
// grants, an admin renames her to alicia, and a new federated identity
// then enrols with the username alice. The newcomer must mint nothing
// for the collection; alicia must keep her grant.
func TestGetUserCollectionScopes_RenamedUserGrantsFollowTheUser(t *testing.T) {
	db := newRenameTestDB(t)
	const ns = "/data/alice-home"
	const localIssuer = "https://local.test"
	seedCollection(t, db, "col-alice", ns)

	alice, err := database.CreateLocalUser(db, "alice", "", localIssuer, database.Creator{UserID: "admin"})
	require.NoError(t, err)
	require.NoError(t, database.GrantCollectionAcl(db, "col-alice", "admin", "admin-id", nil, "user-alice", database.AclRoleRead, nil, true))

	scopes, matched, err := GetUserCollectionScopes(db, alice.Username, alice.ID, nil, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"storage.read:" + ns}, storageScopesFor(scopes, ns))
	assert.Contains(t, matched, "user-alice")

	// Admin renames alice → alicia.
	require.NoError(t, database.RenameUser(db, alice.ID, "alicia", localIssuer))
	alicia, err := database.GetUserByID(db, alice.ID)
	require.NoError(t, err)
	require.Equal(t, "alicia", alicia.Username)

	// A different identity at a federated IdP picks "alice" as its
	// preferred username; the username is now free so enrolment succeeds.
	newcomer, err := database.LookupOrBootstrapUser(db, "someone-else@idp", "https://idp.example", "Alice", []string{"alice"})
	require.NoError(t, err)
	require.Equal(t, "alice", newcomer.Username)
	require.NotEqual(t, alice.ID, newcomer.ID)

	scopes, matched, err = GetUserCollectionScopes(db, newcomer.Username, newcomer.ID, nil, "")
	require.NoError(t, err)
	assert.Empty(t, storageScopesFor(scopes, ns), "a new account with the vacated username must not inherit personal grants")
	assert.NotContains(t, matched, "user-alice")

	scopes, matched, err = GetUserCollectionScopes(db, alicia.Username, alicia.ID, nil, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"storage.read:" + ns}, storageScopesFor(scopes, ns), "the renamed user must keep her grant")
	assert.Contains(t, matched, "user-alicia")
}

// TestGetUserCollectionScopes_LocalGroupCannotImpersonateIdPGroup covers
// the creation-side variant of name stomping. An operator grants a
// collection to an IdP-asserted group ("cms-users") that has no local
// row; the grant is matched purely on name. Because DB-stored group
// membership is consulted regardless of Issuer.GroupSource, a local
// group of the same name would make its members match that grant. So
// creating one must be refused, and the would-be attacker must mint no
// storage scopes — while a genuine IdP member (cookie-asserted group)
// still does.
func TestGetUserCollectionScopes_LocalGroupCannotImpersonateIdPGroup(t *testing.T) {
	db := newRenameTestDB(t)
	const ns = "/data/cms"
	seedCollection(t, db, "col-cms", ns)

	admin, err := database.CreateLocalUser(db, "admin", "", "https://local.test", database.Creator{UserID: "admin"})
	require.NoError(t, err)
	attacker, err := database.CreateLocalUser(db, "eve", "", "https://local.test", database.Creator{UserID: admin.ID})
	require.NoError(t, err)

	// Grant to the IdP group by name. There is no local group row, so
	// GrantCollectionAcl stores the name as given.
	require.NoError(t, database.GrantCollectionAcl(db, "col-cms", admin.Username, admin.ID, nil, "cms-users", database.AclRoleWrite, nil, true))

	// A genuine IdP member (group asserted in the login cookie) gets rwx.
	scopes, matched, err := GetUserCollectionScopes(db, "idp-member", "", []string{"cms-users"}, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"storage.read:" + ns, "storage.modify:" + ns, "storage.create:" + ns}, storageScopesFor(scopes, ns))
	assert.Contains(t, matched, "cms-users")

	// The attacker tries to mint a local group of the same name.
	_, err = database.CreateGroup(db, "cms-users", "", "", database.Creator{UserID: attacker.ID}, "", false)
	require.ErrorIs(t, err, database.ErrACLGrantCollision)

	// Even if they had somehow obtained membership in a group of that
	// name, none exists to join; their token carries nothing for the
	// namespace and the IdP group is not in their matched set.
	var groups []database.Group
	require.NoError(t, db.Where("name = ?", "cms-users").Find(&groups).Error)
	assert.Empty(t, groups)
	scopes, matched, err = GetUserCollectionScopes(db, attacker.Username, attacker.ID, nil, "")
	require.NoError(t, err)
	assert.Empty(t, storageScopesFor(scopes, ns))
	assert.NotContains(t, matched, "cms-users")
}
