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
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	dbutils "github.com/pelicanplatform/pelican/database/utils"
)

// newCollectionTestDB spins up an in-memory sqlite database with just the
// tables GetUserCollectionScopes touches. We deliberately don't migrate
// the full schema — these tests are about scope emission, not about the
// surrounding ownership-model invariants.
func newCollectionTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// The production migrations, not AutoMigrate: GORM can only emit a
	// FULL unique index from struct tags, so a hand-rolled schema lacks
	// the partial indexes that let a soft-deleted group or account
	// release its name — and this package's tests turn on exactly those
	// paths.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// ":memory:" is per-connection, so the pool must be pinned to one.
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	return db
}

// seedUser inserts (or reuses) a user row. Test IDs follow the
// "<username>-id" convention so a fixture can name the same user by
// either handle without threading the slug around.
func seedUser(t *testing.T, db *gorm.DB, username string) string {
	t.Helper()
	id := username + "-id"
	var u database.User
	require.NoError(t, db.Where(database.User{Username: username}).Attrs(database.User{
		ID: id, Sub: username, Issuer: "https://idp.example.com",
		Status: database.UserStatusActive,
	}).FirstOrCreate(&u).Error)
	return u.ID
}

// seedGroup inserts (or reuses) a group row and returns its ID.
func seedGroup(t *testing.T, db *gorm.DB, name string) string {
	t.Helper()
	var g database.Group
	require.NoError(t, db.Where(database.Group{Name: name}).Attrs(database.Group{
		ID: "g-" + name, CreatedBy: "owner-user-id", OwnerID: "owner-user-id",
	}).FirstOrCreate(&g).Error)
	return g.ID
}

// seedCollection inserts a collection row directly. We bypass the
// CreateCollection helper so the test isn't dependent on the surrounding
// ownership / authorization logic.
func seedCollection(t *testing.T, db *gorm.DB, id, namespace string) {
	t.Helper()
	seedUser(t, db, "owner-user")
	require.NoError(t, db.Create(&database.Collection{
		ID:         id,
		Name:       id,
		OwnerID:    "owner-user-id",
		Namespace:  namespace,
		Visibility: database.VisibilityPrivate,
	}).Error)
}

// seedACL grants a role on a collection to `target`, which is written
// the way an operator would name it: a group name, `user-<username>`,
// or the all-authenticated sentinel. The helper materializes whatever
// row that names and stores the resulting ID, mirroring what
// database.ResolveACLSubject does in production.
func seedACL(t *testing.T, db *gorm.DB, collectionID, target string, role database.AclRole, expiresAt *time.Time) {
	t.Helper()
	acl := database.CollectionACL{
		CollectionID: collectionID,
		Role:         role,
		GrantedBy:    "owner-user-id",
		ExpiresAt:    expiresAt,
	}
	switch {
	case target == database.AllAuthenticatedUsersACLGroup:
		acl.SubjectType = database.ACLSubjectAuthenticated
	case strings.HasPrefix(target, database.PersonalACLGroupPrefix):
		acl.SubjectType = database.ACLSubjectUser
		acl.SubjectID = seedUser(t, db, strings.TrimPrefix(target, database.PersonalACLGroupPrefix))
	default:
		acl.SubjectType = database.ACLSubjectGroup
		acl.SubjectID = seedGroup(t, db, target)
	}
	require.NoError(t, db.Create(&acl).Error)
}

// TestGetUserCollectionScopes_StorageScopeBridge verifies the data-plane
// half of the collection-ACL design: a user with a "read" or "write" ACL
// on a collection should get storage.* scopes for that collection's
// namespace, even when the issuer's AuthorizationTemplates grant them
// nothing on that prefix.
func TestGetUserCollectionScopes_StorageScopeBridge(t *testing.T) {
	t.Run("read-acl-emits-storage-read-only", func(t *testing.T) {
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-read", "/data/read-only")
		seedACL(t, db, "col-read", "physics", database.AclRoleRead, nil)

		scopes, matched, err := GetUserCollectionScopes(db, "alice", "", []string{"physics"}, "")
		require.NoError(t, err)

		assert.Contains(t, scopes, "storage.read:/data/read-only",
			"read ACL should grant storage.read on the collection's namespace")
		assert.NotContains(t, scopes, "storage.modify:/data/read-only",
			"read ACL must NOT grant storage.modify")
		assert.NotContains(t, scopes, "storage.create:/data/read-only",
			"read ACL must NOT grant storage.create")

		// Management-plane scope is still emitted, keyed by collection ID.
		assert.Contains(t, scopes, "collection.read:col-read",
			"read ACL should still grant management-plane collection.read")
		assert.NotContains(t, scopes, "collection.modify:col-read",
			"read ACL must NOT grant collection.modify")

		assert.Contains(t, matched, "physics", "ACL'd group should be in matchedGroups")
	})

	t.Run("write-acl-emits-full-rwx", func(t *testing.T) {
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-write", "/data/shared")
		seedACL(t, db, "col-write", "physics", database.AclRoleWrite, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"physics"}, "")
		require.NoError(t, err)

		assert.Contains(t, scopes, "storage.read:/data/shared")
		assert.Contains(t, scopes, "storage.modify:/data/shared")
		assert.Contains(t, scopes, "storage.create:/data/shared")

		assert.Contains(t, scopes, "collection.read:col-write")
		assert.Contains(t, scopes, "collection.modify:col-write")
	})

	t.Run("owner-acl-emits-full-rwx", func(t *testing.T) {
		// AclRoleOwner is the legacy "this group owns the collection"
		// role. Per the ownership-model rewrite it's no longer minted on
		// new collections, but legacy rows in the field still carry it,
		// so the scope path must continue to handle it the same as
		// "write" on the data plane.
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-owner", "/data/legacy")
		seedACL(t, db, "col-owner", "physics", database.AclRoleOwner, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"physics"}, "")
		require.NoError(t, err)

		assert.Contains(t, scopes, "storage.read:/data/legacy")
		assert.Contains(t, scopes, "storage.modify:/data/legacy")
		assert.Contains(t, scopes, "storage.create:/data/legacy")
		assert.Contains(t, scopes, "collection.delete:col-owner",
			"legacy owner ACL still mints management-plane delete")
	})

	t.Run("user-not-in-acl-group-gets-nothing", func(t *testing.T) {
		// The negative case the user explicitly asked for: without
		// membership in the ACL'd group, the user must NOT get storage
		// scopes for the collection's namespace.
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-read", "/data/private")
		seedACL(t, db, "col-read", "physics", database.AclRoleRead, nil)

		scopes, matched, err := GetUserCollectionScopes(db, "bob", "", []string{"chemistry"}, "")
		require.NoError(t, err)

		// The capability scopes (collection.create:/, collection.read:/)
		// are always there for any authenticated caller; that's not
		// sufficient for storage access.
		assert.NotContains(t, scopes, "storage.read:/data/private",
			"non-member must NOT get storage.read on someone else's collection")
		assert.NotContains(t, scopes, "collection.read:col-read",
			"non-member must NOT get collection.read on the specific collection")
		assert.NotContains(t, matched, "physics",
			"the unrelated ACL group must not appear in matchedGroups")
	})

	t.Run("expired-acl-grants-nothing", func(t *testing.T) {
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-expired", "/data/stale")
		past := time.Now().Add(-1 * time.Hour)
		seedACL(t, db, "col-expired", "physics", database.AclRoleWrite, &past)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"physics"}, "")
		require.NoError(t, err)

		assert.NotContains(t, scopes, "storage.read:/data/stale",
			"expired ACL must not contribute storage scopes")
		assert.NotContains(t, scopes, "storage.modify:/data/stale")
	})

	t.Run("user-personal-group-acl-also-bridges", func(t *testing.T) {
		// The function auto-injects "user-<username>" into the groups
		// list so a user's personal group is treated as a real group
		// for ACL lookup. Verify the bridge works through that path
		// even when the caller passes no explicit group memberships.
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-personal", "/data/alice-only")
		seedACL(t, db, "col-personal", "user-alice", database.AclRoleRead, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{}, "")
		require.NoError(t, err)
		assert.Contains(t, scopes, "storage.read:/data/alice-only",
			"a user-<name> ACL on a collection should bridge to storage.read")
	})

	t.Run("multi-acl-takes-highest-role", func(t *testing.T) {
		// If a user is in two groups that both have ACLs on the same
		// collection — one read, one write — they get the union of
		// scopes (which is just the write set, since read ⊂ write).
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-multi", "/data/team")
		seedACL(t, db, "col-multi", "physics", database.AclRoleRead, nil)
		seedACL(t, db, "col-multi", "writers", database.AclRoleWrite, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"physics", "writers"}, "")
		require.NoError(t, err)
		assert.Contains(t, scopes, "storage.read:/data/team")
		assert.Contains(t, scopes, "storage.modify:/data/team")
		assert.Contains(t, scopes, "storage.create:/data/team")
	})

	t.Run("namespace-is-canonicalized", func(t *testing.T) {
		// Defensive: storage scopes are matched against canonical paths
		// downstream, so the bridge should canonicalize whatever is in
		// Collection.Namespace before emitting. Trailing slashes, double
		// slashes, and `..` segments are the typical hazards.
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-dirty", "/data//sub/../shared/")
		seedACL(t, db, "col-dirty", "physics", database.AclRoleRead, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"physics"}, "")
		require.NoError(t, err)
		assert.Contains(t, scopes, "storage.read:/data/shared",
			"namespace path should be canonicalized before being emitted as a scope")
	})

	t.Run("namespace-scoped-issuer-relativizes-storage-scope", func(t *testing.T) {
		// Per-namespace issuers in Pelican mint tokens whose storage
		// scope paths are *namespace-relative*: a token issued at
		// /api/v1.0/issuer/ns/data with the collection rooted at
		// /data/team should carry storage.read:/team, not /data/team.
		// xrootd then validates against the same namespace-relative
		// path. This is the property the E2E test depends on.
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-relative", "/data/team")
		seedACL(t, db, "col-relative", "team-readers", database.AclRoleRead, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"team-readers"}, "/data")
		require.NoError(t, err)
		assert.Contains(t, scopes, "storage.read:/team",
			"per-namespace issuer must emit a namespace-relative storage scope")
		assert.NotContains(t, scopes, "storage.read:/data/team",
			"per-namespace issuer must NOT emit the federation-absolute path")
	})

	t.Run("namespace-scoped-issuer-skips-out-of-scope-collection", func(t *testing.T) {
		// A collection whose namespace is outside the issuer's
		// federation prefix gets no storage.* scopes from this
		// issuer — they would be unenforceable / nonsensical. The
		// management-plane collection.* scope is still emitted,
		// because the management API is namespace-agnostic.
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-outside", "/other/place")
		seedACL(t, db, "col-outside", "team-readers", database.AclRoleWrite, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"team-readers"}, "/data")
		require.NoError(t, err)
		assert.NotContains(t, scopes, "storage.read:/other/place")
		assert.NotContains(t, scopes, "storage.modify:/other/place")
		assert.Contains(t, scopes, "collection.modify:col-outside",
			"out-of-scope collection still gets management-plane scopes")
	})

	t.Run("namespace-scoped-issuer-collection-at-root-returns-slash", func(t *testing.T) {
		// Edge case: collection's namespace is exactly the issuer's
		// namespace (i.e. a collection rooted at the namespace root).
		// Stripping the prefix should leave "/" — the entire
		// namespace is the collection.
		db := newCollectionTestDB(t)
		seedCollection(t, db, "col-root", "/data")
		seedACL(t, db, "col-root", "team-readers", database.AclRoleRead, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"team-readers"}, "/data")
		require.NoError(t, err)
		assert.Contains(t, scopes, "storage.read:/",
			"collection at namespace root should grant storage.read:/")
	})
}
