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

// Data-migration coverage for 20260916120000_id_keyed_collection_authz,
// which re-keys collection ownership and collection ACLs from names onto
// IDs. The interesting behavior is all in the backfill, so the test runs
// the real goose migrations: up to the migration immediately before,
// seeds rows in the old name-keyed shape, then runs the rest and checks
// what came out the other side.

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database/utils"
)

// versionBeforeIDKeyedAuthz is the migration immediately preceding
// 20260916120000. Seeding happens at this version, where
// `collections.owner` and `collection_acls.group_id` still exist.
const versionBeforeIDKeyedAuthz = 20260911120000

// versionBeforeIDKeyedAPIKeys is the migration immediately preceding
// 20260917120000, i.e. the last version where `api_keys.created_by` may
// hold a username and `groups` has no `deleted_at`.
const versionBeforeIDKeyedAPIKeys = 20260916120000

// versionBeforeGroupAdminLatch is the migration immediately preceding
// 20260919120000, i.e. the last version where `users` has no
// group_admin_status.
const versionBeforeGroupAdminLatch = 20260918120000

// migrateToVersion opens a fresh on-disk SQLite database and runs the
// universal migrations up to (and including) `version`.
func migrateToVersion(t *testing.T, version int64) (*gorm.DB, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "id-keyed-authz.sqlite")
	db, err := utils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	goose.SetBaseFS(EmbedUniversalMigrations)
	require.NoError(t, goose.SetDialect("sqlite3"))
	goose.SetTableName("goose_db_version")
	require.NoError(t, goose.UpTo(sqlDB, "universal_migrations", version))
	return db, sqlDB
}

// finishMigrations runs everything left, i.e. the migration under test.
func finishMigrations(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	require.NoError(t, goose.Up(sqlDB, "universal_migrations"))
}

type migratedACL struct {
	CollectionID string
	SubjectType  string
	SubjectID    string
	Role         string
	GrantedBy    string
}

func readACLs(t *testing.T, db *gorm.DB) []migratedACL {
	t.Helper()
	var rows []migratedACL
	require.NoError(t, db.Table("collection_acls").
		Select("collection_id, subject_type, subject_id, role, granted_by").
		Order("collection_id, subject_type, subject_id, role").
		Scan(&rows).Error)
	return rows
}

func TestIDKeyedAuthzMigration(t *testing.T) {
	t.Run("re-keys grants onto group, user and sentinel subjects", func(t *testing.T) {
		db, sqlDB := migrateToVersion(t, versionBeforeIDKeyedAuthz)

		// Two live users and one locally-created group.
		require.NoError(t, db.Exec(`INSERT INTO users (id, username, sub, issuer, created_by) VALUES
			('u-alice', 'alice', 'alice@idp', 'https://idp.example', 'unknown'),
			('u-bob',   'bob',   'bob@idp',   'https://idp.example', 'unknown')`).Error)
		require.NoError(t, db.Exec(`INSERT INTO groups (id, name, created_by, auth_template_eligible) VALUES
			('g-ops', 'ops', 'u-alice', 1)`).Error)
		require.NoError(t, db.Exec(`INSERT INTO collections (id, name, owner, owner_id, namespace, visibility)
			VALUES ('c1', 'one', 'alice', 'u-alice', '/one', 'private')`).Error)

		// Four grants in the old shape: a local group, an
		// IdP-asserted group with no row, a personal grant, and the
		// all-authenticated sentinel. granted_by is a username.
		require.NoError(t, db.Exec(`INSERT INTO collection_acls (collection_id, group_id, role, granted_by) VALUES
			('c1', 'ops',            'read',  'alice'),
			('c1', 'cms-production', 'write', 'alice'),
			('c1', 'user-bob',       'read',  'alice'),
			('c1', '@authenticated', 'read',  'alice')`).Error)

		finishMigrations(t, sqlDB)

		// The provider-asserted name got a group record of its own so
		// the grant has something to point at. It is eligible for auth
		// templates because it already was: the filter passes through
		// names with no record. Its source is 'unknown' — the old
		// schema never said which provider asserted it, and the next
		// assertion stamps the real one.
		var minted Group
		require.NoError(t, db.Where("name = ?", "cms-production").First(&minted).Error)
		assert.Equal(t, GroupSourceUnknown, minted.Source)
		assert.True(t, minted.Source.IsAsserted())
		assert.True(t, minted.AuthTemplateEligible)
		assert.Len(t, minted.ID, 8, "minted IDs must match generateSlug's 8-hex-char shape")

		// The pre-existing Pelican-created group is untouched.
		var ops Group
		require.NoError(t, db.Where("id = ?", "g-ops").First(&ops).Error)
		assert.Equal(t, GroupSourcePelican, ops.Source,
			"every group that existed before this migration came from the management API")

		assert.ElementsMatch(t, []migratedACL{
			{CollectionID: "c1", SubjectType: "group", SubjectID: "g-ops", Role: "read", GrantedBy: "u-alice"},
			{CollectionID: "c1", SubjectType: "group", SubjectID: minted.ID, Role: "write", GrantedBy: "u-alice"},
			{CollectionID: "c1", SubjectType: "user", SubjectID: "u-bob", Role: "read", GrantedBy: "u-alice"},
			{CollectionID: "c1", SubjectType: "authenticated", SubjectID: "", Role: "read", GrantedBy: "u-alice"},
		}, readACLs(t, db), "granted_by must also be converted from username to User.ID")
	})

	t.Run("drops personal grants whose account is gone", func(t *testing.T) {
		// This is the #3752 fix applied to existing data: a grant to
		// `user-ghost` where no live `ghost` account exists is a
		// dangling reference that the next claimant of the username
		// would inherit. Nothing legitimate can be behind it — a
		// deleted user has no authorizations — so it is dropped.
		db, sqlDB := migrateToVersion(t, versionBeforeIDKeyedAuthz)

		require.NoError(t, db.Exec(`INSERT INTO users (id, username, sub, issuer, created_by, deleted_at) VALUES
			('u-ghost', 'ghost', 'ghost@idp', 'https://idp.example', 'unknown', '2026-01-01 00:00:00')`).Error)
		require.NoError(t, db.Exec(`INSERT INTO collections (id, name, owner, owner_id, namespace, visibility)
			VALUES ('c1', 'one', 'someone', '', '/one', 'private')`).Error)
		require.NoError(t, db.Exec(`INSERT INTO collection_acls (collection_id, group_id, role, granted_by) VALUES
			('c1', 'user-ghost',  'read', 'admin'),
			('c1', 'user-absent', 'read', 'admin')`).Error)

		finishMigrations(t, sqlDB)

		assert.Empty(t, readACLs(t, db),
			"a personal grant naming no live account must not survive as a claimable reference")
	})

	t.Run("backfills owner_id, including from a deleted account", func(t *testing.T) {
		// A soft-deleted owner confers no authority, but keeping the
		// link is strictly better than dropping it: restoring the
		// account restores its collections, while a NEW account that
		// claims the same username gets nothing.
		db, sqlDB := migrateToVersion(t, versionBeforeIDKeyedAuthz)

		require.NoError(t, db.Exec(`INSERT INTO users (id, username, sub, issuer, created_by, deleted_at) VALUES
			('u-old', 'carol', 'carol@idp', 'https://idp.example', 'unknown', '2026-01-01 00:00:00')`).Error)
		require.NoError(t, db.Exec(`INSERT INTO collections (id, name, owner, owner_id, namespace, visibility) VALUES
			('c-deleted-owner', 'a', 'carol',   '', '/a', 'private'),
			('c-no-such-owner', 'b', 'nobody',  '', '/b', 'private')`).Error)

		finishMigrations(t, sqlDB)

		var rows []struct {
			ID      string
			OwnerID string
		}
		require.NoError(t, db.Table("collections").Select("id, owner_id").Order("id").Scan(&rows).Error)
		require.Len(t, rows, 2)
		assert.Equal(t, "u-old", rows[0].OwnerID, "backfill must accept a soft-deleted owner")
		assert.Empty(t, rows[1].OwnerID, "an owner username matching no row at all resolves to nothing")

		// The username column is gone entirely — it was an
		// authorization fallback, not an audit field.
		err := db.Exec(`SELECT owner FROM collections`).Error
		require.Error(t, err)
		assert.Contains(t, err.Error(), "owner")
	})

	t.Run("two collections may share a name only when neither has an owner", func(t *testing.T) {
		// The (owner_id, name) index is partial so unresolvable legacy
		// rows don't collide, but it still stops one owner from having
		// two collections of the same name.
		db, sqlDB := migrateToVersion(t, versionBeforeIDKeyedAuthz)
		require.NoError(t, db.Exec(`INSERT INTO collections (id, name, owner, owner_id, namespace, visibility) VALUES
			('c1', 'dup', 'nobody',  '', '/1', 'private'),
			('c2', 'dup', 'no-one',  '', '/2', 'private')`).Error)

		finishMigrations(t, sqlDB)

		require.NoError(t, db.Exec(`INSERT INTO collections (id, name, owner_id, namespace, visibility)
			VALUES ('c3', 'mine', 'u-x', '/3', 'private')`).Error)
		err := db.Exec(`INSERT INTO collections (id, name, owner_id, namespace, visibility)
			VALUES ('c4', 'mine', 'u-x', '/4', 'private')`).Error
		require.Error(t, err, "one owner must not hold two collections of the same name")
	})

	t.Run("converts collection_members.added_by to a user ID", func(t *testing.T) {
		db, sqlDB := migrateToVersion(t, versionBeforeIDKeyedAuthz)
		require.NoError(t, db.Exec(`INSERT INTO users (id, username, sub, issuer, created_by) VALUES
			('u-alice', 'alice', 'alice@idp', 'https://idp.example', 'unknown')`).Error)
		require.NoError(t, db.Exec(`INSERT INTO collections (id, name, owner, owner_id, namespace, visibility)
			VALUES ('c1', 'one', 'alice', 'u-alice', '/one', 'private')`).Error)
		require.NoError(t, db.Exec(`INSERT INTO collection_members (collection_id, object_url, added_by) VALUES
			('c1', 'pelican://example/one/a', 'alice'),
			('c1', 'pelican://example/one/b', 'long-gone')`).Error)

		finishMigrations(t, sqlDB)

		var rows []struct {
			ObjectURL string
			AddedBy   string
		}
		require.NoError(t, db.Table("collection_members").
			Select("object_url, added_by").Order("object_url").Scan(&rows).Error)
		require.Len(t, rows, 2)
		assert.Equal(t, "u-alice", rows[0].AddedBy)
		assert.Equal(t, "unknown", rows[1].AddedBy, "an unresolvable username becomes the audit sentinel")
	})
}

func TestIDKeyedAPIKeysAndGroupSoftDeleteMigration(t *testing.T) {
	t.Run("api_keys.created_by becomes a user ID, or empty", func(t *testing.T) {
		db, sqlDB := migrateToVersion(t, versionBeforeIDKeyedAPIKeys)

		// alice predates her key. bob is the reuse case: the original
		// bob was deleted and someone new was onboarded under the same
		// username AFTER the old bob's key was minted.
		require.NoError(t, db.Exec(`INSERT INTO users (id, username, sub, issuer, created_by, created_at) VALUES
			('u-alice',   'alice', 'alice@idp', 'https://idp.example', 'unknown', '2025-06-01'),
			('u-bob-new', 'bob',   'bob2@idp',  'https://idp.example', 'unknown', '2026-03-01')`).Error)
		// Four shapes the column has held: a username (what the create
		// handler wrote), an ID (what the code always assumed), a name
		// that resolves to nobody at all, and a name that resolves to
		// somebody who is not who minted the key.
		require.NoError(t, db.Exec(`INSERT INTO api_keys (id, name, hashed_value, scopes, expires_at, created_at, created_by) VALUES
			('k1', 'by-name',    'h1', 'web_ui.access', '2030-01-01', '2026-01-01', 'alice'),
			('k2', 'by-id',      'h2', 'web_ui.access', '2030-01-01', '2026-01-01', 'u-alice'),
			('k3', 'by-nobody',  'h3', 'web_ui.access', '2030-01-01', '2026-01-01', 'long-gone'),
			('k4', 'pre-column', 'h4', 'web_ui.access', '2030-01-01', '2026-01-01', ''),
			('k5', 'by-reused',  'h5', 'web_ui.access', '2030-01-01', '2026-01-01', 'bob')`).Error)

		finishMigrations(t, sqlDB)

		var rows []struct {
			ID        string
			CreatedBy string
		}
		require.NoError(t, db.Table("api_keys").Select("id, created_by").Order("id").Scan(&rows).Error)
		require.Len(t, rows, 5)
		assert.Equal(t, "u-alice", rows[0].CreatedBy, "a username must be converted to the account's ID")
		assert.Equal(t, "u-alice", rows[1].CreatedBy, "a value that is already an ID is left alone")
		assert.Empty(t, rows[2].CreatedBy,
			"a creator that resolves to nobody becomes empty, which fails closed on user-grantable scopes")
		assert.Empty(t, rows[3].CreatedBy)
		assert.Empty(t, rows[4].CreatedBy,
			"a username whose current holder was onboarded after the key was minted is NOT that key's creator; "+
				"binding it would be the very handle-reuse this migration exists to close")
	})

	// Rebuilding `groups` drops the old table, and SQLite treats that as
	// deleting every row in it — firing group_members' ON DELETE CASCADE
	// and taking every membership on the server with it. The first
	// version of this migration did exactly that; the first version of
	// this test did not notice, because it seeded no memberships.
	t.Run("rebuilding groups does not cascade away group memberships", func(t *testing.T) {
		db, sqlDB := migrateToVersion(t, versionBeforeIDKeyedAPIKeys)
		require.NoError(t, db.Exec(`PRAGMA foreign_keys = ON`).Error)
		require.NoError(t, db.Exec(`INSERT INTO users (id, username, sub, issuer, created_by) VALUES
			('u-alice', 'alice', 'alice@idp', 'https://idp.example', 'unknown')`).Error)
		require.NoError(t, db.Exec(`INSERT INTO groups (id, name, created_by, auth_template_eligible, source)
			VALUES ('g-ops', 'ops', 'unknown', 1, 'pelican')`).Error)
		require.NoError(t, db.Exec(`INSERT INTO group_members (group_id, user_id, added_by)
			VALUES ('g-ops', 'u-alice', 'unknown')`).Error)
		// group_scopes cascades from groups too, and would go the same
		// way — a group silently losing its granted scopes rather than
		// its members.
		require.NoError(t, db.Exec(`INSERT INTO group_scopes (group_id, scope, granted_by)
			VALUES ('g-ops', 'web_ui.access', 'unknown')`).Error)

		finishMigrations(t, sqlDB)

		var members int64
		require.NoError(t, db.Model(&GroupMember{}).Count(&members).Error)
		assert.EqualValues(t, 1, members, "the membership must survive the rebuild")

		var scopes int64
		require.NoError(t, db.Table("group_scopes").Count(&scopes).Error)
		assert.EqualValues(t, 1, scopes, "the granted scope must survive the rebuild")

		// And the schema is still sound afterwards: foreign keys back on,
		// no dangling references left behind by the swap.
		var violations []map[string]interface{}
		require.NoError(t, db.Raw("PRAGMA foreign_key_check").Scan(&violations).Error)
		assert.Empty(t, violations, "the rebuilt table must leave no foreign-key violations")
	})

	t.Run("groups gain a tombstone and release their name", func(t *testing.T) {
		db, sqlDB := migrateToVersion(t, versionBeforeIDKeyedAPIKeys)
		require.NoError(t, db.Exec(`INSERT INTO groups (id, name, created_by, auth_template_eligible, source)
			VALUES ('g-ops', 'ops', 'unknown', 1, 'pelican')`).Error)

		finishMigrations(t, sqlDB)

		// Existing rows come through live, with every column intact —
		// the table is rebuilt to shed an inline UNIQUE constraint, so
		// this is checking the copy, not just the new column.
		var ops Group
		require.NoError(t, db.First(&ops, "id = ?", "g-ops").Error)
		assert.Equal(t, "ops", ops.Name)
		assert.Equal(t, GroupSourcePelican, ops.Source)
		assert.True(t, ops.AuthTemplateEligible)
		assert.False(t, ops.DeletedAt.Valid)

		// A live name is still unique...
		assert.Error(t, db.Exec(`INSERT INTO groups (id, name, created_by, auth_template_eligible, source)
			VALUES ('g-dup', 'ops', 'unknown', 1, 'pelican')`).Error)

		// ...but a tombstoned one is released, while its ID stays spent.
		require.NoError(t, db.Delete(&ops).Error)
		require.NoError(t, db.Exec(`INSERT INTO groups (id, name, created_by, auth_template_eligible, source)
			VALUES ('g-new', 'ops', 'unknown', 1, 'pelican')`).Error)
		assert.Error(t, db.Exec(`INSERT INTO groups (id, name, created_by, auth_template_eligible, source)
			VALUES ('g-ops', 'other', 'unknown', 1, 'pelican')`).Error,
			"the tombstone must keep the ID spent")
	})
}

// Every account that existed before the latch is 'unknown', not
// 'ruled-out'. That is the whole point: before this migration nothing
// was recorded about group-derived admin privileges, so nothing is
// known, and a guard that reads silence as "not an administrator" is
// how a user-administrator came to be able to act on one.
func TestGroupAdminLatchMigrationDefaultsToUnknown(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGroupAdminLatch)

	require.NoError(t, db.Exec(`INSERT INTO users (id, username, sub, issuer, created_by) VALUES
		('u-alice', 'alice', 'alice@idp', 'https://idp.example', 'unknown'),
		('u-bob',   'bob',   'bob@idp',   'https://idp.example', 'unknown')`).Error)

	finishMigrations(t, sqlDB)

	var users []User
	require.NoError(t, db.Order("id").Find(&users).Error)
	require.Len(t, users, 2)
	for _, u := range users {
		assert.Equal(t, GroupAdminUnknown, u.GroupAdminStatus,
			"account %s must not be presumed safe to touch", u.Username)
		assert.True(t, u.GroupAdminStatus.MayBeAdmin())
		assert.Nil(t, u.GroupsObservedAt, "nothing has been observed yet")
	}

	// And a new account created after the migration starts the same way.
	require.NoError(t, db.Exec(`INSERT INTO users (id, username, sub, issuer, created_by) VALUES
		('u-carol', 'carol', 'carol@idp', 'https://idp.example', 'unknown')`).Error)
	var carol User
	require.NoError(t, db.First(&carol, "id = ?", "u-carol").Error)
	assert.Equal(t, GroupAdminUnknown, carol.GroupAdminStatus)
}
