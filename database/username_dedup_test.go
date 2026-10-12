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

// Coverage for the pre-migration cleanup that resolves usernames shared
// by several live rows before *_global_unique_username.sql runs (issue
// #3824). Each test runs the real goose migrations up to the version
// before that migration, seeds rows in the shapes seen in production,
// runs the cleanup, then finishes the migrations to prove the unique
// index can now be created.

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
)

const (
	dedupLocalIssuer = "https://origin.example.test"
	dedupOldIssuer   = "https://old-origin.example.test"
	dedupOIDCIssuer  = "https://cilogon.org"

	// The base users table from 20250929190630: no last_login_at and no
	// deleted_at yet. v7.26 databases still have this users table.
	versionWithBaseUsersTable = 20250929190630

	// The last universal migration in v7.26.x.
	versionV726 = 20260220120000
)

// versionBeforeGlobalUniqueUsername is the migration the cleanup must run
// after: the last one where UNIQUE(username, issuer) is the rule.
func versionBeforeGlobalUniqueUsername(t *testing.T) int64 {
	t.Helper()
	version, err := globalUniqueUsernameMigrationVersion()
	require.NoError(t, err)
	return version - 1
}

type legacyUser struct {
	id, username, sub, issuer, createdAt string
	lastLoginAt                          *string
}

func insertLegacyUser(t *testing.T, db *gorm.DB, u legacyUser) {
	t.Helper()
	require.NoError(t, db.Exec(
		"INSERT INTO users (id, username, sub, issuer, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?)",
		u.id, u.username, u.sub, u.issuer, u.createdAt, u.lastLoginAt).Error)
}

func strPtr(s string) *string { return &s }

type userState struct {
	id      string
	deleted bool
}

// readUserStates returns every row for a username, live or tombstoned,
// ordered by id.
func readUserStates(t *testing.T, db *gorm.DB, username string) []userState {
	t.Helper()
	rows, err := db.Raw("SELECT id, deleted_at IS NOT NULL FROM users WHERE username = ? ORDER BY id", username).Rows()
	require.NoError(t, err)
	defer rows.Close()
	var out []userState
	for rows.Next() {
		var s userState
		require.NoError(t, rows.Scan(&s.id, &s.deleted))
		out = append(out, s)
	}
	return out
}

func liveUserIDs(t *testing.T, db *gorm.DB, username string) []string {
	t.Helper()
	var ids []string
	for _, s := range readUserStates(t, db, username) {
		if !s.deleted {
			ids = append(ids, s.id)
		}
	}
	return ids
}

func setExternalWebURL(t *testing.T, url string) {
	t.Helper()
	prev := param.Server_ExternalWebUrl.GetString()
	t.Cleanup(func() { require.NoError(t, param.Server_ExternalWebUrl.Set(prev)) })
	require.NoError(t, param.Server_ExternalWebUrl.Set(url))
}

func TestGlobalUniqueUsernameMigrationVersion(t *testing.T) {
	version, err := globalUniqueUsernameMigrationVersion()
	require.NoError(t, err)
	name := fmt.Sprintf("universal_migrations/%d%s", version, globalUniqueUsernameMigrationSuffix)
	_, err = EmbedUniversalMigrations.Open(name)
	require.NoError(t, err, "the resolved version must name an embedded migration")
}

// The director case: Server.ExternalWebUrl changed, so password login
// created a second "admin" row under the new URL. The row matching the
// current URL survives even though the stale row logged in more recently.
func TestDedupLiveUsernamesKeepsRowMatchingExternalWebUrl(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "oldadmin", username: "admin", sub: "admin", issuer: dedupOldIssuer,
		createdAt: "2026-01-01 00:00:00", lastLoginAt: strPtr("2026-09-01 00:00:00")})
	insertLegacyUser(t, db, legacyUser{id: "newadmin", username: "admin", sub: "admin", issuer: dedupLocalIssuer,
		createdAt: "2026-06-01 00:00:00", lastLoginAt: strPtr("2026-07-01 00:00:00")})
	insertLegacyUser(t, db, legacyUser{id: "alice", username: "alice", sub: "sub-alice", issuer: dedupOIDCIssuer,
		createdAt: "2026-03-01 00:00:00"})

	deleted, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)
	assert.Equal(t, []string{"newadmin"}, liveUserIDs(t, db, "admin"))
	assert.Equal(t, []userState{{"newadmin", false}, {"oldadmin", true}}, readUserStates(t, db, "admin"),
		"the loser is tombstoned, not removed")
	assert.Equal(t, []string{"alice"}, liveUserIDs(t, db, "alice"), "rows without a duplicate are untouched")

	finishMigrations(t, sqlDB)
	exists, err := liveUsernameIndexExists(db)
	require.NoError(t, err)
	assert.True(t, exists)

	// The surviving row is the one the admin bootstrap looks up, so the
	// bootstrap adopts it instead of trying to insert a colliding row.
	setExternalWebURL(t, dedupLocalIssuer)
	require.NoError(t, BootstrapAdminAndBackfillOwners(db))
	admin, err := BuiltinAdminUser(db)
	require.NoError(t, err)
	require.NotNil(t, admin)
	assert.Equal(t, "newadmin", admin.ID)
}

// The origin case from issue #3824: the GHSA-rpfr-x88x-xwcw mitigation
// script reserved (admin, cilogon.org) with a placeholder sub. Neither
// row has ever recorded a login; the local row survives and the
// placeholder is tombstoned.
func TestDedupLiveUsernamesDropsProtectivePlaceholder(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "3facd6da", username: "admin", sub: "admin", issuer: dedupLocalIssuer,
		createdAt: "2026-01-28 18:56:07"})
	insertLegacyUser(t, db, legacyUser{id: "ce7baf29", username: "admin",
		sub: protectivePlaceholderSubPrefix + "admin__e6227487", issuer: dedupOIDCIssuer,
		createdAt: "2026-04-23 17:40:27"})
	// A placeholder for a Server.UIAdminUsers entry whose owner had
	// already enrolled under a differently spelled issuer. The placeholder
	// is newer and neither row logged in, so without the placeholder rule
	// the created_at tiebreak would keep the wrong row.
	insertLegacyUser(t, db, legacyUser{id: "bobreal", username: "bob", sub: "http://cilogon.org/serverA/users/42",
		issuer: dedupOIDCIssuer + "/", createdAt: "2026-03-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "bobfake", username: "bob",
		sub: protectivePlaceholderSubPrefix + "bob__e6227487", issuer: dedupOIDCIssuer,
		createdAt: "2026-04-23 17:40:27"})

	deleted, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, 2, deleted)
	assert.Equal(t, []string{"3facd6da"}, liveUserIDs(t, db, "admin"))
	assert.Equal(t, []string{"bobreal"}, liveUserIDs(t, db, "bob"))

	finishMigrations(t, sqlDB)
}

// With no row on the local issuer, the most recent login wins; with no
// logins at all, the newest row wins. The survivors are neither first by
// id nor, for carol, the newest row, so each rule has to do the picking.
func TestDedupLiveUsernamesFallsBackToRecencyThenAge(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "carol-a", username: "carol", sub: "sub-carol", issuer: dedupOIDCIssuer,
		createdAt: "2026-03-01 00:00:00", lastLoginAt: strPtr("2026-04-01 00:00:00")})
	insertLegacyUser(t, db, legacyUser{id: "carol-b", username: "carol", sub: "sub-carol", issuer: dedupOIDCIssuer + "/",
		createdAt: "2026-01-01 00:00:00", lastLoginAt: strPtr("2026-08-01 00:00:00")})
	insertLegacyUser(t, db, legacyUser{id: "carol-c", username: "carol", sub: "sub-carol", issuer: dedupOldIssuer,
		createdAt: "2026-06-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "dave-a", username: "dave", sub: "sub-dave", issuer: dedupOIDCIssuer + "/",
		createdAt: "2026-02-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "dave-b", username: "dave", sub: "sub-dave", issuer: dedupOIDCIssuer,
		createdAt: "2026-06-01 00:00:00"})

	deleted, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, 3, deleted)
	assert.Equal(t, []string{"carol-b"}, liveUserIDs(t, db, "carol"), "latest login beats newer rows and never-logged-in rows")
	assert.Equal(t, []string{"dave-b"}, liveUserIDs(t, db, "dave"), "with no logins the newest row survives")

	finishMigrations(t, sqlDB)
}

// An unset Server.ExternalWebUrl disables the local-issuer preference
// without breaking the rest of the ordering.
func TestDedupLiveUsernamesWithoutExternalWebUrl(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "adm-local", username: "admin", sub: "admin", issuer: dedupLocalIssuer,
		createdAt: "2026-01-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "adm-other", username: "admin", sub: "admin", issuer: dedupOldIssuer,
		createdAt: "2025-06-01 00:00:00", lastLoginAt: strPtr("2026-01-02 00:00:00")})

	deleted, err := dedupLiveUsernames(db, "")
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)
	assert.Equal(t, []string{"adm-other"}, liveUserIDs(t, db, "admin"))

	finishMigrations(t, sqlDB)
}

// Rows already tombstoned are neither counted as duplicates nor touched.
func TestDedupLiveUsernamesIgnoresTombstones(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "live", username: "admin", sub: "admin", issuer: dedupLocalIssuer,
		createdAt: "2026-01-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "gone", username: "admin", sub: "admin", issuer: dedupOldIssuer,
		createdAt: "2025-01-01 00:00:00"})
	require.NoError(t, db.Exec("UPDATE users SET deleted_at = '2026-02-01 00:00:00' WHERE id = 'gone'").Error)

	deleted, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
	assert.Equal(t, []userState{{"gone", true}, {"live", false}}, readUserStates(t, db, "admin"))

	finishMigrations(t, sqlDB)
}

// Once the global index exists the startup wrapper must not touch goose
// or rows. Forgetting an early migration makes any goose call fail with
// "found 1 missing migrations", so success shows none was made.
func TestPrepareForGlobalUniqueUsernamesIsNoopOnceApplied(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "only", username: "admin", sub: "admin", issuer: dedupLocalIssuer,
		createdAt: "2026-01-01 00:00:00"})
	finishMigrations(t, sqlDB)
	require.NoError(t, db.Exec("DELETE FROM goose_db_version WHERE version_id = ?", versionWithBaseUsersTable).Error)

	setExternalWebURL(t, dedupLocalIssuer)
	require.NoError(t, prepareForGlobalUniqueUsernames(sqlDB, db))
	assert.Equal(t, []userState{{"only", false}}, readUserStates(t, db, "admin"))
}

// A database past the global-unique migration without its index (here a
// hand-dropped index) is not on the schema the cleanup was written for,
// so the wrapper leaves its rows alone.
func TestPrepareForGlobalUniqueUsernamesSkipsPastMigration(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	finishMigrations(t, sqlDB)
	require.NoError(t, db.Exec("DROP INDEX "+liveUsernameIndexName).Error)
	insertLegacyUser(t, db, legacyUser{id: "alice-1", username: "alice", sub: "sub-1", issuer: dedupOIDCIssuer,
		createdAt: "2026-01-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "alice-2", username: "alice", sub: "sub-2", issuer: dedupOldIssuer,
		createdAt: "2026-02-01 00:00:00"})

	setExternalWebURL(t, dedupLocalIssuer)
	require.NoError(t, prepareForGlobalUniqueUsernames(sqlDB, db))
	assert.Equal(t, []string{"alice-1", "alice-2"}, liveUserIDs(t, db, "alice"))
}

// readColumnByID returns id -> column for every row of table.
func readColumnByID(t *testing.T, db *gorm.DB, table, column string) map[string]string {
	t.Helper()
	rows, err := db.Raw(fmt.Sprintf("SELECT id, %s FROM %s", column, table)).Rows()
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, value string
		require.NoError(t, rows.Scan(&id, &value))
		out[id] = value
	}
	return out
}

// v7.26 kept collection ownership and API-key creators by username. The
// migrations that turn them into user IDs run with the duplicates live
// (20260429000000) or bind only to a row older than the key
// (20260917110000), so without the cleanup's help both end on the wrong
// row. The placeholder sorts first in idx_user_issuer, so it is the row
// 20260429000000 picks, as on the origins in issue #3824.
func TestPrepareForGlobalUniqueUsernamesMovesUsernameReferences(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionV726)
	require.NoError(t, db.Exec("INSERT INTO users (id, username, sub, issuer, created_at) VALUES "+
		"('oldadmin', 'admin', 'admin', ?, '2026-03-01 12:00:00+02:00'), "+
		"('newadmin', 'admin', 'admin', ?, '2026-06-01 00:00:00'), "+
		"('phadmin', 'admin', ?, ?, '2025-11-01 00:00:00')",
		dedupOldIssuer, dedupLocalIssuer, protectivePlaceholderSubPrefix+"admin__e6227487", dedupOIDCIssuer).Error)
	require.NoError(t, db.Exec(
		"INSERT INTO collections (id, name, owner, namespace) VALUES ('c1', 'stuff', 'admin', '/ns')").Error)
	for _, k := range []struct{ id, createdAt string }{
		// Only the placeholder, a different account, existed.
		{"k-before", "2025-12-01 00:00:00"},
		// 30 minutes after the old-URL row in UTC, though earlier as text.
		{"k-between", "2026-03-01 10:30:00+00:00"},
		{"k-after", "2026-07-01 00:00:00"},
	} {
		require.NoError(t, db.Exec(
			"INSERT INTO api_keys (id, name, hashed_value, created_at, created_by) VALUES (?, ?, 'x', ?, 'admin')",
			k.id, k.id, k.createdAt).Error)
	}

	setExternalWebURL(t, dedupLocalIssuer)
	require.NoError(t, prepareForGlobalUniqueUsernames(sqlDB, db))
	assert.Equal(t, []string{"newadmin"}, liveUserIDs(t, db, "admin"))
	finishMigrations(t, sqlDB)

	assert.Equal(t, map[string]string{"c1": "newadmin"}, readColumnByID(t, db, "collections", "owner_id"))
	assert.Equal(t, map[string]string{"k-after": "newadmin", "k-before": "", "k-between": "newadmin"},
		readColumnByID(t, db, "api_keys", "created_by"),
		"a key older than every row of the admin account stays unattributed")
}

// A collection whose name the survivor already owns stays with the
// soft-deleted row: moving it would break the (owner_id, name) index
// 20260916120000 creates. The survivor got here through a rename from
// "bob" that left collections.owner behind.
func TestDedupLiveUsernamesKeepsCollectionNamesUnique(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "s", username: "alice", sub: "sub-s", issuer: dedupLocalIssuer,
		createdAt: "2026-01-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "l", username: "alice", sub: "sub-l", issuer: dedupOIDCIssuer,
		createdAt: "2026-02-01 00:00:00"})
	require.NoError(t, db.Exec("INSERT INTO collections (id, name, owner, owner_id, namespace) VALUES "+
		"('c-s', 'data', 'bob', 's', '/ns'), ('c-l', 'data', 'alice', 'l', '/ns'), ('c-l2', 'more', 'alice', 'l', '/ns')").Error)

	_, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	finishMigrations(t, sqlDB)
	assert.Equal(t, map[string]string{"c-s": "s", "c-l": "l", "c-l2": "s"}, readColumnByID(t, db, "collections", "owner_id"))
}

// The startup path end to end, from a database with the v7.26 users
// table: it has neither last_login_at nor deleted_at when startup
// begins. The wrapper migrates to the version before the global-unique
// migration (adding those columns), resolves the duplicates, and the
// remaining migrations then succeed. The negative control shows the
// same seed fails without the wrapper, so the test exercises the
// reported crash.
func TestPrepareForGlobalUniqueUsernamesFromPreSoftDeleteSchema(t *testing.T) {
	seed := func(t *testing.T) (*gorm.DB, *sql.DB) {
		db, sqlDB := migrateToVersion(t, versionWithBaseUsersTable)
		require.NoError(t, db.Exec("INSERT INTO users (id, username, sub, issuer) VALUES ('a1', 'admin', 'admin', ?)", dedupOldIssuer).Error)
		require.NoError(t, db.Exec("INSERT INTO users (id, username, sub, issuer) VALUES ('a2', 'admin', 'admin', ?)", dedupLocalIssuer).Error)
		require.NoError(t, db.Exec("INSERT INTO users (id, username, sub, issuer) VALUES ('a3', 'admin', ?, ?)",
			protectivePlaceholderSubPrefix+"admin__e6227487", dedupOIDCIssuer).Error)
		return db, sqlDB
	}

	t.Run("without the cleanup the migration fails", func(t *testing.T) {
		_, sqlDB := seed(t)
		err := goose.Up(sqlDB, "universal_migrations")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "UNIQUE constraint failed: users.username")
	})

	t.Run("with the cleanup the migration succeeds", func(t *testing.T) {
		db, sqlDB := seed(t)
		setExternalWebURL(t, dedupLocalIssuer)
		require.NoError(t, prepareForGlobalUniqueUsernames(sqlDB, db))
		assert.Equal(t, []string{"a2"}, liveUserIDs(t, db, "admin"))

		finishMigrations(t, sqlDB)
		exists, err := liveUsernameIndexExists(db)
		require.NoError(t, err)
		assert.True(t, exists)

		// Idempotent: a second startup finds the index and changes nothing.
		require.NoError(t, prepareForGlobalUniqueUsernames(sqlDB, db))
		assert.Equal(t, []userState{{"a1", true}, {"a2", false}, {"a3", true}}, readUserStates(t, db, "admin"))
	})
}
