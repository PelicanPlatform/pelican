//go:build server || client

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
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	dbutils "github.com/pelicanplatform/pelican/database/utils"
)

// unifyUserIdentitiesMigrationSuffix names the migration under test; its
// version is read from the file name so a renumber cannot desync these tests.
const unifyUserIdentitiesMigrationSuffix = "_unify_user_identities.sql"

func unificationVersion(t *testing.T) int64 {
	t.Helper()
	version, err := dbutils.MigrationVersion(EmbedUniversalMigrations, "universal_migrations", unifyUserIdentitiesMigrationSuffix)
	require.NoError(t, err)
	return version
}

// migrateUpTo runs the universal migrations up to (and including) version.
func migrateUpTo(t *testing.T, sqlDB *sql.DB, version int64) {
	t.Helper()
	require.NoError(t, tryMigrateUpTo(sqlDB, version))
}

// tryMigrateUpTo is migrateUpTo for the cases that expect a migration to stop.
func tryMigrateUpTo(sqlDB *sql.DB, version int64) error {
	goose.SetBaseFS(EmbedUniversalMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}
	goose.SetTableName("goose_db_version")
	return goose.UpTo(sqlDB, "universal_migrations", version)
}

// newPreUnificationDB builds a database at the schema immediately before the
// identity-unification migration, i.e. one that still has users.sub/issuer.
func newPreUnificationDB(t *testing.T) (*gorm.DB, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "unify.sqlite")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	migrateUpTo(t, sqlDB, unificationVersion(t)-1)

	// Sanity: the pre-state really does carry the columns we are removing.
	var cnt int
	require.NoError(t, sqlDB.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name IN ('sub','issuer')`).Scan(&cnt))
	require.Equal(t, 2, cnt, "expected the pre-unification users schema")
	return db, sqlDB
}

func insertPreUnificationUser(t *testing.T, sqlDB *sql.DB, id, username, sub, issuer string) {
	t.Helper()
	_, err := sqlDB.Exec(
		`INSERT INTO users (id, username, sub, issuer, status, created_by) VALUES (?,?,?,?,'active','admin')`,
		id, username, sub, issuer)
	require.NoError(t, err)
}

func insertLegacyIdentity(t *testing.T, sqlDB *sql.DB, id, userID, sub, issuer string) {
	t.Helper()
	_, err := sqlDB.Exec(
		`INSERT INTO user_identities (id, user_id, sub, issuer) VALUES (?,?,?,?)`,
		id, userID, sub, issuer)
	require.NoError(t, err)
}

// TestUnificationMigrationPromotesPrimaryIdentities is the ordinary case: every
// live user's inline identity becomes a row like any other.
func TestUnificationMigrationPromotesPrimaryIdentities(t *testing.T) {
	db, sqlDB := newPreUnificationDB(t)

	insertPreUnificationUser(t, sqlDB, "u-alice", "alice", "alice-sub", "https://idp.example")
	insertPreUnificationUser(t, sqlDB, "u-bob", "bob", "bob-sub", "https://idp.example")
	insertLegacyIdentity(t, sqlDB, "i-alice-2", "u-alice", "alice-kc", "https://kc.example")

	migrateUpTo(t, sqlDB, unificationVersion(t))

	// The columns are gone.
	var cnt int
	require.NoError(t, sqlDB.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name IN ('sub','issuer')`).Scan(&cnt))
	assert.Equal(t, 0, cnt)

	// Alice keeps both identities; each resolves to her.
	for _, pair := range [][2]string{{"alice-sub", "https://idp.example"}, {"alice-kc", "https://kc.example"}} {
		got, err := GetUserByIdentity(db, pair[0], pair[1])
		require.NoError(t, err, "identity %v should resolve", pair)
		assert.Equal(t, "u-alice", got.ID)
	}
	got, err := GetUserByIdentity(db, "bob-sub", "https://idp.example")
	require.NoError(t, err)
	assert.Equal(t, "u-bob", got.ID)
}

// A database already corrupted by the bug this work fixes cannot be carried
// across: the unified indexes hold one of the two rows, not both. The upgrade
// stops rather than picking a winner, because which account owns the identity
// is an operator's decision and a silent reconciliation is one nobody sees.
func TestUnificationMigrationFailsClosedOnConflictingIdentities(t *testing.T) {
	t.Run("an identity another live user owns inline", func(t *testing.T) {
		_, sqlDB := newPreUnificationDB(t)
		insertPreUnificationUser(t, sqlDB, "u-stray", "alice-kc", "kc-sub", "https://kc.example")
		insertPreUnificationUser(t, sqlDB, "u-alice", "alice", "alice-sub", "https://idp.example")
		// The shadowed link an admin thought they had made.
		insertLegacyIdentity(t, sqlDB, "i-shadow", "u-alice", "kc-sub", "https://kc.example")

		err := tryMigrateUpTo(sqlDB, unificationVersion(t))
		require.Error(t, err, "the upgrade must stop rather than reconcile")
		assert.Contains(t, err.Error(), "UNIQUE constraint failed")

		// Dropping the losing row is the whole remedy, and the upgrade goes
		// through on the next start.
		_, err = sqlDB.Exec(`DELETE FROM user_identities WHERE id = 'i-shadow'`)
		require.NoError(t, err)
		migrateUpTo(t, sqlDB, unificationVersion(t))
	})

	t.Run("a second identity at the user's own issuer", func(t *testing.T) {
		_, sqlDB := newPreUnificationDB(t)
		insertPreUnificationUser(t, sqlDB, "u-alice", "alice", "alice-sub", "https://idp.example")
		insertLegacyIdentity(t, sqlDB, "i-dup", "u-alice", "alice-other", "https://idp.example")

		err := tryMigrateUpTo(sqlDB, unificationVersion(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "UNIQUE constraint failed")
	})
}

// TestUnificationMigrationSkipsDeletedUsers keeps the property that
// 20260503120000 established: a tombstoned account must not reserve its
// (sub, issuer) against a later re-enrollment.
func TestUnificationMigrationSkipsDeletedUsers(t *testing.T) {
	db, sqlDB := newPreUnificationDB(t)

	insertPreUnificationUser(t, sqlDB, "u-gone", "gone", "gone-sub", "https://idp.example")
	_, err := sqlDB.Exec(`UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = 'u-gone'`)
	require.NoError(t, err)

	migrateUpTo(t, sqlDB, unificationVersion(t))

	_, err = GetUserByIdentity(db, "gone-sub", "https://idp.example")
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound, "a tombstone must not hold an identity")

	// The freed identity can be claimed by a new account.
	fresh, err := LookupOrBootstrapUser(db, "gone-sub", "https://idp.example", "Gone", []string{"gone2"})
	require.NoError(t, err)
	assert.NotEqual(t, "u-gone", fresh.ID)
}

// TestUnificationMigrationIsReversible exercises the down path, which is lossy
// by nature but must leave a schema the previous release can run against.
func TestUnificationMigrationIsReversible(t *testing.T) {
	_, sqlDB := newPreUnificationDB(t)

	insertPreUnificationUser(t, sqlDB, "u-alice", "alice", "alice-sub", "https://idp.example")
	insertLegacyIdentity(t, sqlDB, "i-alice-2", "u-alice", "alice-kc", "https://kc.example")

	migrateUpTo(t, sqlDB, unificationVersion(t))

	goose.SetBaseFS(EmbedUniversalMigrations)
	require.NoError(t, goose.SetDialect("sqlite3"))
	require.NoError(t, goose.DownTo(sqlDB, "universal_migrations", unificationVersion(t)-1))

	var cnt int
	require.NoError(t, sqlDB.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name IN ('sub','issuer')`).Scan(&cnt))
	assert.Equal(t, 2, cnt, "the columns must come back")

	var sub, issuer string
	require.NoError(t, sqlDB.QueryRow(
		`SELECT sub, issuer FROM users WHERE id = 'u-alice'`).Scan(&sub, &issuer))
	assert.Equal(t, "alice-sub", sub, "the oldest identity is restored inline")
	assert.Equal(t, "https://idp.example", issuer)

	// The identity that was restored inline is not also left duplicated.
	var remaining int
	require.NoError(t, sqlDB.QueryRow(
		`SELECT COUNT(*) FROM user_identities WHERE user_id = 'u-alice'`).Scan(&remaining))
	assert.Equal(t, 1, remaining, "only the second identity should remain in the table")
}
