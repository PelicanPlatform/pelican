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
)

// unificationVersion is the migration under test.
const unificationVersion int64 = 20260824130000

// migrateUpTo runs the universal migrations up to (and including) version.
func migrateUpTo(t *testing.T, sqlDB *sql.DB, version int64) {
	t.Helper()
	goose.SetBaseFS(EmbedUniversalMigrations)
	require.NoError(t, goose.SetDialect("sqlite3"))
	goose.SetTableName("goose_db_version")
	require.NoError(t, goose.UpTo(sqlDB, "universal_migrations", version))
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

	migrateUpTo(t, sqlDB, unificationVersion-1)

	// Sanity: the pre-state really does carry the columns we are removing.
	var cnt int
	require.NoError(t, sqlDB.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name IN ('sub','issuer')`).Scan(&cnt))
	require.Equal(t, 2, cnt, "expected the pre-unification users schema")
	return db, sqlDB
}

func insertLegacyUser(t *testing.T, sqlDB *sql.DB, id, username, sub, issuer string) {
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

	insertLegacyUser(t, sqlDB, "u-alice", "alice", "alice-sub", "https://idp.example")
	insertLegacyUser(t, sqlDB, "u-bob", "bob", "bob-sub", "https://idp.example")
	insertLegacyIdentity(t, sqlDB, "i-alice-2", "u-alice", "alice-kc", "https://kc.example")

	migrateUpTo(t, sqlDB, unificationVersion)

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

// TestUnificationMigrationReconcilesShadowedIdentity covers a database already
// corrupted by the bug this work fixes: a secondary row claiming an identity
// that another user owns inline. Resolution must not change — the users table
// was consulted first, so the primary is what callers observe today — and the
// discarded row must be recoverable rather than silently dropped.
func TestUnificationMigrationReconcilesShadowedIdentity(t *testing.T) {
	db, sqlDB := newPreUnificationDB(t)

	insertLegacyUser(t, sqlDB, "u-stray", "alice-kc", "kc-sub", "https://kc.example")
	insertLegacyUser(t, sqlDB, "u-alice", "alice", "alice-sub", "https://idp.example")
	// The shadowed link an admin thought they had made.
	insertLegacyIdentity(t, sqlDB, "i-shadow", "u-alice", "kc-sub", "https://kc.example")

	migrateUpTo(t, sqlDB, unificationVersion)

	got, err := GetUserByIdentity(db, "kc-sub", "https://kc.example")
	require.NoError(t, err)
	assert.Equal(t, "u-stray", got.ID,
		"the identity must keep resolving where it resolved before the migration")

	var reason string
	require.NoError(t, sqlDB.QueryRow(
		`SELECT reason FROM user_identity_unification_conflicts WHERE id = 'i-shadow'`).Scan(&reason))
	assert.Contains(t, reason, "shadowed")

	// Both accounts survive; the migration reconciles, it does not delete.
	for _, id := range []string{"u-alice", "u-stray"} {
		_, err := GetUserByID(db, id)
		assert.NoError(t, err, "user %s should still exist", id)
	}

	// And the state is now correctable in one step.
	_, err = AdoptUserIdentity(db, "u-alice", "kc-sub", "https://kc.example")
	require.NoError(t, err)
	got, err = GetUserByIdentity(db, "kc-sub", "https://kc.example")
	require.NoError(t, err)
	assert.Equal(t, "u-alice", got.ID)
}

// TestUnificationMigrationSkipsDeletedUsers keeps the property that
// 20260503120000 established: a tombstoned account must not reserve its
// (sub, issuer) against a later re-enrollment.
func TestUnificationMigrationSkipsDeletedUsers(t *testing.T) {
	db, sqlDB := newPreUnificationDB(t)

	insertLegacyUser(t, sqlDB, "u-gone", "gone", "gone-sub", "https://idp.example")
	_, err := sqlDB.Exec(`UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = 'u-gone'`)
	require.NoError(t, err)

	migrateUpTo(t, sqlDB, unificationVersion)

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

	insertLegacyUser(t, sqlDB, "u-alice", "alice", "alice-sub", "https://idp.example")
	insertLegacyIdentity(t, sqlDB, "i-alice-2", "u-alice", "alice-kc", "https://kc.example")

	migrateUpTo(t, sqlDB, unificationVersion)

	goose.SetBaseFS(EmbedUniversalMigrations)
	require.NoError(t, goose.SetDialect("sqlite3"))
	require.NoError(t, goose.DownTo(sqlDB, "universal_migrations", unificationVersion-1))

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
