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
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const (
	preUsernameVersion    int64 = 20260504000000 // the migration just before the global-username one
	globalUsernameVersion int64 = 20260812000000
)

// TestGlobalUsernameMigrationReconcilesDuplicates seeds the exact state an
// existing deployment holds — two LIVE accounts sharing a username at different
// issuers, which the old UNIQUE(username, issuer) index permitted — and proves
// the global-username migration reconciles rather than aborting the upgrade.
//
// This is the case that broke server startup: without reconciliation the
// CREATE UNIQUE INDEX on username fails and the whole migration errors out.
func TestGlobalUsernameMigrationReconcilesDuplicates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "u.sqlite")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	goose.SetBaseFS(EmbedUniversalMigrations)
	require.NoError(t, goose.SetDialect("sqlite3"))
	goose.SetTableName("goose_db_version")

	// Migrate to the state right before global usernames.
	require.NoError(t, goose.UpTo(sqlDB, "universal_migrations", preUsernameVersion))

	// Two live "alice" accounts at different issuers — legal under the old index.
	// Ordering by created_at decides who keeps the name; give them distinct times.
	_, err = sqlDB.Exec(`INSERT INTO users (id, username, sub, issuer, status, created_by, created_at)
		VALUES ('id-old', 'alice', 'alice@a', 'https://a.example', 'active', 'admin', '2026-01-01 00:00:00')`)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO users (id, username, sub, issuer, status, created_by, created_at)
		VALUES ('id-new', 'alice', 'alice@b', 'https://b.example', 'active', 'admin', '2026-02-01 00:00:00')`)
	require.NoError(t, err)
	// A soft-deleted "alice" must not participate or block anything.
	_, err = sqlDB.Exec(`INSERT INTO users (id, username, sub, issuer, status, created_by, created_at, deleted_at)
		VALUES ('id-gone', 'alice', 'alice@c', 'https://c.example', 'active', 'admin', '2025-01-01 00:00:00', '2025-06-01 00:00:00')`)
	require.NoError(t, err)

	// The migration under test must SUCCEED, not abort.
	require.NoError(t, goose.UpTo(sqlDB, "universal_migrations", globalUsernameVersion),
		"global-username migration must reconcile duplicates instead of failing")

	// The oldest live account keeps the name; the newer one was renamed.
	var oldName, newName string
	require.NoError(t, sqlDB.QueryRow(`SELECT username FROM users WHERE id='id-old'`).Scan(&oldName))
	require.NoError(t, sqlDB.QueryRow(`SELECT username FROM users WHERE id='id-new'`).Scan(&newName))
	assert.Equal(t, "alice", oldName, "the oldest account keeps the username")
	assert.NotEqual(t, "alice", newName, "the newer account was renamed")
	assert.Contains(t, newName, "alice-", "rename keeps the original as a prefix")

	// The rename is recorded for the operator.
	var recorded int
	require.NoError(t, sqlDB.QueryRow(
		`SELECT COUNT(*) FROM username_uniqueness_conflicts WHERE id='id-new' AND original_username='alice'`).Scan(&recorded))
	assert.Equal(t, 1, recorded)

	// The global unique index is now in force.
	_, err = sqlDB.Exec(`UPDATE users SET username='alice' WHERE id='id-new'`)
	require.Error(t, err, "a second live 'alice' must now violate the unique index")

	// Down restores the original names (legal again under the per-issuer index).
	require.NoError(t, goose.DownTo(sqlDB, "universal_migrations", preUsernameVersion))
	require.NoError(t, sqlDB.QueryRow(`SELECT username FROM users WHERE id='id-new'`).Scan(&newName))
	assert.Equal(t, "alice", newName, "down-migration restores the reconciled username")
}
