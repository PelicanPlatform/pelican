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

// Each test migrates to the version before the global-unique-username
// migration, seeds the shapes seen in production (issue #3824), runs the
// cleanup, then finishes the migrations.

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const (
	dedupLocalIssuer = "https://origin.example.test"
	dedupOldIssuer   = "https://old-origin.example.test"
	dedupOIDCIssuer  = "https://cilogon.org"

	// The base users table: no last_login_at and no deleted_at yet.
	versionWithBaseUsersTable = 20250929190630
	versionV726               = 20260220120000
)

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

// readUserStates returns every row for a username, live or tombstoned.
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

func insertGroupWithMembers(t *testing.T, db *gorm.DB, groupID string, userIDs ...string) {
	t.Helper()
	require.NoError(t, db.Exec("INSERT INTO groups (id, name, created_by) VALUES (?, ?, 'unknown')", groupID, groupID).Error)
	for _, id := range userIDs {
		require.NoError(t, db.Exec("INSERT INTO group_members (group_id, user_id, added_by) VALUES (?, ?, 'unknown')", groupID, id).Error)
	}
}

func groupMemberIDs(t *testing.T, db *gorm.DB, groupID string) []string {
	t.Helper()
	var ids []string
	require.NoError(t, db.Raw("SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id", groupID).Scan(&ids).Error)
	return ids
}

func insertLegacyAPIKey(t *testing.T, db *gorm.DB, id, createdBy, createdAt string) {
	t.Helper()
	require.NoError(t, db.Exec(
		"INSERT INTO api_keys (id, name, hashed_value, created_at, created_by) VALUES (?, ?, 'x', ?, ?)",
		id, id, createdAt, createdBy).Error)
}

func TestGlobalUniqueUsernameMigrationVersion(t *testing.T) {
	version, err := globalUniqueUsernameMigrationVersion()
	require.NoError(t, err)
	name := fmt.Sprintf("universal_migrations/%d%s", version, globalUniqueUsernameMigrationSuffix)
	_, err = EmbedUniversalMigrations.Open(name)
	require.NoError(t, err, "the resolved version must name an embedded migration")
}

// The director case: the row on the current URL wins over a stale one.
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

	setExternalWebURL(t, dedupLocalIssuer)
	require.NoError(t, BootstrapAdminAndBackfillOwners(db))
	admin, err := BuiltinAdminUser(db)
	require.NoError(t, err)
	require.NotNil(t, admin)
	assert.Equal(t, "newadmin", admin.ID)
}

// The origin case: GHSA-rpfr-x88x-xwcw placeholders lose.
func TestDedupLiveUsernamesDropsProtectivePlaceholder(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "3facd6da", username: "admin", sub: "admin", issuer: dedupLocalIssuer,
		createdAt: "2026-01-28 18:56:07"})
	insertLegacyUser(t, db, legacyUser{id: "ce7baf29", username: "admin",
		sub: protectivePlaceholderSubPrefix + "admin__e6227487", issuer: dedupOIDCIssuer,
		createdAt: "2026-04-23 17:40:27"})
	// Newer than the real row, so only the placeholder rule keeps the right one.
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

func TestDedupLiveUsernamesFallsBackToRecencyThenAge(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "carol-a", username: "carol", sub: "sub-carol", issuer: dedupOIDCIssuer,
		createdAt: "2026-01-01 00:00:00", lastLoginAt: strPtr("2026-02-01 00:00:00")})
	insertLegacyUser(t, db, legacyUser{id: "carol-b", username: "carol", sub: "sub-carol", issuer: dedupOIDCIssuer + "/",
		createdAt: "2026-03-01 00:00:00", lastLoginAt: strPtr("2026-08-01 00:00:00")})
	insertLegacyUser(t, db, legacyUser{id: "carol-c", username: "carol", sub: "sub-carol", issuer: dedupOldIssuer,
		createdAt: "2025-12-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "dave-new", username: "dave", sub: "sub-dave", issuer: dedupOIDCIssuer,
		createdAt: "2026-06-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "dave-old", username: "dave", sub: "sub-dave", issuer: dedupOIDCIssuer + "/",
		createdAt: "2026-02-01 00:00:00"})

	deleted, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, 3, deleted)
	assert.Equal(t, []string{"carol-b"}, liveUserIDs(t, db, "carol"), "latest login beats older rows and never-logged-in rows")
	assert.Equal(t, []string{"dave-new"}, liveUserIDs(t, db, "dave"), "with no logins the newest row survives")

	finishMigrations(t, sqlDB)
}

// With no URL, the sub = "admin" row with the latest login is kept, unmoved.
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

// A lone admin row on an old URL is kept and moved, with its memberships and API keys.
func TestDedupLiveUsernamesMovesLoneStaleAdmin(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "oldadmin", username: "admin", sub: "admin", issuer: dedupOldIssuer,
		createdAt: "2026-01-01 00:00:00", lastLoginAt: strPtr("2026-09-01 00:00:00")})
	insertGroupWithMembers(t, db, "ops", "oldadmin")
	insertLegacyAPIKey(t, db, "k-admin", "admin", "2026-02-01 00:00:00")

	deleted, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
	assert.Equal(t, []string{"oldadmin"}, liveUserIDs(t, db, "admin"))
	assert.Equal(t, []string{"oldadmin"}, groupMemberIDs(t, db, "ops"))

	finishMigrations(t, sqlDB)
	assert.Equal(t, "oldadmin", readColumnByID(t, db, "api_keys", "created_by")["k-admin"])
	setExternalWebURL(t, dedupLocalIssuer)
	require.NoError(t, BootstrapAdminAndBackfillOwners(db))
	admin, err := BuiltinAdminUser(db)
	require.NoError(t, err)
	require.NotNil(t, admin)
	assert.Equal(t, "oldadmin", admin.ID)
}

// Without a row on the current URL, one sub = "admin" row is kept and moved;
// every other "admin" row is retired.
func TestDedupLiveUsernamesKeepsOneAdminRow(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "url1admin", username: "admin", sub: "admin", issuer: dedupOldIssuer,
		createdAt: "2025-12-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "url2admin", username: "admin", sub: "admin", issuer: dedupOldIssuer + ":8444",
		createdAt: "2026-01-01 00:00:00", lastLoginAt: strPtr("2026-09-01 00:00:00")})
	insertLegacyUser(t, db, legacyUser{id: "squatter", username: "admin", sub: "sub-x", issuer: dedupOIDCIssuer,
		createdAt: "2026-02-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "phadmin", username: "admin",
		sub: protectivePlaceholderSubPrefix + "admin__e6227487", issuer: dedupOIDCIssuer + "/",
		createdAt: "2026-04-23 17:40:27"})

	deleted, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, 3, deleted)
	assert.Equal(t, []string{"url2admin"}, liveUserIDs(t, db, "admin"))

	finishMigrations(t, sqlDB)
	setExternalWebURL(t, dedupLocalIssuer)
	admin, err := BuiltinAdminUser(db)
	require.NoError(t, err)
	require.NotNil(t, admin)
	assert.Equal(t, "url2admin", admin.ID)
}

// With no sub = "admin" row left, one is created on the current URL.
func TestDedupLiveUsernamesInsertsAdminWhenNoneRemains(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "phadmin", username: "admin",
		sub: protectivePlaceholderSubPrefix + "admin__e6227487", issuer: dedupOIDCIssuer,
		createdAt: "2026-04-23 17:40:27"})
	insertLegacyAPIKey(t, db, "k-admin", "admin", "2026-05-01 00:00:00")

	deleted, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)
	live := liveUserIDs(t, db, "admin")
	require.Len(t, live, 1)
	assert.NotEqual(t, "phadmin", live[0])
	assert.Equal(t, "", readColumnByID(t, db, "api_keys", "created_by")["k-admin"])

	finishMigrations(t, sqlDB)
	setExternalWebURL(t, dedupLocalIssuer)
	admin, err := BuiltinAdminUser(db)
	require.NoError(t, err)
	require.NotNil(t, admin)
	assert.Equal(t, live[0], admin.ID)
}

// A losing row's group memberships go with it; nothing is moved.
func TestDedupLiveUsernamesRemovesLoserMemberships(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "s", username: "alice", sub: "sub-s", issuer: dedupOIDCIssuer,
		createdAt: "2026-03-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "l", username: "alice", sub: "sub-l", issuer: dedupOIDCIssuer + "/",
		createdAt: "2026-01-01 00:00:00"})
	insertGroupWithMembers(t, db, "shared", "s", "l")
	insertGroupWithMembers(t, db, "losers-only", "l")

	_, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, []string{"s"}, liveUserIDs(t, db, "alice"))
	assert.Equal(t, []string{"s"}, groupMemberIDs(t, db, "shared"))
	assert.Empty(t, groupMemberIDs(t, db, "losers-only"))

	finishMigrations(t, sqlDB)
}

// A key is bound only if kept.created_at <= key < earliest retired, compared as times.
func TestDedupLiveUsernamesBindsOnlyAttributableAPIKeys(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "s", username: "alice", sub: "sub-s", issuer: dedupLocalIssuer,
		createdAt: "2026-01-01 00:00:00"})
	// 10:00 UTC.
	insertLegacyUser(t, db, legacyUser{id: "l", username: "alice", sub: "sub-l", issuer: dedupOIDCIssuer,
		createdAt: "2026-03-01 12:00:00+02:00"})
	insertLegacyAPIKey(t, db, "k-earlier-holder", "alice", "2025-12-01 00:00:00")
	insertLegacyAPIKey(t, db, "k-kept-only", "alice", "2026-02-15 00:00:00")
	// 30 minutes before the retired row in UTC, though later as text.
	insertLegacyAPIKey(t, db, "k-before-retired", "alice", "2026-03-01 09:30:00+00:00")
	// 30 minutes after the retired row in UTC, though earlier as text.
	insertLegacyAPIKey(t, db, "k-after-retired", "alice", "2026-03-01 10:30:00+00:00")
	insertLegacyAPIKey(t, db, "k-later", "alice", "2026-05-01 00:00:00")
	insertLegacyAPIKey(t, db, "k-other-user", "bob", "2026-05-01 00:00:00")

	_, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, []string{"s"}, liveUserIDs(t, db, "alice"))
	assert.Equal(t, map[string]string{
		"k-earlier-holder": "",
		"k-kept-only":      "s",
		"k-before-retired": "s",
		"k-after-retired":  "",
		"k-later":          "",
		"k-other-user":     "bob",
	}, readColumnByID(t, db, "api_keys", "created_by"))

	finishMigrations(t, sqlDB)
	assert.Equal(t, "", readColumnByID(t, db, "api_keys", "created_by")["k-later"],
		"20260917110000 must not re-attribute a cleared key")
}

// Placeholders count toward the cutoff: their sub can be forged.
func TestDedupLiveUsernamesCountsPlaceholdersTowardAPIKeyCutoff(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "s", username: "alice", sub: "sub-s", issuer: dedupOIDCIssuer + "/",
		createdAt: "2026-01-01 00:00:00"})
	insertLegacyUser(t, db, legacyUser{id: "p", username: "alice",
		sub: protectivePlaceholderSubPrefix + "alice__e6227487", issuer: dedupOIDCIssuer,
		createdAt: "2026-04-23 17:40:27"})
	insertLegacyAPIKey(t, db, "k-earlier-holder", "alice", "2025-12-01 00:00:00")
	insertLegacyAPIKey(t, db, "k-before-placeholder", "alice", "2026-02-01 00:00:00")
	insertLegacyAPIKey(t, db, "k-after-placeholder", "alice", "2026-06-01 00:00:00")

	_, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, []string{"s"}, liveUserIDs(t, db, "alice"))
	assert.Equal(t, map[string]string{
		"k-earlier-holder":     "",
		"k-before-placeholder": "s",
		"k-after-placeholder":  "",
	}, readColumnByID(t, db, "api_keys", "created_by"))

	finishMigrations(t, sqlDB)
}

// "admin" keys follow the same rule, with the local admin as the kept row.
func TestDedupLiveUsernamesSettlesAdminAPIKeys(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionBeforeGlobalUniqueUsername(t))
	insertLegacyUser(t, db, legacyUser{id: "3facd6da", username: "admin", sub: "admin", issuer: dedupLocalIssuer,
		createdAt: "2026-01-28 18:56:07"})
	insertLegacyUser(t, db, legacyUser{id: "ce7baf29", username: "admin",
		sub: protectivePlaceholderSubPrefix + "admin__e6227487", issuer: dedupOIDCIssuer,
		createdAt: "2026-04-23 17:40:27"})
	// The same day as the local row, a few hours later.
	insertLegacyAPIKey(t, db, "k-same-day", "admin", "2026-01-28 20:00:00")
	insertLegacyAPIKey(t, db, "k-after-placeholder", "admin", "2026-05-01 00:00:00")

	_, err := dedupLiveUsernames(db, dedupLocalIssuer)
	require.NoError(t, err)
	assert.Equal(t, []string{"3facd6da"}, liveUserIDs(t, db, "admin"))
	assert.Equal(t, map[string]string{
		"k-same-day":          "3facd6da",
		"k-after-placeholder": "",
	}, readColumnByID(t, db, "api_keys", "created_by"))

	finishMigrations(t, sqlDB)
}

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

// A database past the migration but missing its index is left alone.
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

// A collection already on a retired admin row stays there, and with the
// placeholder older than the local admin no "admin" key can be attributed.
func TestPrepareForGlobalUniqueUsernamesLeavesAdminCollectionsInPlace(t *testing.T) {
	db, sqlDB := migrateToVersion(t, versionV726)
	require.NoError(t, db.Exec("INSERT INTO users (id, username, sub, issuer, created_at) VALUES "+
		"('oldadmin', 'admin', 'admin', ?, '2026-03-01 12:00:00+02:00'), "+
		"('newadmin', 'admin', 'admin', ?, '2026-06-01 00:00:00'), "+
		"('phadmin', 'admin', ?, ?, '2025-11-01 00:00:00')",
		dedupOldIssuer, dedupLocalIssuer, protectivePlaceholderSubPrefix+"admin__e6227487", dedupOIDCIssuer).Error)
	require.NoError(t, db.Exec(
		"INSERT INTO collections (id, name, owner, namespace) VALUES ('c1', 'stuff', 'admin', '/ns')").Error)
	insertLegacyAPIKey(t, db, "k-before", "admin", "2025-12-01 00:00:00")
	insertLegacyAPIKey(t, db, "k-between", "admin", "2026-03-01 10:30:00+00:00")
	insertLegacyAPIKey(t, db, "k-after", "admin", "2026-07-01 00:00:00")

	setExternalWebURL(t, dedupLocalIssuer)
	require.NoError(t, prepareForGlobalUniqueUsernames(sqlDB, db))
	assert.Equal(t, []string{"newadmin"}, liveUserIDs(t, db, "admin"))
	assert.Equal(t, map[string]string{"k-before": "", "k-between": "", "k-after": ""},
		readColumnByID(t, db, "api_keys", "created_by"))
	finishMigrations(t, sqlDB)

	assert.Equal(t, map[string]string{"c1": "phadmin"}, readColumnByID(t, db, "collections", "owner_id"))
	assert.Equal(t, map[string]string{"k-after": "", "k-before": "", "k-between": ""},
		readColumnByID(t, db, "api_keys", "created_by"))
}

// A collection whose name the survivor already owns is not moved.
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

// End to end from the base users table, with a negative control that
// reproduces the reported crash.
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
