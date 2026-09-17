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

package web_ui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/glebarez/sqlite"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func setupAssertedGroupTest(t *testing.T, groupFileJSON string) *gorm.DB {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	if groupFileJSON != "" {
		groupFile := filepath.Join(t.TempDir(), "groups.json")
		require.NoError(t, os.WriteFile(groupFile, []byte(groupFileJSON), 0o600))
		require.NoError(t, param.Issuer_GroupFile.Set(groupFile))
	}
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://example.com"))

	prevDB := database.ServerDatabase
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	t.Cleanup(func() { database.ServerDatabase = prevDB })
	migrateTestDB(t)
	require.NoError(t, database.BootstrapAdminAndBackfillOwners(mockDB))
	return mockDB
}

func seedTestUser(t *testing.T, db *gorm.DB, id, username string) *database.User {
	t.Helper()
	u := &database.User{
		ID: id, Username: username, Sub: id + "@idp",
		Issuer: "https://idp.example", Status: database.UserStatusActive,
	}
	require.NoError(t, db.Create(u).Error)
	return u
}

func memberships(t *testing.T, db *gorm.DB, userID string) map[string]database.GroupMember {
	t.Helper()
	var rows []database.GroupMember
	require.NoError(t, db.Where("user_id = ?", userID).Find(&rows).Error)
	out := map[string]database.GroupMember{}
	for _, r := range rows {
		var g database.Group
		require.NoError(t, db.First(&g, "id = ?", r.GroupID).Error)
		out[g.Name] = r
	}
	return out
}

// generateGroupInfo is a pure reader; recording what it found is the
// caller's job, because mirroring a membership needs the user's ID and
// the reader only has a name. Every path that reaches the file provider
// — password login, the init-code admin login, and the OIDC callback
// when Issuer.GroupSource is "file" — must call RecordAssertedGroups.
func TestGroupFileSourceRecordsAssertedGroupsAndMemberships(t *testing.T) {
	db := setupAssertedGroupTest(t, `{"testuser": ["team-readers", "team-writers"]}`)
	user := seedTestUser(t, db, "u-testuser", "testuser")

	groups, err := generateGroupInfo(user.Username)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"team-readers", "team-writers"}, groups)

	var recorded int64
	require.NoError(t, db.Model(&database.Group{}).Count(&recorded).Error)
	assert.Zero(t, recorded, "reading the file must not write anything by itself")

	RecordAssertedGroups(database.GroupSourceFile, user.ID, user.Username, groups)

	var groupRows []database.Group
	require.NoError(t, db.Order("name").Find(&groupRows).Error)
	require.Len(t, groupRows, 2)
	for _, g := range groupRows {
		assert.Equal(t, database.GroupSourceFile, g.Source,
			"the record must name the provider that asserted it")
		assert.NotEmpty(t, g.OwnerID, "asserted groups are owned by the built-in admin")
	}

	mirrored := memberships(t, db, user.ID)
	require.Len(t, mirrored, 2)
	for name, m := range mirrored {
		assert.Equal(t, database.GroupSourceFile, m.Source, "membership in %s", name)
		assert.True(t, m.IsMirrored())
		require.NotNil(t, m.AssertedAt, "a mirrored membership must record when it was asserted")
	}
}

func TestMirroredMembershipsFollowTheProvider(t *testing.T) {
	db := setupAssertedGroupTest(t, "")
	user := seedTestUser(t, db, "u-alice", "alice")

	RecordAssertedGroups(database.GroupSourceOIDC, user.ID, user.Username,
		[]string{"ops", "research"})
	require.Len(t, memberships(t, db, user.ID), 2)

	t.Run("a membership the provider stops asserting is retracted", func(t *testing.T) {
		RecordAssertedGroups(database.GroupSourceOIDC, user.ID, user.Username, []string{"ops"})
		mirrored := memberships(t, db, user.ID)
		require.Len(t, mirrored, 1)
		assert.Contains(t, mirrored, "ops")
	})

	t.Run("asserting nothing retracts everything", func(t *testing.T) {
		RecordAssertedGroups(database.GroupSourceOIDC, user.ID, user.Username, nil)
		assert.Empty(t, memberships(t, db, user.ID),
			"an empty assertion is a statement, not a no-op")
	})

	t.Run("one provider does not retract another's memberships", func(t *testing.T) {
		// A server can genuinely have two asserted sources in play: the
		// password-login path reads the group file whatever
		// Issuer.GroupSource says.
		RecordAssertedGroups(database.GroupSourceOIDC, user.ID, user.Username, []string{"ops"})
		RecordAssertedGroups(database.GroupSourceFile, user.ID, user.Username, []string{"local-team"})
		mirrored := memberships(t, db, user.ID)
		require.Len(t, mirrored, 2)
		assert.Equal(t, database.GroupSourceOIDC, mirrored["ops"].Source)
		assert.Equal(t, database.GroupSourceFile, mirrored["local-team"].Source)

		// The file source retracting its own membership leaves the OIDC
		// one alone.
		RecordAssertedGroups(database.GroupSourceFile, user.ID, user.Username, nil)
		mirrored = memberships(t, db, user.ID)
		require.Len(t, mirrored, 1)
		assert.Contains(t, mirrored, "ops")
	})

	t.Run("an administrator's local membership outranks the assertion", func(t *testing.T) {
		// An admin may add a local member to an asserted group. That
		// membership is Pelican's, so an assertion must neither stamp an
		// expiry on it nor retract it.
		admin, err := database.BuiltinAdminUser(db)
		require.NoError(t, err)
		require.NotNil(t, admin)
		var ops database.Group
		require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
		require.NoError(t, database.AddGroupMember(db, ops.ID, admin.ID, admin.ID, true))

		RecordAssertedGroups(database.GroupSourceOIDC, admin.ID, admin.Username, []string{"ops"})
		adminMemberships := memberships(t, db, admin.ID)
		require.Contains(t, adminMemberships, "ops")
		assert.Equal(t, database.GroupSourcePelican, adminMemberships["ops"].Source)
		assert.Nil(t, adminMemberships["ops"].AssertedAt,
			"a Pelican membership does not expire, so it carries no assertion timestamp")

		RecordAssertedGroups(database.GroupSourceOIDC, admin.ID, admin.Username, nil)
		assert.Contains(t, memberships(t, db, admin.ID), "ops",
			"retracting an assertion must not remove a membership an administrator created")
	})
}

// The admin guard is a RESTRICTING check: a true answer refuses an
// action, so an uncertain one must read as "yes". That is why it looks
// at mirrored memberships without a freshness filter — an admin whose
// authority comes from Server.AdminGroups plus an asserted group has
// nothing else on the server to find them by.
func TestIsSystemAdminUserIDSeesAssertedAdminGroups(t *testing.T) {
	db := setupAssertedGroupTest(t, "")
	require.NoError(t, param.Server_AdminGroups.Set([]string{"ops"}))

	admin := seedTestUser(t, db, "u-admin-via-group", "grace")
	stranger := seedTestUser(t, db, "u-stranger", "mallory")

	assert.False(t, IsSystemAdminUserID(db, admin.ID),
		"before anything is mirrored there is no record to find them by")

	RecordAssertedGroups(database.GroupSourceOIDC, admin.ID, admin.Username, []string{"ops"})

	assert.True(t, IsSystemAdminUserID(db, admin.ID),
		"a mirrored membership in an AdminGroups group must make the guard fire")
	assert.False(t, IsSystemAdminUserID(db, stranger.ID))

	t.Run("a stale copy still fires it", func(t *testing.T) {
		// Granting paths stop honouring this membership once stale.
		// This one must not: "we last saw this account in an admin group
		// a month ago" has to mean refuse, not go ahead.
		var ops database.Group
		require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
		require.NoError(t, db.Model(&database.GroupMember{}).
			Where("group_id = ? AND user_id = ?", ops.ID, admin.ID).
			Update("asserted_at", time.Now().Add(-365*24*time.Hour)).Error)

		assert.True(t, IsSystemAdminUserID(db, admin.ID),
			"expiry governs granting, not retention — a restricting check still sees the copy")
	})

	t.Run("it stops firing once the provider retracts the membership", func(t *testing.T) {
		RecordAssertedGroups(database.GroupSourceOIDC, admin.ID, admin.Username, nil)
		assert.False(t, IsSystemAdminUserID(db, admin.ID),
			"a retraction removes the row outright, unlike expiry")
	})
}

// The file source is the only one that can recover from an outage on
// its own: LaunchPeriodicGroupFileRefresh runs a pass at startup
// precisely so a server that was down across a group-file edit — or
// down for longer than Issuer.AssertedGroupMembershipTTL — does not
// serve stale memberships until each user happens to log in.
func TestGroupFileRefreshReconcilesEveryKnownUser(t *testing.T) {
	db := setupAssertedGroupTest(t, `{"alice": ["ops"], "bob": ["research"]}`)
	alice := seedTestUser(t, db, "u-alice", "alice")
	bob := seedTestUser(t, db, "u-bob", "bob")
	carol := seedTestUser(t, db, "u-carol", "carol")

	refreshGroupFileMemberships()

	assert.Contains(t, memberships(t, db, alice.ID), "ops")
	assert.Contains(t, memberships(t, db, bob.ID), "research")
	assert.Empty(t, memberships(t, db, carol.ID),
		"a user the file says nothing about gets no membership invented for them")

	t.Run("a pass after an outage re-asserts stale memberships", func(t *testing.T) {
		var ops database.Group
		require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
		require.NoError(t, db.Model(&database.GroupMember{}).
			Where("group_id = ? AND user_id = ?", ops.ID, alice.ID).
			Update("asserted_at", time.Now().Add(-30*24*time.Hour)).Error)

		refreshGroupFileMemberships()

		refreshed := memberships(t, db, alice.ID)
		require.Contains(t, refreshed, "ops")
		require.NotNil(t, refreshed["ops"].AssertedAt)
		assert.WithinDuration(t, time.Now(), *refreshed["ops"].AssertedAt, time.Minute,
			"the pass must re-assert, not merely leave the row alone")
	})

	t.Run("a user removed from the file has their membership retracted", func(t *testing.T) {
		// This is why the pass walks USERS rather than the file's keys:
		// an account dropped from the file only gets retracted if we ask
		// about the account.
		require.NoError(t, os.WriteFile(param.Issuer_GroupFile.GetString(),
			[]byte(`{"bob": ["research"]}`), 0o600))

		refreshGroupFileMemberships()

		assert.Empty(t, memberships(t, db, alice.ID),
			"removing someone from the group file takes effect within one interval, not at their next login")
		assert.Contains(t, memberships(t, db, bob.ID), "research")
	})
}
