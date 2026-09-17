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
// action, so it must default to "yes" whenever the account's
// group-derived privileges have not been established. That default is
// the fix — the predicate it replaced answered "not an admin" whenever
// it could not tell, and so opened on exactly the accounts it existed
// to protect.
func TestMustTreatAsSystemAdmin(t *testing.T) {
	db := setupAssertedGroupTest(t, "")
	require.NoError(t, param.Server_AdminGroups.Set([]string{"ops"}))
	require.NoError(t, param.Issuer_GroupSource.Set(GroupSourceTypeOIDC))

	admin := seedTestUser(t, db, "u-admin-via-group", "grace")
	ordinary := seedTestUser(t, db, "u-ordinary", "mallory")

	t.Run("an unobserved account is refused, not waved through", func(t *testing.T) {
		// Nothing is known about either account yet. Before the latch,
		// both read as "not an admin" and a user-administrator could act
		// on both — including the one that is.
		for _, u := range []*database.User{admin, ordinary} {
			mustRefuse, why := MustTreatAsSystemAdmin(db, u.ID)
			assert.True(t, mustRefuse, "account %s", u.Username)
			assert.Contains(t, why, "have not been observed")
		}
	})

	t.Run("observing an ordinary account rules it out", func(t *testing.T) {
		RecordAssertedGroups(database.GroupSourceOIDC, ordinary.ID, ordinary.Username,
			[]string{"some-team"})
		mustRefuse, _ := MustTreatAsSystemAdmin(db, ordinary.ID)
		assert.False(t, mustRefuse, "a user-administrator may act once the account is ruled out")

		var after database.User
		require.NoError(t, db.First(&after, "id = ?", ordinary.ID).Error)
		assert.Equal(t, database.GroupAdminRuledOut, after.GroupAdminStatus)
		assert.NotNil(t, after.GroupsObservedAt)
	})

	t.Run("observing an admin account latches it", func(t *testing.T) {
		RecordAssertedGroups(database.GroupSourceOIDC, admin.ID, admin.Username, []string{"ops"})
		mustRefuse, why := MustTreatAsSystemAdmin(db, admin.ID)
		assert.True(t, mustRefuse)
		assert.Contains(t, why, "holds administrator privileges")

		var after database.User
		require.NoError(t, db.First(&after, "id = ?", admin.ID).Error)
		assert.Equal(t, database.GroupAdminPossible, after.GroupAdminStatus)
	})

	t.Run("the latch survives the provider retracting the membership", func(t *testing.T) {
		// This is the case the latch exists for: the evidence goes away
		// but the history does not, and an account that could administer
		// this server must not become manageable by a user-administrator
		// because a group assignment changed.
		RecordAssertedGroups(database.GroupSourceOIDC, admin.ID, admin.Username, nil)

		assert.False(t, IsConfirmedSystemAdmin(db, admin.ID),
			"there is no longer any evidence of the privilege")
		mustRefuse, why := MustTreatAsSystemAdmin(db, admin.ID)
		assert.True(t, mustRefuse, "but the latch still refuses")
		assert.Contains(t, why, "previously held administrator privileges")

		var after database.User
		require.NoError(t, db.First(&after, "id = ?", admin.ID).Error)
		assert.Equal(t, database.GroupAdminPossible, after.GroupAdminStatus,
			"nothing downgrades the latch")
	})

	t.Run("a stale mirrored membership still refuses", func(t *testing.T) {
		// Granting paths stop honouring a stale membership. This one
		// must not: it asks whether the account might HOLD the
		// privilege, and an old observation still answers that.
		other := seedTestUser(t, db, "u-other-admin", "heidi")
		RecordAssertedGroups(database.GroupSourceOIDC, other.ID, other.Username, []string{"ops"})
		var ops database.Group
		require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
		require.NoError(t, db.Model(&database.GroupMember{}).
			Where("group_id = ? AND user_id = ?", ops.ID, other.ID).
			Update("asserted_at", time.Now().Add(-365*24*time.Hour)).Error)

		mustRefuse, _ := MustTreatAsSystemAdmin(db, other.ID)
		assert.True(t, mustRefuse)
	})

	t.Run("no group can confer admin, so nothing needs observing", func(t *testing.T) {
		// The conservative default is scoped: where Server.AdminGroups
		// is unset, a group cannot make anyone an admin, so an
		// unobserved account is ruled out on the evidence alone and
		// ordinary user administration is unaffected.
		require.NoError(t, param.Server_AdminGroups.Set([]string{}))
		fresh := seedTestUser(t, db, "u-fresh", "ivan")
		mustRefuse, _ := MustTreatAsSystemAdmin(db, fresh.ID)
		assert.False(t, mustRefuse)
	})
}

// The granting-direction counterpart takes uncertainty the other way.
// Wiring the wrong one into a call site inverts its failure mode.
func TestIsConfirmedSystemAdminTreatsUncertaintyAsNo(t *testing.T) {
	db := setupAssertedGroupTest(t, "")
	require.NoError(t, param.Server_AdminGroups.Set([]string{"ops"}))
	require.NoError(t, param.Issuer_GroupSource.Set(GroupSourceTypeOIDC))

	unobserved := seedTestUser(t, db, "u-unobserved", "judy")
	assert.False(t, IsConfirmedSystemAdmin(db, unobserved.ID),
		"an account nothing is known about is not demonstrably an admin")
	mustRefuse, _ := MustTreatAsSystemAdmin(db, unobserved.ID)
	assert.True(t, mustRefuse, "...while the restricting guard refuses on the same account")

	RecordAssertedGroups(database.GroupSourceOIDC, unobserved.ID, unobserved.Username, []string{"ops"})
	assert.True(t, IsConfirmedSystemAdmin(db, unobserved.ID))
}
