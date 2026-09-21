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

// A mirrored membership is a CACHED authorization fact (typically from a
// authorization method that we can't periodically query).  The rule for
// caching is:
//
//	freshness gates GRANTING, not existence.
//
// A stale authorization must not grant access, but must still be visible
// to a check that asks whether an account might HOLD a privilege.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// ageMembership backdates a mirrored membership's asserted_at, standing
// in for "the provider last said this a long time ago".
func ageMembership(t *testing.T, db *gorm.DB, groupID, userID string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	res := db.Model(&GroupMember{}).
		Where("group_id = ? AND user_id = ?", groupID, userID).
		Update("asserted_at", when)
	require.NoError(t, res.Error)
	require.EqualValues(t, 1, res.RowsAffected)
}

func withMembershipTTL(t *testing.T, ttl time.Duration) {
	t.Helper()
	prev := param.Issuer_AssertedGroupMembershipTTL.GetDuration()
	t.Cleanup(func() { require.NoError(t, param.Issuer_AssertedGroupMembershipTTL.Set(prev)) })
	require.NoError(t, param.Issuer_AssertedGroupMembershipTTL.Set(ttl))
}

func TestMirroredMembershipFreshnessGatesGranting(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	withMembershipTTL(t, time.Hour)

	alice := mkUser(t, db, "u-alice", "alice")
	owner := mkUser(t, db, "u-owner", "owner")
	coll := mkCollection(t, db, "c1", "data", owner.ID)

	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops"})
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
	require.NoError(t, GrantCollectionAcl(db, coll.ID, owner.Username, owner.ID, nil,
		ACLSubjectRef("ops"), AclRoleRead, nil, false))
	require.NoError(t, GrantGroupScope(db, ops.ID, token_scopes.Server_CollectionAdmin, CreatorSelf()))

	t.Run("a fresh copy grants", func(t *testing.T) {
		// No asserted group names passed: this is the offline case —
		// deciding about a user who is not the one making the request.
		assert.NoError(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID, nil,
			token_scopes.Collection_Read))
		scopes, err := EffectiveScopes(db, alice.ID, nil)
		require.NoError(t, err)
		assert.Contains(t, scopes, token_scopes.Server_CollectionAdmin)
	})

	t.Run("a stale copy does not", func(t *testing.T) {
		ageMembership(t, db, ops.ID, alice.ID, 2*time.Hour)

		assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID, nil,
			token_scopes.Collection_Read), ErrForbidden,
			"a membership the provider has not confirmed inside the TTL must not hand out access")
		scopes, err := EffectiveScopes(db, alice.ID, nil)
		require.NoError(t, err)
		assert.NotContains(t, scopes, token_scopes.Server_CollectionAdmin)
	})

	t.Run("the caller's own live assertion is never gated by the TTL", func(t *testing.T) {
		// The copy is stale, but alice is here and her token says "ops".
		// The TTL bounds a cache, not the provider speaking directly.
		assert.NoError(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID,
			[]string{"ops"}, token_scopes.Collection_Read))
	})

	t.Run("a stale copy is kept, not deleted", func(t *testing.T) {
		names, err := GroupNamesForRestrictionCheck(db, alice.ID)
		require.NoError(t, err)
		assert.Contains(t, names, "ops",
			"a restricting check must still see it; expiry governs granting, not retention")
	})

	t.Run("re-asserting revives it", func(t *testing.T) {
		require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
		assert.NoError(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID, nil,
			token_scopes.Collection_Read))
	})

	t.Run("a TTL of zero disables mirrored memberships as an authz input", func(t *testing.T) {
		withMembershipTTL(t, 0)
		assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), alice.Username, alice.ID, nil,
			token_scopes.Collection_Read), ErrForbidden)
		// ...while an administrator's own membership is unaffected: it
		// is not a cached fact and does not expire.
		require.NoError(t, AddGroupMember(db, ops.ID, owner.ID, owner.ID, true))
		assert.NoError(t, validateACL(db, reload(t, db, coll.ID), owner.Username, owner.ID, nil,
			token_scopes.Collection_Read))
	})
}

// The motivating offline case: a share's data-plane scopes are clamped
// by what the SHARE OWNER can currently do on the parent collection,
// computed at token-mint time with no session for that owner. Before
// memberships were mirrored, an owner whose access came from an asserted
// group was invisible there and the share silently stopped working.
func TestMirroredMembershipRestoresTheShareOwnerClamp(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	withMembershipTTL(t, time.Hour)

	alice := mkUser(t, db, "u-alice", "alice")
	parentOwner := mkUser(t, db, "u-owner", "owner")
	parent := mkCollection(t, db, "c-parent", "parent", parentOwner.ID)

	// Alice's access to the parent is via an asserted group, and she is
	// not the one asking — the mint path passes no group names.
	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops"})
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
	require.NoError(t, GrantCollectionAcl(db, parent.ID, parentOwner.Username, parentOwner.ID, nil,
		ACLSubjectRef("ops"), AclRoleWrite, nil, false))

	assert.Equal(t, AclRole(""), EffectiveCollectionRole(db, reload(t, db, parent.ID), alice.ID, ""),
		"with nothing mirrored there is no record of alice's access, so the clamp kills the share")

	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
	assert.Equal(t, AclRoleWrite, EffectiveCollectionRole(db, reload(t, db, parent.ID), alice.ID, ""),
		"a mirrored membership is what lets the clamp see asserted access")

	// And it keeps counting once stale. This is the one granting path
	// that tolerates staleness, deliberately: gating it produces a FALSE
	// denial — an owner who has not signed in for a week silently has
	// every share they created mint tokens with no storage scopes, with
	// nothing logged, while the provider still lists them as a member.
	ageMembership(t, db, ops.ID, alice.ID, 30*24*time.Hour)
	assert.Equal(t, AclRoleWrite, EffectiveCollectionRole(db, reload(t, db, parent.ID), alice.ID, ""),
		"the clamp must not silently strip a share owner's access because they have not logged in lately")

	// The ordinary granting paths are unaffected and still refuse it.
	assert.ErrorIs(t, validateACL(db, reload(t, db, parent.ID), alice.Username, alice.ID, nil,
		token_scopes.Collection_Read), ErrForbidden,
		"tolerating staleness in the clamp must not leak into the normal ACL check")
}

func TestMirroredMembershipCannotBeRemovedLocally(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	fx := seedGroupAuthzFixtures(t, db)

	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"asserted-team"})
	var team Group
	require.NoError(t, db.First(&team, "name = ?", "asserted-team").Error)
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, fx.memberID, []string{"asserted-team"}))

	// Neither the member nor an administrator can remove it: the
	// provider still asserts it, so the row would simply come back.
	assert.ErrorIs(t, LeaveGroup(db, team.ID, fx.memberID), ErrMembershipNotLocal)
	assert.ErrorIs(t, RemoveGroupMember(db, team.ID, fx.memberID, fx.ownerID, true), ErrMembershipNotLocal)

	var n int64
	require.NoError(t, db.Model(&GroupMember{}).
		Where("group_id = ? AND user_id = ?", team.ID, fx.memberID).Count(&n).Error)
	assert.EqualValues(t, 1, n)

	// A Pelican membership in the same group is removable as always.
	require.NoError(t, AddGroupMember(db, team.ID, fx.strangerID, fx.ownerID, true))
	assert.NoError(t, RemoveGroupMember(db, team.ID, fx.strangerID, fx.ownerID, true))
}

// Mirrored memberships are rows in group_members, not an in-process
// cache, so they survive a restart — including their asserted_at, which
// is what decides whether they still grant. A server that is down for
// longer than the TTL therefore comes back up with every mirrored
// membership stale, and nothing an oidc or github user can do about it
// until they log in again.
func TestMirroredMembershipsSurviveRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "restart.sqlite")

	open := func() (*gorm.DB, func()) {
		t.Helper()
		db, err := utils.InitSQLiteDB(dbPath)
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		return db, func() { _ = sqlDB.Close() }
	}

	// --- First boot: migrate, mirror a membership, shut down.
	db, closeDB := open()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	goose.SetBaseFS(EmbedUniversalMigrations)
	require.NoError(t, goose.SetDialect("sqlite3"))
	goose.SetTableName("goose_db_version")
	require.NoError(t, goose.Up(sqlDB, "universal_migrations"))

	withExternalWebURL(t, db)
	withMembershipTTL(t, time.Hour)
	alice := mkUser(t, db, "u-alice", "alice")
	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops"})
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
	closeDB()

	// --- Second boot: the same file, a fresh handle.
	db, closeDB = open()
	defer closeDB()

	var member GroupMember
	require.NoError(t, db.Where("user_id = ?", alice.ID).First(&member).Error)
	assert.Equal(t, ops.ID, member.GroupID)
	assert.Equal(t, GroupSourceOIDC, member.Source)
	require.NotNil(t, member.AssertedAt, "asserted_at must survive the restart, not just the row")

	granting, err := grantingMembershipsFor(db, alice.ID)
	require.NoError(t, err)
	assert.Contains(t, granting, ops.ID, "a membership asserted just before shutdown still grants after it")

	// A restart does not reset the clock: an outage longer than the TTL
	// leaves every mirrored membership stale, exactly as if the server
	// had been up and nobody had logged in.
	ageMembership(t, db, ops.ID, alice.ID, 2*time.Hour)
	granting, err = grantingMembershipsFor(db, alice.ID)
	require.NoError(t, err)
	assert.NotContains(t, granting, ops.ID)

	// The row is still there for a restricting check, and re-asserting
	// (i.e. the user logging in again) revives it.
	names, err := GroupNamesForRestrictionCheck(db, alice.ID)
	require.NoError(t, err)
	assert.Contains(t, names, "ops")
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
	granting, err = grantingMembershipsFor(db, alice.ID)
	require.NoError(t, err)
	assert.Contains(t, granting, ops.ID)
}

// Nothing ages a mirrored membership out of existence. Only a provider
// declining to assert it removes one, which is what lets a restricting
// check keep seeing a stale copy.
func TestStaleMirroredMembershipsAreNeverPruned(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	withMembershipTTL(t, time.Hour)

	alice := mkUser(t, db, "u-alice", "alice")
	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops"})
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, []string{"ops"}))
	ageMembership(t, db, ops.ID, alice.ID, 10*365*24*time.Hour)

	// Ten years stale, and every path that merely reads still finds it.
	var n int64
	require.NoError(t, db.Model(&GroupMember{}).Where("user_id = ?", alice.ID).Count(&n).Error)
	assert.EqualValues(t, 1, n)

	// The provider declining to assert it is what removes it.
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, nil))
	require.NoError(t, db.Model(&GroupMember{}).Where("user_id = ?", alice.ID).Count(&n).Error)
	assert.Zero(t, n)
}

// Issuer.GroupSource is single-valued: exactly one provider decides
// membership at a time. A row left behind by a previous source is considered
// stale so the current provider retracts it. Otherwise switching
// sources would leave the old provider's memberships granting until
// their TTL expired, with nothing left that could ever retract them.
//
// The group records keep the original source from creation.
func TestChangingTheGroupSourceRetractsThePreviousProvidersMemberships(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	withMembershipTTL(t, time.Hour)
	alice := mkUser(t, db, "u-alice", "alice")

	// Yesterday's configuration: oidc asserts two groups.
	oidcAccepted := mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops", "research"})
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, alice.ID, oidcAccepted))
	require.Len(t, memberGroupNames(t, db, alice.ID), 2)

	// The operator switches to the group file, which lists only "ops".
	fileAccepted := mustEnsureAssertedGroups(t, db, GroupSourceFile, []string{"ops"})
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceFile, alice.ID, fileAccepted))

	assert.ElementsMatch(t, []string{"ops"}, memberGroupNames(t, db, alice.ID),
		"the previous provider's memberships must not outlive the switch")

	var member GroupMember
	require.NoError(t, db.Where("user_id = ?", alice.ID).First(&member).Error)
	assert.Equal(t, GroupSourceFile, member.Source, "the surviving row is now the file's")

	// The group records keep the source they were bootstrapped with.
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
	assert.Equal(t, GroupSourceOIDC, ops.Source,
		"a group's source records where it came from and is not re-stamped")
}

// memberGroupNames returns the names of the groups a user belongs to.
func memberGroupNames(t *testing.T, db *gorm.DB, userID string) []string {
	t.Helper()
	var rows []struct{ Name string }
	require.NoError(t, db.Table("group_members").
		Joins("JOIN groups ON groups.id = group_members.group_id").
		Select("groups.name").Where("group_members.user_id = ?", userID).
		Scan(&rows).Error)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
}

// The latch that decides whether a user-administrator may act on an
// account. Its one asymmetry: `possible` is never left.
func TestGroupAdminObservationLatch(t *testing.T) {
	db := setupCollectionTestDB(t)
	alice := mkUser(t, db, "u-alice", "alice")

	status := func() GroupAdminStatus {
		t.Helper()
		var u User
		require.NoError(t, db.First(&u, "id = ?", alice.ID).Error)
		return u.GroupAdminStatus
	}

	assert.Equal(t, GroupAdminUnknown, status(), "an account starts out unestablished")
	assert.True(t, GroupAdminUnknown.MayBeAdmin(), "and 'we have not looked' must read as 'might be'")

	t.Run("an observation with no admin group rules the account out", func(t *testing.T) {
		require.NoError(t, RecordGroupAdminObservation(db, alice.ID, false))
		assert.Equal(t, GroupAdminRuledOut, status())
		assert.False(t, GroupAdminRuledOut.MayBeAdmin())

		var u User
		require.NoError(t, db.First(&u, "id = ?", alice.ID).Error)
		require.NotNil(t, u.GroupsObservedAt, "and records that we looked")
	})

	t.Run("an observation with an admin group latches it", func(t *testing.T) {
		require.NoError(t, RecordGroupAdminObservation(db, alice.ID, true))
		assert.Equal(t, GroupAdminPossible, status())
		assert.True(t, GroupAdminPossible.MayBeAdmin())
	})

	t.Run("nothing downgrades the latch", func(t *testing.T) {
		// The provider retracting the membership is exactly the case
		// this exists for: the evidence goes away, the history does not.
		for i := 0; i < 3; i++ {
			require.NoError(t, RecordGroupAdminObservation(db, alice.ID, false))
			assert.Equal(t, GroupAdminPossible, status(),
				"an account that could once administer this server stays latched")
		}
	})
}

// TestStaleAdminGroupMembershipCannotManageAGroup covers the other
// granting path that used to read memberships raw: a group whose
// administrator is itself a group. Membership of that admin group is
// mirrored, so it expires like any other assertion — otherwise a user
// the provider removed from the admin group a year ago could still add
// and remove members.
func TestStaleAdminGroupMembershipCannotManageAGroup(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	withMembershipTTL(t, time.Hour)

	owner := mkUser(t, db, "u-gowner", "gowner")
	deputy := mkUser(t, db, "u-deputy", "deputy")

	// "ops" is asserted by the provider and administers "storage".
	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops"})
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, deputy.ID, []string{"ops"}))

	storage, err := CreateGroup(db, "storage", "", "", Creator{UserID: owner.ID}, "", false)
	require.NoError(t, err)
	require.NoError(t, db.Model(&Group{}).Where("id = ?", storage.ID).
		Updates(map[string]any{"admin_id": ops.ID, "admin_type": AdminTypeGroup}).Error)
	require.NoError(t, db.First(storage, "id = ?", storage.ID).Error)

	assert.True(t, CanManageGroup(db, storage, deputy.ID, false),
		"precondition: a freshly asserted membership of the admin group does confer management")

	ageMembership(t, db, ops.ID, deputy.ID, 48*time.Hour)
	require.NoError(t, db.First(storage, "id = ?", storage.ID).Error)

	assert.False(t, CanManageGroup(db, storage, deputy.ID, false),
		"a mirrored membership past the TTL must not still confer authority over the group")
}

// TestRuleOutGroupAdminOnlyResolvesTheAbsenceOfEvidence covers the
// escape hatch for accounts an external provider will never be asked
// about again — and the line it must not cross.
func TestRuleOutGroupAdminOnlyResolvesTheAbsenceOfEvidence(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)

	t.Run("an unobserved account can be ruled out", func(t *testing.T) {
		// Under oidc/github nothing but a login clears `unknown`, so a
		// departed account would otherwise be untouchable forever.
		u := mkUser(t, db, "u-departed", "departed")
		require.NoError(t, db.Model(&User{}).Where("id = ?", u.ID).
			Update("group_admin_status", GroupAdminUnknown).Error)

		require.NoError(t, RuleOutGroupAdmin(db, u.ID))

		var after User
		require.NoError(t, db.First(&after, "id = ?", u.ID).Error)
		assert.Equal(t, GroupAdminRuledOut, after.GroupAdminStatus)
		assert.False(t, after.GroupAdminStatus.MayBeAdmin())
		assert.NotNil(t, after.GroupsObservedAt, "the judgement is an observation and is timestamped")
	})

	t.Run("a latched account cannot be", func(t *testing.T) {
		// The latch means Pelican has SEEN this account hold an
		// administrative group. An API that erased that would be an API
		// to defeat the guard it feeds.
		u := mkUser(t, db, "u-latched", "latched")
		require.NoError(t, RecordGroupAdminObservation(db, u.ID, true))

		err := RuleOutGroupAdmin(db, u.ID)
		require.ErrorIs(t, err, ErrGroupAdminLatched)

		var after User
		require.NoError(t, db.First(&after, "id = ?", u.ID).Error)
		assert.Equal(t, GroupAdminPossible, after.GroupAdminStatus, "the latch is untouched")
	})

	t.Run("a later observation still wins", func(t *testing.T) {
		// Ruling out is a judgement about the evidence available now,
		// not a permanent exemption: if the provider later asserts an
		// admin group, the latch must still fire.
		u := mkUser(t, db, "u-returning", "returning")
		require.NoError(t, RuleOutGroupAdmin(db, u.ID))
		require.NoError(t, RecordGroupAdminObservation(db, u.ID, true))

		var after User
		require.NoError(t, db.First(&after, "id = ?", u.ID).Error)
		assert.Equal(t, GroupAdminPossible, after.GroupAdminStatus)
	})
}

// assertedAtOf returns the mirrored stamp for one (group, user) pair,
// or nil when there is no row.
func assertedAtOf(t *testing.T, db *gorm.DB, groupID, userID string) *time.Time {
	t.Helper()
	var rows []struct{ AssertedAt *time.Time }
	require.NoError(t, db.Table("group_members").Select("asserted_at").
		Where("group_id = ? AND user_id = ?", groupID, userID).Scan(&rows).Error)
	if len(rows) == 0 {
		return nil
	}
	return rows[0].AssertedAt
}

// TestRepeatedObservationsAreDebounced covers the write-amplification
// fix and, more importantly, the line it must not cross. The group-file
// refresher reconciles every known account every
// Issuer.GroupFileRefreshInterval while rows stay valid for
// Issuer.AssertedGroupMembershipTTL, so re-stamping on every pass is
// hundreds of times more writing than expiry requires — but a change in
// what the provider asserts must still take effect on the very next
// pass.
func TestRepeatedObservationsAreDebounced(t *testing.T) {
	// debounce = TTL/8 = 3h.
	withMembershipTTL(t, 24*time.Hour)

	newFixture := func(t *testing.T) (*gorm.DB, *User, Group) {
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		u := mkUser(t, db, "u-obs", "obs")
		mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops", "atlas"})
		var ops Group
		require.NoError(t, db.First(&ops, "name = ?", "ops").Error)
		require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, u.ID, []string{"ops"}))
		return db, u, ops
	}

	t.Run("an unchanged assertion does not rewrite the stamp", func(t *testing.T) {
		db, u, ops := newFixture(t)
		before := assertedAtOf(t, db, ops.ID, u.ID)
		require.NotNil(t, before)

		require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, u.ID, []string{"ops"}))

		assert.Equal(t, before, assertedAtOf(t, db, ops.ID, u.ID),
			"nothing changed, so the pass must not have opened a write transaction")
	})

	t.Run("a retraction is never debounced", func(t *testing.T) {
		// The property that makes the fast path safe: revocation cannot
		// wait for the window.
		db, u, ops := newFixture(t)
		require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, u.ID, nil))
		assert.Nil(t, assertedAtOf(t, db, ops.ID, u.ID),
			"a membership the provider stopped asserting must go on the very next pass")
	})

	t.Run("a new membership is never debounced", func(t *testing.T) {
		db, u, _ := newFixture(t)
		require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, u.ID, []string{"ops", "atlas"}))
		assert.ElementsMatch(t, []string{"ops", "atlas"}, memberGroupNames(t, db, u.ID))
	})

	t.Run("a change of provider is never debounced", func(t *testing.T) {
		db, u, ops := newFixture(t)
		require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceGitHub, u.ID, []string{"ops"}))
		var src GroupSource
		require.NoError(t, db.Table("group_members").Select("source").
			Where("group_id = ? AND user_id = ?", ops.ID, u.ID).Scan(&src).Error)
		assert.Equal(t, GroupSourceGitHub, src, "a reconfigured source must re-stamp immediately")
	})

	t.Run("the stamp is refreshed once the window has passed", func(t *testing.T) {
		db, u, ops := newFixture(t)
		ageMembership(t, db, ops.ID, u.ID, 4*time.Hour) // past debounce, inside the TTL
		before := assertedAtOf(t, db, ops.ID, u.ID)

		require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, u.ID, []string{"ops"}))

		after := assertedAtOf(t, db, ops.ID, u.ID)
		require.NotNil(t, after)
		assert.True(t, after.After(*before),
			"a row approaching expiry must still be renewed, or debouncing would cause the expiry it exists to prevent")
	})

	t.Run("the admin-group latch is evaluated on every pass", func(t *testing.T) {
		db, u, _ := newFixture(t)
		require.NoError(t, RecordGroupAdminObservation(db, u.ID, false))
		var before User
		require.NoError(t, db.First(&before, "id = ?", u.ID).Error)
		require.Equal(t, GroupAdminRuledOut, before.GroupAdminStatus)

		// Debounced: same verdict, nothing rewritten.
		require.NoError(t, RecordGroupAdminObservation(db, u.ID, false))
		var same User
		require.NoError(t, db.First(&same, "id = ?", u.ID).Error)
		assert.Equal(t, before.GroupsObservedAt, same.GroupsObservedAt)

		// Not debounced: the verdict changed.
		require.NoError(t, RecordGroupAdminObservation(db, u.ID, true))
		var after User
		require.NoError(t, db.First(&after, "id = ?", u.ID).Error)
		assert.Equal(t, GroupAdminPossible, after.GroupAdminStatus,
			"an account that has just been seen in an admin group must latch immediately")
	})
}
