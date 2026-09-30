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

// Groups are soft-deleted, so a tombstoned row is still physically in
// the table. GORM hides it automatically from model-based queries, but
// NOT from the raw db.Table(...) queries several authorization paths
// use. These tests pin that a tombstoned group confers nothing.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestADeletedGroupStopsSuppressingItsName is the reachable one, and it
// is a denial that nothing in the UI would explain.
//
// FilterAuthTemplateEligibleGroups matches on the NAME, and a group
// created by a non-admin is ineligible. Because group names are released
// for reuse on delete (the live-rows-only unique index), a user could
// create "ops", delete it, and leave behind a tombstone that goes on
// stripping "ops" from every caller's group list forever — with no group
// left anywhere in the UI to explain why the operator's
// Server.AdminGroups entry had stopped working.
func TestADeletedGroupStopsSuppressingItsName(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	eve := mkUser(t, db, "u-eve", "eve")

	grp, err := CreateGroup(db, "ops", "", "", Creator{UserID: eve.ID}, "", false)
	require.NoError(t, err)
	require.Equal(t, []string{}, FilterAuthTemplateEligibleGroups(db, []string{"ops"}),
		"precondition: while it exists, the ineligible group does suppress the name")

	require.NoError(t, DeleteGroup(db, grp.ID, eve.ID, false))

	assert.Equal(t, []string{"ops"}, FilterAuthTemplateEligibleGroups(db, []string{"ops"}),
		"a tombstoned group must not go on suppressing the name it released")
}

// TestATombstonedGroupConfersNoAuthority is defense in depth. DeleteGroup
// removes the memberships, ACLs and scopes itself, so these rows should
// not exist — the point is that the authorization paths do not depend on
// that cleanup having been complete.
func TestATombstonedGroupConfersNoAuthority(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	owner := mkUser(t, db, "u-owner", "owner")
	member := mkUser(t, db, "u-member", "member")

	grp, err := CreateGroup(db, "ops", "", "", Creator{UserID: owner.ID}, "", false)
	require.NoError(t, err)
	require.NoError(t, AddGroupMember(db, grp.ID, member.ID, owner.ID, true))
	require.NoError(t, DeleteGroup(db, grp.ID, owner.ID, true))

	// Put a membership back, standing in for any row that outlived the
	// group: a cascade that did not fire, a half-applied migration, a
	// writer racing the delete.
	now := time.Now()
	require.NoError(t, db.Create(&GroupMember{
		GroupID: grp.ID, UserID: member.ID, AddedBy: owner.ID,
		AddedAt: now, Source: GroupSourcePelican,
	}).Error)

	subjects := ResolveCallerACLSubjects(db, member.Username, member.ID, []string{"ops"})
	assert.NotContains(t, subjects.GroupIDs, grp.ID,
		"a tombstoned group must not become an ACL subject, by ID or by the name it released")

	granting, err := grantingMembershipsFor(db, member.ID)
	require.NoError(t, err)
	assert.NotContains(t, granting, grp.ID,
		"a membership in a tombstoned group must not grant")

	stale := ResolveCallerACLSubjectsToleratingStale(db, member.Username, member.ID)
	assert.NotContains(t, stale.GroupIDs, grp.ID,
		"tolerating a stale assertion must not extend to tolerating a deleted group")
}
