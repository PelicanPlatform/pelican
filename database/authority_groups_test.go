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

// Coverage for EnsureConfiguredAuthorityGroups — the startup step that
// reserves the group names Server.*AdminGroups confers authority on.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// TestConfiguredAdminGroupNameCannotBeShadowed is the reason this code
// exists, so it is written as the attack rather than as a property.
//
// Group creation is open to every authenticated user and clamps
// auth_template_eligible off for a non-admin creator.
// FilterAuthTemplateEligibleGroups matches on the NAME and is global:
// one ineligible row named "ops" removes "ops" from *every* caller's
// group list. Absent a reservation, then, any user can create a group
// named after a Server.AdminGroups entry and thereby revoke server.admin
// from every administrator who holds it through the issuer's assertion.
//
// Delete the EnsureConfiguredAuthorityGroups call below and this test
// fails on both assertions: the create succeeds and the admin's group is
// filtered away.
func TestConfiguredAdminGroupNameCannotBeShadowed(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)

	// The operator's config: Server.AdminGroups: [ops]
	require.NoError(t, EnsureConfiguredAuthorityGroups(db, GroupSourceOIDC, []string{"ops"}))

	// Mallory, an ordinary authenticated user, goes after the name.
	mkUser(t, db, "u-mallory", "mallory")
	_, err := CreateGroup(db, "ops", "", "", Creator{UserID: "u-mallory"}, "", false)
	assert.ErrorIs(t, err, ErrGroupNameConflict,
		"a name that confers server.admin must already be held by the server")

	// An administrator whose token asserts "ops" still matches the
	// config entry.
	assert.Equal(t, []string{"ops"}, FilterAuthTemplateEligibleGroups(db, []string{"ops"}),
		"the configured admin group must survive the eligibility filter")
}

func TestEnsureConfiguredAuthorityGroups(t *testing.T) {
	t.Run("mints an admin-owned, eligible record under the configured source", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		admin := withExternalWebURL(t, db)

		require.NoError(t, EnsureConfiguredAuthorityGroups(db, GroupSourceOIDC,
			[]string{"ops", "  ops  ", "storage-admins", ""}))

		var groups []Group
		require.NoError(t, db.Order("name").Find(&groups).Error)
		require.Len(t, groups, 2, "whitespace-only and duplicate entries must collapse")
		for _, g := range groups {
			assert.Equal(t, admin.ID, g.OwnerID, "a reserved name belongs to the built-in admin, not to a user")
			assert.True(t, g.AuthTemplateEligible,
				"the record must not make the operator's own config entry stop matching")
			assert.Equal(t, GroupSourceOIDC, g.Source,
				"stamping the configured source is what lets the provider mirror memberships into it")
			assert.Len(t, g.ID, 8)
		}

		// Idempotent across restarts.
		require.NoError(t, EnsureConfiguredAuthorityGroups(db, GroupSourceOIDC, []string{"ops", "storage-admins"}))
		var count int64
		require.NoError(t, db.Model(&Group{}).Count(&count).Error)
		assert.EqualValues(t, 2, count)
	})

	t.Run("reserves names even when group auto-creation is disabled", func(t *testing.T) {
		// Issuer.DisableGroupAutoCreation is about names this server
		// merely observes from a provider. These were typed into the
		// config by the operator — and with auto-creation off, nothing
		// else would ever reserve them, so this is the case that needs
		// the protection most.
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		require.NoError(t, param.Issuer_DisableGroupAutoCreation.Set(true))

		require.NoError(t, EnsureConfiguredAuthorityGroups(db, GroupSourceOIDC, []string{"ops"}))

		var count int64
		require.NoError(t, db.Model(&Group{}).Where("name = ?", "ops").Count(&count).Error)
		assert.EqualValues(t, 1, count)
	})

	t.Run("does not seize or promote a group that already holds the name", func(t *testing.T) {
		// The collision the operator has to resolve by hand. Taking the
		// group over would steal it from its owner; flipping the
		// eligibility bit would hand its members exactly the authority
		// the config entry describes. Neither is ours to do.
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		mkUser(t, db, "u-eve", "eve")
		local, err := CreateGroup(db, "ops", "", "", Creator{UserID: "u-eve"}, "", false)
		require.NoError(t, err)

		require.NoError(t, EnsureConfiguredAuthorityGroups(db, GroupSourceOIDC, []string{"ops"}))

		var after Group
		require.NoError(t, db.First(&after, "id = ?", local.ID).Error)
		assert.Equal(t, "u-eve", after.OwnerID)
		assert.Equal(t, GroupSourcePelican, after.Source)
		assert.False(t, after.AuthTemplateEligible,
			"a user-created group must never be promoted into admin authority by a config entry")
		var count int64
		require.NoError(t, db.Model(&Group{}).Where("name = ?", "ops").Count(&count).Error)
		assert.EqualValues(t, 1, count, "no second record may be minted for a name already held")
	})

	t.Run("an unconfigured source lands as unknown and is completed by the first assertion", func(t *testing.T) {
		// Reserving the name must not depend on Issuer.GroupSource
		// being set yet. Stamping `pelican` would be wrong — a
		// Pelican-created group is one this server owns the membership
		// of, and nothing would mirror into it once a provider is
		// configured.
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)

		require.NoError(t, EnsureConfiguredAuthorityGroups(db, "", []string{"ops"}))
		var g Group
		require.NoError(t, db.First(&g, "name = ?", "ops").Error)
		require.Equal(t, GroupSourceUnknown, g.Source)

		accepted := mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops"})
		assert.Equal(t, []string{"ops"}, accepted,
			"the reservation must not block the provider that later asserts the name")
		require.NoError(t, db.First(&g, "name = ?", "ops").Error)
		assert.Equal(t, GroupSourceOIDC, g.Source)
	})

	t.Run("an internally-sourced reservation stays locally manageable", func(t *testing.T) {
		// With Issuer.GroupSource: internal there is no provider to
		// mirror from, so the reserved group has to behave like any
		// other Pelican group: the admin puts people in it by hand.
		db := setupCollectionTestDB(t)
		admin := withExternalWebURL(t, db)
		require.NoError(t, EnsureConfiguredAuthorityGroups(db, GroupSourcePelican, []string{"ops"}))

		var g Group
		require.NoError(t, db.First(&g, "name = ?", "ops").Error)
		require.Equal(t, GroupSourcePelican, g.Source)

		member := mkUser(t, db, "u-bob", "bob")
		require.NoError(t, AddGroupMember(db, g.ID, member.ID, admin.ID, true))
		assert.NoError(t, RemoveGroupMember(db, g.ID, member.ID, admin.ID, true),
			"a locally-sourced reservation must not be frozen the way a mirrored membership is")
	})

	t.Run("skips names that collide with a reserved ACL-target form", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)

		require.NoError(t, EnsureConfiguredAuthorityGroups(db, GroupSourceOIDC, []string{
			"user-alice",      // personal-group prefix
			"@authenticated",  // virtual ACL sentinel
			"/cms/production", // WLCG-style; legitimate, must be kept
		}))

		var names []string
		require.NoError(t, db.Model(&Group{}).Order("name").Pluck("name", &names).Error)
		assert.Equal(t, []string{"/cms/production"}, names)
	})
}
