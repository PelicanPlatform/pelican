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
	"github.com/pelicanplatform/pelican/token_scopes"
)

// TestConfiguredAdminGroupNameCannotBeShadowed sees if we can shadow
// an admin group as a user.
//
// Group creation is open to every authenticated user and clamps
// auth_template_eligible off for a non-admin creator.
// FilterAuthTemplateEligibleGroups matches on the NAME and is global:
// one ineligible row named "ops" removes "ops" from *every* caller's
// group list. Absent a reservation, then, any user can create a group
// named after a Server.AdminGroups entry and thereby revoke server.admin
// from every administrator who holds it through the issuer's assertion.
func TestConfiguredAdminGroupNameCannotBeShadowed(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)

	// The operator's config: Server.AdminGroups: [ops]
	require.NoError(t, EnsureConfiguredAuthorityGroups(db, []string{"ops"}))

	// Mallory, an ordinary authenticated user, goes after the name.
	mkUser(t, db, "u-mallory", "mallory")
	_, err := CreateGroup(db, "ops", "", "", Creator{UserID: "u-mallory"}, "", false)
	assert.ErrorIs(t, err, ErrGroupNameConflict,
		"a name that confers server.admin must already be held by the server")

	// The refusal must be the explicit conflict, not an incidental
	// unique-index violation: CreateGroup only explains itself for an
	// ASSERTED source, which is why the reservation is stamped unknown
	// rather than with the configured source. Under
	// Issuer.GroupSource: internal that would map to GroupSourcePelican,
	// which is not asserted — the name would still be taken, but
	// MirrorAssertedGroupMemberships would then refuse to mirror the
	// provider's members into the very group that confers admin.
	assert.ErrorContains(t, err, "asserted",
		"the reserved group must read as provider-asserted, not Pelican-owned")

	// An administrator whose token asserts "ops" still matches the
	// config entry.
	assert.Equal(t, []string{"ops"}, FilterAuthTemplateEligibleGroups(db, []string{"ops"}),
		"the configured admin group must survive the eligibility filter")
}

func TestEnsureConfiguredAuthorityGroups(t *testing.T) {
	t.Run("mints an admin-owned, eligible record stamped unknown", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		admin := withExternalWebURL(t, db)

		require.NoError(t, EnsureConfiguredAuthorityGroups(db,
			[]string{"ops", "  ops  ", "storage-admins", ""}))

		var groups []Group
		require.NoError(t, db.Order("name").Find(&groups).Error)
		require.Len(t, groups, 2, "whitespace-only and duplicate entries must collapse")
		for _, g := range groups {
			assert.Equal(t, admin.ID, g.OwnerID, "a reserved name belongs to the built-in admin, not to a user")
			assert.True(t, g.AuthTemplateEligible,
				"the record must not make the operator's own config entry stop matching")
			assert.Equal(t, GroupSourceUnknown, g.Source,
				"the name has not been observed from any provider yet, so claiming one would invent provenance")
			assert.True(t, g.Source.IsAsserted(),
				"it must still count as asserted, or CreateGroup would not refuse the name")
			assert.Len(t, g.ID, 8)
		}

		// Idempotent across restarts.
		require.NoError(t, EnsureConfiguredAuthorityGroups(db, []string{"ops", "storage-admins"}))
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

		require.NoError(t, EnsureConfiguredAuthorityGroups(db, []string{"ops"}))

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

		require.NoError(t, EnsureConfiguredAuthorityGroups(db, []string{"ops"}))

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

	t.Run("the reservation is completed by the first real assertion", func(t *testing.T) {
		// The reservation is a placeholder: it holds the name until a
		// provider actually asserts it, and that assertion stamps the
		// real source. Reserving must not depend on Issuer.GroupSource
		// being set, or even being correct, at startup.
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)

		require.NoError(t, EnsureConfiguredAuthorityGroups(db, []string{"ops"}))
		var g Group
		require.NoError(t, db.First(&g, "name = ?", "ops").Error)
		require.Equal(t, GroupSourceUnknown, g.Source)

		accepted := mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops"})
		assert.Equal(t, []string{"ops"}, accepted,
			"the reservation must not block the provider that later asserts the name")
		require.NoError(t, db.First(&g, "name = ?", "ops").Error)
		assert.Equal(t, GroupSourceOIDC, g.Source)
	})

	t.Run("a reservation stays locally manageable", func(t *testing.T) {
		// `unknown` is an asserted source, but membership is still
		// Pelican's until a provider claims the name: no group-source
		// guard sits on AddGroupMember, so an admin can put people in
		// the reserved group by hand. That matters most under
		// Issuer.GroupSource: internal, where no provider will ever
		// assert it.
		db := setupCollectionTestDB(t)
		admin := withExternalWebURL(t, db)
		require.NoError(t, EnsureConfiguredAuthorityGroups(db, []string{"ops"}))

		var g Group
		require.NoError(t, db.First(&g, "name = ?", "ops").Error)
		require.Equal(t, GroupSourceUnknown, g.Source)

		member := mkUser(t, db, "u-bob", "bob")
		require.NoError(t, AddGroupMember(db, g.ID, member.ID, admin.ID, true))
		assert.NoError(t, RemoveGroupMember(db, g.ID, member.ID, admin.ID, true),
			"a locally-sourced reservation must not be frozen the way a mirrored membership is")
	})

	t.Run("refuses to start on a configured name it cannot reserve", func(t *testing.T) {
		// A silently-skipped entry is not harmless.
		// FilterAuthTemplateEligibleGroups passes through names with no
		// group record, so an assertion carrying "user-alice" would
		// still confer the scope — with nothing holding the name and no
		// eligibility bit to revoke it with. Failing startup is the
		// only outcome that leaves the operator in control.
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)

		err := EnsureConfiguredAuthorityGroups(db, []string{
			"user-alice",      // personal-group prefix
			"@authenticated",  // virtual ACL sentinel
			"/cms/production", // WLCG-style; legitimate
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user-alice")
		assert.Contains(t, err.Error(), "@authenticated",
			"a second bad entry must not be hidden behind the first")

		var count int64
		require.NoError(t, db.Model(&Group{}).Count(&count).Error)
		assert.Zero(t, count,
			"validation happens before any write, so a rejected config leaves no half-applied state")
	})

	t.Run("accepts a name only a provider could assert", func(t *testing.T) {
		// The legitimate entry from the case above, on its own: a
		// WLCG-style name ValidateIdentifier would reject is still a
		// perfectly good thing to put in Server.AdminGroups.
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)

		require.NoError(t, EnsureConfiguredAuthorityGroups(db,
			[]string{"/cms/production", "  ", "/cms/production"}))

		var names []string
		require.NoError(t, db.Model(&Group{}).Pluck("name", &names).Error)
		assert.Equal(t, []string{"/cms/production"}, names,
			"blank and duplicate entries are dropped silently; neither can grant anything")
	})
}

// withConfiguredAdminGroups points Server.AdminGroups at `names` for the
// duration of one test. The delete guard and the reservation both read
// this list, so a test that exercises either has to set it.
func withConfiguredAdminGroups(t *testing.T, names ...string) {
	t.Helper()
	prev := param.Server_AdminGroups.GetStringSlice()
	t.Cleanup(func() { require.NoError(t, param.Server_AdminGroups.Set(prev)) })
	require.NoError(t, param.Server_AdminGroups.Set(names))
}

// A reserved name must not become claimable just because an admin
// deleted the group holding it. Soft delete releases the name, so
// without this the sequence "admin deletes ops" -> "user creates ops"
// -> restart leaves the config entry granting nothing, which is the
// one user-reachable route into that state on a server that was never
// vulnerable to the original bug.
func TestAnAuthorityGroupCannotBeDeletedWhileConfigured(t *testing.T) {
	db := setupCollectionTestDB(t)
	admin := withExternalWebURL(t, db)
	withConfiguredAdminGroups(t, "ops")
	require.NoError(t, EnsureConfiguredAuthorityGroups(db, configuredAuthorityGroupNames()))

	var g Group
	require.NoError(t, db.First(&g, "name = ?", "ops").Error)

	err := DeleteGroup(db, g.ID, admin.ID, true)
	require.ErrorIs(t, err, ErrConfiguredAuthorityGroup, "even a system admin may not release the name")
	assert.Contains(t, err.Error(), "Server.*AdminGroups",
		"the refusal has to say which configuration is holding the name")

	var count int64
	require.NoError(t, db.Model(&Group{}).Where("name = ?", "ops").Count(&count).Error)
	assert.EqualValues(t, 1, count, "the group must survive the refused delete")

	// Dropping the config entry is what makes the group ordinary again.
	withConfiguredAdminGroups(t)
	assert.NoError(t, DeleteGroup(db, g.ID, admin.ID, true))
}

// The refusal an operator actually sees when they try to create their
// own admin group must not blame a provider that was never involved.
func TestReservedNameIsNotReportedAsProviderAsserted(t *testing.T) {
	db := setupCollectionTestDB(t)
	admin := withExternalWebURL(t, db)
	withConfiguredAdminGroups(t, "ops")
	require.NoError(t, EnsureConfiguredAuthorityGroups(db, configuredAuthorityGroupNames()))

	_, err := CreateGroup(db, "ops", "", "", Creator{UserID: admin.ID}, "", true)
	require.ErrorIs(t, err, ErrGroupNameConflict)
	assert.NotContains(t, err.Error(), "unknown group source",
		"nothing asserted this record; it was reserved from the configuration")
	assert.Contains(t, err.Error(), "Server.*AdminGroups",
		"the operator should be told which configuration reserved it")

	// A record the migration backfilled is also unasserted, but has no
	// config entry behind it, so it gets the other phrasing.
	require.NoError(t, db.Create(&Group{
		ID: "g-legacy", Name: "cms-prod", CreatedBy: CreatorUnknown,
		AuthTemplateEligible: true, Source: GroupSourceUnknown,
	}).Error)
	_, err = CreateGroup(db, "cms-prod", "", "", Creator{UserID: admin.ID}, "", true)
	require.ErrorIs(t, err, ErrGroupNameConflict)
	assert.Contains(t, err.Error(), "no provider has claimed it yet")

	// A genuinely asserted group still names its provider.
	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"atlas"})
	_, err = CreateGroup(db, "atlas", "", "", Creator{UserID: admin.ID}, "", true)
	require.ErrorIs(t, err, ErrGroupNameConflict)
	assert.Contains(t, err.Error(), "asserted by the oidc group source")
}

// A GroupSource this build cannot map must not look like "no provider
// configured". "" switches off mirroring, the group-file refresher and
// the guard that stops a user-administrator acting on an unobserved
// account — so a typo, or a provider someone added without extending
// groupSourcesByConfigValue, has to be visible rather than silently
// disabling all three.
func TestConfiguredGroupSourceMapping(t *testing.T) {
	prev := param.Issuer_GroupSource.GetString()
	t.Cleanup(func() { require.NoError(t, param.Issuer_GroupSource.Set(prev)) })

	for _, tc := range []struct {
		configured string
		want       GroupSource
	}{
		{GroupSourceTypeOIDC, GroupSourceOIDC},
		{GroupSourceTypeFile, GroupSourceFile},
		{GroupSourceTypeGitHub, GroupSourceGitHub},
		{GroupSourceTypeInternal, GroupSourcePelican},
		{"OIDC", GroupSourceOIDC}, // case-insensitive
		{"  file  ", GroupSourceFile},
		{"", ""},
		{"none", ""},
		{"nosuchprovider", ""}, // unmapped: warned about, not silently accepted
	} {
		require.NoError(t, param.Issuer_GroupSource.Set(tc.configured))
		assert.Equal(t, tc.want, ConfiguredGroupSource(), "Issuer.GroupSource = %q", tc.configured)
	}

	// Every declared config spelling must be mappable — this is the
	// check that fails when a provider is added without a table entry.
	for _, spelling := range []string{
		GroupSourceTypeOIDC, GroupSourceTypeFile,
		GroupSourceTypeGitHub, GroupSourceTypeInternal,
	} {
		_, ok := groupSourcesByConfigValue[spelling]
		assert.True(t, ok, "config spelling %q has no GroupSource mapping", spelling)
	}
}

// TestAnAssertionResolvesToAPelicanGroup pins behavior that looks
// inconsistent with EnsureAssertedGroups' refusal to mirror into a
// Pelican-created group, and is not.
//
// The refusal covers MEMBERSHIP: the member list is this server's, and
// a provider does not get to edit it. AUTHORIZATION is a different
// question — it asks who the caller is, and the provider is what tells
// us, including the username. A provider that wanted this group's
// access could assert one of its members' identities instead, so
// refusing the name would buy nothing. It is also what makes a useful
// arrangement work: create a group through the groups API, point a
// collection's admin_id at it, and let the provider decide who is in it
// — see TestCollectionsAPI/admin-group-grants-full-management-authority.
func TestAnAssertionResolvesToAPelicanGroup(t *testing.T) {
	db := setupCollectionTestDB(t)
	admin := withExternalWebURL(t, db)
	grp, err := CreateGroup(db, "finance", "", "", Creator{UserID: admin.ID}, "", true)
	require.NoError(t, err)
	require.Equal(t, GroupSourcePelican, grp.Source)
	require.NoError(t, GrantGroupScope(db, grp.ID, token_scopes.Server_CollectionAdmin, CreatorSelf()))

	// Nobody is a local member; the identity provider merely says the name.
	outsider := mkUser(t, db, "u-outsider", "outsider")

	subjects := ResolveCallerACLSubjects(db, outsider.Username, outsider.ID, []string{"finance"})
	assert.Contains(t, subjects.GroupIDs, grp.ID,
		"an asserted name resolves to a Pelican group; this is what makes the admin-group workflow work")

	scopes, err := EffectiveScopes(db, outsider.ID, []string{"finance"})
	require.NoError(t, err)
	assert.Contains(t, scopes, token_scopes.Server_CollectionAdmin,
		"and carries its scopes with it")

	// Membership, by contrast, is genuinely refused: nothing is mirrored
	// in, so the member list stays the administrator's own.
	accepted, err := EnsureAssertedGroups(db, GroupSourceOIDC, []string{"finance"})
	require.NoError(t, err)
	assert.NotContains(t, accepted, "finance",
		"the reconciliation step still declines to adopt a Pelican-held name")
	require.NoError(t, MirrorAssertedGroupMemberships(db, GroupSourceOIDC, outsider.ID, accepted))
	var members int64
	require.NoError(t, db.Model(&GroupMember{}).Where("group_id = ?", grp.ID).Count(&members).Error)
	assert.Zero(t, members, "no membership row is written for an asserted Pelican-held name")
}

// A PATCH that echoes an asserted group's current name is not a rename,
// and must not take the rest of the update down with it — UIs routinely
// send the whole object back.
func TestEchoingAnAssertedGroupsNameIsNotARename(t *testing.T) {
	db := setupCollectionTestDB(t)
	admin := withExternalWebURL(t, db)
	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"ops"})
	var ops Group
	require.NoError(t, db.First(&ops, "name = ?", "ops").Error)

	sameName, desc := "ops", "CMS operations"
	require.NoError(t, UpdateGroup(db, ops.ID, &sameName, nil, &desc, nil, admin.ID, true, true),
		"echoing the current name must not be refused as a rename")

	var after Group
	require.NoError(t, db.First(&after, "id = ?", ops.ID).Error)
	assert.Equal(t, "ops", after.Name)
	assert.Equal(t, desc, after.Description, "the edit alongside it must survive")

	// An actual rename is still refused.
	other := "ops-renamed"
	assert.ErrorIs(t, UpdateGroup(db, ops.ID, &other, nil, nil, nil, admin.ID, true, true),
		ErrGroupNameConflict)
}
