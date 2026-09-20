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

// Coverage for EnsureAssertedGroups — the reconciliation step that gives
// a provider's group a Pelican record, and with it a stable ID for ACLs
// to key on and a hold on the name so an unprivileged user can't create
// a group that shadows it.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const testExternalWebURL = "https://origin.example.test"

// withExternalWebURL points Server.ExternalWebUrl at a fixed value and
// bootstraps the built-in admin account, which is who asserted groups
// end up owned by.
func withExternalWebURL(t *testing.T, db *gorm.DB) *User {
	t.Helper()
	prevURL := param.Server_ExternalWebUrl.GetString()
	prevDisable := param.Issuer_DisableGroupAutoCreation.GetBool()
	t.Cleanup(func() {
		require.NoError(t, param.Server_ExternalWebUrl.Set(prevURL))
		require.NoError(t, param.Issuer_DisableGroupAutoCreation.Set(prevDisable))
	})
	require.NoError(t, param.Server_ExternalWebUrl.Set(testExternalWebURL))
	require.NoError(t, param.Issuer_DisableGroupAutoCreation.Set(false))

	require.NoError(t, BootstrapAdminAndBackfillOwners(db))
	admin, err := BuiltinAdminUser(db)
	require.NoError(t, err)
	require.NotNil(t, admin)
	return admin
}

func TestEnsureAssertedGroups(t *testing.T) {
	t.Run("mints an admin-owned, template-eligible record per asserted name", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		admin := withExternalWebURL(t, db)

		mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"cms-production", "atlas", "cms-production"})

		var groups []Group
		require.NoError(t, db.Where("source = ?", GroupSourceOIDC).Order("name").Find(&groups).Error)
		require.Len(t, groups, 2, "duplicate names in one assertion must collapse to one record each")
		for _, g := range groups {
			assert.Equal(t, admin.ID, g.OwnerID, "external groups belong to the built-in admin, not to whoever logged in")
			assert.Equal(t, admin.ID, g.CreatedBy)
			assert.True(t, g.AuthTemplateEligible,
				"a name with no record already matched auth templates; creating the record must not silently revoke that")
			assert.Len(t, g.ID, 8)
		}

		// Membership stays with the identity provider — nothing is
		// written to group_members.
		var members int64
		require.NoError(t, db.Model(&GroupMember{}).Count(&members).Error)
		assert.Zero(t, members)

		// Idempotent: a second login asserting the same names changes
		// nothing.
		mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"cms-production", "atlas"})
		var count int64
		require.NoError(t, db.Model(&Group{}).Count(&count).Error)
		assert.EqualValues(t, 2, count)
	})

	t.Run("reserves the name against local group creation", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"cms-production"})

		_, err := CreateGroup(db, "cms-production", "", "", Creator{UserID: "u-nobody"}, "", false)
		assert.ErrorIs(t, err, ErrGroupNameConflict,
			"an unprivileged user must not be able to stand in for the issuer's group")
	})

	t.Run("refuses a source that does not assert memberships", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		_, err := EnsureAssertedGroups(db, GroupSourcePelican, []string{"cms-production"})
		assert.Error(t, err, "Pelican-created groups come from CreateGroup, not from an assertion")
		var count int64
		require.NoError(t, db.Model(&Group{}).Count(&count).Error)
		assert.Zero(t, count)
	})

	t.Run("stamps the real provider onto a migration-backfilled record", func(t *testing.T) {
		// Migration 20260916120000 mints a record for every ACL target
		// it has no group for, but the old schema did not say which
		// provider asserted the name — so it lands as 'unknown'. The
		// first real assertion resolves that.
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		require.NoError(t, db.Create(&Group{
			ID: "g-legacy", Name: "cms-production", CreatedBy: CreatorUnknown,
			AuthTemplateEligible: true, Source: GroupSourceUnknown,
		}).Error)

		mustEnsureAssertedGroups(t, db, GroupSourceGitHub, []string{"cms-production"})

		var g Group
		require.NoError(t, db.First(&g, "id = ?", "g-legacy").Error)
		assert.Equal(t, GroupSourceGitHub, g.Source)
		assert.True(t, g.Source.IsAsserted())
	})

	t.Run("leaves a pre-existing Pelican-created group alone", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		mkUser(t, db, "u-eve", "eve")
		// Eve created "sysadmins" before the issuer ever asserted it.
		// Non-admin creation clamps auth-template eligibility off.
		local, err := CreateGroup(db, "sysadmins", "", "", Creator{UserID: "u-eve"}, "", false)
		require.NoError(t, err)

		mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"sysadmins"})

		var after Group
		require.NoError(t, db.First(&after, "id = ?", local.ID).Error)
		assert.Equal(t, GroupSourcePelican, after.Source,
			"an assertion must not restamp a Pelican-created group as provider-owned")
		assert.Equal(t, "u-eve", after.OwnerID)
		assert.False(t, after.AuthTemplateEligible,
			"an assertion must never promote a user-created group into auth-template authority")
	})

	t.Run("re-observation does not restore an admin-cleared eligibility bit", func(t *testing.T) {
		// The bit is the operator's only lever over a name they do not
		// control — a GitHub org is registerable by anyone, and an OIDC
		// claim is only as trustworthy as the provider. If every login
		// of every member restored it, clearing it would be useless.
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		mustEnsureAssertedGroups(t, db, GroupSourceGitHub, []string{"atlas"})
		require.NoError(t, db.Model(&Group{}).Where("name = ?", "atlas").
			Update("auth_template_eligible", false).Error)

		mustEnsureAssertedGroups(t, db, GroupSourceGitHub, []string{"atlas"})

		var g Group
		require.NoError(t, db.First(&g, "name = ?", "atlas").Error)
		assert.False(t, g.AuthTemplateEligible,
			"an admin's decision to distrust an asserted name must survive the next login")
	})

	t.Run("records any name a provider asserts but not reserved ACL-target forms", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)

		mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{
			"/cms/production", // WLCG-style; ValidateIdentifier would reject the slash
			"a1b2c3d4",        // ID-shaped; only a naming-hygiene rule, not a control
			"",                // empty
			"user-alice",      // reserved personal-group prefix
			"@authenticated",  // the virtual ACL sentinel
		})

		var names []string
		require.NoError(t, db.Model(&Group{}).Order("name").Pluck("name", &names).Error)
		assert.Equal(t, []string{"/cms/production", "a1b2c3d4"}, names,
			"the identifier rules govern what a USER may name a group, not what a provider may assert; "+
				"an ID-shaped asserted name is harmless because nothing resolves a handle by its shape. "+
				"Only names indistinguishable from this server's own NAME-space ACL-target forms are skipped")
	})

	t.Run("does nothing when auto-creation is disabled", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withExternalWebURL(t, db)
		require.NoError(t, param.Issuer_DisableGroupAutoCreation.Set(true))

		mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"cms-production"})
		var count int64
		require.NoError(t, db.Model(&Group{}).Count(&count).Error)
		assert.Zero(t, count)
	})
}

// The point of recording the group: an asserted group now has an ID, so
// it can be named in a collection ACL and an assertion resolves to it.
func TestAssertedGroupBecomesAnUsableACLTarget(t *testing.T) {
	db := setupCollectionTestDB(t)
	withExternalWebURL(t, db)
	owner := mkUser(t, db, "u-owner2", "owner2")
	coll := mkCollection(t, db, "c-ext", "ext", owner.ID)

	// Before anyone from the group has logged in, there is nothing to
	// grant to.
	err := GrantCollectionAcl(db, coll.ID, owner.Username, owner.ID, nil,
		ACLSubjectRef("cms-production"), AclRoleRead, nil, false)
	assert.ErrorIs(t, err, ErrUnknownACLSubject)

	// A login asserting the group reconciles it...
	mustEnsureAssertedGroups(t, db, GroupSourceOIDC, []string{"cms-production"})
	require.NoError(t, GrantCollectionAcl(db, coll.ID, owner.Username, owner.ID, nil,
		ACLSubjectRef("cms-production"), AclRoleRead, nil, false))

	// ...and a caller asserting that name resolves to the same record.
	member := mkUser(t, db, "u-member2", "member2")
	assert.NoError(t, validateACL(db, reload(t, db, coll.ID), member.Username, member.ID,
		[]string{"cms-production"}, token_scopes.Collection_Read))
	assert.ErrorIs(t, validateACL(db, reload(t, db, coll.ID), member.Username, member.ID,
		[]string{"some-other-group"}, token_scopes.Collection_Read), ErrForbidden)
}

// mustEnsureAssertedGroups records the names and returns the subset that
// got a record, failing the test on error. The accepted list is what
// MirrorAssertedGroupMemberships must be given — see its contract.
func mustEnsureAssertedGroups(t *testing.T, db *gorm.DB, source GroupSource, names []string) []string {
	t.Helper()
	accepted, err := EnsureAssertedGroups(db, source, names)
	require.NoError(t, err)
	return accepted
}
