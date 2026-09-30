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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/server_structs"
)

// registrationInviteTestDB extends the shared collection test DB with the
// registrations table the ownership-transfer helpers operate on.
func registrationInviteTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupCollectionTestDB(t)
	require.NoError(t, db.AutoMigrate(&server_structs.Registration{}))
	return db
}

func registrationInviteTestRegistration(t *testing.T, db *gorm.DB, owner string) int {
	t.Helper()
	reg := server_structs.Registration{
		Prefix: "/origins/example.org",
		Pubkey: "mock-pubkey",
		AdminMetadata: server_structs.AdminMetadata{
			UserID:   owner,
			SiteName: "example-site",
			Status:   server_structs.RegApproved,
		},
	}
	require.NoError(t, db.Create(&reg).Error)
	return reg.ID
}

func TestRegistrationOwnershipInviteLink(t *testing.T) {
	t.Run("mint-and-redeem-transfers-owner", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		regID := registrationInviteTestRegistration(t, db, "u-old-owner")
		redeemer, err := CreateLocalUser(db, "bob", "Bob", "https://local", CreatorSelf())
		require.NoError(t, err)

		link, plaintext, err := CreateRegistrationOwnershipInviteLink(
			db, regID, "u-old-owner", time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)
		assert.Equal(t, InviteKindRegistrationOwnership, link.Kind)
		assert.Equal(t, regID, link.RegistrationID)
		assert.True(t, link.IsSingleUse, "ownership transfer must be single-use")

		gotID, gotPrefix, err := RedeemRegistrationOwnershipInviteLink(db, plaintext, redeemer.ID)
		require.NoError(t, err)
		assert.Equal(t, regID, gotID)
		assert.Equal(t, "/origins/example.org", gotPrefix)

		var reg server_structs.Registration
		require.NoError(t, db.First(&reg, "id = ?", regID).Error)
		assert.Equal(t, redeemer.ID, reg.AdminMetadata.UserID,
			"the redeemer's Pelican user ID must be recorded as the owner")
		// Everything else in the admin metadata survives the transfer
		assert.Equal(t, "example-site", reg.AdminMetadata.SiteName)
		assert.Equal(t, server_structs.RegApproved, reg.AdminMetadata.Status)
	})

	t.Run("second-redemption-fails", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		regID := registrationInviteTestRegistration(t, db, "u-old-owner")
		redeemer1, err := CreateLocalUser(db, "bob", "Bob", "https://local", CreatorSelf())
		require.NoError(t, err)
		redeemer2, err := CreateLocalUser(db, "carol", "Carol", "https://local", CreatorSelf())
		require.NoError(t, err)

		_, plaintext, err := CreateRegistrationOwnershipInviteLink(
			db, regID, "u-old-owner", time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		_, _, err = RedeemRegistrationOwnershipInviteLink(db, plaintext, redeemer1.ID)
		require.NoError(t, err)
		_, _, err = RedeemRegistrationOwnershipInviteLink(db, plaintext, redeemer2.ID)
		assert.Error(t, err, "a single-use link must not transfer ownership twice")

		var reg server_structs.Registration
		require.NoError(t, db.First(&reg, "id = ?", regID).Error)
		assert.Equal(t, redeemer1.ID, reg.AdminMetadata.UserID)
	})

	t.Run("expired-link-fails", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		regID := registrationInviteTestRegistration(t, db, "u-old-owner")
		redeemer, err := CreateLocalUser(db, "bob", "Bob", "https://local", CreatorSelf())
		require.NoError(t, err)

		_, plaintext, err := CreateRegistrationOwnershipInviteLink(
			db, regID, "u-old-owner", time.Now().Add(-time.Minute), "", "")
		require.NoError(t, err)

		_, _, err = RedeemRegistrationOwnershipInviteLink(db, plaintext, redeemer.ID)
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})

	t.Run("rejects-invalid-registration-id", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		_, _, err := CreateRegistrationOwnershipInviteLink(
			db, 0, "u-creator", time.Now().Add(time.Hour), "", "")
		assert.Error(t, err)
	})

	t.Run("owner-change-revokes-other-outstanding-invites", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		regID := registrationInviteTestRegistration(t, db, "u-old-owner")
		redeemer, err := CreateLocalUser(db, "bob", "Bob", "https://local", CreatorSelf())
		require.NoError(t, err)
		rival, err := CreateLocalUser(db, "carol", "Carol", "https://local", CreatorSelf())
		require.NoError(t, err)

		_, plaintext1, err := CreateRegistrationOwnershipInviteLink(
			db, regID, "u-old-owner", time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)
		link2, plaintext2, err := CreateRegistrationOwnershipInviteLink(
			db, regID, "u-old-owner", time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		// The first redemption transfers ownership; the sibling invite was
		// minted under the previous owner's authority and must die with it.
		_, _, err = RedeemRegistrationOwnershipInviteLink(db, plaintext1, redeemer.ID)
		require.NoError(t, err)

		var sibling GroupInviteLink
		require.NoError(t, db.First(&sibling, "id = ?", link2.ID).Error)
		assert.True(t, sibling.Revoked,
			"outstanding invites must be revoked when the owner changes")

		_, _, err = RedeemRegistrationOwnershipInviteLink(db, plaintext2, rival.ID)
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound,
			"a revoked invite must not transfer ownership")

		var reg server_structs.Registration
		require.NoError(t, db.First(&reg, "id = ?", regID).Error)
		assert.Equal(t, redeemer.ID, reg.AdminMetadata.UserID,
			"ownership must stay with the first redeemer")
	})
}

// TestRedeemRegistrationOwnershipInviteLinkNotFoundIsOnlyForTheLink pins
// the error contract handlers rely on: gorm.ErrRecordNotFound means "no such
// invite link" and nothing else, so a vanished registration or an unknown
// redeemer is never reported to the caller as a missing link.
func TestRedeemRegistrationOwnershipInviteLinkNotFoundIsOnlyForTheLink(t *testing.T) {
	t.Run("unknown-token", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		redeemer, err := CreateLocalUser(db, "bob", "Bob", "https://local", CreatorSelf())
		require.NoError(t, err)
		_, _, err = RedeemRegistrationOwnershipInviteLink(db, "not-a-real-token", redeemer.ID)
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})

	t.Run("registration-deleted-after-mint", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		regID := registrationInviteTestRegistration(t, db, "u-old-owner")
		redeemer, err := CreateLocalUser(db, "bob", "Bob", "https://local", CreatorSelf())
		require.NoError(t, err)
		_, plaintext, err := CreateRegistrationOwnershipInviteLink(
			db, regID, "u-old-owner", time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		require.NoError(t, db.Delete(&server_structs.Registration{}, "id = ?", regID).Error)

		_, _, err = RedeemRegistrationOwnershipInviteLink(db, plaintext, redeemer.ID)
		require.Error(t, err)
		assert.NotErrorIs(t, err, gorm.ErrRecordNotFound,
			"a missing registration must not masquerade as a missing invite link")
		assert.Contains(t, err.Error(), "no longer exists")
	})

	t.Run("unknown-redeemer", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		regID := registrationInviteTestRegistration(t, db, "u-old-owner")
		_, plaintext, err := CreateRegistrationOwnershipInviteLink(
			db, regID, "u-old-owner", time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		_, _, err = RedeemRegistrationOwnershipInviteLink(db, plaintext, "no-such-user")
		require.Error(t, err)
		assert.NotErrorIs(t, err, gorm.ErrRecordNotFound,
			"an unknown redeemer must not masquerade as a missing invite link")
		assert.Contains(t, err.Error(), "does not exist")

		// The failed redemption must not have consumed the link.
		redeemer, err := CreateLocalUser(db, "bob", "Bob", "https://local", CreatorSelf())
		require.NoError(t, err)
		_, _, err = RedeemRegistrationOwnershipInviteLink(db, plaintext, redeemer.ID)
		require.NoError(t, err, "the link must remain redeemable after a rejected redemption")
	})
}

// TestSetRegistrationOwner covers the shared ownership-write primitive both
// the claim path and the invite redemption path go through.
func TestSetRegistrationOwner(t *testing.T) {
	t.Run("rejects-empty-owner-and-unloaded-registration", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		regID := registrationInviteTestRegistration(t, db, "")
		var reg server_structs.Registration
		require.NoError(t, db.First(&reg, "id = ?", regID).Error)

		assert.Error(t, SetRegistrationOwner(db, &reg, ""))
		assert.Error(t, SetRegistrationOwner(db, nil, "u-new"))
		assert.Error(t, SetRegistrationOwner(db, &server_structs.Registration{}, "u-new"))

		require.NoError(t, db.First(&reg, "id = ?", regID).Error)
		assert.Equal(t, "", reg.AdminMetadata.UserID, "rejected calls must not write")
	})

	t.Run("writes-owner-preserves-metadata-and-revokes-invites", func(t *testing.T) {
		db := registrationInviteTestDB(t)
		regID := registrationInviteTestRegistration(t, db, "u-old-owner")
		link, _, err := CreateRegistrationOwnershipInviteLink(
			db, regID, "u-old-owner", time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		var reg server_structs.Registration
		require.NoError(t, db.First(&reg, "id = ?", regID).Error)
		before := reg.AdminMetadata.UpdatedAt

		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			return SetRegistrationOwner(tx, &reg, "u-new-owner")
		}))
		assert.Equal(t, "u-new-owner", reg.AdminMetadata.UserID, "the in-memory copy mirrors the write")

		var stored server_structs.Registration
		require.NoError(t, db.First(&stored, "id = ?", regID).Error)
		assert.Equal(t, "u-new-owner", stored.AdminMetadata.UserID)
		assert.Equal(t, "example-site", stored.AdminMetadata.SiteName)
		assert.Equal(t, server_structs.RegApproved, stored.AdminMetadata.Status)
		assert.False(t, stored.AdminMetadata.UpdatedAt.Before(before))

		var storedLink GroupInviteLink
		require.NoError(t, db.First(&storedLink, "id = ?", link.ID).Error)
		assert.True(t, storedLink.Revoked, "an owner change must revoke outstanding ownership invites")
	})
}
