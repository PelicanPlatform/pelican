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
}
