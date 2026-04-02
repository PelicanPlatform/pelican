/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func setupCollectionTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(
		&Collection{},
		&CollectionMember{},
		&CollectionACL{},
		&CollectionMetadata{},
		&User{},
		&Group{},
		&GroupMember{},
		&GroupInviteLink{},
		&UserIdentity{},
	)
	require.NoError(t, err)
	err = db.Exec("PRAGMA foreign_keys = ON").Error
	require.NoError(t, err)
	return db
}

func createTestInviteLink(t *testing.T, db *gorm.DB, groupID, createdBy, plaintext string, isSingleUse bool, expiresAt time.Time) *GroupInviteLink {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	require.NoError(t, err)
	link := GroupInviteLink{
		ID:          "link-" + plaintext,
		GroupID:     groupID,
		HashedToken: string(hashed),
		CreatedBy:   createdBy,
		ExpiresAt:   expiresAt,
		IsSingleUse: isSingleUse,
	}
	require.NoError(t, db.Create(&link).Error)
	return &link
}

func TestRedeemGroupInviteLink(t *testing.T) {
	t.Run("redeem-with-existing-user", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		user := User{ID: "user-1", Username: "alice", Sub: "alice-sub", Issuer: "https://issuer.example.com"}
		require.NoError(t, db.Create(&user).Error)
		group := Group{ID: "group-1", Name: "test-group", CreatedBy: "admin"}
		require.NoError(t, db.Create(&group).Error)

		token := "test-token-existing"
		createTestInviteLink(t, db, "group-1", "admin", token, false, time.Now().Add(1*time.Hour))

		err := RedeemGroupInviteLink(db, token, "user-1", "", "", "")
		require.NoError(t, err)

		// Verify user was added to group
		var member GroupMember
		require.NoError(t, db.First(&member, "group_id = ? AND user_id = ?", "group-1", "user-1").Error)
		assert.Equal(t, "user-1", member.UserID)
	})

	t.Run("redeem-with-auto-create-user", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		group := Group{ID: "group-2", Name: "test-group-2", CreatedBy: "admin"}
		require.NoError(t, db.Create(&group).Error)

		token := "test-token-autocreate"
		createTestInviteLink(t, db, "group-2", "admin", token, false, time.Now().Add(1*time.Hour))

		// No user exists; provide sub+issuer for auto-creation
		err := RedeemGroupInviteLink(db, token, "", "new-user-sub", "https://issuer.example.com", "newuser")
		require.NoError(t, err)

		// Verify user was created
		var user User
		require.NoError(t, db.First(&user, "sub = ? AND issuer = ?", "new-user-sub", "https://issuer.example.com").Error)
		assert.Equal(t, "newuser", user.Username)

		// Verify user was added to group
		var member GroupMember
		require.NoError(t, db.First(&member, "group_id = ? AND user_id = ?", "group-2", user.ID).Error)
		assert.Equal(t, user.ID, member.UserID)
	})

	t.Run("redeem-with-auto-create-derives-username-from-sub", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		group := Group{ID: "group-3", Name: "test-group-3", CreatedBy: "admin"}
		require.NoError(t, db.Create(&group).Error)

		token := "test-token-derive"
		createTestInviteLink(t, db, "group-3", "admin", token, false, time.Now().Add(1*time.Hour))

		// No username provided; should derive from sub
		err := RedeemGroupInviteLink(db, token, "", "derived-sub", "https://issuer.example.com", "")
		require.NoError(t, err)

		var user User
		require.NoError(t, db.First(&user, "sub = ?", "derived-sub").Error)
		assert.Equal(t, "derived-sub", user.Username)
	})

	t.Run("redeem-expired-link", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		user := User{ID: "user-exp", Username: "alice-exp", Sub: "alice-exp-sub", Issuer: "https://issuer.example.com"}
		require.NoError(t, db.Create(&user).Error)

		token := "test-token-expired"
		createTestInviteLink(t, db, "", "admin", token, false, time.Now().Add(-1*time.Hour))

		err := RedeemGroupInviteLink(db, token, "user-exp", "", "", "")
		require.Error(t, err)
		// Expired links shouldn't be found (WHERE clause filters them out)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("redeem-single-use-already-redeemed", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		user1 := User{ID: "user-su1", Username: "bob", Sub: "bob-sub", Issuer: "https://issuer.example.com"}
		require.NoError(t, db.Create(&user1).Error)
		user2 := User{ID: "user-su2", Username: "carol", Sub: "carol-sub", Issuer: "https://issuer.example.com"}
		require.NoError(t, db.Create(&user2).Error)
		group := Group{ID: "group-su", Name: "su-group", CreatedBy: "admin"}
		require.NoError(t, db.Create(&group).Error)

		token := "test-token-singleuse"
		createTestInviteLink(t, db, "group-su", "admin", token, true, time.Now().Add(1*time.Hour))

		// First redeem
		err := RedeemGroupInviteLink(db, token, "user-su1", "", "", "")
		require.NoError(t, err)

		// Second redeem should fail
		err = RedeemGroupInviteLink(db, token, "user-su2", "", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already been redeemed")
	})

	t.Run("redeem-invalid-token", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		user := User{ID: "user-inv", Username: "dave", Sub: "dave-sub", Issuer: "https://issuer.example.com"}
		require.NoError(t, db.Create(&user).Error)

		err := RedeemGroupInviteLink(db, "nonexistent-token", "user-inv", "", "", "")
		require.Error(t, err)
	})

	t.Run("redeem-without-identity-fails", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		group := Group{ID: "group-noid", Name: "noid-group", CreatedBy: "admin"}
		require.NoError(t, db.Create(&group).Error)

		token := "test-token-noid"
		createTestInviteLink(t, db, "group-noid", "admin", token, false, time.Now().Add(1*time.Hour))

		// No userID and no sub/issuer
		err := RedeemGroupInviteLink(db, token, "", "", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be auto-created")
	})

	t.Run("redeem-finds-existing-user-by-identity", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		// Create user with primary identity
		user := User{ID: "user-ident", Username: "eve", Sub: "eve-oidc-sub", Issuer: "https://issuer.example.com"}
		require.NoError(t, db.Create(&user).Error)

		group := Group{ID: "group-ident", Name: "ident-group", CreatedBy: "admin"}
		require.NoError(t, db.Create(&group).Error)

		token := "test-token-ident"
		createTestInviteLink(t, db, "group-ident", "admin", token, false, time.Now().Add(1*time.Hour))

		// Provide sub/issuer that matches existing user's primary identity, but no userID
		err := RedeemGroupInviteLink(db, token, "", "eve-oidc-sub", "https://issuer.example.com", "")
		require.NoError(t, err)

		// Verify user was added to the group
		var member GroupMember
		require.NoError(t, db.First(&member, "group_id = ? AND user_id = ?", "group-ident", "user-ident").Error)
		assert.Equal(t, "user-ident", member.UserID)
	})
}

func TestInputValidation_UserStatus(t *testing.T) {
	t.Run("valid-active-status", func(t *testing.T) {
		status := UserStatus("active")
		assert.Equal(t, UserStatusActive, status)
	})

	t.Run("valid-inactive-status", func(t *testing.T) {
		status := UserStatus("inactive")
		assert.Equal(t, UserStatusInactive, status)
	})

	t.Run("invalid-status-is-not-equal", func(t *testing.T) {
		status := UserStatus("deleted")
		assert.NotEqual(t, UserStatusActive, status)
		assert.NotEqual(t, UserStatusInactive, status)
	})
}
