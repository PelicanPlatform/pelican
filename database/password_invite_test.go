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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// passwordInviteTestUser creates one user we can drive password
// invites against. Returns the user ID. Identical shape across the
// subtests below so each one starts from the same baseline.
func passwordInviteTestUser(t *testing.T, db *gorm.DB) string {
	t.Helper()
	u, err := CreateLocalUser(db, "alice", "Alice", "https://local", CreatorSelf())
	require.NoError(t, err)
	return u.ID
}

// TestCreatePasswordInviteLink covers the mint side of the flow: who
// can be targeted, what the returned token looks like, and that
// every fresh invite is single-use by construction.
func TestCreatePasswordInviteLink(t *testing.T) {
	t.Run("happy path returns hash-prefixed token + DB row", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)

		expires := time.Now().Add(24 * time.Hour)
		link, plain, err := CreatePasswordInviteLink(db, uid, "u-creator", expires, "", "")
		require.NoError(t, err)
		require.NotNil(t, link)

		assert.Equal(t, InviteKindPassword, link.Kind)
		assert.Equal(t, uid, link.TargetUserID)
		assert.Empty(t, link.GroupID, "password invites must not carry a group_id")
		assert.True(t, link.IsSingleUse,
			"password invites are always single-use; a multi-use link would let an attacker rotate a victim's password from a leaked token")
		assert.NotEmpty(t, plain, "plaintext token must be returned to the caller (shown only once)")
		assert.NotEmpty(t, link.HashedToken, "stored token must be a hash, not the plaintext")
		assert.NotEqual(t, plain, link.HashedToken,
			"stored value must NOT equal the plaintext")
		assert.NotEmpty(t, link.TokenPrefix,
			"token prefix is the public short ID — must be populated for admin diff/audit")
		assert.True(t, strings.HasPrefix(plain, link.TokenPrefix),
			"the stored prefix must match the start of the plaintext token")
	})

	t.Run("rejects empty target user", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		_, _, err := CreatePasswordInviteLink(db, "", "u-creator", time.Now().Add(time.Hour), "", "")
		assert.Error(t, err)
	})

	t.Run("rejects unknown target user", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		_, _, err := CreatePasswordInviteLink(db, "u-nonexistent", "u-creator", time.Now().Add(time.Hour), "", "")
		assert.Error(t, err,
			"server must reject a password invite minted for a user that doesn't exist — otherwise the redeem path would silently fail later")
	})

	t.Run("each mint produces a distinct token + prefix", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)

		_, plain1, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)
		_, plain2, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)
		assert.NotEqual(t, plain1, plain2,
			"two mints in a row must yield distinct tokens; otherwise admin couldn't tell them apart in the audit log")
	})
}

// TestRedeemPasswordInviteLink covers the consumer side, including
// the negative paths that make the flow safe (single-use,
// expiry, revocation, wrong-token).
func TestRedeemPasswordInviteLink(t *testing.T) {
	t.Run("happy path sets the password and marks redeemed", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)

		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		const newPw = "topsecret-12345"
		gotUserID, err := RedeemPasswordInviteLink(db, plain, newPw)
		require.NoError(t, err)
		assert.Equal(t, uid, gotUserID)

		// VerifyUserPassword should now succeed with the chosen password.
		_, err = VerifyUserPassword(db, "alice", newPw, "https://local")
		require.NoError(t, err)

		// And the link is marked redeemed.
		var link GroupInviteLink
		require.NoError(t, db.First(&link, "target_user_id = ?", uid).Error)
		assert.NotEmpty(t, link.RedeemedBy)
		assert.NotNil(t, link.RedeemedAt)
	})

	t.Run("requires a non-empty password", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)
		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		_, err = RedeemPasswordInviteLink(db, plain, "")
		assert.Error(t, err, "DB layer must reject empty password — defense-in-depth alongside the handler's length check")
	})

	t.Run("single-use guard: second redeem fails", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)
		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		_, err = RedeemPasswordInviteLink(db, plain, "first-pw-12345")
		require.NoError(t, err)
		_, err = RedeemPasswordInviteLink(db, plain, "second-pw-67890")
		assert.Error(t, err,
			"single-use links must reject a second redemption (the original holder would otherwise rotate the password indefinitely)")

		// The password must still be the FIRST one, never the second.
		// Critical: the conditional UPDATE pattern in the redeem flow
		// has to claim the link BEFORE writing the hash, so a beaten
		// race rolls back the hash write too.
		_, err = VerifyUserPassword(db, "alice", "first-pw-12345", "https://local")
		assert.NoError(t, err, "first redemption's password should still be in effect")
		_, err = VerifyUserPassword(db, "alice", "second-pw-67890", "https://local")
		assert.ErrorIs(t, err, ErrInvalidPassword,
			"second redemption must NOT have rewritten the hash")
	})

	t.Run("unknown token returns NotFound", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		_, err := RedeemPasswordInviteLink(db, "definitely-not-a-real-token", "any-pw-12345")
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
	})

	t.Run("expired link returns NotFound", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)

		// Mint with future expiry to satisfy any guards, then push it
		// into the past via a direct UPDATE so we exercise the
		// expiry filter rather than testing time math.
		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)
		past := time.Now().Add(-time.Minute)
		require.NoError(t, db.Model(&GroupInviteLink{}).
			Where("target_user_id = ?", uid).
			Update("expires_at", past).Error)

		_, err = RedeemPasswordInviteLink(db, plain, "any-pw-12345")
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound),
			"expired link must NOT be redeemable; redeem queries filter on expires_at")
	})

	t.Run("revoked link returns NotFound", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)
		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)
		require.NoError(t, db.Model(&GroupInviteLink{}).
			Where("target_user_id = ?", uid).
			Update("revoked", true).Error)

		_, err = RedeemPasswordInviteLink(db, plain, "any-pw-12345")
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound),
			"revoked link must NOT be redeemable")
	})

	t.Run("group-kind token cannot redeem as password", func(t *testing.T) {
		db := setupCollectionTestDB(t)

		// Mint a group-kind invite directly so we can try to mis-redeem it
		// via the password endpoint.
		group := Group{ID: "g-x", Name: "g-x", CreatedBy: "u-creator", OwnerID: "u-creator"}
		require.NoError(t, db.Create(&group).Error)
		_, plain, err := CreateGroupInviteLink(db, "g-x", "u-creator",
			time.Now().Add(time.Hour), false, true, "", "")
		require.NoError(t, err)

		_, err = RedeemPasswordInviteLink(db, plain, "any-pw-12345")
		assert.Error(t, err,
			"a group-kind token must not be usable to set a password (kind discriminator must be enforced)")
	})

	t.Run("password hash on the row matches the plaintext bcrypt", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)

		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		const pw = "password-from-redeem-12345"
		_, err = RedeemPasswordInviteLink(db, plain, pw)
		require.NoError(t, err)

		// Cross-check the credential row directly so we know the
		// flow actually persisted a bcrypt hash that matches `pw`.
		// Goes through the credential-only struct so we don't need a
		// PasswordHash field on User.
		var cred userCredential
		require.NoError(t, db.Model(&userCredential{}).
			Select("id, password_hash").
			Where("id = ?", uid).Limit(1).
			Find(&cred).Error)
		require.NotEmpty(t, cred.PasswordHash, "redeem must have populated password_hash")
		assert.NoError(t,
			bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(pw)),
			"stored bcrypt hash must verify against the plaintext supplied at redeem time")
	})
}

// TestLookupInviteLinkByToken covers the no-consume probe used by
// the redemption UI to decide which form to render.
func TestLookupInviteLinkByToken(t *testing.T) {
	t.Run("returns metadata without consuming the link", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)
		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		got, err := LookupInviteLinkByToken(db, plain)
		require.NoError(t, err)
		assert.Equal(t, InviteKindPassword, got.Kind)
		assert.Empty(t, got.HashedToken,
			"probe response must NOT echo the stored hash back to the caller")

		// Lookup must not have consumed the link — redeeming after
		// must still succeed.
		_, err = RedeemPasswordInviteLink(db, plain, "fresh-pw-12345")
		require.NoError(t, err)
	})

	t.Run("revoked link is not visible to the probe", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)
		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)
		require.NoError(t, db.Model(&GroupInviteLink{}).
			Where("target_user_id = ?", uid).
			Update("revoked", true).Error)

		_, err = LookupInviteLinkByToken(db, plain)
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound),
			"the public probe must not leak revoked-link existence")
	})

	t.Run("already-redeemed single-use link returns NotFound", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		uid := passwordInviteTestUser(t, db)
		_, plain, err := CreatePasswordInviteLink(db, uid, "u-creator",
			time.Now().Add(time.Hour), "", "")
		require.NoError(t, err)

		_, err = RedeemPasswordInviteLink(db, plain, "first-pw-12345")
		require.NoError(t, err)

		_, err = LookupInviteLinkByToken(db, plain)
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound),
			"a redeemed single-use link must look 'not found' to the probe so the UI doesn't lure a second user into trying it")
	})
}

// TestListPasswordInvitesForUser confirms the audit query returns
// historical (redeemed/revoked) entries alongside live ones, so an
// admin can see "this user has 2 outstanding setup links and 1 has
// already been used."
func TestListPasswordInvitesForUser(t *testing.T) {
	db := setupCollectionTestDB(t)
	uid := passwordInviteTestUser(t, db)

	// One live, one redeemed, one revoked.
	_, plain1, err := CreatePasswordInviteLink(db, uid, "u-creator",
		time.Now().Add(time.Hour), "", "")
	require.NoError(t, err)
	_, err = RedeemPasswordInviteLink(db, plain1, "pw-redeemed-12345")
	require.NoError(t, err)

	_, _, err = CreatePasswordInviteLink(db, uid, "u-creator",
		time.Now().Add(time.Hour), "", "")
	require.NoError(t, err)

	_, _, err = CreatePasswordInviteLink(db, uid, "u-creator",
		time.Now().Add(time.Hour), "", "")
	require.NoError(t, err)
	require.NoError(t, db.Model(&GroupInviteLink{}).
		Where("target_user_id = ? AND revoked = 0 AND redeemed_by = ''", uid).
		Limit(1).
		Update("revoked", true).Error)

	rows, err := ListPasswordInvitesForUser(db, uid)
	require.NoError(t, err)
	assert.Len(t, rows, 3,
		"audit list must include redeemed and revoked rows alongside live ones")
}
