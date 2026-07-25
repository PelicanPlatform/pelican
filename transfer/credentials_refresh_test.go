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

package transfer

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }

// TestSecretAADBinding verifies that an encrypted secret is bound to its
// (userID, field) via AES-GCM associated data: decrypting with a different
// user's id or a different column fails, so a ciphertext cannot be moved between
// rows or columns.
func TestSecretAADBinding(t *testing.T) {
	newTransferTestDB(t) // sets up the server DB + master key for encryptSecret

	enc, err := encryptSecret("s3cr3t", "user-a", fieldCredAccessToken)
	require.NoError(t, err)

	// Correct (userID, field) round-trips.
	got, err := decryptSecret(enc, "user-a", fieldCredAccessToken)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", got)

	// Wrong user (ciphertext moved to another user's row) fails.
	_, err = decryptSecret(enc, "user-b", fieldCredAccessToken)
	assert.Error(t, err, "decryption must fail under a different user id")

	// Wrong column (ciphertext moved to another field) fails.
	_, err = decryptSecret(enc, "user-a", fieldCredRefreshToken)
	assert.Error(t, err, "decryption must fail under a different column")
}

// TestCredentialRefreshDecision covers the pure predicates that decide whether a
// stored credential is expired and whether it can/should be refreshed.
func TestCredentialRefreshDecision(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	soon := time.Now().Add(time.Minute) // within the refresh margin
	later := time.Now().Add(time.Hour)  // outside the refresh margin
	refresh := strPtr("enc-refresh-token")

	t.Run("expired", func(t *testing.T) {
		assert.True(t, credentialExpired(&TransferCredential{TokenExpiry: &past}))
		assert.False(t, credentialExpired(&TransferCredential{TokenExpiry: &later}))
		assert.False(t, credentialExpired(&TransferCredential{}), "unknown expiry is not treated as expired")
	})

	t.Run("refreshable", func(t *testing.T) {
		assert.True(t, credentialRefreshable(&TransferCredential{TokenIssuer: "https://issuer", EncryptedRefreshToken: refresh}))
		assert.False(t, credentialRefreshable(&TransferCredential{TokenIssuer: "https://issuer"}), "no refresh token")
		assert.False(t, credentialRefreshable(&TransferCredential{EncryptedRefreshToken: refresh}), "no issuer")
	})

	t.Run("needsRefresh", func(t *testing.T) {
		refreshable := func(c TransferCredential) TransferCredential {
			c.TokenIssuer = "https://issuer"
			c.EncryptedRefreshToken = refresh
			return c
		}
		assert.True(t, credentialNeedsRefresh(&TransferCredential{TokenExpiry: &soon, TokenIssuer: "https://issuer", EncryptedRefreshToken: refresh, EncryptedAccessToken: "enc"}),
			"expiring soon and refreshable")
		c := refreshable(TransferCredential{TokenExpiry: &later, EncryptedAccessToken: "enc"})
		assert.False(t, credentialNeedsRefresh(&c), "valid well into the future needs no refresh")
		c = refreshable(TransferCredential{EncryptedAccessToken: ""})
		assert.True(t, credentialNeedsRefresh(&c), "a missing access token with a refresh token should refresh")
		assert.False(t, credentialNeedsRefresh(&TransferCredential{TokenExpiry: &soon, EncryptedAccessToken: "enc"}),
			"expiring but not refreshable")
	})
}

// TestGetDecryptedAccessTokenFailFastOnExpired verifies that a credential whose
// token has expired and cannot be refreshed fails fast with a clear error rather
// than handing back a token the destination will reject.
func TestGetDecryptedAccessTokenFailFastOnExpired(t *testing.T) {
	db, userID := newTransferTestDB(t)
	owner := ownerIdentity{UserID: userID}

	enc, err := encryptSecret("expired-token", userID, fieldCredAccessToken)
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour)
	cred := TransferCredential{
		ID:                   uuid.New().String(),
		UserID:               userID,
		Name:                 "expired-cred",
		CredentialType:       "bearer",
		EncryptedAccessToken: enc,
		TokenExpiry:          &past, // expired, and no refresh token / issuer
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	require.NoError(t, db.Create(&cred).Error)

	_, err = getDecryptedAccessToken(db, cred.ID, owner)
	require.Error(t, err, "an expired, non-refreshable token must fail fast")
	assert.Contains(t, err.Error(), "expired")
}

// TestGetDecryptedAccessTokenReturnsValidToken verifies the common path: a
// non-expired token is decrypted and returned without any refresh attempt.
func TestGetDecryptedAccessTokenReturnsValidToken(t *testing.T) {
	db, userID := newTransferTestDB(t)
	owner := ownerIdentity{UserID: userID}

	enc, err := encryptSecret("valid-token", userID, fieldCredAccessToken)
	require.NoError(t, err)
	future := time.Now().Add(time.Hour)
	cred := TransferCredential{
		ID:                   uuid.New().String(),
		UserID:               userID,
		Name:                 "valid-cred",
		CredentialType:       "bearer",
		EncryptedAccessToken: enc,
		TokenExpiry:          &future,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	require.NoError(t, db.Create(&cred).Error)

	tok, err := getDecryptedAccessToken(db, cred.ID, owner)
	require.NoError(t, err)
	assert.Equal(t, "valid-token", tok)
}
