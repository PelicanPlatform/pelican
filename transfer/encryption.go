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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/database"
)

// transferSecretHKDFPurpose is the HKDF "info" string used to derive the
// transfer module's secret-encryption key from the server master key. It must
// remain stable: changing it would make previously stored secrets
// undecryptable.
const transferSecretHKDFPurpose = "pelican-transfer-secrets-v1"

var (
	transferSecretKeyMu sync.RWMutex
	transferSecretKey   []byte // 32-byte AES key derived from the server master key
)

// secretEncryptionKey returns the transfer module's secret-encryption key,
// deriving it from the server master key (HKDF) on first use and caching it.
// This mirrors how the embedded OIDC issuer derives its sub-keys, so all
// server-side secrets share a single root of trust managed by the database.
func secretEncryptionKey() ([]byte, error) {
	transferSecretKeyMu.RLock()
	key := transferSecretKey
	transferSecretKeyMu.RUnlock()
	if len(key) == 32 {
		return key, nil
	}

	transferSecretKeyMu.Lock()
	defer transferSecretKeyMu.Unlock()
	if len(transferSecretKey) == 32 {
		return transferSecretKey, nil
	}

	db := database.ServerDatabase
	if db == nil {
		return nil, errors.New("server database is not initialized; cannot derive secret-encryption key")
	}
	masterKey, err := database.LoadOrCreateMasterKey(db)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load the server master key")
	}
	subKey, err := database.DeriveSubKey(masterKey, transferSecretHKDFPurpose, 32)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive the transfer secret-encryption key")
	}
	transferSecretKey = subKey
	return subKey, nil
}

// secretAEAD returns an AES-GCM AEAD keyed by the transfer secret-encryption key.
func secretAEAD() (cipher.AEAD, error) {
	key, err := secretEncryptionKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Column identifiers used as AES-GCM associated data (see secretAAD). Changing
// these strings would make previously stored secrets undecryptable.
const (
	fieldCredAccessToken  = "transfer_credentials.access_token"
	fieldCredRefreshToken = "transfer_credentials.refresh_token"
	fieldClientID         = "transfer_oauth_clients.client_id"
	fieldClientSecret     = "transfer_oauth_clients.client_secret"
)

// secretAAD binds a ciphertext to the row and column it belongs to. Passing it as
// AES-GCM associated data means a stored secret fails to decrypt if it is moved
// to a different owner's row or a different column — defense-in-depth against a
// DB-write primitive that cannot read the master key. userID is the owning row's
// user_id (for a shared/admin OAuth client, that is the admin who registered it,
// so encrypt and decrypt must both use the row's own user_id).
func secretAAD(userID, field string) []byte {
	return []byte(userID + "|" + field)
}

// encryptSecret encrypts a secret value for storage in the database. The result
// is base64(nonce || ciphertext), authenticated with AES-GCM under a key derived
// from the server master key and bound to (userID, field) via associated data.
func encryptSecret(plaintext, userID, field string) (string, error) {
	gcm, err := secretAEAD()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "failed to generate nonce")
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), secretAAD(userID, field))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptSecret reverses encryptSecret. It must be called with the same
// (userID, field) the value was encrypted under, or decryption fails.
func decryptSecret(ciphertext, userID, field string) (string, error) {
	gcm, err := secretAEAD()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.Wrap(err, "invalid encrypted-secret encoding")
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("encrypted secret is too short")
	}
	nonce, sealed := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, sealed, secretAAD(userID, field))
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt secret")
	}
	return string(plaintext), nil
}
