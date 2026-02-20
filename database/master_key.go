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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
)

const (
	// masterKeyBytes is the size of the randomly-generated master key.
	masterKeyBytes = 32

	// naclNonceSize is the byte length of a NaCl box nonce.
	NaclNonceSize = 24
)

// naclKeyPairFromJWK derives a NaCl box keypair from a JWK private key.
// This mirrors the approach used in config/encrypted.go.
func naclKeyPairFromJWK(issuerKey jwk.Key) (privKey, pubKey *[32]byte, err error) {
	secret, err := config.GetSecret(issuerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive secret from key %s: %w", issuerKey.KeyID(), err)
	}

	privKey = new([32]byte)
	copy(privKey[:], []byte(secret))

	pubKey = new([32]byte)
	curve25519.ScalarBaseMult(pubKey, privKey) //nolint:staticcheck // matches config/encrypted.go
	return privKey, pubKey, nil
}

// EncryptMasterKey encrypts the master key using a NaCl box derived from
// the given server private key. Returns nonce (24 bytes) || ciphertext.
func EncryptMasterKey(masterKey []byte, serverKey jwk.Key) ([]byte, error) {
	privKey, pubKey, err := naclKeyPairFromJWK(serverKey)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// box.Seal appends to the first arg; pre-fill with nonce so result is nonce||ciphertext.
	encrypted := box.Seal(nonce[:], masterKey, &nonce, pubKey, privKey)
	return encrypted, nil
}

// DecryptMasterKey decrypts a blob produced by EncryptMasterKey using the
// corresponding server private key.
func DecryptMasterKey(encryptedBlob []byte, serverKey jwk.Key) ([]byte, error) {
	if len(encryptedBlob) <= NaclNonceSize {
		return nil, errors.New("encrypted master key blob is too short")
	}

	privKey, pubKey, err := naclKeyPairFromJWK(serverKey)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], encryptedBlob[:NaclNonceSize])

	decrypted, ok := box.Open(nil, encryptedBlob[NaclNonceSize:], &nonce, pubKey, privKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed for key %s", serverKey.KeyID())
	}
	return decrypted, nil
}

// DeriveSubKey derives a purpose-specific sub-key from the master key
// using HKDF-SHA256.  The purpose string (HKDF "info") distinguishes
// different key usages, preventing one derived key from being usable
// in another context.
func DeriveSubKey(masterKey []byte, purpose string, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, masterKey, nil, []byte(purpose))
	subKey := make([]byte, length)
	if _, err := io.ReadFull(r, subKey); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed for purpose %q: %w", purpose, err)
	}
	return subKey, nil
}

// ---- Storage operations for server_master_keys ----

// SaveMasterKeyRow inserts or replaces an encrypted master key row.
func SaveMasterKeyRow(ctx context.Context, db *gorm.DB, fingerprint string, encryptedKey []byte) error {
	return db.WithContext(ctx).Exec(
		`INSERT OR REPLACE INTO server_master_keys (key_fingerprint, encrypted_master_key) VALUES (?, ?)`,
		fingerprint, encryptedKey,
	).Error
}

// LoadMasterKeyRows returns all rows from server_master_keys as a
// map[keyFingerprint] → encryptedBlob.
func LoadMasterKeyRows(ctx context.Context, db *gorm.DB) (map[string][]byte, error) {
	rows, err := db.WithContext(ctx).Raw(
		`SELECT key_fingerprint, encrypted_master_key FROM server_master_keys`,
	).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]byte)
	for rows.Next() {
		var fp string
		var blob []byte
		if err := rows.Scan(&fp, &blob); err != nil {
			return nil, err
		}
		result[fp] = blob
	}
	return result, rows.Err()
}

// DeleteMasterKeyRows removes rows whose fingerprints are in the given list.
func DeleteMasterKeyRows(ctx context.Context, db *gorm.DB, fingerprints []string) error {
	if len(fingerprints) == 0 {
		return nil
	}
	return db.WithContext(ctx).Exec(
		`DELETE FROM server_master_keys WHERE key_fingerprint IN (?)`, fingerprints,
	).Error
}

// ClearMasterKeyRows removes all rows from server_master_keys.
func ClearMasterKeyRows(ctx context.Context, db *gorm.DB) error {
	return db.WithContext(ctx).Exec(`DELETE FROM server_master_keys`).Error
}

// ---- Master key lifecycle ----

// SyncMasterKeyRows ensures server_master_keys has exactly one row per
// current server private key, each containing the master key encrypted
// for that key.  Rows for keys no longer present are removed.
func SyncMasterKeyRows(db *gorm.DB, masterKey []byte, currentKeys map[string]jwk.Key) error {
	ctx := context.Background()

	existing, err := LoadMasterKeyRows(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to load master key rows: %w", err)
	}

	// Remove rows for keys that are no longer present.
	var toDelete []string
	for fp := range existing {
		if _, ok := currentKeys[fp]; !ok {
			toDelete = append(toDelete, fp)
		}
	}
	if len(toDelete) > 0 {
		if err := DeleteMasterKeyRows(ctx, db, toDelete); err != nil {
			return fmt.Errorf("failed to remove stale master key rows: %w", err)
		}
		log.Infof("Removed %d stale master key row(s)", len(toDelete))
	}

	// Add rows for keys that don't already have one.
	for fp, key := range currentKeys {
		if _, exists := existing[fp]; exists {
			continue
		}
		encrypted, err := EncryptMasterKey(masterKey, key)
		if err != nil {
			return fmt.Errorf("failed to encrypt master key for key %s: %w", fp, err)
		}
		if err := SaveMasterKeyRow(ctx, db, fp, encrypted); err != nil {
			return fmt.Errorf("failed to save master key row for key %s: %w", fp, err)
		}
		log.Infof("Added master key row for server key %s", fp)
	}

	return nil
}

// LoadOrCreateMasterKey loads the master key by decrypting any available
// row in server_master_keys using the server's private keys.  If no rows
// exist (first start), a fresh 32-byte master key is generated.  After
// loading or creating, the rows are synced to match the current set of
// server private keys so that key rotation is handled transparently.
func LoadOrCreateMasterKey(db *gorm.DB) ([]byte, error) {
	ctx := context.Background()

	existingRows, err := LoadMasterKeyRows(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("failed to load master key rows: %w", err)
	}

	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		// Ensure at least the current key is loaded.
		currentKey, err := config.GetIssuerPrivateJWK()
		if err != nil {
			return nil, fmt.Errorf("no server private keys available: %w", err)
		}
		allKeys = map[string]jwk.Key{currentKey.KeyID(): currentKey}
	}

	var masterKey []byte

	// Try to decrypt using any matching key.
	for fp, blob := range existingRows {
		key, found := allKeys[fp]
		if !found {
			continue
		}
		decrypted, err := DecryptMasterKey(blob, key)
		if err != nil {
			log.Warnf("Failed to decrypt master key row for key %s: %v", fp, err)
			continue
		}
		masterKey = decrypted
		log.Infof("Loaded master key using server key %s", fp)
		break
	}

	// Generate a new master key if none could be decrypted.
	if masterKey == nil {
		masterKey = make([]byte, masterKeyBytes)
		if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
			return nil, fmt.Errorf("failed to generate master key: %w", err)
		}
		if len(existingRows) > 0 {
			log.Warn("Could not decrypt any existing master key rows; generating a new master key. " +
				"Previously-issued opaque tokens will be invalidated.")
		} else {
			log.Info("No master key found; generating a new one")
		}
	}

	// Sync the rows to match current keys.
	if err := SyncMasterKeyRows(db, masterKey, allKeys); err != nil {
		return nil, fmt.Errorf("failed to sync master key rows: %w", err)
	}

	return masterKey, nil
}
