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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database/utils"
)

// testJWK creates a fresh ECDSA P-256 JWK with the given keyID.
func testJWK(t *testing.T, keyID string) jwk.Key {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, keyID))
	return key
}

// setupMasterKeyDB creates a temporary SQLite database with the
// server_master_keys table for testing.
func setupMasterKeyDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test-master-key.sqlite")
	db, err := utils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, utils.MigrateDB(sqlDB, EmbedUniversalMigrations, "universal_migrations"))
	return db
}

// ---- Crypto round-trip tests ----

func TestEncryptDecryptMasterKey(t *testing.T) {
	key := testJWK(t, "test-key-1")

	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	encrypted, err := EncryptMasterKey(masterKey, key)
	require.NoError(t, err)
	assert.Greater(t, len(encrypted), NaclNonceSize, "ciphertext should be longer than the nonce")

	decrypted, err := DecryptMasterKey(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, masterKey, decrypted)
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key1 := testJWK(t, "key-1")
	key2 := testJWK(t, "key-2")

	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	encrypted, err := EncryptMasterKey(masterKey, key1)
	require.NoError(t, err)

	_, err = DecryptMasterKey(encrypted, key2)
	assert.Error(t, err, "decryption with a different key should fail")
}

func TestDecryptTruncatedBlobFails(t *testing.T) {
	key := testJWK(t, "key-trunc")

	_, err := DecryptMasterKey(make([]byte, NaclNonceSize), key)
	assert.Error(t, err, "blob that is only nonce-sized should fail")

	_, err = DecryptMasterKey(make([]byte, 10), key)
	assert.Error(t, err, "short blob should fail")
}

// ---- HKDF sub-key derivation tests ----

func TestDeriveSubKeyDeterministic(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	k1, err := DeriveSubKey(masterKey, "pelican-idp-hmac-v1", 32)
	require.NoError(t, err)
	k2, err := DeriveSubKey(masterKey, "pelican-idp-hmac-v1", 32)
	require.NoError(t, err)

	assert.Equal(t, k1, k2, "same master key + purpose should yield identical sub-keys")
}

func TestDeriveSubKeyDifferentPurpose(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	k1, err := DeriveSubKey(masterKey, "purpose-a", 32)
	require.NoError(t, err)
	k2, err := DeriveSubKey(masterKey, "purpose-b", 32)
	require.NoError(t, err)

	assert.NotEqual(t, k1, k2, "different purposes should produce different sub-keys")
}

func TestDeriveSubKeyDifferentMasterKeys(t *testing.T) {
	mk1 := make([]byte, 32)
	mk2 := make([]byte, 32)
	_, _ = rand.Read(mk1)
	_, _ = rand.Read(mk2)

	k1, err := DeriveSubKey(mk1, "pelican-idp-hmac-v1", 32)
	require.NoError(t, err)
	k2, err := DeriveSubKey(mk2, "pelican-idp-hmac-v1", 32)
	require.NoError(t, err)

	assert.NotEqual(t, k1, k2, "different master keys should produce different sub-keys")
}

// ---- Storage methods tests ----

func TestMasterKeyRowsCRUD(t *testing.T) {
	db := setupMasterKeyDB(t)
	ctx := context.Background()

	// Initially empty.
	rows, err := LoadMasterKeyRows(ctx, db)
	require.NoError(t, err)
	assert.Empty(t, rows)

	// Insert two rows.
	require.NoError(t, SaveMasterKeyRow(ctx, db, "fp-a", []byte("blob-a")))
	require.NoError(t, SaveMasterKeyRow(ctx, db, "fp-b", []byte("blob-b")))

	rows, err = LoadMasterKeyRows(ctx, db)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, []byte("blob-a"), rows["fp-a"])
	assert.Equal(t, []byte("blob-b"), rows["fp-b"])

	// Upsert replaces.
	require.NoError(t, SaveMasterKeyRow(ctx, db, "fp-a", []byte("blob-a-v2")))
	rows, err = LoadMasterKeyRows(ctx, db)
	require.NoError(t, err)
	assert.Equal(t, []byte("blob-a-v2"), rows["fp-a"])

	// Delete one.
	require.NoError(t, DeleteMasterKeyRows(ctx, db, []string{"fp-b"}))
	rows, err = LoadMasterKeyRows(ctx, db)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Contains(t, rows, "fp-a")

	// Clear all.
	require.NoError(t, ClearMasterKeyRows(ctx, db))
	rows, err = LoadMasterKeyRows(ctx, db)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// ---- SyncMasterKeyRows tests ----

func TestSyncMasterKeyRows(t *testing.T) {
	db := setupMasterKeyDB(t)
	ctx := context.Background()

	key1 := testJWK(t, "sync-1")
	key2 := testJWK(t, "sync-2")
	key3 := testJWK(t, "sync-3")

	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	// Sync with two keys → creates two rows.
	keys12 := map[string]jwk.Key{"sync-1": key1, "sync-2": key2}
	require.NoError(t, SyncMasterKeyRows(db, masterKey, keys12))

	rows, err := LoadMasterKeyRows(ctx, db)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	// Both rows should decrypt to the same master key.
	for fp, blob := range rows {
		decrypted, err := DecryptMasterKey(blob, keys12[fp])
		require.NoError(t, err)
		assert.Equal(t, masterKey, decrypted)
	}

	// Rotate: remove key1, add key3.
	keys23 := map[string]jwk.Key{"sync-2": key2, "sync-3": key3}
	require.NoError(t, SyncMasterKeyRows(db, masterKey, keys23))

	rows, err = LoadMasterKeyRows(ctx, db)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Contains(t, rows, "sync-2")
	assert.Contains(t, rows, "sync-3")
	assert.NotContains(t, rows, "sync-1")

	// The new key3 row should also decrypt correctly.
	decrypted, err := DecryptMasterKey(rows["sync-3"], key3)
	require.NoError(t, err)
	assert.Equal(t, masterKey, decrypted)
}

func TestSyncMasterKeyRowsIdempotent(t *testing.T) {
	db := setupMasterKeyDB(t)

	key := testJWK(t, "idem-key")
	keys := map[string]jwk.Key{"idem-key": key}

	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	require.NoError(t, SyncMasterKeyRows(db, masterKey, keys))
	rows1, err := LoadMasterKeyRows(context.Background(), db)
	require.NoError(t, err)
	blob1 := rows1["idem-key"]

	// Second sync with same keys should not re-encrypt (row unchanged).
	require.NoError(t, SyncMasterKeyRows(db, masterKey, keys))
	rows2, err := LoadMasterKeyRows(context.Background(), db)
	require.NoError(t, err)
	assert.Equal(t, blob1, rows2["idem-key"], "idempotent sync should not change existing row")
}

// ---- End-to-end: derive HMAC from master key ----

func TestDeriveHMACFromMasterKey(t *testing.T) {
	key := testJWK(t, "hmac-roundtrip")
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	// Encrypt, store, load, decrypt, derive — full pipeline.
	db := setupMasterKeyDB(t)
	ctx := context.Background()

	encrypted, err := EncryptMasterKey(masterKey, key)
	require.NoError(t, err)
	require.NoError(t, SaveMasterKeyRow(ctx, db, "hmac-roundtrip", encrypted))

	rows, err := LoadMasterKeyRows(ctx, db)
	require.NoError(t, err)
	decrypted, err := DecryptMasterKey(rows["hmac-roundtrip"], key)
	require.NoError(t, err)
	assert.Equal(t, masterKey, decrypted)

	hmacKey, err := DeriveSubKey(decrypted, "pelican-idp-hmac-v1", 32)
	require.NoError(t, err)
	assert.Len(t, hmacKey, 32)

	// Same derivation should be deterministic.
	hmacKey2, err := DeriveSubKey(decrypted, "pelican-idp-hmac-v1", 32)
	require.NoError(t, err)
	assert.Equal(t, hmacKey, hmacKey2)
}
