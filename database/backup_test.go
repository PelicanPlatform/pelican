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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
)

// setupTestDBAndKeys creates a temporary database, generates issuer keys,
// and configures viper params for backup testing.
func setupTestDBAndKeys(t *testing.T) (dbPath, backupDir, keysDir string) {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath = filepath.Join(tmpDir, "test.sqlite")
	backupDir = filepath.Join(tmpDir, "backups")
	keysDir = filepath.Join(tmpDir, "keys")

	require.NoError(t, os.MkdirAll(keysDir, 0750))

	// Configure keys directory and generate an issuer key
	require.NoError(t, param.Set("IssuerKeysDirectory", keysDir))
	config.ResetIssuerPrivateKeys()
	_, err := config.GeneratePEM(keysDir)
	require.NoError(t, err)

	// Load the generated key into the global issuer keys store
	key, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	require.NotNil(t, key)

	// Initialize the database
	db, err := utils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	ServerDatabase = db

	// Register cleanup to close the database before t.TempDir() removal.
	// This must be registered after t.TempDir() so that LIFO ordering
	// ensures the DB is closed before the temp directory is removed
	// (required on Windows where open files cannot be deleted).
	t.Cleanup(func() {
		if ServerDatabase != nil {
			_ = ShutdownDB()
			ServerDatabase = nil
		}
	})

	// Insert some test data
	err = ServerDatabase.Exec("CREATE TABLE test_data (id INTEGER PRIMARY KEY, value TEXT)").Error
	require.NoError(t, err)
	err = ServerDatabase.Exec("INSERT INTO test_data (value) VALUES ('hello'), ('world')").Error
	require.NoError(t, err)

	// Set config values
	require.NoError(t, param.MultiSet(map[string]interface{}{
		"Server.DbLocation":               dbPath,
		"Server.DatabaseBackup.Location":  backupDir,
		"Server.DatabaseBackup.MaxCount":  10,
		"Server.DatabaseBackup.Frequency": "24h",
	}))

	return dbPath, backupDir, keysDir
}

func TestDeriveBackupKeyPair(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	keysDir := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0750))
	require.NoError(t, param.Set("IssuerKeysDirectory", keysDir))
	config.ResetIssuerPrivateKeys()

	key, err := config.GeneratePEM(keysDir)
	require.NoError(t, err)

	t.Run("deterministic-derivation", func(t *testing.T) {
		priv1, pub1, err := deriveBackupKeyPair(key)
		require.NoError(t, err)
		priv2, pub2, err := deriveBackupKeyPair(key)
		require.NoError(t, err)
		assert.Equal(t, priv1, priv2, "same key should yield same private key")
		assert.Equal(t, pub1, pub2, "same key should yield same public key")
	})

	t.Run("different-keys-yield-different-pairs", func(t *testing.T) {
		key2, err := config.GeneratePEM(keysDir)
		require.NoError(t, err)

		priv1, _, err := deriveBackupKeyPair(key)
		require.NoError(t, err)
		priv2, _, err := deriveBackupKeyPair(key2)
		require.NoError(t, err)
		assert.NotEqual(t, priv1, priv2, "different keys should yield different private keys")
	})
}

func TestEncryptedChunkWriter(t *testing.T) {
	var dek [32]byte
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, dek[:])
	require.NoError(t, err)
	_, err = io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	t.Run("small-data-single-chunk", func(t *testing.T) {
		var buf bytes.Buffer
		w := newEncryptedChunkWriter(&buf, dek, nonce)
		data := []byte("hello world")
		_, err := w.Write(data)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		// Should produce exactly one PEM block
		block, rest := pem.Decode(buf.Bytes())
		require.NotNil(t, block)
		assert.Equal(t, pemTypeData, block.Type)
		assert.Equal(t, "1", block.Headers["Chunk"])

		// No more blocks
		block2, _ := pem.Decode(rest)
		assert.Nil(t, block2)
	})

	t.Run("large-data-multiple-chunks", func(t *testing.T) {
		var buf bytes.Buffer
		w := newEncryptedChunkWriter(&buf, dek, nonce)
		// Write 3.5 chunks worth of data
		data := make([]byte, chunkSize*3+chunkSize/2)
		_, err := io.ReadFull(rand.Reader, data)
		require.NoError(t, err)
		_, err = w.Write(data)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		// Count PEM blocks
		rest := buf.Bytes()
		var count int
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			count++
			rest = remaining
		}
		assert.Equal(t, 4, count, "should produce 4 chunks for 3.5x chunkSize data")
	})

	t.Run("roundtrip-decrypt", func(t *testing.T) {
		var buf bytes.Buffer
		w := newEncryptedChunkWriter(&buf, dek, nonce)
		original := []byte("This is test data for roundtrip encryption verification")
		_, err := w.Write(original)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		// Manually decrypt
		block, _ := pem.Decode(buf.Bytes())
		require.NotNil(t, block)

		var chunkNonce [24]byte
		copy(chunkNonce[:], nonce[:])
		// XOR with chunk 1
		chunkNonce[7] ^= 1
		decrypted, ok := secretbox.Open(nil, block.Bytes, &chunkNonce, &dek)
		require.True(t, ok)
		assert.Equal(t, original, decrypted)
	})
}

func TestWriteEncryptedKeys(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	keysDir := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0750))
	require.NoError(t, param.Set("IssuerKeysDirectory", keysDir))
	config.ResetIssuerPrivateKeys()

	key1, err := config.GeneratePEM(keysDir)
	require.NoError(t, err)
	key2, err := config.GeneratePEM(keysDir)
	require.NoError(t, err)

	allKeys := map[string]jwk.Key{
		key1.KeyID(): key1,
		key2.KeyID(): key2,
	}

	dekAndNonce := make([]byte, 56)
	_, err = io.ReadFull(rand.Reader, dekAndNonce)
	require.NoError(t, err)

	t.Run("writes-pem-blocks", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeEncryptedKeys(&buf, dekAndNonce, allKeys)
		require.NoError(t, err)

		// Should produce two PEM blocks
		rest := buf.Bytes()
		var count int
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			assert.Equal(t, pemTypeKey, block.Type)
			assert.NotEmpty(t, block.Headers["Key-Id"])
			count++
			rest = remaining
		}
		assert.Equal(t, 2, count)
	})

	t.Run("decrypt-key-block", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeEncryptedKeys(&buf, dekAndNonce, allKeys)
		require.NoError(t, err)

		// Try to decrypt with each key
		rest := buf.Bytes()
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			keyID := block.Headers["Key-Id"]
			issuerKey, found := allKeys[keyID]
			require.True(t, found)

			privKey, pubKey, err := deriveBackupKeyPair(issuerKey)
			require.NoError(t, err)

			require.GreaterOrEqual(t, len(block.Bytes), 24)
			var keyNonce [24]byte
			copy(keyNonce[:], block.Bytes[:24])
			decrypted, ok := box.Open(nil, block.Bytes[24:], &keyNonce, pubKey, privKey)
			require.True(t, ok)
			assert.Equal(t, dekAndNonce, decrypted)

			rest = remaining
		}
	})

	t.Run("no-keys-fails", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeEncryptedKeys(&buf, dekAndNonce, map[string]jwk.Key{})
		assert.Error(t, err)
	})
}

func TestPEMStreamDecoder(t *testing.T) {
	t.Run("reads-multiple-blocks", func(t *testing.T) {
		var buf bytes.Buffer
		for i := 0; i < 3; i++ {
			err := pem.Encode(&buf, &pem.Block{
				Type:  "TEST BLOCK",
				Bytes: []byte("data"),
			})
			require.NoError(t, err)
		}

		decoder := newPEMStreamDecoder(&buf)
		var count int
		for {
			block, err := decoder.next()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			assert.Equal(t, "TEST BLOCK", block.Type)
			count++
		}
		assert.Equal(t, 3, count)
	})

	t.Run("reads-blocks-with-headers", func(t *testing.T) {
		var buf bytes.Buffer
		err := pem.Encode(&buf, &pem.Block{
			Type:    pemTypeKey,
			Headers: map[string]string{"Key-Id": "test-key"},
			Bytes:   []byte("encrypted-data"),
		})
		require.NoError(t, err)

		decoder := newPEMStreamDecoder(&buf)
		block, err := decoder.next()
		require.NoError(t, err)
		assert.Equal(t, "test-key", block.Headers["Key-Id"])

		_, err = decoder.next()
		assert.ErrorIs(t, err, io.EOF)
	})
}

func TestCreateBackup(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	dbPath, backupDir, _ := setupTestDBAndKeys(t)
	_ = dbPath

	t.Run("creates-backup-file", func(t *testing.T) {
		ctx := context.Background()
		err := createBackup(ctx)
		require.NoError(t, err)

		// Verify backup file was created
		entries, err := os.ReadDir(backupDir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Contains(t, entries[0].Name(), backupFilePrefix)
		assert.Contains(t, entries[0].Name(), backupFileExt)
	})

	t.Run("backup-file-contains-pem-blocks", func(t *testing.T) {
		entries, err := os.ReadDir(backupDir)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(entries), 1)

		data, err := os.ReadFile(filepath.Join(backupDir, entries[0].Name()))
		require.NoError(t, err)

		// Verify it contains PEM blocks
		rest := data
		var metaBlocks, keyBlocks, dataBlocks int
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			switch block.Type {
			case pemTypeMetadata:
				metaBlocks++
			case pemTypeKey:
				keyBlocks++
			case pemTypeData:
				dataBlocks++
			}
			rest = remaining
		}
		assert.Equal(t, 1, metaBlocks, "should have exactly one metadata block")
		assert.GreaterOrEqual(t, keyBlocks, 1, "should have at least one key block")
		assert.GreaterOrEqual(t, dataBlocks, 1, "should have at least one data block")
	})

	t.Run("no-temp-files-remain", func(t *testing.T) {
		entries, err := os.ReadDir(backupDir)
		require.NoError(t, err)
		for _, e := range entries {
			assert.False(t, strings.HasSuffix(e.Name(), backupTempSuffix),
				"temporary file should not remain: %s", e.Name())
			assert.False(t, strings.HasPrefix(e.Name(), vacuumTempPrefix) && strings.HasSuffix(e.Name(), ".sqlite"),
				"vacuum temp file should not remain: %s", e.Name())
		}
	})
}

func TestRotateBackups(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	backupDir := filepath.Join(t.TempDir(), "backups")
	require.NoError(t, os.MkdirAll(backupDir, 0750))

	require.NoError(t, param.Set("Server.DatabaseBackup.MaxCount", 3))

	// Create 5 backup files with different timestamps
	for i := 0; i < 5; i++ {
		ts := time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(backupTimestampFormat)
		fname := backupFilePrefix + ts + backupFileExt
		err := os.WriteFile(filepath.Join(backupDir, fname), []byte("test"), 0600)
		require.NoError(t, err)
	}

	err := rotateBackups(backupDir)
	require.NoError(t, err)

	entries, err := os.ReadDir(backupDir)
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	// Verify oldest files were removed (keep 3 newest)
	assert.Equal(t, backupFilePrefix+"2026-01-03T000000"+backupFileExt, entries[0].Name())
	assert.Equal(t, backupFilePrefix+"2026-01-04T000000"+backupFileExt, entries[1].Name())
	assert.Equal(t, backupFilePrefix+"2026-01-05T000000"+backupFileExt, entries[2].Name())
}

func TestRotateBackupsCleansTempFiles(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	backupDir := filepath.Join(t.TempDir(), "backups")
	require.NoError(t, os.MkdirAll(backupDir, 0750))
	require.NoError(t, param.Set("Server.DatabaseBackup.MaxCount", 10))

	// Create a stale temp file (pretend it's old)
	staleTmpPath := filepath.Join(backupDir, backupTempPrefix+"stale.tmp")
	require.NoError(t, os.WriteFile(staleTmpPath, []byte("stale"), 0600))
	// Set mod time to 2 hours ago
	oldTime := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(staleTmpPath, oldTime, oldTime))

	// Create a recent temp file (should not be removed)
	recentTmpPath := filepath.Join(backupDir, backupTempPrefix+"recent.tmp")
	require.NoError(t, os.WriteFile(recentTmpPath, []byte("recent"), 0600))

	// Create a stale vacuum temp file
	staleVacuumPath := filepath.Join(backupDir, vacuumTempPrefix+"stale.sqlite")
	require.NoError(t, os.WriteFile(staleVacuumPath, []byte("vacuum"), 0600))
	require.NoError(t, os.Chtimes(staleVacuumPath, oldTime, oldTime))

	err := rotateBackups(backupDir)
	require.NoError(t, err)

	// Stale files should be removed
	_, err = os.Stat(staleTmpPath)
	assert.True(t, os.IsNotExist(err), "stale temp file should be removed")
	_, err = os.Stat(staleVacuumPath)
	assert.True(t, os.IsNotExist(err), "stale vacuum file should be removed")

	// Recent temp file should remain
	_, err = os.Stat(recentTmpPath)
	assert.NoError(t, err, "recent temp file should not be removed")
}

func TestRestoreFromBackup(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	dbPath, backupDir, _ := setupTestDBAndKeys(t)

	// Create a backup first
	ctx := context.Background()
	err := createBackup(ctx)
	require.NoError(t, err)

	// Shut down the database
	require.NoError(t, ShutdownDB())
	ServerDatabase = nil

	// Remove the original database
	require.NoError(t, os.Remove(dbPath))
	// Also remove WAL and SHM files if they exist
	os.Remove(dbPath + "-wal")
	os.Remove(dbPath + "-shm")

	t.Run("restore-from-backup", func(t *testing.T) {
		restored, err := restoreFromBackup(dbPath)
		require.NoError(t, err)
		assert.True(t, restored)

		// Verify the restored database works
		db, err := utils.InitSQLiteDB(dbPath)
		require.NoError(t, err)
		ServerDatabase = db

		var count int64
		err = ServerDatabase.Raw("SELECT COUNT(*) FROM test_data").Scan(&count).Error
		require.NoError(t, err)
		assert.Equal(t, int64(2), count)

		var value string
		err = ServerDatabase.Raw("SELECT value FROM test_data WHERE id = 1").Scan(&value).Error
		require.NoError(t, err)
		assert.Equal(t, "hello", value)
	})

	t.Run("no-restore-when-db-exists", func(t *testing.T) {
		// DB now exists from the restore above
		restored, err := restoreFromBackup(dbPath)
		require.NoError(t, err)
		assert.False(t, restored)
	})

	t.Run("no-restore-when-no-backup-dir", func(t *testing.T) {
		nonExistentDB := filepath.Join(t.TempDir(), "nonexistent.sqlite")
		require.NoError(t, param.Set("Server.DatabaseBackup.Location", filepath.Join(t.TempDir(), "no-such-dir")))

		restored, err := restoreFromBackup(nonExistentDB)
		require.NoError(t, err)
		assert.False(t, restored)

		// Restore config
		require.NoError(t, param.Set("Server.DatabaseBackup.Location", backupDir))
	})

	t.Run("no-restore-when-no-backups", func(t *testing.T) {
		emptyBackupDir := filepath.Join(t.TempDir(), "empty-backups")
		require.NoError(t, os.MkdirAll(emptyBackupDir, 0750))
		require.NoError(t, param.Set("Server.DatabaseBackup.Location", emptyBackupDir))

		nonExistentDB := filepath.Join(t.TempDir(), "nonexistent.sqlite")
		restored, err := restoreFromBackup(nonExistentDB)
		require.NoError(t, err)
		assert.False(t, restored)

		require.NoError(t, param.Set("Server.DatabaseBackup.Location", backupDir))
	})
}

func TestLaunchPeriodicBackup(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	_, backupDir, _ := setupTestDBAndKeys(t)

	// Set a very short frequency for testing
	require.NoError(t, param.Set("Server.DatabaseBackup.Frequency", "200ms"))

	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)

	LaunchPeriodicBackup(ctx, egrp)

	// Wait for at least one backup to be created
	require.Eventually(t, func() bool {
		entries, err := os.ReadDir(backupDir)
		if err != nil {
			return false
		}
		return len(entries) > 0
	}, 5*time.Second, 100*time.Millisecond, "expected at least one backup to be created")

	// Cancel the context to stop periodic backup
	cancel()

	// Wait for the goroutine to finish
	err := egrp.Wait()
	assert.NoError(t, err)
}

func TestLaunchPeriodicBackupDisabled(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	backupDir := filepath.Join(t.TempDir(), "backups")
	require.NoError(t, param.MultiSet(map[string]interface{}{
		"Server.DatabaseBackup.Location":  backupDir,
		"Server.DatabaseBackup.Frequency": "0s",
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, ctx := errgroup.WithContext(ctx)

	// This should return immediately without starting a goroutine
	LaunchPeriodicBackup(ctx, egrp)

	// Verify no backup was created
	_, err := os.ReadDir(backupDir)
	assert.True(t, os.IsNotExist(err), "backup dir should not have been created")
}

func TestBackupAndRestoreRoundTrip(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	dbPath, _, _ := setupTestDBAndKeys(t)

	// Insert more complex data
	err := ServerDatabase.Exec("INSERT INTO test_data (value) VALUES ('data1'), ('data2'), ('data3')").Error
	require.NoError(t, err)

	// Create backup
	ctx := context.Background()
	err = createBackup(ctx)
	require.NoError(t, err)

	// Get original data
	var originalValues []string
	err = ServerDatabase.Raw("SELECT value FROM test_data ORDER BY id").Scan(&originalValues).Error
	require.NoError(t, err)

	// Shut down and delete original database
	require.NoError(t, ShutdownDB())
	ServerDatabase = nil
	require.NoError(t, os.Remove(dbPath))
	os.Remove(dbPath + "-wal")
	os.Remove(dbPath + "-shm")

	// Restore from backup
	restored, err := restoreFromBackup(dbPath)
	require.NoError(t, err)
	require.True(t, restored)

	// Open restored database and verify data
	db, err := utils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	ServerDatabase = db

	var restoredValues []string
	err = ServerDatabase.Raw("SELECT value FROM test_data ORDER BY id").Scan(&restoredValues).Error
	require.NoError(t, err)

	assert.Equal(t, originalValues, restoredValues)
}

func TestWriteAndReadBackupMetadata(t *testing.T) {
	t.Run("round-trip", func(t *testing.T) {
		meta := BackupMetadata{
			FormatVersion:  "1",
			Timestamp:      "2026-02-21T12:00:00Z",
			Hostname:       "testhost",
			Username:       "testuser",
			PelicanVersion: "7.14.0",
			ServerURL:      "https://example.com:8444",
			DatabasePath:   "/var/lib/pelican/pelican.sqlite",
			GOOS:           "linux",
			GOARCH:         "amd64",
		}

		var buf bytes.Buffer
		err := writeBackupMetadata(&buf, meta)
		require.NoError(t, err)

		// The metadata should be a PEM block with all headers.
		block, _ := pem.Decode(buf.Bytes())
		require.NotNil(t, block)
		assert.Equal(t, pemTypeMetadata, block.Type)
		assert.Equal(t, "1", block.Headers["Format-Version"])
		assert.Equal(t, "testhost", block.Headers["Hostname"])
		assert.Equal(t, "testuser", block.Headers["Username"])
		assert.Equal(t, "7.14.0", block.Headers["Pelican-Version"])
		assert.Equal(t, "https://example.com:8444", block.Headers["Server-URL"])
		assert.Equal(t, "/var/lib/pelican/pelican.sqlite", block.Headers["Database-Path"])
		assert.Equal(t, "linux", block.Headers["GOOS"])
		assert.Equal(t, "amd64", block.Headers["GOARCH"])
		assert.Empty(t, block.Bytes)

		// Now test the read path via readBackupMetadata.
		reader := bytes.NewReader(buf.Bytes())
		readMeta, err := readBackupMetadata(reader)
		require.NoError(t, err)
		require.NotNil(t, readMeta)
		assert.Equal(t, meta, *readMeta)
	})

	t.Run("optional-fields-omitted", func(t *testing.T) {
		meta := BackupMetadata{
			FormatVersion:  "1",
			Timestamp:      "2026-02-21T12:00:00Z",
			PelicanVersion: "dev",
			GOOS:           "darwin",
			GOARCH:         "arm64",
		}

		var buf bytes.Buffer
		err := writeBackupMetadata(&buf, meta)
		require.NoError(t, err)

		block, _ := pem.Decode(buf.Bytes())
		require.NotNil(t, block)
		assert.Equal(t, "", block.Headers["Hostname"])
		assert.Equal(t, "", block.Headers["Username"])
		assert.Equal(t, "", block.Headers["Server-URL"])
		assert.Equal(t, "", block.Headers["Database-Path"])

		reader := bytes.NewReader(buf.Bytes())
		readMeta, err := readBackupMetadata(reader)
		require.NoError(t, err)
		require.NotNil(t, readMeta)
		assert.Equal(t, "", readMeta.Hostname)
		assert.Equal(t, "", readMeta.Username)
	})

	t.Run("no-metadata-block", func(t *testing.T) {
		// Simulate an older backup that starts with a key block.
		var buf bytes.Buffer
		keyBlock := &pem.Block{
			Type:    pemTypeKey,
			Headers: map[string]string{"Key-Id": "test-key"},
			Bytes:   []byte("fake-encrypted-key"),
		}
		require.NoError(t, pem.Encode(&buf, keyBlock))

		reader := bytes.NewReader(buf.Bytes())
		readMeta, err := readBackupMetadata(reader)
		require.NoError(t, err)
		assert.Nil(t, readMeta, "should return nil for backups without metadata")
	})
}

func TestCreateBackupIncludesMetadata(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	_, backupDir, _ := setupTestDBAndKeys(t)

	ctx := context.Background()
	err := createBackup(ctx)
	require.NoError(t, err)

	entries, err := os.ReadDir(backupDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	meta, err := ReadBackupMetadata(filepath.Join(backupDir, entries[0].Name()))
	require.NoError(t, err)
	require.NotNil(t, meta, "backup should contain a metadata block")

	assert.Equal(t, "1", meta.FormatVersion)
	assert.NotEmpty(t, meta.Timestamp)
	assert.NotEmpty(t, meta.PelicanVersion)
	assert.NotEmpty(t, meta.GOOS)
	assert.NotEmpty(t, meta.GOARCH)
	// DatabasePath should be set since we configured Server.DbLocation.
	assert.NotEmpty(t, meta.DatabasePath)
}
