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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Insert some test data
	err = ServerDatabase.Exec("CREATE TABLE test_data (id INTEGER PRIMARY KEY, value TEXT)").Error
	require.NoError(t, err)
	err = ServerDatabase.Exec("INSERT INTO test_data (value) VALUES ('hello'), ('world')").Error
	require.NoError(t, err)

	// Set config values
	require.NoError(t, param.MultiSet(map[string]interface{}{
		"Server.DbLocation":              dbPath,
		"Server.DatabaseBackup.Location":  backupDir,
		"Server.DatabaseBackup.MaxCount":  10,
		"Server.DatabaseBackup.Frequency": "24h",
	}))

	return dbPath, backupDir, keysDir
}

func TestEncryptDecryptBackup(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		config.ResetConfig()
	})

	keysDir := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0750))

	require.NoError(t, param.Set("IssuerKeysDirectory", keysDir))
	config.ResetIssuerPrivateKeys()

	// Generate two issuer keys to test multi-key encryption
	_, err := config.GeneratePEM(keysDir)
	require.NoError(t, err)

	_, err = config.GeneratePEM(keysDir)
	require.NoError(t, err)

	// Load generated keys into the global issuer keys store
	_, err = config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	// Refresh to pick up all keys
	_, err = config.RefreshKeys()
	require.NoError(t, err)

	allKeys := config.GetIssuerPrivateKeys()
	require.GreaterOrEqual(t, len(allKeys), 2, "expected at least 2 issuer keys")

	testData := []byte("This is test backup data for encryption testing")

	t.Run("encrypt-decrypt-with-all-keys", func(t *testing.T) {
		encrypted, err := encryptBackup(testData, allKeys)
		require.NoError(t, err)
		require.NotEmpty(t, encrypted)

		decrypted, err := decryptBackup(encrypted, allKeys)
		require.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("decrypt-with-single-key", func(t *testing.T) {
		// Encrypt with all keys
		encrypted, err := encryptBackup(testData, allKeys)
		require.NoError(t, err)

		// Try to decrypt with just one key at a time
		for keyID, key := range allKeys {
			singleKey := map[string]jwk.Key{keyID: key}
			decrypted, err := decryptBackup(encrypted, singleKey)
			require.NoError(t, err, "should decrypt with key %s", keyID)
			assert.Equal(t, testData, decrypted)
		}
	})

	t.Run("decrypt-with-wrong-key-fails", func(t *testing.T) {
		encrypted, err := encryptBackup(testData, allKeys)
		require.NoError(t, err)

		// Generate a completely new key that was not used for encryption
		otherKeysDir := filepath.Join(t.TempDir(), "other-keys")
		require.NoError(t, os.MkdirAll(otherKeysDir, 0750))

		otherKey, err := config.GeneratePEM(otherKeysDir)
		require.NoError(t, err)

		wrongKeys := map[string]jwk.Key{otherKey.KeyID(): otherKey}
		_, err = decryptBackup(encrypted, wrongKeys)
		assert.Error(t, err)
	})

	t.Run("encrypt-no-keys-fails", func(t *testing.T) {
		_, err := encryptBackup(testData, map[string]jwk.Key{})
		assert.Error(t, err)
	})

	t.Run("decrypt-no-keys-fails", func(t *testing.T) {
		encrypted, err := encryptBackup(testData, allKeys)
		require.NoError(t, err)

		_, err = decryptBackup(encrypted, map[string]jwk.Key{})
		assert.Error(t, err)
	})
}

func TestCreateBackup(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		if ServerDatabase != nil {
			_ = ShutdownDB()
		}
		config.ResetConfig()
	})

	dbPath, backupDir, _ := setupTestDBAndKeys(t)
	_ = dbPath

	t.Run("creates-backup-file", func(t *testing.T) {
		ctx := context.Background()
		err := CreateBackup(ctx)
		require.NoError(t, err)

		// Verify backup file was created
		entries, err := os.ReadDir(backupDir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Contains(t, entries[0].Name(), backupFilePrefix)
		assert.Contains(t, entries[0].Name(), backupFileExt)
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
		ts := time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC).Format("20060102-150405")
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
	assert.Equal(t, backupFilePrefix+"20260103-000000"+backupFileExt, entries[0].Name())
	assert.Equal(t, backupFilePrefix+"20260104-000000"+backupFileExt, entries[1].Name())
	assert.Equal(t, backupFilePrefix+"20260105-000000"+backupFileExt, entries[2].Name())
}

func TestRestoreFromBackup(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		if ServerDatabase != nil {
			_ = ShutdownDB()
		}
		config.ResetConfig()
	})

	dbPath, backupDir, _ := setupTestDBAndKeys(t)

	// Create a backup first
	ctx := context.Background()
	err := CreateBackup(ctx)
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
		restored, err := RestoreFromBackup(dbPath)
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
		restored, err := RestoreFromBackup(dbPath)
		require.NoError(t, err)
		assert.False(t, restored)
	})

	t.Run("no-restore-when-no-backup-dir", func(t *testing.T) {
		nonExistentDB := filepath.Join(t.TempDir(), "nonexistent.sqlite")
		require.NoError(t, param.Set("Server.DatabaseBackup.Location", filepath.Join(t.TempDir(), "no-such-dir")))

		restored, err := RestoreFromBackup(nonExistentDB)
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
		restored, err := RestoreFromBackup(nonExistentDB)
		require.NoError(t, err)
		assert.False(t, restored)

		require.NoError(t, param.Set("Server.DatabaseBackup.Location", backupDir))
	})
}

func TestLaunchPeriodicBackup(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() {
		if ServerDatabase != nil {
			_ = ShutdownDB()
		}
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
		if ServerDatabase != nil {
			_ = ShutdownDB()
		}
		config.ResetConfig()
	})

	dbPath, _, _ := setupTestDBAndKeys(t)

	// Insert more complex data
	err := ServerDatabase.Exec("INSERT INTO test_data (value) VALUES ('data1'), ('data2'), ('data3')").Error
	require.NoError(t, err)

	// Create backup
	ctx := context.Background()
	err = CreateBackup(ctx)
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
	restored, err := RestoreFromBackup(dbPath)
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
