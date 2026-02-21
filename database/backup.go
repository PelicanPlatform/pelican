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
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

const (
	backupFilePrefix = "pelican-db-backup-"
	backupFileExt    = ".bak"
)

// encryptBackup encrypts the compressed database backup data.
// It generates a random data encryption key (DEK), encrypts the data with it,
// then wraps the DEK with each issuer key so any key can decrypt.
//
// Format:
//
//	[4 bytes: key count N]
//	For each key:
//	  [4 bytes: keyID length][keyID bytes][4 bytes: encrypted DEK length][encrypted DEK bytes]
//	[encrypted data]
func encryptBackup(data []byte, issuerKeys map[string]jwk.Key) ([]byte, error) {
	if len(issuerKeys) == 0 {
		return nil, errors.New("no issuer keys available for encryption")
	}

	// Generate a random data encryption key (DEK) and nonce
	var dek [32]byte
	if _, err := io.ReadFull(rand.Reader, dek[:]); err != nil {
		return nil, errors.Wrap(err, "failed to generate data encryption key")
	}
	var dataNonce [24]byte
	if _, err := io.ReadFull(rand.Reader, dataNonce[:]); err != nil {
		return nil, errors.Wrap(err, "failed to generate data nonce")
	}

	// Encrypt data with DEK using NaCl box (using DEK as both keys for symmetric-like encryption)
	encryptedData := box.Seal(nil, data, &dataNonce, &dek, &dek)

	var buf bytes.Buffer

	// Write key count
	keyCount := uint32(len(issuerKeys))
	if err := binary.Write(&buf, binary.BigEndian, keyCount); err != nil {
		return nil, errors.Wrap(err, "failed to write key count")
	}

	// Sort key IDs for deterministic output
	keyIDs := make([]string, 0, len(issuerKeys))
	for keyID := range issuerKeys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)

	// For each issuer key, encrypt the DEK+nonce
	dekAndNonce := append(dek[:], dataNonce[:]...)
	for _, keyID := range keyIDs {
		issuerKey := issuerKeys[keyID]

		privKey, pubKey, err := config.GetEncryptionKeyPair(issuerKey)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get encryption key pair for key %s", keyID)
		}

		// Encrypt DEK+nonce with this issuer key pair
		var keyNonce [24]byte
		if _, err := io.ReadFull(rand.Reader, keyNonce[:]); err != nil {
			return nil, errors.Wrap(err, "failed to generate key nonce")
		}
		encryptedDEK := box.Seal(keyNonce[:], dekAndNonce, &keyNonce, pubKey, privKey)

		// Write keyID
		keyIDBytes := []byte(keyID)
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(keyIDBytes))); err != nil {
			return nil, err
		}
		buf.Write(keyIDBytes)

		// Write encrypted DEK
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(encryptedDEK))); err != nil {
			return nil, err
		}
		buf.Write(encryptedDEK)
	}

	// Write encrypted data
	buf.Write(encryptedData)

	return buf.Bytes(), nil
}

// decryptBackup decrypts a backup file using the available issuer keys.
func decryptBackup(encryptedData []byte, issuerKeys map[string]jwk.Key) ([]byte, error) {
	if len(issuerKeys) == 0 {
		return nil, errors.New("no issuer keys available for decryption")
	}

	buf := bytes.NewReader(encryptedData)

	// Read key count
	var keyCount uint32
	if err := binary.Read(buf, binary.BigEndian, &keyCount); err != nil {
		return nil, errors.Wrap(err, "failed to read key count from backup")
	}

	// Read each encrypted DEK entry and try to decrypt
	var decryptedDEKAndNonce []byte
	for i := uint32(0); i < keyCount; i++ {
		// Read keyID
		var keyIDLen uint32
		if err := binary.Read(buf, binary.BigEndian, &keyIDLen); err != nil {
			return nil, errors.Wrap(err, "failed to read key ID length")
		}
		keyIDBytes := make([]byte, keyIDLen)
		if _, err := io.ReadFull(buf, keyIDBytes); err != nil {
			return nil, errors.Wrap(err, "failed to read key ID")
		}
		keyID := string(keyIDBytes)

		// Read encrypted DEK
		var encDEKLen uint32
		if err := binary.Read(buf, binary.BigEndian, &encDEKLen); err != nil {
			return nil, errors.Wrap(err, "failed to read encrypted DEK length")
		}
		encDEK := make([]byte, encDEKLen)
		if _, err := io.ReadFull(buf, encDEK); err != nil {
			return nil, errors.Wrap(err, "failed to read encrypted DEK")
		}

		// Skip if already decrypted
		if decryptedDEKAndNonce != nil {
			continue
		}

		// Try to decrypt with matching issuer key
		issuerKey, found := issuerKeys[keyID]
		if !found {
			continue
		}

		privKey, pubKey, err := config.GetEncryptionKeyPair(issuerKey)
		if err != nil {
			log.Debugf("Failed to get encryption key pair for key %s: %v", keyID, err)
			continue
		}

		// Extract nonce from first 24 bytes
		if len(encDEK) < 24 {
			continue
		}
		var keyNonce [24]byte
		copy(keyNonce[:], encDEK[:24])

		dekAndNonce, ok := box.Open(nil, encDEK[24:], &keyNonce, pubKey, privKey)
		if !ok {
			log.Debugf("Failed to decrypt DEK with key %s", keyID)
			continue
		}
		decryptedDEKAndNonce = dekAndNonce
	}

	if decryptedDEKAndNonce == nil {
		return nil, errors.New("failed to decrypt backup: no matching issuer key found")
	}

	if len(decryptedDEKAndNonce) != 56 { // 32 bytes DEK + 24 bytes nonce
		return nil, errors.New("invalid decrypted DEK+nonce length")
	}

	var dek [32]byte
	copy(dek[:], decryptedDEKAndNonce[:32])
	var dataNonce [24]byte
	copy(dataNonce[:], decryptedDEKAndNonce[32:])

	// Read remaining encrypted data
	remainingData, err := io.ReadAll(buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read encrypted data")
	}

	// Decrypt the data
	decrypted, ok := box.Open(nil, remainingData, &dataNonce, &dek, &dek)
	if !ok {
		return nil, errors.New("failed to decrypt backup data")
	}

	return decrypted, nil
}

// CreateBackup creates a compressed and encrypted backup of the SQLite database.
// It uses VACUUM INTO for an atomic snapshot, then compresses with gzip and encrypts
// with all available issuer keys.
func CreateBackup(ctx context.Context) error {
	dbPath := param.Server_DbLocation.GetString()
	backupDir := param.Server_DatabaseBackup_Location.GetString()

	if dbPath == "" {
		return errors.New("database path is not configured")
	}
	if backupDir == "" {
		return errors.New("backup directory is not configured")
	}

	if ServerDatabase == nil {
		return errors.New("server database is not initialized")
	}

	// Get issuer keys for encryption
	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		return errors.New("no issuer keys available for backup encryption")
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return errors.Wrapf(err, "failed to create backup directory %s", backupDir)
	}

	// Create a temporary file path for the VACUUM INTO output
	tempPath := filepath.Join(backupDir, fmt.Sprintf("pelican-db-vacuum-%d.sqlite", time.Now().UnixNano()))
	defer os.Remove(tempPath)

	// Use VACUUM INTO for atomic backup
	sqlDB, err := ServerDatabase.DB()
	if err != nil {
		return errors.Wrap(err, "failed to get underlying SQL database")
	}

	vacuumSQL := fmt.Sprintf("VACUUM INTO '%s'", tempPath)
	if _, err := sqlDB.ExecContext(ctx, vacuumSQL); err != nil {
		return errors.Wrap(err, "failed to create database backup via VACUUM INTO")
	}

	// Read the vacuumed database file
	rawData, err := os.ReadFile(tempPath)
	if err != nil {
		return errors.Wrap(err, "failed to read vacuumed database file")
	}

	// Compress with gzip
	var compressed bytes.Buffer
	gzWriter, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return errors.Wrap(err, "failed to create gzip writer")
	}
	if _, err := gzWriter.Write(rawData); err != nil {
		return errors.Wrap(err, "failed to compress backup data")
	}
	if err := gzWriter.Close(); err != nil {
		return errors.Wrap(err, "failed to finalize gzip compression")
	}

	// Encrypt the compressed data
	encrypted, err := encryptBackup(compressed.Bytes(), allKeys)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt backup")
	}

	// Write the final backup file with base64 encoding
	timestamp := time.Now().UTC().Format("20060102-150405")
	backupFileName := fmt.Sprintf("%s%s%s", backupFilePrefix, timestamp, backupFileExt)
	backupPath := filepath.Join(backupDir, backupFileName)

	encoded := base64.StdEncoding.EncodeToString(encrypted)
	if err := os.WriteFile(backupPath, []byte(encoded), 0600); err != nil {
		return errors.Wrapf(err, "failed to write backup file %s", backupPath)
	}

	log.Infof("Database backup created: %s", backupPath)

	// Rotate old backups
	if err := rotateBackups(backupDir); err != nil {
		log.Warnf("Failed to rotate old backups: %v", err)
	}

	return nil
}

// rotateBackups removes old backup files that exceed the configured maximum count.
func rotateBackups(backupDir string) error {
	maxCount := param.Server_DatabaseBackup_MaxCount.GetInt()
	if maxCount <= 0 {
		return nil
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return errors.Wrapf(err, "failed to read backup directory %s", backupDir)
	}

	// Collect backup files
	var backupFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), backupFilePrefix) && strings.HasSuffix(entry.Name(), backupFileExt) {
			backupFiles = append(backupFiles, entry)
		}
	}

	if len(backupFiles) <= maxCount {
		return nil
	}

	// Sort by name (includes timestamp, so lexicographic = chronological)
	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].Name() < backupFiles[j].Name()
	})

	// Remove oldest backups
	toRemove := len(backupFiles) - maxCount
	for i := 0; i < toRemove; i++ {
		path := filepath.Join(backupDir, backupFiles[i].Name())
		if err := os.Remove(path); err != nil {
			log.Warnf("Failed to remove old backup %s: %v", path, err)
		} else {
			log.Infof("Removed old backup: %s", path)
		}
	}

	return nil
}

// RestoreFromBackup restores the database from the most recent backup file
// if the primary database file is missing but backups exist.
// Returns true if a restore was performed.
func RestoreFromBackup(dbPath string) (bool, error) {
	backupDir := param.Server_DatabaseBackup_Location.GetString()
	if backupDir == "" {
		return false, nil
	}

	// Check if the primary database already exists
	if _, err := os.Stat(dbPath); err == nil {
		return false, nil
	}

	// Check if backup directory exists
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.Wrapf(err, "failed to read backup directory %s", backupDir)
	}

	// Collect backup files
	var backupFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), backupFilePrefix) && strings.HasSuffix(entry.Name(), backupFileExt) {
			backupFiles = append(backupFiles, entry)
		}
	}

	if len(backupFiles) == 0 {
		return false, nil
	}

	// Sort descending to get the most recent backup first
	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].Name() > backupFiles[j].Name()
	})

	// Get issuer keys for decryption
	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		return false, errors.New("no issuer keys available for backup decryption")
	}

	// Try to restore from the most recent backup, falling back to older ones
	for _, backupEntry := range backupFiles {
		backupPath := filepath.Join(backupDir, backupEntry.Name())
		log.Infof("Attempting to restore database from backup: %s", backupPath)

		restored, err := restoreFromSingleBackup(dbPath, backupPath, allKeys)
		if err != nil {
			log.Warnf("Failed to restore from backup %s: %v", backupPath, err)
			continue
		}
		if restored {
			log.Infof("Database successfully restored from backup: %s", backupPath)
			return true, nil
		}
	}

	return false, errors.New("failed to restore database from any available backup")
}

// restoreFromSingleBackup attempts to restore the database from a single backup file.
func restoreFromSingleBackup(dbPath, backupPath string, issuerKeys map[string]jwk.Key) (bool, error) {
	encodedData, err := os.ReadFile(backupPath)
	if err != nil {
		return false, errors.Wrapf(err, "failed to read backup file %s", backupPath)
	}

	// Base64 decode
	encrypted, err := base64.StdEncoding.DecodeString(string(encodedData))
	if err != nil {
		return false, errors.Wrap(err, "failed to base64 decode backup data")
	}

	// Decrypt
	compressed, err := decryptBackup(encrypted, issuerKeys)
	if err != nil {
		return false, errors.Wrap(err, "failed to decrypt backup")
	}

	// Decompress
	gzReader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return false, errors.Wrap(err, "failed to create gzip reader")
	}
	defer gzReader.Close()

	rawData, err := io.ReadAll(gzReader)
	if err != nil {
		return false, errors.Wrap(err, "failed to decompress backup data")
	}

	// Ensure the directory for the database exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return false, errors.Wrap(err, "failed to create directory for restored database")
	}

	// Write the restored database
	if err := os.WriteFile(dbPath, rawData, 0600); err != nil {
		return false, errors.Wrap(err, "failed to write restored database")
	}

	return true, nil
}

// LaunchPeriodicBackup starts a background goroutine that periodically creates
// database backups. The goroutine is managed by the provided errgroup and
// cancellable via the context.
func LaunchPeriodicBackup(ctx context.Context, egrp *errgroup.Group) {
	frequency := param.Server_DatabaseBackup_Frequency.GetDuration()
	if frequency <= 0 {
		log.Info("Database backup is disabled (frequency is 0 or negative)")
		return
	}

	log.Infof("Starting periodic database backup every %s", frequency)

	egrp.Go(func() error {
		ticker := time.NewTicker(frequency)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Stopping periodic database backup")
				return nil
			case <-ticker.C:
				if err := CreateBackup(ctx); err != nil {
					log.Errorf("Failed to create database backup: %v", err)
				}
			}
		}
	})
}
