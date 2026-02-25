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
	"bufio"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/version"
)

const (
	backupFilePrefix = "pelican-db-backup-"
	backupFileExt    = ".bak"
	backupTempPrefix = "pelican-db-backup-"
	backupTempSuffix = ".tmp"
	vacuumTempPrefix = "pelican-db-vacuum-"

	// chunkSize is the maximum plaintext size per encrypted chunk.
	// NaCl secretbox docs recommend not encrypting large messages in a single
	// call; 16 KiB chunks are a safe choice.
	chunkSize = 16 * 1024

	// PEM block types used in the backup format.
	pemTypeMetadata = "BACKUP METADATA"
	pemTypeKey      = "ENCRYPTED BACKUP KEY"
	pemTypeData     = "ENCRYPTED BACKUP DATA"

	// backupTimestampFormat is the Go reference-time layout used in backup
	// filenames. It produces strings like "2026-01-02T150405".
	backupTimestampFormat = "2006-01-02T150405"

	// tempFileMaxAge is the maximum age of temporary files before they are
	// cleaned up by rotateBackups.
	tempFileMaxAge = 1 * time.Hour
)

// ErrDatabaseExists is returned by RestoreFromSpecificBackup when the
// target database file already exists and force is false.
var ErrDatabaseExists = errors.New("database already exists at restore target")

// ErrNoMatchingKey is returned when a backup cannot be decrypted because
// none of the currently-available issuer keys match the keys used to
// encrypt the backup. The RequiredKeyIDs field lists the key IDs that
// the backup was encrypted with.
type ErrNoMatchingKey struct {
	RequiredKeyIDs []string
}

func (e *ErrNoMatchingKey) Error() string {
	return fmt.Sprintf("failed to decrypt backup: no matching issuer key found; backup was encrypted with key(s): %s",
		strings.Join(e.RequiredKeyIDs, ", "))
}

// BackupMetadata contains human-readable information about a backup file.
// These fields are stored as PEM headers in the first block of the backup
// file and are visible even without decryption keys.
type BackupMetadata struct {
	// FormatVersion is the backup format version (currently "1").
	FormatVersion string `json:"format_version"`
	// Timestamp is the RFC3339 UTC time the backup was created.
	Timestamp string `json:"timestamp"`
	// Hostname is the hostname of the machine that created the backup.
	Hostname string `json:"hostname,omitempty"`
	// Username is the OS user that created the backup.
	Username string `json:"username,omitempty"`
	// PelicanVersion is the version of Pelican that created the backup.
	PelicanVersion string `json:"pelican_version"`
	// ServerURL is the external web URL of the server, if configured.
	ServerURL string `json:"server_url,omitempty"`
	// DatabasePath is the path to the database that was backed up.
	DatabasePath string `json:"database_path,omitempty"`
	// GOOS is the operating system (e.g., "linux", "darwin").
	GOOS string `json:"goos"`
	// GOARCH is the architecture (e.g., "amd64", "arm64").
	GOARCH string `json:"goarch"`
}

// collectBackupMetadata gathers metadata about the current system and
// database being backed up. The provided timestamp is used so that the
// metadata and backup filename are consistent.
func collectBackupMetadata(dbPath string, backupTime time.Time) BackupMetadata {
	meta := BackupMetadata{
		FormatVersion:  "1",
		Timestamp:      backupTime.Format(time.RFC3339),
		PelicanVersion: version.GetVersion(),
		DatabasePath:   dbPath,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
	}
	if h, err := os.Hostname(); err == nil {
		meta.Hostname = h
	}
	if u, err := user.Current(); err == nil {
		meta.Username = u.Username
	}
	if url := param.Server_ExternalWebUrl.GetString(); url != "" {
		meta.ServerURL = url
	}
	return meta
}

// writeBackupMetadata writes a plaintext BACKUP METADATA PEM block to w.
// All information is stored in PEM headers so it is human-readable with
// any text viewer.
func writeBackupMetadata(w io.Writer, meta BackupMetadata) error {
	headers := map[string]string{
		"Format-Version":  meta.FormatVersion,
		"Timestamp":       meta.Timestamp,
		"Pelican-Version": meta.PelicanVersion,
		"GOOS":            meta.GOOS,
		"GOARCH":          meta.GOARCH,
	}
	if meta.Hostname != "" {
		headers["Hostname"] = meta.Hostname
	}
	if meta.Username != "" {
		headers["Username"] = meta.Username
	}
	if meta.ServerURL != "" {
		headers["Server-URL"] = meta.ServerURL
	}
	if meta.DatabasePath != "" {
		headers["Database-Path"] = meta.DatabasePath
	}
	block := &pem.Block{
		Type:    pemTypeMetadata,
		Headers: headers,
		Bytes:   nil,
	}
	return pem.Encode(w, block)
}

// readBackupMetadata reads the BACKUP METADATA PEM block from a backup file.
// It returns the metadata and any error encountered. The file is rewound to
// the beginning on success or failure, provided r supports Seek.
func readBackupMetadata(r io.ReadSeeker) (*BackupMetadata, error) {
	decoder := newPEMStreamDecoder(r)
	block, err := decoder.next()
	if err != nil {
		if _, seekErr := r.Seek(0, io.SeekStart); seekErr != nil {
			return nil, errors.Wrap(seekErr, "failed to rewind file after metadata read error")
		}
		return nil, errors.Wrap(err, "failed to read first PEM block")
	}
	if _, seekErr := r.Seek(0, io.SeekStart); seekErr != nil {
		return nil, errors.Wrap(seekErr, "failed to rewind file after reading metadata")
	}
	if block.Type != pemTypeMetadata {
		// Older format without metadata block — not an error.
		return nil, nil
	}
	meta := &BackupMetadata{
		FormatVersion:  block.Headers["Format-Version"],
		Timestamp:      block.Headers["Timestamp"],
		Hostname:       block.Headers["Hostname"],
		Username:       block.Headers["Username"],
		PelicanVersion: block.Headers["Pelican-Version"],
		ServerURL:      block.Headers["Server-URL"],
		DatabasePath:   block.Headers["Database-Path"],
		GOOS:           block.Headers["GOOS"],
		GOARCH:         block.Headers["GOARCH"],
	}
	return meta, nil
}

// ReadBackupMetadata reads the metadata from a backup file at the given path.
// It returns nil (without error) for older backup files that lack a metadata
// block.
func ReadBackupMetadata(backupPath string) (*BackupMetadata, error) {
	f, err := os.Open(backupPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open backup file %s", backupPath)
	}
	defer f.Close()
	return readBackupMetadata(f)
}

// deriveBackupKeyPair derives a Curve25519 key pair from an issuer JWK using
// HKDF-SHA256.
func deriveBackupKeyPair(issuerKey jwk.Key) (privateKey, publicKey *[32]byte, err error) {
	var rawKey any
	if err := issuerKey.Raw(&rawKey); err != nil {
		return nil, nil, errors.Wrap(err, "failed to extract raw key from JWK")
	}

	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(rawKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal private key to PKCS8")
	}

	// Use HKDF-SHA256 to derive a 32-byte Curve25519 private key.
	// The info string binds the derived key to backup encryption usage.
	hkdfReader := hkdf.New(sha256.New, derPrivateKey, nil, []byte("pelican-backup-encryption"))

	privateKey = new([32]byte)
	if _, err := io.ReadFull(hkdfReader, privateKey[:]); err != nil {
		return nil, nil, errors.Wrap(err, "failed to derive key via HKDF")
	}

	publicKey = new([32]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)

	return privateKey, publicKey, nil
}

// encryptedChunkWriter implements io.WriteCloser. Data written to it is
// buffered into chunkSize pieces, each encrypted with NaCl secretbox and
// emitted as a PEM block of type pemTypeData.
//
// For each chunk, the nonce is the base nonce XOR'd with the 1-based chunk
// sequence number (big-endian in the first 8 bytes).
type encryptedChunkWriter struct {
	dest     io.Writer
	dek      [32]byte
	nonce    [24]byte
	chunkNum uint64
	buf      []byte
}

func newEncryptedChunkWriter(dest io.Writer, dek [32]byte, nonce [24]byte) *encryptedChunkWriter {
	return &encryptedChunkWriter{
		dest:  dest,
		dek:   dek,
		nonce: nonce,
	}
}

func (w *encryptedChunkWriter) Write(p []byte) (int, error) {
	total := len(p)
	w.buf = append(w.buf, p...)
	for len(w.buf) >= chunkSize {
		if err := w.flushChunk(w.buf[:chunkSize]); err != nil {
			return 0, err
		}
		w.buf = append([]byte(nil), w.buf[chunkSize:]...) // shrink underlying array
	}
	return total, nil
}

// Close flushes any remaining buffered data as a final chunk.
func (w *encryptedChunkWriter) Close() error {
	if len(w.buf) > 0 {
		return w.flushChunk(w.buf)
	}
	return nil
}

// flushChunk encrypts one chunk and writes a PEM block to the destination.
func (w *encryptedChunkWriter) flushChunk(data []byte) error {
	w.chunkNum++

	// Derive per-chunk nonce: base nonce XOR'd with the chunk number.
	var chunkNonce [24]byte
	copy(chunkNonce[:], w.nonce[:])
	var numBuf [8]byte
	binary.BigEndian.PutUint64(numBuf[:], w.chunkNum)
	for i := 0; i < 8; i++ {
		chunkNonce[i] ^= numBuf[i]
	}

	encrypted := secretbox.Seal(nil, data, &chunkNonce, &w.dek)

	block := &pem.Block{
		Type: pemTypeData,
		Headers: map[string]string{
			"Chunk": strconv.FormatUint(w.chunkNum, 10),
		},
		Bytes: encrypted,
	}
	return pem.Encode(w.dest, block)
}

// writeEncryptedKeys writes PEM blocks containing the DEK+nonce encrypted
// with each issuer key via NaCl box.
func writeEncryptedKeys(dest io.Writer, dekAndNonce []byte, issuerKeys map[string]jwk.Key) error {
	if len(issuerKeys) == 0 {
		return errors.New("no issuer keys available for encryption")
	}

	// Sort key IDs for deterministic output.
	keyIDs := make([]string, 0, len(issuerKeys))
	for keyID := range issuerKeys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)

	for _, keyID := range keyIDs {
		issuerKey := issuerKeys[keyID]

		privKey, pubKey, err := deriveBackupKeyPair(issuerKey)
		if err != nil {
			return errors.Wrapf(err, "failed to derive key pair for key %s", keyID)
		}

		// Encrypt DEK+nonce. The box nonce is prepended to the ciphertext.
		var keyNonce [24]byte
		if _, err := io.ReadFull(rand.Reader, keyNonce[:]); err != nil {
			return errors.Wrap(err, "failed to generate key nonce")
		}
		encryptedDEK := box.Seal(keyNonce[:], dekAndNonce, &keyNonce, pubKey, privKey)

		block := &pem.Block{
			Type: pemTypeKey,
			Headers: map[string]string{
				"Key-Id": keyID,
			},
			Bytes: encryptedDEK,
		}
		if err := pem.Encode(dest, block); err != nil {
			return errors.Wrapf(err, "failed to write PEM key block for %s", keyID)
		}
	}

	return nil
}

// createBackup creates a compressed and encrypted backup of the SQLite database.
// It uses VACUUM INTO for an atomic snapshot, then streams the data through
// gzip compression and chunked NaCl secretbox encryption, writing the result
// as a sequence of PEM blocks. The final file is written atomically via
// rename.
func createBackup(ctx context.Context) error {
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

	// Capture the timestamp once so that the metadata and filename are consistent.
	backupTime := time.Now().UTC()

	// Get issuer keys for encryption.
	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		return errors.New("no issuer keys available for backup encryption")
	}

	// Ensure backup directory exists.
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return errors.Wrapf(err, "failed to create backup directory %s", backupDir)
	}

	// Create a temporary file for the VACUUM INTO output.
	vacuumFile, err := os.CreateTemp(backupDir, vacuumTempPrefix+"*.sqlite")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary vacuum file")
	}
	vacuumPath := vacuumFile.Name()
	vacuumFile.Close()
	os.Remove(vacuumPath) // VACUUM INTO needs the file to not exist
	defer os.Remove(vacuumPath)

	// Use VACUUM INTO for an atomic database snapshot.
	sqlDB, err := ServerDatabase.DB()
	if err != nil {
		return errors.Wrap(err, "failed to get underlying SQL database")
	}

	// Escape any single quotes in the path to prevent SQL injection.
	escapedPath := strings.ReplaceAll(vacuumPath, "'", "''")
	if _, err := sqlDB.ExecContext(ctx, "VACUUM INTO '"+escapedPath+"'"); err != nil {
		return errors.Wrap(err, "failed to create database backup via VACUUM INTO")
	}

	// Open the vacuumed database for streaming.
	sourceFile, err := os.Open(vacuumPath)
	if err != nil {
		return errors.Wrap(err, "failed to open vacuumed database file")
	}
	defer sourceFile.Close()

	// Generate a random data encryption key (DEK) and base nonce.
	var dek [32]byte
	if _, err := io.ReadFull(rand.Reader, dek[:]); err != nil {
		return errors.Wrap(err, "failed to generate data encryption key")
	}
	var baseNonce [24]byte
	if _, err := io.ReadFull(rand.Reader, baseNonce[:]); err != nil {
		return errors.Wrap(err, "failed to generate base nonce")
	}

	// Create a temporary file for the backup output (atomic write via rename).
	tmpBackupFile, err := os.CreateTemp(backupDir, backupTempPrefix+"*.tmp")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary backup file")
	}
	tmpBackupPath := tmpBackupFile.Name()
	defer func() {
		tmpBackupFile.Close()
		os.Remove(tmpBackupPath) // clean up on failure; no-op after rename
	}()

	// Write the metadata PEM block first (human-readable, unencrypted).
	meta := collectBackupMetadata(dbPath, backupTime)
	if err := writeBackupMetadata(tmpBackupFile, meta); err != nil {
		return errors.Wrap(err, "failed to write backup metadata block")
	}

	// Write the encrypted key PEM blocks.
	dekAndNonce := make([]byte, 56) // 32-byte DEK + 24-byte nonce
	copy(dekAndNonce[:32], dek[:])
	copy(dekAndNonce[32:], baseNonce[:])
	if err := writeEncryptedKeys(tmpBackupFile, dekAndNonce, allKeys); err != nil {
		return errors.Wrap(err, "failed to write encrypted key blocks")
	}

	// Stream: source file → gzip → encrypted chunk writer → PEM → temp file
	chunkWriter := newEncryptedChunkWriter(tmpBackupFile, dek, baseNonce)
	gzWriter, err := gzip.NewWriterLevel(chunkWriter, gzip.BestCompression)
	if err != nil {
		return errors.Wrap(err, "failed to create gzip writer")
	}
	if _, err := io.Copy(gzWriter, sourceFile); err != nil {
		return errors.Wrap(err, "failed to compress and encrypt backup data")
	}
	if err := gzWriter.Close(); err != nil {
		return errors.Wrap(err, "failed to finalize gzip compression")
	}
	if err := chunkWriter.Close(); err != nil {
		return errors.Wrap(err, "failed to finalize encrypted chunk writer")
	}

	// Sync and close before rename.
	if err := tmpBackupFile.Sync(); err != nil {
		return errors.Wrap(err, "failed to sync temporary backup file")
	}
	if err := tmpBackupFile.Close(); err != nil {
		return errors.Wrap(err, "failed to close temporary backup file")
	}

	// Atomically move the temporary file to the final backup path.
	// Use the same backupTime captured at the start for the filename.
	timestamp := backupTime.Format(backupTimestampFormat)
	backupFileName := fmt.Sprintf("%s%s%s", backupFilePrefix, timestamp, backupFileExt)
	backupPath := filepath.Join(backupDir, backupFileName)

	if err := os.Rename(tmpBackupPath, backupPath); err != nil {
		return errors.Wrapf(err, "failed to rename temporary backup to %s", backupPath)
	}

	log.Infof("Database backup created: %s", backupPath)

	// Rotate old backups.
	if err := rotateBackups(backupDir); err != nil {
		log.Warnf("Failed to rotate old backups: %v", err)
	}

	return nil
}

// rotateBackups removes old backup files that exceed the configured maximum
// count. It also removes stale temporary files (from interrupted backups)
// that are older than tempFileMaxAge.
func rotateBackups(backupDir string) error {
	maxCount := param.Server_DatabaseBackup_MaxCount.GetInt()

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return errors.Wrapf(err, "failed to read backup directory %s", backupDir)
	}

	now := time.Now()

	// Clean up stale temporary files from interrupted backups.
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		isTemp := strings.HasSuffix(name, backupTempSuffix) ||
			strings.HasPrefix(name, vacuumTempPrefix)
		if !isTemp {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			log.Debugf("Failed to stat temp file %s: %v", name, err)
			continue
		}
		if now.Sub(info.ModTime()) > tempFileMaxAge {
			path := filepath.Join(backupDir, name)
			if err := os.Remove(path); err != nil {
				log.Warnf("Failed to remove stale temp file %s: %v", path, err)
			} else {
				log.Infof("Removed stale temporary file: %s", path)
			}
		}
	}

	if maxCount <= 0 {
		return nil
	}

	// Collect backup files.
	var backupFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), backupFilePrefix) && strings.HasSuffix(entry.Name(), backupFileExt) {
			backupFiles = append(backupFiles, entry)
		}
	}

	if len(backupFiles) <= maxCount {
		return nil
	}

	// Sort by name (includes timestamp, so lexicographic = chronological).
	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].Name() < backupFiles[j].Name()
	})

	// Remove oldest backups.
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

// pemStreamDecoder reads PEM blocks one at a time from a buffered reader,
// avoiding the need to load the entire backup file into memory.
type pemStreamDecoder struct {
	reader *bufio.Reader
}

func newPEMStreamDecoder(r io.Reader) *pemStreamDecoder {
	return &pemStreamDecoder{reader: bufio.NewReader(r)}
}

// next returns the next PEM block from the stream, or (nil, io.EOF) when done.
func (d *pemStreamDecoder) next() (*pem.Block, error) {
	// Accumulate lines belonging to one PEM block.
	var buf []byte
	inBlock := false

	for {
		line, err := d.reader.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := strings.TrimSpace(string(line))
			if strings.HasPrefix(trimmed, "-----BEGIN ") {
				inBlock = true
				buf = buf[:0]
			}
			if inBlock {
				buf = append(buf, line...)
			}
			if inBlock && strings.HasPrefix(trimmed, "-----END ") {
				block, _ := pem.Decode(buf)
				if block == nil {
					return nil, errors.New("failed to decode PEM block")
				}
				return block, nil
			}
		}
		if err != nil {
			if err == io.EOF {
				if inBlock {
					return nil, errors.New("unexpected EOF inside PEM block")
				}
				return nil, io.EOF
			}
			return nil, err
		}
	}
}

// restoreFromBackup restores the database from the most recent backup file
// if the primary database file is missing but backups exist.
// Returns true if a restore was performed.
func restoreFromBackup(dbPath string) (bool, error) {
	backupDir := param.Server_DatabaseBackup_Location.GetString()
	if backupDir == "" {
		return false, nil
	}

	// Check if the primary database already exists.
	if _, err := os.Stat(dbPath); err == nil {
		return false, nil
	}

	// Check if backup directory exists.
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.Wrapf(err, "failed to read backup directory %s", backupDir)
	}

	// Collect backup files.
	var backupFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), backupFilePrefix) && strings.HasSuffix(entry.Name(), backupFileExt) {
			backupFiles = append(backupFiles, entry)
		}
	}

	if len(backupFiles) == 0 {
		return false, nil
	}

	// Sort descending to get the most recent backup first.
	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].Name() > backupFiles[j].Name()
	})

	// Get issuer keys for decryption.
	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		return false, errors.New("no issuer keys available for backup decryption")
	}

	// Try to restore from the most recent backup, falling back to older ones.
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

// restoreFromSingleBackup attempts to restore the database from a single
// backup file. It streams PEM blocks from the file, decrypts chunks via
// temporary files, and atomically places the restored database at dbPath.
func restoreFromSingleBackup(dbPath, backupPath string, issuerKeys map[string]jwk.Key) (bool, error) {
	backupFile, err := os.Open(backupPath)
	if err != nil {
		return false, errors.Wrapf(err, "failed to open backup file %s", backupPath)
	}
	defer backupFile.Close()

	decoder := newPEMStreamDecoder(backupFile)

	// Phase 1: read ENCRYPTED BACKUP KEY blocks and attempt to decrypt DEK.
	var dek [32]byte
	var baseNonce [24]byte
	dekDecrypted := false

	// Zero out the DEK when we're done to reduce the window for memory-dump attacks.
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	// We need to save un-tried key blocks in case we find the matching key later.
	type keyBlockEntry struct {
		keyID string
		data  []byte
	}
	var keyBlocks []keyBlockEntry
	var firstDataBlock *pem.Block

	for {
		block, err := decoder.next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return false, errors.Wrap(err, "failed to read PEM block")
		}

		if block.Type == pemTypeKey {
			keyID := block.Headers["Key-Id"]
			keyBlocks = append(keyBlocks, keyBlockEntry{keyID: keyID, data: block.Bytes})
		} else if block.Type == pemTypeData {
			// We've moved past key blocks; save this first data block.
			firstDataBlock = block
			break
		}
	}

	// Try to decrypt the DEK with any matching issuer key.
	for _, kb := range keyBlocks {
		issuerKey, found := issuerKeys[kb.keyID]
		if !found {
			continue
		}

		privKey, pubKey, err := deriveBackupKeyPair(issuerKey)
		if err != nil {
			log.Debugf("Failed to derive key pair for key %s: %v", kb.keyID, err)
			continue
		}

		if len(kb.data) < 24 {
			continue
		}
		var keyNonce [24]byte
		copy(keyNonce[:], kb.data[:24])

		dekAndNonce, ok := box.Open(nil, kb.data[24:], &keyNonce, pubKey, privKey)
		if !ok {
			log.Debugf("Failed to decrypt DEK with key %s", kb.keyID)
			continue
		}

		if len(dekAndNonce) != 56 {
			continue
		}
		copy(dek[:], dekAndNonce[:32])
		copy(baseNonce[:], dekAndNonce[32:])
		dekDecrypted = true
		break
	}

	if !dekDecrypted {
		keyIDs := make([]string, len(keyBlocks))
		for i, kb := range keyBlocks {
			keyIDs[i] = kb.keyID
		}
		return false, &ErrNoMatchingKey{RequiredKeyIDs: keyIDs}
	}

	// Phase 2: decrypt data chunks into a temporary compressed file.
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return false, errors.Wrap(err, "failed to create directory for restored database")
	}

	compressedTmp, err := os.CreateTemp(dbDir, "pelican-restore-compressed-*.tmp")
	if err != nil {
		return false, errors.Wrap(err, "failed to create temp file for compressed data")
	}
	compressedTmpPath := compressedTmp.Name()
	defer os.Remove(compressedTmpPath)

	decryptChunk := func(block *pem.Block) error {
		chunkStr := block.Headers["Chunk"]
		chunkNum, err := strconv.ParseUint(chunkStr, 10, 64)
		if err != nil {
			return errors.Wrapf(err, "invalid chunk number %q", chunkStr)
		}

		var chunkNonce [24]byte
		copy(chunkNonce[:], baseNonce[:])
		var numBuf [8]byte
		binary.BigEndian.PutUint64(numBuf[:], chunkNum)
		for i := 0; i < 8; i++ {
			chunkNonce[i] ^= numBuf[i]
		}

		plaintext, ok := secretbox.Open(nil, block.Bytes, &chunkNonce, &dek)
		if !ok {
			return fmt.Errorf("failed to decrypt chunk %d", chunkNum)
		}

		_, err = compressedTmp.Write(plaintext)
		return err
	}

	// Decrypt the first data block we already read.
	if firstDataBlock != nil {
		if err := decryptChunk(firstDataBlock); err != nil {
			compressedTmp.Close()
			return false, errors.Wrap(err, "failed to decrypt first data chunk")
		}
	}

	// Continue reading and decrypting remaining data blocks.
	for {
		block, err := decoder.next()
		if err != nil {
			if err == io.EOF {
				break
			}
			compressedTmp.Close()
			return false, errors.Wrap(err, "failed to read PEM data block")
		}
		if block.Type != pemTypeData {
			continue
		}
		if err := decryptChunk(block); err != nil {
			compressedTmp.Close()
			return false, errors.Wrap(err, "failed to decrypt data chunk")
		}
	}

	if err := compressedTmp.Close(); err != nil {
		return false, errors.Wrap(err, "failed to close compressed temp file")
	}

	// Phase 3: decompress into a temporary database file, then rename atomically.
	compressedFile, err := os.Open(compressedTmpPath)
	if err != nil {
		return false, errors.Wrap(err, "failed to reopen compressed temp file")
	}
	defer compressedFile.Close()

	gzReader, err := gzip.NewReader(compressedFile)
	if err != nil {
		return false, errors.Wrap(err, "failed to create gzip reader")
	}
	defer gzReader.Close()

	restoredTmp, err := os.CreateTemp(dbDir, "pelican-restore-db-*.tmp")
	if err != nil {
		return false, errors.Wrap(err, "failed to create temp file for restored database")
	}
	restoredTmpPath := restoredTmp.Name()
	defer os.Remove(restoredTmpPath)

	if _, err := io.Copy(restoredTmp, gzReader); err != nil {
		restoredTmp.Close()
		return false, errors.Wrap(err, "failed to decompress backup data")
	}
	if err := restoredTmp.Sync(); err != nil {
		restoredTmp.Close()
		return false, errors.Wrap(err, "failed to sync restored database file")
	}
	if err := restoredTmp.Close(); err != nil {
		return false, errors.Wrap(err, "failed to close restored database file")
	}

	// Verify the restored file is a valid SQLite database before putting it in place.
	if err := verifySQLiteIntegrity(restoredTmpPath); err != nil {
		return false, errors.Wrap(err, "restored database failed integrity check")
	}

	// Set appropriate permissions before rename.
	if err := os.Chmod(restoredTmpPath, 0600); err != nil {
		return false, errors.Wrap(err, "failed to set permissions on restored database")
	}

	// Atomic rename.
	if err := os.Rename(restoredTmpPath, dbPath); err != nil {
		return false, errors.Wrap(err, "failed to rename restored database into place")
	}

	return true, nil
}

// verifySQLiteIntegrity opens the file at dbPath as a SQLite database and
// runs PRAGMA integrity_check to verify it is not corrupted. This prevents
// restoring a backup that was damaged during storage or decryption.
func verifySQLiteIntegrity(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return errors.Wrap(err, "failed to open database for integrity check")
	}
	defer db.Close()

	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return errors.Wrap(err, "integrity check query failed")
	}
	if result != "ok" {
		return fmt.Errorf("integrity check failed: %s", result)
	}
	return nil
}

// BackupInfo holds metadata about a backup file, suitable for display in
// CLI listings.
type BackupInfo struct {
	Name      string          `json:"name"`
	Path      string          `json:"path"`
	Size      int64           `json:"size"`
	Timestamp time.Time       `json:"timestamp"`
	Metadata  *BackupMetadata `json:"metadata,omitempty"`
}

// CreateBackup creates a compressed and encrypted backup of the database.
// This is the exported entry point for the CLI.
func CreateBackup(ctx context.Context) error {
	return createBackup(ctx)
}

// RestoreFromBackup restores the database from the most recent backup file
// if the primary database file is missing. This is the exported entry point
// used by InitServerDatabase.
func RestoreFromBackup(dbPath string) (bool, error) {
	return restoreFromBackup(dbPath)
}

// RestoreFromSpecificBackup restores the database from a specific backup file.
// If force is true, the existing database is backed up then overwritten.
// Returns an error if the database already exists and force is false.
func RestoreFromSpecificBackup(dbPath, backupPath string, force bool) error {
	if dbPath == "" {
		dbPath = param.Server_DbLocation.GetString()
	}
	if dbPath == "" {
		return errors.New("database path is not configured")
	}

	// Check if the database already exists.
	if _, err := os.Stat(dbPath); err == nil {
		if !force {
			return fmt.Errorf("%w: %s", ErrDatabaseExists, dbPath)
		}
		// Back up the existing database before overwriting.
		bakPath := dbPath + ".pre-restore." + time.Now().UTC().Format(backupTimestampFormat)
		log.Infof("Existing database backed up to %s", bakPath)
		if err := os.Rename(dbPath, bakPath); err != nil {
			return errors.Wrapf(err, "failed to move existing database to %s", bakPath)
		}
		// Also move WAL/SHM files if present.
		for _, ext := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(dbPath + ext); err == nil {
				_ = os.Rename(dbPath+ext, bakPath+ext)
			}
		}
	}

	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		return errors.New("no issuer keys available for backup decryption")
	}

	restored, err := restoreFromSingleBackup(dbPath, backupPath, allKeys)
	if err != nil {
		return errors.Wrapf(err, "failed to restore from backup %s", backupPath)
	}
	if !restored {
		return errors.New("restore did not complete successfully")
	}

	log.Infof("Database restored from %s to %s", backupPath, dbPath)
	return nil
}

// VerifyBackup checks that a backup file can be successfully decrypted
// and decompressed without writing any data. Returns nil on success.
func VerifyBackup(backupPath string) error {
	allKeys := config.GetIssuerPrivateKeys()
	if len(allKeys) == 0 {
		return errors.New("no issuer keys available for backup verification")
	}

	backupFile, err := os.Open(backupPath)
	if err != nil {
		return errors.Wrapf(err, "failed to open backup file %s", backupPath)
	}
	defer backupFile.Close()

	decoder := newPEMStreamDecoder(backupFile)

	// Read key blocks and try to decrypt the DEK.
	var dek [32]byte
	var baseNonce [24]byte
	dekDecrypted := false

	type keyBlockEntry struct {
		keyID string
		data  []byte
	}
	var keyBlocks []keyBlockEntry
	var firstDataBlock *pem.Block

	for {
		block, err := decoder.next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrap(err, "failed to read PEM block")
		}
		if block.Type == pemTypeKey {
			keyID := block.Headers["Key-Id"]
			keyBlocks = append(keyBlocks, keyBlockEntry{keyID: keyID, data: block.Bytes})
		} else if block.Type == pemTypeData {
			firstDataBlock = block
			break
		}
	}

	for _, kb := range keyBlocks {
		issuerKey, found := allKeys[kb.keyID]
		if !found {
			continue
		}
		privKey, pubKey, err := deriveBackupKeyPair(issuerKey)
		if err != nil {
			continue
		}
		if len(kb.data) < 24 {
			continue
		}
		var keyNonce [24]byte
		copy(keyNonce[:], kb.data[:24])
		dekAndNonce, ok := box.Open(nil, kb.data[24:], &keyNonce, pubKey, privKey)
		if !ok {
			continue
		}
		if len(dekAndNonce) != 56 {
			continue
		}
		copy(dek[:], dekAndNonce[:32])
		copy(baseNonce[:], dekAndNonce[32:])
		dekDecrypted = true
		break
	}

	if !dekDecrypted {
		keyIDs := make([]string, len(keyBlocks))
		for i, kb := range keyBlocks {
			keyIDs[i] = kb.keyID
		}
		return &ErrNoMatchingKey{RequiredKeyIDs: keyIDs}
	}

	// Verify all data chunks can be decrypted.
	verifyChunk := func(block *pem.Block) error {
		chunkStr := block.Headers["Chunk"]
		chunkNum, err := strconv.ParseUint(chunkStr, 10, 64)
		if err != nil {
			return errors.Wrapf(err, "invalid chunk number %q", chunkStr)
		}
		var chunkNonce [24]byte
		copy(chunkNonce[:], baseNonce[:])
		var numBuf [8]byte
		binary.BigEndian.PutUint64(numBuf[:], chunkNum)
		for i := 0; i < 8; i++ {
			chunkNonce[i] ^= numBuf[i]
		}
		_, ok := secretbox.Open(nil, block.Bytes, &chunkNonce, &dek)
		if !ok {
			return fmt.Errorf("failed to decrypt chunk %d", chunkNum)
		}
		return nil
	}

	if firstDataBlock != nil {
		if err := verifyChunk(firstDataBlock); err != nil {
			return err
		}
	}

	var chunkCount uint64
	if firstDataBlock != nil {
		chunkCount = 1
	}
	for {
		block, err := decoder.next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrap(err, "failed to read PEM data block")
		}
		if block.Type != pemTypeData {
			continue
		}
		if err := verifyChunk(block); err != nil {
			return err
		}
		chunkCount++
	}

	log.Infof("Backup verified: %d key(s), %d data chunk(s)", len(keyBlocks), chunkCount)
	return nil
}

// ListBackups returns metadata about all available backups in the configured
// backup directory, sorted newest-first.
func ListBackups() ([]BackupInfo, error) {
	backupDir := param.Server_DatabaseBackup_Location.GetString()
	if backupDir == "" {
		return nil, errors.New("backup directory is not configured (Server.DatabaseBackup.Location)")
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "failed to read backup directory %s", backupDir)
	}

	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), backupFilePrefix) || !strings.HasSuffix(entry.Name(), backupFileExt) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			log.Debugf("Failed to stat backup file %s: %v", entry.Name(), err)
			continue
		}

		// Parse timestamp from filename: pelican-db-backup-2026-01-02T150405.bak
		name := entry.Name()
		tsStr := strings.TrimPrefix(name, backupFilePrefix)
		tsStr = strings.TrimSuffix(tsStr, backupFileExt)
		ts, _ := time.Parse(backupTimestampFormat, tsStr)

		fullPath := filepath.Join(backupDir, name)
		bi := BackupInfo{
			Name:      name,
			Path:      fullPath,
			Size:      info.Size(),
			Timestamp: ts,
		}
		if meta, err := ReadBackupMetadata(fullPath); err == nil && meta != nil {
			bi.Metadata = meta
		}
		backups = append(backups, bi)
	}

	// Sort newest-first.
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Name > backups[j].Name
	})

	return backups, nil
}

// LaunchPeriodicBackup starts a background goroutine that periodically creates
// database backups. The goroutine is managed by the provided errgroup and
// cancellable via the context.
//
// On startup, the function checks for existing backups. If none exist, one is
// created immediately. Otherwise, the first backup is scheduled based on the
// age of the most recent backup so that the configured frequency is maintained
// across restarts.
func LaunchPeriodicBackup(ctx context.Context, egrp *errgroup.Group) {
	frequency := param.Server_DatabaseBackup_Frequency.GetDuration()
	if frequency <= 0 {
		log.Info("Database backup is disabled (frequency is 0 or negative)")
		return
	}

	// Determine initial delay based on the most recent backup.
	var initialDelay time.Duration
	backups, err := ListBackups()
	if err != nil {
		log.Warnf("Failed to list existing backups; creating one now: %v", err)
	}

	if len(backups) == 0 || err != nil {
		// No backups exist (or we couldn't list them) — run immediately.
		initialDelay = 0
		log.Info("No existing database backups found; creating one now")
	} else {
		lastBackup := backups[0].Timestamp
		if lastBackup.IsZero() {
			// Could not parse timestamp from filename; create one now.
			initialDelay = 0
		} else {
			age := time.Since(lastBackup)
			if age >= frequency {
				initialDelay = 0
			} else {
				initialDelay = frequency - age
			}
		}
		if initialDelay == 0 {
			log.Info("Most recent backup is older than the configured frequency; creating one now")
		} else {
			log.Infof("Most recent backup is %s old; next backup in %s",
				time.Since(backups[0].Timestamp).Truncate(time.Second),
				initialDelay.Truncate(time.Second))
		}
	}

	log.Infof("Starting periodic database backup every %s", frequency)

	egrp.Go(func() error {
		// Handle the initial backup or delay.
		if initialDelay == 0 {
			if err := createBackup(ctx); err != nil {
				log.Errorf("Failed to create initial database backup: %v", err)
			}
		} else {
			timer := time.NewTimer(initialDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				log.Info("Stopping periodic database backup")
				return nil
			case <-timer.C:
				if err := createBackup(ctx); err != nil {
					log.Errorf("Failed to create database backup: %v", err)
				}
			}
		}

		// Now tick at the regular frequency.
		ticker := time.NewTicker(frequency)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Stopping periodic database backup")
				return nil
			case <-ticker.C:
				if err := createBackup(ctx); err != nil {
					log.Errorf("Failed to create database backup: %v", err)
				}
			}
		}
	})
}
