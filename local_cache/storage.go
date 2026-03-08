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

package local_cache

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// createFile creates a file at the given path. If the parent directory
// does not exist, it creates the directory (with 0750 permissions) and
// retries the file creation. This avoids the overhead of a-priori
// directory existence checks.
func createFile(name string) (*os.File, error) {
	fp, err := os.Create(name)
	if err == nil {
		return fp, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(name), 0750); mkdirErr != nil {
		return nil, mkdirErr
	}
	return os.Create(name)
}

const (
	objectsSubDir = "objects"
	uuidFileName  = ".pelican-cache-id"
)

// StorageManager handles hybrid storage of cached objects
// Small objects (< InlineThreshold) are stored inline in BadgerDB
// Large objects are stored as encrypted files on disk with block tracking.
// Multiple storage directories can be configured; each directory is identified
// by a storageID (starting at StorageIDFirstDisk).
type StorageManager struct {
	db *CacheDB

	// dirs maps storageID → objects directory (e.g. "/data1/objects").
	// StorageIDFirstDisk is always present; additional dirs have
	// sequential IDs.
	dirs map[uint8]string

	// inlineMaxBytes is the maximum size of objects stored inline in
	// BadgerDB.  Objects at or below this threshold are stored inline;
	// larger objects go to disk.  Defaults to InlineThreshold (4096).
	inlineMaxBytes int

	// Shared per-object block availability state.  All RangeReaders for the
	// same instanceHash share one *ObjectBlockState so that block additions and
	// removals are immediately visible across goroutines.
	blockStates   map[string]*ObjectBlockState
	blockStatesMu sync.Mutex
}

// StorageDirInfo describes a configured storage directory at runtime.
type StorageDirInfo struct {
	StorageID  uint8
	ObjectsDir string
}

// readDirUUID reads the UUID file from a directory root.  Returns the
// UUID string and true if the file exists and is valid, or ("", false)
// if missing / unreadable.
func readDirUUID(dir string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(dir, uuidFileName))
	if err != nil {
		return "", false
	}
	id := string(data)
	// Basic validation: must parse as a UUID.
	if _, err := uuid.Parse(id); err != nil {
		return "", false
	}
	return id, true
}

// writeDirUUID writes a UUID file into a directory root.
func writeDirUUID(dir, id string) error {
	return os.WriteFile(filepath.Join(dir, uuidFileName), []byte(id), 0600)
}

// NewStorageManager creates a new storage manager with UUID-based directory
// identity.  It performs the following steps:
//
//  1. Load existing storageID → (UUID, path) mappings from the database.
//  2. Scan the supplied directory paths for UUID files.
//  3. Match discovered UUIDs against known mappings, updating paths as needed
//     (so that sysadmins can remount directories at different locations).
//  4. Assign new storage IDs to directories that have no UUID yet and drop
//     a new UUID file in each.
//  5. Persist updated mappings to the database.
//
// dirs is the ordered set of configured directory paths.  inlineMax sets the
// maximum inline object size (0 = use default InlineThreshold).
func NewStorageManager(db *CacheDB, dirs []string, inlineMax int) (*StorageManager, error) {
	if len(dirs) == 0 {
		return nil, errors.New("at least one storage directory must be configured")
	}
	if len(dirs) > 255 {
		return nil, errors.New("at most 255 storage directories are supported")
	}

	// Step 1: load persisted mappings keyed by UUID.
	persisted, err := db.LoadDiskMappings()
	if err != nil {
		log.Warnf("Failed to load disk mappings (will reassign): %v", err)
	}
	byUUID := make(map[string]DiskMapping, len(persisted))
	usedIDs := make(map[uint8]bool, len(persisted))
	for _, dm := range persisted {
		byUUID[dm.UUID] = dm
		usedIDs[dm.ID] = true
	}

	// Step 2–3: scan directories, match UUIDs, build result map.
	objDirs := make(map[uint8]string, len(dirs))

	// discoveredUUIDs maps discovered UUID → dir path, for all dirs that
	// already have a UUID file.
	discoveredUUIDs := make(map[string]string, len(dirs))
	// newDirs holds paths that don't have a UUID yet.
	var newDirs []string

	for _, dir := range dirs {
		id, ok := readDirUUID(dir)
		if ok {
			discoveredUUIDs[id] = dir
		} else {
			newDirs = append(newDirs, dir)
		}
	}

	// Re-associate known UUIDs (possibly with updated paths).
	for uid, dir := range discoveredUUIDs {
		dm, known := byUUID[uid]
		if known {
			// Existing directory — update path if it moved.
			if dm.Directory != dir {
				log.Infof("Storage dir %d (UUID %s) moved: %s → %s", dm.ID, uid, dm.Directory, dir)
				dm.Directory = dir
			}
			objDirs[dm.ID] = filepath.Join(dir, objectsSubDir)
			if err := db.SaveDiskMapping(dm); err != nil {
				return nil, errors.Wrapf(err, "failed to update disk mapping for UUID %s", uid)
			}
		} else {
			// UUID file exists but no DB record — treat as new.
			newDirs = append(newDirs, dir)
		}
	}

	// Step 4: assign new IDs to new directories.
	// Sort for deterministic ordering.
	sort.Strings(newDirs)
	nextID := uint8(StorageIDFirstDisk)
	for _, dir := range newDirs {
		// Find next unused ID.
		for usedIDs[nextID] {
			nextID++
			if nextID == 0 {
				// All 255 IDs are taken.  Recycle the unmounted
				// storageID with the smallest usage — purge its
				// contents from the database and reuse the ID.
				recycledID, err := db.FindRecyclableStorageID(objDirs)
				if err != nil {
					return nil, errors.Wrap(err, "exhausted storage IDs and no recyclable IDs available")
				}
				if err := db.PurgeStorageID(recycledID); err != nil {
					return nil, errors.Wrapf(err, "failed to purge recycled storage ID %d", recycledID)
				}
				nextID = recycledID
				break
			}
		}

		newUUID := uuid.New().String()
		if err := writeDirUUID(dir, newUUID); err != nil {
			return nil, errors.Wrapf(err, "failed to write UUID file in %s", dir)
		}

		dm := DiskMapping{ID: nextID, UUID: newUUID, Directory: dir}
		if err := db.SaveDiskMapping(dm); err != nil {
			return nil, errors.Wrapf(err, "failed to save disk mapping for %s", dir)
		}

		objDirs[nextID] = filepath.Join(dir, objectsSubDir)
		usedIDs[nextID] = true
		log.Infof("Assigned storage ID %d (UUID %s) to %s", nextID, newUUID, dir)
		nextID++
	}

	if len(objDirs) == 0 {
		return nil, errors.New("no storage directories after UUID resolution")
	}

	if inlineMax <= 0 {
		inlineMax = InlineThreshold
	}

	return &StorageManager{
		db:             db,
		dirs:           objDirs,
		inlineMaxBytes: inlineMax,
		blockStates:    make(map[string]*ObjectBlockState),
	}, nil
}

// GetDirs returns the configured storage directories (storageID → objects dir).
func (sm *StorageManager) GetDirs() map[uint8]string {
	return sm.dirs
}

// InlineMaxBytes returns the configured maximum inline object size.
func (sm *StorageManager) InlineMaxBytes() int {
	return sm.inlineMaxBytes
}

// getObjectPathForDir returns the full path for an object in a specific directory.
func (sm *StorageManager) getObjectPathForDir(storageID uint8, instanceHash string) string {
	dir, ok := sm.dirs[storageID]
	if !ok {
		// Fallback to first dir (should not happen in practice)
		for _, d := range sm.dirs {
			dir = d
			break
		}
	}
	return filepath.Join(dir, GetInstanceStoragePath(instanceHash))
}

// getObjectPath returns the full filesystem path for an object.
// For objects already stored, use getObjectPathForDir with their StorageID.
// This legacy helper uses StorageIDFirstDisk for backward compatibility.
func (sm *StorageManager) getObjectPath(instanceHash string) string {
	return sm.getObjectPathForDir(StorageIDFirstDisk, instanceHash)
}

// StoreInline stores small data inline in BadgerDB
func (sm *StorageManager) StoreInline(ctx context.Context, instanceHash string, meta *CacheMetadata, data []byte) error {
	if len(data) > sm.inlineMaxBytes {
		return errors.Errorf("data too large for inline storage: %d > %d", len(data), sm.inlineMaxBytes)
	}

	encMgr := sm.db.GetEncryptionManager()

	// Generate encryption keys if not already set
	if meta.DataKey == nil {
		dek, err := encMgr.GenerateDataKey()
		if err != nil {
			return errors.Wrap(err, "failed to generate data key")
		}
		encryptedDEK, err := encMgr.EncryptDataKey(dek)
		if err != nil {
			return errors.Wrap(err, "failed to encrypt data key")
		}
		meta.DataKey = encryptedDEK
	}

	if meta.Nonce == nil {
		nonce, err := encMgr.GenerateNonce()
		if err != nil {
			return errors.Wrap(err, "failed to generate nonce")
		}
		meta.Nonce = nonce
	}

	// Decrypt the DEK to use for encryption
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt data key")
	}

	// Encrypt the data
	encryptedData, err := encMgr.EncryptInline(data, dek, meta.Nonce)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt inline data")
	}

	// Store metadata
	meta.StorageID = StorageIDInline
	meta.ContentLength = int64(len(data))
	meta.Completed = time.Now()

	if err := sm.db.SetMetadata(instanceHash, meta); err != nil {
		return errors.Wrap(err, "failed to store metadata")
	}

	// Store encrypted data
	if err := sm.db.SetInlineData(instanceHash, encryptedData); err != nil {
		return errors.Wrap(err, "failed to store inline data")
	}

	return nil
}

// ReadInline reads small data from inline storage
func (sm *StorageManager) ReadInline(instanceHash string) ([]byte, error) {
	// Get metadata
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}
	if !meta.IsInline() {
		return nil, errors.New("object is not stored inline")
	}

	// Get encrypted data
	encryptedData, err := sm.db.GetInlineData(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get inline data")
	}
	if encryptedData == nil {
		return nil, errors.New("inline data not found")
	}

	// Decrypt the DEK
	encMgr := sm.db.GetEncryptionManager()
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data key")
	}

	// Decrypt the data
	return encMgr.DecryptInline(encryptedData, dek, meta.Nonce)
}

// InitDiskStorage initializes disk storage for a large object in the specified
// storage directory.  Returns the metadata with encryption keys set up.
func (sm *StorageManager) InitDiskStorage(ctx context.Context, instanceHash string, contentLength int64, storageID uint8) (*CacheMetadata, error) {
	encMgr := sm.db.GetEncryptionManager()

	// Generate encryption keys
	dek, err := encMgr.GenerateDataKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate data key")
	}

	encryptedDEK, err := encMgr.EncryptDataKey(dek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt data key")
	}

	nonce, err := encMgr.GenerateNonce()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	meta := &CacheMetadata{
		StorageID:     storageID,
		ContentLength: contentLength,
		DataKey:       encryptedDEK,
		Nonce:         nonce,
	}

	// Create the file; createFile lazily creates the parent directory
	objectPath := sm.getObjectPathForDir(storageID, instanceHash)
	file, err := createFile(objectPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create object file")
	}

	// Pre-allocate the file to the expected size (blocks * BlockTotalSize)
	totalBlocks := CalculateBlockCount(contentLength)
	fileSize := int64(totalBlocks) * BlockTotalSize
	if err := file.Truncate(fileSize); err != nil {
		file.Close()
		os.Remove(objectPath)
		return nil, errors.Wrap(err, "failed to pre-allocate file")
	}

	// Store metadata
	if err := sm.db.SetMetadata(instanceHash, meta); err != nil {
		file.Close()
		os.Remove(objectPath)
		return nil, errors.Wrap(err, "failed to store metadata")
	}

	// Initialize block state as empty bitmap
	if err := sm.db.SetBlockState(instanceHash, roaring.New()); err != nil {
		file.Close()
		os.Remove(objectPath)
		if delErr := sm.db.DeleteMetadata(instanceHash); delErr != nil {
			log.Warnf("Failed to clean up metadata for %s: %v", instanceHash, delErr)
		}
		return nil, errors.Wrap(err, "failed to initialize block state")
	}

	file.Close()

	return meta, nil
}

// WriteBlocks writes encrypted blocks to disk storage
// This is the main write path for large objects
func (sm *StorageManager) WriteBlocks(instanceHash string, startOffset int64, data []byte) error {
	// Get metadata
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return errors.New("object not found")
	}
	if !meta.IsDisk() {
		return errors.New("object is not stored on disk")
	}

	// Decrypt the DEK
	encMgr := sm.db.GetEncryptionManager()
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt data key")
	}

	// Create block encryptor
	encryptor, err := NewBlockEncryptor(dek, meta.Nonce)
	if err != nil {
		return errors.Wrap(err, "failed to create block encryptor")
	}

	// Open file for writing
	objectPath := sm.getObjectPathForDir(meta.StorageID, instanceHash)
	file, err := os.OpenFile(objectPath, os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "failed to open object file")
	}
	defer file.Close()

	// Calculate starting block
	startBlock := ContentOffsetToBlock(startOffset)
	offsetWithinBlock := ContentOffsetWithinBlock(startOffset)

	// If starting in the middle of a block, we need to read-modify-write
	if offsetWithinBlock != 0 {
		return errors.New("writing to middle of block not supported; use block-aligned writes")
	}

	// Write blocks
	blocksWritten := uint32(0)
	dataOffset := 0
	currentBlock := startBlock

	for dataOffset < len(data) {
		// Calculate how much data for this block
		remaining := len(data) - dataOffset
		blockData := BlockDataSize
		if remaining < blockData {
			blockData = remaining
		}

		// Extract block data
		block := data[dataOffset : dataOffset+blockData]

		// Encrypt the block
		encryptedBlock, err := encryptor.EncryptBlock(currentBlock, block)
		if err != nil {
			return errors.Wrapf(err, "failed to encrypt block %d", currentBlock)
		}

		// Write to file
		fileOffset := BlockOffset(currentBlock)
		if _, err := file.WriteAt(encryptedBlock, fileOffset); err != nil {
			return errors.Wrapf(err, "failed to write block %d", currentBlock)
		}

		dataOffset += blockData
		currentBlock++
		blocksWritten++
	}

	// Update block state
	if err := sm.db.MarkBlocksDownloaded(instanceHash, startBlock, startBlock+blocksWritten-1); err != nil {
		return errors.Wrap(err, "failed to update block state")
	}

	// Check if download is complete
	totalBlocks := CalculateBlockCount(meta.ContentLength)
	downloadedCount, err := sm.db.GetDownloadedBlockCount(instanceHash)
	if err != nil {
		log.Warnf("Failed to check download completion: %v", err)
	} else if uint32(downloadedCount) == totalBlocks {
		// Mark as completed
		meta.Completed = time.Now()
		if err := sm.db.SetMetadata(instanceHash, meta); err != nil {
			log.Warnf("Failed to update completion time: %v", err)
		}
	}

	return nil
}

// ReadBlocks reads and decrypts blocks from disk storage.
// It uses the shared ObjectBlockState to check block availability.
func (sm *StorageManager) ReadBlocks(instanceHash string, startOffset int64, length int) ([]byte, error) {
	// Get metadata
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}
	if !meta.IsDisk() {
		return nil, errors.New("object is not stored on disk")
	}

	// Decrypt the DEK
	encMgr := sm.db.GetEncryptionManager()
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data key")
	}

	// Create block encryptor
	encryptor, err := NewBlockEncryptor(dek, meta.Nonce)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create block encryptor")
	}

	// Use the shared block state to verify blocks are downloaded
	blockState, err := sm.GetSharedBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	// Calculate block range
	startBlock := ContentOffsetToBlock(startOffset)
	endOffset := startOffset + int64(length)
	if endOffset > meta.ContentLength {
		endOffset = meta.ContentLength
	}
	endBlock := ContentOffsetToBlock(endOffset - 1)

	// Check all needed blocks are downloaded
	for block := startBlock; block <= endBlock; block++ {
		if !blockState.Contains(block) {
			return nil, errors.Errorf("block %d not yet downloaded", block)
		}
	}

	// Open file for reading
	objectPath := sm.getObjectPathForDir(meta.StorageID, instanceHash)
	file, err := os.Open(objectPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open object file")
	}
	defer file.Close()

	// Read and decrypt blocks
	result := make([]byte, 0, length)
	offsetWithinFirstBlock := ContentOffsetWithinBlock(startOffset)

	for block := startBlock; block <= endBlock; block++ {
		// Read encrypted block
		encryptedBlock := make([]byte, BlockTotalSize)
		fileOffset := BlockOffset(block)
		n, err := file.ReadAt(encryptedBlock, fileOffset)
		if err != nil && err != io.EOF {
			return nil, errors.Wrapf(err, "failed to read block %d", block)
		}

		// Handle last block which may be smaller
		if block == CalculateBlockCount(meta.ContentLength)-1 {
			lastBlockDataSize := int(meta.ContentLength % BlockDataSize)
			if lastBlockDataSize == 0 {
				lastBlockDataSize = BlockDataSize
			}
			encryptedBlock = encryptedBlock[:lastBlockDataSize+AuthTagSize]
		} else if n < BlockTotalSize {
			return nil, errors.Errorf("short read on block %d: got %d, expected %d", block, n, BlockTotalSize)
		}

		// Decrypt the block
		decryptedBlock, err := encryptor.DecryptBlock(block, encryptedBlock)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decrypt block %d", block)
		}

		// Handle partial first block
		if block == startBlock && offsetWithinFirstBlock > 0 {
			decryptedBlock = decryptedBlock[offsetWithinFirstBlock:]
		}

		// Handle partial last block
		if block == endBlock {
			remaining := int64(length) - int64(len(result))
			if int64(len(decryptedBlock)) > remaining {
				decryptedBlock = decryptedBlock[:remaining]
			}
		}

		result = append(result, decryptedBlock...)
	}

	return result, nil
}

// IdentifyCorruptBlocks probes each block in [startBlock, endBlock] on disk and
// returns the block numbers whose AES-GCM authentication tag fails or whose
// on-disk data is too short.  Blocks that are not in the downloaded bitmap are
// skipped.  A missing or unopenable file returns all requested blocks.
func (sm *StorageManager) IdentifyCorruptBlocks(instanceHash string, startBlock, endBlock uint32) ([]uint32, error) {
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}
	if !meta.IsDisk() {
		return nil, nil
	}

	encMgr := sm.db.GetEncryptionManager()
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data key")
	}
	encryptor, err := NewBlockEncryptor(dek, meta.Nonce)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create block encryptor")
	}

	blockState, err := sm.GetSharedBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	objectPath := sm.getObjectPathForDir(meta.StorageID, instanceHash)
	file, err := os.Open(objectPath)
	if err != nil {
		// File missing entirely — all requested blocks are corrupt
		var corrupt []uint32
		for b := startBlock; b <= endBlock; b++ {
			if blockState.Contains(b) {
				corrupt = append(corrupt, b)
			}
		}
		return corrupt, nil
	}
	defer file.Close()

	totalBlocks := CalculateBlockCount(meta.ContentLength)
	var corrupt []uint32

	for block := startBlock; block <= endBlock; block++ {
		if !blockState.Contains(block) {
			continue
		}

		readSize := BlockTotalSize
		if block == totalBlocks-1 {
			lastBlockDataSize := int(meta.ContentLength % BlockDataSize)
			if lastBlockDataSize == 0 {
				lastBlockDataSize = BlockDataSize
			}
			readSize = lastBlockDataSize + AuthTagSize
		}

		buf := make([]byte, readSize)
		n, readErr := file.ReadAt(buf, BlockOffset(block))
		if readErr != nil && readErr != io.EOF {
			corrupt = append(corrupt, block)
			continue
		}
		if n < readSize {
			corrupt = append(corrupt, block)
			continue
		}

		if _, decErr := encryptor.DecryptBlock(block, buf[:readSize]); decErr != nil {
			corrupt = append(corrupt, block)
		}
	}

	return corrupt, nil
}

// GetMissingBlocks returns the ranges of blocks that haven't been downloaded yet
func (sm *StorageManager) GetMissingBlocks(instanceHash string) ([]BlockRange, error) {
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}

	bitmap, err := sm.db.GetBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	totalBlocks := CalculateBlockCount(meta.ContentLength)
	var missing []BlockRange

	inRange := false
	var rangeStart uint32

	for block := uint32(0); block < totalBlocks; block++ {
		if !bitmap.Contains(block) {
			if !inRange {
				inRange = true
				rangeStart = block
			}
		} else {
			if inRange {
				missing = append(missing, BlockRange{Start: rangeStart, End: block - 1})
				inRange = false
			}
		}
	}

	if inRange {
		missing = append(missing, BlockRange{Start: rangeStart, End: totalBlocks - 1})
	}

	return missing, nil
}

// BlockRange represents a contiguous range of blocks
type BlockRange struct {
	Start uint32
	End   uint32
}

// IsComplete checks if all blocks have been downloaded
func (sm *StorageManager) IsComplete(instanceHash string) (bool, error) {
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return false, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return false, nil
	}

	if meta.IsInline() {
		return true, nil // Inline data is always complete
	}

	totalBlocks := CalculateBlockCount(meta.ContentLength)
	downloadedCount, err := sm.db.GetDownloadedBlockCount(instanceHash)
	if err != nil {
		return false, errors.Wrap(err, "failed to get download count")
	}

	return uint32(downloadedCount) == totalBlocks, nil
}

// Delete removes an object from storage
func (sm *StorageManager) Delete(instanceHash string) error {
	// Get metadata to determine storage mode
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return errors.Wrap(err, "failed to get metadata")
	}

	// Delete from database (handles inline data, block state, LRU)
	if err := sm.db.DeleteObject(instanceHash); err != nil {
		return errors.Wrap(err, "failed to delete database entries")
	}

	// If stored on disk, delete the file
	if meta != nil && meta.IsDisk() {
		objectPath := sm.getObjectPathForDir(meta.StorageID, instanceHash)
		if err := os.Remove(objectPath); err != nil && !os.IsNotExist(err) {
			log.Warnf("Failed to delete object file %s: %v", objectPath, err)
		}
	}

	return nil
}

// EvictByLRU walks the LRU index for a given storage+namespace and evicts
// the oldest objects until either maxObjects have been removed or maxBytes
// of content has been freed — whichever comes first.  A value of 0 for
// either limit means "no limit on that dimension".  The method is allowed
// to go one object over the byte threshold to prevent starvation.
//
// All DB mutations happen atomically; filesystem deletes follow afterward.
// Returns the evicted objects, total bytes freed, and any error.
func (sm *StorageManager) EvictByLRU(storageID uint8, namespaceID uint32, maxObjects int, maxBytes int64) ([]evictedObject, uint64, error) {
	evicted, err := sm.db.EvictByLRU(storageID, namespaceID, maxObjects, maxBytes)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to evict objects by LRU")
	}

	var totalFreed uint64
	for _, obj := range evicted {
		totalFreed += uint64(obj.contentLen)

		if obj.storageID != StorageIDInline {
			objectPath := sm.getObjectPathForDir(obj.storageID, obj.instanceHash)
			if err := os.Remove(objectPath); err != nil && !os.IsNotExist(err) {
				log.Warnf("Failed to delete evicted object file %s: %v", objectPath, err)
			}
		}
	}

	return evicted, totalFreed, nil
}

// GetObjectSize returns the content length of a cached object
func (sm *StorageManager) GetObjectSize(instanceHash string) (int64, error) {
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return 0, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return 0, errors.New("object not found")
	}
	return meta.ContentLength, nil
}

// NOTE: ListObjects was removed - use db.ScanMetadata or db.ScanMetadataFrom directly
// to iterate over objects without loading all into memory.

// GetMetadata retrieves metadata for an object
func (sm *StorageManager) GetMetadata(instanceHash string) (*CacheMetadata, error) {
	return sm.db.GetMetadata(instanceHash)
}

// SetMetadata stores metadata for an object
func (sm *StorageManager) SetMetadata(instanceHash string, meta *CacheMetadata) error {
	return sm.db.SetMetadata(instanceHash, meta)
}

// HasObject checks if an object exists in storage
func (sm *StorageManager) HasObject(instanceHash string) (bool, error) {
	return sm.db.HasMetadata(instanceHash)
}

// ObjectReader provides a reader interface for cached objects
type ObjectReader struct {
	sm           *StorageManager
	instanceHash string
	meta         *CacheMetadata
	position     int64
	length       int64
	encryptor    *BlockEncryptor
	file         *os.File
	bitmap       *roaring.Bitmap
	inlineData   []byte
}

// NewObjectReader creates a reader for a cached object
func (sm *StorageManager) NewObjectReader(instanceHash string) (*ObjectReader, error) {
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}

	reader := &ObjectReader{
		sm:           sm,
		instanceHash: instanceHash,
		meta:         meta,
		position:     0,
		length:       meta.ContentLength,
	}

	if meta.IsInline() {
		// Read all inline data upfront
		data, err := sm.ReadInline(instanceHash)
		if err != nil {
			return nil, err
		}
		reader.inlineData = data
	} else {
		// Set up for disk-based reading
		encMgr := sm.db.GetEncryptionManager()
		dek, err := encMgr.DecryptDataKey(meta.DataKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt data key")
		}

		reader.encryptor, err = NewBlockEncryptor(dek, meta.Nonce)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create block encryptor")
		}

		reader.bitmap, err = sm.db.GetBlockState(instanceHash)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get block state")
		}

		reader.file, err = os.Open(sm.getObjectPathForDir(meta.StorageID, instanceHash))
		if err != nil {
			return nil, errors.Wrap(err, "failed to open object file")
		}
	}

	return reader, nil
}

// Read implements io.Reader
func (r *ObjectReader) Read(p []byte) (n int, err error) {
	if r.position >= r.length {
		return 0, io.EOF
	}

	toRead := len(p)
	if int64(toRead) > r.length-r.position {
		toRead = int(r.length - r.position)
	}

	if r.meta.IsInline() {
		n = copy(p[:toRead], r.inlineData[r.position:])
		r.position += int64(n)
		if r.position >= r.length {
			return n, io.EOF
		}
		return n, nil
	}

	// Disk-based reading
	data, err := r.sm.ReadBlocks(r.instanceHash, r.position, toRead)
	if err != nil {
		return 0, err
	}

	n = copy(p, data)
	r.position += int64(n)

	if r.position >= r.length {
		return n, io.EOF
	}

	return n, nil
}

// Seek implements io.Seeker
func (r *ObjectReader) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = r.position + offset
	case io.SeekEnd:
		newPos = r.length + offset
	default:
		return 0, errors.New("invalid whence")
	}

	if newPos < 0 {
		return 0, errors.New("negative position")
	}
	if newPos > r.length {
		newPos = r.length
	}

	r.position = newPos
	return newPos, nil
}

// Close closes the reader
func (r *ObjectReader) Close() error {
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// ReadAt implements io.ReaderAt
func (r *ObjectReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= r.length {
		return 0, io.EOF
	}

	toRead := len(p)
	if int64(toRead) > r.length-off {
		toRead = int(r.length - off)
	}

	if r.meta.IsInline() {
		n = copy(p[:toRead], r.inlineData[off:])
		if off+int64(n) >= r.length {
			return n, io.EOF
		}
		return n, nil
	}

	data, err := r.sm.ReadBlocks(r.instanceHash, off, toRead)
	if err != nil {
		return 0, err
	}

	n = copy(p, data)
	if off+int64(n) >= r.length {
		return n, io.EOF
	}

	return n, nil
}

// Size returns the total size of the object
func (r *ObjectReader) Size() int64 {
	return r.length
}

// ContentType returns the content type of the object
func (r *ObjectReader) ContentType() string {
	return r.meta.ContentType
}

// LastModified returns the last modified time
func (r *ObjectReader) LastModified() time.Time {
	return r.meta.LastModified
}

// ETag returns the ETag
func (r *ObjectReader) ETag() string {
	return r.meta.ETag
}

// BlockWriter is an io.WriteCloser that encrypts and writes blocks directly to disk storage.
// It buffers incoming data and writes complete blocks as they are filled.
// This is used for efficient streaming downloads with block-level encryption.
type BlockWriter struct {
	sm           *StorageManager
	instanceHash string
	file         *os.File
	encryptor    *BlockEncryptor
	meta         *CacheMetadata
	bitmap       *roaring.Bitmap   // Snapshot used for skip-detection (optimization)
	sharedState  *ObjectBlockState // Shared state updated after each block write
	buffer       []byte
	currentBlock uint32
	totalBlocks  uint32
	bytesWritten int64
	mu           sync.Mutex
	closed       bool
	onComplete   func() // Called when all blocks are written
}

// NewBlockWriter creates a new block writer for streaming encrypted writes to disk.
// The existingBitmap parameter allows resuming partial downloads by skipping
// already-downloaded blocks.  startBlock specifies which block number the
// first incoming byte corresponds to (use 0 to start from the beginning).
func (sm *StorageManager) NewBlockWriter(instanceHash string, startBlock uint32, existingBitmap *roaring.Bitmap, onComplete func()) (*BlockWriter, error) {
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found in metadata")
	}
	if !meta.IsDisk() {
		return nil, errors.New("block writer only works with disk storage")
	}

	// Get the shared block state so we can update it after each write
	sharedState, err := sm.GetSharedBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get shared block state")
	}

	// Decrypt the DEK
	encMgr := sm.db.GetEncryptionManager()
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data key")
	}

	// Create block encryptor
	encryptor, err := NewBlockEncryptor(dek, meta.Nonce)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create block encryptor")
	}

	// Open the file for writing, creating it and its parent directory if necessary.
	objectPath := sm.getObjectPathForDir(meta.StorageID, instanceHash)
	file, err := os.OpenFile(objectPath, os.O_WRONLY|os.O_CREATE, 0600)
	if errors.Is(err, os.ErrNotExist) {
		if mkdirErr := os.MkdirAll(filepath.Dir(objectPath), 0750); mkdirErr != nil {
			return nil, errors.Wrap(mkdirErr, "failed to create object directory")
		}
		file, err = os.OpenFile(objectPath, os.O_WRONLY|os.O_CREATE, 0600)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to open object file for writing")
	}

	// If the file was newly created (or truncated to 0), pre-allocate it to
	// the expected size so block writes land at the correct offsets.
	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, errors.Wrap(err, "failed to stat object file")
	}
	expectedSize := int64(CalculateBlockCount(meta.ContentLength)) * BlockTotalSize
	if fi.Size() < expectedSize {
		if err := file.Truncate(expectedSize); err != nil {
			file.Close()
			return nil, errors.Wrap(err, "failed to pre-allocate object file")
		}
	}

	return &BlockWriter{
		sm:           sm,
		instanceHash: instanceHash,
		file:         file,
		encryptor:    encryptor,
		meta:         meta,
		bitmap:       existingBitmap,
		sharedState:  sharedState,
		buffer:       make([]byte, 0, BlockDataSize),
		currentBlock: startBlock,
		totalBlocks:  CalculateBlockCount(meta.ContentLength),
		onComplete:   onComplete,
	}, nil
}

// Write implements io.Writer. Data is buffered and written to disk in encrypted blocks.
// Blocks that already exist in the bitmap are skipped.
func (bw *BlockWriter) Write(p []byte) (n int, err error) {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	if bw.closed {
		return 0, errors.New("writer is closed")
	}

	n = len(p)
	data := p

	for len(data) > 0 {
		// Calculate how much we can buffer
		spaceInBuffer := BlockDataSize - len(bw.buffer)
		toBuffer := len(data)
		if toBuffer > spaceInBuffer {
			toBuffer = spaceInBuffer
		}

		bw.buffer = append(bw.buffer, data[:toBuffer]...)
		data = data[toBuffer:]

		// If buffer is full, write the block
		if len(bw.buffer) == BlockDataSize {
			if err := bw.writeCurrentBlock(); err != nil {
				return 0, err
			}
		}
	}

	bw.bytesWritten += int64(n)
	return n, nil
}

// writeCurrentBlock encrypts and writes the buffered block to disk
func (bw *BlockWriter) writeCurrentBlock() error {
	if len(bw.buffer) == 0 {
		return nil
	}

	// Check if this block already exists — first the static snapshot
	// (cheap), then the live shared state which other concurrent writers
	// may have updated since we started.
	alreadyExists := bw.bitmap != nil && bw.bitmap.Contains(bw.currentBlock)
	if !alreadyExists && bw.sharedState != nil {
		alreadyExists = bw.sharedState.Contains(bw.currentBlock)
	}

	if !alreadyExists {
		// Encrypt the block
		encryptedBlock, err := bw.encryptor.EncryptBlock(bw.currentBlock, bw.buffer)
		if err != nil {
			return errors.Wrapf(err, "failed to encrypt block %d", bw.currentBlock)
		}

		// Write to file at the correct offset
		fileOffset := BlockOffset(bw.currentBlock)
		if _, err := bw.file.WriteAt(encryptedBlock, fileOffset); err != nil {
			return errors.Wrapf(err, "failed to write block %d", bw.currentBlock)
		}

		// Update block state in database
		if err := bw.sm.db.MarkBlocksDownloaded(bw.instanceHash, bw.currentBlock, bw.currentBlock); err != nil {
			return errors.Wrapf(err, "failed to mark block %d as downloaded", bw.currentBlock)
		}

		// Update the shared in-memory block state so all concurrent
		// readers see this block as available immediately.
		if bw.sharedState != nil {
			bw.sharedState.Add(bw.currentBlock)
		}
	}

	// Clear buffer and advance to next block
	bw.buffer = bw.buffer[:0]
	bw.currentBlock++

	return nil
}

// Close flushes any remaining data and closes the file
func (bw *BlockWriter) Close() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	if bw.closed {
		return nil
	}
	bw.closed = true

	// Write any remaining partial block (last block of file)
	if len(bw.buffer) > 0 {
		if err := bw.writeCurrentBlock(); err != nil {
			bw.file.Close()
			return errors.Wrap(err, "failed to write final block")
		}
	}

	if err := bw.file.Close(); err != nil {
		return errors.Wrap(err, "failed to close file")
	}

	// Check if download is complete and call callback
	downloadedCount, err := bw.sm.db.GetDownloadedBlockCount(bw.instanceHash)
	if err == nil && uint32(downloadedCount) == bw.totalBlocks {
		// Mark as completed
		bw.meta.Completed = time.Now()
		if err := bw.sm.db.SetMetadata(bw.instanceHash, bw.meta); err != nil {
			log.Warnf("Failed to update completion time: %v", err)
		}
		if bw.onComplete != nil {
			bw.onComplete()
		}
	}

	return nil
}

// BytesWritten returns the total number of bytes written so far
func (bw *BlockWriter) BytesWritten() int64 {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.bytesWritten
}
