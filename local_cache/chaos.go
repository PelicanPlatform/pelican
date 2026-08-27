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
	"os"
	"path/filepath"
	"regexp"

	"github.com/pkg/errors"
)

// hexHashPattern matches a non-empty hexadecimal string.  Instance/object
// hashes are hex-encoded HMAC-SHA256 digests, so validating a hash against this
// (anchored) pattern before it is used to build a filesystem path prevents path
// traversal from a caller-supplied instance value — a hex-only string cannot
// contain a path separator or "..".
var hexHashPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// ChaosInjector injects corruption into a running cache's already-open
// database and storage, for fault-injection ("chaos") testing of the cache's
// integrity-detection paths.
//
// BadgerDB is single-process, so corruption must be performed in-process by the
// cache server itself (a CLI cannot open the database while the server holds
// it).  The injector therefore wraps the live handles and does not own them —
// there is nothing to close.
type ChaosInjector struct {
	db      *CacheDB
	storage *StorageManager
}

// NewChaosInjector wraps a live cache's database and storage manager.
func NewChaosInjector(db *CacheDB, storage *StorageManager) *ChaosInjector {
	return &ChaosInjector{db: db, storage: storage}
}

// ChaosResult describes a corruption injected into a cached object by the
// chaos-testing helpers.  It is intended for fault-injection testing of the
// cache's integrity scan and read-time corruption detection.
type ChaosResult struct {
	InstanceHash string `json:"instance_hash"`
	SourceURL    string `json:"source_url,omitempty"`
	ETag         string `json:"etag,omitempty"`
	Operation    string `json:"operation"` // "corrupt-block" or "truncate"
	ChunkIndex   int    `json:"chunk_index"`
	FilePath     string `json:"file_path"`
	BlockNum     int64  `json:"block_num,omitempty"` // global block number (corrupt-block)
	DiskOffset   int64  `json:"disk_offset"`
	BytesChanged int    `json:"bytes_changed,omitempty"`
	OldFileSize  int64  `json:"old_file_size"`
	NewFileSize  int64  `json:"new_file_size"`
}

// resolveInstanceHash resolves an object instance from either an explicit
// instance hash, or an object URL plus optional ETag (defaulting to the latest
// cached version).  It returns the instance hash and its metadata.
func (ci *ChaosInjector) resolveInstanceHash(objectURL, etag, instanceHash string) (InstanceHash, *CacheMetadata, error) {
	var hash InstanceHash
	if instanceHash != "" {
		hash = InstanceHash(instanceHash)
	} else {
		normalized := NormalizePelicanURL(objectURL)
		if normalized == "" {
			return "", nil, errors.New("either an object URL or an instance hash is required")
		}
		objectHash := ci.db.ObjectHash(normalized)
		if etag == "" {
			var found bool
			var err error
			etag, found, err = ci.db.GetLatestETag(objectHash)
			if err != nil {
				return "", nil, errors.Wrap(err, "failed to get latest ETag")
			}
			if !found {
				return "", nil, errors.New("no cached version found for this object")
			}
		}
		hash = ci.db.InstanceHash(etag, objectHash)
	}

	// Guard against path traversal from a caller-supplied instance hash before
	// the hash is ever used to construct a filesystem path.
	if !hexHashPattern.MatchString(string(hash)) {
		return "", nil, errors.Errorf("invalid instance hash %q: must be hexadecimal", hash)
	}

	meta, err := ci.storage.GetMetadata(hash)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to read object metadata")
	}
	if meta == nil {
		return "", nil, errors.Errorf("no cached object found for instance %s", hash)
	}
	return hash, meta, nil
}

// safeChunkPath resolves the on-disk chunk file path and verifies it stays
// within its storage directory, defending against path traversal.  The
// object-relative portion is built from the (already hex-validated) instance
// hash; filepath.IsLocal confirms it cannot escape the storage root before it
// is joined to the trusted directory.
func (ci *ChaosInjector) safeChunkPath(storageID StorageID, hash InstanceHash, chunkIndex int) (string, error) {
	root, ok := ci.storage.GetDirs()[storageID]
	if !ok {
		return "", errors.Errorf("unknown storage id %d", storageID)
	}
	rel := GetChunkPath(GetInstanceStoragePath(hash), chunkIndex)
	if !filepath.IsLocal(rel) {
		return "", errors.Errorf("refusing non-local chunk path %q for instance %s", rel, hash)
	}
	return filepath.Join(root, rel), nil
}

// chunkFileForBlock maps a global block number to the on-disk chunk file that
// stores it and the byte offset of the (encrypted) block within that file.
func (ci *ChaosInjector) chunkFileForBlock(hash InstanceHash, meta *CacheMetadata, blockNum uint32) (chunkPath string, chunkIndex int, diskOffset int64, err error) {
	contentOffset := int64(blockNum) * BlockDataSize
	if contentOffset >= meta.ContentLength {
		return "", 0, 0, errors.Errorf("block %d is past the end of the object (%d block(s), %d bytes)",
			blockNum, CalculateBlockCount(meta.ContentLength), meta.ContentLength)
	}

	chunkIndex = ContentOffsetToChunk(contentOffset, meta.ChunkSizeCode)
	storageID := meta.GetChunkStorageID(chunkIndex)
	if storageID == StorageIDInline {
		return "", 0, 0, errors.Errorf("chunk %d is not yet allocated on disk", chunkIndex)
	}
	chunkPath, err = ci.safeChunkPath(storageID, hash, chunkIndex)
	if err != nil {
		return "", 0, 0, err
	}

	// The on-disk offset is the (zero-based) block index within this chunk file
	// times the encrypted block size.
	localBlock := uint32(OffsetInChunk(contentOffset, meta.ChunkSizeCode) / BlockDataSize)
	diskOffset = BlockOffset(localBlock)
	return chunkPath, chunkIndex, diskOffset, nil
}

// CorruptBlock flips the first numBytes bytes of the on-disk (encrypted)
// representation of the given block.  This makes the block's AES-GCM
// authentication tag fail to validate, which the cache detects on the next
// read of that block or during the periodic data-integrity scan.
//
// blockNum is a global, zero-based block number.  numBytes <= 0 defaults to the
// authentication-tag size (the minimum needed to guarantee detection).
//
// Detection is not necessarily immediate: a block whose plaintext is still in
// the cache's in-memory caches will continue to read successfully until those
// entries are evicted; the corruption is caught on the next cold read of the
// block, the periodic data-integrity scan, or after a restart.
func (ci *ChaosInjector) CorruptBlock(objectURL, etag, instanceHash string, blockNum uint32, numBytes int) (*ChaosResult, error) {
	hash, meta, err := ci.resolveInstanceHash(objectURL, etag, instanceHash)
	if err != nil {
		return nil, err
	}
	if meta.IsInline() {
		return nil, errors.New("object is stored inline in the database; chaos injection only supports disk-backed objects")
	}

	chunkPath, chunkIndex, diskOffset, err := ci.chunkFileForBlock(hash, meta, blockNum)
	if err != nil {
		return nil, err
	}

	if numBytes <= 0 {
		numBytes = AuthTagSize
	}
	if numBytes > BlockTotalSize {
		numBytes = BlockTotalSize
	}

	f, err := os.OpenFile(chunkPath, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open chunk file %s", chunkPath)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "failed to stat chunk file")
	}
	if diskOffset >= info.Size() {
		return nil, errors.Errorf("block %d is not present on disk (chunk file is %d bytes)", blockNum, info.Size())
	}
	// Do not read past EOF for a short final block.
	if diskOffset+int64(numBytes) > info.Size() {
		numBytes = int(info.Size() - diskOffset)
	}

	// numBytes is bounded by BlockTotalSize above, so a fixed-size stack buffer
	// suffices and avoids a caller-influenced dynamic allocation.
	var blockBuf [BlockTotalSize]byte
	buf := blockBuf[:numBytes]
	if _, err := f.ReadAt(buf, diskOffset); err != nil {
		return nil, errors.Wrap(err, "failed to read block bytes")
	}
	for i := range buf {
		buf[i] ^= 0xFF
	}
	if _, err := f.WriteAt(buf, diskOffset); err != nil {
		return nil, errors.Wrap(err, "failed to write corrupted bytes")
	}

	return &ChaosResult{
		InstanceHash: string(hash),
		SourceURL:    meta.SourceURL,
		ETag:         meta.ETag,
		Operation:    "corrupt-block",
		ChunkIndex:   chunkIndex,
		FilePath:     chunkPath,
		BlockNum:     int64(blockNum),
		DiskOffset:   diskOffset,
		BytesChanged: numBytes,
		OldFileSize:  info.Size(),
		NewFileSize:  info.Size(),
	}, nil
}

// TruncateObject removes dropBytes bytes from the end of one of the object's
// on-disk chunk files (the last chunk by default, when chunkIndex < 0).  This
// drops trailing block(s), which the cache detects on a cold read or during
// the data scan.  dropBytes <= 0 defaults to a single encrypted block
// (BlockTotalSize).
func (ci *ChaosInjector) TruncateObject(objectURL, etag, instanceHash string, chunkIndex int, dropBytes int64) (*ChaosResult, error) {
	hash, meta, err := ci.resolveInstanceHash(objectURL, etag, instanceHash)
	if err != nil {
		return nil, err
	}
	if meta.IsInline() {
		return nil, errors.New("object is stored inline in the database; chaos injection only supports disk-backed objects")
	}

	chunkCount := meta.ChunkCount()
	if chunkIndex < 0 {
		chunkIndex = chunkCount - 1
	}
	if chunkIndex >= chunkCount {
		return nil, errors.Errorf("chunk %d is out of range (object has %d chunk(s))", chunkIndex, chunkCount)
	}
	storageID := meta.GetChunkStorageID(chunkIndex)
	if storageID == StorageIDInline {
		return nil, errors.Errorf("chunk %d is not yet allocated on disk", chunkIndex)
	}
	chunkPath, err := ci.safeChunkPath(storageID, hash, chunkIndex)
	if err != nil {
		return nil, err
	}

	if dropBytes <= 0 {
		dropBytes = BlockTotalSize
	}

	f, err := os.OpenFile(chunkPath, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open chunk file %s", chunkPath)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "failed to stat chunk file")
	}
	oldSize := info.Size()
	newSize := oldSize - dropBytes
	if newSize < 0 {
		newSize = 0
	}
	if err := f.Truncate(newSize); err != nil {
		return nil, errors.Wrap(err, "failed to truncate chunk file")
	}

	return &ChaosResult{
		InstanceHash: string(hash),
		SourceURL:    meta.SourceURL,
		ETag:         meta.ETag,
		Operation:    "truncate",
		ChunkIndex:   chunkIndex,
		FilePath:     chunkPath,
		DiskOffset:   newSize,
		OldFileSize:  oldSize,
		NewFileSize:  newSize,
	}, nil
}
