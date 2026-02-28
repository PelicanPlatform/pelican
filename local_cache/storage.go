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
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

// removeFileWithRetry removes a file, retrying briefly on Windows if the
// file is still held open by an asynchronous eviction callback (ttlcache
// fires OnEviction in a goroutine, so the file descriptor may not be
// closed by the time we attempt the delete).
func removeFileWithRetry(name string) error {
	err := os.Remove(name)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	if runtime.GOOS != "windows" {
		return err
	}
	// On Windows, retry a few times to allow the async close to finish.
	for attempt := 0; attempt < 5; attempt++ {
		time.Sleep(10 * time.Millisecond)
		err = os.Remove(name)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
	}
	return err
}

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

// refCountedFile wraps an *os.File with atomic reference counting.
// The file is only closed when the last reference is released.
//
// Every call to Acquire() increments the counter; every call to Release()
// decrements it.  When the counter reaches zero the underlying file is
// closed.  newRefCountedFile returns the wrapper with an initial count of
// 1, so the creator must call Release() when done.
//
// This ensures that TTL-cache eviction (which also calls Release) cannot
// close the file while I/O operations are in progress on other goroutines.
//
// refCountedFile must not be copied after first use (contains atomic.Int32).
type refCountedFile struct {
	_    noCopy
	f    *os.File
	refs atomic.Int32
}

// noCopy may be added to structs which must not be copied after the first
// use.  See https://golang.org/issues/8005#issuecomment-190753527 and
// https://github.com/golang/go/blob/master/src/sync/cond.go#L95
//
// go vet's -copylocks checker will flag copies of types containing a
// Lock() method.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// newRefCountedFile wraps f with an initial reference count of 1.
func newRefCountedFile(f *os.File) *refCountedFile {
	rc := &refCountedFile{f: f}
	rc.refs.Store(1)
	return rc
}

// Acquire increments the reference count.  Callers must pair every
// successful Acquire with exactly one Release.  Returns false (and does
// not increment) if the file has already been fully released.
func (rc *refCountedFile) Acquire() bool {
	for {
		n := rc.refs.Load()
		if n <= 0 {
			return false
		}
		if rc.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// Release decrements the reference count and closes the file when it
// reaches zero.  It is safe to call Release concurrently.
func (rc *refCountedFile) Release() {
	if n := rc.refs.Add(-1); n == 0 {
		rc.f.Close()
	}
}

// File returns the underlying *os.File for I/O.  The caller must hold a
// reference (via Acquire or newRefCountedFile) for the entire duration of
// any I/O operation.
func (rc *refCountedFile) File() *os.File {
	return rc.f
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
// diskCryptoEntry caches the immutable cryptographic material for a disk-
// backed object: the metadata snapshot at open-time, the decrypted DEK, and
// the derived BlockEncryptor.  These values never change after
// InitDiskStorage, so caching them avoids repeated BadgerDB reads and AES
// key-wrap operations on every ReadBlocks / WriteBlocks call.
//
// IMPORTANT: The *CacheMetadata pointer is shared and must be treated as
// read-only.  Callers that need to mutate metadata fields (e.g.
// ContentLength, Completed) must make a shallow copy first.
type diskCryptoEntry struct {
	meta      *CacheMetadata  // READ-ONLY — do not mutate
	encryptor *BlockEncryptor // READ-ONLY — thread-safe for concurrent encrypt/decrypt
}

// diskCryptoTTL is how long an idle diskCryptoEntry lives before eviction.
const diskCryptoTTL = 5 * time.Minute

// openFileTTL is how long an idle cached file descriptor lives before
// being closed and evicted.
const openFileTTL = 2 * time.Minute

// writeBatchBlocks is the number of contiguous encrypted blocks the
// BlockWriter accumulates before flushing them to disk with a single
// WriteAt call.  64 blocks × 4096 bytes = 256 KiB — large enough to
// amortise syscall overhead and align well with typical filesystem
// block sizes.
const writeBatchBlocks uint32 = 64

type StorageManager struct {
	db *CacheDB

	// dirs maps storageID → objects directory (e.g. "/data1/objects").
	// StorageIDFirstDisk is always present; additional dirs have
	// sequential IDs.
	dirs map[StorageID]string

	// inlineMaxBytes is the maximum size of objects stored inline in
	// BadgerDB.  Objects at or below this threshold are stored inline;
	// larger objects go to disk.  Defaults to InlineThreshold (4096).
	inlineMaxBytes int

	// Shared per-object block availability state.  All RangeReaders for the
	// same instanceHash share one *ObjectBlockState so that block additions and
	// removals are immediately visible across goroutines.  Idle entries are
	// evicted after blockStateTTL and reloaded from the database on next
	// access.
	blockStates *ttlcache.Cache[InstanceHash, *ObjectBlockState]

	// diskCrypto caches metadata + BlockEncryptor for disk-backed objects
	// so that ReadBlocks / WriteBlocks / NewBlockWriter skip the DB
	// lookup and DEK decryption on hot paths.
	diskCrypto *ttlcache.Cache[InstanceHash, *diskCryptoEntry]

	// openFiles caches reference-counted file descriptors for disk-backed
	// objects.  Multiple goroutines can share a single FD via ReadAt /
	// WriteAt (offset-based, concurrency-safe).  Each cache hit calls
	// Acquire() on the refCountedFile; callers must call Release() when
	// they are done with I/O.  On eviction the cache also calls Release(),
	// but the underlying *os.File is only closed when the last reference
	// is gone — so in-flight I/O is never interrupted.
	openFiles *ttlcache.Cache[InstanceHash, *refCountedFile]

	// fdCacheMaxSize is the maximum number of entries in the openFiles
	// cache.  When 0, the cache is disabled entirely and every getFile
	// call opens a fresh descriptor.
	fdCacheMaxSize uint64
}

// StorageDirInfo describes a configured storage directory at runtime.
type StorageDirInfo struct {
	StorageID  StorageID
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
func NewStorageManager(db *CacheDB, dirs []string, inlineMax int, egrp *errgroup.Group) (*StorageManager, error) {
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
	usedIDs := make(map[StorageID]bool, len(persisted))
	for _, dm := range persisted {
		byUUID[dm.UUID] = dm
		usedIDs[dm.ID] = true
	}

	// Step 2–3: scan directories, match UUIDs, build result map.
	objDirs := make(map[StorageID]string, len(dirs))

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
	nextID := StorageID(StorageIDFirstDisk)
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

	fdCacheSizeParam := param.LocalCache_FDCacheSize.GetInt()
	var fdCacheSize uint64
	if fdCacheSizeParam > 0 {
		fdCacheSize = uint64(fdCacheSizeParam)
	}
	// fdCacheSizeParam <= 0 → fdCacheSize stays 0, disabling caching.

	sm := &StorageManager{
		db:             db,
		dirs:           objDirs,
		inlineMaxBytes: inlineMax,
		fdCacheMaxSize: fdCacheSize,
		blockStates:    newBlockStateCache(db),
		diskCrypto: ttlcache.New[InstanceHash, *diskCryptoEntry](
			ttlcache.WithTTL[InstanceHash, *diskCryptoEntry](diskCryptoTTL),
		),
		openFiles: ttlcache.New[InstanceHash, *refCountedFile](
			ttlcache.WithTTL[InstanceHash, *refCountedFile](openFileTTL),
			ttlcache.WithCapacity[InstanceHash, *refCountedFile](fdCacheSize),
		),
	}

	// Release the cache's reference when an entry is evicted.  The
	// underlying file is closed only when the last reference is gone
	// (i.e. no in-flight I/O holds a reference).
	sm.openFiles.OnEviction(func(_ context.Context, _ ttlcache.EvictionReason, item *ttlcache.Item[InstanceHash, *refCountedFile]) {
		if rc := item.Value(); rc != nil {
			rc.Release()
		}
	})

	// Start the TTL cache eviction goroutines so idle entries are reaped
	// automatically.  They are stopped when the StorageManager is closed.
	// Launching through the errgroup prevents goroutine leaks in tests.
	egrp.Go(func() error { sm.blockStates.Start(); return nil })
	egrp.Go(func() error { sm.diskCrypto.Start(); return nil })
	egrp.Go(func() error { sm.openFiles.Start(); return nil })

	return sm, nil
}

// GetDirs returns the configured storage directories (storageID → objects dir).
func (sm *StorageManager) GetDirs() map[StorageID]string {
	return sm.dirs
}

// Close stops TTL cache eviction goroutines and releases cached resources.
func (sm *StorageManager) Close() {
	sm.blockStates.Stop()
	sm.diskCrypto.Stop()
	sm.openFiles.Stop()
	// Closing openFiles evicts all entries, triggering OnEviction which
	// closes each file descriptor.
	sm.openFiles.DeleteAll()
}

// InlineMaxBytes returns the configured maximum inline object size.
func (sm *StorageManager) InlineMaxBytes() int {
	return sm.inlineMaxBytes
}

// getDiskCrypto returns the cached metadata + BlockEncryptor for a disk-
// backed object, loading from the database and decrypting the DEK on cache
// miss.  The returned entry must not be mutated.
func (sm *StorageManager) getDiskCrypto(instanceHash InstanceHash) (*diskCryptoEntry, error) {
	if item := sm.diskCrypto.Get(instanceHash); item != nil {
		return item.Value(), nil
	}

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

	encMgr := sm.db.GetEncryptionManager()
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data key")
	}

	encryptor, err := NewBlockEncryptor(dek, zeroNonce())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create block encryptor")
	}

	entry := &diskCryptoEntry{meta: meta, encryptor: encryptor}
	sm.diskCrypto.Set(instanceHash, entry, ttlcache.DefaultTTL)
	return entry, nil
}

// getFile returns a reference-counted, cached file descriptor for the
// given disk-backed object, opening the file on cache miss.
//
// The returned *refCountedFile has one additional reference held on
// behalf of the caller.  The caller MUST call Release() when I/O is
// complete.  All I/O must use ReadAt / WriteAt (offset-based,
// concurrency-safe).
func (sm *StorageManager) getFile(instanceHash InstanceHash, storageID StorageID) (*refCountedFile, error) {
	if sm.fdCacheMaxSize > 0 {
		if item := sm.openFiles.Get(instanceHash); item != nil {
			rc := item.Value()
			if rc.Acquire() {
				return rc, nil
			}
			// Ref count already at zero (being closed) — fall through to open a new one.
		}
	}

	objectPath := sm.getObjectPathForDir(storageID, instanceHash)

	file, err := os.OpenFile(objectPath, os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open object file")
	}

	rc := newRefCountedFile(file)
	if sm.fdCacheMaxSize > 0 {
		// The cache takes its own reference.
		rc.Acquire()
		sm.openFiles.Set(instanceHash, rc, ttlcache.DefaultTTL)
	}
	return rc, nil
}

// invalidateObjectCaches removes all in-memory cached state for an object:
// block state, disk crypto, and read file descriptor.  Call this when an
// object is deleted or evicted.
func (sm *StorageManager) invalidateObjectCaches(instanceHash InstanceHash) {
	sm.InvalidateSharedBlockState(instanceHash)
	sm.diskCrypto.Delete(instanceHash)
	sm.openFiles.Delete(instanceHash) // triggers OnEviction → file.Close()
}

// getObjectPathForDir returns the full path for an object in a specific directory.
func (sm *StorageManager) getObjectPathForDir(storageID StorageID, instanceHash InstanceHash) string {
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
func (sm *StorageManager) getObjectPath(instanceHash InstanceHash) string {
	return sm.getObjectPathForDir(StorageIDFirstDisk, instanceHash)
}

// StoreInline stores small data inline in BadgerDB
func (sm *StorageManager) StoreInline(ctx context.Context, instanceHash InstanceHash, meta *CacheMetadata, data []byte) error {
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

	// Decrypt the DEK to use for encryption
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt data key")
	}

	// Encrypt the data (nonce is always zero; DEK uniqueness is sufficient)
	encryptedData, err := encMgr.EncryptInline(data, dek, zeroNonce())
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
func (sm *StorageManager) ReadInline(instanceHash InstanceHash) ([]byte, error) {
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
	return encMgr.DecryptInline(encryptedData, dek, zeroNonce())
}

// InitDiskStorage initializes disk storage for a large object in the specified
// storage directory.  Returns the metadata with encryption keys set up.
func (sm *StorageManager) InitDiskStorage(ctx context.Context, instanceHash InstanceHash, contentLength int64, storageID StorageID) (*CacheMetadata, error) {
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

	meta := &CacheMetadata{
		StorageID:     storageID,
		ContentLength: contentLength,
		DataKey:       encryptedDEK,
	}

	// Create the file; createFile lazily creates the parent directory
	objectPath := sm.getObjectPathForDir(storageID, instanceHash)
	file, err := createFile(objectPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create object file")
	}

	// Pre-allocate the file to the exact encrypted size.
	fileSize := CalculateFileSize(contentLength)
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

	// Cache the freshly-created R/W file descriptor so that subsequent
	// WriteBlocks and ReadBlocks calls reuse it.  The refCountedFile
	// starts with count=1; the cache's Set takes an extra Acquire, and
	// we Release the creator's ref since we have no further I/O here.
	rc := newRefCountedFile(file)
	if sm.fdCacheMaxSize > 0 {
		rc.Acquire() // for the cache
		sm.openFiles.Set(instanceHash, rc, ttlcache.DefaultTTL)
	}
	rc.Release() // creator's ref

	return meta, nil
}

// WriteBlocks writes encrypted blocks to disk storage
// This is the main write path for large objects
func (sm *StorageManager) WriteBlocks(instanceHash InstanceHash, startOffset int64, data []byte) error {
	// Get cached metadata + encryptor
	dc, err := sm.getDiskCrypto(instanceHash)
	if err != nil {
		return err
	}
	meta := dc.meta
	encryptor := dc.encryptor

	// Use the cached R/W file descriptor.  WriteAt is concurrency-safe
	// (it uses pwrite underneath) so sharing the FD is fine.
	rc, err := sm.getFile(instanceHash, meta.StorageID)
	if err != nil {
		return err
	}
	defer rc.Release()
	file := rc.File()

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
	if err := sm.db.MarkBlocksDownloaded(instanceHash, startBlock, startBlock+blocksWritten-1, meta.StorageID, meta.NamespaceID, meta.ContentLength); err != nil {
		return errors.Wrap(err, "failed to update block state")
	}

	// Check if download is complete
	totalBlocks := CalculateBlockCount(meta.ContentLength)
	downloadedCount, err := sm.db.GetDownloadedBlockCount(instanceHash)
	if err != nil {
		log.Warnf("Failed to check download completion: %v", err)
	} else if uint32(downloadedCount) == totalBlocks {
		// Mark as completed via merge to avoid overwriting concurrent changes.
		completionMeta := &CacheMetadata{Completed: time.Now()}
		if err := sm.db.MergeMetadata(instanceHash, completionMeta); err != nil {
			log.Warnf("Failed to update completion time: %v", err)
		}
	}

	return nil
}

// ReadBlocks reads and decrypts blocks from disk storage.
// It uses the shared ObjectBlockState to check block availability.
func (sm *StorageManager) ReadBlocks(instanceHash InstanceHash, startOffset int64, length int) ([]byte, error) {
	// Get cached metadata + encryptor (avoids DB lookup and DEK decrypt on hot path)
	dc, err := sm.getDiskCrypto(instanceHash)
	if err != nil {
		return nil, err
	}
	meta := dc.meta
	encryptor := dc.encryptor

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

	// Get a cached file descriptor (ref-counted).
	rc, err := sm.getFile(instanceHash, meta.StorageID)
	if err != nil {
		return nil, err
	}
	defer rc.Release()
	file := rc.File()

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
func (sm *StorageManager) IdentifyCorruptBlocks(instanceHash InstanceHash, startBlock, endBlock uint32) ([]uint32, error) {
	dc, err := sm.getDiskCrypto(instanceHash)
	if err != nil {
		return nil, err
	}
	meta := dc.meta
	encryptor := dc.encryptor

	blockState, err := sm.GetSharedBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	// Try the cached FD first; fall back to a direct open so we can
	// detect "file missing" as a special case.
	rc, fileErr := sm.getFile(instanceHash, meta.StorageID)
	if fileErr != nil {
		// File missing entirely — every block the bitmap thinks is present
		// is corrupt, not just those in the requested [startBlock, endBlock]
		// range.  Returning only the narrow range would leave the remaining
		// blocks marked as present in the shared state, so subsequent reads
		// of those blocks would hit zeros on the newly pre-allocated file
		// and fail with decryption errors.
		snapshot := blockState.Clone()
		corrupt := snapshot.ToArray()
		return corrupt, nil
	}
	defer rc.Release()
	file := rc.File()

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
func (sm *StorageManager) GetMissingBlocks(instanceHash InstanceHash) ([]BlockRange, error) {
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
func (sm *StorageManager) IsComplete(instanceHash InstanceHash) (bool, error) {
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
func (sm *StorageManager) Delete(instanceHash InstanceHash) error {
	// Get metadata to determine storage mode
	meta, err := sm.db.GetMetadata(instanceHash)
	if err != nil {
		return errors.Wrap(err, "failed to get metadata")
	}

	// Delete from database (handles inline data, block state, LRU)
	if err := sm.db.DeleteObject(instanceHash); err != nil {
		return errors.Wrap(err, "failed to delete database entries")
	}

	// Remove all in-memory cached state for this object.
	sm.invalidateObjectCaches(instanceHash)

	// If stored on disk, delete the file
	if meta != nil && meta.IsDisk() {
		objectPath := sm.getObjectPathForDir(meta.StorageID, instanceHash)
		if err := removeFileWithRetry(objectPath); err != nil {
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
func (sm *StorageManager) EvictByLRU(storageID StorageID, namespaceID NamespaceID, maxObjects int, maxBytes int64) ([]evictedObject, uint64, error) {
	evicted, err := sm.db.EvictByLRU(storageID, namespaceID, maxObjects, maxBytes)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to evict objects by LRU")
	}

	var totalFreed uint64
	for _, obj := range evicted {
		totalFreed += uint64(obj.contentLen)

		// Remove all in-memory cached state for this object.
		sm.invalidateObjectCaches(obj.instanceHash)

		if obj.storageID != StorageIDInline {
			objectPath := sm.getObjectPathForDir(obj.storageID, obj.instanceHash)
			if err := removeFileWithRetry(objectPath); err != nil {
				log.Warnf("Failed to delete evicted object file %s: %v", objectPath, err)
			}
		}
	}

	return evicted, totalFreed, nil
}

// GetObjectSize returns the content length of a cached object
func (sm *StorageManager) GetObjectSize(instanceHash InstanceHash) (int64, error) {
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
func (sm *StorageManager) GetMetadata(instanceHash InstanceHash) (*CacheMetadata, error) {
	return sm.db.GetMetadata(instanceHash)
}

// SetMetadata stores metadata for an object (full replace, use for initial creation only)
func (sm *StorageManager) SetMetadata(instanceHash InstanceHash, meta *CacheMetadata) error {
	return sm.db.SetMetadata(instanceHash, meta)
}

// MergeMetadata performs an atomic read-modify-update of object metadata
func (sm *StorageManager) MergeMetadata(instanceHash InstanceHash, meta *CacheMetadata) error {
	return sm.db.MergeMetadata(instanceHash, meta)
}

// HasObject checks if an object exists in storage
func (sm *StorageManager) HasObject(instanceHash InstanceHash) (bool, error) {
	return sm.db.HasMetadata(instanceHash)
}

// ObjectReader provides a reader interface for cached objects
type ObjectReader struct {
	sm           *StorageManager
	instanceHash InstanceHash
	meta         *CacheMetadata
	position     int64
	length       int64
	file         *refCountedFile // ref-counted handle from the TTL cache; nil for inline objects
	inlineData   []byte
}

// NewObjectReader creates a reader for a cached object
func (sm *StorageManager) NewObjectReader(instanceHash InstanceHash) (*ObjectReader, error) {
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
		// Acquire a ref-counted handle from the TTL cache.  This keeps the
		// underlying FD alive for the lifetime of the reader (even if the
		// cache evicts the entry) and shares the handle with concurrent
		// ReadBlocks callers.
		rc, err := sm.getFile(instanceHash, meta.StorageID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open object file")
		}
		reader.file = rc
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

// Close releases the reader's reference to the underlying file handle.
// The actual FD is closed only when all references (including the TTL
// cache entry) have been released.
func (r *ObjectReader) Close() error {
	if r.file != nil {
		r.file.Release()
		r.file = nil
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
// Contiguous encrypted blocks are batched (up to writeBatchBlocks) so that
// multiple blocks can be written to disk in a single WriteAt call, reducing
// syscall overhead and improving sequential write throughput.
// This is used for efficient streaming downloads with block-level encryption.
type BlockWriter struct {
	sm           *StorageManager
	instanceHash InstanceHash
	file         *refCountedFile
	encryptor    *BlockEncryptor
	meta         *CacheMetadata
	bitmap       *roaring.Bitmap   // Snapshot used for skip-detection (optimization)
	sharedState  *ObjectBlockState // Shared state updated after each block write
	buffer       []byte
	currentBlock uint32
	totalBlocks  uint32
	bytesWritten int64

	// Sequential write batching: encrypted blocks are accumulated in
	// writeBatch.  When the batch reaches writeBatchBlocks blocks, or a
	// non-contiguous gap is encountered, the batch is flushed to disk
	// with a single WriteAt.
	writeBatch []byte // accumulated encrypted block data
	batchStart uint32 // first block number in the current batch
	batchCount uint32 // number of blocks in the current batch

	mu         sync.Mutex
	closed     bool
	onComplete func() // Called when all blocks are written
}

// NewBlockWriter creates a new block writer for streaming encrypted writes to disk.
// The existingBitmap parameter allows resuming partial downloads by skipping
// already-downloaded blocks.  startBlock specifies which block number the
// first incoming byte corresponds to (use 0 to start from the beginning).
func (sm *StorageManager) NewBlockWriter(instanceHash InstanceHash, startBlock uint32, existingBitmap *roaring.Bitmap, onComplete func()) (*BlockWriter, error) {
	// Get cached metadata + encryptor
	dc, err := sm.getDiskCrypto(instanceHash)
	if err != nil {
		return nil, err
	}
	// Copy the metadata so that BlockWriter mutations (ContentLength,
	// Completed) do not corrupt the shared cached entry.
	metaCopy := *dc.meta
	meta := &metaCopy
	encryptor := dc.encryptor

	// Get the shared block state so we can update it after each write
	sharedState, err := sm.GetSharedBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get shared block state")
	}

	// Open the file for read/write, creating it and its parent directory if necessary.
	objectPath := sm.getObjectPathForDir(meta.StorageID, instanceHash)
	file, err := os.OpenFile(objectPath, os.O_RDWR|os.O_CREATE, 0600)
	if errors.Is(err, os.ErrNotExist) {
		if mkdirErr := os.MkdirAll(filepath.Dir(objectPath), 0750); mkdirErr != nil {
			return nil, errors.Wrap(mkdirErr, "failed to create object directory")
		}
		file, err = os.OpenFile(objectPath, os.O_RDWR|os.O_CREATE, 0600)
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
	expectedSize := CalculateFileSize(meta.ContentLength)
	if fi.Size() < expectedSize {
		if err := file.Truncate(expectedSize); err != nil {
			file.Close()
			return nil, errors.Wrap(err, "failed to pre-allocate object file")
		}
	}

	// Hint to the kernel that this FD will be used for sequential I/O.
	if err := fadviseSequential(file); err != nil {
		log.Debugf("fadvise(SEQUENTIAL) failed (non-fatal): %v", err)
	}

	rc := newRefCountedFile(file)
	return &BlockWriter{
		sm:           sm,
		instanceHash: instanceHash,
		file:         rc,
		encryptor:    encryptor,
		meta:         meta,
		bitmap:       existingBitmap,
		sharedState:  sharedState,
		buffer:       make([]byte, 0, BlockDataSize),
		currentBlock: startBlock,
		totalBlocks:  CalculateBlockCount(meta.ContentLength),
		writeBatch:   make([]byte, 0, int(writeBatchBlocks)*BlockTotalSize),
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

// writeCurrentBlock encrypts the buffered block and adds it to the write
// batch.  The batch is flushed to disk when it reaches writeBatchBlocks
// contiguous blocks or when a non-contiguous gap (skipped block) is
// encountered.
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

		// If this block is not contiguous with the current batch, flush first.
		if bw.batchCount > 0 && bw.batchStart+bw.batchCount != bw.currentBlock {
			if err := bw.flushWriteBatch(); err != nil {
				return err
			}
		}
		if bw.batchCount == 0 {
			bw.batchStart = bw.currentBlock
		}
		bw.writeBatch = append(bw.writeBatch, encryptedBlock...)
		bw.batchCount++

		// Flush if the batch reached the threshold
		if bw.batchCount >= writeBatchBlocks {
			if err := bw.flushWriteBatch(); err != nil {
				return err
			}
		}
	} else {
		// Block was skipped — flush any accumulated batch so that all
		// preceding blocks become visible to concurrent readers.
		if bw.batchCount > 0 {
			if err := bw.flushWriteBatch(); err != nil {
				return err
			}
		}
	}

	// Clear buffer and advance to next block
	bw.buffer = bw.buffer[:0]
	bw.currentBlock++

	return nil
}

// flushWriteBatch writes the accumulated encrypted blocks to disk in a
// single WriteAt call, marks them as downloaded in the database, and
// updates the shared in-memory block state so that concurrent readers
// see the new blocks immediately.
func (bw *BlockWriter) flushWriteBatch() error {
	if bw.batchCount == 0 {
		return nil
	}

	fileOffset := BlockOffset(bw.batchStart)
	if _, err := bw.file.File().WriteAt(bw.writeBatch, fileOffset); err != nil {
		return errors.Wrapf(err, "failed to write blocks %d–%d", bw.batchStart, bw.batchStart+bw.batchCount-1)
	}

	endBlock := bw.batchStart + bw.batchCount - 1
	if err := bw.sm.db.MarkBlocksDownloaded(bw.instanceHash, bw.batchStart, endBlock, bw.meta.StorageID, bw.meta.NamespaceID, bw.meta.ContentLength); err != nil {
		return errors.Wrapf(err, "failed to mark blocks %d–%d as downloaded", bw.batchStart, endBlock)
	}

	// Update the shared in-memory block state so all concurrent readers
	// see these blocks as available immediately.
	if bw.sharedState != nil {
		for block := bw.batchStart; block <= endBlock; block++ {
			bw.sharedState.Add(block)
		}
	}

	bw.writeBatch = bw.writeBatch[:0]
	bw.batchCount = 0
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

	// For unknown-size transfers (chunked encoding), set ContentLength
	// BEFORE writing the last block so that calculateUsageDelta
	// correctly sizes the final (possibly partial) block.  During the
	// streaming write each full block added BlockDataSize to usage;
	// only the last block needs the real ContentLength to compute
	// its potentially smaller contribution.
	if bw.meta.ContentLength < 0 {
		bw.meta.ContentLength = bw.bytesWritten
		bw.totalBlocks = CalculateBlockCount(bw.bytesWritten)
		// Persist the now-known size so the last MarkBlocksDownloaded
		// (and any concurrent readers) can use the correct value.
		sizeMeta := &CacheMetadata{ContentLength: bw.bytesWritten}
		if err := bw.sm.db.MergeMetadata(bw.instanceHash, sizeMeta); err != nil {
			log.Warnf("Failed to update content length for unknown-size download: %v", err)
		}
	}

	// Write any remaining partial block (last block of file).
	// For unknown-size transfers the updated ContentLength ensures
	// MarkBlocksDownloaded adds exactly the right usage for this block.
	if len(bw.buffer) > 0 {
		if err := bw.writeCurrentBlock(); err != nil {
			bw.file.Release()
			return errors.Wrap(err, "failed to write final block")
		}
	}

	// Flush any remaining batched encrypted blocks to disk.
	if err := bw.flushWriteBatch(); err != nil {
		bw.file.Release()
		return errors.Wrap(err, "failed to flush write batch")
	}

	// For unknown-size (chunked) transfers the file was allocated with
	// size 0 and grew via block writes; truncate to the exact final size
	// now that ContentLength is known.  For known-size transfers the file
	// was already pre-allocated to the exact size by InitDiskStorage /
	// NewBlockWriter, so this is a no-op.
	if bw.totalBlocks > 0 {
		actualSize := CalculateFileSize(bw.meta.ContentLength)
		if err := bw.file.File().Truncate(actualSize); err != nil {
			log.Warnf("Failed to truncate file to actual size: %v", err)
		}
	}

	// Donate the file descriptor to the cache.  The cache's own ref was
	// not yet taken (the BlockWriter owned the sole ref), so Acquire for
	// the cache and then Release the writer's ref.
	if bw.sm.fdCacheMaxSize > 0 {
		bw.file.Acquire() // for the cache
		bw.sm.openFiles.Set(bw.instanceHash, bw.file, ttlcache.DefaultTTL)
	}
	bw.file.Release() // writer's ref

	// Check if download is complete and call callback
	downloadedCount, err := bw.sm.db.GetDownloadedBlockCount(bw.instanceHash)
	if err == nil && uint32(downloadedCount) == bw.totalBlocks {
		// Mark as completed via merge to avoid overwriting concurrent changes.
		bw.meta.Completed = time.Now()
		completionMeta := &CacheMetadata{Completed: bw.meta.Completed}
		if err := bw.sm.db.MergeMetadata(bw.instanceHash, completionMeta); err != nil {
			log.Warnf("Failed to update completion time: %v", err)
		}

		// Remove the block-state bitmap now that the object is complete.
		// GetBlockState synthesizes a full bitmap for completed objects,
		// so this is safe.  Order matters: metadata is marked complete
		// above before we delete the bitmap so that a crash between the
		// two leaves the bitmap in place (wasteful but correct).
		if err := bw.sm.db.DeleteBlockState(bw.instanceHash); err != nil {
			log.Warnf("Failed to delete block state after completion: %v", err)
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
