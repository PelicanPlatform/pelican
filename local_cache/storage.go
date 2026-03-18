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
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RoaringBitmap/roaring"
	ristretto "github.com/dgraph-io/ristretto/v2"
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
// https://github.com/golang/go/blob/go1.24.1/src/sync/cond.go#L95
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

// DefaultReadBatchBlocks is the default number of blocks to read from disk
// in a single ReadAt syscall before decrypting block-by-block.
// 16 blocks × 4096 bytes = 64 KiB.
const DefaultReadBatchBlocks = 16

// OptimalReadSize is the ideal number of plaintext bytes to request per
// read call.  It equals DefaultReadBatchBlocks × BlockDataSize (16 × 4080
// = 65 280 B).  When callers align their buffer sizes to a multiple of
// BlockDataSize (4080), every block decrypts directly into the
// destination buffer (zero-copy).  Misaligned sizes cause the last
// partial block in each batch to be decrypted into a temporary buffer
// and copied, adding overhead.
const OptimalReadSize = DefaultReadBatchBlocks * BlockDataSize

// readBufPool pools reusable read buffers for batch disk reads.
// Each buffer is DefaultReadBatchBlocks × BlockTotalSize = 64 KiB.
// Storing *[]byte avoids an interface-boxing allocation on Get/Put.
var readBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, DefaultReadBatchBlocks*BlockTotalSize)
		return &b
	},
}

// writeBufPool pools reusable write buffers for batched disk writes.
// Each buffer is writeBatchBlocks × BlockTotalSize = 256 KiB.
var writeBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, int(writeBatchBlocks)*BlockTotalSize)
		return &b
	},
}

// writeToOutBufPool pools the plaintext output buffers used by WriteTo.
// Each buffer is writeToReadBatchBlocks × BlockDataSize ≈ 255 KiB.
var writeToOutBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, writeToReadBatchBlocks*BlockDataSize)
		return &b
	},
}

// ptCacheKey builds a uint64 cache key for the plaintext block cache.
// Since instanceHash is already a cryptographic hash, its first 8 bytes
// are uniformly distributed; XOR-ing with the block number produces a
// collision probability of ~1/2^64 per pair — effectively zero.
func ptCacheKey(h InstanceHash, block uint32) uint64 {
	return binary.LittleEndian.Uint64([]byte(h)[:8]) ^ uint64(block)
}

// chunkFileKey identifies a specific chunk file in the FD cache.
type chunkFileKey struct {
	instanceHash InstanceHash
	chunkIndex   int
}

// smallChunkLimit is the threshold below which chunk file tracking uses
// a fixed-size array instead of a heap-allocated map.  Almost all real
// objects have fewer chunks than this.
const smallChunkLimit = 20

// chunkTracker tracks open refCountedFile handles for chunk files during
// a single read or write operation.  For chunk counts ≤ smallChunkLimit
// it uses a stack-allocated array; otherwise it falls back to a map.
type chunkTracker struct {
	smallKeys  [smallChunkLimit]int
	smallVals  [smallChunkLimit]*refCountedFile
	smallCount int
	bigMap     map[int]*refCountedFile
}

func (ct *chunkTracker) get(chunkIdx int) (*refCountedFile, bool) {
	if ct.bigMap != nil {
		rc, ok := ct.bigMap[chunkIdx]
		return rc, ok
	}
	for i := 0; i < ct.smallCount; i++ {
		if ct.smallKeys[i] == chunkIdx {
			return ct.smallVals[i], true
		}
	}
	return nil, false
}

func (ct *chunkTracker) set(chunkIdx int, rc *refCountedFile) {
	if ct.bigMap != nil {
		ct.bigMap[chunkIdx] = rc
		return
	}
	if ct.smallCount < smallChunkLimit {
		ct.smallKeys[ct.smallCount] = chunkIdx
		ct.smallVals[ct.smallCount] = rc
		ct.smallCount++
		return
	}
	// Spill to map.
	ct.bigMap = make(map[int]*refCountedFile, ct.smallCount+1)
	for i := 0; i < ct.smallCount; i++ {
		ct.bigMap[ct.smallKeys[i]] = ct.smallVals[i]
	}
	ct.bigMap[chunkIdx] = rc
}

func (ct *chunkTracker) releaseAll() {
	if ct.bigMap != nil {
		for _, rc := range ct.bigMap {
			rc.Release()
		}
		return
	}
	for i := 0; i < ct.smallCount; i++ {
		ct.smallVals[i].Release()
	}
}

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

	// openFiles caches reference-counted file descriptors for all disk-
	// backed files — both non-chunked objects and individual chunk files.
	// Keyed by (instanceHash, chunkIndex); non-chunked objects and chunk 0
	// use chunkIndex 0.  Multiple goroutines can share a single FD via
	// ReadAt / WriteAt (offset-based, concurrency-safe).  Each cache hit
	// calls Acquire() on the refCountedFile; callers must call Release()
	// when they are done with I/O.  On eviction the cache also calls
	// Release(), but the underlying *os.File is only closed when the last
	// reference is gone — so in-flight I/O is never interrupted.
	openFiles *ttlcache.Cache[chunkFileKey, *refCountedFile]

	// fdCacheMaxSize is the maximum number of entries in the openFiles
	// cache.  When 0, the cache is disabled entirely and every getFile
	// call opens a fresh descriptor.
	fdCacheMaxSize uint64

	// ptCache is an optional in-memory plaintext block cache backed by
	// ristretto.  When non-nil, decrypted 4080-byte blocks are cached
	// so that repeated reads bypass AES-GCM decryption.  Keyed by
	// (InstanceHash, blockNumber); cost = BlockDataSize per entry.
	// Nil when disabled (MemoryCacheSize == 0).
	ptCache *ristretto.Cache[uint64, []byte]

	// chooseDir selects a storage directory for new chunk files.
	// Defaults to simple round-robin.  In production, NewPersistentCache
	// overwrites this with EvictionManager.ChooseDiskStorage (weighted
	// by free space) before any concurrent access begins.
	chooseDir func() StorageID
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

	// Plaintext block cache: when MemoryCacheSize > 0, create a
	// ristretto cache that stores decrypted 4080-byte blocks keyed by
	// (instanceHash, blockNum).  MaxCost = configured size in bytes;
	// each entry costs BlockDataSize (4080) bytes.
	var ptCache *ristretto.Cache[uint64, []byte]
	ptCacheSize := param.LocalCache_MemoryCacheSize.GetInt()
	if ptCacheSize > 0 {
		// NumCounters should be ~10× the expected max number of entries.
		numEntries := int64(ptCacheSize) / BlockDataSize
		numCounters := numEntries * 10
		if numCounters < 1000 {
			numCounters = 1000
		}
		var err error
		ptCache, err = ristretto.NewCache(&ristretto.Config[uint64, []byte]{
			NumCounters: numCounters,
			MaxCost:     int64(ptCacheSize),
			BufferItems: 64,
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to create plaintext block cache")
		}
	}

	// Build sorted directory ID list for default round-robin.
	dirIDs := make([]StorageID, 0, len(objDirs))
	for id := range objDirs {
		dirIDs = append(dirIDs, id)
	}
	sort.Slice(dirIDs, func(i, j int) bool { return dirIDs[i] < dirIDs[j] })

	var rrCounter atomic.Uint64
	defaultChooseDir := func() StorageID {
		idx := int(rrCounter.Add(1)) % len(dirIDs)
		return dirIDs[idx]
	}

	sm := &StorageManager{
		db:             db,
		dirs:           objDirs,
		inlineMaxBytes: inlineMax,
		fdCacheMaxSize: fdCacheSize,
		ptCache:        ptCache,
		chooseDir:      defaultChooseDir,
		blockStates:    newBlockStateCache(db),
		diskCrypto: ttlcache.New[InstanceHash, *diskCryptoEntry](
			ttlcache.WithTTL[InstanceHash, *diskCryptoEntry](diskCryptoTTL),
		),
		openFiles: ttlcache.New[chunkFileKey, *refCountedFile](
			ttlcache.WithTTL[chunkFileKey, *refCountedFile](openFileTTL),
			ttlcache.WithCapacity[chunkFileKey, *refCountedFile](fdCacheSize),
		),
	}

	// Release the cache's reference when an entry is evicted.  The
	// underlying file is closed only when the last reference is gone
	// (i.e. no in-flight I/O holds a reference).
	sm.openFiles.OnEviction(func(_ context.Context, _ ttlcache.EvictionReason, item *ttlcache.Item[chunkFileKey, *refCountedFile]) {
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
	// Closing caches evicts all entries, triggering OnEviction which
	// closes each file descriptor.
	sm.openFiles.DeleteAll()
	if sm.ptCache != nil {
		sm.ptCache.Close()
	}
}

// NewStorageManagerReadOnly creates a storage manager for read-only introspection.
// This is a lightweight variant suitable for CLI tools that only need to read
// metadata and block states, not perform downloads or writes.
func NewStorageManagerReadOnly(baseDir string, db *CacheDB) (*StorageManager, error) {
	// Load disk mappings to discover storage directories
	mappings, err := db.LoadDiskMappings()
	if err != nil {
		return nil, errors.Wrap(err, "failed to load disk mappings")
	}

	objDirs := make(map[StorageID]string, len(mappings))
	for _, dm := range mappings {
		objDirs[dm.ID] = filepath.Join(dm.Directory, objectsSubDir)
	}

	// Create minimal caches with no goroutine management
	sm := &StorageManager{
		db:             db,
		dirs:           objDirs,
		inlineMaxBytes: InlineThreshold,
		blockStates:    newBlockStateCache(db),
		diskCrypto: ttlcache.New[InstanceHash, *diskCryptoEntry](
			ttlcache.WithTTL[InstanceHash, *diskCryptoEntry](diskCryptoTTL),
		),
		openFiles: ttlcache.New[chunkFileKey, *refCountedFile](
			ttlcache.WithTTL[chunkFileKey, *refCountedFile](openFileTTL),
		),
	}

	// Set up eviction callback for openFiles
	sm.openFiles.OnEviction(func(_ context.Context, _ ttlcache.EvictionReason, item *ttlcache.Item[chunkFileKey, *refCountedFile]) {
		if rc := item.Value(); rc != nil {
			rc.Release()
		}
	})

	log.Debugf("Storage manager opened in read-only mode with %d directories", len(objDirs))
	return sm, nil
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
	key := chunkFileKey{instanceHash: instanceHash, chunkIndex: 0}
	if sm.fdCacheMaxSize > 0 {
		if item := sm.openFiles.Get(key); item != nil {
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
		sm.openFiles.Set(key, rc, ttlcache.DefaultTTL)
	}
	return rc, nil
}

// invalidateObjectCaches removes all in-memory cached state for an object:
// block state, disk crypto, and file descriptors.  chunkCount is the number
// of chunk files (1 for non-chunked objects).  Call this when an object is
// deleted or evicted.
func (sm *StorageManager) invalidateObjectCaches(instanceHash InstanceHash, chunkCount int) {
	sm.InvalidateSharedBlockState(instanceHash)
	sm.diskCrypto.Delete(instanceHash)
	for i := 0; i < chunkCount; i++ {
		sm.openFiles.Delete(chunkFileKey{instanceHash: instanceHash, chunkIndex: i})
	}
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

// getChunkPath returns the filesystem path for a specific chunk of an object.
// For chunk 0, this is the same as getObjectPathForDir.
// For chunks 1+, a suffix like "-2", "-3" is appended.
func (sm *StorageManager) getChunkPath(storageID StorageID, instanceHash InstanceHash, chunkIndex int) string {
	basePath := sm.getObjectPathForDir(storageID, instanceHash)
	return GetChunkPath(basePath, chunkIndex)
}

// getChunkFile returns a reference-counted file descriptor for a specific chunk.
// chunkIndex is 0-based.  The caller MUST call Release() when done.
// Returns an error if the chunk is not allocated (StorageID = 0).
func (sm *StorageManager) getChunkFile(instanceHash InstanceHash, meta *CacheMetadata, chunkIndex int) (*refCountedFile, error) {
	if !meta.IsChunked() || chunkIndex == 0 {
		// Non-chunked objects or chunk 0 use the base file path
		storageID := meta.StorageID
		if storageID == StorageIDInline {
			if meta.IsChunked() {
				return nil, errors.New("chunk 0 is not yet allocated")
			}
			return nil, errors.New("cannot get file for inline storage")
		}
		return sm.getFile(instanceHash, storageID)
	}

	// For chunks > 0, check if allocated
	if !meta.IsChunkAllocated(chunkIndex) {
		return nil, errors.Errorf("chunk %d is not allocated", chunkIndex)
	}

	// Look up in the unified FD cache.
	key := chunkFileKey{instanceHash: instanceHash, chunkIndex: chunkIndex}
	if sm.fdCacheMaxSize > 0 {
		if item := sm.openFiles.Get(key); item != nil {
			rc := item.Value()
			if rc.Acquire() {
				return rc, nil
			}
		}
	}

	storageID := meta.GetChunkStorageID(chunkIndex)
	chunkPath := sm.getChunkPath(storageID, instanceHash, chunkIndex)

	file, err := os.OpenFile(chunkPath, os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open chunk %d file", chunkIndex)
	}

	rc := newRefCountedFile(file)
	if sm.fdCacheMaxSize > 0 {
		rc.Acquire()
		sm.openFiles.Set(key, rc, ttlcache.DefaultTTL)
	}
	return rc, nil
}

// DirCount returns the number of configured storage directories.
// This is used to determine if chunking should be enabled.
func (sm *StorageManager) DirCount() int {
	return len(sm.dirs)
}

// DirIDs returns the list of configured storage directory IDs in sorted order.
func (sm *StorageManager) DirIDs() []StorageID {
	ids := make([]StorageID, 0, len(sm.dirs))
	for id := range sm.dirs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
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
	// If another goroutine already initialized storage for this instance,
	// return the existing metadata rather than generating a second DataKey
	// (which would cause a set-once conflict in MergeMetadata).
	if existing, err := sm.GetMetadata(instanceHash); err == nil && existing != nil && len(existing.DataKey) > 0 {
		return existing, nil
	}

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
		sm.openFiles.Set(chunkFileKey{instanceHash: instanceHash, chunkIndex: 0}, rc, ttlcache.DefaultTTL)
	}
	rc.Release() // creator's ref

	return meta, nil
}

// InitLazyChunkedStorage initializes metadata for a chunked object WITHOUT creating
// chunk files. Files are created lazily when AllocateChunk is called (typically on
// first write to each chunk). This supports byte-range downloads where chunks may
// be written out of order.
//
// All chunk StorageIDs are initialized to 0 (unallocated). Use AllocateChunk to
// assign a storage directory and create the file for each chunk before writing.
//
// Parameters:
//   - instanceHash: unique identifier for this object version
//   - contentLength: total object size in bytes
//   - chunkSizeCode: chunk size encoding (must be non-zero for chunked storage)
func (sm *StorageManager) InitLazyChunkedStorage(
	ctx context.Context,
	instanceHash InstanceHash,
	contentLength int64,
	chunkSizeCode ChunkSizeCode,
) (*CacheMetadata, error) {
	// If another goroutine already initialized storage for this instance,
	// return the existing metadata rather than generating a second DataKey.
	if existing, err := sm.GetMetadata(instanceHash); err == nil && existing != nil && len(existing.DataKey) > 0 {
		return existing, nil
	}

	if chunkSizeCode == ChunkingDisabled {
		return nil, errors.New("InitLazyChunkedStorage requires chunking enabled (chunkSizeCode > 0)")
	}

	encMgr := sm.db.GetEncryptionManager()

	// Generate encryption keys (shared across all chunks)
	dek, err := encMgr.GenerateDataKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate data key")
	}

	encryptedDEK, err := encMgr.EncryptDataKey(dek)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt data key")
	}

	// Pre-allocate ChunkLocations with all StorageID = 0 (unallocated)
	chunkCount := CalculateChunkCount(contentLength, chunkSizeCode)
	var chunkLocations []ChunkLocation
	if chunkCount > 1 {
		chunkLocations = make([]ChunkLocation, chunkCount-1)
		// All ChunkLocation.StorageID are zero-valued (unallocated)
	}

	meta := &CacheMetadata{
		StorageID:      StorageIDInline, // Chunk 0 also unallocated (0 = unallocated for chunked)
		ContentLength:  contentLength,
		DataKey:        encryptedDEK,
		ChunkSizeCode:  chunkSizeCode,
		ChunkLocations: chunkLocations,
	}

	// Store metadata (no files created yet)
	if err := sm.db.SetMetadata(instanceHash, meta); err != nil {
		return nil, errors.Wrap(err, "failed to store metadata")
	}

	// Initialize block state as empty bitmap
	if err := sm.db.SetBlockState(instanceHash, roaring.New()); err != nil {
		if delErr := sm.db.DeleteMetadata(instanceHash); delErr != nil {
			log.Warnf("Failed to clean up metadata for %s: %v", instanceHash, delErr)
		}
		return nil, errors.Wrap(err, "failed to initialize block state")
	}

	return meta, nil
}

// AllocateChunk allocates a storage directory for a chunk and creates the chunk file.
// This must be called before writing to a chunk that has StorageID = 0 (unallocated).
//
// The storage directory is chosen via the pluggable chooseDir function, which
// defaults to simple round-robin but is replaced in production with
// EvictionManager.ChooseDiskStorage (weighted by free space).
//
// Returns the updated CacheMetadata (which should be used for subsequent operations).
func (sm *StorageManager) AllocateChunk(
	ctx context.Context,
	instanceHash InstanceHash,
	meta *CacheMetadata,
	chunkIndex int,
) (*CacheMetadata, error) {
	// Check if already allocated
	if meta.IsChunkAllocated(chunkIndex) {
		return meta, nil
	}

	// Choose storage directory.
	storageID := sm.chooseDir()

	// Create the chunk file
	chunkPath := sm.getChunkPath(storageID, instanceHash, chunkIndex)
	file, err := createFile(chunkPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create chunk %d file", chunkIndex)
	}

	// Calculate chunk content length and encrypted file size
	chunkContentLen := ChunkContentLength(meta.ContentLength, meta.ChunkSizeCode, chunkIndex)
	fileSize := CalculateFileSize(chunkContentLen)

	if err := file.Truncate(fileSize); err != nil {
		file.Close()
		_ = removeFileWithRetry(chunkPath)
		return nil, errors.Wrapf(err, "failed to pre-allocate chunk %d file", chunkIndex)
	}

	// Cache the freshly-created file descriptor.
	rc := newRefCountedFile(file)
	if sm.fdCacheMaxSize > 0 {
		rc.Acquire()
		sm.openFiles.Set(chunkFileKey{instanceHash: instanceHash, chunkIndex: chunkIndex}, rc, ttlcache.DefaultTTL)
	}
	rc.Release()

	// Update metadata with the new storage ID
	meta.SetChunkStorageID(chunkIndex, storageID)

	// Persist the updated metadata
	if err := sm.db.SetMetadata(instanceHash, meta); err != nil {
		_ = removeFileWithRetry(chunkPath)
		return nil, errors.Wrap(err, "failed to update metadata with chunk storage")
	}

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

	// Calculate starting block offset to validate alignment
	offsetWithinBlock := ContentOffsetWithinBlock(startOffset)

	// If starting in the middle of a block, we need to read-modify-write
	if offsetWithinBlock != 0 {
		return errors.New("writing to middle of block not supported; use block-aligned writes")
	}

	return sm.writeBlocks(instanceHash, meta, encryptor, startOffset, data)
}

// writeBlocks encrypts and writes a contiguous range of blocks to disk.
// It handles both chunked and non-chunked objects: for non-chunked objects
// every block maps to chunk 0 and the single object file, so the chunk
// bookkeeping collapses to a no-op.
func (sm *StorageManager) writeBlocks(instanceHash InstanceHash, meta *CacheMetadata, encryptor *BlockEncryptor, startOffset int64, data []byte) error {
	// Make a local copy of metadata so we never mutate the cached
	// diskCryptoEntry (which is shared/read-only).
	localMeta := *meta
	meta = &localMeta

	startBlock := ContentOffsetToBlock(startOffset)

	// Track which files we have open (by chunk index).
	var openChunks chunkTracker
	defer openChunks.releaseAll()

	// Helper to get or open a chunk file, allocating on demand.
	getChunkFile := func(chunkIdx int) (*os.File, error) {
		if rc, ok := openChunks.get(chunkIdx); ok {
			return rc.File(), nil
		}
		if !meta.IsChunkAllocated(chunkIdx) {
			updatedMeta, err := sm.AllocateChunk(context.Background(), instanceHash, meta, chunkIdx)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to allocate chunk %d", chunkIdx)
			}
			*meta = *updatedMeta
			// Invalidate the diskCrypto cache so future callers see updated metadata
			sm.diskCrypto.Delete(instanceHash)
		}
		rc, err := sm.getChunkFile(instanceHash, meta, chunkIdx)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			// File was removed from disk (e.g. corruption auto-repair).
			// Recreate it so the write can proceed.
			storageID := meta.GetChunkStorageID(chunkIdx)
			chunkPath := sm.getChunkPath(storageID, instanceHash, chunkIdx)
			chunkContentLen := ChunkContentLength(meta.ContentLength, meta.ChunkSizeCode, chunkIdx)
			fileSize := CalculateFileSize(chunkContentLen)
			f, createErr := createFile(chunkPath)
			if createErr != nil {
				return nil, errors.Wrapf(createErr, "failed to recreate missing chunk %d file", chunkIdx)
			}
			if truncErr := f.Truncate(fileSize); truncErr != nil {
				f.Close()
				return nil, errors.Wrapf(truncErr, "failed to pre-allocate recreated chunk %d file", chunkIdx)
			}
			rc = newRefCountedFile(f)
		}
		openChunks.set(chunkIdx, rc)
		return rc.File(), nil
	}

	// Pooled write buffer for batching.
	writeBufSize := int(writeBatchBlocks) * BlockTotalSize
	wbp := writeBufPool.Get().(*[]byte)
	writeBuf := (*wbp)[:0]
	defer writeBufPool.Put(wbp)

	// Flush helper
	flushBatch := func(file *os.File, batchStartChunkBlock uint32) error {
		if len(writeBuf) == 0 {
			return nil
		}
		fileOffset := BlockOffset(batchStartChunkBlock)
		if _, err := file.WriteAt(writeBuf, fileOffset); err != nil {
			return err
		}
		writeBuf = writeBuf[:0]
		return nil
	}

	// Track block ranges per chunk for usage accounting
	type chunkBlockRange struct {
		startBlock uint32
		endBlock   uint32
		storageID  StorageID
	}
	var chunkRanges []chunkBlockRange

	dataOffset := 0
	currentBlock := startBlock
	currentContentOffset := startOffset
	currentChunkIdx := -1
	var currentFile *os.File
	var batchStartChunkBlock uint32
	var rangeStartBlock uint32

	for dataOffset < len(data) {
		// Determine which chunk this block belongs to
		chunkIdx := ContentOffsetToChunk(currentContentOffset, meta.ChunkSizeCode)
		chunkStart, _ := GetChunkRange(meta.ContentLength, meta.ChunkSizeCode, chunkIdx)
		offsetInChunk := currentContentOffset - chunkStart
		chunkBlockNum := ContentOffsetToBlock(offsetInChunk)

		// If chunk changed, flush previous batch and record range
		if chunkIdx != currentChunkIdx {
			if currentFile != nil {
				if err := flushBatch(currentFile, batchStartChunkBlock); err != nil {
					return errors.Wrapf(err, "failed to flush batch to chunk %d", currentChunkIdx)
				}
			}
			if currentChunkIdx >= 0 {
				chunkRanges = append(chunkRanges, chunkBlockRange{
					startBlock: rangeStartBlock,
					endBlock:   currentBlock - 1,
					storageID:  meta.GetChunkStorageID(currentChunkIdx),
				})
			}
			var err error
			currentFile, err = getChunkFile(chunkIdx)
			if err != nil {
				return errors.Wrapf(err, "failed to open chunk %d", chunkIdx)
			}
			currentChunkIdx = chunkIdx
			batchStartChunkBlock = chunkBlockNum
			rangeStartBlock = currentBlock
		}

		// Check if we need to flush current batch (buffer full)
		if len(writeBuf) >= writeBufSize {
			if err := flushBatch(currentFile, batchStartChunkBlock); err != nil {
				return errors.Wrapf(err, "failed to flush batch to chunk %d", chunkIdx)
			}
			batchStartChunkBlock = chunkBlockNum
		}

		remaining := len(data) - dataOffset
		blockDataLen := BlockDataSize
		if remaining < blockDataLen {
			blockDataLen = remaining
		}

		blockData := data[dataOffset : dataOffset+blockDataLen]

		// Encrypt directly into write buffer (zero-copy)
		var err error
		writeBuf, err = encryptor.EncryptBlockTo(writeBuf, currentBlock, blockData)
		if err != nil {
			return errors.Wrapf(err, "failed to encrypt block %d", currentBlock)
		}

		dataOffset += blockDataLen
		currentContentOffset += int64(blockDataLen)
		currentBlock++
	}

	// Flush remaining batch
	if currentFile != nil && len(writeBuf) > 0 {
		if err := flushBatch(currentFile, batchStartChunkBlock); err != nil {
			return errors.Wrapf(err, "failed to flush final batch to chunk %d", currentChunkIdx)
		}
	}

	// Record final chunk range
	if currentChunkIdx >= 0 {
		chunkRanges = append(chunkRanges, chunkBlockRange{
			startBlock: rangeStartBlock,
			endBlock:   currentBlock - 1,
			storageID:  meta.GetChunkStorageID(currentChunkIdx),
		})
	}

	// Update block state with per-chunk storage IDs for correct usage accounting
	for _, cr := range chunkRanges {
		if err := sm.db.MarkBlocksDownloaded(instanceHash, cr.startBlock, cr.endBlock, cr.storageID, meta.NamespaceID, meta.ContentLength); err != nil {
			return errors.Wrap(err, "failed to update block state")
		}
	}

	// Check if download is complete
	sm.checkAndMarkComplete(instanceHash, meta)

	return nil
}

// checkAndMarkComplete checks if all blocks are downloaded and marks the object as complete
func (sm *StorageManager) checkAndMarkComplete(instanceHash InstanceHash, meta *CacheMetadata) {
	totalBlocks := CalculateBlockCount(meta.ContentLength)
	downloadedCount, err := sm.db.GetDownloadedBlockCount(instanceHash)
	if err != nil {
		log.Warnf("Failed to check download completion: %v", err)
		return
	}
	if uint32(downloadedCount) == totalBlocks {
		completionMeta := &CacheMetadata{Completed: time.Now()}
		if err := sm.db.MergeMetadata(instanceHash, completionMeta); err != nil {
			log.Warnf("Failed to update completion time: %v", err)
		}
	}
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
	endOffset := min(startOffset+int64(length), meta.ContentLength)
	endBlock := ContentOffsetToBlock(endOffset - 1)

	// Check all needed blocks are downloaded (single lock acquisition)
	if !blockState.ContainsRange(startBlock, endBlock) {
		// Get missing blocks for error message
		missing := blockState.MissingInRange(startBlock, endBlock)
		if len(missing) > 0 {
			return nil, errors.Errorf("block %d not yet downloaded", missing[0])
		}
		return nil, errors.New("blocks not yet downloaded")
	}

	return sm.readBlocksChunked(instanceHash, meta, encryptor, startOffset, length)
}

// ReadBlocksInto reads and decrypts blocks from disk storage directly into
// the caller-provided dst buffer.  It returns the number of bytes written
// to dst.  This avoids the result allocation and copy that ReadBlocks
// performs.  dst must be large enough to hold the requested data.
func (sm *StorageManager) ReadBlocksInto(dst []byte, instanceHash InstanceHash, startOffset int64) (int, error) {
	dc, err := sm.getDiskCrypto(instanceHash)
	if err != nil {
		return 0, err
	}
	meta := dc.meta
	encryptor := dc.encryptor

	length := len(dst)
	endOffset := min(startOffset+int64(length), meta.ContentLength)
	actualLen := int(endOffset - startOffset)
	if actualLen <= 0 {
		return 0, nil
	}

	blockState, err := sm.GetSharedBlockState(instanceHash)
	if err != nil {
		return 0, errors.Wrap(err, "failed to get block state")
	}

	startBlock := ContentOffsetToBlock(startOffset)
	endBlock := ContentOffsetToBlock(endOffset - 1)

	if !blockState.ContainsRange(startBlock, endBlock) {
		missing := blockState.MissingInRange(startBlock, endBlock)
		if len(missing) > 0 {
			return 0, errors.Errorf("block %d not yet downloaded", missing[0])
		}
		return 0, errors.New("blocks not yet downloaded")
	}

	return sm.readBlocksChunkedInto(instanceHash, meta, encryptor, dst[:actualLen], startOffset)
}

// decryptBlocksFromFile reads and decrypts blocks from a single file
// directly into dst.  It uses a pooled read buffer for the encrypted
// disk I/O.  globalBlockNum0 is the global block number corresponding to
// file-local block 0; pass 0 for non-chunked files (where local == global).
// For chunk files, pass ContentOffsetToBlock(chunkStart).
func decryptBlocksFromFile(file *os.File, contentLength int64, encryptor *BlockEncryptor, dst []byte, startOffset int64, ptCache *ristretto.Cache[uint64, []byte], instanceHash InstanceHash, globalBlockNum0 uint32) (int, error) {
	endOffset := startOffset + int64(len(dst))
	if endOffset > contentLength {
		endOffset = contentLength
	}

	startBlock := ContentOffsetToBlock(startOffset)
	endBlock := ContentOffsetToBlock(endOffset - 1)
	lastObjectBlock := CalculateBlockCount(contentLength) - 1
	offsetWithinFirstBlock := ContentOffsetWithinBlock(startOffset)

	resultLen := int(endOffset - startOffset)
	resultPos := 0

	// Use pooled read buffer.
	bp := readBufPool.Get().(*[]byte)
	readBuf := *bp
	defer readBufPool.Put(bp)

	for batchStart := startBlock; batchStart <= endBlock; batchStart += uint32(DefaultReadBatchBlocks) {
		batchEnd := batchStart + uint32(DefaultReadBatchBlocks) - 1
		if batchEnd > endBlock {
			batchEnd = endBlock
		}
		batchBlockCount := int(batchEnd - batchStart + 1)

		// Calculate read size — last block of file may be smaller.
		var readSize int
		if batchEnd == lastObjectBlock {
			lastBlockDataSize := int(contentLength % BlockDataSize)
			if lastBlockDataSize == 0 {
				lastBlockDataSize = BlockDataSize
			}
			readSize = (batchBlockCount-1)*BlockTotalSize + lastBlockDataSize + AuthTagSize
		} else {
			readSize = batchBlockCount * BlockTotalSize
		}

		fileOffset := BlockOffset(batchStart)
		n, err := file.ReadAt(readBuf[:readSize], fileOffset)
		if err != nil && err != io.EOF {
			return 0, errors.Wrapf(err, "failed to read blocks %d-%d", batchStart, batchEnd)
		}

		readPos := 0
		for i := 0; i < batchBlockCount; i++ {
			block := batchStart + uint32(i)
			globalBlock := globalBlockNum0 + block

			var encBlockSize int
			if block == lastObjectBlock {
				lastBlockDataSize := int(contentLength % BlockDataSize)
				if lastBlockDataSize == 0 {
					lastBlockDataSize = BlockDataSize
				}
				encBlockSize = lastBlockDataSize + AuthTagSize
			} else {
				encBlockSize = BlockTotalSize
			}

			if readPos+encBlockSize > n {
				return 0, errors.Errorf("short read on block %d: got %d bytes in batch, expected at least %d", globalBlock, n, readPos+encBlockSize)
			}

			encryptedSlice := readBuf[readPos : readPos+encBlockSize]
			readPos += encBlockSize

			blockDataSize := encBlockSize - AuthTagSize

			isPartialFirst := block == startBlock && offsetWithinFirstBlock > 0
			isPartialLast := block == endBlock && resultLen-resultPos < blockDataSize

			// Check plaintext cache first.
			if ptCache != nil {
				if cached, ok := ptCache.Get(ptCacheKey(instanceHash, globalBlock)); ok {
					if !isPartialFirst && !isPartialLast {
						copy(dst[resultPos:], cached[:blockDataSize])
						resultPos += blockDataSize
					} else {
						dataStart := 0
						dataEnd := len(cached)
						if isPartialFirst {
							dataStart = int(offsetWithinFirstBlock)
						}
						if isPartialLast {
							remaining := resultLen - resultPos
							if dataEnd-dataStart > remaining {
								dataEnd = dataStart + remaining
							}
						}
						copy(dst[resultPos:], cached[dataStart:dataEnd])
						resultPos += dataEnd - dataStart
					}
					continue
				}
			}

			if !isPartialFirst && !isPartialLast {
				// Full block: decrypt directly into dst (zero-copy).
				_, err := encryptor.DecryptBlockTo(dst[resultPos:resultPos:resultPos+blockDataSize], globalBlock, encryptedSlice)
				if err != nil {
					return 0, errors.Wrapf(err, "failed to decrypt block %d", globalBlock)
				}
				if ptCache != nil {
					entry := make([]byte, blockDataSize)
					copy(entry, dst[resultPos:resultPos+blockDataSize])
					ptCache.Set(ptCacheKey(instanceHash, globalBlock), entry, int64(BlockDataSize))
				}
				resultPos += blockDataSize
			} else {
				// Partial block: decrypt to temp buffer, copy needed portion.
				decrypted, err := encryptor.DecryptBlock(globalBlock, encryptedSlice)
				if err != nil {
					return 0, errors.Wrapf(err, "failed to decrypt block %d", globalBlock)
				}

				if ptCache != nil {
					entry := make([]byte, len(decrypted))
					copy(entry, decrypted)
					ptCache.Set(ptCacheKey(instanceHash, globalBlock), entry, int64(BlockDataSize))
				}

				dataStart := 0
				dataEnd := len(decrypted)

				if isPartialFirst {
					dataStart = int(offsetWithinFirstBlock)
				}
				if isPartialLast {
					remaining := resultLen - resultPos
					if dataEnd-dataStart > remaining {
						dataEnd = dataStart + remaining
					}
				}

				copy(dst[resultPos:], decrypted[dataStart:dataEnd])
				resultPos += dataEnd - dataStart
			}
		}
	}

	return resultPos, nil
}

// readBlocksChunked reads blocks from a chunked object, handling reads that
// span chunk boundaries.  It allocates a result buffer and delegates to
// readBlocksChunkedInto.
func (sm *StorageManager) readBlocksChunked(instanceHash InstanceHash, meta *CacheMetadata, encryptor *BlockEncryptor, startOffset int64, length int) ([]byte, error) {
	endOffset := startOffset + int64(length)
	if endOffset > meta.ContentLength {
		endOffset = meta.ContentLength
	}
	resultLen := int(endOffset - startOffset)
	result := make([]byte, resultLen)

	n, err := sm.readBlocksChunkedInto(instanceHash, meta, encryptor, result, startOffset)
	if err != nil {
		return nil, err
	}
	return result[:n], nil
}

// readBlocksChunkedInto reads blocks from a chunked object directly into dst.
// It iterates over the chunks that overlap the requested range and delegates
// each chunk's I/O to decryptBlocksFromFile.
func (sm *StorageManager) readBlocksChunkedInto(instanceHash InstanceHash, meta *CacheMetadata, encryptor *BlockEncryptor, dst []byte, startOffset int64) (int, error) {
	endOffset := startOffset + int64(len(dst))
	if endOffset > meta.ContentLength {
		endOffset = meta.ContentLength
	}

	// Track which files we have open (by chunk index).
	var openChunks chunkTracker
	defer openChunks.releaseAll()

	resultPos := 0
	currentOffset := startOffset

	for currentOffset < endOffset {
		// Determine which chunk this offset falls in.
		chunkIdx := ContentOffsetToChunk(currentOffset, meta.ChunkSizeCode)
		chunkStart, chunkEnd := GetChunkRange(meta.ContentLength, meta.ChunkSizeCode, chunkIdx)
		chunkContentLen := chunkEnd - chunkStart + 1

		// Get (or open) the file for this chunk.
		var file *os.File
		if rc, ok := openChunks.get(chunkIdx); ok {
			file = rc.File()
		} else {
			rc, err := sm.getChunkFile(instanceHash, meta, chunkIdx)
			if err != nil {
				return 0, errors.Wrapf(err, "failed to open chunk %d", chunkIdx)
			}
			openChunks.set(chunkIdx, rc)
			file = rc.File()
		}

		// How many bytes to read from this chunk.
		chunkLocalOffset := currentOffset - chunkStart
		readLen := min(chunkContentLen-chunkLocalOffset, endOffset-currentOffset)

		// Global block number of local block 0 in this chunk file.
		globalBlockNum0 := ContentOffsetToBlock(chunkStart)

		n, err := decryptBlocksFromFile(file, chunkContentLen, encryptor,
			dst[resultPos:resultPos+int(readLen)], chunkLocalOffset,
			sm.ptCache, instanceHash, globalBlockNum0)
		if err != nil {
			return 0, err
		}

		resultPos += n
		currentOffset += int64(n)
	}

	return resultPos, nil
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
	chunkCount := 1
	if meta != nil {
		chunkCount = meta.ChunkCount()
	}
	sm.invalidateObjectCaches(instanceHash, chunkCount)

	// If stored on disk, delete all chunk files
	if meta != nil && meta.IsDisk() {
		sm.deleteChunkFiles(instanceHash, meta.ContentLength, meta.StorageID, meta.ChunkSizeCode, meta.ChunkLocations)
	}

	return nil
}

// deleteChunkFiles removes all chunk files for an object from disk.
func (sm *StorageManager) deleteChunkFiles(instanceHash InstanceHash, contentLen int64, baseStorageID StorageID, chunkSizeCode ChunkSizeCode, chunkLocations []ChunkLocation) {
	chunkCount := CalculateChunkCount(contentLen, chunkSizeCode)
	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		var storageID StorageID
		if chunkIdx == 0 {
			storageID = baseStorageID
		} else if chunkIdx-1 < len(chunkLocations) {
			storageID = chunkLocations[chunkIdx-1].StorageID
		} else {
			storageID = baseStorageID // fallback
		}

		// Skip unallocated chunks (lazy allocation: StorageID 0 means no file was created)
		if storageID == StorageIDInline {
			continue
		}

		chunkPath := sm.getChunkPath(storageID, instanceHash, chunkIdx)
		if err := removeFileWithRetry(chunkPath); err != nil && !os.IsNotExist(err) {
			log.Warnf("Failed to delete chunk %d file %s: %v", chunkIdx, chunkPath, err)
		}
	}
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
		// Return the attempted (uncommitted) objects alongside the error
		// so the caller can log which objects were involved in a conflict.
		return evicted, 0, errors.Wrap(err, "failed to evict objects by LRU")
	}

	var totalFreed uint64
	for _, obj := range evicted {
		totalFreed += uint64(obj.contentLen)

		// Remove all in-memory cached state for this object.
		sm.invalidateObjectCaches(obj.instanceHash, CalculateChunkCount(obj.contentLen, obj.chunkSizeCode))

		// Delete all chunk files from disk
		if obj.storageID != StorageIDInline {
			sm.deleteChunkFiles(obj.instanceHash, obj.contentLen, obj.storageID, obj.chunkSizeCode, obj.chunkLocations)
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

// ObjectReader provides a reader interface for cached objects.
// For disk-backed objects, it caches the BlockEncryptor and ObjectBlockState
// at construction time so that Read/ReadAt calls do not need to look them up
// through the TTL caches on every call.
type ObjectReader struct {
	sm           *StorageManager
	instanceHash InstanceHash
	meta         *CacheMetadata
	position     int64
	length       int64
	file         *refCountedFile // ref-counted handle from the TTL cache; nil for inline objects
	inlineData   []byte
	encryptor    *BlockEncryptor   // cached from getDiskCrypto; nil for inline
	blockState   *ObjectBlockState // cached from GetSharedBlockState; nil for inline
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
		// Cache the encryptor so Read/ReadAt skip the getDiskCrypto TTL lookup.
		dc, err := sm.getDiskCrypto(instanceHash)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get disk crypto")
		}
		reader.encryptor = dc.encryptor

		// Cache the block state so Read/ReadAt skip the GetSharedBlockState TTL lookup.
		bs, err := sm.GetSharedBlockState(instanceHash)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get block state")
		}
		reader.blockState = bs

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

// readDiskDirect reads and decrypts blocks directly into dst using the
// ObjectReader's cached encryptor, blockState, and file handle.  This avoids
// the per-call TTL cache lookups that ReadBlocks performs (getDiskCrypto,
// GetSharedBlockState, getFile) and eliminates the intermediate buffer
// allocation + copy.
//
// For chunked objects the method falls back to sm.readBlocksChunked (which
// still benefits from the cached encryptor/blockState) because those reads
// need to open multiple chunk files.
func (r *ObjectReader) readDiskDirect(dst []byte, off int64) (int, error) {
	meta := r.meta
	encryptor := r.encryptor
	length := len(dst)

	endOffset := off + int64(length)
	if endOffset > meta.ContentLength {
		endOffset = meta.ContentLength
	}
	actualLen := int(endOffset - off)
	if actualLen <= 0 {
		return 0, nil
	}

	startBlock := ContentOffsetToBlock(off)
	endBlock := ContentOffsetToBlock(endOffset - 1)

	// Verify blocks are downloaded.
	if !r.blockState.ContainsRange(startBlock, endBlock) {
		missing := r.blockState.MissingInRange(startBlock, endBlock)
		if len(missing) > 0 {
			return 0, errors.Errorf("block %d not yet downloaded", missing[0])
		}
		return 0, errors.New("blocks not yet downloaded")
	}

	if meta.IsChunked() {
		// Chunked objects need to open multiple chunk files; use the
		// "into" variant that writes directly into dst with pooled readBuf.
		return r.sm.readBlocksChunkedInto(r.instanceHash, meta, encryptor, dst[:actualLen], off)
	}

	// Non-chunked fast path: read directly into dst using r.file.
	return r.readSimpleInto(dst[:actualLen], off)
}

// readSimpleInto reads and decrypts blocks from a non-chunked object directly
// into dst.  It delegates to decryptBlocksFromFile which uses a pooled read
// buffer.
func (r *ObjectReader) readSimpleInto(dst []byte, off int64) (int, error) {
	return decryptBlocksFromFile(r.file.File(), r.meta.ContentLength, r.encryptor, dst, off, r.sm.ptCache, r.instanceHash, 0)
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

	// Align to block boundaries so every block hits the zero-copy
	// DecryptBlockTo path inside decryptBlocksFromFile.  Returning fewer
	// bytes than len(p) (a "short read") is legal per io.Reader and
	// causes io.Copy / io.CopyN to simply call Read again.
	if toRead > BlockDataSize {
		if off := ContentOffsetWithinBlock(r.position); off == 0 {
			toRead = (toRead / BlockDataSize) * BlockDataSize
		} else {
			// Mid-block: finish the current block to re-align.
			toRead = BlockDataSize - off
		}
	}

	if r.meta.IsInline() {
		n = copy(p[:toRead], r.inlineData[r.position:])
		r.position += int64(n)
		if r.position >= r.length {
			return n, io.EOF
		}
		return n, nil
	}

	// Fast path: read directly into p using cached encryptor, blockState, and file handle.
	n, err = r.readDiskDirect(p[:toRead], r.position)
	if err != nil {
		return 0, err
	}
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

	// Fast path: read directly into p using cached state.
	n, err = r.readDiskDirect(p[:toRead], off)
	if err != nil {
		return 0, err
	}
	if off+int64(n) >= r.length {
		return n, io.EOF
	}

	return n, nil
}

// writeToReadBatchBlocks is the number of blocks to read per disk I/O
// when streaming via WriteTo.  64 blocks × 4080 B ≈ 255 KB of plaintext
// per write — much larger than the 32 KB buffer io.Copy uses by default.
const writeToReadBatchBlocks = 64

// WriteTo implements io.WriterTo.  When io.Copy detects this interface it
// calls WriteTo directly instead of issuing many small Read calls with a
// 32 KB default buffer.  This lets the ObjectReader control the batch
// size, reading and decrypting many blocks at once and writing the
// plaintext to w in large chunks.
func (r *ObjectReader) WriteTo(w io.Writer) (int64, error) {
	if r.position >= r.length {
		return 0, nil
	}

	if r.meta.IsInline() {
		n, err := w.Write(r.inlineData[r.position:r.length])
		r.position += int64(n)
		return int64(n), err
	}

	bufSize := writeToReadBatchBlocks * BlockDataSize
	obp := writeToOutBufPool.Get().(*[]byte)
	buf := *obp
	defer writeToOutBufPool.Put(obp)

	var total int64
	for r.position < r.length {
		toRead := min(int(r.length-r.position), bufSize)

		n, err := r.readDiskDirect(buf[:toRead], r.position)
		if err != nil {
			return total, err
		}

		written, werr := w.Write(buf[:n])
		total += int64(written)
		r.position += int64(written)
		if werr != nil {
			return total, werr
		}
		if written != n {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
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
		// Invalidate the diskCrypto cache so that subsequent ReadBlocks
		// calls see the updated ContentLength instead of -1.
		bw.sm.diskCrypto.Delete(bw.instanceHash)
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
		bw.sm.openFiles.Set(chunkFileKey{instanceHash: bw.instanceHash, chunkIndex: 0}, bw.file, ttlcache.DefaultTTL)
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

// Flush writes any accumulated batch of encrypted blocks to disk and
// updates the shared block state so that concurrent readers can see them
// immediately.  This is a no-op when the batch is empty.
//
// Callers that need low-latency streaming (e.g. the blockWriter adapter
// in AdoptTransfer) should call Flush periodically instead of waiting
// for the batch to reach writeBatchBlocks.
func (bw *BlockWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.flushWriteBatch()
}

// BytesWritten returns the total number of bytes written so far
func (bw *BlockWriter) BytesWritten() int64 {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.bytesWritten
}
