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

// Multi-Storage Architecture — Status
//
// The following items are already implemented in the current codebase:
//   - Usage keys are composite: PrefixUsage + storageID + namespaceID (see UsageKey)
//   - Inline data is tracked as a separate storage resource (StorageIDInline = 0)
//   - CacheMetadata includes StorageID to distinguish storage backends
//   - Block-state and usage updates are atomic (MergeBlockStateWithUsage)
//
// Future work for true multi-storage (multiple disk directories):
//   - Allow multiple storage directories with independent size limits
//   - Support device balancing (e.g., fast SSD vs large HDD)
//   - Make ConsistencyChecker and EvictionManager operate per-directory
//   - Add configurable InlineStorageMaxBytes limit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/sync/errgroup"
)

const (
	dbSubDir = "db"
)

// CacheDB wraps BadgerDB with cache-specific operations
type CacheDB struct {
	db        *badger.DB
	encMgr    *EncryptionManager
	baseDir   string
	salt      []byte // random salt for hashing object/instance names
	closeOnce sync.Once

	// usageMu protects usageMergeOps for lazy creation of merge operators
	usageMu       sync.RWMutex
	usageMergeOps map[StorageUsageKey]*badger.MergeOperator
}

// NewCacheDB creates and initializes a new cache database.
//
// Requires issuer keys to be initialized via config.GetIssuerPublicJWKS() or
// InitIssuerKeyForTests() before calling this function.
func NewCacheDB(ctx context.Context, baseDir string) (*CacheDB, error) {
	dbPath := filepath.Join(baseDir, dbSubDir)

	// Ensure directory exists
	if err := os.MkdirAll(dbPath, 0750); err != nil {
		return nil, errors.Wrap(err, "failed to create database directory")
	}

	// Initialize encryption manager first
	encMgr, err := NewEncryptionManager(baseDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize encryption manager")
	}

	// Configure BadgerDB with optimized settings for cache workload
	opts := badger.DefaultOptions(dbPath)

	// Performance: Disable synchronous writes for cache data
	// Risk: Power loss may lose last few seconds of 'access history' or 'download state'
	// Mitigation: Cache is self-healing; missing blocks will simply be re-downloaded
	opts.SyncWrites = false

	// Storage: Force small values into LSM tree
	// Bitmaps and usage counters need fast merge speeds
	opts.ValueThreshold = 4096

	// Reduce logging noise
	opts.Logger = newBadgerLogger()

	// Encrypt BadgerDB at rest so that metadata (ETags, URLs, timestamps)
	// stored in LSM tree and WAL files is not readable without the key.
	// We derive a separate key from the master key using HKDF for proper
	// key separation (the master key itself encrypts data blocks).
	dbKey, err := encMgr.DeriveDBKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive database encryption key")
	}
	opts.EncryptionKey = dbKey
	opts.EncryptionKeyRotationDuration = 0 // Disable rotation; we manage keys ourselves
	// BadgerDB requires IndexCacheSize > 0 when encryption is enabled
	opts.IndexCacheSize = 64 << 20 // 64 MB

	// Open the database
	db, err := badger.Open(opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open BadgerDB")
	}

	cdb := &CacheDB{
		db:            db,
		encMgr:        encMgr,
		baseDir:       baseDir,
		usageMergeOps: make(map[StorageUsageKey]*badger.MergeOperator),
	}

	// Load or generate the hash salt.  The salt is persisted in the DB
	// so that object/instance hashes are stable across restarts.
	salt, err := cdb.loadOrCreateSalt()
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to initialise hash salt")
	}
	cdb.salt = salt

	log.Infof("Cache database initialized at %s", dbPath)
	return cdb, nil
}

// Close closes the database.  All usage MergeOperators are stopped first
// (blocking until their background goroutines exit) so that accumulated
// deltas are flushed before the DB is closed.
func (cdb *CacheDB) Close() error {
	var closeErr error
	cdb.closeOnce.Do(func() {
		cdb.usageMu.Lock()
		for key, op := range cdb.usageMergeOps {
			op.Stop()
			delete(cdb.usageMergeOps, key)
		}
		cdb.usageMu.Unlock()

		closeErr = cdb.db.Close()
	})
	return closeErr
}

// OpenCacheDBReadOnly opens an existing cache database in read-only mode.
// This is suitable for CLI introspection tools that need to inspect cache
// contents without modifying anything.
//
// Like NewCacheDB, this requires issuer keys to be available for decrypting
// the database encryption key.
func OpenCacheDBReadOnly(baseDir string) (*CacheDB, error) {
	dbPath := filepath.Join(baseDir, dbSubDir)

	// Initialize encryption manager to get the database key
	encMgr, err := NewEncryptionManager(baseDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize encryption manager")
	}

	// Configure BadgerDB for read-only access
	opts := badger.DefaultOptions(dbPath)
	opts.ReadOnly = true
	opts.Logger = newBadgerLogger()

	// Derive the database encryption key
	dbKey, err := encMgr.DeriveDBKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive database encryption key")
	}
	opts.EncryptionKey = dbKey
	opts.EncryptionKeyRotationDuration = 0
	opts.IndexCacheSize = 64 << 20 // 64 MB

	// Open the database in read-only mode
	db, err := badger.Open(opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open BadgerDB in read-only mode")
	}

	cdb := &CacheDB{
		db:      db,
		encMgr:  encMgr,
		baseDir: baseDir,
	}

	// Load the hash salt (must exist for read operations to make sense)
	err = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(KeySalt))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			cdb.salt = make([]byte, len(val))
			copy(cdb.salt, val)
			return nil
		})
	})
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to load hash salt")
	}

	log.Debugf("Cache database opened in read-only mode at %s", dbPath)
	return cdb, nil
}

// StartGC starts the background garbage collection goroutine
func (cdb *CacheDB) StartGC(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				err := cdb.db.RunValueLogGC(0.5)
				if err != nil && !errors.Is(err, badger.ErrNoRewrite) {
					log.Warnf("BadgerDB GC error: %v", err)
				}
			}
		}
	})
}

// GetEncryptionManager returns the encryption manager
func (cdb *CacheDB) GetEncryptionManager() *EncryptionManager {
	return cdb.encMgr
}

// loadOrCreateSalt reads the hash salt from the DB, or generates a new
// random salt and persists it if none exists yet.
func (cdb *CacheDB) loadOrCreateSalt() ([]byte, error) {
	var salt []byte
	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(KeySalt))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			salt = make([]byte, len(val))
			copy(salt, val)
			return nil
		})
	})
	if err == nil {
		return salt, nil
	}
	if !errors.Is(err, badger.ErrKeyNotFound) {
		return nil, err
	}

	// No salt yet — generate one.
	salt = make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.Wrap(err, "failed to generate random salt")
	}
	if err := cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(KeySalt), salt)
	}); err != nil {
		return nil, errors.Wrap(err, "failed to persist hash salt")
	}
	return salt, nil
}

// Salt returns the per-database random salt used for hashing.
func (cdb *CacheDB) Salt() []byte { return cdb.salt }

// ObjectHash computes the salted SHA-256 hash for a pelican URL.
func (cdb *CacheDB) ObjectHash(pelicanURL string) ObjectHash {
	return ComputeObjectHash(cdb.salt, pelicanURL)
}

// InstanceHash computes the salted SHA-256 hash for (etag, objectHash).
func (cdb *CacheDB) InstanceHash(etag string, objectHash ObjectHash) InstanceHash {
	return ComputeInstanceHash(cdb.salt, etag, objectHash)
}

// --- Metadata Operations ---

// GetMetadata retrieves cache metadata for a file
func (cdb *CacheDB) GetMetadata(instanceHash InstanceHash) (*CacheMetadata, error) {
	var meta CacheMetadata

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(MetaKey(instanceHash))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return msgpack.Unmarshal(val, &meta)
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get metadata")
	}

	return &meta, nil
}

// SetMetadata stores cache metadata for a file, unconditionally replacing
// any previously stored metadata.  Use this only for initial creation of a
// metadata entry (e.g. InitDiskStorage, StoreInline); for subsequent updates
// prefer MergeMetadata which applies field-level merge semantics.
func (cdb *CacheDB) SetMetadata(instanceHash InstanceHash, meta *CacheMetadata) error {
	data, err := msgpack.Marshal(meta)
	if err != nil {
		return errors.Wrap(err, "failed to marshal metadata")
	}

	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(MetaKey(instanceHash), data)
	})
}

// MergeMetadata performs an atomic read-modify-update of the metadata for
// instanceHash.  If no metadata exists yet, incoming is written as-is (initial
// creation).
//
// Field-level merge rules:
//
//   - Max-time (LastModified, LastValidated, LastAccessTime, Expires,
//     Completed): keep the later of existing vs incoming.
//   - Additive (Checksums): union by ChecksumType; if both sides provide the
//     same Type, prefer the OriginVerified entry.
//   - Last-writer-wins (ContentType, ContentLength, VaryHeaders, CCFlags,
//     CCMaxAge): incoming replaces existing when the incoming value is non-zero /
//     non-empty.
//   - Set-once (ETag, SourceURL, DataKey, StorageID, NamespaceID): may transition
//     from zero-value to a value, but changing a non-zero value to a different
//     non-zero value returns an error.  ETag is set-once because it is part of
//     the instance hash; a changed ETag produces a different instance.
//
// The method retries on BadgerDB transaction conflicts, which can occur when
// multiple concurrent callers merge metadata for the same instance (e.g.
// concurrent range-on-miss initialization via initObjectFromStat).
func (cdb *CacheDB) MergeMetadata(instanceHash InstanceHash, incoming *CacheMetadata) error {
	const maxRetries = 20
	backoff := 100 * time.Microsecond
	for attempt := 0; ; attempt++ {
		err := cdb.db.Update(func(txn *badger.Txn) error {
			existing, err := getMetadataInTxn(txn, instanceHash)
			if err != nil {
				return errors.Wrap(err, "failed to read existing metadata for merge")
			}

			merged := incoming
			if existing != nil {
				if err := mergeMetadataFields(existing, incoming); err != nil {
					return err
				}
				merged = existing // existing was mutated in place
			}

			data, err := msgpack.Marshal(merged)
			if err != nil {
				return errors.Wrap(err, "failed to marshal merged metadata")
			}
			return txn.Set(MetaKey(instanceHash), data)
		})
		if err == nil {
			return nil
		}
		if errors.Is(err, badger.ErrConflict) && attempt < maxRetries-1 {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(backoff)))
			jitter := time.Duration(n.Int64())
			time.Sleep(backoff + jitter)
			backoff *= 2
			if backoff > 50*time.Millisecond {
				backoff = 50 * time.Millisecond
			}
			continue
		}
		return err
	}
}

// mergeMetadataFields applies incoming field values into existing according to
// the merge semantics documented on CacheMetadata.  It mutates existing in place.
func mergeMetadataFields(existing, incoming *CacheMetadata) error {
	// --- Max-time fields ---
	if incoming.LastModified.After(existing.LastModified) {
		existing.LastModified = incoming.LastModified
	}
	if incoming.LastValidated.After(existing.LastValidated) {
		existing.LastValidated = incoming.LastValidated
	}
	if incoming.LastAccessTime.After(existing.LastAccessTime) {
		existing.LastAccessTime = incoming.LastAccessTime
	}
	if incoming.Expires.After(existing.Expires) {
		existing.Expires = incoming.Expires
	}
	if incoming.Completed.After(existing.Completed) {
		existing.Completed = incoming.Completed
	}

	// --- Additive: Checksums ---
	existing.Checksums = mergeChecksums(existing.Checksums, incoming.Checksums)

	// --- Last-writer-wins (non-zero incoming replaces existing) ---
	if incoming.ContentType != "" {
		existing.ContentType = incoming.ContentType
	}
	if incoming.ContentLength != 0 {
		existing.ContentLength = incoming.ContentLength
	}
	if len(incoming.VaryHeaders) > 0 {
		existing.VaryHeaders = incoming.VaryHeaders
	}
	if incoming.CCFlags != 0 {
		existing.CCFlags = incoming.CCFlags
	}
	if incoming.CCMaxAge != 0 {
		existing.CCMaxAge = incoming.CCMaxAge
	}

	// --- Set-once fields ---
	if err := mergeSetOnce("ETag", &existing.ETag, incoming.ETag); err != nil {
		return err
	}
	if err := mergeSetOnce("SourceURL", &existing.SourceURL, incoming.SourceURL); err != nil {
		return err
	}
	if err := mergeSetOnceBytes("DataKey", &existing.DataKey, incoming.DataKey); err != nil {
		return err
	}
	if err := mergeSetOnceComparable("StorageID", &existing.StorageID, incoming.StorageID); err != nil {
		return err
	}
	if err := mergeSetOnceComparable("NamespaceID", &existing.NamespaceID, incoming.NamespaceID); err != nil {
		return err
	}

	return nil
}

// mergeChecksums returns the union of two checksum slices.  If both sides
// contain the same ChecksumType, the OriginVerified entry wins; ties go to
// incoming.
func mergeChecksums(existing, incoming []Checksum) []Checksum {
	if len(incoming) == 0 {
		return existing
	}
	if len(existing) == 0 {
		return incoming
	}

	// Build map keyed by ChecksumType.
	byType := make(map[ChecksumType]Checksum, len(existing)+len(incoming))
	for _, c := range existing {
		byType[c.Type] = c
	}
	for _, c := range incoming {
		prev, ok := byType[c.Type]
		if !ok || c.OriginVerified || !prev.OriginVerified {
			byType[c.Type] = c
		}
	}

	result := make([]Checksum, 0, len(byType))
	for _, c := range byType {
		result = append(result, c)
	}
	return result
}

// mergeSetOnce enforces set-once semantics for a string field.
func mergeSetOnce(name string, existing *string, incoming string) error {
	if incoming == "" {
		return nil // incoming is zero-value, no change
	}
	if *existing == "" {
		*existing = incoming
		return nil
	}
	if *existing != incoming {
		return errors.Errorf("set-once field %s: cannot change %q to %q", name, *existing, incoming)
	}
	return nil
}

// mergeSetOnceBytes enforces set-once semantics for a []byte field.
func mergeSetOnceBytes(name string, existing *[]byte, incoming []byte) error {
	if len(incoming) == 0 {
		return nil
	}
	if len(*existing) == 0 {
		*existing = incoming
		return nil
	}
	if !bytes.Equal(*existing, incoming) {
		return errors.Errorf("set-once field %s: cannot change non-zero value", name)
	}
	return nil
}

// mergeSetOnceComparable enforces set-once semantics for a comparable field.
func mergeSetOnceComparable[T comparable](name string, existing *T, incoming T) error {
	var zero T
	if incoming == zero {
		return nil
	}
	if *existing == zero {
		*existing = incoming
		return nil
	}
	if *existing != incoming {
		return errors.Errorf("set-once field %s: cannot change value", name)
	}
	return nil
}

// DeleteMetadata removes metadata for a file
func (cdb *CacheDB) DeleteMetadata(instanceHash InstanceHash) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(MetaKey(instanceHash))
	})
}

// --- ETag Operations ---

// GetLatestETag retrieves the latest ETag for an object.
// Returns (etag, found, err).  An object cached without an ETag will
// return ("", true, nil); an object not in the cache returns ("", false, nil).
func (cdb *CacheDB) GetLatestETag(objectHash ObjectHash) (string, bool, error) {
	var etag string

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(ETagKey(objectHash))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			etag, _ = decodeETagEntry(val)
			return nil
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return "", false, nil
		}
		return "", false, errors.Wrap(err, "failed to get latest ETag")
	}

	return etag, true, nil
}

// SetLatestETag stores the latest ETag for an object, but only if
// observedAt is more recent than the already-stored timestamp.  This
// prevents a slow download that finishes late from clobbering a newer
// ETag written by a more recent request.
func (cdb *CacheDB) SetLatestETag(objectHash ObjectHash, etag string, observedAt time.Time) error {
	key := ETagKey(objectHash)
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Read-modify-write: only update if newer.
		item, err := txn.Get(key)
		if err == nil {
			var existing time.Time
			_ = item.Value(func(val []byte) error {
				_, existing = decodeETagEntry(val)
				return nil
			})
			if !existing.IsZero() && !observedAt.After(existing) {
				return nil // existing entry is at least as recent
			}
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return txn.Set(key, encodeETagEntry(etag, observedAt))
	})
}

// DeleteLatestETag removes the ETag entry for an object
func (cdb *CacheDB) DeleteLatestETag(objectHash ObjectHash) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(ETagKey(objectHash))
	})
}

// encodeETagEntry packs an ETag and observation timestamp into a single
// byte slice: [8-byte big-endian Unix-nano timestamp][etag bytes].
func encodeETagEntry(etag string, observedAt time.Time) []byte {
	buf := make([]byte, 8+len(etag))
	binary.BigEndian.PutUint64(buf[:8], uint64(observedAt.UnixNano()))
	copy(buf[8:], etag)
	return buf
}

// decodeETagEntry unpacks an encoded ETag entry.  For legacy entries
// (no timestamp prefix), the returned time is zero.
func decodeETagEntry(val []byte) (string, time.Time) {
	if len(val) < 8 {
		return string(val), time.Time{}
	}
	nanos := int64(binary.BigEndian.Uint64(val[:8]))
	return string(val[8:]), time.Unix(0, nanos)
}

// --- Namespace Mapping Operations ---

// SetNamespaceMapping persists the mapping from a namespace prefix string
// to a numeric ID.  This ensures the IDs survive restarts so that LRU
// keys and usage counters remain valid.
func (cdb *CacheDB) SetNamespaceMapping(prefix string, id NamespaceID) error {
	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, uint32(id))
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(NamespaceKey(prefix), val)
	})
}

// LoadNamespaceMappings loads all persisted namespace mappings and returns
// them as a map[prefix]->id, along with the highest ID seen (so the
// caller can resume the counter).
func (cdb *CacheDB) LoadNamespaceMappings() (map[string]NamespaceID, NamespaceID, error) {
	result := make(map[string]NamespaceID)
	var maxID NamespaceID

	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixNamespace)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := string(item.Key()[len(prefix):])

			err := item.Value(func(val []byte) error {
				if len(val) != 4 {
					return errors.Errorf("invalid namespace ID value for %s", key)
				}
				id := NamespaceID(binary.LittleEndian.Uint32(val))
				result[key] = id
				if id > maxID {
					maxID = id
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to load namespace mappings")
	}
	return result, maxID, nil
}

// --- Disk Mapping Operations ---

// DiskMappingKey returns the BadgerDB key for a disk mapping entry.
func DiskMappingKey(storageID StorageID) []byte {
	return []byte(fmt.Sprintf("%s%d", PrefixDiskMap, storageID))
}

// SaveDiskMapping persists a single storageID → (UUID, directory) mapping.
func (cdb *CacheDB) SaveDiskMapping(dm DiskMapping) error {
	data, err := msgpack.Marshal(&dm)
	if err != nil {
		return errors.Wrap(err, "failed to marshal disk mapping")
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(DiskMappingKey(dm.ID), data)
	})
}

// LoadDiskMappings loads all persisted disk mappings.
func (cdb *CacheDB) LoadDiskMappings() ([]DiskMapping, error) {
	var mappings []DiskMapping
	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixDiskMap)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			err := it.Item().Value(func(val []byte) error {
				var dm DiskMapping
				if err := msgpack.Unmarshal(val, &dm); err != nil {
					return err
				}
				mappings = append(mappings, dm)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to load disk mappings")
	}
	return mappings, nil
}

// --- Block State Operations ---

// GetBlockState retrieves the bitmap of downloaded blocks for a file.
//
// If the block-state key is absent but the object's metadata indicates a
// completed download, a fully-populated bitmap is returned.  This allows
// callers to treat completed objects uniformly without requiring a
// separate completion check.  The block-state key is removed on
// completion to save database space (see BlockWriter.Close).
func (cdb *CacheDB) GetBlockState(instanceHash InstanceHash) (*roaring.Bitmap, error) {
	bitmap := roaring.New()

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(StateKey(instanceHash))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				// No block state key.  If the metadata says the
				// download is complete, synthesize a full bitmap.
				meta, metaErr := getMetadataInTxn(txn, instanceHash)
				if metaErr != nil || meta == nil {
					return nil // truly empty — no metadata either
				}
				if !meta.Completed.IsZero() && meta.ContentLength > 0 {
					totalBlocks := CalculateBlockCount(meta.ContentLength)
					bitmap.AddRange(0, uint64(totalBlocks))
				}
				return nil
			}
			return err
		}

		return item.Value(func(val []byte) error {
			_, err := bitmap.FromBuffer(val)
			return err
		})
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	return bitmap, nil
}

// SetBlockState stores the bitmap of downloaded blocks
func (cdb *CacheDB) SetBlockState(instanceHash InstanceHash, bitmap *roaring.Bitmap) error {
	data, err := bitmap.ToBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize bitmap")
	}

	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(StateKey(instanceHash), data)
	})
}

// MergeBlockStateWithUsage atomically merges new blocks into the existing bitmap
// AND updates usage statistics based on the number of newly-enabled bits.
//
// contentLength controls how the usage delta is calculated:
//   - If >= 0, the supplied contentLength, storageID, and namespaceID are used
//     directly, avoiding a metadata DB read.
//   - If < 0 (typically -1), the metadata is read within the transaction
//     to obtain the content length, storage ID, and namespace ID.
//
// The method retries on BadgerDB transaction conflicts, which can occur when
// multiple concurrent block fetchers write to the same object's bitmap.
func (cdb *CacheDB) MergeBlockStateWithUsage(instanceHash InstanceHash, newBlocks *roaring.Bitmap, storageID StorageID, namespaceID NamespaceID, contentLength int64) error {
	newData, err := newBlocks.ToBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize new blocks bitmap")
	}

	const maxRetries = 20
	backoff := 100 * time.Microsecond
	for attempt := 0; ; attempt++ {
		err := cdb.db.Update(func(txn *badger.Txn) error {
			return cdb.mergeBlockStateWithUsageTxn(txn, instanceHash, newData, newBlocks, storageID, namespaceID, contentLength)
		})
		if err == nil {
			return nil
		}
		if errors.Is(err, badger.ErrConflict) && attempt < maxRetries-1 {
			// Exponential backoff with jitter to avoid thundering herd
			// when many concurrent writers conflict on the same bitmap.
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(backoff)))
			jitter := time.Duration(n.Int64())
			time.Sleep(backoff + jitter)
			backoff *= 2
			if backoff > 50*time.Millisecond {
				backoff = 50 * time.Millisecond
			}
			continue
		}
		return err
	}
}

func (cdb *CacheDB) mergeBlockStateWithUsageTxn(txn *badger.Txn, instanceHash InstanceHash, newData []byte, newBlocks *roaring.Bitmap, storageID StorageID, namespaceID NamespaceID, contentLength int64) error {
	// Only merge the block bitmap.  Usage is now charged upfront at
	// file-creation time (InitDiskStorage / AllocateChunk / StoreInline)
	// to match the filesystem's pre-allocation.
	//
	// The function is kept separate from mergeBlocKStateInTxn in case we
	// ever want to do some interesting usage accounting.
	_, err := mergeBlockStateInTxn(txn, instanceHash, newData)
	return err
}

// mergeBlockStateInTxn performs the bitmap merge within an existing transaction.
// Returns the number of newly-enabled bits (blocks that were not previously set).
func mergeBlockStateInTxn(txn *badger.Txn, instanceHash InstanceHash, newData []byte) (uint64, error) {
	key := StateKey(instanceHash)

	// Get existing bitmap
	existing := roaring.New()
	item, err := txn.Get(key)
	if err == nil {
		err = item.Value(func(val []byte) error {
			_, err := existing.FromBuffer(val)
			return err
		})
		if err != nil {
			return 0, errors.Wrap(err, "failed to deserialize existing bitmap")
		}
	} else if !errors.Is(err, badger.ErrKeyNotFound) {
		return 0, err
	}

	previousCardinality := existing.GetCardinality()

	// Merge bitmaps using OR operation
	newBitmap := roaring.New()
	if _, err := newBitmap.FromBuffer(newData); err != nil {
		return 0, errors.Wrap(err, "failed to deserialize new bitmap")
	}
	existing.Or(newBitmap)

	newCardinality := existing.GetCardinality()

	// Save merged result
	mergedData, err := existing.ToBytes()
	if err != nil {
		return 0, errors.Wrap(err, "failed to serialize merged bitmap")
	}

	if err := txn.Set(key, mergedData); err != nil {
		return 0, err
	}

	return newCardinality - previousCardinality, nil
}

// getMetadataInTxn reads CacheMetadata within an existing transaction.
// Returns nil (not an error) if the key does not exist.
func getMetadataInTxn(txn *badger.Txn, instanceHash InstanceHash) (*CacheMetadata, error) {
	item, err := txn.Get(MetaKey(instanceHash))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, err
	}

	var meta CacheMetadata
	err = item.Value(func(val []byte) error {
		return msgpack.Unmarshal(val, &meta)
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal metadata in txn")
	}
	return &meta, nil
}

// encodeUsage serializes an int64 usage value into 8 little-endian bytes.
func encodeUsage(v int64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(v))
	return buf
}

// decodeUsage deserializes 8 little-endian bytes into an int64 usage value,
// clamping negative values to zero.  Returns 0 if the slice is too short.
func decodeUsage(b []byte) int64 {
	if len(b) < 8 {
		return 0
	}
	v := int64(binary.LittleEndian.Uint64(b))
	if v < 0 {
		return 0
	}
	return v
}

// decodeUsageRaw is like decodeUsage but does not clamp negative values.
// It is used by usageMergeFunc where intermediate negative totals must
// be preserved so that out-of-order deltas eventually converge.
func decodeUsageRaw(b []byte) int64 {
	if len(b) < 8 {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(b))
}

// usageMergeFunc is the merge function for BadgerDB MergeOperators.
// Both existingVal and newVal are 8-byte little-endian int64 values.
// The result is their sum.  Intermediate negative totals are allowed
// (e.g. when deletion deltas arrive before the corresponding charge)
// and are clamped to zero at read time.
func usageMergeFunc(existingVal, newVal []byte) []byte {
	return encodeUsage(decodeUsageRaw(existingVal) + decodeUsageRaw(newVal))
}

// usageCompactionInterval controls how often the MergeOperator background
// goroutine compacts accumulated delta versions into a single value.
const usageCompactionInterval = 1 * time.Second

// getUsageMergeOp returns the MergeOperator for the given usage key,
// creating one lazily if it does not yet exist.
func (cdb *CacheDB) getUsageMergeOp(storageID StorageID, namespaceID NamespaceID) *badger.MergeOperator {
	key := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}

	cdb.usageMu.RLock()
	op, ok := cdb.usageMergeOps[key]
	cdb.usageMu.RUnlock()
	if ok {
		return op
	}

	cdb.usageMu.Lock()
	defer cdb.usageMu.Unlock()
	// Double-check after acquiring write lock
	if op, ok = cdb.usageMergeOps[key]; ok {
		return op
	}
	op = cdb.db.GetMergeOperator(UsageKey(storageID, namespaceID), usageMergeFunc, usageCompactionInterval)
	cdb.usageMergeOps[key] = op
	return op
}

// AddUsage atomically adjusts the namespace-scoped usage counter by delta
// bytes.  Internally this uses BadgerDB's MergeOperator so that the write
// is append-only (no read-modify-write cycle) and cannot conflict with
// concurrent transactions.
func (cdb *CacheDB) AddUsage(storageID StorageID, namespaceID NamespaceID, delta int64) error {
	if delta == 0 {
		return nil
	}
	return cdb.getUsageMergeOp(storageID, namespaceID).Add(encodeUsage(delta))
}

// ChargeUsage is an alias for AddUsage for backward compatibility.
func (cdb *CacheDB) ChargeUsage(storageID StorageID, namespaceID NamespaceID, delta int64) error {
	return cdb.AddUsage(storageID, namespaceID, delta)
}

// StorageUsageKey combines storage ID and namespace ID for usage tracking
type StorageUsageKey struct {
	StorageID   StorageID
	NamespaceID NamespaceID
}

// MarkBlocksDownloaded marks specific blocks as downloaded and atomically
// updates usage statistics based on the number of newly-added blocks.
// Usage tracking requires metadata to be set for the instanceHash;
// if metadata is not yet available, the bitmap is still updated but
// usage tracking is skipped.
func (cdb *CacheDB) MarkBlocksDownloaded(instanceHash InstanceHash, startBlock, endBlock uint32, storageID StorageID, namespaceID NamespaceID, contentLength int64) error {
	newBlocks := roaring.New()
	newBlocks.AddRange(uint64(startBlock), uint64(endBlock)+1)
	return cdb.MergeBlockStateWithUsage(instanceHash, newBlocks, storageID, namespaceID, contentLength)
}

// ClearBlocks removes the specified blocks from the downloaded bitmap so they
// will be re-fetched on the next read.  This is used during auto-repair when
// corruption is detected.
func (cdb *CacheDB) ClearBlocks(instanceHash InstanceHash, blocks []uint32) error {
	if len(blocks) == 0 {
		return nil
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		key := StateKey(instanceHash)
		bitmap := roaring.New()

		item, err := txn.Get(key)
		if err == nil {
			err = item.Value(func(val []byte) error {
				_, err := bitmap.FromBuffer(val)
				return err
			})
			if err != nil {
				return errors.Wrap(err, "failed to deserialize bitmap")
			}
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}

		for _, b := range blocks {
			bitmap.Remove(b)
		}

		data, err := bitmap.ToBytes()
		if err != nil {
			return errors.Wrap(err, "failed to serialize bitmap")
		}
		return txn.Set(key, data)
	})
}

// IsBlockDownloaded checks if a specific block has been downloaded
func (cdb *CacheDB) IsBlockDownloaded(instanceHash InstanceHash, blockNum uint32) (bool, error) {
	bitmap, err := cdb.GetBlockState(instanceHash)
	if err != nil {
		return false, err
	}
	return bitmap.Contains(blockNum), nil
}

// GetDownloadedBlockCount returns the number of downloaded blocks
func (cdb *CacheDB) GetDownloadedBlockCount(instanceHash InstanceHash) (uint64, error) {
	bitmap, err := cdb.GetBlockState(instanceHash)
	if err != nil {
		return 0, err
	}
	return bitmap.GetCardinality(), nil
}

// DeleteBlockState removes block state for a file
func (cdb *CacheDB) DeleteBlockState(instanceHash InstanceHash) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(StateKey(instanceHash))
	})
}

// --- Inline Data Operations ---

// GetInlineData retrieves encrypted inline data for a small file
func (cdb *CacheDB) GetInlineData(instanceHash InstanceHash) ([]byte, error) {
	var data []byte

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(InlineKey(instanceHash))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			data = make([]byte, len(val))
			copy(data, val)
			return nil
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get inline data")
	}

	return data, nil
}

// SetInlineData stores encrypted inline data for a small file.
// The caller (StoreInline) is responsible for usage accounting via
// ChargeUsage; this function does NOT adjust usage counters.
func (cdb *CacheDB) SetInlineData(instanceHash InstanceHash, encryptedData []byte) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(InlineKey(instanceHash), encryptedData)
	})
}

// --- LRU Operations ---

// UpdateLRU updates the LRU access time for a file
// Uses debouncing: only updates if last access was more than debounceTime ago
// This is optimized to avoid iteration by storing the last access time in metadata
func (cdb *CacheDB) UpdateLRU(instanceHash InstanceHash, debounceTime time.Duration) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Get metadata to find prefixID and last access time
		item, err := txn.Get(MetaKey(instanceHash))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil // No metadata, nothing to update
			}
			return errors.Wrap(err, "failed to get metadata for LRU update")
		}

		var meta CacheMetadata
		err = item.Value(func(val []byte) error {
			return msgpack.Unmarshal(val, &meta)
		})
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal metadata")
		}

		now := time.Now()

		// Check debounce using metadata's last access time
		if !meta.LastAccessTime.IsZero() && now.Sub(meta.LastAccessTime) < debounceTime {
			return nil // Too recent, skip update
		}

		// Delete old LRU key if we have a previous access time
		if !meta.LastAccessTime.IsZero() {
			oldKey := LRUKey(meta.StorageID, meta.NamespaceID, meta.LastAccessTime, instanceHash)
			if err := txn.Delete(oldKey); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
				return errors.Wrap(err, "failed to delete old LRU key")
			}
		}

		// Set new LRU key
		newKey := LRUKey(meta.StorageID, meta.NamespaceID, now, instanceHash)
		if err := txn.Set(newKey, nil); err != nil {
			return errors.Wrap(err, "failed to set new LRU key")
		}

		// Update metadata with new access time
		meta.LastAccessTime = now
		metaData, err := msgpack.Marshal(&meta)
		if err != nil {
			return errors.Wrap(err, "failed to marshal updated metadata")
		}
		return txn.Set(MetaKey(instanceHash), metaData)
	})
}

// --- Usage Counter Operations ---

// GetUsage retrieves the total bytes used by a storage+namespace combination.
// If a MergeOperator is active for the key, its Get() method is used to
// replay all accumulated deltas; otherwise a raw read is performed.
func (cdb *CacheDB) GetUsage(storageID StorageID, namespaceID NamespaceID) (int64, error) {
	key := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}

	cdb.usageMu.RLock()
	op, hasOp := cdb.usageMergeOps[key]
	cdb.usageMu.RUnlock()

	if hasOp {
		val, err := op.Get()
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return 0, nil
			}
			return 0, errors.Wrap(err, "failed to get usage")
		}
		return decodeUsage(val), nil
	}

	// No active merge operator — raw read (dormant key from prior run).
	var usage int64
	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(UsageKey(storageID, namespaceID))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) < 8 {
				return errors.New("invalid usage value")
			}
			usage = decodeUsage(val)
			return nil
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return 0, nil
		}
		return 0, errors.Wrap(err, "failed to get usage")
	}
	return usage, nil
}

// GetAllUsage returns usage for all storage+namespace combinations
func (cdb *CacheDB) GetAllUsage() (map[StorageUsageKey]int64, error) {
	return cdb.getUsageByPrefix([]byte(PrefixUsage))
}

// ComputeInlineDataSize scans all inline data entries (d: prefix) and sums
// the stored value sizes.  This gives the actual bytes consumed in BadgerDB
// for inline object data (excluding metadata overhead).
func (cdb *CacheDB) ComputeInlineDataSize() (int64, error) {
	var total int64
	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixInline)
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			total += int64(it.Item().ValueSize())
		}
		return nil
	})
	return total, err
}

// GetDirUsage returns usage for all namespaces within a single storage directory.
func (cdb *CacheDB) GetDirUsage(storageID StorageID) (map[NamespaceID]int64, error) {
	prefix := []byte(fmt.Sprintf("%s%d:", PrefixUsage, storageID))
	full, err := cdb.getUsageByPrefix(prefix)
	if err != nil {
		return nil, err
	}
	result := make(map[NamespaceID]int64, len(full))
	for key, usage := range full {
		result[key.NamespaceID] = usage
	}
	return result, nil
}

// getUsageByPrefix returns usage for all keys matching the given prefix.
// Active MergeOperators are consulted first; dormant keys (no operator)
// are read via a normal prefix scan.
func (cdb *CacheDB) getUsageByPrefix(prefix []byte) (map[StorageUsageKey]int64, error) {
	usage := make(map[StorageUsageKey]int64)

	// Phase 1: read from active merge operators whose keys match prefix.
	activeKeys := make(map[string]bool)
	cdb.usageMu.RLock()
	for suk, op := range cdb.usageMergeOps {
		dbKey := UsageKey(suk.StorageID, suk.NamespaceID)
		if !bytes.HasPrefix(dbKey, prefix) {
			continue
		}
		val, err := op.Get()
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				continue
			}
			cdb.usageMu.RUnlock()
			return nil, errors.Wrap(err, "failed to get usage from merge operator")
		}
		if len(val) >= 8 {
			usage[suk] = decodeUsage(val)
		}
		activeKeys[string(dbKey)] = true
	}
	cdb.usageMu.RUnlock()

	// Phase 2: scan the DB for keys without active operators.
	err := cdb.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()

			if activeKeys[string(key)] {
				continue
			}

			storageID, namespaceID, err := ParseUsageKey(key)
			if err != nil {
				continue
			}

			err = item.Value(func(val []byte) error {
				if len(val) >= 8 {
					usageKey := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}
					usage[usageKey] = decodeUsage(val)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return usage, err
}

// SetUsage sets the absolute usage counter for a (storageID, namespaceID)
// pair.  Any active MergeOperator for the key is stopped first (flushing
// pending deltas) and then the value is overwritten.
//
// The entry is written with WithDiscard() so that BadgerDB marks all
// earlier versions of the key as eligible for garbage collection.
// Without this flag, the MergeOperator's iterateAndMerge would still
// see the old compacted entry (which carries bitDiscardEarlierVersions)
// and sum it into the total, causing the counter to include both the
// new baseline and the old accumulated value — a compounding overcount
// that grows with every reconciliation cycle.
//
// The next AddUsage call will lazily create a fresh MergeOperator.
func (cdb *CacheDB) SetUsage(storageID StorageID, namespaceID NamespaceID, value int64) error {
	suk := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}

	cdb.usageMu.Lock()
	if op, ok := cdb.usageMergeOps[suk]; ok {
		op.Stop()
		delete(cdb.usageMergeOps, suk)
	}
	cdb.usageMu.Unlock()

	if value < 0 {
		value = 0
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(badger.NewEntry(UsageKey(storageID, namespaceID), encodeUsage(value)).WithDiscard())
	})
}

// ComputeActualUsage performs a full scan of the metadata table to compute
// the real byte-level usage per (StorageID, NamespaceID).
//
// Completed objects contribute their full ContentLength.  In-progress
// objects contribute the bytes implied by their block bitmap.
//
// This is an expensive read-only operation.  The consistency checker
// accumulates usage during its metadata scan instead of calling this;
// it is retained for ad-hoc diagnostics and tests.
func (cdb *CacheDB) ComputeActualUsage() (map[StorageUsageKey]int64, error) {
	actual := make(map[StorageUsageKey]int64)

	err := cdb.db.View(func(txn *badger.Txn) error {
		metaPrefix := []byte(PrefixMeta)
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(metaPrefix); it.ValidForPrefix(metaPrefix); it.Next() {
			item := it.Item()
			metaKey := item.Key()
			instanceHash := InstanceHash(metaKey[len(PrefixMeta):])

			// Decode metadata to get StorageID, NamespaceID, ContentLength.
			var meta CacheMetadata
			err := item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &meta)
			})
			if err != nil {
				log.Warnf("ComputeActualUsage: failed to unmarshal metadata for %s: %v", instanceHash, err)
				continue
			}

			key := StorageUsageKey{StorageID: meta.StorageID, NamespaceID: meta.NamespaceID}

			// Both completed and in-progress objects are charged at their
			// full ContentLength, matching the upfront-charge model where
			// usage is reserved at file-creation time.
			if meta.ContentLength > 0 {
				actual[key] += meta.ContentLength
			}
		}
		return nil
	})

	return actual, err
}

// --- Bulk Operations ---

// deleteObjectInTxn removes all DB keys for a cached object within an
// existing transaction.  It returns the decoded metadata (if present) so
// the caller can decide what to do with filesystem files and usage
// counters.  The caller is responsible for usage adjustments — this
// function does NOT modify usage counters.
//
// salt is required to recompute the ObjectHash from SourceURL for
// ETag-table cleanup.
func deleteObjectInTxn(txn *badger.Txn, salt []byte, instanceHash InstanceHash) (*CacheMetadata, error) {
	var meta CacheMetadata
	var hasMetadata bool

	item, err := txn.Get(MetaKey(instanceHash))
	if err == nil {
		hasMetadata = true
		err = item.Value(func(val []byte) error {
			return msgpack.Unmarshal(val, &meta)
		})
		if err != nil {
			log.Warnf("Failed to unmarshal metadata during object deletion: %v", err)
			hasMetadata = false
		}
	} else if !errors.Is(err, badger.ErrKeyNotFound) {
		return nil, errors.Wrap(err, "failed to get metadata for deletion")
	}

	// Delete LRU entry using metadata (before deleting metadata)
	if hasMetadata && !meta.LastAccessTime.IsZero() {
		lruKey := LRUKey(meta.StorageID, meta.NamespaceID, meta.LastAccessTime, instanceHash)
		if err := txn.Delete(lruKey); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.Wrap(err, "failed to delete LRU key")
		}
	}

	// Clean up ETag table if this was the latest version.
	// ObjectHash is derived from SourceURL + salt rather than stored
	// redundantly in metadata.
	if hasMetadata && meta.SourceURL != "" {
		objectHash := ComputeObjectHash(salt, meta.SourceURL)
		etagItem, err := txn.Get(ETagKey(objectHash))
		if err == nil {
			var currentETag string
			err = etagItem.Value(func(val []byte) error {
				currentETag = string(val)
				return nil
			})
			if err == nil && currentETag == meta.ETag {
				if err := txn.Delete(ETagKey(objectHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
					log.Warnf("Failed to delete ETag entry for %s: %v", objectHash, err)
				}
			}
		}
	}

	// Delete metadata
	if err := txn.Delete(MetaKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return nil, err
	}

	// Delete block state
	if err := txn.Delete(StateKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return nil, err
	}

	// Delete inline data if stored inline
	if hasMetadata && meta.IsInline() {
		if err := txn.Delete(InlineKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return nil, err
		}
	}

	// Delete purge-first marker if present (best-effort, ignore not-found)
	_ = txn.Delete(PurgeFirstKey(instanceHash))

	if hasMetadata {
		return &meta, nil
	}
	return nil, nil
}

// DeleteObject removes all data for a cached object.
// Uses metadata to compute exact LRU key for efficient deletion.
// Also cleans up ETag table, purge-first marker, and adjusts usage
// counters.  Usage is decremented via AddUsage after the transaction
// commits so that the write cannot conflict.
func (cdb *CacheDB) DeleteObject(instanceHash InstanceHash) error {
	var meta *CacheMetadata
	err := cdb.db.Update(func(txn *badger.Txn) error {
		var txnErr error
		meta, txnErr = deleteObjectInTxn(txn, cdb.salt, instanceHash)
		return txnErr
	})
	if err != nil {
		return err
	}
	if meta != nil {
		// Deduct the on-disk size (content + per-block MAC overhead)
		// to match what was charged in InitDiskStorage / AllocateChunk.
		// Inline objects have no MAC overhead.
		for sid, bytes := range meta.PerDirectoryBytes() {
			if err := cdb.AddUsage(sid, meta.NamespaceID, -bytes); err != nil {
				log.Warnf("Failed to decrease usage for storage %d namespace %d: %v",
					sid, meta.NamespaceID, err)
			}
		}
	}
	return nil
}

// evictedObject holds the information needed to clean up the filesystem
// after the DB transaction commits.
type evictedObject struct {
	instanceHash   InstanceHash
	storageID      StorageID
	contentLen     int64
	namespaceID    NamespaceID
	chunkSizeCode  ChunkSizeCode   // For chunked objects
	chunkLocations []ChunkLocation // Locations of chunks 1, 2, ...
}

// EvictByLRU evicts objects from a storage+namespace combination, draining
// purge-first items before walking the regular LRU index — all within a
// single BadgerDB transaction.
//
// Eviction stops when either maxObjects have been removed or maxBytes of
// content has been freed — whichever comes first.  A value of 0 for
// either limit means "no limit on that dimension".  The method is allowed
// to go one object over the byte threshold so that progress is always
// made even when only large objects remain.
func (cdb *CacheDB) EvictByLRU(storageID StorageID, namespaceID NamespaceID, maxObjects int, maxBytes int64) ([]evictedObject, error) {
	var evicted []evictedObject
	usageDeltas := make(map[StorageUsageKey]int64)

	err := cdb.db.Update(func(txn *badger.Txn) error {
		var freedBytes int64

		// --- helper: returns true when we should stop evicting ---
		limitReached := func() bool {
			if maxObjects > 0 && len(evicted) >= maxObjects {
				return true
			}
			if maxBytes > 0 && freedBytes >= maxBytes {
				return true
			}
			return false
		}

		// --- helper: delete one object by hash, record results ---
		evictOne := func(hash InstanceHash) {
			meta, err := deleteObjectInTxn(txn, cdb.salt, hash)
			if err != nil {
				log.Warnf("Failed to delete object %s during eviction: %v", hash, err)
				return
			}
			if meta == nil {
				return
			}
			evicted = append(evicted, evictedObject{
				instanceHash:   hash,
				storageID:      meta.StorageID,
				contentLen:     meta.ContentLength,
				namespaceID:    meta.NamespaceID,
				chunkSizeCode:  meta.ChunkSizeCode,
				chunkLocations: meta.ChunkLocations,
			})
			// For chunked objects, decrement usage from each storage
			// based on the on-disk bytes it holds.  For
			// non-chunked objects this returns a single entry for the
			// base StorageID with CalculateFileSize(ContentLength).
			for sid, bytes := range meta.PerDirectoryBytes() {
				key := StorageUsageKey{StorageID: sid, NamespaceID: meta.NamespaceID}
				usageDeltas[key] -= bytes
			}
			if meta.StorageID == StorageIDInline {
				freedBytes += meta.ContentLength
			} else {
				freedBytes += CalculateFileSize(meta.ContentLength)
			}
		}

		// objectUsesDir reports whether an object touches the given
		// storage directory — either as its base or via any chunk.
		objectUsesDir := func(meta *CacheMetadata, sid StorageID) bool {
			if meta.StorageID == sid {
				return true
			}
			for _, loc := range meta.ChunkLocations {
				if loc.StorageID == sid {
					return true
				}
			}
			return false
		}

		// Phase 1: drain purge-first items for this storageID.
		// Walk the pf: prefix; for each item whose metadata matches
		// the requested storageID (base or chunk), evict it immediately.
		{
			pfPrefix := []byte(PrefixPurgeFirst)
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false

			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(pfPrefix); it.ValidForPrefix(pfPrefix); it.Next() {
				if limitReached() {
					break
				}
				keyStr := string(it.Item().Key())
				hash := InstanceHash(keyStr[len(PrefixPurgeFirst):])
				if hash == "" {
					continue
				}

				// Peek at metadata to check storageID.
				metaItem, err := txn.Get(MetaKey(hash))
				if err != nil {
					// Object already gone — clean up stale marker.
					_ = txn.Delete(it.Item().KeyCopy(nil))
					continue
				}
				var meta CacheMetadata
				err = metaItem.Value(func(val []byte) error {
					return msgpack.Unmarshal(val, &meta)
				})
				if err != nil {
					continue
				}
				if !objectUsesDir(&meta, storageID) {
					continue
				}

				evictOne(hash)
			}
		}

		// Phase 2: walk the LRU index for the requested storage+namespace.
		// This finds objects whose base (chunk 0) is in storageID.
		if !limitReached() {
			lruPrefix := []byte(fmt.Sprintf("%s%d:%d:", PrefixLRU, storageID, namespaceID))
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false

			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(lruPrefix); it.ValidForPrefix(lruPrefix); it.Next() {
				_, _, _, hash, err := ParseLRUKey(it.Item().Key())
				if err != nil {
					continue
				}
				evictOne(hash)
				if limitReached() {
					break
				}
			}
		}

		// Phase 3: cross-directory scan for chunked objects.
		// If Phase 2 was not sufficient, scan ALL LRU entries for
		// the requested namespace.  For each candidate whose base
		// lives in another directory, check whether any of its chunk
		// locations reference storageID.  Skip entries that were
		// already evicted in Phase 2 (their metadata will be gone).
		if !limitReached() {
			nsLRUPrefix := fmt.Appendf(nil, "%s", PrefixLRU)
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false

			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(nsLRUPrefix); it.ValidForPrefix(nsLRUPrefix); it.Next() {
				if limitReached() {
					break
				}
				lruSID, lruNS, _, hash, err := ParseLRUKey(it.Item().Key())
				if err != nil {
					continue
				}
				// Skip the namespace we already scanned in Phase 2,
				// or different namespaces.
				if lruNS != namespaceID {
					continue
				}
				if lruSID == storageID {
					continue // already covered by Phase 2
				}

				// Peek at metadata to check chunk locations.
				metaItem, err := txn.Get(MetaKey(hash))
				if err != nil {
					continue
				}
				var meta CacheMetadata
				err = metaItem.Value(func(val []byte) error {
					return msgpack.Unmarshal(val, &meta)
				})
				if err != nil {
					continue
				}
				if !meta.IsChunked() {
					continue
				}
				if !objectUsesDir(&meta, storageID) {
					continue
				}
				evictOne(hash)
			}
		}

		return nil
	})

	// Apply accumulated usage decrements via MergeOperator (outside
	// the eviction transaction so they cannot cause conflicts).
	for key, delta := range usageDeltas {
		if err := cdb.AddUsage(key.StorageID, key.NamespaceID, delta); err != nil {
			log.Warnf("Failed to decrease usage for storage %d namespace %d: %v",
				key.StorageID, key.NamespaceID, err)
		}
	}

	return evicted, err
}

// badgerLogger adapts Pelican's logrus to BadgerDB's logger interface
type badgerLogger struct {
	log *log.Entry
}

func newBadgerLogger() *badgerLogger {
	return &badgerLogger{log: log.WithField("component", "BadgerDB")}
}

func (l *badgerLogger) Errorf(format string, args ...interface{}) {
	l.log.Errorf(format, args...)
}

func (l *badgerLogger) Warningf(format string, args ...interface{}) {
	l.log.Warnf(format, args...)
}

func (l *badgerLogger) Infof(format string, args ...interface{}) {
	l.log.Debugf(format, args...)
}

func (l *badgerLogger) Debugf(format string, args ...interface{}) {
	l.log.Tracef(format, args...)
}

// Verify badgerLogger satisfies the interface
var _ badger.Logger = (*badgerLogger)(nil)

// ScanMetadata iterates over all metadata entries
func (cdb *CacheDB) ScanMetadata(fn func(instanceHash InstanceHash, meta *CacheMetadata) error) error {
	return cdb.ScanMetadataFrom("", fn)
}

// ScanMetadataFrom scans metadata starting from the given instanceHash (empty string = start from beginning)
func (cdb *CacheDB) ScanMetadataFrom(startKey InstanceHash, fn func(instanceHash InstanceHash, meta *CacheMetadata) error) error {
	return cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixMeta)
		opts := badger.DefaultIteratorOptions

		it := txn.NewIterator(opts)
		defer it.Close()

		// Seek to the starting position
		seekKey := prefix
		if startKey != "" {
			seekKey = MetaKey(startKey)
		}

		for it.Seek(seekKey); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := string(item.Key())
			instanceHash := InstanceHash(key[len(PrefixMeta):])

			// Skip the start key itself if resuming (we already processed it)
			if startKey != "" && instanceHash == startKey {
				continue
			}

			var meta CacheMetadata
			err := item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &meta)
			})
			if err != nil {
				log.Warnf("Failed to unmarshal metadata for %s: %v", instanceHash, err)
				continue
			}

			if err := fn(instanceHash, &meta); err != nil {
				return err
			}
		}
		return nil
	})
}

// HasMetadata checks if metadata exists for a file
func (cdb *CacheDB) HasMetadata(instanceHash InstanceHash) (bool, error) {
	var exists bool
	err := cdb.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(MetaKey(instanceHash))
		if err == nil {
			exists = true
		} else if errors.Is(err, badger.ErrKeyNotFound) {
			exists = false
		} else {
			return err
		}
		return nil
	})
	return exists, err
}

// Batch allows batching multiple writes for efficiency
type Batch struct {
	wb *badger.WriteBatch
}

// NewBatch creates a new write batch
func (cdb *CacheDB) NewBatch() *Batch {
	return &Batch{wb: cdb.db.NewWriteBatch()}
}

// Set adds a key-value pair to the batch
func (b *Batch) Set(key, value []byte) error {
	return b.wb.Set(key, value)
}

// Delete adds a delete operation to the batch
func (b *Batch) Delete(key []byte) error {
	return b.wb.Delete(key)
}

// Flush commits the batch
func (b *Batch) Flush() error {
	return b.wb.Flush()
}

// Cancel discards the batch
func (b *Batch) Cancel() {
	b.wb.Cancel()
}

// --- Purge First Operations ---

// MarkPurgeFirst marks a file hash for priority eviction
func (cdb *CacheDB) MarkPurgeFirst(instanceHash InstanceHash) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Check if metadata exists first
		_, err := txn.Get(MetaKey(instanceHash))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return errors.New("object not found in cache")
			}
			return err
		}
		// Set the purge first marker
		return txn.Set(PurgeFirstKey(instanceHash), []byte{1})
	})
}

// UnmarkPurgeFirst removes the purge first marker for a file hash
func (cdb *CacheDB) UnmarkPurgeFirst(instanceHash InstanceHash) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(PurgeFirstKey(instanceHash))
	})
}

// IsPurgeFirst checks if a file hash is marked for priority eviction
func (cdb *CacheDB) IsPurgeFirst(instanceHash InstanceHash) (bool, error) {
	var isPurgeFirst bool
	err := cdb.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(PurgeFirstKey(instanceHash))
		if err == nil {
			isPurgeFirst = true
		} else if errors.Is(err, badger.ErrKeyNotFound) {
			isPurgeFirst = false
		} else {
			return err
		}
		return nil
	})
	return isPurgeFirst, err
}

// FindRecyclableStorageID searches persisted disk mappings for the
// unmounted storageID with the least usage.  mountedDirs maps storageID
// to directory path for IDs currently assigned to live directories —
// those are excluded.  Returns the storageID and nil on success, or an
// error if no recyclable ID exists.
func (cdb *CacheDB) FindRecyclableStorageID(mountedDirs map[StorageID]string) (StorageID, error) {
	mappings, err := cdb.LoadDiskMappings()
	if err != nil {
		return 0, errors.Wrap(err, "failed to load disk mappings")
	}

	bestID := StorageID(0)
	bestUsage := int64(-1)
	found := false

	for _, dm := range mappings {
		if _, mounted := mountedDirs[dm.ID]; mounted {
			continue // still in use
		}

		// Sum usage across all namespaces for this storageID.
		dirUsage, err := cdb.GetDirUsage(dm.ID)
		if err != nil {
			log.Warnf("Failed to read usage for storage %d during recycle scan: %v", dm.ID, err)
			continue
		}
		var total int64
		for _, u := range dirUsage {
			total += u
		}

		if !found || total < bestUsage || (total == bestUsage && dm.ID < bestID) {
			bestID = dm.ID
			bestUsage = total
			found = true
		}
	}

	if !found {
		return 0, errors.New("no recyclable storage IDs available")
	}

	log.Infof("Selected storage ID %d (usage %d bytes) for recycling", bestID, bestUsage)
	return bestID, nil
}

// PurgeStorageID removes all database entries associated with a storageID:
// object metadata, block state, inline data, LRU entries, purge-first
// markers, ETag entries, usage counters, and the disk mapping itself.
//
// This is used during storage ID recycling to reclaim an ID that was
// previously assigned to a directory that is no longer mounted.
//
// Objects are deleted in batches to avoid exceeding BadgerDB's
// transaction size limit.
func (cdb *CacheDB) PurgeStorageID(storageID StorageID) error {
	const batchSize = 500

	lruPrefix := []byte(fmt.Sprintf("%s%d:", PrefixLRU, storageID))
	totalDeleted := 0

	// Iterate the LRU in batch-sized chunks.  After deleting a batch the
	// iterator is invalidated, so we re-seek from the prefix on each pass.
	// The loop terminates when a scan finds no more keys.
	for {
		var hashes []InstanceHash
		err := cdb.db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(lruPrefix); it.ValidForPrefix(lruPrefix); it.Next() {
				_, _, _, hash, err := ParseLRUKey(it.Item().Key())
				if err != nil {
					continue
				}
				hashes = append(hashes, hash)
				if len(hashes) >= batchSize {
					break
				}
			}
			return nil
		})
		if err != nil {
			return errors.Wrap(err, "failed to scan LRU entries for purge")
		}
		if len(hashes) == 0 {
			break
		}

		err = cdb.db.Update(func(txn *badger.Txn) error {
			for _, hash := range hashes {
				if _, err := deleteObjectInTxn(txn, cdb.salt, hash); err != nil {
					log.Warnf("Failed to delete object %s during storage purge: %v", hash, err)
				}
			}
			return nil
		})
		if err != nil {
			return errors.Wrapf(err, "failed to delete object batch during purge of storage %d", storageID)
		}
		totalDeleted += len(hashes)
	}

	// Clean up usage counters, any straggler LRU keys, and the disk mapping.
	err := cdb.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		// Delete all usage keys for this storageID.
		usagePrefix := []byte(fmt.Sprintf("%s%d:", PrefixUsage, storageID))
		it := txn.NewIterator(opts)
		defer it.Close()

		var usageKeys [][]byte
		for it.Seek(usagePrefix); it.ValidForPrefix(usagePrefix); it.Next() {
			usageKeys = append(usageKeys, it.Item().KeyCopy(nil))
		}
		for _, key := range usageKeys {
			if err := txn.Delete(key); err != nil {
				log.Warnf("Failed to delete usage key during purge: %v", err)
			}
		}

		// Delete any remaining LRU keys (should already be gone from
		// object deletions, but clean up in case of inconsistency).
		lruIt := txn.NewIterator(opts)
		defer lruIt.Close()

		var lruKeys [][]byte
		for lruIt.Seek(lruPrefix); lruIt.ValidForPrefix(lruPrefix); lruIt.Next() {
			lruKeys = append(lruKeys, lruIt.Item().KeyCopy(nil))
		}
		for _, key := range lruKeys {
			if err := txn.Delete(key); err != nil {
				log.Warnf("Failed to delete LRU key during purge: %v", err)
			}
		}

		// Delete the disk mapping entry.
		return txn.Delete(DiskMappingKey(storageID))
	})
	if err != nil {
		return errors.Wrapf(err, "failed to clean up usage/mapping for storage %d", storageID)
	}

	log.Infof("Purged storage ID %d: deleted %d objects", storageID, totalDeleted)
	return nil
}
