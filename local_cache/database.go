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
	opts.Logger = &badgerLogger{}

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
		db:      db,
		encMgr:  encMgr,
		baseDir: baseDir,
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

// Close closes the database
func (cdb *CacheDB) Close() error {
	var closeErr error
	cdb.closeOnce.Do(func() {
		closeErr = cdb.db.Close()
	})
	return closeErr
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
func (cdb *CacheDB) MergeMetadata(instanceHash InstanceHash, incoming *CacheMetadata) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
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

// GetLatestETag retrieves the latest ETag for an object
func (cdb *CacheDB) GetLatestETag(objectHash ObjectHash) (string, error) {
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
			return "", nil
		}
		return "", errors.Wrap(err, "failed to get latest ETag")
	}

	return etag, nil
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
	newBitCount, err := mergeBlockStateInTxn(txn, instanceHash, newData)
	if err != nil {
		return err
	}
	if newBitCount == 0 {
		return nil // No new blocks added; nothing to track
	}

	if contentLength < 0 {
		// Caller didn't supply the size — look up metadata.
		meta, err := getMetadataInTxn(txn, instanceHash)
		if err != nil || meta == nil {
			// Metadata may not exist yet (e.g., blocks written before metadata).
			// Skip usage tracking rather than failing the bitmap merge.
			return nil
		}
		contentLength = meta.ContentLength
		storageID = meta.StorageID
		namespaceID = meta.NamespaceID
	}

	meta := &CacheMetadata{ContentLength: contentLength}
	delta := calculateUsageDelta(meta, newBlocks, newBitCount)
	if delta > 0 {
		return addUsageInTxn(txn, storageID, namespaceID, delta)
	}
	return nil
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

// calculateUsageDelta returns the byte-level usage increase for newBitCount
// newly-enabled blocks. Every full block contributes BlockDataSize bytes;
// the last block of the object may be smaller.
//
// When ContentLength is unknown (<= 0), each block is treated as full-sized.
// For chunked (unknown-size) downloads, BlockWriter.Close sets ContentLength
// before marking the final block so that the last partial block is correctly
// sized.
func calculateUsageDelta(meta *CacheMetadata, newBlocks *roaring.Bitmap, newBitCount uint64) int64 {
	if newBitCount == 0 {
		return 0
	}

	if meta.ContentLength <= 0 {
		// Unknown content length: treat every block as full-sized.
		return int64(newBitCount) * int64(BlockDataSize)
	}

	totalBlocks := CalculateBlockCount(meta.ContentLength)
	lastBlock := totalBlocks - 1

	// Start by assuming all new blocks are full-sized
	delta := int64(newBitCount) * int64(BlockDataSize)

	// If the last block is among the newly-added blocks, adjust for its
	// potentially smaller size.
	if newBlocks.Contains(lastBlock) {
		remainder := meta.ContentLength % int64(BlockDataSize)
		if remainder > 0 {
			// Last block is partial: subtract the over-count
			delta -= int64(BlockDataSize) - remainder
		}
		// If remainder == 0 the last block is exactly full, no adjustment needed
	}

	return delta
}

// addUsageInTxn performs the usage counter merge within an existing transaction
func addUsageInTxn(txn *badger.Txn, storageID StorageID, namespaceID NamespaceID, delta int64) error {
	key := UsageKey(storageID, namespaceID)

	var currentUsage int64
	item, err := txn.Get(key)
	if err == nil {
		err = item.Value(func(val []byte) error {
			if len(val) >= 8 {
				currentUsage = int64(binary.LittleEndian.Uint64(val))
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else if !errors.Is(err, badger.ErrKeyNotFound) {
		return err
	}

	newUsage := currentUsage + delta
	if newUsage < 0 {
		newUsage = 0
	}

	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, uint64(newUsage))
	return txn.Set(key, data)
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

// SetInlineData stores encrypted inline data for a small file
// Also updates usage statistics for the inline storage namespace
func (cdb *CacheDB) SetInlineData(instanceHash InstanceHash, encryptedData []byte) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Check if inline data already exists to avoid double-counting
		var oldSize int64
		item, err := txn.Get(InlineKey(instanceHash))
		if err == nil {
			err = item.Value(func(val []byte) error {
				oldSize = int64(len(val))
				return nil
			})
			if err != nil {
				return err
			}
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}

		// Set the new inline data
		if err := txn.Set(InlineKey(instanceHash), encryptedData); err != nil {
			return err
		}

		// Get metadata to find namespace ID for usage tracking
		var meta CacheMetadata
		item, err = txn.Get(MetaKey(instanceHash))
		if err == nil {
			err = item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &meta)
			})
			if err != nil {
				return errors.Wrap(err, "failed to unmarshal metadata")
			}

			// Update usage: subtract old size, add new size
			delta := int64(len(encryptedData)) - oldSize
			if delta != 0 {
				if err := addUsageInTxn(txn, meta.StorageID, meta.NamespaceID, delta); err != nil {
					return errors.Wrap(err, "failed to update usage")
				}
			}
		}
		// If metadata doesn't exist yet, usage will be tracked when metadata is set

		return nil
	})
}

// DeleteInlineData removes inline data for a file
// Also decreases usage statistics for the inline storage namespace
func (cdb *CacheDB) DeleteInlineData(instanceHash InstanceHash) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Get the size of the data being deleted
		var dataSize int64
		item, err := txn.Get(InlineKey(instanceHash))
		if err == nil {
			err = item.Value(func(val []byte) error {
				dataSize = int64(len(val))
				return nil
			})
			if err != nil {
				return err
			}
		} else if errors.Is(err, badger.ErrKeyNotFound) {
			return nil // Already deleted
		} else {
			return err
		}

		// Delete the inline data
		if err := txn.Delete(InlineKey(instanceHash)); err != nil {
			return err
		}

		// Get metadata to find namespace ID for usage tracking
		var meta CacheMetadata
		item, err = txn.Get(MetaKey(instanceHash))
		if err == nil {
			err = item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &meta)
			})
			if err != nil {
				return errors.Wrap(err, "failed to unmarshal metadata")
			}

			// Decrease usage
			if err := addUsageInTxn(txn, meta.StorageID, meta.NamespaceID, -dataSize); err != nil {
				return errors.Wrap(err, "failed to update usage")
			}
		}
		// If metadata doesn't exist, can't track usage decrease (orphaned inline data)

		return nil
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

// GetUsage retrieves the total bytes used by a storage+namespace combination
func (cdb *CacheDB) GetUsage(storageID StorageID, namespaceID NamespaceID) (int64, error) {
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
			usage = int64(binary.LittleEndian.Uint64(val))
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

// getUsageByPrefix scans usage keys matching the given prefix and returns
// the decoded (storageID, namespaceID) → bytes mapping.
func (cdb *CacheDB) getUsageByPrefix(prefix []byte) (map[StorageUsageKey]int64, error) {
	usage := make(map[StorageUsageKey]int64)

	err := cdb.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()

			storageID, namespaceID, err := ParseUsageKey(key)
			if err != nil {
				continue
			}

			err = item.Value(func(val []byte) error {
				if len(val) >= 8 {
					usageKey := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}
					usage[usageKey] = int64(binary.LittleEndian.Uint64(val))
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
// pair.  It overwrites the existing value (in contrast to addUsageInTxn which
// adds a delta).
func (cdb *CacheDB) SetUsage(storageID StorageID, namespaceID NamespaceID, value int64) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		key := UsageKey(storageID, namespaceID)
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(value))
		return txn.Set(key, data)
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

			// Completed objects: usage == ContentLength (bitmap is deleted on completion).
			if !meta.Completed.IsZero() {
				if meta.ContentLength > 0 {
					actual[key] += meta.ContentLength
				}
				continue
			}

			// In-progress: compute from the block bitmap.
			stateItem, err := txn.Get(StateKey(instanceHash))
			if err != nil {
				if errors.Is(err, badger.ErrKeyNotFound) {
					continue // No blocks downloaded — contributes 0 bytes
				}
				return errors.Wrapf(err, "failed to read block state for %s", instanceHash)
			}

			var objectUsage int64
			err = stateItem.Value(func(val []byte) error {
				bm := roaring.New()
				if _, err := bm.FromBuffer(val); err != nil {
					return errors.Wrapf(err, "failed to deserialize bitmap for %s", instanceHash)
				}
				cardinality := bm.GetCardinality()
				if cardinality == 0 {
					return nil
				}
				objectUsage = calculateUsageDelta(&meta, bm, cardinality)
				return nil
			})
			if err != nil {
				log.Warnf("ComputeActualUsage: %v", err)
				continue
			}

			actual[key] += objectUsage
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
// counters — all within a single transaction.
func (cdb *CacheDB) DeleteObject(instanceHash InstanceHash) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		meta, err := deleteObjectInTxn(txn, cdb.salt, instanceHash)
		if err != nil {
			return err
		}
		// Decrease usage statistics
		if meta != nil {
			if err := addUsageInTxn(txn, meta.StorageID, meta.NamespaceID, -meta.ContentLength); err != nil {
				log.Warnf("Failed to decrease usage for storage %d namespace %d: %v", meta.StorageID, meta.NamespaceID, err)
			}
		}
		return nil
	})
}

// evictedObject holds the information needed to clean up the filesystem
// after the DB transaction commits.
type evictedObject struct {
	instanceHash InstanceHash
	storageID    StorageID
	contentLen   int64
	namespaceID  NamespaceID
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

	err := cdb.db.Update(func(txn *badger.Txn) error {
		usageDeltas := make(map[StorageUsageKey]int64)
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
				instanceHash: hash,
				storageID:    meta.StorageID,
				contentLen:   meta.ContentLength,
				namespaceID:  meta.NamespaceID,
			})
			key := StorageUsageKey{StorageID: meta.StorageID, NamespaceID: meta.NamespaceID}
			usageDeltas[key] -= meta.ContentLength
			freedBytes += meta.ContentLength
		}

		// Phase 1: drain purge-first items for this storageID.
		// Walk the pf: prefix; for each item whose metadata matches
		// the requested storageID, evict it immediately.
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
				if meta.StorageID != storageID {
					continue
				}

				evictOne(hash)
			}
		}

		// Phase 2: walk the LRU index for the requested storage+namespace.
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

		// Apply accumulated usage decrements.
		for key, delta := range usageDeltas {
			if err := addUsageInTxn(txn, key.StorageID, key.NamespaceID, delta); err != nil {
				log.Warnf("Failed to decrease usage for storage %d namespace %d: %v",
					key.StorageID, key.NamespaceID, err)
			}
		}

		return nil
	})

	return evicted, err
}

// badgerLogger adapts Pelican's logrus to BadgerDB's logger interface
type badgerLogger struct{}

func (l *badgerLogger) Errorf(format string, args ...interface{}) {
	log.Errorf("[BadgerDB] "+format, args...)
}

func (l *badgerLogger) Warningf(format string, args ...interface{}) {
	log.Warnf("[BadgerDB] "+format, args...)
}

func (l *badgerLogger) Infof(format string, args ...interface{}) {
	log.Debugf("[BadgerDB] "+format, args...)
}

func (l *badgerLogger) Debugf(format string, args ...interface{}) {
	log.Tracef("[BadgerDB] "+format, args...)
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
