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

// TODO: Multi-Storage Architecture
// The current implementation tracks usage per-namespace, but future work should:
//   1. Split tracking into both "namespace" and "storage path" dimensions
//      - Allow multiple storage directories with independent usage limits
//      - Support balancing across storage devices (e.g., fast SSD vs large HDD)
//   2. Store the storage path in CacheMetadata.StoragePath (field added)
//      - This tells DeleteObject where to remove the file from disk
//   3. Make all periodic cleanup routines (ConsistencyChecker, EvictionManager)
//      operate per-storage directory independently
//   4. Treat inline data as a separate "storage resource" with configurable max usage
//      - Add InlineStorageMaxBytes configuration parameter
//      - Track inline data usage separately from disk storage
//   5. Update usage keys to be composite: storage+namespace instead of just namespace
//      - Example: PrefixUsage + storageID + namespaceID

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
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
	mu        sync.RWMutex
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

// --- Metadata Operations ---

// GetMetadata retrieves cache metadata for a file
func (cdb *CacheDB) GetMetadata(instanceHash string) (*CacheMetadata, error) {
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

// SetMetadata stores cache metadata for a file
func (cdb *CacheDB) SetMetadata(instanceHash string, meta *CacheMetadata) error {
	data, err := msgpack.Marshal(meta)
	if err != nil {
		return errors.Wrap(err, "failed to marshal metadata")
	}

	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(MetaKey(instanceHash), data)
	})
}

// DeleteMetadata removes metadata for a file
func (cdb *CacheDB) DeleteMetadata(instanceHash string) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(MetaKey(instanceHash))
	})
}

// --- ETag Operations ---

// GetLatestETag retrieves the latest ETag for an object
func (cdb *CacheDB) GetLatestETag(objectHash string) (string, error) {
	var etag string

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(ETagKey(objectHash))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			etag = string(val)
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

// SetLatestETag stores the latest ETag for an object
func (cdb *CacheDB) SetLatestETag(objectHash, etag string) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(ETagKey(objectHash), []byte(etag))
	})
}

// DeleteLatestETag removes the ETag entry for an object
func (cdb *CacheDB) DeleteLatestETag(objectHash string) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(ETagKey(objectHash))
	})
}

// --- Namespace Mapping Operations ---

// SetNamespaceMapping persists the mapping from a namespace prefix string
// to a numeric ID.  This ensures the IDs survive restarts so that LRU
// keys and usage counters remain valid.
func (cdb *CacheDB) SetNamespaceMapping(prefix string, id uint32) error {
	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, id)
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(NamespaceKey(prefix), val)
	})
}

// LoadNamespaceMappings loads all persisted namespace mappings and returns
// them as a map[prefix]->id, along with the highest ID seen (so the
// caller can resume the counter).
func (cdb *CacheDB) LoadNamespaceMappings() (map[string]uint32, uint32, error) {
	result := make(map[string]uint32)
	var maxID uint32

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
				id := binary.LittleEndian.Uint32(val)
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

// --- Block State Operations ---

// GetBlockState retrieves the bitmap of downloaded blocks for a file
func (cdb *CacheDB) GetBlockState(instanceHash string) (*roaring.Bitmap, error) {
	bitmap := roaring.New()

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(StateKey(instanceHash))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			_, err := bitmap.FromBuffer(val)
			return err
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return bitmap, nil // Return empty bitmap
		}
		return nil, errors.Wrap(err, "failed to get block state")
	}

	return bitmap, nil
}

// SetBlockState stores the bitmap of downloaded blocks
func (cdb *CacheDB) SetBlockState(instanceHash string, bitmap *roaring.Bitmap) error {
	data, err := bitmap.ToBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize bitmap")
	}

	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(StateKey(instanceHash), data)
	})
}

// MergeBlockState atomically merges new blocks into the existing bitmap
// Uses read-modify-write within a transaction to handle concurrent updates
func (cdb *CacheDB) MergeBlockState(instanceHash string, newBlocks *roaring.Bitmap) error {
	newData, err := newBlocks.ToBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize new blocks bitmap")
	}

	return cdb.db.Update(func(txn *badger.Txn) error {
		return mergeBlockStateInTxn(txn, instanceHash, newData)
	})
}

// mergeBlockStateInTxn performs the bitmap merge within an existing transaction
// TODO: For better consistency between block state and usage statistics, calculate
// the usage increase directly from the number of newly-enabled bits in the bitmap
// (except for the last block which may be partial). This requires:
//   1. Getting metadata to know the block size and total content length
//   2. Computing cardinality difference: (existing OR new).Cardinality() - existing.Cardinality()
//   3. Multiplying by block size (except for last block)
//   4. Calling addUsageInTxn within the same transaction
func mergeBlockStateInTxn(txn *badger.Txn, instanceHash string, newData []byte) error {
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
			return errors.Wrap(err, "failed to deserialize existing bitmap")
		}
	} else if !errors.Is(err, badger.ErrKeyNotFound) {
		return err
	}

	// Merge bitmaps using OR operation
	newBitmap := roaring.New()
	if _, err := newBitmap.FromBuffer(newData); err != nil {
		return errors.Wrap(err, "failed to deserialize new bitmap")
	}
	existing.Or(newBitmap)

	// Save merged result
	mergedData, err := existing.ToBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize merged bitmap")
	}

	return txn.Set(key, mergedData)
}

// addUsageInTxn performs the usage counter merge within an existing transaction
func addUsageInTxn(txn *badger.Txn, storageID uint8, namespaceID uint32, delta int64) error {
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
	StorageID   uint8
	NamespaceID uint32
}

// MergeUpdate performs multiple merge operations atomically in a single transaction.
// This is the "fire and forget" API for concurrent downloads as described in the design doc.
// Operations:
//   - bitmapMerges: map of instanceHash -> bitmap data to OR-merge into block state
//   - usageDeltas: map of StorageUsageKey -> bytes to add to usage counter
func (cdb *CacheDB) MergeUpdate(bitmapMerges map[string][]byte, usageDeltas map[StorageUsageKey]int64) error {
	if len(bitmapMerges) == 0 && len(usageDeltas) == 0 {
		return nil
	}

	return cdb.db.Update(func(txn *badger.Txn) error {
		// Merge all bitmap updates
		for instanceHash, newData := range bitmapMerges {
			if err := mergeBlockStateInTxn(txn, instanceHash, newData); err != nil {
				return errors.Wrapf(err, "failed to merge bitmap for %s", instanceHash)
			}
		}

		// Merge all usage counter updates
		for key, delta := range usageDeltas {
			if err := addUsageInTxn(txn, key.StorageID, key.NamespaceID, delta); err != nil {
				return errors.Wrapf(err, "failed to update usage for storage %d namespace %d", key.StorageID, key.NamespaceID)
			}
		}

		return nil
	})
}

// MarkBlocksDownloaded marks specific blocks as downloaded
func (cdb *CacheDB) MarkBlocksDownloaded(instanceHash string, startBlock, endBlock uint32) error {
	newBlocks := roaring.New()
	newBlocks.AddRange(uint64(startBlock), uint64(endBlock)+1)
	return cdb.MergeBlockState(instanceHash, newBlocks)
}

// ClearBlocks removes the specified blocks from the downloaded bitmap so they
// will be re-fetched on the next read.  This is used during auto-repair when
// corruption is detected.
func (cdb *CacheDB) ClearBlocks(instanceHash string, blocks []uint32) error {
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
func (cdb *CacheDB) IsBlockDownloaded(instanceHash string, blockNum uint32) (bool, error) {
	bitmap, err := cdb.GetBlockState(instanceHash)
	if err != nil {
		return false, err
	}
	return bitmap.Contains(blockNum), nil
}

// GetDownloadedBlockCount returns the number of downloaded blocks
func (cdb *CacheDB) GetDownloadedBlockCount(instanceHash string) (uint64, error) {
	bitmap, err := cdb.GetBlockState(instanceHash)
	if err != nil {
		return 0, err
	}
	return bitmap.GetCardinality(), nil
}

// DeleteBlockState removes block state for a file
func (cdb *CacheDB) DeleteBlockState(instanceHash string) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(StateKey(instanceHash))
	})
}

// --- Inline Data Operations ---

// GetInlineData retrieves encrypted inline data for a small file
func (cdb *CacheDB) GetInlineData(instanceHash string) ([]byte, error) {
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
func (cdb *CacheDB) SetInlineData(instanceHash string, encryptedData []byte) error {
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
func (cdb *CacheDB) DeleteInlineData(instanceHash string) error {
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
func (cdb *CacheDB) UpdateLRU(instanceHash string, debounceTime time.Duration) error {
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

// DeleteLRU removes the LRU entry for a file using metadata for direct key lookup
func (cdb *CacheDB) DeleteLRU(instanceHash string) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Get metadata to find prefixID and last access time
		item, err := txn.Get(MetaKey(instanceHash))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil // No metadata, nothing to delete
			}
			return errors.Wrap(err, "failed to get metadata for LRU delete")
		}

		var meta CacheMetadata
		err = item.Value(func(val []byte) error {
			return msgpack.Unmarshal(val, &meta)
		})
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal metadata")
		}

		// Delete LRU key if we have a last access time
		if !meta.LastAccessTime.IsZero() {
			lruKey := LRUKey(meta.StorageID, meta.NamespaceID, meta.LastAccessTime, instanceHash)
			if err := txn.Delete(lruKey); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
				return errors.Wrap(err, "failed to delete LRU key")
			}
		}
		return nil
	})
}

// --- Usage Counter Operations ---

// GetOldestLRUEntries returns the oldest LRU entries for a storage+namespace combination
func (cdb *CacheDB) GetOldestLRUEntries(storageID uint8, namespaceID uint32, limit int) ([]string, error) {
	var entries []string

	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(fmt.Sprintf("%s%d:%d:", PrefixLRU, storageID, namespaceID))
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix) && len(entries) < limit; it.Next() {
			key := it.Item().Key()
			sid, nid, _, hash, err := ParseLRUKey(key)
			if err != nil {
				continue
			}
			if sid == storageID && nid == namespaceID {
				entries = append(entries, hash)
			}
		}
		return nil
	})

	return entries, err
}

// GetUsage retrieves the total bytes used by a storage+namespace combination
func (cdb *CacheDB) GetUsage(storageID uint8, namespaceID uint32) (int64, error) {
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

// AddUsage atomically adds to the usage counter for a storage+namespace combination
// Uses the shared addUsageInTxn helper for consistency with MergeUpdate
func (cdb *CacheDB) AddUsage(storageID uint8, namespaceID uint32, delta int64) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return addUsageInTxn(txn, storageID, namespaceID, delta)
	})
}

// GetAllUsage returns usage for all storage+namespace combinations
func (cdb *CacheDB) GetAllUsage() (map[StorageUsageKey]int64, error) {
	usage := make(map[StorageUsageKey]int64)

	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixUsage)
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

// --- Bulk Operations ---

// DeleteObject removes all data for a cached object
// Uses metadata to compute exact LRU key for efficient deletion
// Also cleans up ETag table if this was the latest version
func (cdb *CacheDB) DeleteObject(instanceHash string) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Get metadata first to find LRU key info and objectHash before deleting
		var meta CacheMetadata
		var hasMetadata bool

		item, err := txn.Get(MetaKey(instanceHash))
		if err == nil {
			hasMetadata = true
			err = item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &meta)
			})
			if err != nil {
				// Log but continue with deletion - metadata may be corrupt
				log.Warnf("Failed to unmarshal metadata during object deletion: %v", err)
				hasMetadata = false
			}
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return errors.Wrap(err, "failed to get metadata for deletion")
		}

		// Delete LRU entry using metadata (before deleting metadata)
		if hasMetadata && !meta.LastAccessTime.IsZero() {
			lruKey := LRUKey(meta.StorageID, meta.NamespaceID, meta.LastAccessTime, instanceHash)
			if err := txn.Delete(lruKey); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
				return errors.Wrap(err, "failed to delete LRU key")
			}
		}

		// Clean up ETag table if this was the latest version
		// Only delete if the current ETag entry points to this object's ETag
		if hasMetadata && meta.ObjectHash != "" {
			etagItem, err := txn.Get(ETagKey(meta.ObjectHash))
			if err == nil {
				var currentETag string
				err = etagItem.Value(func(val []byte) error {
					currentETag = string(val)
					return nil
				})
				if err == nil && currentETag == meta.ETag {
					// This is the latest version, delete the ETag entry
					if err := txn.Delete(ETagKey(meta.ObjectHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
						log.Warnf("Failed to delete ETag entry for %s: %v", meta.ObjectHash, err)
					}
				}
			}
		}

		// Decrease usage statistics before deleting
		if hasMetadata {
			// Decrease usage by the content length
			if err := addUsageInTxn(txn, meta.StorageID, meta.NamespaceID, -meta.ContentLength); err != nil {
				log.Warnf("Failed to decrease usage for storage %d namespace %d: %v", meta.StorageID, meta.NamespaceID, err)
			}
		}

		// Delete metadata
		if err := txn.Delete(MetaKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}

		// Delete block state
		if err := txn.Delete(StateKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}

		// Delete inline data only if storage mode is inline (we know from metadata)
		if hasMetadata && meta.StorageMode == StorageModeInline {
			if err := txn.Delete(InlineKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
		}

		return nil
	})
}

// NOTE: ListAllObjects was removed - use ScanMetadata or ScanMetadataFrom instead
// to iterate over objects without loading all into memory.

// --- Transaction Support ---

// Transaction represents a database transaction
type Transaction struct {
	txn *badger.Txn
	cdb *CacheDB
}

// Begin starts a new transaction
func (cdb *CacheDB) Begin(readOnly bool) *Transaction {
	var txn *badger.Txn
	if readOnly {
		txn = cdb.db.NewTransaction(false)
	} else {
		txn = cdb.db.NewTransaction(true)
	}
	return &Transaction{txn: txn, cdb: cdb}
}

// Commit commits the transaction
func (t *Transaction) Commit() error {
	return t.txn.Commit()
}

// Discard discards the transaction
func (t *Transaction) Discard() {
	t.txn.Discard()
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
func (cdb *CacheDB) ScanMetadata(fn func(instanceHash string, meta *CacheMetadata) error) error {
	return cdb.ScanMetadataFrom("", fn)
}

// ScanMetadataFrom scans metadata starting from the given instanceHash (empty string = start from beginning)
func (cdb *CacheDB) ScanMetadataFrom(startKey string, fn func(instanceHash string, meta *CacheMetadata) error) error {
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
			instanceHash := key[len(PrefixMeta):]

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
func (cdb *CacheDB) HasMetadata(instanceHash string) (bool, error) {
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

// IterateLRUByNamespace iterates over LRU entries for a specific storage+namespace combination
// Entries are returned in order from oldest to newest
func (cdb *CacheDB) IterateLRUByNamespace(storageID uint8, namespaceID uint32, fn func(instanceHash string, timestamp time.Time) error) error {
	return cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(fmt.Sprintf("%s%d:%d:", PrefixLRU, storageID, namespaceID))
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := it.Item().Key()
			sid, nid, ts, hash, err := ParseLRUKey(key)
			if err != nil {
				continue
			}
			if sid == storageID && nid == namespaceID {
				if err := fn(hash, ts); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// CreateSnapshot creates a snapshot of the database for backup
func (cdb *CacheDB) CreateSnapshot(w *bytes.Buffer) error {
	_, err := cdb.db.Backup(w, 0)
	return err
}

// RestoreFromSnapshot restores the database from a snapshot
func (cdb *CacheDB) RestoreFromSnapshot(r *bytes.Buffer) error {
	return cdb.db.Load(r, 256)
}

// --- Purge First Operations ---

// MarkPurgeFirst marks a file hash for priority eviction
func (cdb *CacheDB) MarkPurgeFirst(instanceHash string) error {
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
func (cdb *CacheDB) UnmarkPurgeFirst(instanceHash string) error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(PurgeFirstKey(instanceHash))
	})
}

// IsPurgeFirst checks if a file hash is marked for priority eviction
func (cdb *CacheDB) IsPurgeFirst(instanceHash string) (bool, error) {
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

// GetPurgeFirstItems returns all file hashes marked for priority eviction
func (cdb *CacheDB) GetPurgeFirstItems() ([]string, error) {
	var items []string

	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixPurgeFirst)
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := string(it.Item().Key())
			if len(key) > len(PrefixPurgeFirst) {
				items = append(items, key[len(PrefixPurgeFirst):])
			}
		}
		return nil
	})

	return items, err
}
