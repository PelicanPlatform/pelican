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

// SourcedCache: the cache's block store, filled from a caller's BlockSource
// rather than from the federation.
//
// PersistentCache is the cache server: it resolves objects through the
// director, authorizes requests, revalidates by downloading, and tiers.  A
// SourcedCache is the same storage underneath -- encrypted blocks, a shared
// block state that coalesces readers and fills, write fences, pins, and LRU
// eviction -- with none of that above it.  The caller decides what an object
// is, when it is fresh and when it has changed, and supplies the bytes.  An
// origin uses one to keep copies of objects from remote storage.

package local_cache

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// sourcedCacheMarker is the file that says a directory holds a
// SourcedCache, so that one whose master key can no longer be unwrapped may
// be emptied without risk of emptying anything else.
const sourcedCacheMarker = ".pelican-sourced-cache"

// SourcedCacheConfig configures OpenSourcedCache.
type SourcedCacheConfig struct {
	// Dir holds the cache's database and its data.  It must be empty or
	// hold a SourcedCache.
	Dir string
	// MaxSize bounds what the cache stores, in bytes; 0 sizes it to the
	// filesystem holding Dir.  Eviction starts at 90% and stops at 80%.
	MaxSize uint64
	// FillIdleTimeout is how long a background fill goes on once no reader
	// of its object is open; 0 means LocalCache.PrefetchTimeout.
	FillIdleTimeout time.Duration
}

// SourceObject describes a version of an object as its source reports it.
type SourceObject struct {
	Size         int64
	ETag         string
	LastModified time.Time
	CacheControl string
}

// SourcedCache keeps copies of objects whose bytes come from the caller.
//
// An object is named by a key, a URL the caller makes up; each version of it
// is an instance, named by the key and its entity tag.  The key's pointer
// names the version the caller last published.  A version's blocks are
// fetched as readers need them, each pinned to that version's entity tag,
// so a copy never mixes bytes of two versions.
type SourcedCache struct {
	db       *CacheDB
	storage  *StorageManager
	eviction *EvictionManager

	fillIdleTimeout time.Duration
	prefetchSem     chan struct{}
	initGroup       singleflight.Group

	// ctx bounds the background fills and loops; Close cancels it.
	ctx    context.Context
	cancel context.CancelFunc
	loops  errgroup.Group

	// openMu orders starting a fill against Close; see whileOpen.
	openMu    sync.RWMutex
	closed    atomic.Bool
	fills     sync.WaitGroup
	closeOnce sync.Once
}

// OpenSourcedCache opens the cache in cfg.Dir, creating it if the directory
// is empty.  Like every user of the block store, it needs the issuer keys,
// under which the cache's master key is wrapped.  The cache is only a copy,
// so if none of the keys that wrapped it is still loaded it is emptied and
// started afresh rather than refused.
//
// egrp runs the storage manager's background work, which stops on Close.
func OpenSourcedCache(ctx context.Context, egrp *errgroup.Group, cfg SourcedCacheConfig) (*SourcedCache, error) {
	if cfg.Dir == "" {
		return nil, errors.New("a sourced cache needs a directory")
	}
	if err := claimSourcedCacheDir(cfg.Dir); err != nil {
		return nil, err
	}
	if masterKeyUnwrappable(cfg.Dir) {
		log.Warnf("None of the loaded issuer keys can unlock the cache in %s; emptying it", cfg.Dir)
		if err := emptySourcedCacheDir(cfg.Dir); err != nil {
			return nil, err
		}
	}

	db, err := NewCacheDB(ctx, cfg.Dir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open the cache database")
	}
	if err := db.EnsureStoreMode(StoreModeSourcedCache); err != nil {
		db.Close()
		return nil, err
	}
	// Wrap the master key under the keys loaded now, so that the cache
	// survives a key being rotated out as long as it restarts in between.
	if encMgr := db.GetEncryptionManager(); encMgr != nil {
		if err := encMgr.UpdateMasterKeyEncryption(); err != nil {
			log.Warnf("Failed to wrap the master key of the cache in %s under the current issuer keys: %v", cfg.Dir, err)
		}
	}

	storage, err := NewStorageManager(db, []string{cfg.Dir}, 0, egrp)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to open the cache's block storage")
	}
	dirConfigs := make(map[StorageID]EvictionDirConfig, 1)
	for id := range storage.GetDirs() {
		maxSize := cfg.MaxSize
		if maxSize == 0 {
			if maxSize, err = getCacheSize(cfg.Dir, db, id); err != nil {
				storage.Close()
				db.Close()
				return nil, errors.Wrapf(err, "failed to size the cache in %s", cfg.Dir)
			}
		}
		dirConfigs[id] = EvictionDirConfig{MaxSize: maxSize, HighWaterPercentage: 90, LowWaterPercentage: 80}
	}
	eviction := NewEvictionManager(db, storage, EvictionConfig{DirConfigs: dirConfigs})
	storage.SetChooseDir(eviction.ChooseDiskStorage)

	idle := cfg.FillIdleTimeout
	if idle <= 0 {
		idle = DefaultPrefetchTimeout
	}
	c := &SourcedCache{
		db:              db,
		storage:         storage,
		eviction:        eviction,
		fillIdleTimeout: idle,
		prefetchSem:     make(chan struct{}, 1),
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	// The loops run on a group of the cache's own, so that Close can wait
	// for them before it closes the database under them.
	db.StartGC(c.ctx, &c.loops)
	eviction.Start(c.ctx, &c.loops)
	return c, nil
}

// claimSourcedCacheDir creates dir if need be and marks it as a
// SourcedCache's, refusing a directory that holds anything else.
func claimSourcedCacheDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.Wrapf(err, "failed to create the cache directory %s", dir)
	}
	marker := filepath.Join(dir, sourcedCacheMarker)
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.Wrapf(err, "failed to read the cache directory %s", dir)
	}
	if len(entries) > 0 {
		return errors.Errorf("the cache directory %s is not empty and does not hold a cache; "+
			"refusing to use it, since the cache may delete what it holds", dir)
	}
	return errors.Wrapf(os.WriteFile(marker, nil, 0600), "failed to mark %s as a cache directory", dir)
}

// emptySourcedCacheDir removes everything in a marked cache directory but
// the marker.
func emptySourcedCacheDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.Wrapf(err, "failed to read the cache directory %s", dir)
	}
	for _, e := range entries {
		if e.Name() == sourcedCacheMarker {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return errors.Wrapf(err, "failed to empty the cache directory %s", dir)
		}
	}
	return nil
}

// Close stops the cache's fills and loops and closes its storage.  It is
// safe to call more than once.
func (c *SourcedCache) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.openMu.Lock()
		c.closed.Store(true)
		c.openMu.Unlock()
		c.cancel()
		c.fills.Wait()
		_ = c.loops.Wait()
		c.storage.Close()
		err = c.db.Close()
	})
	return err
}

// whileOpen runs start, which registers a fill with c.fills and launches
// it, unless the cache is closing, and reports whether it ran.  Close sets
// closed under the write lock before it waits on c.fills, so a fill is
// either registered before the wait or not started at all.
func (c *SourcedCache) whileOpen(start func()) bool {
	c.openMu.RLock()
	defer c.openMu.RUnlock()
	if c.closed.Load() {
		return false
	}
	start()
	return true
}

// Namespace returns the ID under which the cache accounts for objects
// filed under name, registering one if need be.  Eviction takes from the
// namespace using the most space first, so giving each of the caller's
// scopes its own keeps one from crowding out the rest.
func (c *SourcedCache) Namespace(name string) (NamespaceID, error) {
	existing, next, err := c.db.LoadNamespaceMappings()
	if err != nil {
		return 0, errors.Wrap(err, "failed to load namespace mappings")
	}
	if id, ok := existing[name]; ok {
		return id, nil
	}
	if next == 0 {
		next = 1
	}
	if err := c.db.SetNamespaceMapping(name, next); err != nil {
		return 0, errors.Wrapf(err, "failed to register namespace %s", name)
	}
	return next, nil
}

// Lookup returns the version key's pointer names and its record, or a nil
// record when there is none.
func (c *SourcedCache) Lookup(key string) (InstanceHash, *CacheMetadata, error) {
	objectHash := c.db.ObjectHash(key)
	etag, found, err := c.db.GetLatestETag(objectHash)
	if err != nil || !found {
		return "", nil, err
	}
	instanceHash := c.db.InstanceHash(etag, objectHash)
	meta, err := c.storage.GetMetadata(instanceHash)
	if err != nil || meta == nil {
		return "", nil, err
	}
	return instanceHash, meta, nil
}

// Init returns the record of version obj of key, making one -- with no
// blocks yet -- if there is none, and records that the source reported it
// at validatedAt.  It does not publish the version; see Publish.
func (c *SourcedCache) Init(key string, namespace NamespaceID, obj SourceObject, validatedAt time.Time) (InstanceHash, *CacheMetadata, error) {
	objectHash := c.db.ObjectHash(key)
	instanceHash := c.db.InstanceHash(obj.ETag, objectHash)
	v, err, _ := c.initGroup.Do(string(instanceHash), func() (interface{}, error) {
		if meta, err := c.storage.GetMetadata(instanceHash); err != nil || meta != nil {
			return meta, err
		}
		storageID := c.eviction.ChooseDiskStorage()
		meta, err := c.storage.InitDiskStorage(c.ctx, instanceHash, obj.Size, storageID, namespace)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to make room for %s", key)
		}
		c.eviction.NoteUsageIncrease(storageID, CalculateFileSize(obj.Size))
		meta.ETag = obj.ETag
		meta.LastModified = obj.LastModified
		meta.SourceURL = key
		meta.NamespaceID = namespace
		meta.ContentType = "application/octet-stream"
		meta.LastValidated = validatedAt
		meta.SetCacheControl(obj.CacheControl)
		if obj.Size == 0 {
			// No blocks to wait for.
			meta.Completed = time.Now()
		}
		if err := c.storage.MergeMetadata(instanceHash, meta); err != nil {
			return nil, errors.Wrapf(err, "failed to record %s", key)
		}
		// Eviction walks the LRU index, so a version that is never read --
		// one whose publication lost a race, say -- must be in it too.
		if err := c.eviction.RecordAccess(instanceHash); err != nil {
			log.Debugf("Failed to record an access to %s: %v", key, err)
		}
		return meta, nil
	})
	if err != nil {
		return "", nil, err
	}
	meta := v.(*CacheMetadata)
	if meta.LastValidated.Before(validatedAt) {
		// An existing record, from an earlier publication of this version.
		if err := c.Revalidated(instanceHash, obj.CacheControl, validatedAt); err != nil {
			return "", nil, err
		}
		if meta, err = c.storage.GetMetadata(instanceHash); err != nil {
			return "", nil, err
		} else if meta == nil {
			return "", nil, errors.Errorf("%s was evicted as it was recorded", key)
		}
	}
	return instanceHash, meta, nil
}

// Complete reports whether every block of a version is cached.
func (c *SourcedCache) Complete(instanceHash InstanceHash) (bool, error) {
	return c.storage.IsComplete(instanceHash)
}

// Publish points key at version etag, as the source reported at
// observedAt, and reports whether it did: it does not when a later
// observation is already published.
func (c *SourcedCache) Publish(key, etag string, observedAt time.Time) (bool, error) {
	return c.db.SetLatestETagIfNewer(c.db.ObjectHash(key), etag, observedAt)
}

// Revalidated records that the source confirmed the version at at, with
// cacheControl as its Cache-Control.  A confirmation older than one already
// recorded changes nothing.
func (c *SourcedCache) Revalidated(instanceHash InstanceHash, cacheControl string, at time.Time) error {
	_, err := c.db.UpdateExistingMetadata(instanceHash, func(meta *CacheMetadata) {
		if at.Before(meta.LastValidated) {
			return
		}
		meta.LastValidated = at
		// Replace the directives outright: one the source no longer sends
		// must not linger, which a merge would let it.
		meta.CCFlags, meta.CCMaxAge = 0, 0
		meta.SetCacheControl(cacheControl)
	})
	return err
}

// Forget removes key's pointer, so the next lookup misses, and deletes the
// version it named unless a reader holds it (eviction takes it later).
func (c *SourcedCache) Forget(key string) error {
	objectHash := c.db.ObjectHash(key)
	etag, found, err := c.db.GetLatestETag(objectHash)
	if err != nil || !found {
		return err
	}
	if err := c.db.DeleteLatestETag(objectHash); err != nil {
		return err
	}
	c.Discard(c.db.InstanceHash(etag, objectHash))
	return nil
}

// ForgetPrefix forgets every cached key beginning with prefix, and returns
// how many it found.  It reads every record in the cache.
func (c *SourcedCache) ForgetPrefix(prefix string) (int, error) {
	keys := map[string]struct{}{}
	err := c.db.ScanMetadata(func(_ InstanceHash, meta *CacheMetadata) error {
		if strings.HasPrefix(meta.SourceURL, prefix) {
			keys[meta.SourceURL] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return 0, errors.Wrap(err, "failed to scan the cache")
	}
	for key := range keys {
		if err := c.Forget(key); err != nil {
			return 0, err
		}
	}
	return len(keys), nil
}

// Discard deletes a version unless a reader holds it.
func (c *SourcedCache) Discard(instanceHash InstanceHash) {
	if _, err := c.storage.DeleteIfUnpinned(instanceHash); err != nil {
		log.Debugf("Failed to delete %s from the cache: %v", instanceHash, err)
	}
}

// NewReader opens a reader of the whole of a version, which is not empty.
// The reader fetches the blocks it lacks from src, label naming the object
// in logs.  Like the cache server's readers, a read of a block that nothing
// is writing starts a background fill from it to the end of the reader's
// range, unless LimitFill says otherwise; the fill outlives the reader by
// the cache's FillIdleTimeout.  The reader holds the version against
// deletion until it is closed.
func (c *SourcedCache) NewReader(instanceHash InstanceHash, src BlockSource, label string) (*RangeReader, error) {
	var mu sync.Mutex
	var fetcher *BlockFetcherV2
	closed := false
	fetchBlocks := func(ctx context.Context, startBlock, endBlock uint32) error {
		mu.Lock()
		if closed {
			mu.Unlock()
			return errors.New("the reader is closed")
		}
		if fetcher == nil {
			bf, err := c.newFetcher(instanceHash, src, label)
			if err != nil {
				mu.Unlock()
				return err
			}
			fetcher = bf
		}
		bf := fetcher
		mu.Unlock()
		return bf.FetchBlocks(ctx, startBlock, endBlock)
	}

	unpin := c.storage.PinObject(instanceHash)
	rr, err := NewRangeReader(c.storage, instanceHash, 0, -1, fetchBlocks)
	if err != nil {
		unpin()
		return nil, err
	}
	rr.startFill = func(block, last uint32, overDownload bool) (bool, <-chan struct{}) {
		return c.startFill(instanceHash, src, label, rr.blockState, rr.meta.ContentLength, block, last, overDownload)
	}
	rr.onClose = func() {
		mu.Lock()
		closed = true
		if fetcher != nil {
			fetcher.Close()
		}
		mu.Unlock()
		unpin()
	}
	if err := c.eviction.RecordAccess(instanceHash); err != nil {
		log.Debugf("Failed to record an access to %s: %v", label, err)
	}
	return rr, nil
}

func (c *SourcedCache) newFetcher(instanceHash InstanceHash, src BlockSource, label string) (*BlockFetcherV2, error) {
	return NewSourcedBlockFetcher(c.storage, instanceHash, src, label, BlockFetcherV2Config{
		PrefetchTimeout: c.fillIdleTimeout,
		PrefetchSem:     c.prefetchSem,
	})
}

// startFill starts a background fill of blocks block through last, or up to
// the first block already present, as PersistentCache.startFill does for
// the cache server; see there.
func (c *SourcedCache) startFill(instanceHash InstanceHash, src BlockSource, label string, state *ObjectBlockState, size int64, block, last uint32, overDownload bool) (covered bool, started <-chan struct{}) {
	if c.closed.Load() || size <= 0 {
		return false, nil
	}
	fill := state.beginFill(block, last, overDownload)
	if fill == nil {
		// Already written, or something else is writing it.
		return true, nil
	}
	bf, err := c.newFetcher(instanceHash, src, label)
	if err != nil {
		state.endFill(fill)
		log.Debugf("Not filling %s in the background: %v", label, err)
		return false, nil
	}
	// The fill can outlive the reader that started it, so it holds the
	// version against deletion itself.
	unpin := c.storage.PinObject(instanceHash)
	launched := c.whileOpen(func() {
		c.fills.Add(1)
		go func() {
			defer c.fills.Done()
			defer unpin()
			defer state.endFill(fill)
			defer bf.Close()
			if err := bf.Fill(c.ctx, fill.start, fill.end); err != nil {
				log.Debugf("Background fill of blocks %d-%d of %s ended early: %v", fill.start, fill.end, label, err)
			}
		}()
	})
	if !launched {
		bf.Close()
		state.endFill(fill)
		unpin()
		return false, nil
	}
	return true, fill.done
}
