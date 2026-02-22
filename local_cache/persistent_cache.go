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

// persistent_cache.go implements PersistentCache, the main entry point for
// the local-cache subsystem.  It coordinates:
//
//   - Object resolution and download orchestration (resolveObject,
//     downloadObject, performDownload).
//   - Cache-Control / ETag-based revalidation (revalidateObject).
//   - Inline (small-file) vs disk (large-file) storage decisions via
//     decisionWriter.
//   - No-store passthrough streaming when the origin forbids caching.
//   - Namespace ID assignment and federation token management.
//   - Background configuration updates from the director.
//
// Supporting types live in other files: CacheDB (database.go),
// StorageManager / BlockWriter (storage.go), EvictionManager
// (eviction.go), ConsistencyChecker (consistency.go), and
// BlockFetcherV2 (block_fetcher.go).
package local_cache

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

// ErrNoStore is returned when the origin sends Cache-Control: no-store (or private).
// The response data is streamed via persistentDownload.noStoreReader (an io.Pipe)
// directly to the first caller without persisting to the cache.
var ErrNoStore = errors.New("origin response has Cache-Control: no-store")

// ErrNoStoreRetry is returned to waiters that attach to an in-flight no-store
// download.  Because the stream can only be consumed once (by the first caller),
// subsequent callers must retry independently.
var ErrNoStoreRetry = errors.New("no-store download in progress; retry independently")

// isEvictedError returns true when err is characteristic of an object that was
// evicted between resolveObject (which found its metadata) and the subsequent
// attempt to open a reader.  This lets GetSeekableReader / GetRange retry
// once — the second resolveObject will trigger a fresh download.
func isEvictedError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "object not found") ||
		strings.Contains(msg, "failed to open object file")
}

// clientChecksumsToCache converts transfer-client checksums into the local
// cache schema.  Server-supplied checksums are marked OriginVerified; client-
// computed checksums are not.  Unrecognised algorithms are silently dropped.
func clientChecksumsToCache(result *client.TransferResults) []Checksum {
	if result == nil {
		return nil
	}

	algMap := map[client.ChecksumType]ChecksumType{
		client.AlgMD5:   ChecksumMD5,
		client.AlgSHA1:  ChecksumSHA1,
		client.AlgCRC32: ChecksumCRC32,
		// CRC32C is supported by the client but not yet used in local cache verification.
		// Store it anyway so it's available for future use.
		client.AlgCRC32C: ChecksumCRC32C,
	}

	var out []Checksum
	for _, ci := range result.ServerChecksums {
		if ct, ok := algMap[ci.Algorithm]; ok {
			out = append(out, Checksum{Type: ct, Value: ci.Value, OriginVerified: true})
		}
	}
	for _, ci := range result.ClientChecksums {
		if ct, ok := algMap[ci.Algorithm]; ok {
			out = append(out, Checksum{Type: ct, Value: ci.Value})
		}
	}
	return out
}

// PersistentCache is the new persistent local cache implementation
// It uses BadgerDB for metadata and block tracking, and encrypted files on disk
type PersistentCache struct {
	ctx     context.Context
	egrp    *errgroup.Group
	baseDir string

	// Core components
	db          *CacheDB
	storage     *StorageManager
	eviction    *EvictionManager
	consistency *ConsistencyChecker

	// Transfer engine for creating per-request clients
	te *client.TransferEngine

	// Federation configuration
	directorURL *url.URL
	defaultFed  string
	ac          *authConfig

	// Namespace mapping (URL prefix -> namespace ID)
	namespaceMap    map[string]NamespaceID
	namespaceMapMu  sync.RWMutex
	nextNamespaceID atomic.Uint32

	// Active downloads tracking
	activeDownloads   map[ObjectHash]*persistentDownload
	activeDownloadsMu sync.RWMutex
	downloadWg        sync.WaitGroup     // Tracks in-flight download goroutines (adopted transfers + inline drains)
	downloadCtx       context.Context    // Cancelled during Close() to stop in-flight transfers
	downloadCancel    context.CancelFunc // Cancels downloadCtx

	// Active revalidations deduplication (keyed by objectHash)
	revalGroup singleflight.Group

	// Federation token set by LaunchFedTokManager via SetFedToken.
	// fedTokenMu protects the token string. fedTokenReady is closed
	// the first time a non-empty token is stored, allowing getFedToken()
	// to block briefly during startup.
	fedToken      string
	fedTokenMu    sync.Mutex
	fedTokenReady chan struct{} // closed on first non-empty SetFedToken

	// Configuration
	wasConfigured bool
	closed        atomic.Bool

	// Shared prefetch semaphore: limits total concurrent prefetch/background
	// download operations across all BlockFetcherV2 instances and
	// completeDownload goroutines.
	prefetchSem chan struct{}

	// Prestage worker pool manager (created lazily on first API call).
	prestageManager *PrestageManager
}

// persistentDownload tracks an active download operation
type persistentDownload struct {
	instanceHash InstanceHash
	objectHash   ObjectHash // Hash of the URL (for ETag table)
	sourceURL    string
	namespaceID  NamespaceID
	etag         string     // ETag from origin
	etagObserved time.Time  // When the ETag was observed (for timestamped ETag storage)
	lastModified time.Time  // Last-Modified from origin
	cacheControl string     // Cache-Control from origin
	checksums    []Checksum // Checksums from the transfer result
	waiters      []chan error
	mu           sync.Mutex
	done         bool
	err          error

	// noStoreReader is the read end of an io.Pipe that streams the response
	// body when the origin sends Cache-Control: no-store (or private).
	// Only the first caller consumes this; waiters receive ErrNoStoreRetry.
	noStoreReader io.ReadCloser
	noStoreMeta   *CacheMetadata

	// Background completion tracking (for non-blocking downloads)
	completionDone chan struct{} // Closed when background finalization completes
	completionErr  atomic.Value  // Stores error from background finalization (type error)

	// Client tracking: stores the UnixNano timestamp of the last
	// time a client registered with this download.  completeDownload
	// periodically checks this timestamp and cancels the download
	// if the time since the last activity exceeds
	// LocalCache.PrefetchTimeout.
	lastClientActivity atomic.Int64
	cancelFn           context.CancelFunc // Cancels the per-download context

	// fetcher is the BlockFetcherV2 driving the background download.
	// Set by performDownload during the disk-mode handoff.
	// Reused by newFetchingRangeReader so concurrent readers share
	// the same fetcher instead of creating duplicate transfers.
	fetcher *BlockFetcherV2
}

// RegisterClient records that a client is actively consuming data from
// this download and returns a deregistration function (currently a no-op
// kept for symmetry).  Each call updates the activity timestamp so the
// idle timer in completeDownload sees recent activity.
func (dl *persistentDownload) RegisterClient() func() {
	dl.lastClientActivity.Store(time.Now().UnixNano())
	return func() {
		// No-op: the idle timer checks elapsed time since last activity
		// rather than a client count, so deregistration is unnecessary.
	}
}

// revalidation carries no-store streaming data from revalidateObject back
// to the caller.  Only non-nil when the origin responds with no-store.
type revalidation struct {
	noStoreReader io.ReadCloser  // Non-nil if origin now says no-store
	noStoreMeta   *CacheMetadata // Metadata for no-store response
}

// revalResult is the internal result type used by the singleflight group
// inside revalidateObject.
type revalResult struct {
	instanceHash  InstanceHash
	meta          *CacheMetadata
	noStoreReader io.ReadCloser
	noStoreMeta   *CacheMetadata
	stale         bool // true ⇒ revalidation failed, serve stale data
}

// PersistentCacheConfig holds configuration for the persistent cache
type PersistentCacheConfig struct {
	// BaseDir is the root directory for the cache.  The BadgerDB database
	// lives directly under BaseDir.  If StorageDirs is empty, a single
	// storage directory is created under BaseDir/objects.
	BaseDir string

	// StorageDirs configures one or more storage directories.
	// Each entry describes a directory path and its size limits.
	// When empty, a single directory under BaseDir is used with
	// MaxSize / HighWaterMarkPercentage / LowWaterMarkPercentage
	// as its limits (for backward compatibility).
	StorageDirs []StorageDirConfig

	// Legacy single-directory fields — used only when StorageDirs is empty.
	MaxSize                 uint64
	HighWaterMarkPercentage int
	LowWaterMarkPercentage  int

	// InlineStorageMaxBytes sets the maximum size for objects stored
	// inline in BadgerDB.  Objects at or below this threshold are stored
	// inline; larger objects go to disk.  0 means use the default (4096).
	InlineStorageMaxBytes int

	DefaultFederation string

	// DeferConfig delays the initial director namespace fetch until
	// Config() is called explicitly.  The server launcher sets this to
	// true because the director may not be reachable when the cache is
	// first constructed (e.g. cache starts before director discovery).
	DeferConfig bool
}

// NewPersistentCache creates a new persistent cache instance
func NewPersistentCache(ctx context.Context, egrp *errgroup.Group, cfg PersistentCacheConfig) (*PersistentCache, error) {
	// Use defaults from param if not specified
	if cfg.BaseDir == "" {
		cfg.BaseDir = param.LocalCache_DataLocation.GetString()
	}
	if cfg.BaseDir == "" {
		return nil, errors.New("LocalCache.DataLocation is not set; cannot determine where to place cache data")
	}

	// Ensure base directory exists (needed before getCacheSize)
	if err := os.MkdirAll(cfg.BaseDir, 0750); err != nil {
		return nil, errors.Wrap(err, "failed to create cache directory")
	}

	// Resolve default watermark percentages from config/params.
	defaultHWP := cfg.HighWaterMarkPercentage
	if defaultHWP == 0 {
		defaultHWP = param.LocalCache_HighWaterMarkPercentage.GetInt()
		if defaultHWP == 0 {
			defaultHWP = 90
		}
	}
	defaultLWP := cfg.LowWaterMarkPercentage
	if defaultLWP == 0 {
		defaultLWP = param.LocalCache_LowWaterMarkPercentage.GetInt()
		if defaultLWP == 0 {
			defaultLWP = 80
		}
	}

	// Build storage dirs and eviction dir configs.
	// If StorageDirs is configured, use them.  Otherwise fall back to the
	// legacy single-dir config (BaseDir + MaxSize).
	storageDirs := cfg.StorageDirs
	if len(storageDirs) == 0 {
		// Legacy single-directory mode
		maxSz := cfg.MaxSize
		if maxSz == 0 {
			sizeStr := param.LocalCache_Size.GetString()
			if sizeStr != "" {
				var err error
				maxSz, err = utils.ParseBytes(sizeStr)
				if err != nil {
					return nil, errors.Wrap(err, "failed to parse LocalCache.Size")
				}
			} else {
				cacheSize, err := getCacheSize(cfg.BaseDir)
				if err != nil {
					return nil, errors.Wrap(err, "failed to determine cache size")
				}
				maxSz = cacheSize
			}
		}
		storageDirs = []StorageDirConfig{{
			Path:                    cfg.BaseDir,
			MaxSize:                 maxSz,
			HighWaterMarkPercentage: defaultHWP,
			LowWaterMarkPercentage:  defaultLWP,
		}}
	}

	// Collect ordered paths and per-dir config keyed by path for later
	// eviction config construction (storage IDs are assigned by
	// NewStorageManager via UUID matching).
	dirPaths := make([]string, len(storageDirs))
	sdCfgByPath := make(map[string]StorageDirConfig, len(storageDirs))
	for i, sd := range storageDirs {
		dirPaths[i] = sd.Path
		sdCfgByPath[sd.Path] = sd

		// Ensure the storage base directory exists.
		if err := os.MkdirAll(sd.Path, 0700); err != nil {
			return nil, errors.Wrapf(err, "failed to create storage directory %q", sd.Path)
		}
	}

	// Initialize database
	db, err := NewCacheDB(ctx, cfg.BaseDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize cache database")
	}

	// Initialize storage manager — assigns storageIDs internally via UUIDs.
	storage, err := NewStorageManager(db, dirPaths, cfg.InlineStorageMaxBytes, egrp)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to initialize storage manager")
	}

	// Build eviction dir configs now that we know storageID → path mapping.
	// GetDirs() returns paths with /objects appended; strip the suffix to
	// match against the original config paths.
	evictionDirCfgs := make(map[StorageID]EvictionDirConfig, len(storageDirs))
	for id, objDir := range storage.GetDirs() {
		basePath := filepath.Dir(objDir) // strip "/objects"
		sd, ok := sdCfgByPath[basePath]
		if !ok {
			// Should not happen — every directory in GetDirs was passed in.
			db.Close()
			return nil, errors.Errorf("storage directory %q not found in config", basePath)
		}

		// Resolve per-dir size.  0 means auto-detect from filesystem.
		maxSz := sd.MaxSize
		if maxSz == 0 {
			cs, err := getCacheSize(sd.Path)
			if err != nil {
				db.Close()
				return nil, errors.Wrapf(err, "failed to determine size for storage dir %q", sd.Path)
			}
			maxSz = cs
		}

		hwp := sd.HighWaterMarkPercentage
		if hwp <= 0 {
			hwp = defaultHWP
		}
		lwp := sd.LowWaterMarkPercentage
		if lwp <= 0 {
			lwp = defaultLWP
		}

		evictionDirCfgs[id] = EvictionDirConfig{
			MaxSize:             maxSz,
			HighWaterPercentage: hwp,
			LowWaterPercentage:  lwp,
		}
	}

	// Initialize eviction manager
	eviction := NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: evictionDirCfgs,
	})

	// Initialize consistency checker
	consistency := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MinAgeForCleanup: -1, // Use default grace period
	})

	// Get federation info
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to get federation info")
	}

	directorURL, err := url.Parse(fedInfo.DirectorEndpoint)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to parse director URL")
	}

	// Initialize transfer engine
	if err := config.InitClient(); err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to initialize client")
	}

	te, err := client.NewTransferEngine(ctx)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to create transfer engine")
	}

	downloadCtx, downloadCancel := context.WithCancel(ctx)

	pc := &PersistentCache{
		ctx:             ctx,
		egrp:            egrp,
		baseDir:         cfg.BaseDir,
		db:              db,
		storage:         storage,
		eviction:        eviction,
		consistency:     consistency,
		te:              te,
		directorURL:     directorURL,
		defaultFed:      cfg.DefaultFederation,
		ac:              newAuthConfig(ctx, egrp),
		namespaceMap:    make(map[string]NamespaceID),
		activeDownloads: make(map[ObjectHash]*persistentDownload),
		downloadCtx:     downloadCtx,
		downloadCancel:  downloadCancel,
		prefetchSem:     make(chan struct{}, 5),
	}
	pc.fedTokenReady = make(chan struct{})
	pc.prestageManager = NewPrestageManager(pc)

	// Restore persisted namespace mappings so that LRU keys and usage
	// counters from prior runs remain valid.
	nsMap, maxID, err := db.LoadNamespaceMappings()
	if err != nil {
		log.Warnf("Failed to load namespace mappings (will reassign): %v", err)
	} else if len(nsMap) > 0 {
		pc.namespaceMap = nsMap
		pc.nextNamespaceID.Store(uint32(maxID))
		log.Infof("Restored %d namespace mappings (max ID %d)", len(nsMap), maxID)
	}

	// Start background tasks
	db.StartGC(ctx, egrp)
	eviction.Start(ctx, egrp)
	consistency.Start(ctx, egrp)

	// Ensure all resources are released when the context is cancelled.
	// Without this, the TransferEngine and BadgerDB leak across tests
	// (each NewFedTest creates a new PersistentCache).
	egrp.Go(func() error {
		<-ctx.Done()
		pc.Close()
		return nil
	})

	// Configure authorization if not deferred
	if !cfg.DeferConfig {
		if err := pc.Config(egrp); err != nil {
			log.Warnf("Initial cache configuration failed: %v", err)
		}
	}

	log.Infof("Persistent cache initialized: %s (%d storage dir(s))", cfg.BaseDir, len(storageDirs))

	return pc, nil
}

// Config configures the cache and starts periodic updates
func (pc *PersistentCache) Config(egrp *errgroup.Group) error {
	if pc.wasConfigured {
		return nil
	}
	pc.wasConfigured = true

	if err := pc.updateConfig(); err != nil {
		log.Warnf("Initial config update failed: %v", err)
	}

	egrp.Go(pc.periodicUpdateConfig)
	return nil
}

// Close shuts down the persistent cache.
//
// Shutdown order:
//  1. Cancel all in-flight downloads (via downloadCancel).
//  2. Wait for completeDownload goroutines to finish — each one closes
//     its own TransferClient, so all clients are gone before step 3.
//  3. Shut down the transfer engine (no live clients remain).
//  4. Stop the consistency checker.
//  5. Close the database.
func (pc *PersistentCache) Close() error {
	if pc.closed.Swap(true) {
		return nil
	}

	// 1. Cancel all in-flight transfers.  This causes transfer workers to
	//    produce error results, which flow back through the engine to each
	//    completeDownload goroutine.
	pc.downloadCancel()

	// 2. Wait for every completeDownload goroutine to finish.  Each one
	//    calls tc.Close() on its own TransferClient before returning, so
	//    by the time downloadWg reaches zero all clients have shut down.
	pc.downloadWg.Wait()

	// 3. Shut down the transfer engine.  Because all clients already closed
	//    their work channels, the engine can drain immediately.
	if pc.te != nil {
		if err := pc.te.Shutdown(); err != nil {
			log.Warnf("Error shutting down transfer engine: %v", err)
		}
	}

	// 4. Stop consistency checker.
	if pc.consistency != nil {
		pc.consistency.Stop()
	}

	// 5. Stop the storage manager (TTL cache eviction goroutine).
	if pc.storage != nil {
		pc.storage.Close()
	}

	// 6. Close database.
	if pc.db != nil {
		if err := pc.db.Close(); err != nil {
			log.Warnf("Error closing cache database: %v", err)
		}
	}

	return nil
}

// KeyChangeCallback returns a callback function that re-encrypts the master key
// when issuer keys change. This is used with LaunchIssuerKeysDirRefresh to ensure
// the cache data remains accessible as long as any issuer key is available.
// The callback updates the masterkey.json file with the master key encrypted
// under all current issuer keys.
func (pc *PersistentCache) KeyChangeCallback() func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if pc.closed.Load() {
			return nil
		}
		if pc.db == nil {
			return nil
		}

		encMgr := pc.db.GetEncryptionManager()
		if encMgr == nil {
			return nil
		}

		log.Info("Issuer keys changed, re-encrypting master key")
		if err := encMgr.UpdateMasterKeyEncryption(); err != nil {
			return errors.Wrap(err, "failed to update master key encryption after key change")
		}
		log.Info("Master key re-encrypted with new issuer keys")
		return nil
	}
}

// Get retrieves an object from the cache, downloading if necessary
func (pc *PersistentCache) Get(ctx context.Context, objectPath, token string) (io.ReadCloser, error) {
	return pc.GetRange(ctx, objectPath, token, "")
}

// SeekableReader is a reader that supports seeking and on-demand block fetching.
// It implements io.ReadSeekCloser for use with http.ServeContent.
//
// For no-store streaming responses, the reader is NOT seekable (IsNoStore returns true).
// In that case the handler must use io.Copy instead of http.ServeContent.
type SeekableReader struct {
	*RangeReader
}

// IsNoStore returns true when this reader wraps a streaming no-store response.
// The caller must NOT use http.ServeContent (which requires seeking); instead
// it should stream the response with io.Copy and set headers manually.
func (sr *SeekableReader) IsNoStore() bool {
	return sr.RangeReader != nil && sr.RangeReader.noStoreReader != nil
}

// objectResolution holds the results of resolving an object path to its
// cached (or newly downloaded) metadata.  It is produced by resolveObject
// and consumed by GetSeekableReader / GetRange.
type objectResolution struct {
	instanceHash InstanceHash
	pelicanURL   string
	token        string
	meta         *CacheMetadata
	dl           *persistentDownload // non-nil when a background download was started
	noStoreRC    io.ReadCloser       // non-nil when the origin says no-store
	noStoreMeta  *CacheMetadata      // metadata for no-store streaming responses
}

// resolveObject performs the shared lookup + download/init/revalidate
// sequence used by every read path.  It returns an objectResolution on
// success.  When the origin responds with no-store, the resolution
// contains a noStoreRC that the caller must consume.
//
// tryRangeInit controls whether the lightweight HEAD-based init
// (initObjectFromStat) is attempted on a cache miss before falling back
// to a full download.
func (pc *PersistentCache) resolveObject(
	ctx context.Context,
	objectPath, token string,
	tryRangeInit bool,
) (*objectResolution, error) {
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(pelicanURL)

	if !pc.ac.authorize(token_scopes.Wlcg_Storage_Read, objectPath, token) {
		return nil, authorizationDenied
	}

	namespaceID := pc.getNamespaceID(objectPath)

	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check ETag cache")
	}

	instanceHash := pc.db.InstanceHash(etag, objectHash)
	meta, err := pc.storage.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check cache")
	}

	var dl *persistentDownload

	if meta == nil {
		if tryRangeInit {
			instanceHash, meta, err = pc.initObjectFromStat(ctx, pelicanURL, objectHash, namespaceID, token)
			if err != nil {
				log.Debugf("initObjectFromStat failed, falling back to full download: %v", err)
				meta = nil
			}
		}
		if meta == nil {
			instanceHash, dl, err = pc.downloadObject(ctx, pelicanURL, objectHash, namespaceID, token)
			if errors.Is(err, ErrNoStore) && dl != nil && dl.noStoreReader != nil {
				return &objectResolution{
					noStoreRC:   dl.noStoreReader,
					noStoreMeta: dl.noStoreMeta,
				}, nil
			}
			if errors.Is(err, ErrNoStoreRetry) {
				return pc.resolveObject(ctx, objectPath, token, tryRangeInit)
			}
			if err != nil {
				return nil, err
			}

			meta, err = pc.storage.GetMetadata(instanceHash)
			if err != nil || meta == nil {
				return nil, errors.New("download completed but metadata not found")
			}
		}
	} else {
		var rv *revalidation
		instanceHash, meta, rv, err = pc.revalidateObject(ctx, instanceHash, objectHash, pelicanURL, namespaceID, token, meta)
		if err != nil {
			return nil, err
		}
		if rv != nil && rv.noStoreReader != nil {
			return &objectResolution{
				noStoreRC:   rv.noStoreReader,
				noStoreMeta: rv.noStoreMeta,
			}, nil
		}
	}

	if err := pc.eviction.RecordAccess(instanceHash); err != nil {
		log.Debugf("Failed to record access for %s: %v", instanceHash, err)
	}

	return &objectResolution{
		instanceHash: instanceHash,
		pelicanURL:   pelicanURL,
		token:        token,
		meta:         meta,
		dl:           dl,
	}, nil
}

// newFetchingRangeReader creates a RangeReader for the given byte range with
// an attached BlockFetcherV2 for on-demand fetching, plus client registration
// for a background download (if any).  All cleanup is wired into the
// RangeReader's onClose callback.
//
// When an active download (res.dl) has an attached fetcher, the reader reuses
// it instead of creating a new one.  This avoids duplicate origin transfers:
// the sequential download writes blocks through the same fetcher, and
// on-demand range fetches for blocks ahead of the sequential position are
// handled by the fetcher's FetchBlocks/doFetch machinery.
// for writing blocks to storage.
func (pc *PersistentCache) newFetchingRangeReader(
	res *objectResolution,
	startByte, endByte int64,
) (*RangeReader, error) {
	var fetcher *BlockFetcherV2
	var fetcherOwned bool // true if we created it (must close on error/onClose)

	if res.dl != nil && res.dl.fetcher != nil {
		// Reuse the download's fetcher — the sequential download is
		// already writing blocks and this fetcher can handle on-demand
		// range fetches for blocks ahead of the download position.
		fetcher = res.dl.fetcher
	} else {
		// No active download or no fetcher — create a per-reader fetcher.
		var err error
		var fedTP client.TokenProvider
		if pc.getFedToken() != "" {
			fedTP = pc.fedTokenAsProvider()
		}
		fetcher, err = NewBlockFetcherV2(
			pc.storage, res.instanceHash, res.pelicanURL, res.token, fedTP, pc.te,
			BlockFetcherV2Config{PrefetchSem: pc.prefetchSem},
		)
		if err != nil {
			log.Warnf("Failed to create block fetcher: %v", err)
		}
		fetcherOwned = true
	}

	var fetchCallback func(ctx context.Context, startBlock, endBlock uint32) error
	if fetcher != nil {
		fetchCallback = fetcher.CreateFetchCallback()
	}

	var dlClientDone func()
	if res.dl != nil {
		dlClientDone = res.dl.RegisterClient()
	}

	rr, err := NewRangeReader(pc.storage, res.instanceHash, startByte, endByte, fetchCallback)
	if err != nil {
		if dlClientDone != nil {
			dlClientDone()
		}
		if fetcherOwned && fetcher != nil {
			fetcher.Close()
		}
		return nil, err
	}

	rr.onClose = func() {
		if dlClientDone != nil {
			dlClientDone()
		}
		if fetcherOwned && fetcher != nil {
			fetcher.Close()
		}
	}

	return rr, nil
}

// GetSeekableReader returns a seekable reader for the full object with on-demand block fetching.
// This is designed for use with http.ServeContent which handles Range requests internally.
//
// When rangeOnly is true and the object is not yet cached, GetSeekableReader
// uses a lightweight HEAD request to initialise on-disk storage instead of
// starting a full sequential download.  This allows BlockFetcherV2 to fetch
// only the blocks the caller actually reads, avoiding a potentially expensive
// full transfer.  Callers should set rangeOnly when they know the request is
// for a sub-range of the object (e.g. an HTTP Range request).
func (pc *PersistentCache) GetSeekableReader(ctx context.Context, objectPath, bearerToken string, rangeOnly bool) (*SeekableReader, *CacheMetadata, error) {
	// Retry once if the object is evicted between resolveObject and reader
	// creation.  The second pass re-resolves the object (triggering a fresh
	// download) and creates a new reader.
	const maxAttempts = 2
	for attempt := 0; attempt < maxAttempts; attempt++ {
		res, err := pc.resolveObject(ctx, objectPath, bearerToken, rangeOnly)
		if err != nil {
			return nil, nil, err
		}

		// Handle no-store streaming response
		if res.noStoreRC != nil {
			return &SeekableReader{RangeReader: &RangeReader{
				size:          res.noStoreMeta.ContentLength,
				noStoreReader: res.noStoreRC,
			}}, res.noStoreMeta, nil
		}

		// Zero-byte file: nothing to read, no fetcher needed.
		if res.meta.ContentLength == 0 {
			return &SeekableReader{RangeReader: &RangeReader{
				storage:      pc.storage,
				instanceHash: res.instanceHash,
				meta:         res.meta,
				start:        0,
				end:          -1,
				position:     0,
			}}, res.meta, nil
		}

		rr, err := pc.newFetchingRangeReader(res, 0, res.meta.ContentLength-1)
		if err != nil {
			if attempt < maxAttempts-1 && isEvictedError(err) {
				log.Debugf("Object %s was evicted during reader setup; retrying resolution", res.instanceHash)
				continue
			}
			return nil, nil, errors.Wrap(err, "failed to create seekable reader")
		}

		return &SeekableReader{RangeReader: rr}, res.meta, nil
	}
	// Unreachable, but the compiler doesn't know the loop always returns.
	return nil, nil, errors.New("failed to create seekable reader after retry")
}

// GetRange retrieves a range of an object from the cache
func (pc *PersistentCache) GetRange(ctx context.Context, objectPath, token, rangeHeader string) (io.ReadCloser, error) {
	// Retry once if the object is evicted between resolveObject and reader
	// creation.  See GetSeekableReader for a detailed explanation.
	const maxAttempts = 2
	for attempt := 0; attempt < maxAttempts; attempt++ {
		res, err := pc.resolveObject(ctx, objectPath, token, rangeHeader != "")
		if err != nil {
			return nil, err
		}

		// Handle no-store streaming response
		if res.noStoreRC != nil {
			return res.noStoreRC, nil
		}

		// Handle range request
		if rangeHeader != "" {
			ranges, err := ParseRangeHeader(rangeHeader, res.meta.ContentLength)
			if err != nil {
				return nil, errors.Wrap(err, "invalid range header")
			}

			if len(ranges) > 0 {
				r := ranges[0]
				rr, err := pc.newFetchingRangeReader(res, r.Start, r.End)
				if err != nil {
					if attempt < maxAttempts-1 && isEvictedError(err) {
						log.Debugf("Object %s was evicted during reader setup; retrying resolution", res.instanceHash)
						continue
					}
					return nil, err
				}
				return rr, nil
			}
		}

		// Return full object reader.  If a background download is in flight,
		// register a client so completeDownload doesn't cancel it while we
		// are reading.
		objReader, objErr := pc.storage.NewObjectReader(res.instanceHash)
		if objErr != nil {
			if attempt < maxAttempts-1 && isEvictedError(objErr) {
				log.Debugf("Object %s was evicted during reader setup; retrying resolution", res.instanceHash)
				continue
			}
			return nil, objErr
		}
		if res.dl != nil {
			dlDone := res.dl.RegisterClient()
			return &readCloserWithCleanup{
				ReadCloser: objReader,
				cleanup:    dlDone,
			}, nil
		}
		return objReader, nil
	}
	return nil, errors.New("failed to create reader after retry")
}

// GetMetadata returns the cache metadata for an object if it exists.
// Returns nil, nil if the object is not cached.
func (pc *PersistentCache) GetMetadata(objectPath, token string) (*CacheMetadata, error) {
	// Check authorization
	if !pc.ac.authorize(token_scopes.Wlcg_Storage_Read, objectPath, token) {
		return nil, authorizationDenied
	}

	// Normalize and compute object hash
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(pelicanURL)

	// Look up latest ETag for this object
	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check ETag cache")
	}

	// Compute file hash and check cache
	instanceHash := pc.db.InstanceHash(etag, objectHash)
	return pc.storage.GetMetadata(instanceHash)
}

// Stat returns the size of an object, querying the origin if not cached
func (pc *PersistentCache) Stat(objectPath, token string) (uint64, error) {
	return pc.stat(objectPath, token, false)
}

// StatCachedOnly returns the size of an object only if it's cached.
// Returns 0, ErrNotCached if the object is not in the cache.
func (pc *PersistentCache) StatCachedOnly(objectPath, token string) (uint64, error) {
	return pc.stat(objectPath, token, true)
}

// HeadResult contains the response metadata for a HEAD request.
type HeadResult struct {
	ContentLength int64
	Meta          *CacheMetadata // non-nil when the object is cached
}

// HeadObject returns metadata for an object without triggering a download.
// If the object is cached, the full CacheMetadata is returned.
// If not cached, the origin is queried via HEAD (DoStat) for the size.
func (pc *PersistentCache) HeadObject(objectPath, token string) (*HeadResult, error) {
	if !pc.ac.authorize(token_scopes.Wlcg_Storage_Read, objectPath, token) {
		return nil, authorizationDenied
	}

	pelicanURL := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(pelicanURL)

	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check ETag cache")
	}

	instanceHash := pc.db.InstanceHash(etag, objectHash)
	meta, err := pc.storage.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check cache")
	}

	if meta != nil {
		return &HeadResult{ContentLength: meta.ContentLength, Meta: meta}, nil
	}

	// Not cached — query the origin for size only.
	dUrl := *pc.directorURL
	dUrl.Path = objectPath
	dUrl.Scheme = "pelican"

	opts := []client.TransferOption{client.WithToken(token), client.WithCacheEmbeddedClientMode()}
	if ft := pc.getFedToken(); ft != "" {
		opts = append(opts, client.WithFedToken(pc.fedTokenAsProvider()))
	}
	statInfo, err := client.DoStat(context.Background(), dUrl.String(), opts...)
	if err != nil {
		return nil, err
	}

	return &HeadResult{ContentLength: statInfo.Size}, nil
}

// ErrNotCached is returned when an object is not in the cache
var ErrNotCached = errors.New("object not cached")

// ErrInitNoStore is a sentinel error returned by initObjectFromStat when
// the origin's Cache-Control indicates the response must not be stored.
// The caller should fall back to a full streaming download via downloadObject.
var ErrInitNoStore = errors.New("object must not be stored (no-store/no-cache/private)")

// stat returns the size of an object
func (pc *PersistentCache) stat(objectPath, token string, cachedOnly bool) (uint64, error) {
	// Check authorization
	if !pc.ac.authorize(token_scopes.Wlcg_Storage_Read, objectPath, token) {
		return 0, authorizationDenied
	}

	// Normalize and compute object hash
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(pelicanURL)

	// Look up latest ETag for this object
	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return 0, errors.Wrap(err, "failed to check ETag cache")
	}

	// Compute file hash and check cache
	instanceHash := pc.db.InstanceHash(etag, objectHash)
	meta, err := pc.storage.GetMetadata(instanceHash)
	if err != nil {
		return 0, errors.Wrap(err, "failed to check cache")
	}

	if meta != nil {
		return uint64(meta.ContentLength), nil
	}

	// Not in cache
	if cachedOnly {
		return 0, ErrNotCached
	}

	// Query origin via the director's origin endpoint
	dUrl := *pc.directorURL
	dUrl.Path = objectPath
	dUrl.Scheme = "pelican"

	opts := []client.TransferOption{client.WithToken(token), client.WithCacheEmbeddedClientMode()}
	if ft := pc.getFedToken(); ft != "" {
		opts = append(opts, client.WithFedToken(pc.fedTokenAsProvider()))
	}
	statInfo, err := client.DoStat(context.Background(), dUrl.String(), opts...)
	if err != nil {
		return 0, err
	}

	return uint64(statInfo.Size), nil
}

// initObjectFromStat performs a lightweight HEAD request to the origin to
// obtain metadata (ETag, Size, LastModified) and initializes on-disk storage
// with an empty block bitmap.  This is the fast path for range-on-miss:
// instead of starting a full sequential download, we only need metadata so
// that BlockFetcherV2 can fetch the requested blocks on demand.
//
// Returns ErrInitNoStore if the origin's response headers indicate the
// object must not be cached — the caller should fall back to downloadObject.
func (pc *PersistentCache) initObjectFromStat(
	ctx context.Context,
	pelicanURL string, objectHash ObjectHash,
	namespaceID NamespaceID,
	token string,
) (InstanceHash, *CacheMetadata, error) {
	// Build a pelican:// URL routed through the director's origin endpoint
	dUrl, err := url.Parse(pelicanURL)
	if err != nil {
		return "", nil, errors.Wrap(err, "invalid source URL")
	}
	dUrl.Scheme = "pelican"

	opts := []client.TransferOption{client.WithToken(token), client.WithCacheEmbeddedClientMode()}
	if ft := pc.getFedToken(); ft != "" {
		opts = append(opts, client.WithFedToken(pc.fedTokenAsProvider()))
	}
	statInfo, err := client.DoStat(ctx, dUrl.String(), opts...)
	if err != nil {
		return "", nil, errors.Wrap(err, "stat failed for range-on-miss")
	}

	etag := statInfo.ETag
	instanceHash := pc.db.InstanceHash(etag, objectHash)

	// If storage already exists (e.g. concurrent request created it), reuse it
	existingMeta, err := pc.storage.GetMetadata(instanceHash)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to check existing storage")
	}
	if existingMeta != nil {
		return instanceHash, existingMeta, nil
	}

	// Initialize disk storage with empty block bitmap
	storageID := pc.eviction.ChooseDiskStorage()
	meta, err := pc.storage.InitDiskStorage(ctx, instanceHash, statInfo.Size, storageID)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to init disk storage for range-on-miss")
	}

	meta.ETag = etag
	meta.LastModified = statInfo.ModTime
	meta.SourceURL = pelicanURL
	meta.NamespaceID = namespaceID
	meta.ContentType = "application/octet-stream"
	meta.LastValidated = time.Now()

	// A zero-byte file has zero blocks — it is "fully downloaded"
	// immediately.  Mark it complete so Age is returned right away.
	if statInfo.Size == 0 {
		meta.Completed = time.Now()
	}

	if err := pc.storage.MergeMetadata(instanceHash, meta); err != nil {
		return "", nil, errors.Wrap(err, "failed to set metadata for range-on-miss")
	}

	// Map objectHash → ETag so subsequent lookups find this instance
	if err := pc.db.SetLatestETag(objectHash, etag, time.Now()); err != nil {
		log.Warnf("Failed to update ETag table for range-on-miss: %v", err)
	}

	log.Debugf("initObjectFromStat: initialized storage for %s (size=%d, etag=%q)",
		instanceHash, statInfo.Size, etag)
	return instanceHash, meta, nil
}

// revalidateObject checks whether a cached object is stale and, if so,
// triggers a single revalidation.  Multiple concurrent callers for the same
// objectHash share one in-flight revalidation via singleflight — the first
// caller does the work and subsequent callers block until it completes.
//
// If the object is fresh (or has no cache-control directives), the method
// returns the original instanceHash and metadata unchanged.
//
// Returns:
//   - instanceHash: the (possibly new) instanceHash after revalidation
//   - meta: updated metadata
//   - rv: non-nil only when the origin responds with no-store (caller must
//     handle the streaming reader)
//   - err: non-nil only on unrecoverable errors; failed revalidations serve
//     stale data silently
func (pc *PersistentCache) revalidateObject(
	ctx context.Context,
	instanceHash InstanceHash, objectHash ObjectHash, pelicanURL string,
	namespaceID NamespaceID,
	token string,
	meta *CacheMetadata,
) (InstanceHash, *CacheMetadata, *revalidation, error) {
	// Check whether staleness revalidation is needed at all
	ccDirectives := meta.GetCacheDirectives()
	if !ccDirectives.HasDirectives() {
		return instanceHash, meta, nil, nil
	}
	if !ccDirectives.IsStale(meta.LastValidated) {
		return instanceHash, meta, nil, nil
	}

	log.Debugf("Cached object %s is stale (validated %v), revalidating", instanceHash, meta.LastValidated)

	// ---- singleflight deduplication ----
	ch := pc.revalGroup.DoChan(string(objectHash), func() (interface{}, error) {
		newHash, dl, dlErr := pc.downloadObject(ctx, pelicanURL, objectHash, namespaceID, token)

		if errors.Is(dlErr, ErrNoStore) && dl != nil && dl.noStoreReader != nil {
			return &revalResult{
				noStoreReader: dl.noStoreReader,
				noStoreMeta:   dl.noStoreMeta,
			}, nil
		}
		if errors.Is(dlErr, ErrNoStoreRetry) {
			return nil, ErrNoStoreRetry
		}

		if dlErr == nil && newHash != "" {
			if newHash != instanceHash {
				log.Debugf("Revalidation fetched new version %s (was %s)", newHash, instanceHash)
				newMeta, getErr := pc.storage.GetMetadata(newHash)
				if getErr != nil || newMeta == nil {
					return &revalResult{stale: true}, nil
				}
				return &revalResult{instanceHash: newHash, meta: newMeta}, nil
			}
			// Same ETag — update LastValidated to extend freshness.
			meta.LastValidated = time.Now()
			revalMeta := &CacheMetadata{LastValidated: meta.LastValidated}
			if setErr := pc.storage.MergeMetadata(instanceHash, revalMeta); setErr != nil {
				log.Warnf("Failed to update LastValidated: %v", setErr)
			}
			return &revalResult{instanceHash: instanceHash, meta: meta}, nil
		}

		if dlErr != nil {
			log.Debugf("Revalidation failed for %s, serving stale: %v", instanceHash, dlErr)
		}
		return &revalResult{stale: true}, nil
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			if errors.Is(res.Err, ErrNoStoreRetry) {
				return "", nil, nil, ErrNoStoreRetry
			}
			return "", nil, nil, res.Err
		}
		result := res.Val.(*revalResult)
		if result.stale {
			return instanceHash, meta, nil, nil
		}
		if result.noStoreReader != nil {
			if res.Shared {
				// Waiter — cannot consume the same reader; caller must retry.
				return "", nil, nil, ErrNoStoreRetry
			}
			return "", nil, &revalidation{
				noStoreReader: result.noStoreReader,
				noStoreMeta:   result.noStoreMeta,
			}, nil
		}
		return result.instanceHash, result.meta, nil, nil
	case <-ctx.Done():
		return "", nil, nil, ctx.Err()
	}
}

// downloadObject downloads an object from the origin and returns the resulting instanceHash.
// The objectHash identifies the logical object (URL); the returned instanceHash includes the ETag.
// When the origin responds with Cache-Control: no-store, the returned error is ErrNoStore
// and the *persistentDownload contains the buffered response data in noStoreData/noStoreMeta.
func (pc *PersistentCache) downloadObject(ctx context.Context, pelicanURL string, objectHash ObjectHash, namespaceID NamespaceID, token string) (InstanceHash, *persistentDownload, error) {
	pc.activeDownloadsMu.Lock()

	// Check if download is already in progress (keyed by objectHash, not instanceHash)
	if dl, exists := pc.activeDownloads[objectHash]; exists {
		waiter := make(chan error, 1)
		dl.mu.Lock()
		if dl.done {
			instanceHash := dl.instanceHash
			err := dl.err
			dl.mu.Unlock()
			pc.activeDownloadsMu.Unlock()
			if errors.Is(err, ErrNoStore) {
				// Stream already consumed by first caller — tell this
				// caller to start its own download.
				return "", nil, ErrNoStoreRetry
			}
			return instanceHash, dl, err
		}
		dl.waiters = append(dl.waiters, waiter)
		dlRef := dl // Keep reference to download
		dl.mu.Unlock()
		pc.activeDownloadsMu.Unlock()

		select {
		case err := <-waiter:
			// Read instanceHash from our reference (no need to look up again)
			dlRef.mu.Lock()
			instanceHash := dlRef.instanceHash
			dlRef.mu.Unlock()
			if errors.Is(err, ErrNoStore) {
				// Stream already consumed by first caller — retry.
				return "", nil, ErrNoStoreRetry
			}
			return instanceHash, dlRef, err
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
	}

	// Create new download (keyed by objectHash)
	dl := &persistentDownload{
		objectHash:     objectHash,
		sourceURL:      pelicanURL,
		namespaceID:    namespaceID,
		completionDone: make(chan struct{}),
	}
	pc.activeDownloads[objectHash] = dl
	pc.activeDownloadsMu.Unlock()

	// Perform download (this will set dl.instanceHash and dl.etag)
	err := pc.performDownload(ctx, dl, token)

	// Ensure completionDone is closed on error/no-store paths so that
	// the deferred cleanup goroutine (and invalidateCachedObject waiters)
	// don't block forever.  For successful inline downloads, performDownload
	// already closed it; for disk mode, completeDownload handles it.
	if err != nil && !errors.Is(err, ErrNoStore) {
		close(dl.completionDone)
	}

	// Notify waiters
	dl.mu.Lock()
	dl.done = true
	dl.err = err
	for _, w := range dl.waiters {
		w <- err
	}
	dl.mu.Unlock()

	// Defer cleanup of the active download entry until background
	// completion finishes.  This keeps the entry (with dl.done == true)
	// in the map so that invalidateCachedObject can find and wait on
	// completionDone, and concurrent GETs for the same object still
	// benefit from deduplication.
	go func() {
		<-dl.completionDone
		pc.activeDownloadsMu.Lock()
		delete(pc.activeDownloads, objectHash)
		pc.activeDownloadsMu.Unlock()
	}()

	if errors.Is(err, ErrNoStore) {
		return "", dl, err
	}
	return dl.instanceHash, dl, err
}

// performDownload actually downloads the object without a prior stat.
// It starts the download and uses early metadata from response headers to decide
// between inline (small files) and disk-based (large files) storage.
func (pc *PersistentCache) performDownload(ctx context.Context, dl *persistentDownload, token string) error {
	sourceURL, err := url.Parse(dl.sourceURL)
	if err != nil {
		return errors.Wrap(err, "invalid source URL")
	}

	// Route the request through the director's origin endpoint so that the
	// director redirects us to the origin.  The client's cache mode causes
	// queryDirector to use the /api/v1.0/director/origin/ prefix, avoiding
	// the need for the origin to have the DirectReads capability.
	sourceURL.Scheme = "pelican"

	// Pass the user token and federation token as separate options.
	// The client sends the user token via Authorization header (which the
	// director copies to the authz query param on redirect) and the
	// federation token as access_token query param on the origin URL.
	userToken := token
	var fedTP client.TokenProvider
	if pc.getFedToken() != "" {
		fedTP = pc.fedTokenAsProvider()
	}

	// Create per-request transfer client
	tc, err := pc.te.NewClient(client.WithAcquireToken(false), client.WithCallback(pc.transferCallback), client.WithCacheEmbeddedClientMode())
	if err != nil {
		return errors.Wrap(err, "failed to create transfer client")
	}
	// tc ownership: if we hand off to the fetcher (AdoptTransfer), it takes
	// over closing tc.  Otherwise we must close it ourselves before returning.
	tcHandedOff := false
	defer func() {
		if !tcHandedOff {
			tc.Close()
		}
	}()

	// Create a channel to receive early metadata (size, ETag) before body transfer
	metadataChan := make(chan client.TransferMetadata, 1)

	// Create a decision writer that buffers data until we know the size
	dw := newDecisionWriter(pc, dl)

	// Derive a per-download context from the cache-wide downloadCtx.
	// PersistentCache.Close() cancels downloadCtx which cascades to all
	// per-download contexts.  The fetcher's idle timeout (in
	// AdoptTransfer) can also cancel this individual context when no
	// clients remain.
	dlCtx, dlCancel := context.WithCancel(pc.downloadCtx)
	dl.cancelFn = dlCancel
	transferOpts := []client.TransferOption{
		client.WithToken(userToken),
		client.WithWriter(dw),
		client.WithMetadataChannel(metadataChan),
	}
	if fedTP != nil {
		transferOpts = append(transferOpts, client.WithFedToken(fedTP))
	}
	tj, err := tc.NewTransferJob(dlCtx, sourceURL, "", false, false, transferOpts...)
	if err != nil {
		return errors.Wrap(err, "failed to create transfer job")
	}

	if err := tc.Submit(tj); err != nil {
		return errors.Wrap(err, "failed to submit transfer job")
	}

	// Wait for metadata or transfer completion
	var metadata client.TransferMetadata
	var metadataReceived bool

	// Channel to receive transfer results.
	// This goroutine terminates when tc.Results() is closed by tc.Close().
	resultChan := make(chan *client.TransferResults, 1)
	tjID := tj.ID()
	pc.egrp.Go(func() error {
		results := tc.Results()
		for result := range results {
			if result.ID() == tjID {
				resultChan <- &result
				return nil
			}
		}
		resultChan <- nil
		return nil
	})

	// Wait for either metadata or result (whichever comes first).
	// We watch both the request context and the download context so that
	// PersistentCache.Close() (which cancels downloadCtx) can abort the
	// metadata wait promptly.
	select {
	case metadata = <-metadataChan:
		metadataReceived = true
		log.Debugf("performDownload: Received early metadata - Size: %d, ETag: %q", metadata.Size, metadata.ETag)
	case result := <-resultChan:
		// Transfer completed before we got metadata (shouldn't happen for successful transfers)
		if result != nil && result.Error != nil {
			return result.Error
		}
		// If we got here without metadata, the transfer completed very quickly
		// Check the decision writer's buffer for size
	case <-ctx.Done():
		return ctx.Err()
	case <-pc.downloadCtx.Done():
		return pc.downloadCtx.Err()
	}

	// Use metadata to compute instanceHash and make storage decision
	if metadataReceived {
		dl.etag = metadata.ETag
		dl.etagObserved = time.Now()
		dl.lastModified = metadata.LastModified
		dl.cacheControl = metadata.CacheControl
		dl.instanceHash = pc.db.InstanceHash(dl.etag, dl.objectHash)

		// Parse Cache-Control directives to decide whether to persist
		ccDirectives := ParseCacheControl(dl.cacheControl)

		// Check if object with this ETag already exists (only relevant for storable responses)
		if ccDirectives.ShouldStore() {
			existingMeta, err := pc.storage.GetMetadata(dl.instanceHash)
			if err != nil {
				log.Warnf("Failed to check existing metadata: %v", err)
			}
			if existingMeta != nil {
				// Object already exists - cancel the download and use cached version
				log.Debugf("performDownload: Object with ETag %q already cached, skipping download", dl.etag)
				if err := pc.db.SetLatestETag(dl.objectHash, dl.etag, dl.etagObserved); err != nil {
					log.Warnf("Failed to update ETag table: %v", err)
				}
				// Signal the writer to discard data
				dw.SetDiscard()
				// Wait for transfer to complete (it may error due to discard, that's ok)
				<-resultChan
				close(dl.completionDone)
				return nil
			}
		} else {
			// Origin says not to store — stream directly to the caller via
			// an io.Pipe instead of buffering the entire response in memory
			// (which could OOM on large objects).
			log.Debugf("performDownload: Origin sent Cache-Control %q — will not persist", dl.cacheControl)

			pr, pw := io.Pipe()
			buffered := dw.SetPipeMode(pw)

			// Combine any data buffered before the decision with the pipe.
			// This avoids writing into the pipe before a consumer is reading
			// (io.Pipe is unbuffered, so that would deadlock).
			var noStoreReader io.ReadCloser
			if len(buffered) > 0 {
				noStoreReader = &multiReadCloser{
					Reader: io.MultiReader(bytes.NewReader(buffered), pr),
					close:  pr.Close,
				}
			} else {
				noStoreReader = pr
			}

			dl.noStoreReader = noStoreReader
			dl.noStoreMeta = &CacheMetadata{
				ETag:          dl.etag,
				LastModified:  dl.lastModified,
				ContentType:   "application/octet-stream",
				ContentLength: metadata.Size,
				SourceURL:     dl.sourceURL,
				NamespaceID:   dl.namespaceID,
			}
			dl.noStoreMeta.SetCacheControl(dl.cacheControl)

			// Spawn a background goroutine to finish receiving the transfer
			// and close the pipe writer when done.  The caller reads from pr.
			tcHandedOff = true
			pc.downloadWg.Add(1)
			pc.egrp.Go(func() error {
				defer pc.downloadWg.Done()
				defer tc.Close()
				defer close(dl.completionDone)
				result := <-resultChan
				if result != nil && result.Error != nil {
					pw.CloseWithError(result.Error)
				} else {
					pw.Close()
				}
				return nil
			})

			return ErrNoStore
		}

		// Make storage decision based on size.
		// metadata.Size == -1 means the origin used chunked encoding
		// (no Content-Length).  In that case we defer the decision:
		// block until enough data has been buffered to decide, or
		// the transfer finishes (whichever comes first).
		if metadata.Size < 0 {
			select {
			case <-dw.ThresholdReady():
				// Buffer reached InlineMaxBytes while transfer is still
				// ongoing → disk mode with unknown final size.
				log.Debugf("performDownload: Unknown size reached threshold — using disk mode")
				if err := dw.SetDiskMode(ctx, -1); err != nil {
					return errors.Wrap(err, "failed to set disk mode for unknown size")
				}
				sharedState, err := pc.storage.GetSharedBlockState(dl.instanceHash)
				if err == nil {
					sharedState.SetDownloading()
				}
			case result := <-resultChan:
				// Transfer finished before reaching the threshold.
				// All data is in the decisionWriter's buffer.
				if result != nil && result.Error != nil {
					return result.Error
				}
				actualSize := int64(dw.BufferLen())
				log.Debugf("performDownload: Unknown size transfer completed — %d bytes, using inline", actualSize)
				if err := dw.SetInlineMode(ctx, actualSize); err != nil {
					return errors.Wrap(err, "failed to set inline mode for deferred decision")
				}
				if err := dw.Finalize(dl); err != nil {
					return errors.Wrap(err, "failed to finalize inline storage")
				}
				close(dl.completionDone)
				return nil
			case <-ctx.Done():
				return ctx.Err()
			case <-pc.downloadCtx.Done():
				return pc.downloadCtx.Err()
			}
		} else if metadata.Size < int64(pc.storage.InlineMaxBytes()) {
			// Small file - use inline storage
			if err := dw.SetInlineMode(ctx, metadata.Size); err != nil {
				return errors.Wrap(err, "failed to set inline mode")
			}
		} else {
			// Large file - use disk storage
			if err := dw.SetDiskMode(ctx, metadata.Size); err != nil {
				return errors.Wrap(err, "failed to set disk mode")
			}
			// Mark the shared block state as having an active download so
			// that concurrent readers wait for blocks instead of starting
			// duplicate range downloads from the origin.
			sharedState, err := pc.storage.GetSharedBlockState(dl.instanceHash)
			if err == nil {
				sharedState.SetDownloading()
			}
		}
	} else {
		// No metadata received — the transfer completed before the origin
		// sent response headers (should be rare).  All data is already in
		// the decisionWriter's buffer, so decide based on actual size.
		dl.etag = ""
		dl.instanceHash = pc.db.InstanceHash(dl.etag, dl.objectHash)
		bufLen := int64(dw.BufferLen())
		if bufLen < int64(pc.storage.InlineMaxBytes()) {
			if err := dw.SetInlineMode(ctx, bufLen); err != nil {
				return errors.Wrap(err, "failed to set inline mode")
			}
		} else {
			if err := dw.SetDiskMode(ctx, bufLen); err != nil {
				return errors.Wrap(err, "failed to set disk mode")
			}
			sharedState, err := pc.storage.GetSharedBlockState(dl.instanceHash)
			if err == nil {
				sharedState.SetDownloading()
			}
		}
	}

	// For inline (small-file) mode, complete synchronously — the data is tiny
	// and the caller needs metadata to be available immediately after
	// downloadObject returns.
	if dw.inlineMode {
		result := <-resultChan
		if result != nil && result.Error != nil {
			return result.Error
		}
		dl.checksums = clientChecksumsToCache(result)
		if err := dw.Finalize(dl); err != nil {
			return errors.Wrap(err, "failed to finalize inline storage")
		}
		close(dl.completionDone)
		return nil
	}

	// For disk (large-file) mode, hand off the in-flight transfer to a
	// BlockFetcherV2.  The fetcher wraps the decisionWriter's BlockWriter
	// with chunk-notification and ETA tracking, drives the transfer to
	// completion via its idle-timeout loop, and can serve on-demand range
	// fetches for blocks ahead of the sequential position.
	fetcher, fetcherErr := NewBlockFetcherV2(
		pc.storage, dl.instanceHash, dl.sourceURL, userToken, fedTP, pc.te,
		BlockFetcherV2Config{PrefetchSem: pc.prefetchSem},
	)
	if fetcherErr != nil {
		return errors.Wrap(fetcherErr, "failed to create block fetcher for handoff")
	}
	dl.fetcher = fetcher

	tcHandedOff = true
	fetcher.AdoptTransfer(dlCtx, tc, dw, resultChan, pc.egrp, &pc.downloadWg,
		func(err error) {
			if sharedState, stateErr := pc.storage.GetSharedBlockState(dl.instanceHash); stateErr == nil {
				sharedState.ClearDownloading()
			}
			if err != nil {
				dl.completionErr.Store(err)
			}
			close(dl.completionDone)
		},
	)

	return nil
}

// multiReadCloser combines an io.Reader (e.g. io.MultiReader) with a
// close function.  This is used to prepend buffered data before a pipe
// reader while still allowing Close() to clean up the pipe.
type multiReadCloser struct {
	io.Reader
	close func() error
}

func (m *multiReadCloser) Close() error {
	return m.close()
}

// readCloserWithCleanup wraps an io.ReadCloser and calls a cleanup
// function when Close is called.  Used to deregister a download client
// when the reader is closed.
type readCloserWithCleanup struct {
	io.ReadCloser
	cleanup func()
}

func (rc *readCloserWithCleanup) Close() error {
	rc.cleanup()
	return rc.ReadCloser.Close()
}

// decisionWriter buffers data until a storage decision is made based on response headers.
// It supports four modes: inline (small files), disk (large files), pipe (no-store streaming),
// and discard (already cached).
type decisionWriter struct {
	pc     *PersistentCache
	dl     *persistentDownload
	mu     sync.Mutex
	cond   *sync.Cond
	buffer []byte

	// thresholdReady is closed when len(buffer) >= InlineMaxBytes while
	// the writer is still undecided.  performDownload uses this to
	// detect that the response is "large enough" for disk storage when
	// the Content-Length header was absent (chunked encoding).
	thresholdReady chan struct{}

	// Mode indicators (set by SetInlineMode, SetDiskMode, SetPipeMode, or SetDiscard)
	decided     bool
	inlineMode  bool
	diskMode    bool
	pipeMode    bool
	discardMode bool

	// For disk mode
	blockWriter io.WriteCloser
	diskMeta    *CacheMetadata
	ctx         context.Context
	size        int64

	// For pipe mode (no-store streaming)
	pipeWriter *io.PipeWriter

	// Error from mode setup
	setupErr error
}

func newDecisionWriter(pc *PersistentCache, dl *persistentDownload) *decisionWriter {
	dw := &decisionWriter{
		pc:             pc,
		dl:             dl,
		buffer:         make([]byte, 0, 64*1024), // Initial 64KB buffer
		thresholdReady: make(chan struct{}),
	}
	dw.cond = sync.NewCond(&dw.mu)
	return dw
}

func (w *decisionWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Wait for decision if not yet made
	for !w.decided {
		// Buffer data while waiting
		w.buffer = append(w.buffer, p...)
		// If the buffer reached the inline threshold, signal
		// performDownload so it can make the deferred storage
		// decision for unknown-size (chunked) responses.
		if len(w.buffer) >= w.pc.storage.InlineMaxBytes() {
			select {
			case <-w.thresholdReady:
				// already closed
			default:
				close(w.thresholdReady)
			}
		}
		return len(p), nil
	}

	if w.setupErr != nil {
		return 0, w.setupErr
	}

	if w.discardMode {
		// Discard all data (object already cached)
		return len(p), nil
	}

	if w.inlineMode {
		// Continue buffering for inline storage
		w.buffer = append(w.buffer, p...)
		return len(p), nil
	}

	if w.diskMode {
		// Write to block writer
		return w.blockWriter.Write(p)
	}

	if w.pipeMode {
		// Stream directly to the pipe (no buffering)
		return w.pipeWriter.Write(p)
	}

	return 0, errors.New("decisionWriter: no mode set")
}

func (w *decisionWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.diskMode && w.blockWriter != nil {
		return w.blockWriter.Close()
	}
	if w.pipeMode && w.pipeWriter != nil {
		return w.pipeWriter.Close()
	}
	return nil
}

// ThresholdReady returns a channel that is closed once the internal buffer
// has accumulated at least InlineMaxBytes of data while still undecided.
// Used by performDownload to wake up when enough data has arrived to
// make the inline-vs-disk decision for chunked (unknown-size) responses.
func (w *decisionWriter) ThresholdReady() <-chan struct{} {
	return w.thresholdReady
}

// BufferLen returns the current length of the internal buffer.
// Safe to call from any goroutine (acquires the mutex).
func (w *decisionWriter) BufferLen() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.buffer)
}

// HandoffBlockWriter atomically replaces the decisionWriter's internal
// block writer with a new io.WriteCloser (typically the fetcher's
// blockWriter adapter that adds chunk notification and ETA tracking).
//
// The underlying *BlockWriter is obtained by type-asserting the current
// blockWriter.  wrapFn is called under the decisionWriter's mutex so the
// swap is atomic with respect to Write.
//
// Returns the wrapper created by wrapFn.
func (w *decisionWriter) HandoffBlockWriter(
	wrapFn func(bw *BlockWriter, bytesWritten int64) io.WriteCloser,
) io.WriteCloser {
	w.mu.Lock()
	defer w.mu.Unlock()
	bw := w.blockWriter.(*BlockWriter)
	bytesWritten := bw.BytesWritten()
	adapter := wrapFn(bw, bytesWritten)
	w.blockWriter = adapter
	return adapter
}

// SetDiscard marks this writer to discard all data (object already cached)
func (w *decisionWriter) SetDiscard() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.discardMode = true
	w.decided = true
	w.cond.Broadcast()
}

// SetPipeMode configures the writer to stream data directly to a pipe writer.
// This is used for no-store responses where data must not be buffered in memory.
// Any data already buffered (before the decision was made) is flushed to the pipe.
// SetPipeMode configures the writer to stream subsequent data to the pipe.
// It returns any data buffered before the decision was made.  The caller
// must prepend this data (e.g. via io.MultiReader) so the full response
// reaches the consumer.  We intentionally do NOT write the buffer into the
// pipe here because the pipe reader is not yet connected to a consumer,
// and io.Pipe is unbuffered — the write would deadlock.
func (w *decisionWriter) SetPipeMode(pw *io.PipeWriter) (buffered []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pipeWriter = pw

	// Hand the pre-decision buffer to the caller instead of writing it
	// into the pipe (which would block).
	buffered = w.buffer
	w.buffer = nil

	w.pipeMode = true
	w.decided = true
	w.cond.Broadcast()
	return buffered
}

// SetInlineMode configures the writer for inline (in-memory) storage
func (w *decisionWriter) SetInlineMode(ctx context.Context, size int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.ctx = ctx

	if size > 0 {
		// Pre-allocate buffer if size is known
		newBuf := make([]byte, len(w.buffer), size)
		copy(newBuf, w.buffer)
		w.buffer = newBuf
	}

	w.inlineMode = true
	w.decided = true
	w.size = size
	w.cond.Broadcast()
	return nil
}

// SetDiskMode configures the writer for disk-based block storage
func (w *decisionWriter) SetDiskMode(ctx context.Context, size int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.ctx = ctx
	w.size = size

	// Initialize disk storage
	storageID := w.pc.eviction.ChooseDiskStorage()
	meta, err := w.pc.storage.InitDiskStorage(ctx, w.dl.instanceHash, size, storageID)
	if err != nil {
		w.setupErr = errors.Wrap(err, "failed to initialize disk storage")
		w.decided = true
		w.cond.Broadcast()
		return w.setupErr
	}

	meta.ETag = w.dl.etag
	meta.LastModified = w.dl.lastModified
	meta.SetCacheControl(w.dl.cacheControl)
	meta.SourceURL = w.dl.sourceURL
	meta.NamespaceID = w.dl.namespaceID
	meta.ContentType = "application/octet-stream"
	meta.LastValidated = time.Now()
	w.diskMeta = meta

	// Update metadata (merge with initial record created by InitDiskStorage)
	if err := w.pc.storage.MergeMetadata(w.dl.instanceHash, meta); err != nil {
		w.setupErr = errors.Wrap(err, "failed to set metadata")
		w.decided = true
		w.cond.Broadcast()
		return w.setupErr
	}

	// Create block writer
	onComplete := func() {
		// At this point the BlockWriter has finalized — if the original
		// content length was unknown (Size == -1 / chunked encoding),
		// BlockWriter.Close() will have updated meta.ContentLength to
		// the actual number of bytes received.
		actualSize := meta.ContentLength

		// Persist any checksums the transfer client collected.
		if len(w.dl.checksums) > 0 {
			checksumMeta := &CacheMetadata{Checksums: w.dl.checksums}
			if err := w.pc.storage.MergeMetadata(w.dl.instanceHash, checksumMeta); err != nil {
				log.Warnf("Failed to update metadata with checksums: %v", err)
			}
		}

		// Usage was already tracked per-block atomically in MarkBlocksDownloaded.
		// Notify the eviction manager so its in-memory counter stays current and
		// an eviction check is triggered if needed.
		w.pc.eviction.NoteUsageIncrease(storageID, actualSize)
		if err := w.pc.db.SetLatestETag(w.dl.objectHash, w.dl.etag, w.dl.etagObserved); err != nil {
			log.Warnf("Failed to update ETag table: %v", err)
		}
		log.Debugf("Completed disk download of %s (%d bytes)", w.dl.instanceHash, actualSize)
	}

	blockWriter, err := w.pc.storage.NewBlockWriter(w.dl.instanceHash, 0, nil, onComplete)
	if err != nil {
		w.setupErr = errors.Wrap(err, "failed to create block writer")
		w.decided = true
		w.cond.Broadcast()
		return w.setupErr
	}
	w.blockWriter = blockWriter

	// Flush buffered data to block writer
	if len(w.buffer) > 0 {
		if _, err := w.blockWriter.Write(w.buffer); err != nil {
			w.setupErr = errors.Wrap(err, "failed to flush buffer to disk")
			w.decided = true
			w.cond.Broadcast()
			return w.setupErr
		}
		w.buffer = nil // Free the buffer
	}

	w.diskMode = true
	w.decided = true
	w.cond.Broadcast()
	return nil
}

// Finalize completes the storage operation after transfer is done
func (w *decisionWriter) Finalize(dl *persistentDownload) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.discardMode {
		// Nothing to do, object was already cached
		return nil
	}

	if w.inlineMode {
		// Store buffered data to inline storage
		meta := &CacheMetadata{
			ETag:          dl.etag,
			LastModified:  dl.lastModified,
			ContentType:   "application/octet-stream",
			ContentLength: int64(len(w.buffer)),
			SourceURL:     dl.sourceURL,
			NamespaceID:   dl.namespaceID,
			Completed:     time.Now(),
			LastValidated: time.Now(),
			Checksums:     dl.checksums,
		}
		meta.SetCacheControl(dl.cacheControl)

		if err := w.pc.storage.StoreInline(w.ctx, dl.instanceHash, meta, w.buffer); err != nil {
			return errors.Wrap(err, "failed to store inline")
		}

		if err := w.pc.db.SetLatestETag(dl.objectHash, dl.etag, dl.etagObserved); err != nil {
			log.Warnf("Failed to update ETag table: %v", err)
		}

		// StoreInline's SetInlineData already tracked usage in the DB;
		// just bump the in-memory estimate so eviction can trigger.
		w.pc.eviction.NoteUsageIncrease(StorageIDInline, int64(len(w.buffer)))
		log.Debugf("Completed inline download of %s (%d bytes)", dl.instanceHash, len(w.buffer))
		return nil
	}

	if w.diskMode {
		// Block writer handles completion via callback
		if w.blockWriter != nil {
			return w.blockWriter.Close()
		}
		return nil
	}

	return errors.New("decisionWriter: finalize called without mode set")
}

// transferCallback handles transfer progress updates
func (pc *PersistentCache) transferCallback(path string, downloaded int64, size int64, completed bool) {
	log.WithFields(log.Fields{
		"path":       path,
		"downloaded": downloaded,
		"size":       size,
		"completed":  completed,
	}).Debug("Transfer progress")
}

// SetFedToken stores the federation token in memory.  It is called by
// cache.LaunchFedTokManager (via the onTokenUpdate callback) whenever the
// token is created or refreshed, eliminating the need to read the token
// back from disk on every origin request.
func (pc *PersistentCache) SetFedToken(tok string) {
	pc.fedTokenMu.Lock()
	first := pc.fedToken == "" && tok != ""
	pc.fedToken = tok
	pc.fedTokenMu.Unlock()

	// Signal any goroutine blocked in getFedToken().
	if first {
		close(pc.fedTokenReady)
	}
}

// getFedToken returns the current federation token.  If no token has
// been set yet it blocks for up to 2 seconds waiting for SetFedToken to
// be called (which happens when the federation token manager
// successfully fetches its first token).  Returns the empty string if
// the wait times out (e.g. site-local mode where no token is expected).
func (pc *PersistentCache) getFedToken() string {
	pc.fedTokenMu.Lock()
	tok := pc.fedToken
	pc.fedTokenMu.Unlock()
	if tok != "" {
		log.Tracef("getFedToken: returning cached token (len=%d)", len(tok))
		return tok
	}

	// No token yet — wait briefly for the first successful fetch.
	log.Debugf("getFedToken: no token available, waiting up to 2s")
	select {
	case <-pc.fedTokenReady:
		log.Debugf("getFedToken: token became available via channel")
	case <-time.After(2 * time.Second):
		log.Debugf("getFedToken: timed out waiting for token")
	}

	pc.fedTokenMu.Lock()
	tok = pc.fedToken
	pc.fedTokenMu.Unlock()
	return tok
}

// fedTokenProvider adapts PersistentCache.getFedToken into a
// client.TokenProvider.  This lets long-running transfers resolve
// the token lazily on each attempt, ensuring they always use the
// latest short-lived federation token.
type fedTokenProvider struct{ pc *PersistentCache }

// Get returns the current federation token (never errors).
func (p *fedTokenProvider) Get() (string, error) { return p.pc.getFedToken(), nil }

// fedTokenAsProvider returns a TokenProvider backed by getFedToken.
// Callers should first verify that a token is available (getFedToken
// blocks briefly on startup) and only create a provider when non-empty.
func (pc *PersistentCache) fedTokenAsProvider() client.TokenProvider {
	return &fedTokenProvider{pc: pc}
}

// normalizePath converts a path to a full pelican URL.
// osdf:// URLs are rewritten to their pelican:// equivalent so that
// cache keys are consistent regardless of the scheme used by the caller.
func (pc *PersistentCache) normalizePath(objectPath string) string {
	if strings.HasPrefix(objectPath, "osdf://") {
		return "pelican://osg-htc.org" + strings.TrimPrefix(objectPath, "osdf://")
	}

	// If already a full URL, return as-is
	if strings.HasPrefix(objectPath, "pelican://") {
		return objectPath
	}

	// Construct URL using director
	u := *pc.directorURL
	u.Scheme = "pelican"
	u.Path = path.Clean(objectPath)

	return u.String()
}

// getNamespaceID returns or assigns a namespace ID for a path
func (pc *PersistentCache) getNamespaceID(objectPath string) NamespaceID {
	// Extract namespace prefix from path
	prefix := extractNamespacePrefix(objectPath)

	pc.namespaceMapMu.RLock()
	if id, exists := pc.namespaceMap[prefix]; exists {
		pc.namespaceMapMu.RUnlock()
		return id
	}
	pc.namespaceMapMu.RUnlock()

	// Assign new ID
	pc.namespaceMapMu.Lock()
	defer pc.namespaceMapMu.Unlock()

	// Double-check after acquiring write lock
	if id, exists := pc.namespaceMap[prefix]; exists {
		return id
	}

	id := NamespaceID(pc.nextNamespaceID.Add(1))
	pc.namespaceMap[prefix] = id

	// Persist the mapping so it survives restarts
	if err := pc.db.SetNamespaceMapping(prefix, id); err != nil {
		log.Warnf("Failed to persist namespace mapping %s -> %d: %v", prefix, id, err)
	}

	log.Debugf("Assigned namespace ID %d to prefix %s", id, prefix)
	return id
}

// extractNamespacePrefix extracts the namespace prefix from a path
func extractNamespacePrefix(objectPath string) string {
	// Parse URL if present
	if strings.Contains(objectPath, "://") {
		if u, err := url.Parse(objectPath); err == nil {
			objectPath = u.Path
		}
	}

	// Clean the path
	objectPath = path.Clean(objectPath)

	// Split and take first component
	parts := strings.SplitN(strings.TrimPrefix(objectPath, "/"), "/", 2)
	if len(parts) > 0 {
		return "/" + parts[0]
	}
	return "/"
}

// updateConfig updates the cache configuration from the director
func (pc *PersistentCache) updateConfig() error {
	var respNS []server_structs.NamespaceAdV2

	fedInfo, err := config.GetFederation(pc.ctx)
	if err != nil {
		return err
	}

	directorEndpoint := fedInfo.DirectorEndpoint
	if directorEndpoint == "" {
		return errors.New("no director specified")
	}

	directorEndpointURL, err := url.Parse(directorEndpoint)
	if err != nil {
		return errors.Wrap(err, "unable to parse director URL")
	}

	listURL, err := url.JoinPath(directorEndpointURL.String(), "api", "v2.0", "director", "listNamespaces")
	if err != nil {
		return errors.Wrap(err, "unable to generate listNamespaces URL")
	}

	tr := config.GetTransport()
	req, err := http.NewRequestWithContext(pc.ctx, "GET", listURL, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create listNamespaces request")
	}
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to fetch listNamespaces")
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&respNS); err != nil {
		return errors.Wrap(err, "failed to decode namespace response")
	}

	return pc.ac.updateConfig(respNS)
}

// periodicUpdateConfig periodically updates the cache configuration
func (pc *PersistentCache) periodicUpdateConfig() error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pc.ctx.Done():
			return nil
		case <-ticker.C:
			if err := pc.updateConfig(); err != nil {
				log.Warnf("Failed to update cache config: %v", err)
			}
		}
	}
}

// GetStats returns cache statistics
func (pc *PersistentCache) GetStats() PersistentCacheStats {
	evictStats := pc.eviction.GetStats()
	consistStats := pc.consistency.GetStats()

	// Convert StorageUsageKey map to string-keyed map for JSON serialization
	nsUsage := make(map[string]int64, len(evictStats.NamespaceUsage))
	for k, v := range evictStats.NamespaceUsage {
		key := fmt.Sprintf("s%d:ns%d", k.StorageID, k.NamespaceID)
		nsUsage[key] = v
	}

	return PersistentCacheStats{
		TotalUsage:       evictStats.TotalUsage,
		DirStats:         evictStats.DirStats,
		NamespaceUsage:   nsUsage,
		ConsistencyStats: consistStats,
	}
}

// PersistentCacheStats holds cache statistics
type PersistentCacheStats struct {
	TotalUsage       uint64
	DirStats         map[StorageID]DirEvictionStats
	NamespaceUsage   map[string]int64
	ConsistencyStats ConsistencyStats
}
