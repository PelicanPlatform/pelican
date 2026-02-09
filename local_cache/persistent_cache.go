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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// ErrNoStore is returned when the origin sends Cache-Control: no-store (or private).
// The response data is buffered in persistentDownload.noStoreData and must be served
// directly without persisting to the cache.
var ErrNoStore = errors.New("origin response has Cache-Control: no-store")

// PersistentCache is the new persistent local cache implementation
// It uses BadgerDB for metadata and block tracking, and encrypted files on disk
type PersistentCache struct {
	ctx           context.Context
	egrp          *errgroup.Group
	baseDir       string

	// Core components
	db           *CacheDB
	storage      *StorageManager
	eviction     *EvictionManager
	consistency  *ConsistencyChecker

	// Transfer engine for creating per-request clients
	te           *client.TransferEngine

	// Federation configuration
	directorURL  *url.URL
	defaultFed   string
	ac           *authConfig

	// Namespace mapping (URL prefix -> namespace ID)
	namespaceMap     map[string]uint32
	namespaceMapMu   sync.RWMutex
	nextNamespaceID  atomic.Uint32

	// Active downloads tracking
	activeDownloads   map[string]*persistentDownload
	activeDownloadsMu sync.RWMutex

	// Configuration
	wasConfigured bool
	closed        atomic.Bool
}

// persistentDownload tracks an active download operation
type persistentDownload struct {
	instanceHash     string
	objectHash   string // Hash of the URL (for ETag table)
	sourceURL    string
	namespaceID  uint32
	etag         string    // ETag from origin
	lastModified time.Time // Last-Modified from origin
	cacheControl string    // Cache-Control from origin
	meta         *CacheMetadata
	waiters     []chan error
	mu          sync.Mutex
	done        bool
	err         error

	// noStoreData holds the buffered response body when the origin sends
	// Cache-Control: no-store (or private).  The data is served directly
	// to the client without being persisted to the cache.
	noStoreData []byte
	noStoreMeta *CacheMetadata

	// Background completion tracking (for non-blocking downloads)
	completionDone chan struct{} // Closed when background finalization completes
	completionErr  atomic.Value  // Stores error from background finalization (type error)
}

// PersistentCacheConfig holds configuration for the persistent cache
type PersistentCacheConfig struct {
	BaseDir                 string
	MaxSize                 uint64
	HighWaterMarkPercentage int
	LowWaterMarkPercentage  int
	DefaultFederation       string
	DeferConfig             bool
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

	if cfg.MaxSize == 0 {
		sizeStr := param.LocalCache_Size.GetString()
		if sizeStr != "" {
			var err error
			cfg.MaxSize, err = parseSize(sizeStr)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse LocalCache.Size")
			}
		} else {
			// Get available space on disk
			cacheSize, err := getCacheSize(cfg.BaseDir)
			if err != nil {
				return nil, errors.Wrap(err, "failed to determine cache size")
			}
			cfg.MaxSize = cacheSize
		}
	}

	if cfg.HighWaterMarkPercentage == 0 {
		cfg.HighWaterMarkPercentage = param.LocalCache_HighWaterMarkPercentage.GetInt()
		if cfg.HighWaterMarkPercentage == 0 {
			cfg.HighWaterMarkPercentage = 90
		}
	}

	if cfg.LowWaterMarkPercentage == 0 {
		cfg.LowWaterMarkPercentage = param.LocalCache_LowWaterMarkPercentage.GetInt()
		if cfg.LowWaterMarkPercentage == 0 {
			cfg.LowWaterMarkPercentage = 80
		}
	}

	// Initialize database
	db, err := NewCacheDB(ctx, cfg.BaseDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize cache database")
	}

	// Initialize storage manager
	storage, err := NewStorageManager(db, cfg.BaseDir)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to initialize storage manager")
	}

	// Initialize eviction manager
	eviction := NewEvictionManager(db, storage, EvictionConfig{
		MaxSize:             cfg.MaxSize,
		HighWaterPercentage: cfg.HighWaterMarkPercentage,
		LowWaterPercentage:  cfg.LowWaterMarkPercentage,
	})

	// Initialize consistency checker
	consistency := NewConsistencyChecker(db, storage, cfg.BaseDir, ConsistencyConfig{
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
		namespaceMap:    make(map[string]uint32),
		activeDownloads: make(map[string]*persistentDownload),
	}

	// Restore persisted namespace mappings so that LRU keys and usage
	// counters from prior runs remain valid.
	nsMap, maxID, err := db.LoadNamespaceMappings()
	if err != nil {
		log.Warnf("Failed to load namespace mappings (will reassign): %v", err)
	} else if len(nsMap) > 0 {
		pc.namespaceMap = nsMap
		pc.nextNamespaceID.Store(maxID)
		log.Infof("Restored %d namespace mappings (max ID %d)", len(nsMap), maxID)
	}

	// Start background tasks
	db.StartGC(ctx, egrp)
	eviction.Start(ctx, egrp)
	consistency.Start(ctx, egrp)

	// Configure authorization if not deferred
	if !cfg.DeferConfig {
		if err := pc.Config(egrp); err != nil {
			log.Warnf("Initial cache configuration failed: %v", err)
		}
	}

	log.Infof("Persistent cache initialized: %s (max size: %d bytes)", cfg.BaseDir, cfg.MaxSize)

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

// Close shuts down the persistent cache
func (pc *PersistentCache) Close() error {
	if pc.closed.Swap(true) {
		return nil
	}

	// Close transfer engine
	if pc.te != nil {
		if err := pc.te.Shutdown(); err != nil {
			log.Warnf("Error shutting down transfer engine: %v", err)
		}
	}

	// Stop consistency checker
	if pc.consistency != nil {
		pc.consistency.Stop()
	}

	// Close database
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
type SeekableReader struct {
	*RangeReader
}

// GetSeekableReader returns a seekable reader for the full object with on-demand block fetching.
// This is designed for use with http.ServeContent which handles Range requests internally.
func (pc *PersistentCache) GetSeekableReader(ctx context.Context, objectPath, bearerToken string) (*SeekableReader, *CacheMetadata, error) {
	// Normalize and compute object hash (URL-based)
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := ComputeObjectHash(pelicanURL)

	// Check authorization
	if !pc.ac.authorize("storage.read", objectPath, bearerToken) {
		return nil, nil, authorizationDenied
	}

	// Get or assign namespace ID
	namespaceID := pc.getNamespaceID(objectPath)

	// Look up latest ETag for this object
	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to check ETag cache")
	}

	// Compute file hash (etag:objectHash)
	instanceHash := ComputeInstanceHash(etag, objectHash)

	// Check if we have the object with this ETag
	meta, err := pc.storage.GetMetadata(instanceHash)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to check cache")
	}

	if meta == nil {
		// Need to download the object (will query for current ETag)
		// Note: downloadObject starts the download asynchronously; it returns
		// as soon as metadata is available, not when the download completes
		var dl *persistentDownload
		instanceHash, dl, err = pc.downloadObject(ctx, pelicanURL, objectHash, namespaceID, bearerToken)
		if errors.Is(err, ErrNoStore) && dl != nil {
			// Origin says no-store — serve directly from in-memory buffer
			reader := bytes.NewReader(dl.noStoreData)
			return &SeekableReader{RangeReader: &RangeReader{
				reader: reader,
				size:   int64(len(dl.noStoreData)),
			}}, dl.noStoreMeta, nil
		}
		if err != nil {
			return nil, nil, err
		}

		// Re-fetch metadata
		meta, err = pc.storage.GetMetadata(instanceHash)
		if err != nil || meta == nil {
			return nil, nil, errors.New("download completed but metadata not found")
		}
	} else {
		// Object is cached — check staleness via Cache-Control directives.
		ccDirectives := meta.GetCacheDirectives()
		// Only check staleness if any cache-control directive was set
		if ccDirectives.NoStore || ccDirectives.NoCache || ccDirectives.Private || ccDirectives.MaxAgeSet || ccDirectives.SMaxAgeSet {
			if ccDirectives.IsStale(meta.LastValidated) {
				log.Debugf("Cached object %s is stale (validated %v), revalidating", instanceHash, meta.LastValidated)
				newHash, dl, dlErr := pc.downloadObject(ctx, pelicanURL, objectHash, namespaceID, bearerToken)
				if errors.Is(dlErr, ErrNoStore) && dl != nil {
					reader := bytes.NewReader(dl.noStoreData)
					return &SeekableReader{RangeReader: &RangeReader{
						reader: reader,
						size:   int64(len(dl.noStoreData)),
					}}, dl.noStoreMeta, nil
				}
				if dlErr == nil && newHash != "" {
					// Download succeeded — the origin returned a (possibly new) version.
					// If the instanceHash changed (new ETag), use the new metadata.
					if newHash != instanceHash {
						log.Debugf("Revalidation fetched new version %s (was %s)", newHash, instanceHash)
						instanceHash = newHash
						meta, err = pc.storage.GetMetadata(instanceHash)
						if err != nil || meta == nil {
							return nil, nil, errors.New("revalidation completed but metadata not found")
						}
					} else {
						// Same ETag — update LastValidated to extend freshness
						meta.LastValidated = time.Now()
						if setErr := pc.storage.SetMetadata(instanceHash, meta); setErr != nil {
							log.Warnf("Failed to update LastValidated: %v", setErr)
						}
					}
				} else if dlErr != nil {
					// Revalidation failed — serve stale data rather than failing
					log.Debugf("Revalidation failed for %s, serving stale: %v", instanceHash, dlErr)
				}
			}
		}
	}

	// Record access for LRU
	pc.eviction.RecordAccess(instanceHash)

	// Create block fetcher for on-demand fetching
	fetcher, err := NewBlockFetcherV2(
		pc.storage, instanceHash, pelicanURL, bearerToken, pc.te,
		BlockFetcherV2Config{}, // Use defaults from params
	)
	if err != nil {
		log.Warnf("Failed to create block fetcher: %v", err)
	}

	var fetchCallback func(ctx context.Context, startBlock, endBlock uint32) error
	var clientDone func()
	if fetcher != nil {
		fetchCallback = fetcher.CreateFetchCallback()
		clientDone = fetcher.RegisterClient()
	}

	// Create a RangeReader for the full object (0 to ContentLength-1)
	rr, err := NewRangeReader(pc.storage, instanceHash, 0, meta.ContentLength-1, fetchCallback)
	if err != nil {
		if clientDone != nil {
			clientDone()
		}
		if fetcher != nil {
			fetcher.Close()
		}
		return nil, nil, errors.Wrap(err, "failed to create seekable reader")
	}
	// Chain cleanup: deregister client and close the fetcher's TransferClient
	rr.onClose = func() {
		if clientDone != nil {
			clientDone()
		}
		if fetcher != nil {
			fetcher.Close()
		}
	}

	return &SeekableReader{RangeReader: rr}, meta, nil
}

// GetRange retrieves a range of an object from the cache
func (pc *PersistentCache) GetRange(ctx context.Context, objectPath, token, rangeHeader string) (io.ReadCloser, error) {
	// Normalize and compute object hash (URL-based)
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := ComputeObjectHash(pelicanURL)

	// Check authorization
	if !pc.ac.authorize("storage.read", objectPath, token) {
		return nil, authorizationDenied
	}

	// Get or assign namespace ID
	namespaceID := pc.getNamespaceID(objectPath)

	// Look up latest ETag for this object
	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check ETag cache")
	}

	// Compute file hash (etag:objectHash)
	instanceHash := ComputeInstanceHash(etag, objectHash)

	// Check if we have the object with this ETag
	meta, err := pc.storage.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check cache")
	}

	if meta == nil {
		// Need to download the object (will query for current ETag)
		var dl *persistentDownload
		instanceHash, dl, err = pc.downloadObject(ctx, pelicanURL, objectHash, namespaceID, token)
		if errors.Is(err, ErrNoStore) && dl != nil {
			// Origin says no-store — serve directly from in-memory buffer
			// For range requests we still need a seekable reader, but wrap in io.NopCloser
			reader := bytes.NewReader(dl.noStoreData)
			return io.NopCloser(reader), nil
		}
		if err != nil {
			return nil, err
		}

		// Re-fetch metadata
		meta, err = pc.storage.GetMetadata(instanceHash)
		if err != nil || meta == nil {
			return nil, errors.New("download completed but metadata not found")
		}
	}

	// Record access for LRU
	pc.eviction.RecordAccess(instanceHash)

	// Handle range request
	if rangeHeader != "" {
		fetcher, err := NewBlockFetcherV2(
			pc.storage, instanceHash, pelicanURL, token, pc.te,
			BlockFetcherV2Config{}, // Use defaults from params
		)
		if err != nil {
			log.Warnf("Failed to create block fetcher: %v", err)
		}

		ranges, err := ParseRangeHeader(rangeHeader, meta.ContentLength)
		if err != nil {
			if fetcher != nil {
				fetcher.Close()
			}
			return nil, errors.Wrap(err, "invalid range header")
		}

		if len(ranges) > 0 {
			r := ranges[0]
			var fetchCallback func(ctx context.Context, startBlock, endBlock uint32) error
			var clientDone func()
			if fetcher != nil {
				fetchCallback = fetcher.CreateFetchCallback()
				clientDone = fetcher.RegisterClient()
			}
			rr, rrErr := NewRangeReader(pc.storage, instanceHash, r.Start, r.End, fetchCallback)
			if rrErr != nil {
				if clientDone != nil {
					clientDone()
				}
				if fetcher != nil {
					fetcher.Close()
				}
				return nil, rrErr
			}
			rr.onClose = func() {
				if clientDone != nil {
					clientDone()
				}
				if fetcher != nil {
					fetcher.Close()
				}
			}
			return rr, nil
		}

		// No valid ranges — close the fetcher
		if fetcher != nil {
			fetcher.Close()
		}
	}

	// Return full object reader
	return pc.storage.NewObjectReader(instanceHash)
}

// GetMetadata returns the cache metadata for an object if it exists.
// Returns nil, nil if the object is not cached.
func (pc *PersistentCache) GetMetadata(objectPath, token string) (*CacheMetadata, error) {
	// Check authorization
	if !pc.ac.authorize("storage.read", objectPath, token) {
		return nil, authorizationDenied
	}

	// Normalize and compute object hash
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := ComputeObjectHash(pelicanURL)

	// Look up latest ETag for this object
	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check ETag cache")
	}

	// Compute file hash and check cache
	instanceHash := ComputeInstanceHash(etag, objectHash)
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

// ErrNotCached is returned when an object is not in the cache
var ErrNotCached = errors.New("object not cached")

// stat returns the size of an object
func (pc *PersistentCache) stat(objectPath, token string, cachedOnly bool) (uint64, error) {
	// Check authorization
	if !pc.ac.authorize("storage.read", objectPath, token) {
		return 0, authorizationDenied
	}

	// Normalize and compute object hash
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := ComputeObjectHash(pelicanURL)

	// Look up latest ETag for this object
	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return 0, errors.Wrap(err, "failed to check ETag cache")
	}

	// Compute file hash and check cache
	instanceHash := ComputeInstanceHash(etag, objectHash)
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

	// Query origin with directread to bypass cache (we ARE the cache)
	dUrl := *pc.directorURL
	dUrl.Path = objectPath
	dUrl.Scheme = "pelican"
	q := dUrl.Query()
	q.Set("directread", "")
	dUrl.RawQuery = q.Encode()

	statInfo, err := client.DoStat(context.Background(), dUrl.String(), client.WithToken(token))
	if err != nil {
		return 0, err
	}

	return uint64(statInfo.Size), nil
}

// downloadObject downloads an object from the origin and returns the resulting instanceHash.
// The objectHash identifies the logical object (URL); the returned instanceHash includes the ETag.
// When the origin responds with Cache-Control: no-store, the returned error is ErrNoStore
// and the *persistentDownload contains the buffered response data in noStoreData/noStoreMeta.
func (pc *PersistentCache) downloadObject(ctx context.Context, pelicanURL, objectHash string, namespaceID uint32, token string) (string, *persistentDownload, error) {
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
				return "", dl, err
			}
			return instanceHash, nil, err
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
				return "", dlRef, err
			}
			return instanceHash, nil, err
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

	// Notify waiters
	dl.mu.Lock()
	dl.done = true
	dl.err = err
	for _, w := range dl.waiters {
		w <- err
	}
	dl.mu.Unlock()

	// Clean up the active download entry
	// Waiters have their own reference, so it's safe to delete immediately
	go func() {
		pc.activeDownloadsMu.Lock()
		delete(pc.activeDownloads, objectHash)
		pc.activeDownloadsMu.Unlock()
	}()

	if errors.Is(err, ErrNoStore) {
		return "", dl, err
	}
	return dl.instanceHash, nil, err
}

// performDownload actually downloads the object without a prior stat.
// It starts the download and uses early metadata from response headers to decide
// between inline (small files) and disk-based (large files) storage.
func (pc *PersistentCache) performDownload(ctx context.Context, dl *persistentDownload, token string) error {
	sourceURL, err := url.Parse(dl.sourceURL)
	if err != nil {
		return errors.Wrap(err, "invalid source URL")
	}

	// Add directread query parameter to bypass cache (we ARE the cache)
	sourceURL.Scheme = "pelican"
	q := sourceURL.Query()
	q.Set("directread", "")
	sourceURL.RawQuery = q.Encode()

	// Create per-request transfer client
	tc, err := pc.te.NewClient(client.WithAcquireToken(false), client.WithCallback(pc.transferCallback))
	if err != nil {
		return errors.Wrap(err, "failed to create transfer client")
	}
	defer tc.Close()

	// Create a channel to receive early metadata (size, ETag) before body transfer
	metadataChan := make(chan client.TransferMetadata, 1)

	// Create a decision writer that buffers data until we know the size
	dw := newDecisionWriter(pc, dl)

	// Start the transfer - the decision writer will buffer until we make a storage decision
	tj, err := tc.NewTransferJob(ctx, sourceURL, "", false, false,
		client.WithToken(token),
		client.WithWriter(dw),
		client.WithMetadataChannel(metadataChan),
	)
	if err != nil {
		return errors.Wrap(err, "failed to create transfer job")
	}

	if err := tc.Submit(tj); err != nil {
		return errors.Wrap(err, "failed to submit transfer job")
	}

	// Wait for metadata or transfer completion
	var metadata client.TransferMetadata
	var metadataReceived bool

	// Channel to receive transfer results
	resultChan := make(chan *client.TransferResults, 1)
	go func() {
		results := tc.Results()
		for result := range results {
			if result.ID() == tj.ID() {
				resultChan <- &result
				return
			}
		}
		resultChan <- nil
	}()

	// Wait for either metadata or result (whichever comes first)
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
	}

	// Use metadata to compute instanceHash and make storage decision
	if metadataReceived {
		dl.etag = metadata.ETag
		dl.lastModified = metadata.LastModified
		dl.cacheControl = metadata.CacheControl
		dl.instanceHash = ComputeInstanceHash(dl.etag, dl.objectHash)

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
				if err := pc.db.SetLatestETag(dl.objectHash, dl.etag); err != nil {
					log.Warnf("Failed to update ETag table: %v", err)
				}
				// Signal the writer to discard data
				dw.SetDiscard()
				// Wait for transfer to complete (it may error due to discard, that's ok)
				<-resultChan
				return nil
			}
		}

		if !ccDirectives.ShouldStore() {
			// Origin says not to store — buffer in memory and return ErrNoStore.
			// We still need to finish receiving the transfer so the client gets data.
			log.Debugf("performDownload: Origin sent Cache-Control %q — will not persist", dl.cacheControl)
			if err := dw.SetInlineMode(ctx, metadata.Size); err != nil {
				return errors.Wrap(err, "failed to set inline mode for no-store response")
			}

			// Wait for transfer to finish
			result := <-resultChan
			if result != nil && result.Error != nil {
				return result.Error
			}

			// Capture the buffered data and metadata for the caller
			dl.noStoreData = dw.buffer
			dl.noStoreMeta = &CacheMetadata{
				ETag:          dl.etag,
				LastModified:  dl.lastModified,
				ContentType:   "application/octet-stream",
				ContentLength: int64(len(dw.buffer)),
				SourceURL:     dl.sourceURL,
				ObjectHash:    dl.objectHash,
				NamespaceID:   dl.namespaceID,
			}
			dl.noStoreMeta.SetCacheControl(dl.cacheControl)
			return ErrNoStore
		}

		// Make storage decision based on size
		if metadata.Size < InlineThreshold {
			// Small file - use inline storage
			if err := dw.SetInlineMode(ctx, metadata.Size); err != nil {
				return errors.Wrap(err, "failed to set inline mode")
			}
		} else {
			// Large file - use disk storage
			if err := dw.SetDiskMode(ctx, metadata.Size); err != nil {
				return errors.Wrap(err, "failed to set disk mode")
			}
		}
	} else {
		// No metadata received - use buffered data size
		// This is a fallback for origins that don't provide Content-Length
		dl.etag = ""
		dl.instanceHash = ComputeInstanceHash(dl.etag, dl.objectHash)
		// Default to inline mode for unknown sizes
		if err := dw.SetInlineMode(ctx, 0); err != nil {
			return errors.Wrap(err, "failed to set inline mode")
		}
	}

	// Storage decision made - spawn background goroutine for completion
	// This allows reads to begin immediately while download continues
	go pc.completeDownload(ctx, dl, dw, resultChan)

	return nil
}

// completeDownload handles the background completion of a download after the
// storage decision has been made. This runs in a separate goroutine to allow
// non-blocking downloads.
func (pc *PersistentCache) completeDownload(ctx context.Context, dl *persistentDownload, dw *decisionWriter, resultChan chan *client.TransferResults) {
	defer close(dl.completionDone)

	// Wait for transfer completion
	result := <-resultChan
	if result != nil && result.Error != nil {
		dl.completionErr.Store(result.Error)
		log.Warnf("Transfer failed for %s: %v", dl.instanceHash, result.Error)
		return
	}

	// Finalize storage
	if err := dw.Finalize(dl); err != nil {
		dl.completionErr.Store(errors.Wrap(err, "failed to finalize storage"))
		log.Warnf("Failed to finalize %s: %v", dl.instanceHash, err)
		return
	}

	log.Debugf("Background completion finished for %s", dl.instanceHash)
}

// inlineWriter is a simple io.WriteCloser that collects data in memory
type inlineWriter struct {
	data []byte
}

func (w *inlineWriter) Write(p []byte) (n int, err error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *inlineWriter) Close() error {
	return nil
}

// decisionWriter buffers data until a storage decision is made based on response headers.
// It supports three modes: inline (small files), disk (large files), and discard (cached).
type decisionWriter struct {
	pc     *PersistentCache
	dl     *persistentDownload
	mu     sync.Mutex
	cond   *sync.Cond
	buffer []byte

	// Mode indicators (set by SetInlineMode, SetDiskMode, or SetDiscard)
	decided     bool
	inlineMode  bool
	diskMode    bool
	discardMode bool

	// For disk mode
	blockWriter io.WriteCloser
	diskMeta    *CacheMetadata
	ctx         context.Context
	size        int64

	// Error from mode setup
	setupErr error
}

func newDecisionWriter(pc *PersistentCache, dl *persistentDownload) *decisionWriter {
	dw := &decisionWriter{
		pc:     pc,
		dl:     dl,
		buffer: make([]byte, 0, 64*1024), // Initial 64KB buffer
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

	return 0, errors.New("decisionWriter: no mode set")
}

func (w *decisionWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.diskMode && w.blockWriter != nil {
		return w.blockWriter.Close()
	}
	return nil
}

// SetDiscard marks this writer to discard all data (object already cached)
func (w *decisionWriter) SetDiscard() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.discardMode = true
	w.decided = true
	w.cond.Broadcast()
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
	meta, err := w.pc.storage.InitDiskStorage(ctx, w.dl.instanceHash, size)
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
	meta.ObjectHash = w.dl.objectHash
	meta.NamespaceID = w.dl.namespaceID
	meta.ContentType = "application/octet-stream"
	meta.LastValidated = time.Now()
	w.diskMeta = meta

	// Update metadata
	if err := w.pc.storage.SetMetadata(w.dl.instanceHash, meta); err != nil {
		w.setupErr = errors.Wrap(err, "failed to set metadata")
		w.decided = true
		w.cond.Broadcast()
		return w.setupErr
	}

	// Create block writer
	onComplete := func() {
		w.pc.eviction.AddUsage(w.diskMeta.StorageID, w.dl.namespaceID, size)
		if err := w.pc.db.SetLatestETag(w.dl.objectHash, w.dl.etag); err != nil {
			log.Warnf("Failed to update ETag table: %v", err)
		}
		log.Debugf("Completed disk download of %s (%d bytes)", w.dl.instanceHash, size)
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
			ObjectHash:    dl.objectHash,
			NamespaceID:   dl.namespaceID,
			Completed:     time.Now(),
			LastValidated: time.Now(),
		}
		meta.SetCacheControl(dl.cacheControl)

		if err := w.pc.storage.StoreInline(w.ctx, dl.instanceHash, meta, w.buffer); err != nil {
			return errors.Wrap(err, "failed to store inline")
		}

		if err := w.pc.db.SetLatestETag(dl.objectHash, dl.etag); err != nil {
			log.Warnf("Failed to update ETag table: %v", err)
		}

		// StoreInline sets meta.StorageID = StorageIDInline
		w.pc.eviction.AddUsage(StorageIDInline, dl.namespaceID, int64(len(w.buffer)))
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
	log.Debugf("Transfer progress: %s - %d/%d (complete: %v)", path, downloaded, size, completed)
}

// normalizePath converts a path to a full pelican URL
func (pc *PersistentCache) normalizePath(objectPath string) string {
	// If already a full URL, return as-is
	if strings.HasPrefix(objectPath, "pelican://") || strings.HasPrefix(objectPath, "osdf://") {
		return objectPath
	}

	// Construct URL using director
	u := *pc.directorURL
	u.Scheme = "pelican"
	u.Path = path.Clean(objectPath)

	return u.String()
}

// getNamespaceID returns or assigns a namespace ID for a path
func (pc *PersistentCache) getNamespaceID(objectPath string) uint32 {
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

	id := pc.nextNamespaceID.Add(1)
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
	respData, err := makeRequest(pc.ctx, tr, listURL, "GET", nil, nil)
	if err != nil {
		return err
	}

	if err := unmarshalJSON(respData, &respNS); err != nil {
		return errors.Wrapf(err, "failed to unmarshal namespace response")
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

	return PersistentCacheStats{
		TotalUsage:      evictStats.TotalUsage,
		MaxSize:         evictStats.MaxSize,
		HighWater:       evictStats.HighWater,
		LowWater:        evictStats.LowWater,
		NamespaceUsage:  evictStats.NamespaceUsage,
		ConsistencyStats: consistStats,
	}
}

// PersistentCacheStats holds cache statistics
type PersistentCacheStats struct {
	TotalUsage       uint64
	MaxSize          uint64
	HighWater        uint64
	LowWater         uint64
	NamespaceUsage   map[StorageUsageKey]int64
	ConsistencyStats ConsistencyStats
}

// Helper functions

func parseSize(sizeStr string) (uint64, error) {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	// Check longer suffixes before shorter ones to avoid matching "MB" as "B"
	suffixes := []struct {
		suffix string
		mult   uint64
	}{
		{"TB", 1024 * 1024 * 1024 * 1024},
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"KB", 1024},
		{"T", 1024 * 1024 * 1024 * 1024},
		{"G", 1024 * 1024 * 1024},
		{"M", 1024 * 1024},
		{"K", 1024},
		{"B", 1},
	}

	for _, s := range suffixes {
		if strings.HasSuffix(sizeStr, s.suffix) {
			numStr := strings.TrimSuffix(sizeStr, s.suffix)
			num, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return 0, err
			}
			return uint64(num * float64(s.mult)), nil
		}
	}

	// Try parsing as plain number
	num, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil {
		return 0, errors.Errorf("invalid size format: %s", sizeStr)
	}
	return num, nil
}

func makeRequest(ctx context.Context, tr http.RoundTripper, url, method string, headers map[string]string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// convertClientChecksums converts checksums from the client module format to our schema format
func convertClientChecksums(clientChecksums []client.ChecksumInfo) []Checksum {
	if len(clientChecksums) == 0 {
		return nil
	}

	result := make([]Checksum, 0, len(clientChecksums))
	for _, cc := range clientChecksums {
		var csType ChecksumType
		switch cc.Algorithm {
		case client.AlgMD5:
			csType = ChecksumMD5
		case client.AlgSHA1:
			csType = ChecksumSHA1
		case client.AlgCRC32, client.AlgCRC32C:
			csType = ChecksumCRC32
		default:
			continue // Skip unknown algorithms
		}
		result = append(result, Checksum{
			Type:  csType,
			Value: cc.Value,
		})
	}
	return result
}

// ComputeObjectHashFromPath computes the object hash from a raw path (without federation URL).
// This is a simple helper for cases where you only have the path, not the full pelican URL.
func ComputeObjectHashFromPath(objectPath string) string {
	h := sha256.Sum256([]byte(objectPath))
	return hex.EncodeToString(h[:])
}
