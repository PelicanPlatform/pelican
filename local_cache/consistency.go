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
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

var (
	// Singleton errors for flow control
	errMaxDeletionsReached = errors.New("max_deletions_reached")
	errTransactionTimeout  = errors.New("transaction_timeout")
	errChannelFull         = errors.New("channel_full")

	metadataScanInconsistentObjects = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_metadata_scan_inconsistent_objects_total",
		Help: "Total number of inconsistent objects found during metadata scans",
	})
	metadataScanInconsistentBytes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_metadata_scan_inconsistent_bytes_total",
		Help: "Total bytes of inconsistent objects found during metadata scans",
	})
	metadataScanLastStartTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_metadata_scan_last_start_timestamp_seconds",
		Help: "Unix timestamp when the last metadata scan started",
	})
	dataScanInconsistentObjects = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_data_scan_inconsistent_objects_total",
		Help: "Total number of inconsistent objects found during data integrity scans",
	})
	dataScanInconsistentBytes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_data_scan_inconsistent_bytes_total",
		Help: "Total bytes of inconsistent objects found during data integrity scans",
	})
	dataScanLastStartTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_data_scan_last_start_timestamp_seconds",
		Help: "Unix timestamp when the last data integrity scan started",
	})
	metadataScanDurationSeconds = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_metadata_scan_duration_seconds_total",
		Help: "Total duration of all metadata scans in seconds",
	})
	metadataScanFilesProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_metadata_scan_files_processed_total",
		Help: "Total number of files processed during metadata scans",
	})
	metadataScanDBEntriesProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_metadata_scan_db_entries_processed_total",
		Help: "Total number of database entries processed during metadata scans",
	})
	dataScanDurationSeconds = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_data_scan_duration_seconds_total",
		Help: "Total duration of all data scans in seconds",
	})
	dataScanObjectsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_data_scan_objects_processed_total",
		Help: "Total number of objects processed during data scans",
	})
	dataScanBytesProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_data_scan_bytes_processed_total",
		Help: "Total bytes processed during data scans",
	})
)

// ConsistencyChecker verifies cache consistency between database and disk
type ConsistencyChecker struct {
	db         *CacheDB
	storage    *StorageManager
	objectsDir string

	// Rate limiting (using rate.Limiter treating each token as 1ns)
	metadataScanLimiter *rate.Limiter // Limits metadata scan active time
	dataScanBytesPerSec int64         // Max bytes per second for data scanning
	minAgeForCleanup    time.Duration // Minimum age before cleanup to avoid races

	// Statistics
	stats   ConsistencyStats
	statsMu sync.RWMutex

	// Control
	running          atomic.Bool
	stopCh           chan struct{}
	lastMetadataScan atomic.Int64 // Unix timestamp of last metadata scan start
	lastDataScan     atomic.Int64 // Unix timestamp of last data scan start
}

// ConsistencyConfig holds configuration for the consistency checker
type ConsistencyConfig struct {
	// MetadataScanActiveMs limits metadata scan to this many ms per second (default: 100)
	MetadataScanActiveMs int64
	// DataScanBytesPerSec limits data scan to this many bytes per second (default: 100MB)
	DataScanBytesPerSec int64
	// MinAgeForCleanup is the minimum age before an entry/file can be cleaned up (default: 5 minutes, 0 for tests)
	MinAgeForCleanup time.Duration
}

// ConsistencyStats holds statistics from consistency checks
type ConsistencyStats struct {
	LastMetadataScan   time.Time
	LastDataScan       time.Time
	MetadataScanErrors int64
	DataScanErrors     int64
	OrphanedFiles      int64
	OrphanedDBEntries  int64
	ChecksumMismatches int64
	BytesVerified      int64
	ObjectsVerified    int64
}

// NewConsistencyChecker creates a new consistency checker
func NewConsistencyChecker(db *CacheDB, storage *StorageManager, baseDir string, config ConsistencyConfig) *ConsistencyChecker {
	if config.MetadataScanActiveMs <= 0 {
		config.MetadataScanActiveMs = 100 // 100ms active per second
	}
	if config.DataScanBytesPerSec <= 0 {
		config.DataScanBytesPerSec = 100 * 1024 * 1024 // 100 MB/s
	}
	// Use -1 to indicate "not set" and allow 0 to explicitly disable the grace period
	if config.MinAgeForCleanup < 0 {
		config.MinAgeForCleanup = 5 * time.Minute // Default 5 minutes grace period
	}

	// Create rate limiter: treat each token as 1ns, allow burst of 100ms
	activeNsPerSec := config.MetadataScanActiveMs * 1_000_000 // convert ms to ns
	burstNs := 100 * 1_000_000                                // 100ms burst capacity
	limiter := rate.NewLimiter(rate.Limit(activeNsPerSec), burstNs)

	// Initialize metrics
	now := float64(time.Now().Unix())
	metadataScanLastStartTime.Set(now)
	dataScanLastStartTime.Set(now)

	return &ConsistencyChecker{
		db:                  db,
		storage:             storage,
		objectsDir:          filepath.Join(baseDir, objectsSubDir),
		metadataScanLimiter: limiter,
		dataScanBytesPerSec: config.DataScanBytesPerSec,
		minAgeForCleanup:    config.MinAgeForCleanup,
		stopCh:              make(chan struct{}),
	}
}

// Start begins the background consistency checking goroutines
func (cc *ConsistencyChecker) Start(ctx context.Context, egrp *errgroup.Group) {
	if cc.running.Swap(true) {
		return // Already running
	}

	// Metadata scan goroutine - runs every hour
	egrp.Go(func() error {
		return cc.metadataScanLoop(ctx)
	})

	// Data scan goroutine - runs every 24 hours
	egrp.Go(func() error {
		return cc.dataScanLoop(ctx)
	})
}

// Stop stops the consistency checker
func (cc *ConsistencyChecker) Stop() {
	if cc.running.Swap(false) {
		close(cc.stopCh)
	}
}

// GetStats returns current statistics
func (cc *ConsistencyChecker) GetStats() ConsistencyStats {
	cc.statsMu.RLock()
	defer cc.statsMu.RUnlock()
	return cc.stats
}

// metadataScanLoop runs periodic metadata consistency scans
func (cc *ConsistencyChecker) metadataScanLoop(ctx context.Context) error {
	// Initial delay to let the system settle
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(5 * time.Minute):
	}

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-cc.stopCh:
			return nil
		case <-ticker.C:
			// Enforce minimum interval between scan start times
			lastScan := time.Unix(cc.lastMetadataScan.Load(), 0)
			if time.Since(lastScan) < 1*time.Hour {
				log.Debugf("Skipping metadata scan, only %v since last scan", time.Since(lastScan))
				continue
			}
			if err := cc.RunMetadataScan(ctx); err != nil {
				log.Warnf("Metadata scan error: %v", err)
			}
		}
	}
}

// dataScanLoop runs periodic data integrity scans
func (cc *ConsistencyChecker) dataScanLoop(ctx context.Context) error {
	// Initial delay
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(30 * time.Minute):
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-cc.stopCh:
			return nil
		case <-ticker.C:
			// Enforce minimum interval between scan start times
			lastScan := time.Unix(cc.lastDataScan.Load(), 0)
			if time.Since(lastScan) < 24*time.Hour {
				log.Debugf("Skipping data scan, only %v since last scan", time.Since(lastScan))
				continue
			}
			if err := cc.RunDataScan(ctx); err != nil {
				log.Warnf("Data scan error: %v", err)
			}
		}
	}
}

// RunMetadataScan performs a metadata consistency scan
// It verifies that database entries match files on disk and vice versa
// using an efficient streaming merge algorithm over sorted lists.
func (cc *ConsistencyChecker) RunMetadataScan(ctx context.Context) error {
	log.Info("Starting metadata consistency scan")
	scanStartTime := time.Now()
	cc.lastMetadataScan.Store(scanStartTime.Unix())
	metadataScanLastStartTime.Set(float64(scanStartTime.Unix()))

	// Use os.DirFS to avoid symlink attacks
	fsys := os.DirFS(cc.objectsDir)

	// Stream files from disk via channel (filesystem walk is in lexicographical order)
	type fileInfo struct {
		instanceHash string
		path         string
		modTime      time.Time
		size         int64
	}
	fileChan := make(chan fileInfo, 100)
	walkErr := make(chan error, 1)

	// Start filesystem walk in background
	go func() {
		err := fs.WalkDir(fsys, ".", func(relPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // Skip errors
			}

			if d.IsDir() {
				return nil
			}

			// Reconstruct hash from path (remove directory separators)
			instanceHash := strings.ReplaceAll(relPath, string(filepath.Separator), "")

			// Validate instance hash format: must be 64 hex characters (SHA256)
			if len(instanceHash) != 64 {
				return nil
			}
			// Quick validation: check if all characters are hex
			for _, c := range instanceHash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					return nil
				}
			}

			// Get file info
			info, err := d.Info()
			if err != nil {
				return nil
			}

			// Do not mark for deletion any file newer than the start of the current scan
			if info.ModTime().After(scanStartTime) {
				return nil
			}

			// Only include files old enough to avoid races
			if cc.minAgeForCleanup > 0 && time.Since(info.ModTime()) < cc.minAgeForCleanup {
				return nil
			}

			select {
			case fileChan <- fileInfo{
				instanceHash: instanceHash,
				path:         filepath.Join(cc.objectsDir, relPath),
				modTime:      info.ModTime(),
				size:         info.Size(),
			}:
			case <-ctx.Done():
				return ctx.Err()
			}

			return nil
		})
		close(fileChan)
		if err != nil {
			walkErr <- err
		}
		close(walkErr)
	}()

	// Structures to track what to delete (limit to 1k changes per transaction)
	type deleteAction struct {
		instanceHash string
		isFile       bool
		path         string
		size         int64
	}
	var deletions []deleteAction
	const maxDeletionsPerTx = 1000

	orphanedDBEntries := int64(0)
	orphanedFiles := int64(0)
	orphanedBytes := int64(0)
	dbEntriesScanned := int64(0)
	filesScanned := int64(0)

	// Read first file from channel
	var currentFile fileInfo
	var fileOk bool
	currentFile, fileOk = <-fileChan
	if fileOk {
		filesScanned++
	}

	// Track where to resume DB scan after each transaction restart
	lastDBKey := ""
	transactionStartTime := time.Now()
	const transactionTimeout = 5 * time.Second

	// Outer loop: restart transactions every 5 seconds
	for {
		transactionStartTime = time.Now()
		transactionComplete := false
		entriesThisTransaction := int64(0)
		deletions = deletions[:0] // Clear deletions list

		err := cc.db.ScanMetadataFrom(lastDBKey, func(instanceHash string, meta *CacheMetadata) error {
			// Check context
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Rate limit using the limiter (treat as ns of active time)
			opStart := time.Now()
			defer func() {
				duration := time.Since(opStart)
				_ = cc.metadataScanLimiter.WaitN(ctx, int(duration.Nanoseconds()))
			}()

			// Only process entries old enough to avoid races
			if cc.minAgeForCleanup > 0 && !meta.Completed.IsZero() && time.Since(meta.Completed) < cc.minAgeForCleanup {
				lastDBKey = instanceHash
				return nil
			}

			dbEntriesScanned++
			entriesThisTransaction++

			// Process all files that are less than current DB entry (orphaned files)
			for fileOk && currentFile.instanceHash < instanceHash {
				if len(deletions) < maxDeletionsPerTx {
					deletions = append(deletions, deleteAction{
						instanceHash: currentFile.instanceHash,
						isFile:       true,
						path:         currentFile.path,
						size:         currentFile.size,
					})
				}
				filesScanned++
				// Get next file
				currentFile, fileOk = <-fileChan
			}

			// Check if current file matches DB entry
			if fileOk && currentFile.instanceHash == instanceHash {
				// Match - both exist
				if meta.StorageMode == StorageModeDisk {
					// Expected: file exists for disk storage
					filesScanned++
					// Get next file
					currentFile, fileOk = <-fileChan
				} else {
					// Unexpected: file exists but storage is inline
					if len(deletions) < maxDeletionsPerTx {
						deletions = append(deletions, deleteAction{
							instanceHash: currentFile.instanceHash,
							isFile:       true,
							path:         currentFile.path,
							size:         currentFile.size,
						})
					}
					filesScanned++
					// Get next file
					currentFile, fileOk = <-fileChan
				}
			} else {
				// No matching file for this DB entry
				if meta.StorageMode == StorageModeDisk {
					// Orphaned DB entry - file should exist but doesn't
					if len(deletions) < maxDeletionsPerTx {
						deletions = append(deletions, deleteAction{
							instanceHash: instanceHash,
							isFile:       false,
							size:         meta.ContentLength,
						})
					}
				} else if meta.StorageMode == StorageModeInline {
					// Verify inline data exists
					data, err := cc.db.GetInlineData(instanceHash)
					if err != nil || data == nil {
						if len(deletions) < maxDeletionsPerTx {
							deletions = append(deletions, deleteAction{
								instanceHash: instanceHash,
								isFile:       false,
								size:         meta.ContentLength,
							})
						}
					}
				}
			}

			// Update last processed key
			lastDBKey = instanceHash

			// Stop if we have enough deletions to process
			if len(deletions) >= maxDeletionsPerTx {
				return errMaxDeletionsReached
			}

			// Check if we should restart the transaction (every 5 seconds)
			if time.Since(transactionStartTime) > transactionTimeout {
				log.Debugf("Restarting metadata scan transaction after %v (processed %d entries, last key: %.8s...)",
					time.Since(transactionStartTime), entriesThisTransaction, lastDBKey)
				return errTransactionTimeout
			}

			return nil
		})

		// Check for errors other than our control signals
		if err != nil && !errors.Is(err, errMaxDeletionsReached) && !errors.Is(err, errTransactionTimeout) {
			return errors.Wrap(err, "error scanning metadata")
		}

		// Process deletions in a new read-write transaction
		if len(deletions) > 0 {
			for _, del := range deletions {
				// Re-verify before deleting
				if del.isFile {
					// Re-check file still exists
					if _, err := os.Stat(del.path); err == nil {
						log.Warnf("Orphaned file: %s", del.path)
						orphanedFiles++
						orphanedBytes += del.size
						if err := os.Remove(del.path); err != nil {
							log.Warnf("Failed to remove orphaned file %s: %v", del.path, err)
						}
					}
				} else {
					// Re-check DB entry still exists and is inconsistent
					meta, err := cc.db.GetMetadata(del.instanceHash)
					if err == nil && meta != nil {
						stillInconsistent := false
						if meta.StorageMode == StorageModeDisk {
							filePath := filepath.Join(cc.objectsDir, GetInstanceStoragePath(del.instanceHash))
							if _, err := os.Stat(filePath); os.IsNotExist(err) {
								stillInconsistent = true
							}
						} else if meta.StorageMode == StorageModeInline {
							data, err := cc.db.GetInlineData(del.instanceHash)
							if err != nil || data == nil {
								stillInconsistent = true
							}
						}

						if stillInconsistent {
							log.Warnf("Orphaned DB entry: %s", del.instanceHash)
							orphanedDBEntries++
							orphanedBytes += del.size
							if err := cc.db.DeleteObject(del.instanceHash); err != nil {
								log.Warnf("Failed to clean up orphaned DB entry %s: %v", del.instanceHash, err)
							}
						}
					}
				}
			}

			// Update metrics immediately after processing deletions
			inconsistentCount := int64(0)
			inconsistentSize := int64(0)
			for _, del := range deletions {
				inconsistentCount++
				inconsistentSize += del.size
			}
			metadataScanInconsistentObjects.Add(float64(inconsistentCount))
			metadataScanInconsistentBytes.Add(float64(inconsistentSize))
		}

		// Check if we've processed all DB entries (no entries in this transaction means we're done)
		if entriesThisTransaction == 0 || err == nil {
			transactionComplete = true
		}

		if transactionComplete {
			break // All DB entries processed
		}
	}

	// Process any remaining files (all are orphaned)
	for fileOk {
		// Re-check file (might have been created after scan start)
		if info, err := os.Stat(currentFile.path); err == nil {
			if !info.ModTime().After(scanStartTime) {
				log.Warnf("Orphaned file: %s", currentFile.path)
				orphanedFiles++
				orphanedBytes += currentFile.size
				if err := os.Remove(currentFile.path); err != nil {
					log.Warnf("Failed to remove orphaned file %s: %v", currentFile.path, err)
				}
			}
		}
		filesScanned++
		currentFile, fileOk = <-fileChan
	}

	// Check for walk errors
	if walkError := <-walkErr; walkError != nil {
		log.Warnf("Error during filesystem walk: %v", walkError)
	}

	// Update stats and metrics
	scanDuration := time.Since(scanStartTime)
	cc.statsMu.Lock()
	cc.stats.LastMetadataScan = time.Now()
	cc.stats.OrphanedDBEntries += orphanedDBEntries
	cc.stats.OrphanedFiles += orphanedFiles
	cc.statsMu.Unlock()

	metadataScanDurationSeconds.Add(scanDuration.Seconds())
	metadataScanFilesProcessed.Add(float64(filesScanned))
	metadataScanDBEntriesProcessed.Add(float64(dbEntriesScanned))

	log.Infof("Metadata scan complete in %v: scanned %d DB entries and %d files, found %d orphaned DB entries and %d orphaned files (%d bytes)",
		scanDuration, dbEntriesScanned, filesScanned, orphanedDBEntries, orphanedFiles, orphanedBytes)

	return nil
}

// scanItem represents an object from a database scan
type scanItem struct {
	instanceHash string
	meta         *CacheMetadata
}

// RunDataScan performs a full data integrity scan
// It verifies checksums of stored objects using block-by-block reading
func (cc *ConsistencyChecker) RunDataScan(ctx context.Context) error {
	log.Info("Starting data integrity scan")
	scanStartTime := time.Now()
	cc.lastDataScan.Store(scanStartTime.Unix())
	dataScanLastStartTime.Set(float64(scanStartTime.Unix()))

	// Rate limiter for I/O
	bytesLimiter := rate.NewLimiter(rate.Limit(cc.dataScanBytesPerSec), int(cc.dataScanBytesPerSec))

	checksumMismatches := int64(0)
	inconsistentBytes := int64(0)
	bytesVerified := int64(0)
	objectsVerified := int64(0)

	// Channel for streaming objects from DB scan
	objectChan := make(chan scanItem, 1000)
	scanErr := make(chan error, 1)

	// Start DB scan in background goroutine
	go func() {
		const transactionTimeout = 5 * time.Second

		// Generate random 4-byte hex starting point (16 bits = 4 hex chars)
		// This randomizes where we start scanning through the database
		rng := rand.New(rand.NewSource(scanStartTime.UnixNano()))
		randomStart := fmt.Sprintf("%04x", rng.Intn(1<<16))

		startKey := randomStart
		lastKey := startKey
		wrappedAround := false

		for {
			transactionStart := time.Now()
			scannedThisTx := 0

			err := cc.db.ScanMetadataFrom(lastKey, func(instanceHash string, meta *CacheMetadata) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				// If we've wrapped around and reached our starting point, we're done
				if wrappedAround && instanceHash >= startKey {
					return errChannelFull // Use as "scan complete" signal
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				case objectChan <- scanItem{instanceHash: instanceHash, meta: meta}:
					scannedThisTx++
					lastKey = instanceHash
				}

				// Restart transaction after timeout
				if time.Since(transactionStart) > transactionTimeout {
					return errTransactionTimeout
				}

				return nil
			})

			if err != nil && !errors.Is(err, errTransactionTimeout) && !errors.Is(err, errChannelFull) {
				scanErr <- err
				close(objectChan)
				close(scanErr)
				return
			}

			// Check if scan is complete
			if errors.Is(err, errChannelFull) {
				close(objectChan)
				close(scanErr)
				return
			}

			// If no items scanned, we've reached the end of the database
			if scannedThisTx == 0 {
				if wrappedAround {
					// Already wrapped and reached end again - done
					close(objectChan)
					close(scanErr)
					return
				}
				// Wrap around to beginning
				wrappedAround = true
				lastKey = ""
				log.Debugf("Data scan wrapping around from end to beginning (started at %s)", startKey)
			}
		}
	}()

	// Main goroutine: process objects from channel
	batch := make([]scanItem, 0, 1000)
	for {
		// Read up to 1k objects or until channel blocks
		batch = batch[:0]
		for len(batch) < cap(batch) {
			select {
			case item, ok := <-objectChan:
				if !ok {
					// Channel closed, process final batch
					if len(batch) > 0 {
						cc.processBatchForDataScan(ctx, batch, bytesLimiter, &checksumMismatches, &inconsistentBytes, &bytesVerified, &objectsVerified)
					}
					goto scanComplete
				}
				batch = append(batch, item)
			default:
				// Would block, process what we have
				if len(batch) > 0 {
					goto processBatch
				}
				// Wait a bit if batch is empty
				time.Sleep(10 * time.Millisecond)
			}
		}

	processBatch:
		if len(batch) > 0 {
			cc.processBatchForDataScan(ctx, batch, bytesLimiter, &checksumMismatches, &inconsistentBytes, &bytesVerified, &objectsVerified)
		}
	}

scanComplete:
	// Check for scan errors
	if err := <-scanErr; err != nil && !errors.Is(err, context.Canceled) {
		log.Warnf("Error during data scan: %v", err)
	}

	// Update stats and metrics
	scanDuration := time.Since(scanStartTime)
	cc.statsMu.Lock()
	cc.stats.LastDataScan = time.Now()
	cc.stats.ChecksumMismatches += checksumMismatches
	cc.stats.BytesVerified += bytesVerified
	cc.stats.ObjectsVerified += objectsVerified
	cc.statsMu.Unlock()

	dataScanInconsistentObjects.Add(float64(checksumMismatches))
	dataScanInconsistentBytes.Add(float64(inconsistentBytes))
	dataScanDurationSeconds.Add(scanDuration.Seconds())
	dataScanObjectsProcessed.Add(float64(objectsVerified))
	dataScanBytesProcessed.Add(float64(bytesVerified))

	log.Infof("Data scan complete in %v: verified %d objects (%d bytes), %d checksum mismatches (%d bytes)",
		scanDuration, objectsVerified, bytesVerified, checksumMismatches, inconsistentBytes)

	return nil
}

// processBatchForDataScan processes a batch of objects for data integrity verification
func (cc *ConsistencyChecker) processBatchForDataScan(
	ctx context.Context,
	batch []scanItem,
	bytesLimiter *rate.Limiter,
	checksumMismatches, inconsistentBytes, bytesVerified, objectsVerified *int64,
) {
	for _, item := range batch {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := cc.verifyObjectChecksum(ctx, item.instanceHash, item.meta, bytesLimiter, checksumMismatches, inconsistentBytes, bytesVerified, objectsVerified); err != nil {
			log.Warnf("Error verifying object %s: %v", item.instanceHash, err)
		}
	}
}

// verifyObjectChecksum verifies a single object's checksum block-by-block
func (cc *ConsistencyChecker) verifyObjectChecksum(
	ctx context.Context,
	instanceHash string,
	meta *CacheMetadata,
	bytesLimiter *rate.Limiter,
	checksumMismatches, inconsistentBytes, bytesVerified, objectsVerified *int64,
) error {
	// For disk storage, check if complete before attempting any checksumming
	if meta.StorageMode == StorageModeDisk {
		bitmap, err := cc.db.GetBlockState(instanceHash)
		if err != nil {
			return errors.Wrap(err, "failed to get block state")
		}

		totalBlocks := CalculateBlockCount(meta.ContentLength)
		if bitmap.GetCardinality() != uint64(totalBlocks) {
			return nil // Skip incomplete objects
		}
	}

	// If no checksums available, calculate and store them
	if len(meta.Checksums) == 0 {
		if err := cc.calculateAndStoreChecksums(ctx, instanceHash, meta, bytesLimiter); err != nil {
			return err
		}
		// Just calculated checksum, no need to re-verify
		*objectsVerified++
		return nil
	}

	// For inline storage, verify directly
	if meta.StorageMode == StorageModeInline {
		data, err := cc.storage.ReadInline(instanceHash)
		if err != nil {
			return errors.Wrap(err, "failed to read inline data")
		}

		if err := bytesLimiter.WaitN(ctx, len(data)); err != nil {
			return err
		}

		// Verify checksums
		for _, cksum := range meta.Checksums {
			computed := computeChecksum(data, cksum.Type)
			if !bytes.Equal(computed, cksum.Value) {
				log.Warnf("Checksum mismatch for inline object %s (type %d)", instanceHash, cksum.Type)
				*checksumMismatches++
				*inconsistentBytes += meta.ContentLength

				// Mark for re-download
				if err := cc.storage.Delete(instanceHash); err != nil {
					log.Warnf("Failed to delete corrupted object %s: %v", instanceHash, err)
				}
				return nil
			}
		}

		*bytesVerified += int64(len(data))
		*objectsVerified++
		return nil
	}

	// For disk storage, verify with 128KB chunk reads
	bitmap, err := cc.db.GetBlockState(instanceHash)
	if err != nil {
		return errors.Wrap(err, "failed to get block state")
	}

	// Verify using streaming approach with 128KB chunks
	hasher, err := cc.createHasher(meta.Checksums[0].Type)
	if err != nil {
		return err
	}

	filePath := filepath.Join(cc.objectsDir, GetInstanceStoragePath(instanceHash))
	file, err := os.Open(filePath)
	if err != nil {
		return errors.Wrap(err, "failed to open file")
	}
	defer file.Close()

	// Get DEK for decryption
	dek, err := cc.db.GetEncryptionManager().DecryptDataKey(meta.DataKey)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt DEK")
	}

	encryptor, err := NewBlockEncryptor(dek, meta.Nonce)
	if err != nil {
		return errors.Wrap(err, "failed to create encryptor")
	}

	totalBlocks := CalculateBlockCount(meta.ContentLength)
	var verifiedBytes int64

	// Read and verify in 128KB chunks (multiple blocks at once)
	const chunkSize = 128 * 1024
	readBuffer := make([]byte, chunkSize)

	for block := uint32(0); block < totalBlocks; {
		// Determine how many blocks to read in this chunk
		blocksInChunk := 0
		chunkBytes := 0

		for block < totalBlocks && chunkBytes < chunkSize {
			if !bitmap.Contains(block) {
				block++
				continue
			}

			blockSize := BlockDataSize
			if block == totalBlocks-1 {
				lastBlockSize := int(meta.ContentLength % BlockDataSize)
				if lastBlockSize != 0 {
					blockSize = lastBlockSize
				}
			}

			encBlockSize := blockSize + AuthTagSize
			if chunkBytes+encBlockSize > len(readBuffer) {
				break // Would exceed buffer
			}

			// Read encrypted block into buffer
			offset := BlockOffset(block)
			n, err := file.ReadAt(readBuffer[chunkBytes:chunkBytes+encBlockSize], offset)
			if err != nil && err != io.EOF {
				log.Warnf("Error reading block %d of %s: %v", block, instanceHash, err)
				*checksumMismatches++
				*inconsistentBytes += meta.ContentLength
				if err := cc.storage.Delete(instanceHash); err != nil {
					log.Warnf("Failed to delete corrupted object %s: %v", instanceHash, err)
				}
				return nil
			}
			if n < encBlockSize {
				log.Warnf("Short read for block %d of %s", block, instanceHash)
				*checksumMismatches++
				*inconsistentBytes += meta.ContentLength
				if err := cc.storage.Delete(instanceHash); err != nil {
					log.Warnf("Failed to delete corrupted object %s: %v", instanceHash, err)
				}
				return nil
			}

			// Decrypt and verify auth tag
			plaintext, err := encryptor.DecryptBlock(block, readBuffer[chunkBytes:chunkBytes+encBlockSize])
			if err != nil {
				log.Warnf("Block %d authentication failed for %s: %v", block, instanceHash, err)
				*checksumMismatches++
				*inconsistentBytes += meta.ContentLength
				if err := cc.storage.Delete(instanceHash); err != nil {
					log.Warnf("Failed to delete corrupted object %s: %v", instanceHash, err)
				}
				return nil
			}

			// Update checksum hash
			hasher.Write(plaintext[:blockSize])
			verifiedBytes += int64(blockSize)

			chunkBytes += encBlockSize
			blocksInChunk++
			block++
		}

		// Rate limit the entire chunk
		if chunkBytes > 0 {
			if err := bytesLimiter.WaitN(ctx, chunkBytes); err != nil {
				return err
			}
		}

		// If no blocks in chunk, advance to next block
		if blocksInChunk == 0 {
			block++
		}
	}

	// Verify final checksum (we already checked completeness upfront)
	if true {
		computed := hasher.Sum(nil)
		if !bytes.Equal(computed, meta.Checksums[0].Value) {
			log.Warnf("Final checksum mismatch for %s", instanceHash)
			*checksumMismatches++
			*inconsistentBytes += meta.ContentLength

			if err := cc.storage.Delete(instanceHash); err != nil {
				log.Warnf("Failed to delete corrupted object %s: %v", instanceHash, err)
			}
			return nil
		}
	}

	*bytesVerified += verifiedBytes
	*objectsVerified++
	return nil
}

// calculateAndStoreChecksums calculates checksums for an object and stores them
func (cc *ConsistencyChecker) calculateAndStoreChecksums(
	ctx context.Context,
	instanceHash string,
	meta *CacheMetadata,
	bytesLimiter *rate.Limiter,
) error {
	log.Debugf("Calculating checksum for %s", instanceHash)

	var hasher hash.Hash = sha256.New()
	var data []byte
	var err error

	if meta.StorageMode == StorageModeInline {
		data, err = cc.storage.ReadInline(instanceHash)
		if err != nil {
			return errors.Wrap(err, "failed to read inline data")
		}
		hasher.Write(data)
		if err := bytesLimiter.WaitN(ctx, len(data)); err != nil {
			return err
		}
	} else {
		// Read block-by-block for disk storage
		var bitmap *roaring.Bitmap
		bitmap, err = cc.db.GetBlockState(instanceHash)
		if err != nil {
			return errors.Wrap(err, "failed to get block state")
		}

		// Only calculate checksum if all blocks are present
		totalBlocks := CalculateBlockCount(meta.ContentLength)
		if bitmap.GetCardinality() != uint64(totalBlocks) {
			return nil // Skip incomplete objects
		}

		// Read blocks through storage manager (validates auth tags)
		for block := uint32(0); block < totalBlocks; block++ {
			if !bitmap.Contains(block) {
				continue // Skip non-downloaded blocks
			}

			blockSize := BlockDataSize
			if block == totalBlocks-1 {
				lastBlockSize := int(meta.ContentLength % BlockDataSize)
				if lastBlockSize != 0 {
					blockSize = lastBlockSize
				}
			}

			offset := int64(block) * BlockDataSize
			blockData, err := cc.storage.ReadBlocks(instanceHash, offset, blockSize)
			if err != nil {
				return errors.Wrapf(err, "failed to read block %d", block)
			}

			hasher.Write(blockData)
			if err := bytesLimiter.WaitN(ctx, len(blockData)); err != nil {
				return err
			}
		}
	}

	// Store the calculated checksum
	checksum := Checksum{
		Type:            ChecksumSHA256,
		Value:           hasher.Sum(nil),
		OriginVerified:  false,
		VerifyAttempted: false,
	}

	meta.Checksums = []Checksum{checksum}
	if err := cc.db.SetMetadata(instanceHash, meta); err != nil {
		return errors.Wrap(err, "failed to store checksum")
	}

	log.Debugf("Calculated and stored checksum for %s", instanceHash)
	return nil
}

// createHasher creates a hash.Hash for the given checksum type
func (cc *ConsistencyChecker) createHasher(checksumType ChecksumType) (hash.Hash, error) {
	switch checksumType {
	case ChecksumMD5:
		return md5.New(), nil
	case ChecksumSHA1:
		return sha1.New(), nil
	case ChecksumSHA256:
		return sha256.New(), nil
	case ChecksumCRC32:
		return crc32.NewIEEE(), nil
	default:
		return nil, errors.Errorf("unknown checksum type: %d", checksumType)
	}
}

// VerifyObject verifies a single object's integrity
func (cc *ConsistencyChecker) VerifyObject(instanceHash string) (bool, error) {
	meta, err := cc.storage.GetMetadata(instanceHash)
	if err != nil {
		return false, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return false, errors.New("object not found")
	}

	// Check file exists (for disk storage)
	if meta.StorageMode == StorageModeDisk {
		filePath := filepath.Join(cc.objectsDir, GetInstanceStoragePath(instanceHash))
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return false, nil
		}
	}

	// Verify checksums if present
	if len(meta.Checksums) == 0 {
		return true, nil // No checksums to verify
	}

	var data []byte
	if meta.StorageMode == StorageModeInline {
		data, err = cc.storage.ReadInline(instanceHash)
	} else {
		var complete bool
		complete, err = cc.storage.IsComplete(instanceHash)
		if err != nil || !complete {
			return true, nil // Can't verify incomplete objects
		}
		data, err = cc.storage.ReadBlocks(instanceHash, 0, int(meta.ContentLength))
	}

	if err != nil {
		return false, errors.Wrap(err, "failed to read object data")
	}

	for _, cksum := range meta.Checksums {
		computed := computeChecksum(data, cksum.Type)
		if !bytes.Equal(computed, cksum.Value) {
			return false, nil
		}
	}

	return true, nil
}

// computeChecksum computes a checksum of the given type
func computeChecksum(data []byte, checksumType ChecksumType) []byte {
	var h hash.Hash

	switch checksumType {
	case ChecksumMD5:
		h = md5.New()
	case ChecksumSHA1:
		h = sha1.New()
	case ChecksumSHA256:
		h = sha256.New()
	case ChecksumCRC32:
		h32 := crc32.NewIEEE()
		h32.Write(data)
		result := make([]byte, 4)
		sum := h32.Sum32()
		result[0] = byte(sum >> 24)
		result[1] = byte(sum >> 16)
		result[2] = byte(sum >> 8)
		result[3] = byte(sum)
		return result
	default:
		return nil
	}

	h.Write(data)
	return h.Sum(nil)
}

// ParseChecksumHeader parses a checksum from HTTP headers
func ParseChecksumHeader(headerValue string, headerType string) *Checksum {
	if headerValue == "" {
		return nil
	}

	var checksumType ChecksumType
	switch strings.ToLower(headerType) {
	case "content-md5", "md5":
		checksumType = ChecksumMD5
	case "x-checksum-sha1", "sha1":
		checksumType = ChecksumSHA1
	case "x-checksum-sha256", "sha256":
		checksumType = ChecksumSHA256
	case "x-checksum-crc32", "crc32":
		checksumType = ChecksumCRC32
	default:
		return nil
	}

	// Decode the value (base64 or hex depending on type)
	var value []byte
	// For simplicity, assume hex encoding here
	// In practice, you'd need to handle different encodings
	value = []byte(headerValue)

	return &Checksum{
		Type:  checksumType,
		Value: value,
	}
}

// VerifyBlockIntegrity verifies the integrity of individual blocks
func (cc *ConsistencyChecker) VerifyBlockIntegrity(instanceHash string) ([]uint32, error) {
	meta, err := cc.storage.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}

	if meta.StorageMode != StorageModeDisk {
		return nil, nil // Only applicable to disk storage
	}

	// Get encryption keys
	encMgr := cc.db.GetEncryptionManager()
	dek, err := encMgr.DecryptDataKey(meta.DataKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data key")
	}

	encryptor, err := NewBlockEncryptor(dek, meta.Nonce)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create block encryptor")
	}

	// Open the file
	filePath := filepath.Join(cc.objectsDir, GetInstanceStoragePath(instanceHash))
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open object file")
	}
	defer file.Close()

	// Check each block
	bitmap, err := cc.db.GetBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	totalBlocks := CalculateBlockCount(meta.ContentLength)
	var corruptedBlocks []uint32

	for block := uint32(0); block < totalBlocks; block++ {
		if !bitmap.Contains(block) {
			continue // Skip non-downloaded blocks
		}

		// Read the encrypted block
		encryptedBlock := make([]byte, BlockTotalSize)
		offset := BlockOffset(block)

		// Handle last block size
		readSize := BlockTotalSize
		if block == totalBlocks-1 {
			lastBlockDataSize := int(meta.ContentLength % BlockDataSize)
			if lastBlockDataSize == 0 {
				lastBlockDataSize = BlockDataSize
			}
			readSize = lastBlockDataSize + AuthTagSize
		}

		n, err := file.ReadAt(encryptedBlock[:readSize], offset)
		if err != nil && err != io.EOF {
			log.Warnf("Error reading block %d: %v", block, err)
			corruptedBlocks = append(corruptedBlocks, block)
			continue
		}
		if n < readSize {
			corruptedBlocks = append(corruptedBlocks, block)
			continue
		}

		// Try to decrypt (verifies auth tag)
		_, err = encryptor.DecryptBlock(block, encryptedBlock[:readSize])
		if err != nil {
			log.Warnf("Block %d authentication failed: %v", block, err)
			corruptedBlocks = append(corruptedBlocks, block)
		}
	}

	return corruptedBlocks, nil
}
