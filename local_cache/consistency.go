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
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	errScanDone            = errors.New("scan_done")
	errChecksumSkipped     = errors.New("checksum_skipped")

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

// ConsistencyChecker verifies cache consistency between database and disk.
// For multi-directory configurations, it scans each storage directory
// independently.
type ConsistencyChecker struct {
	db      *CacheDB
	storage *StorageManager

	// Rate limiting (using rate.Limiter treating each token as 1ns)
	metadataScanLimiter *rate.Limiter  // Limits metadata scan active time
	dataScanBytesPerSec int64          // Max bytes per second for data scanning
	minAgeForCleanup    time.Duration  // Minimum age before cleanup to avoid races
	checksumTypes       []ChecksumType // Checksum algorithms to calculate/verify

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
	// ChecksumTypes specifies which checksums to calculate and verify.
	// When empty, defaults to []ChecksumType{ChecksumSHA256}.
	ChecksumTypes []ChecksumType
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

// NewConsistencyChecker creates a new consistency checker.
func NewConsistencyChecker(db *CacheDB, storage *StorageManager, config ConsistencyConfig) *ConsistencyChecker {
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

	checksumTypes := config.ChecksumTypes
	if len(checksumTypes) == 0 {
		checksumTypes = []ChecksumType{ChecksumSHA256}
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
		metadataScanLimiter: limiter,
		dataScanBytesPerSec: config.DataScanBytesPerSec,
		minAgeForCleanup:    config.MinAgeForCleanup,
		checksumTypes:       checksumTypes,
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

// metadataScanLoop runs periodic metadata consistency scans.
// After each scan completes the timer is reset so there is always a full
// hour of idle time between the end of one scan and the start of the next.
func (cc *ConsistencyChecker) metadataScanLoop(ctx context.Context) error {
	// Initial delay to let the system settle
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(5 * time.Minute):
	}

	const scanInterval = 1 * time.Hour

	for {
		// Run the scan, then wait scanInterval before the next one.
		if err := cc.RunMetadataScan(ctx); err != nil {
			log.Warnf("Metadata scan error: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-cc.stopCh:
			return nil
		case <-time.After(scanInterval):
		}
	}
}

// dataScanLoop runs periodic data integrity scans.
// After each scan completes the timer is reset so there is always a full
// 24 hours of idle time between the end of one scan and the start of the next.
func (cc *ConsistencyChecker) dataScanLoop(ctx context.Context) error {
	// Initial delay
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(30 * time.Minute):
	}

	const scanInterval = 24 * time.Hour

	for {
		if err := cc.RunDataScan(ctx); err != nil {
			log.Warnf("Data scan error: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-cc.stopCh:
			return nil
		case <-time.After(scanInterval):
		}
	}
}

// RunMetadataScan performs a metadata consistency scan.
// It verifies that database entries match files on disk and vice versa.
func (cc *ConsistencyChecker) RunMetadataScan(ctx context.Context) error {
	log.Info("Starting metadata consistency scan")
	scanStartTime := time.Now()
	cc.lastMetadataScan.Store(scanStartTime.Unix())
	metadataScanLastStartTime.Set(float64(scanStartTime.Unix()))

	// Stream files from disk via channel.  Each directory's WalkDir
	// produces entries in lexicographic order.  A k-way merge goroutine
	// combines the per-directory streams into a single globally-sorted
	// stream on fileChan, which the merge-join algorithm requires.
	type fileInfo struct {
		instanceHash InstanceHash
		path         string
		modTime      time.Time
		size         int64
	}
	fileChan := make(chan fileInfo, 100)
	walkErr := make(chan error, 1)

	// hadWalkError is set to true if any directory walk encounters an I/O
	// error.  When set, no metadata entries may be deleted during this scan
	// because we cannot be sure the file listing is complete.
	var hadWalkError atomic.Bool

	// walkOneDir walks a single objects directory, sending valid entries
	// to the returned channel in lexicographic order.
	walkOneDir := func(objectsDir string) <-chan fileInfo {
		ch := make(chan fileInfo, 64)
		go func() {
			defer close(ch)
			fsys := os.DirFS(objectsDir)
			_ = fs.WalkDir(fsys, ".", func(relPath string, d fs.DirEntry, err error) error {
				if err != nil {
					// A missing root directory is benign (e.g. inline-only
					// storage has no objects/ dir yet).  Only flag actual
					// mid-walk I/O errors.
					if relPath == "." && os.IsNotExist(err) {
						return fs.SkipAll
					}
					log.Warnf("Walk error in %s/%s: %v", objectsDir, relPath, err)
					hadWalkError.Store(true)
					return nil
				}
				if d.IsDir() {
					return nil
				}

				// Reconstruct hash from path (remove directory separators).
				// io/fs.WalkDir always uses forward slashes, but we also
				// handle backslashes for robustness on Windows.
				hash := strings.ReplaceAll(relPath, "/", "")
				hash = strings.ReplaceAll(hash, "\\", "")
				instanceHash := InstanceHash(hash)

				// Validate instance hash format: must be 64 hex characters (SHA256)
				if len(instanceHash) != 64 {
					return nil
				}
				for _, c := range instanceHash {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						return nil
					}
				}

				info, err := d.Info()
				if err != nil {
					log.Warnf("Unable to stat %s/%s: %v", objectsDir, relPath, err)
					hadWalkError.Store(true)
					return nil
				}

				// Skip files newer than scan start or younger than the grace period
				if info.ModTime().After(scanStartTime) {
					return nil
				}
				if cc.minAgeForCleanup > 0 && time.Since(info.ModTime()) < cc.minAgeForCleanup {
					return nil
				}

				select {
				case ch <- fileInfo{
					instanceHash: instanceHash,
					path:         filepath.Join(objectsDir, relPath),
					modTime:      info.ModTime(),
					size:         info.Size(),
				}:
				case <-ctx.Done():
					return ctx.Err()
				}
				return nil
			})
		}()
		return ch
	}

	// Launch one walker per directory.
	objectsDirs := cc.storage.GetDirs()
	dirChans := make([]<-chan fileInfo, 0, len(objectsDirs))
	for _, objectsDir := range objectsDirs {
		dirChans = append(dirChans, walkOneDir(objectsDir))
	}

	// k-way merge: read from all per-directory channels, always
	// forwarding the entry with the smallest instanceHash.
	go func() {
		defer close(fileChan)
		defer close(walkErr)

		// heads[i] holds the next undelivered entry from dirChans[i].
		// ok[i] is false once dirChans[i] is exhausted.
		heads := make([]fileInfo, len(dirChans))
		ok := make([]bool, len(dirChans))
		for i, ch := range dirChans {
			heads[i], ok[i] = <-ch
		}

		for {
			// Find the channel with the smallest instanceHash.
			minIdx := -1
			for i := range dirChans {
				if !ok[i] {
					continue
				}
				if minIdx == -1 || heads[i].instanceHash < heads[minIdx].instanceHash {
					minIdx = i
				}
			}
			if minIdx == -1 {
				return // All channels exhausted
			}

			select {
			case fileChan <- heads[minIdx]:
			case <-ctx.Done():
				return
			}
			heads[minIdx], ok[minIdx] = <-dirChans[minIdx]
		}
	}()

	// Structures to track what to delete (limit to 1k changes per transaction)
	type deleteAction struct {
		instanceHash InstanceHash
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

	// Accumulate actual byte-level usage per (StorageID, NamespaceID)
	// as we iterate metadata.  This avoids a second expensive full-table
	// scan in reconcileUsage.
	usageDuringScan := make(map[StorageUsageKey]int64)

	// Track where to resume DB scan after each transaction restart
	lastDBKey := InstanceHash("")
	transactionStartTime := time.Now()
	const transactionTimeout = 5 * time.Second

	// Outer loop: restart transactions every 5 seconds
	for {
		transactionStartTime = time.Now()
		transactionComplete := false
		entriesThisTransaction := int64(0)
		deletions = deletions[:0] // Clear deletions list

		err := cc.db.ScanMetadataFrom(lastDBKey, func(instanceHash InstanceHash, meta *CacheMetadata) error {
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

			// Accumulate usage for this entry.  We do this for every
			// entry (including the too-young ones below) so that the
			// totals match the real state of the database.
			if !meta.Completed.IsZero() {
				// Completed object: usage equals its content length
				// (no need to consult the block bitmap).
				if meta.ContentLength > 0 {
					uk := StorageUsageKey{StorageID: meta.StorageID, NamespaceID: meta.NamespaceID}
					usageDuringScan[uk] += meta.ContentLength
				}
			} else {
				// In-progress download: compute usage from the block bitmap.
				if bm, bmErr := cc.db.GetBlockState(instanceHash); bmErr == nil {
					if card := bm.GetCardinality(); card > 0 {
						uk := StorageUsageKey{StorageID: meta.StorageID, NamespaceID: meta.NamespaceID}
						usageDuringScan[uk] += calculateUsageDelta(meta, bm, card)
					}
				}
			}

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
				if meta.IsDisk() {
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
				if meta.IsDisk() {
					// Orphaned DB entry - file should exist but doesn't
					if len(deletions) < maxDeletionsPerTx {
						deletions = append(deletions, deleteAction{
							instanceHash: instanceHash,
							isFile:       false,
							size:         meta.ContentLength,
						})
					}
				} else if meta.IsInline() {
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

		// Process deletions in a new read-write transaction.
		// If any walk error occurred, we cannot trust the file listing and
		// must not delete any entries (files or DB rows) in this scan.
		if len(deletions) > 0 && !hadWalkError.Load() {
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
						if meta.IsDisk() {
							filePath := cc.storage.getObjectPathForDir(meta.StorageID, del.instanceHash)
							if _, err := os.Stat(filePath); os.IsNotExist(err) {
								stillInconsistent = true
							}
						} else if meta.IsInline() {
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

	// Process any remaining files (all are orphaned).
	// Like deletions above, skip if a walk error occurred.
	for fileOk {
		if !hadWalkError.Load() {
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

	// Reconcile the stored usage counters against the running totals
	// accumulated during the metadata scan above.  This avoids a second
	// full-table scan of the metadata and block-state tables.
	if err := cc.reconcileUsage(ctx, usageDuringScan); err != nil {
		log.Warnf("Usage reconciliation failed: %v", err)
	}

	return nil
}

// reconcileUsage compares the stored usage counters against the actual
// usage computed during the metadata scan.  If a counter deviates by more
// than 5 % from the recomputed value, it is corrected.
//
// The caller passes a pre-computed map of actual usage per
// (StorageID, NamespaceID) so that no second full-table scan is needed.
//
// This catches drift that can accumulate from crash recovery, orphan
// cleanup, or bugs in the incremental usage tracking.
func (cc *ConsistencyChecker) reconcileUsage(ctx context.Context, actual map[StorageUsageKey]int64) error {
	stored, err := cc.db.GetAllUsage()
	if err != nil {
		return errors.Wrap(err, "failed to read stored usage")
	}

	corrected := 0

	// Check every key that exists in the actual (recomputed) map.
	for key, actualBytes := range actual {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		storedBytes := stored[key] // 0 if absent

		if !usageDrifted(storedBytes, actualBytes) {
			continue
		}

		log.Warnf("Usage drift for storageID=%d namespaceID=%d: stored=%d actual=%d; correcting",
			key.StorageID, key.NamespaceID, storedBytes, actualBytes)
		if err := cc.db.SetUsage(key.StorageID, key.NamespaceID, actualBytes); err != nil {
			log.Warnf("Failed to correct usage for storageID=%d namespaceID=%d: %v",
				key.StorageID, key.NamespaceID, err)
			continue
		}
		corrected++
	}

	// Check keys that exist in stored but not in actual — they should be 0.
	for key, storedBytes := range stored {
		if _, exists := actual[key]; exists {
			continue // Already handled above.
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !usageDrifted(storedBytes, 0) {
			continue
		}

		log.Warnf("Usage drift for storageID=%d namespaceID=%d: stored=%d actual=0; correcting",
			key.StorageID, key.NamespaceID, storedBytes)
		if err := cc.db.SetUsage(key.StorageID, key.NamespaceID, 0); err != nil {
			log.Warnf("Failed to correct usage for storageID=%d namespaceID=%d: %v",
				key.StorageID, key.NamespaceID, err)
			continue
		}
		corrected++
	}

	if corrected > 0 {
		log.Infof("Usage reconciliation corrected %d counter(s)", corrected)
	} else {
		log.Debug("Usage reconciliation: all counters are within tolerance")
	}

	return nil
}

// usageDrifted returns true if the stored value differs from the actual
// value by more than 5 %.  When the actual value is zero the stored value
// must also be zero (any positive stored value is a 100 % drift).
func usageDrifted(stored, actual int64) bool {
	if actual == 0 {
		return stored != 0
	}
	diff := stored - actual
	if diff < 0 {
		diff = -diff
	}
	// diff > actual*5/100, rearranged to avoid overflow:
	return diff*100 > actual*5
}

// scanItem represents an object from a database scan
type scanItem struct {
	instanceHash InstanceHash
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

	// Start DB scan in background goroutine.  The WaitGroup ensures
	// we do not return from RunDataScan until this goroutine exits.
	var scanWg sync.WaitGroup
	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		defer close(objectChan)
		defer close(scanErr)

		const transactionTimeout = 5 * time.Second

		// Generate random 4-byte hex starting point (16 bits = 4 hex chars)
		// This randomizes where we start scanning through the database
		rng := rand.New(rand.NewSource(scanStartTime.UnixNano()))
		randomStart := fmt.Sprintf("%04x", rng.Intn(1<<16))

		startKey := InstanceHash(randomStart)
		lastKey := startKey
		wrappedAround := false

		for {
			// Wait for the channel to have room before opening a new
			// read transaction.  This avoids holding a transaction open
			// while the consumer is still processing the previous batch.
			for len(objectChan) >= cap(objectChan) {
				select {
				case <-ctx.Done():
					return
				case <-time.After(50 * time.Millisecond):
				}
			}

			transactionStart := time.Now()
			scannedThisTx := 0

			err := cc.db.ScanMetadataFrom(lastKey, func(instanceHash InstanceHash, meta *CacheMetadata) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				// If we've wrapped around and reached our starting point, we're done
				if wrappedAround && instanceHash >= startKey {
					return errScanDone
				}

				// Non-blocking send: if the channel is full, break out of
				// the scan to release the read transaction rather than
				// blocking while the consumer catches up.
				select {
				case objectChan <- scanItem{instanceHash: instanceHash, meta: meta}:
					scannedThisTx++
					lastKey = instanceHash
				default:
					return errChannelFull
				}

				// Restart transaction after timeout
				if time.Since(transactionStart) > transactionTimeout {
					return errTransactionTimeout
				}

				return nil
			})

			if err != nil && !errors.Is(err, errTransactionTimeout) && !errors.Is(err, errChannelFull) && !errors.Is(err, errScanDone) {
				scanErr <- err
				return
			}

			// Check if scan is complete
			if errors.Is(err, errScanDone) {
				return
			}

			// If no items scanned, we've reached the end of the database
			if scannedThisTx == 0 {
				if wrappedAround {
					// Already wrapped and reached end again - done
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
	// Wait for the background DB-scan goroutine to finish before
	// reading from scanErr; this guarantees the goroutine cannot
	// outlive RunDataScan.
	scanWg.Wait()

	// Check for scan errors
	if err := <-scanErr; err != nil && !errors.Is(err, context.Canceled) {
		log.Warnf("Error during data scan: %v", err)
	}

	// Final stats update (scan timing / log)
	scanDuration := time.Since(scanStartTime)
	dataScanDurationSeconds.Add(scanDuration.Seconds())

	log.Infof("Data scan complete in %v: verified %d objects (%d bytes), %d checksum mismatches (%d bytes)",
		scanDuration, objectsVerified, bytesVerified, checksumMismatches, inconsistentBytes)

	return nil
}

// processBatchForDataScan processes a batch of objects for data integrity verification.
// Statistics and prometheus metrics are updated after every object so that
// progress is visible even during multi-day scans.
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

		prevMismatches := *checksumMismatches
		prevInconsistent := *inconsistentBytes
		prevBytes := *bytesVerified
		prevObjects := *objectsVerified

		if err := cc.verifyObjectChecksum(ctx, item.instanceHash, item.meta, bytesLimiter, checksumMismatches, inconsistentBytes, bytesVerified, objectsVerified); err != nil {
			if errors.Is(err, errChecksumSkipped) {
				continue // Incomplete object — don't count as verified
			}
			log.Warnf("Error verifying object %s: %v", item.instanceHash, err)
		}

		// Update prometheus metrics and stats after every object
		deltaMismatches := *checksumMismatches - prevMismatches
		deltaInconsistent := *inconsistentBytes - prevInconsistent
		deltaBytes := *bytesVerified - prevBytes
		deltaObjects := *objectsVerified - prevObjects

		if deltaMismatches > 0 || deltaBytes > 0 || deltaObjects > 0 {
			dataScanInconsistentObjects.Add(float64(deltaMismatches))
			dataScanInconsistentBytes.Add(float64(deltaInconsistent))
			dataScanObjectsProcessed.Add(float64(deltaObjects))
			dataScanBytesProcessed.Add(float64(deltaBytes))

			cc.statsMu.Lock()
			cc.stats.LastDataScan = time.Now()
			cc.stats.ChecksumMismatches += deltaMismatches
			cc.stats.BytesVerified += deltaBytes
			cc.stats.ObjectsVerified += deltaObjects
			cc.statsMu.Unlock()
		}
	}
}

// verifyObjectChecksum verifies a single object's checksum block-by-block.
// If the object is incomplete, it returns errChecksumSkipped.
func (cc *ConsistencyChecker) verifyObjectChecksum(
	ctx context.Context,
	instanceHash InstanceHash,
	meta *CacheMetadata,
	bytesLimiter *rate.Limiter,
	checksumMismatches, inconsistentBytes, bytesVerified, objectsVerified *int64,
) error {
	// For disk storage, check if complete before attempting any checksumming
	if meta.IsDisk() {
		complete, err := cc.storage.IsComplete(instanceHash)
		if err != nil {
			return errors.Wrap(err, "failed to check completeness")
		}
		if !complete {
			return errChecksumSkipped
		}
	}

	// If no checksums available, calculate and store them
	if len(meta.Checksums) == 0 {
		if err := cc.calculateAndStoreChecksums(ctx, instanceHash, meta, bytesLimiter); err != nil {
			return err
		}
		*objectsVerified++
		return nil
	}

	// Build hashers for all stored checksums
	hashers := make([]hash.Hash, len(meta.Checksums))
	for i, cksum := range meta.Checksums {
		h, err := cc.createHasher(cksum.Type)
		if err != nil {
			return err
		}
		hashers[i] = h
	}

	// Read all data through storage manager and hash in one pass
	verified, err := cc.hashObjectData(ctx, instanceHash, meta, bytesLimiter, hashers)
	if err != nil {
		return err
	}

	// Verify each checksum
	for i, cksum := range meta.Checksums {
		computed := hashers[i].Sum(nil)
		if !bytes.Equal(computed, cksum.Value) {
			log.Warnf("Checksum mismatch for object %s (type %d)", instanceHash, cksum.Type)
			*checksumMismatches++
			*inconsistentBytes += meta.ContentLength
			if err := cc.storage.Delete(instanceHash); err != nil {
				log.Warnf("Failed to delete corrupted object %s: %v", instanceHash, err)
			}
			return nil
		}
	}

	*bytesVerified += verified
	*objectsVerified++
	return nil
}

// hashObjectData reads all object data through the storage manager and
// writes it to every hasher.  Returns the number of bytes hashed.
// This is shared between verifyObjectChecksum and calculateAndStoreChecksums
// so that decryption/inline logic lives in one place.
func (cc *ConsistencyChecker) hashObjectData(
	ctx context.Context,
	instanceHash InstanceHash,
	meta *CacheMetadata,
	bytesLimiter *rate.Limiter,
	hashers []hash.Hash,
) (int64, error) {
	if meta.IsInline() {
		data, err := cc.storage.ReadInline(instanceHash)
		if err != nil {
			return 0, errors.Wrap(err, "failed to read inline data")
		}
		if err := bytesLimiter.WaitN(ctx, len(data)); err != nil {
			return 0, err
		}
		for _, h := range hashers {
			h.Write(data)
		}
		return int64(len(data)), nil
	}

	// Disk storage: read block-by-block through storage manager
	// (handles decryption and auth-tag validation for us).
	totalBlocks := CalculateBlockCount(meta.ContentLength)
	var verified int64

	for block := uint32(0); block < totalBlocks; block++ {
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
			return verified, errors.Wrapf(err, "failed to read block %d", block)
		}

		for _, h := range hashers {
			h.Write(blockData)
		}
		verified += int64(len(blockData))

		if err := bytesLimiter.WaitN(ctx, len(blockData)); err != nil {
			return verified, err
		}
	}

	return verified, nil
}

// calculateAndStoreChecksums calculates checksums for an object and stores them.
// Returns errChecksumSkipped if the object is incomplete.
func (cc *ConsistencyChecker) calculateAndStoreChecksums(
	ctx context.Context,
	instanceHash InstanceHash,
	meta *CacheMetadata,
	bytesLimiter *rate.Limiter,
) error {
	log.Debugf("Calculating checksum for %s", instanceHash)

	// For disk storage, verify completeness first
	if meta.IsDisk() {
		complete, err := cc.storage.IsComplete(instanceHash)
		if err != nil {
			return errors.Wrap(err, "failed to check completeness")
		}
		if !complete {
			return errChecksumSkipped
		}
	}

	// Create hashers for all configured checksum types
	hashers := make([]hash.Hash, len(cc.checksumTypes))
	for i, ct := range cc.checksumTypes {
		h, err := cc.createHasher(ct)
		if err != nil {
			return err
		}
		hashers[i] = h
	}

	// Hash all data in one pass through the storage manager
	if _, err := cc.hashObjectData(ctx, instanceHash, meta, bytesLimiter, hashers); err != nil {
		return err
	}

	// Store the calculated checksums
	checksums := make([]Checksum, len(cc.checksumTypes))
	for i, ct := range cc.checksumTypes {
		checksums[i] = Checksum{
			Type:            ct,
			Value:           hashers[i].Sum(nil),
			OriginVerified:  false,
			VerifyAttempted: false,
		}
	}

	checksumMeta := &CacheMetadata{Checksums: checksums}
	if err := cc.db.MergeMetadata(instanceHash, checksumMeta); err != nil {
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

// VerifyObject verifies a single object's integrity.
// If checksums are present, it verifies them all in a single pass.
// If no checksums are present, it still reads all data to verify readability
// (i.e. that decryption tags are valid and all blocks are accessible).
// Returns (true, nil) if the object is valid, (false, nil) if corrupt.
func (cc *ConsistencyChecker) VerifyObject(instanceHash InstanceHash) (bool, error) {
	meta, err := cc.storage.GetMetadata(instanceHash)
	if err != nil {
		return false, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return false, errors.New("object not found")
	}

	// For disk storage, check that the file exists and is complete
	if meta.IsDisk() {
		filePath := cc.storage.getObjectPathForDir(meta.StorageID, instanceHash)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return false, nil
		}
		complete, err := cc.storage.IsComplete(instanceHash)
		if err != nil {
			return false, errors.Wrap(err, "failed to check completeness")
		}
		if !complete {
			return true, nil // Can't verify incomplete objects
		}
	}

	// Build hashers for all stored checksums (may be empty)
	hashers := make([]hash.Hash, len(meta.Checksums))
	for i, cksum := range meta.Checksums {
		h, err := cc.createHasher(cksum.Type)
		if err != nil {
			return false, err
		}
		hashers[i] = h
	}

	// An unlimited rate limiter so VerifyObject runs at full speed
	unlimited := rate.NewLimiter(rate.Inf, 0)

	// Read all data through the storage manager.  Even with no checksums
	// this validates that every block can be decrypted and read.
	if _, err := cc.hashObjectData(context.Background(), instanceHash, meta, unlimited, hashers); err != nil {
		return false, errors.Wrap(err, "failed to read object data")
	}

	// Verify each checksum
	for i, cksum := range meta.Checksums {
		computed := hashers[i].Sum(nil)
		if !bytes.Equal(computed, cksum.Value) {
			return false, nil
		}
	}

	return true, nil
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

// VerifyBlockIntegrity verifies the integrity of individual blocks by
// delegating to the storage manager's IdentifyCorruptBlocks, which handles
// crypto setup, file access, and AES-GCM auth-tag verification.
func (cc *ConsistencyChecker) VerifyBlockIntegrity(instanceHash InstanceHash) ([]uint32, error) {
	meta, err := cc.storage.GetMetadata(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object not found")
	}

	if !meta.IsDisk() {
		return nil, nil // Only applicable to disk storage
	}

	totalBlocks := CalculateBlockCount(meta.ContentLength)
	if totalBlocks == 0 {
		return nil, nil
	}

	return cc.storage.IdentifyCorruptBlocks(instanceHash, 0, totalBlocks-1)
}
