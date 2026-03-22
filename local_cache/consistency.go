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
	"encoding/hex"
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

	"github.com/pelicanplatform/pelican/utils"
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
	lastMetadataScan atomic.Int64  // Unix timestamp of last metadata scan start
	lastDataScan     atomic.Int64  // Unix timestamp of last data scan start
	metaScanCounter  atomic.Uint64 // monotonic ID for metadata scan instances
	dataScanCounter  atomic.Uint64 // monotonic ID for data scan instances
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
		if err := cc.RunMetadataScan(ctx, nil); err != nil {
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
		if err := cc.RunDataScan(ctx, nil); err != nil {
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

// hashBucket returns the zero-based position (0–255) of the first byte
// of a hex-encoded hash.  Used to estimate scan progress: bucket 0x00
// means 1/256 complete, 0xff means 256/256 complete.
func hashBucket(h InstanceHash) int {
	if len(h) < 2 {
		return 0
	}
	b, err := hex.DecodeString(string(h[:2]))
	if err != nil || len(b) == 0 {
		return 0
	}
	return int(b[0])
}

// RunMetadataScan performs a metadata consistency scan.
// It verifies that database entries match files on disk and vice versa.
func (cc *ConsistencyChecker) RunMetadataScan(ctx context.Context, progressCh chan<- ScanProgressEvent) error {
	scanID := cc.metaScanCounter.Add(1)
	sl := log.WithFields(log.Fields{
		"scan":   "metadata",
		"scanID": scanID,
	})
	sl.Info("Starting metadata consistency scan")
	scanStartTime := time.Now()
	lastProgressLog := scanStartTime
	lastProgressSend := scanStartTime
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
		chunkIndex   int       // 0 for base file, 1+ for chunk suffix files (-2, -3, etc.)
		storageID    StorageID // Which storage directory this file is in
	}
	fileChan := make(chan fileInfo, 100)
	walkErr := make(chan error, 1)

	// hadWalkError is set to true if any directory walk encounters an I/O
	// error.  When set, no metadata entries may be deleted during this scan
	// because we cannot be sure the file listing is complete.
	var hadWalkError atomic.Bool

	// walkOneDir walks a single objects directory, sending valid entries
	// to the returned channel in lexicographic order.
	walkOneDir := func(storageID StorageID, objectsDir string) <-chan fileInfo {
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
					sl.WithError(err).WithField("path", objectsDir+"/"+relPath).Warn("Walk error")
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

				// Parse the filename to extract base hash and any chunk index
				// Files can be: <64-hex-hash> (chunk 0) or <64-hex-hash>-N (chunk N-1)
				baseHash, chunkIndex, ok := ParseChunkFilename(hash)
				if !ok {
					return nil
				}
				instanceHash := baseHash

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
					sl.WithError(err).WithField("path", objectsDir+"/"+relPath).Warn("Unable to stat file")
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
					chunkIndex:   chunkIndex,
					storageID:    storageID,
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
	for storageID, objectsDir := range objectsDirs {
		dirChans = append(dirChans, walkOneDir(storageID, objectsDir))
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
		chunkIndex   int // For file deletions: which chunk (0 = base file, 1+ = chunk suffix)
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
			//
			// Both completed and in-progress objects are charged at
			// their actual on-disk size: CalculateFileSize(ContentLength)
			// for disk objects (which accounts for the 16-byte MAC per
			// 4080-byte block), or ContentLength for inline objects.
			if meta.ContentLength > 0 {
				uk := StorageUsageKey{StorageID: meta.StorageID, NamespaceID: meta.NamespaceID}
				if meta.StorageID == StorageIDInline {
					usageDuringScan[uk] += meta.ContentLength
				} else {
					usageDuringScan[uk] += CalculateFileSize(meta.ContentLength)
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
						chunkIndex:   currentFile.chunkIndex,
					})
				}
				filesScanned++
				// Get next file
				currentFile, fileOk = <-fileChan
			}

			// Process all files that match current DB entry (could be multiple chunks)
			for fileOk && currentFile.instanceHash == instanceHash {
				filesScanned++

				if meta.IsDisk() {
					// DB entry expects disk storage - verify chunk validity
					if meta.IsChunked() {
						// For chunked objects, verify chunk index is within range
						expectedChunks := meta.ChunkCount()
						if currentFile.chunkIndex >= expectedChunks {
							// Chunk index out of range - orphaned chunk file
							if len(deletions) < maxDeletionsPerTx {
								deletions = append(deletions, deleteAction{
									instanceHash: currentFile.instanceHash,
									isFile:       true,
									path:         currentFile.path,
									size:         currentFile.size,
									chunkIndex:   currentFile.chunkIndex,
								})
							}
						} else {
							// Verify chunk is in the correct storage directory
							// With lazy allocation, unallocated chunks (StorageID 0) shouldn't have files
							if !meta.IsChunkAllocated(currentFile.chunkIndex) {
								// File exists for an unallocated chunk - orphaned
								if len(deletions) < maxDeletionsPerTx {
									deletions = append(deletions, deleteAction{
										instanceHash: currentFile.instanceHash,
										isFile:       true,
										path:         currentFile.path,
										size:         currentFile.size,
										chunkIndex:   currentFile.chunkIndex,
									})
								}
							} else {
								// Check chunk is in correct storage directory
								expectedStorageID := meta.GetChunkStorageID(currentFile.chunkIndex)
								if currentFile.storageID != expectedStorageID {
									// File is in wrong storage directory - orphaned
									// (The correct file should exist in expectedStorageID)
									if len(deletions) < maxDeletionsPerTx {
										deletions = append(deletions, deleteAction{
											instanceHash: currentFile.instanceHash,
											isFile:       true,
											path:         currentFile.path,
											size:         currentFile.size,
											chunkIndex:   currentFile.chunkIndex,
										})
									}
								}
							}
						}
						// Valid chunk file - no action needed
					} else {
						// Non-chunked object should only have chunk 0 (base file)
						if currentFile.chunkIndex != 0 {
							// Orphaned chunk suffix file for non-chunked object
							if len(deletions) < maxDeletionsPerTx {
								deletions = append(deletions, deleteAction{
									instanceHash: currentFile.instanceHash,
									isFile:       true,
									path:         currentFile.path,
									size:         currentFile.size,
									chunkIndex:   currentFile.chunkIndex,
								})
							}
						} else {
							// Verify non-chunked file is in correct storage directory
							if currentFile.storageID != meta.StorageID {
								if len(deletions) < maxDeletionsPerTx {
									deletions = append(deletions, deleteAction{
										instanceHash: currentFile.instanceHash,
										isFile:       true,
										path:         currentFile.path,
										size:         currentFile.size,
										chunkIndex:   currentFile.chunkIndex,
									})
								}
							}
						}
						// Valid base file - no action needed
					}
				} else {
					// DB entry is inline but file exists - orphaned file
					if len(deletions) < maxDeletionsPerTx {
						deletions = append(deletions, deleteAction{
							instanceHash: currentFile.instanceHash,
							isFile:       true,
							path:         currentFile.path,
							size:         currentFile.size,
							chunkIndex:   currentFile.chunkIndex,
						})
					}
				}

				// Get next file
				currentFile, fileOk = <-fileChan
			}

			// For completed disk objects, verify all required chunk files exist.
			// In-progress objects may have partial chunks (from byte-range downloads),
			// so we only check completed objects.
			if meta.IsDisk() && !meta.Completed.IsZero() {
				if !cc.allChunkFilesExist(meta, instanceHash) {
					// Some chunk files are missing - queue DB entry for deletion
					if len(deletions) < maxDeletionsPerTx {
						deletions = append(deletions, deleteAction{
							instanceHash: instanceHash,
							isFile:       false,
							size:         meta.ContentLength,
						})
					}
				}
			}

			if meta.IsInline() {
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

			// Update last processed key
			lastDBKey = instanceHash

			// Periodic progress logging and SSE updates
			now := time.Now()
			bucket := hashBucket(instanceHash)
			pctDone := float64(bucket+1) / 256.0 * 100.0

			if now.Sub(lastProgressLog) > time.Minute {
				lastProgressLog = now
				elapsed := now.Sub(scanStartTime)
				var eta time.Duration
				if pctDone > 0 {
					eta = time.Duration(float64(elapsed) * (100.0 - pctDone) / pctDone)
				}
				sl.WithFields(log.Fields{
					"progress":      fmt.Sprintf("%.1f%%", pctDone),
					"dbEntries":     dbEntriesScanned,
					"filesScanned":  filesScanned,
					"orphanedDB":    orphanedDBEntries,
					"orphanedFiles": orphanedFiles,
					"orphanedBytes": utils.HumanBytes(orphanedBytes),
					"elapsed":       elapsed.Truncate(time.Second),
					"eta":           eta.Truncate(time.Second),
				}).Info("Metadata scan progress")
			}

			// Send progress to SSE channel (more frequently than logs)
			if progressCh != nil && now.Sub(lastProgressSend) > 2*time.Second {
				lastProgressSend = now
				select {
				case progressCh <- ScanProgressEvent{
					Phase:            "metadata",
					PercentComplete:  pctDone,
					DBEntriesScanned: dbEntriesScanned,
					FilesScanned:     filesScanned,
				}:
				default:
				}
			}

			// Stop if we have enough deletions to process
			if len(deletions) >= maxDeletionsPerTx {
				return errMaxDeletionsReached
			}

			// Check if we should restart the transaction (every 5 seconds)
			if time.Since(transactionStartTime) > transactionTimeout {
				sl.WithFields(log.Fields{
					"duration": time.Since(transactionStartTime).Truncate(time.Millisecond),
					"entries":  entriesThisTransaction,
					"lastKey":  fmt.Sprintf("%.8s...", lastDBKey),
				}).Debug("Restarting metadata scan transaction")
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
						sl.WithField("path", del.path).Warn("Orphaned file")
						orphanedFiles++
						orphanedBytes += del.size
						if err := os.Remove(del.path); err != nil {
							sl.WithError(err).WithField("path", del.path).Warn("Failed to remove orphaned file")
						}
						// For base files (chunk 0), also remove any associated chunk files (chunks 1+)
						// Chunk suffix files are detected and removed independently, so only
						// clean up chunk suffix files when we delete a base file.
						if del.chunkIndex == 0 {
							cc.removeOrphanedChunkFiles(sl, del.path, &orphanedFiles, &orphanedBytes)
						}
					}
				} else {
					// Re-check DB entry still exists and is inconsistent
					meta, err := cc.db.GetMetadata(del.instanceHash)
					if err == nil && meta != nil {
						stillInconsistent := false
						if meta.IsDisk() {
							// Verify all chunk files exist
							stillInconsistent = !cc.allChunkFilesExist(meta, del.instanceHash)
						} else if meta.IsInline() {
							data, err := cc.db.GetInlineData(del.instanceHash)
							if err != nil || data == nil {
								stillInconsistent = true
							}
						}

						if stillInconsistent {
							sl.WithField("instanceHash", del.instanceHash).Warn("Orphaned DB entry")
							orphanedDBEntries++
							orphanedBytes += del.size
							if err := cc.db.DeleteObject(del.instanceHash); err != nil {
								sl.WithError(err).WithField("instanceHash", del.instanceHash).Warn("Failed to clean up orphaned DB entry")
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
					sl.WithField("path", currentFile.path).Warn("Orphaned file")
					orphanedFiles++
					orphanedBytes += currentFile.size
					if err := os.Remove(currentFile.path); err != nil {
						sl.WithError(err).WithField("path", currentFile.path).Warn("Failed to remove orphaned file")
					}
				}
			}
		}
		filesScanned++
		currentFile, fileOk = <-fileChan
	}

	// Check for walk errors
	if walkError := <-walkErr; walkError != nil {
		sl.WithError(walkError).Warn("Error during filesystem walk")
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

	log.Infof("Metadata scan complete in %v: scanned %d DB entries and %d files, found %d orphaned DB entries and %d orphaned files (%s)",
		scanDuration, dbEntriesScanned, filesScanned, orphanedDBEntries, orphanedFiles, utils.HumanBytes(orphanedBytes))

	// Reconcile the stored usage counters against the running totals
	// accumulated during the metadata scan above.  This avoids a second
	// full-table scan of the metadata and block-state tables.
	if err := cc.reconcileUsage(ctx, sl, usageDuringScan); err != nil {
		sl.WithError(err).Warn("Usage reconciliation failed")
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
func (cc *ConsistencyChecker) reconcileUsage(ctx context.Context, sl *log.Entry, actual map[StorageUsageKey]int64) error {
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

		sl.WithFields(log.Fields{
			"storageID":   key.StorageID,
			"namespaceID": key.NamespaceID,
			"stored":      storedBytes,
			"actual":      actualBytes,
		}).Warn("Usage drift; correcting")
		if err := cc.db.SetUsage(key.StorageID, key.NamespaceID, actualBytes); err != nil {
			sl.WithError(err).WithFields(log.Fields{
				"storageID":   key.StorageID,
				"namespaceID": key.NamespaceID,
			}).Warn("Failed to correct usage")
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

		sl.WithFields(log.Fields{
			"storageID":   key.StorageID,
			"namespaceID": key.NamespaceID,
			"stored":      storedBytes,
		}).Warn("Usage drift (actual=0); correcting")
		if err := cc.db.SetUsage(key.StorageID, key.NamespaceID, 0); err != nil {
			sl.WithError(err).WithFields(log.Fields{
				"storageID":   key.StorageID,
				"namespaceID": key.NamespaceID,
			}).Warn("Failed to correct usage")
			continue
		}
		corrected++
	}

	if corrected > 0 {
		sl.WithField("corrected", corrected).Info("Usage reconciliation corrected counters")
	} else {
		sl.Debug("Usage reconciliation: all counters within tolerance")
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
func (cc *ConsistencyChecker) RunDataScan(ctx context.Context, progressCh chan<- ScanProgressEvent) error {
	scanID := cc.dataScanCounter.Add(1)
	sl := log.WithFields(log.Fields{
		"scan":   "data",
		"scanID": scanID,
	})
	sl.Info("Starting data integrity scan")
	scanStartTime := time.Now()
	cc.lastDataScan.Store(scanStartTime.Unix())
	dataScanLastStartTime.Set(float64(scanStartTime.Unix()))

	// Rate limiter for I/O
	bytesLimiter := rate.NewLimiter(rate.Limit(cc.dataScanBytesPerSec), int(cc.dataScanBytesPerSec))

	checksumMismatches := int64(0)
	inconsistentBytes := int64(0)
	bytesVerified := int64(0)
	objectsVerified := int64(0)
	lastProgressSend := scanStartTime

	// Generate random 4-byte hex starting point (16 bits = 4 hex chars)
	// This randomizes where we start scanning through the database
	rng := rand.New(rand.NewSource(scanStartTime.UnixNano()))
	randomStart := fmt.Sprintf("%04x", rng.Intn(1<<16))
	startBucket := hashBucket(InstanceHash(randomStart))

	// Channel for streaming objects from DB scan
	objectChan := make(chan scanItem, 1000)
	scanErr := make(chan error, 1)

	// wrappedAround is set by the producer goroutine when it reaches the end
	// of the keyspace and wraps to the beginning.  The consumer reads it
	// to compute progress.
	var wrappedAround atomic.Bool

	// Start DB scan in background goroutine.  The WaitGroup ensures
	// we do not return from RunDataScan until this goroutine exits.
	var scanWg sync.WaitGroup
	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		defer close(objectChan)
		defer close(scanErr)

		const transactionTimeout = 5 * time.Second

		startKey := InstanceHash(randomStart)
		lastKey := startKey

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
				if wrappedAround.Load() && instanceHash >= startKey {
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
				if wrappedAround.Load() {
					// Already wrapped and reached end again - done
					return
				}
				// Wrap around to beginning
				wrappedAround.Store(true)
				lastKey = ""
				sl.WithField("startKey", string(startKey)).Debug("Data scan wrapping around from end to beginning")
			}
		}
	}()

	// Main goroutine: process objects from channel
	var lastProcessedHash InstanceHash
	var consumerWrappedAround bool
	lastProgressLog := scanStartTime
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
						cc.processBatchForDataScan(ctx, sl, batch, bytesLimiter, &checksumMismatches, &inconsistentBytes, &bytesVerified, &objectsVerified)
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
			cc.processBatchForDataScan(ctx, sl, batch, bytesLimiter, &checksumMismatches, &inconsistentBytes, &bytesVerified, &objectsVerified)
			lastProcessedHash = batch[len(batch)-1].instanceHash
			// Detect when the consumer crosses the wrap point.  Before
			// wrapping, all hashes have bucket >= startBucket.  Once we
			// see a bucket < startBucket we have wrapped around.
			if !consumerWrappedAround && hashBucket(lastProcessedHash) < startBucket {
				consumerWrappedAround = true
			}
		}

		// Periodic progress logging and SSE updates
		now := time.Now()
		currentBucket := hashBucket(lastProcessedHash)
		var distance int
		if !consumerWrappedAround {
			distance = currentBucket - startBucket
			if distance < 0 {
				distance = 0
			}
		} else {
			distance = (256 - startBucket) + currentBucket
		}
		pctDone := float64(distance) / 256.0 * 100.0

		if now.Sub(lastProgressLog) > time.Minute {
			lastProgressLog = now
			elapsed := now.Sub(scanStartTime)
			var eta time.Duration
			if pctDone > 0 {
				eta = time.Duration(float64(elapsed) * (100.0 - pctDone) / pctDone)
			}
			sl.WithFields(log.Fields{
				"progress":           fmt.Sprintf("%.1f%%", pctDone),
				"objectsVerified":    objectsVerified,
				"bytesVerified":      utils.HumanBytes(bytesVerified),
				"checksumMismatches": checksumMismatches,
				"elapsed":            elapsed.Truncate(time.Second),
				"eta":                eta.Truncate(time.Second),
			}).Info("Data scan progress")
		}

		// Send progress to SSE channel (more frequently than logs)
		if progressCh != nil && now.Sub(lastProgressSend) > 2*time.Second {
			lastProgressSend = now
			select {
			case progressCh <- ScanProgressEvent{
				Phase:           "data",
				PercentComplete: pctDone,
				ObjectsVerified: objectsVerified,
				BytesVerified:   bytesVerified,
			}:
			default:
			}
		}
	}

scanComplete:
	// Wait for the background DB-scan goroutine to finish before
	// reading from scanErr; this guarantees the goroutine cannot
	// outlive RunDataScan.
	scanWg.Wait()

	// Check for scan errors
	if err := <-scanErr; err != nil && !errors.Is(err, context.Canceled) {
		sl.WithError(err).Warn("Error during data scan")
	}

	// Final stats update (scan timing / log)
	scanDuration := time.Since(scanStartTime)
	dataScanDurationSeconds.Add(scanDuration.Seconds())

	sl.WithFields(log.Fields{
		"elapsed":            scanDuration.Truncate(time.Second),
		"objectsVerified":    objectsVerified,
		"bytesVerified":      utils.HumanBytes(bytesVerified),
		"checksumMismatches": checksumMismatches,
		"inconsistentBytes":  utils.HumanBytes(inconsistentBytes),
	}).Info("Data scan complete")

	return nil
}

// processBatchForDataScan processes a batch of objects for data integrity verification.
// Statistics and prometheus metrics are updated after every object so that
// progress is visible even during multi-day scans.
func (cc *ConsistencyChecker) processBatchForDataScan(
	ctx context.Context,
	sl *log.Entry,
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
			sl.WithError(err).WithField("instanceHash", item.instanceHash).Warn("Error verifying object")
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
	case ChecksumCRC32C:
		return crc32.New(crc32.MakeTable(crc32.Castagnoli)), nil
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

	// For disk storage, check that all ALLOCATED chunk files exist and object is complete
	if meta.IsDisk() {
		chunkCount := CalculateChunkCount(meta.ContentLength, meta.ChunkSizeCode)
		for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
			// Skip unallocated chunks (they're not expected to exist)
			if !meta.IsChunkAllocated(chunkIdx) {
				continue
			}
			storageID := meta.GetChunkStorageID(chunkIdx)
			chunkPath := cc.storage.getChunkPath(storageID, instanceHash, chunkIdx)
			if _, err := os.Stat(chunkPath); os.IsNotExist(err) {
				return false, nil
			}
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

// allChunkFilesExist checks if all ALLOCATED chunk files for a chunked object exist.
// With lazy allocation, chunks with StorageID = 0 are unallocated and not expected to exist.
func (cc *ConsistencyChecker) allChunkFilesExist(meta *CacheMetadata, instanceHash InstanceHash) bool {
	chunkCount := CalculateChunkCount(meta.ContentLength, meta.ChunkSizeCode)
	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		// Skip unallocated chunks (StorageID = 0)
		if !meta.IsChunkAllocated(chunkIdx) {
			continue
		}
		storageID := meta.GetChunkStorageID(chunkIdx)
		chunkPath := cc.storage.getChunkPath(storageID, instanceHash, chunkIdx)
		if _, err := os.Stat(chunkPath); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// removeOrphanedChunkFiles removes chunk files (chunks 1+) associated with a base file.
// This is called when an orphaned base file (chunk 0) is being deleted.
// Because chunks may be lazily allocated (non-sequential), we list the parent
// directory and match by prefix rather than probing sequential indices.
func (cc *ConsistencyChecker) removeOrphanedChunkFiles(sl *log.Entry, basePath string, orphanedFiles *int64, orphanedBytes *int64) {
	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)
	prefix := base + "-"

	entries, err := os.ReadDir(dir)
	if err != nil {
		sl.WithError(err).WithField("dir", dir).Warn("Failed to list directory for orphaned chunk cleanup")
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		chunkPath := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			sl.WithError(err).WithField("path", chunkPath).Warn("Error getting info for chunk file")
			continue
		}
		sl.WithField("path", chunkPath).Warn("Orphaned chunk file")
		(*orphanedFiles)++
		(*orphanedBytes) += info.Size()
		if err := os.Remove(chunkPath); err != nil {
			sl.WithError(err).WithField("path", chunkPath).Warn("Failed to remove orphaned chunk file")
		}
	}
}
