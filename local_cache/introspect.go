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
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// ObjectInstance represents a cached instance of an object with a specific ETag.
type ObjectInstance struct {
	InstanceHash  string    `json:"instance_hash"`
	ETag          string    `json:"etag"`
	SourceURL     string    `json:"source_url"`
	ContentLength int64     `json:"content_length"`
	ContentType   string    `json:"content_type"`
	LastModified  time.Time `json:"last_modified,omitempty"`
	Completed     time.Time `json:"completed,omitempty"`
	LastAccessed  time.Time `json:"last_accessed,omitempty"`
	Expires       time.Time `json:"expires,omitempty"`
	IsLatest      bool      `json:"is_latest"` // True if this is the latest ETag
	IsInline      bool      `json:"is_inline"` // True if stored inline in database
}

// BlockSummary provides an overview of which blocks have been downloaded.
type BlockSummary struct {
	TotalBlocks      uint32   `json:"total_blocks"`
	DownloadedBlocks uint32   `json:"downloaded_blocks"`
	MissingBlocks    []uint32 `json:"missing_blocks,omitempty"` // Up to first 100 missing blocks
	IsComplete       bool     `json:"is_complete"`
	PercentComplete  float64  `json:"percent_complete"`
}

// ObjectDetails provides detailed metadata for a cached object instance.
type ObjectDetails struct {
	ObjectInstance

	// Additional details
	NamespaceID   uint16            `json:"namespace_id"`
	StorageID     uint8             `json:"storage_id"`
	LastValidated time.Time         `json:"last_validated,omitempty"`
	CacheControl  string            `json:"cache_control,omitempty"`
	Checksums     []ChecksumInfo    `json:"checksums,omitempty"`
	BlockSummary  *BlockSummary     `json:"block_summary,omitempty"` // nil for inline storage
	ChunkSummary  *ChunkInfoSummary `json:"chunk_info,omitempty"`    // nil for non-chunked
}

// ChecksumInfo describes a stored checksum.
type ChecksumInfo struct {
	Type           string `json:"type"`
	Value          string `json:"value"` // Hex-encoded
	OriginVerified bool   `json:"origin_verified"`
}

// ChunkInfoSummary describes chunking configuration for large objects.
type ChunkInfoSummary struct {
	ChunkSizeBytes int64   `json:"chunk_size_bytes"`
	ChunkCount     int     `json:"chunk_count"`
	ChunkLocations []uint8 `json:"chunk_locations"` // StorageID per chunk
}

// VerificationResult contains the result of a checksum verification.
type VerificationResult struct {
	InstanceHash   string           `json:"instance_hash"`
	Valid          bool             `json:"valid"`
	Error          string           `json:"error,omitempty"`
	ChecksumStatus []ChecksumStatus `json:"checksum_status,omitempty"`
}

// ChecksumStatus describes the verification status of a single checksum.
type ChecksumStatus struct {
	Type     string `json:"type"`
	Expected string `json:"expected"` // Hex-encoded
	Computed string `json:"computed"` // Hex-encoded (only if verification ran)
	Match    bool   `json:"match"`
}

// CacheStats contains aggregate size statistics about the cache.
type CacheStats struct {
	TotalInlineBytes     int64                       `json:"total_inline_bytes"`
	TotalMetadataEntries int64                       `json:"total_metadata_entries"`
	TotalBytesMetadata   int64                       `json:"total_bytes_metadata"`     // Sum of ContentLength from metadata entries
	UsageCounters        map[string]int64            `json:"usage_counters,omitempty"` // Pre-computed usage from u: prefix keys
	StorageBreakdown     map[string]*StorageDirStats `json:"storage_breakdown,omitempty"`
	DirPaths             map[uint8]string            `json:"dir_paths,omitempty"`       // StorageID → directory path
	NamespaceNames       map[uint32]string           `json:"namespace_names,omitempty"` // NamespaceID → prefix string
}

// StorageDirStats holds per-storage-directory statistics.
type StorageDirStats struct {
	StorageID   uint8 `json:"storage_id"`
	ObjectCount int64 `json:"object_count"`
	TotalBytes  int64 `json:"total_bytes"`   // Sum of ContentLength for objects in this dir
	InlineCount int64 `json:"inline_count"`  // Number of inline objects
	InlineBytes int64 `json:"inline_bytes"`  // Sum of ContentLength for inline objects
	OnDiskCount int64 `json:"on_disk_count"` // Number of on-disk objects
	OnDiskBytes int64 `json:"on_disk_bytes"` // Actual bytes on disk (content + per-block MAC overhead)
}

// DiskUsageResult contains the result of an expensive disk walk.
type DiskUsageResult struct {
	TotalBytesOnDisk int64                   `json:"total_bytes_on_disk"`
	TotalFiles       int64                   `json:"total_files"`
	Directories      map[string]*DirDiskStat `json:"directories,omitempty"`
	Duration         string                  `json:"duration"` // How long the walk took
}

// DirDiskStat holds per-directory disk usage from walking the filesystem.
type DirDiskStat struct {
	StorageID uint8  `json:"storage_id"`
	Path      string `json:"path"`
	BytesUsed int64  `json:"bytes_used"`
	FileCount int64  `json:"file_count"`
}

// ConsistencyCheckResult contains the result of a consistency check run.
type ConsistencyCheckResult struct {
	MetadataScanRan    bool   `json:"metadata_scan_ran"`
	DataScanRan        bool   `json:"data_scan_ran"`
	OrphanedFiles      int64  `json:"orphaned_files"`
	OrphanedDBEntries  int64  `json:"orphaned_db_entries"`
	ChecksumMismatches int64  `json:"checksum_mismatches"`
	BytesVerified      int64  `json:"bytes_verified"`
	ObjectsVerified    int64  `json:"objects_verified"`
	MetadataScanErrors int64  `json:"metadata_scan_errors"`
	DataScanErrors     int64  `json:"data_scan_errors"`
	Duration           string `json:"duration"`
	Error              string `json:"error,omitempty"`
}

// ScanProgressEvent is sent as an SSE event to report scan progress.
// The Event field (used as SSE event type) is one of:
//   - "metadata_progress": periodic update during the metadata scan
//   - "metadata_done": the metadata scan has finished
//   - "data_progress": periodic update during the data scan
//   - "data_done": the data scan has finished
//   - "error": an error occurred
//   - "done": all scans complete; the Data field is a ConsistencyCheckResult
type ScanProgressEvent struct {
	// Phase is the scan phase: "metadata" or "data".
	Phase string `json:"phase"`

	// PercentComplete is the estimated completion (0–100).
	PercentComplete float64 `json:"percent_complete"`

	// DBEntriesScanned is the number of DB entries processed so far (metadata only).
	DBEntriesScanned int64 `json:"db_entries_scanned,omitempty"`

	// FilesScanned is the number of filesystem entries processed (metadata only).
	FilesScanned int64 `json:"files_scanned,omitempty"`

	// ObjectsVerified is the number of objects checksummed so far (data only).
	ObjectsVerified int64 `json:"objects_verified,omitempty"`

	// BytesVerified is the total bytes read for checksumming (data only).
	BytesVerified int64 `json:"bytes_verified,omitempty"`

	// Message is a human-readable status line.
	Message string `json:"message,omitempty"`
}

// IntrospectAPIOpen provides read-only introspection access to the cache database.
// It opens the cache database in read-only mode, suitable for CLI tools that
// need to inspect cache contents without disturbing a running cache server.
type IntrospectAPIOpen struct {
	db      *CacheDB
	storage *StorageManager
	baseDir string
}

// NewIntrospectAPI creates a new introspection API by opening the cache
// database and storage manager in read-only mode.
func NewIntrospectAPI(baseDir string) (*IntrospectAPIOpen, error) {
	// Open database (read-only is not directly supported by NewCacheDB,
	// but we only perform read operations)
	db, err := OpenCacheDBReadOnly(baseDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open cache database")
	}

	// Open storage manager
	storage, err := NewStorageManagerReadOnly(baseDir, db)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to open storage manager")
	}

	return &IntrospectAPIOpen{
		db:      db,
		storage: storage,
		baseDir: baseDir,
	}, nil
}

// Close releases resources held by the introspection API.
func (api *IntrospectAPIOpen) Close() error {
	if api.storage != nil {
		api.storage.Close()
	}
	if api.db != nil {
		if err := api.db.Close(); err != nil {
			return err
		}
	}
	return nil
}

// ListObjectInstances returns all cached instances for a given object URL.
// The URL should be a pelican:// URL (e.g., pelican://host/path/file.dat).
// If the URL doesn't have a scheme, it will be normalized with the default federation.
func (api *IntrospectAPIOpen) ListObjectInstances(objectURL string) ([]ObjectInstance, error) {
	// Normalize the URL
	normalized := NormalizePelicanURL(objectURL)
	if normalized == "" {
		return nil, errors.New("invalid object URL")
	}

	// Compute object hash
	objectHash := api.db.ObjectHash(normalized)

	// Get the latest ETag for this object
	latestETag, _, err := api.db.GetLatestETag(objectHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get latest ETag")
	}

	// Scan all metadata entries to find instances matching this URL
	var instances []ObjectInstance
	err = api.db.ScanMetadata(func(instanceHash InstanceHash, meta *CacheMetadata) error {
		// Check if this instance belongs to the object we're looking for
		// by comparing the SourceURL
		if meta.SourceURL != normalized && meta.SourceURL != objectURL {
			// Try normalizing the stored URL for comparison
			if NormalizePelicanURL(meta.SourceURL) != normalized {
				return nil // Not a match
			}
		}

		expires := meta.Expires
		if expires.IsZero() {
			expires = meta.ComputeExpires()
		}

		instance := ObjectInstance{
			InstanceHash:  string(instanceHash),
			ETag:          meta.ETag,
			SourceURL:     meta.SourceURL,
			ContentLength: meta.ContentLength,
			ContentType:   meta.ContentType,
			LastModified:  meta.LastModified,
			Completed:     meta.Completed,
			LastAccessed:  meta.LastAccessTime,
			Expires:       expires,
			IsLatest:      meta.ETag == latestETag,
			IsInline:      meta.IsInline(),
		}
		instances = append(instances, instance)
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan metadata")
	}

	// Sort by LastAccessed (most recent first)
	sort.Slice(instances, func(i, j int) bool {
		return instances[i].LastAccessed.After(instances[j].LastAccessed)
	})

	return instances, nil
}

// GetObjectDetails returns detailed metadata for a specific object instance.
// The instanceHash can be obtained from ListObjectInstances.
// Alternatively, pass objectURL and etag to look up by those identifiers.
func (api *IntrospectAPIOpen) GetObjectDetails(instanceHash string) (*ObjectDetails, error) {
	hash := InstanceHash(instanceHash)

	meta, err := api.storage.GetMetadata(hash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object instance not found")
	}

	expires := meta.Expires
	if expires.IsZero() {
		expires = meta.ComputeExpires()
	}

	details := &ObjectDetails{
		ObjectInstance: ObjectInstance{
			InstanceHash:  instanceHash,
			ETag:          meta.ETag,
			SourceURL:     meta.SourceURL,
			ContentLength: meta.ContentLength,
			ContentType:   meta.ContentType,
			LastModified:  meta.LastModified,
			Completed:     meta.Completed,
			LastAccessed:  meta.LastAccessTime,
			Expires:       expires,
			IsInline:      meta.IsInline(),
		},
		NamespaceID:   uint16(meta.NamespaceID),
		StorageID:     uint8(meta.StorageID),
		LastValidated: meta.LastValidated,
	}

	// Extract cache-control as string
	cc := meta.GetCacheDirectives()
	if cc.HasDirectives() {
		details.CacheControl = formatCacheDirectives(cc)
	}

	// Convert checksums
	for _, cksum := range meta.Checksums {
		details.Checksums = append(details.Checksums, ChecksumInfo{
			Type:           checksumTypeString(cksum.Type),
			Value:          hex.EncodeToString(cksum.Value),
			OriginVerified: cksum.OriginVerified,
		})
	}

	// For disk storage, get block summary
	if !meta.IsInline() {
		summary, err := api.getBlockSummary(hash, meta.ContentLength)
		if err != nil {
			// Log but don't fail - partial info is still useful
			summary = &BlockSummary{
				TotalBlocks: uint32(CalculateBlockCount(meta.ContentLength)),
			}
		}
		details.BlockSummary = summary
	}

	// For chunked objects, include chunk info
	if meta.IsChunked() {
		chunkSize := ChunkSizeCodeToBytes(meta.ChunkSizeCode)
		chunkCount := meta.ChunkCount()
		locations := make([]uint8, chunkCount)
		locations[0] = uint8(meta.StorageID)
		for i := 1; i < chunkCount && i-1 < len(meta.ChunkLocations); i++ {
			locations[i] = uint8(meta.ChunkLocations[i-1].StorageID)
		}
		details.ChunkSummary = &ChunkInfoSummary{
			ChunkSizeBytes: int64(chunkSize),
			ChunkCount:     chunkCount,
			ChunkLocations: locations,
		}
	}

	// Check if this is the latest version
	objectHash := api.db.ObjectHash(meta.SourceURL)
	latestETag, _, _ := api.db.GetLatestETag(objectHash)
	details.IsLatest = meta.ETag == latestETag

	return details, nil
}

// GetObjectDetailsByURL looks up object details by URL and optional ETag.
// If etag is empty, returns details for the latest version.
func (api *IntrospectAPIOpen) GetObjectDetailsByURL(objectURL, etag string) (*ObjectDetails, error) {
	normalized := NormalizePelicanURL(objectURL)
	if normalized == "" {
		return nil, errors.New("invalid object URL")
	}

	objectHash := api.db.ObjectHash(normalized)

	// If no ETag specified, get the latest
	if etag == "" {
		var found bool
		var err error
		etag, found, err = api.db.GetLatestETag(objectHash)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get latest ETag")
		}
		if !found {
			return nil, errors.New("no cached version found for this object")
		}
	}

	instanceHash := api.db.InstanceHash(etag, objectHash)
	return api.GetObjectDetails(string(instanceHash))
}

// VerifyChecksum triggers a checksum verification for the specified instance.
// Returns detailed verification results including per-checksum status.
func (api *IntrospectAPIOpen) VerifyChecksum(instanceHash string) (*VerificationResult, error) {
	hash := InstanceHash(instanceHash)

	meta, err := api.storage.GetMetadata(hash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get metadata")
	}
	if meta == nil {
		return nil, errors.New("object instance not found")
	}

	result := &VerificationResult{
		InstanceHash: instanceHash,
	}

	// Check if object is complete
	if !meta.IsInline() {
		complete, err := api.storage.IsComplete(hash)
		if err != nil {
			result.Error = fmt.Sprintf("failed to check completeness: %v", err)
			return result, nil
		}
		if !complete {
			result.Error = "object download is not complete, cannot verify"
			return result, nil
		}
	}

	// Create the consistency checker config
	ccConfig := ConsistencyConfig{
		ChecksumTypes: []ChecksumType{ChecksumSHA256, ChecksumMD5, ChecksumSHA1},
	}
	cc := NewConsistencyChecker(api.db, api.storage, ccConfig)

	// Run verification
	valid, err := cc.VerifyObject(hash)
	if err != nil {
		result.Error = fmt.Sprintf("verification failed: %v", err)
		return result, nil
	}

	result.Valid = valid

	// If there are stored checksums, report their status
	if len(meta.Checksums) > 0 {
		for _, cksum := range meta.Checksums {
			status := ChecksumStatus{
				Type:     checksumTypeString(cksum.Type),
				Expected: hex.EncodeToString(cksum.Value),
				Match:    valid, // If valid is true, all matched
			}
			result.ChecksumStatus = append(result.ChecksumStatus, status)
		}
	}

	return result, nil
}

// VerifyChecksumByURL verifies checksum for an object by URL and optional ETag.
func (api *IntrospectAPIOpen) VerifyChecksumByURL(objectURL, etag string) (*VerificationResult, error) {
	normalized := NormalizePelicanURL(objectURL)
	if normalized == "" {
		return nil, errors.New("invalid object URL")
	}

	objectHash := api.db.ObjectHash(normalized)

	if etag == "" {
		var found bool
		var err error
		etag, found, err = api.db.GetLatestETag(objectHash)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get latest ETag")
		}
		if !found {
			return nil, errors.New("no cached version found for this object")
		}
	}

	instanceHash := api.db.InstanceHash(etag, objectHash)
	return api.VerifyChecksum(string(instanceHash))
}

// getBlockSummary computes block download status for an object.
func (api *IntrospectAPIOpen) getBlockSummary(instanceHash InstanceHash, contentLength int64) (*BlockSummary, error) {
	if contentLength <= 0 {
		return &BlockSummary{IsComplete: true, PercentComplete: 100.0}, nil
	}

	totalBlocks := uint32(CalculateBlockCount(contentLength))
	bitmap, err := api.db.GetBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	downloadedBlocks := uint32(bitmap.GetCardinality())
	isComplete := downloadedBlocks >= totalBlocks

	summary := &BlockSummary{
		TotalBlocks:      totalBlocks,
		DownloadedBlocks: downloadedBlocks,
		IsComplete:       isComplete,
		PercentComplete:  float64(downloadedBlocks) / float64(totalBlocks) * 100.0,
	}

	// Find missing blocks (limit to first 100)
	if !isComplete {
		for blockNum := uint32(0); blockNum < totalBlocks && len(summary.MissingBlocks) < 100; blockNum++ {
			if !bitmap.Contains(blockNum) {
				summary.MissingBlocks = append(summary.MissingBlocks, blockNum)
			}
		}
	}

	return summary, nil
}

// ListAllObjects returns a summary of all cached objects.
// This can be slow for large caches; consider using pagination in production.
func (api *IntrospectAPIOpen) ListAllObjects(limit int, pattern string) ([]ObjectInstance, error) {
	if limit <= 0 {
		limit = 1000 // Default limit
	}

	// If pattern contains no glob metacharacters, treat it as a substring
	// match (simpler and faster for plain URL fragments).  Otherwise use
	// filepath.Match-style glob matching.  Double-star ("**") is expanded
	// to match across path separators.
	isGlob := strings.ContainsAny(pattern, "*?[")

	var instances []ObjectInstance
	err := api.db.ScanMetadata(func(instanceHash InstanceHash, meta *CacheMetadata) error {
		if len(instances) >= limit {
			return errors.New("limit reached") // Stop scanning
		}

		if pattern != "" {
			if isGlob {
				// Replace ** with a sentinel, match each path segment with *,
				// and restore.  filepath.Match does not support **.
				p := strings.ReplaceAll(pattern, "**", "\x00")
				// If the pattern has no \x00 (no **), use filepath.Match directly.
				if !strings.Contains(p, "\x00") {
					matched, _ := filepath.Match(pattern, meta.SourceURL)
					if !matched {
						return nil
					}
				} else {
					// Simple ** support: split on \x00 and check that all
					// literal parts appear in order in the URL.
					parts := strings.Split(p, "\x00")
					remaining := meta.SourceURL
					ok := true
					for i, part := range parts {
						if part == "" {
							continue
						}
						idx := strings.Index(remaining, part)
						if idx < 0 {
							ok = false
							break
						}
						if i == 0 && !strings.HasPrefix(pattern, "**") && idx != 0 {
							ok = false
							break
						}
						remaining = remaining[idx+len(part):]
					}
					if !ok {
						return nil
					}
					if !strings.HasSuffix(pattern, "**") && remaining != "" {
						return nil
					}
				}
			} else if !strings.Contains(meta.SourceURL, pattern) {
				return nil
			}
		}

		expires := meta.Expires
		if expires.IsZero() {
			expires = meta.ComputeExpires()
		}

		instance := ObjectInstance{
			InstanceHash:  string(instanceHash),
			ETag:          meta.ETag,
			SourceURL:     meta.SourceURL,
			ContentLength: meta.ContentLength,
			ContentType:   meta.ContentType,
			LastModified:  meta.LastModified,
			Completed:     meta.Completed,
			LastAccessed:  meta.LastAccessTime,
			Expires:       expires,
			IsInline:      meta.IsInline(),
		}
		instances = append(instances, instance)
		return nil
	})
	if err != nil && err.Error() != "limit reached" {
		return nil, errors.Wrap(err, "failed to scan metadata")
	}

	return instances, nil
}

// GetCacheStats returns aggregate cache size statistics by scanning metadata.
// This scans all metadata entries and the inline data prefix, but does NOT
// walk the disk (use GetDiskUsage for that).
func (api *IntrospectAPIOpen) GetCacheStats() (*CacheStats, error) {
	stats := &CacheStats{
		StorageBreakdown: make(map[string]*StorageDirStats),
	}

	// Scan all metadata entries to compute counts + total bytes
	err := api.db.ScanMetadata(func(instanceHash InstanceHash, meta *CacheMetadata) error {
		stats.TotalMetadataEntries++
		stats.TotalBytesMetadata += meta.ContentLength

		dirKey := fmt.Sprintf("storage-%d", meta.StorageID)
		ds, ok := stats.StorageBreakdown[dirKey]
		if !ok {
			ds = &StorageDirStats{StorageID: uint8(meta.StorageID)}
			stats.StorageBreakdown[dirKey] = ds
		}
		ds.ObjectCount++
		ds.TotalBytes += meta.ContentLength

		if meta.IsInline() {
			ds.InlineCount++
			ds.InlineBytes += meta.ContentLength
		} else {
			ds.OnDiskCount++
			ds.OnDiskBytes += CalculateFileSize(meta.ContentLength)
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan metadata")
	}

	// Compute total inline bytes by scanning the inline data prefix
	inlineBytes, inlineErr := api.db.ComputeInlineDataSize()
	if inlineErr != nil {
		return nil, errors.Wrap(inlineErr, "failed to compute inline data size")
	}
	stats.TotalInlineBytes = inlineBytes

	// Read pre-computed usage counters
	usage, usageErr := api.db.GetAllUsage()
	if usageErr == nil && len(usage) > 0 {
		stats.UsageCounters = make(map[string]int64, len(usage))
		for k, v := range usage {
			key := fmt.Sprintf("s%d:ns%d", k.StorageID, k.NamespaceID)
			stats.UsageCounters[key] = v
		}
	}

	// Populate human-readable mappings for storage dirs and namespaces.
	if mappings, err := api.db.LoadDiskMappings(); err == nil && len(mappings) > 0 {
		stats.DirPaths = make(map[uint8]string, len(mappings))
		for _, dm := range mappings {
			stats.DirPaths[uint8(dm.ID)] = dm.Directory
		}
	}
	if nsMappings, _, err := api.db.LoadNamespaceMappings(); err == nil && len(nsMappings) > 0 {
		stats.NamespaceNames = make(map[uint32]string, len(nsMappings))
		for prefix, id := range nsMappings {
			stats.NamespaceNames[uint32(id)] = prefix
		}
	}

	return stats, nil
}

// GetDiskUsage walks the storage directories to compute actual disk usage.
// This is an expensive operation that reads every file's size on disk.
func (api *IntrospectAPIOpen) GetDiskUsage() (*DiskUsageResult, error) {
	start := time.Now()
	result := &DiskUsageResult{
		Directories: make(map[string]*DirDiskStat),
	}

	dirs := api.storage.GetDirs()
	for storageID, objectsDir := range dirs {
		dirKey := fmt.Sprintf("storage-%d", storageID)
		ds := &DirDiskStat{
			StorageID: uint8(storageID),
			Path:      objectsDir,
		}

		err := filepath.WalkDir(objectsDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil // skip entries we can't stat
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil // skip
			}
			ds.FileCount++
			ds.BytesUsed += info.Size()
			return nil
		})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to walk storage directory %s", objectsDir)
		}

		result.Directories[dirKey] = ds
		result.TotalBytesOnDisk += ds.BytesUsed
		result.TotalFiles += ds.FileCount
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

// RunConsistencyCheck runs a full consistency check (metadata scan + data scan)
// and returns statistics. This creates a temporary ConsistencyChecker with
// unlimited rate limiting for the ad-hoc run.
func (api *IntrospectAPIOpen) RunConsistencyCheck(ctx context.Context, metadataScan, dataScan bool) (*ConsistencyCheckResult, error) {
	start := time.Now()
	result := &ConsistencyCheckResult{}

	// Create a checker with no rate limiting for ad-hoc run
	checker := NewConsistencyChecker(api.db, api.storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,                    // Use full second of active time per second (no throttling)
		DataScanBytesPerSec:  10 * 1024 * 1024 * 1024, // 10 GB/s (effectively unlimited)
		MinAgeForCleanup:     0,                       // No grace period for offline check
	})

	if metadataScan {
		if err := checker.RunMetadataScan(ctx, nil); err != nil {
			result.Error = fmt.Sprintf("metadata scan failed: %v", err)
		}
		result.MetadataScanRan = true
	}

	if dataScan {
		if err := checker.RunDataScan(ctx, nil); err != nil {
			if result.Error != "" {
				result.Error += "; "
			}
			result.Error += fmt.Sprintf("data scan failed: %v", err)
		}
		result.DataScanRan = true
	}

	stats := checker.GetStats()
	result.OrphanedFiles = stats.OrphanedFiles
	result.OrphanedDBEntries = stats.OrphanedDBEntries
	result.ChecksumMismatches = stats.ChecksumMismatches
	result.BytesVerified = stats.BytesVerified
	result.ObjectsVerified = stats.ObjectsVerified
	result.MetadataScanErrors = stats.MetadataScanErrors
	result.DataScanErrors = stats.DataScanErrors
	result.Duration = time.Since(start).String()

	return result, nil
}

// NormalizePelicanURL normalizes a Pelican URL for consistent hashing.
// Handles pelican://, osdf://, and bare paths.
func NormalizePelicanURL(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" {
		return ""
	}

	// If it's already a full URL, normalize it
	if strings.HasPrefix(urlStr, "pelican://") || strings.HasPrefix(urlStr, "osdf://") {
		return normalizeURL(urlStr)
	}

	// For bare paths, we cannot normalize without federation context
	// Just return the path cleaned
	if strings.HasPrefix(urlStr, "/") {
		return urlStr
	}

	return urlStr
}

// checksumTypeString converts a ChecksumType to its string representation.
func checksumTypeString(ct ChecksumType) string {
	switch ct {
	case ChecksumMD5:
		return "MD5"
	case ChecksumSHA1:
		return "SHA1"
	case ChecksumSHA256:
		return "SHA256"
	case ChecksumCRC32:
		return "CRC32"
	case ChecksumCRC32C:
		return "CRC32C"
	default:
		return fmt.Sprintf("unknown(%d)", ct)
	}
}

// formatCacheDirectives converts CacheDirectives to a human-readable string.
func formatCacheDirectives(cc CacheDirectives) string {
	var parts []string
	if cc.NoStore() {
		parts = append(parts, "no-store")
	}
	if cc.NoCache() {
		parts = append(parts, "no-cache")
	}
	if cc.Private() {
		parts = append(parts, "private")
	}
	if cc.MustRevalidate() {
		parts = append(parts, "must-revalidate")
	}
	if maxAge, ok := cc.Freshness(); ok {
		parts = append(parts, fmt.Sprintf("max-age=%d", int(maxAge.Seconds())))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}
