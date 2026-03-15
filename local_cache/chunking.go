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
	"fmt"
	"strconv"
	"strings"
)

// ChunkSizeCode is a compact uint8 encoding of chunk sizes for storage efficiency.
// The encoding is non-linear to cover a wide range from 2MB to ~57GB:
//
//   - 0:      Chunking disabled (object stored in a single file)
//   - 1-6:    Doubling: 2^n MB (2, 4, 8, 16, 32, 64 MB)
//   - 7-21:   64 MB increments starting at 128 MB (128, 192, ..., 1024 MB)
//   - 22-53:  128 MB increments starting at 1152 MB (1152, 1280, ..., 5120 MB)
//   - 54-255: 256 MB increments starting at 5376 MB (5376, 5632, ..., ~57 GB)
type ChunkSizeCode uint8

const (
	// ChunkingDisabled indicates the object is stored in a single file
	ChunkingDisabled ChunkSizeCode = 0

	// Minimum and maximum chunk size codes
	minDoubleCode    ChunkSizeCode = 1
	maxDoubleCode    ChunkSizeCode = 6
	min64MBCode      ChunkSizeCode = 7
	max64MBCode      ChunkSizeCode = 21
	min128MBCode     ChunkSizeCode = 22
	max128MBCode     ChunkSizeCode = 53
	min256MBCode     ChunkSizeCode = 54
	maxChunkSizeCode ChunkSizeCode = 255

	// Size constants in bytes
	mb = 1024 * 1024
	gb = 1024 * mb
)

// ChunkSizeCodeToBytes converts a ChunkSizeCode to the actual chunk size in bytes.
// Returns 0 if chunking is disabled.
// The returned size is always rounded down to a multiple of BlockDataSize to ensure
// blocks don't span chunk boundaries.
func ChunkSizeCodeToBytes(code ChunkSizeCode) uint64 {
	var rawSize uint64
	switch {
	case code == ChunkingDisabled:
		return 0
	case code <= maxDoubleCode:
		// 1-6: 2^code MB (2, 4, 8, 16, 32, 64 MB)
		rawSize = uint64(1<<code) * mb
	case code <= max64MBCode:
		// 7-21: 128 + (code-7)*64 MB
		rawSize = uint64(128+(int(code)-7)*64) * mb
	case code <= max128MBCode:
		// 22-53: 1152 + (code-22)*128 MB
		rawSize = uint64(1152+(int(code)-22)*128) * mb
	default:
		// 54-255: 5376 + (code-54)*256 MB
		rawSize = uint64(5376+(int(code)-54)*256) * mb
	}
	// Round down to block boundary to prevent blocks from spanning chunks
	return (rawSize / BlockDataSize) * BlockDataSize
}

// BytesToChunkSizeCode converts a byte size to the nearest ChunkSizeCode
// that is >= the requested size (rounds up to ensure chunks can hold the data).
// Returns ChunkingDisabled (0) if size is 0.
func BytesToChunkSizeCode(size uint64) ChunkSizeCode {
	if size == 0 {
		return ChunkingDisabled
	}

	// Convert to MB for easier calculation (round up)
	sizeMB := (size + mb - 1) / mb

	// Check doubling range: 2, 4, 8, 16, 32, 64 MB
	if sizeMB <= 2 {
		return 1 // 2 MB
	}
	if sizeMB <= 4 {
		return 2 // 4 MB
	}
	if sizeMB <= 8 {
		return 3 // 8 MB
	}
	if sizeMB <= 16 {
		return 4 // 16 MB
	}
	if sizeMB <= 32 {
		return 5 // 32 MB
	}
	if sizeMB <= 64 {
		return 6 // 64 MB
	}

	// 64 MB increment range: 128, 192, ..., 1024 MB
	if sizeMB <= 1024 {
		// code = 7 + ceil((sizeMB - 128) / 64)
		if sizeMB <= 128 {
			return 7 // 128 MB
		}
		code := 7 + (sizeMB-128+63)/64
		if code > uint64(max64MBCode) {
			code = uint64(max64MBCode)
		}
		return ChunkSizeCode(code)
	}

	// 128 MB increment range: 1152, 1280, ..., 5120 MB
	if sizeMB <= 5120 {
		// code = 22 + ceil((sizeMB - 1152) / 128)
		if sizeMB <= 1152 {
			return 22 // 1152 MB
		}
		code := 22 + (sizeMB-1152+127)/128
		if code > uint64(max128MBCode) {
			code = uint64(max128MBCode)
		}
		return ChunkSizeCode(code)
	}

	// 256 MB increment range: 5376, 5632, ..., ~57 GB
	// code = 54 + ceil((sizeMB - 5376) / 256)
	if sizeMB <= 5376 {
		return 54 // 5376 MB
	}
	code := 54 + (sizeMB-5376+255)/256
	if code > uint64(maxChunkSizeCode) {
		code = uint64(maxChunkSizeCode)
	}
	return ChunkSizeCode(code)
}

// ChunkLocation stores the storage location of a single chunk.
// Chunk 0 is always stored at the StorageID in CacheMetadata.
// Additional chunks (1, 2, ...) are stored in the ChunkLocations slice.
type ChunkLocation struct {
	StorageID StorageID `msgpack:"s"` // Which storage directory holds this chunk
}

// CalculateChunkCount returns the number of chunks needed to store an object
// of the given size with the specified chunk size code.
// Returns 1 if chunking is disabled (the entire object is one "chunk").
func CalculateChunkCount(contentLength int64, chunkSizeCode ChunkSizeCode) int {
	if contentLength <= 0 || chunkSizeCode == ChunkingDisabled {
		return 1
	}

	chunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	if chunkSize == 0 {
		return 1
	}

	return int((contentLength + chunkSize - 1) / chunkSize)
}

// GetChunkRange returns the start and end byte offsets (inclusive) for a specific chunk.
// chunkIndex is 0-based.
func GetChunkRange(contentLength int64, chunkSizeCode ChunkSizeCode, chunkIndex int) (start, end int64) {
	if contentLength <= 0 || chunkSizeCode == ChunkingDisabled || chunkIndex < 0 {
		return 0, contentLength - 1
	}

	chunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	if chunkSize == 0 {
		return 0, contentLength - 1
	}

	start = int64(chunkIndex) * chunkSize
	if start >= contentLength {
		// Invalid chunk index
		return 0, -1
	}

	end = start + chunkSize - 1
	if end >= contentLength {
		end = contentLength - 1
	}

	return start, end
}

// ContentOffsetToChunk returns the chunk index for a given content byte offset.
func ContentOffsetToChunk(contentOffset int64, chunkSizeCode ChunkSizeCode) int {
	if contentOffset < 0 || chunkSizeCode == ChunkingDisabled {
		return 0
	}

	chunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	if chunkSize == 0 {
		return 0
	}

	return int(contentOffset / chunkSize)
}

// GetChunkFileSuffix returns the file suffix for a chunk.
// Chunk 0 has no suffix (the base file), chunk 1 is "-2", chunk 2 is "-3", etc.
func GetChunkFileSuffix(chunkIndex int) string {
	if chunkIndex <= 0 {
		return ""
	}
	return fmt.Sprintf("-%d", chunkIndex+1)
}

// GetChunkPath returns the full path for a chunk file.
// basePath is the path for chunk 0 (no suffix).
func GetChunkPath(basePath string, chunkIndex int) string {
	return basePath + GetChunkFileSuffix(chunkIndex)
}

// ParseChunkFilename parses a filename (without path) that may be a chunk file.
// Returns the base instance hash and chunk index.
// For non-chunked files (no suffix), returns the filename as-is and chunkIndex 0.
// For chunk files like "deadbeef...-2", returns the base hash and chunkIndex 1.
// Returns ok=false if the filename doesn't match expected patterns.
func ParseChunkFilename(filename string) (baseHash InstanceHash, chunkIndex int, ok bool) {
	// Check for chunk suffix pattern: "-N" where N >= 2
	if idx := strings.LastIndex(filename, "-"); idx > 0 {
		suffix := filename[idx+1:]
		if n, err := strconv.Atoi(suffix); err == nil && n >= 2 {
			baseHash = InstanceHash(filename[:idx])
			chunkIndex = n - 1 // -2 means chunk index 1, -3 means chunk index 2, etc.
			ok = true
			return
		}
	}
	// No valid suffix - treat as base file (chunk 0)
	baseHash = InstanceHash(filename)
	chunkIndex = 0
	ok = true
	return
}

// ChunkInfo holds computed information about a chunk.
type ChunkInfo struct {
	Index       int       // 0-based chunk index
	StorageID   StorageID // Storage directory for this chunk
	StartOffset int64     // Content byte offset where this chunk starts
	EndOffset   int64     // Content byte offset where this chunk ends (inclusive)
	Size        int64     // Size of this chunk in bytes
}

// GetChunkInfo returns information about all chunks for an object.
// chunkLocations should be the ChunkLocations from CacheMetadata (may be nil/empty for non-chunked objects).
// baseStorageID is the StorageID from CacheMetadata (where chunk 0 is stored).
func GetChunkInfo(contentLength int64, chunkSizeCode ChunkSizeCode, chunkLocations []ChunkLocation, baseStorageID StorageID) []ChunkInfo {
	count := CalculateChunkCount(contentLength, chunkSizeCode)
	infos := make([]ChunkInfo, count)

	for i := 0; i < count; i++ {
		start, end := GetChunkRange(contentLength, chunkSizeCode, i)

		// Determine storage ID: chunk 0 uses baseStorageID, others use ChunkLocations
		storageID := baseStorageID
		if i > 0 && len(chunkLocations) >= i {
			storageID = chunkLocations[i-1].StorageID
		}

		infos[i] = ChunkInfo{
			Index:       i,
			StorageID:   storageID,
			StartOffset: start,
			EndOffset:   end,
			Size:        end - start + 1,
		}
	}

	return infos
}

// ValidateChunkLocations checks that ChunkLocations has the correct number of entries.
// Returns nil if valid, error otherwise.
func ValidateChunkLocations(contentLength int64, chunkSizeCode ChunkSizeCode, locations []ChunkLocation) error {
	if chunkSizeCode == ChunkingDisabled {
		if len(locations) > 0 {
			return fmt.Errorf("chunk locations present but chunking is disabled")
		}
		return nil
	}

	chunkCount := CalculateChunkCount(contentLength, chunkSizeCode)
	expectedLocations := chunkCount - 1 // chunk 0 is in StorageID, not ChunkLocations

	if len(locations) != expectedLocations {
		return fmt.Errorf("expected %d chunk locations, got %d", expectedLocations, len(locations))
	}

	return nil
}

// BlocksInChunk returns the range of blocks (startBlock, endBlock inclusive) that
// belong to a specific chunk.
func BlocksInChunk(contentLength int64, chunkSizeCode ChunkSizeCode, chunkIndex int) (startBlock, endBlock uint32) {
	chunkStart, chunkEnd := GetChunkRange(contentLength, chunkSizeCode, chunkIndex)
	if chunkEnd < 0 {
		// Invalid chunk
		return 0, 0
	}

	startBlock = ContentOffsetToBlock(chunkStart)
	endBlock = ContentOffsetToBlock(chunkEnd)
	return startBlock, endBlock
}

// ChunkContainsBlock returns true if the specified block belongs to the given chunk.
func ChunkContainsBlock(contentLength int64, chunkSizeCode ChunkSizeCode, chunkIndex int, blockNum uint32) bool {
	chunkStart, chunkEnd := GetChunkRange(contentLength, chunkSizeCode, chunkIndex)
	if chunkEnd < 0 {
		return false
	}

	blockContentStart := int64(blockNum) * BlockDataSize
	blockContentEnd := blockContentStart + BlockDataSize - 1
	if blockContentEnd >= contentLength {
		blockContentEnd = contentLength - 1
	}

	// Block is in chunk if any part of it overlaps
	return blockContentStart <= chunkEnd && blockContentEnd >= chunkStart
}

// ParseChunkSize parses a human-readable chunk size string (e.g., "64MB", "2GB")
// and returns the corresponding ChunkSizeCode.
func ParseChunkSize(s string) (ChunkSizeCode, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "0" || strings.EqualFold(s, "disabled") {
		return ChunkingDisabled, nil
	}

	var multiplier uint64 = 1
	var numStr string

	switch {
	case strings.HasSuffix(s, "GB"):
		multiplier = gb
		numStr = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "G"):
		multiplier = gb
		numStr = strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "MB"):
		multiplier = mb
		numStr = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "M"):
		multiplier = mb
		numStr = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "B"):
		numStr = strings.TrimSuffix(s, "B")
	default:
		numStr = s
	}

	numStr = strings.TrimSpace(numStr)
	val, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return ChunkingDisabled, fmt.Errorf("invalid chunk size format: %s", s)
	}

	bytes := val * multiplier
	if bytes == 0 {
		return ChunkingDisabled, nil
	}

	return BytesToChunkSizeCode(bytes), nil
}

// FormatChunkSize returns a human-readable string for a ChunkSizeCode.
func FormatChunkSize(code ChunkSizeCode) string {
	if code == ChunkingDisabled {
		return "disabled"
	}

	bytes := ChunkSizeCodeToBytes(code)
	if bytes >= gb && bytes%gb == 0 {
		return fmt.Sprintf("%dGB", bytes/gb)
	}
	if bytes >= mb && bytes%mb == 0 {
		return fmt.Sprintf("%dMB", bytes/mb)
	}
	return fmt.Sprintf("%d", bytes)
}

// OffsetInChunk converts an absolute content offset to an offset within a chunk.
// Returns the offset relative to the start of the chunk.
func OffsetInChunk(contentOffset int64, chunkSizeCode ChunkSizeCode) int64 {
	if chunkSizeCode == ChunkingDisabled {
		return contentOffset
	}

	chunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	if chunkSize == 0 {
		return contentOffset
	}

	return contentOffset % chunkSize
}

// ChunkContentLength returns the content length for a specific chunk.
// This is the size of data within the chunk (not the encrypted file size).
func ChunkContentLength(totalContentLength int64, chunkSizeCode ChunkSizeCode, chunkIndex int) int64 {
	start, end := GetChunkRange(totalContentLength, chunkSizeCode, chunkIndex)
	if end < 0 || end < start {
		return 0
	}
	return end - start + 1
}
