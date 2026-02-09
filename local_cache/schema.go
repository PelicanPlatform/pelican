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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
)

// Key prefixes for BadgerDB
const (
	// PrefixMeta stores CacheMetadata (headers, validation info, storage mode)
	PrefixMeta = "m:"
	// PrefixState stores Roaring Bitmap tracking downloaded blocks
	PrefixState = "s:"
	// PrefixInline stores encrypted inline data for small objects (< 4KB)
	PrefixInline = "d:"
	// PrefixLRU stores sorted index for eviction candidates: l:<storage_id>:<namespace_id>:<ts>:<instance_hash>
	PrefixLRU = "l:"
	// PrefixUsage stores total bytes used per storage+namespace: u:<storage_id>:<namespace_id>
	PrefixUsage = "u:"
	// PrefixDiskMap stores the mapping of disk IDs to directories
	PrefixDiskMap = "di:"
	// PrefixPurgeFirst stores instance hashes marked for priority eviction
	PrefixPurgeFirst = "pf:"
	// PrefixETag stores the latest ETag for an object: e:<object_hash> -> etag
	PrefixETag = "e:"
	// PrefixNamespace stores namespace prefix -> ID mappings: n:<prefix> -> uint32
	PrefixNamespace = "n:"
)

// Storage mode constants
const (
	// StorageModeInline indicates the object data is stored directly in BadgerDB
	StorageModeInline uint8 = 0
	// StorageModeDisk indicates the object data is stored on disk
	StorageModeDisk uint8 = 1
	// Additional disk modes can be added for multiple storage directories
	// StorageModeDiskB uint8 = 2
	// StorageModeDiskC uint8 = 3
)

// Storage ID constants
const (
	// StorageIDInline is the storage ID for inline data stored in BadgerDB
	StorageIDInline uint8 = 0
	// StorageIDPrimaryDisk is the storage ID for the primary disk storage location
	StorageIDPrimaryDisk uint8 = 1
	// Storage IDs 2-255 are reserved for additional disk storage paths
	// Configured via LocalCache.DataLocations parameter
)

// Block size constants for encryption and storage
const (
	// BlockDataSize is the size of data in each encrypted block (before encryption)
	BlockDataSize = 4080
	// AuthTagSize is the size of the AES-GCM authentication tag
	AuthTagSize = 16
	// BlockTotalSize is the total size of an encrypted block on disk
	BlockTotalSize = BlockDataSize + AuthTagSize
	// InlineThreshold is the max size for inline storage (< 4KB stored in DB)
	InlineThreshold = 4096
	// NonceSize is the standard size for AES-GCM nonce
	NonceSize = 12
	// KeySize is the size for AES-256 key
	KeySize = 32
)

// Cache-Control flag bits
const (
	CCFlagNoStore       uint8 = 0x01 // no-store
	CCFlagNoCache       uint8 = 0x02 // no-cache
	CCFlagPrivate       uint8 = 0x04 // private
	CCFlagMustRevalidate uint8 = 0x08 // must-revalidate
)

// ChecksumType identifies the type of checksum
type ChecksumType uint8

const (
	ChecksumMD5    ChecksumType = 0
	ChecksumSHA1   ChecksumType = 1
	ChecksumSHA256 ChecksumType = 2
	ChecksumCRC32  ChecksumType = 3
)

// Checksum holds a checksum type and its value
type Checksum struct {
	Type            ChecksumType `msgpack:"t"`
	Value           []byte       `msgpack:"v"`
	OriginVerified  bool         `msgpack:"ov"`          // True if checksum came from origin
	VerifyAttempted bool         `msgpack:"va,omitempty"` // True if we tried to get origin checksum
}

// CacheMetadata stores all metadata about a cached object
// Serialized using MessagePack for efficiency
type CacheMetadata struct {
	// Validation fields
	ETag          string     `msgpack:"etag"`           // HTTP ETag header
	LastModified  time.Time  `msgpack:"lm"`             // HTTP Last-Modified header
	Expires       time.Time  `msgpack:"exp"`            // HTTP Expires header
	LastValidated time.Time  `msgpack:"lv"`             // When we last validated with origin
	Completed     time.Time  `msgpack:"c"`              // When download was completed
	Checksums     []Checksum `msgpack:"ck,omitempty"`   // Object checksums

	// Identification fields
	ContentType   string   `msgpack:"ct"`            // MIME type
	ContentLength int64    `msgpack:"cl"`            // Total object size in bytes
	VaryHeaders   []string `msgpack:"vh,omitempty"`  // Headers that affect caching
	SourceURL     string   `msgpack:"url,omitempty"` // Original URL including federation
	ObjectHash    string   `msgpack:"oh"`            // Hash of the URL (for ETag table cleanup)

	// Cache-Control directives (efficient packed representation)
	CCFlags uint8 `msgpack:"ccf,omitempty"` // Bitset: 0x01=no-store, 0x02=no-cache, 0x04=private, 0x08=must-revalidate
	CCMaxAge int32 `msgpack:"ccma,omitempty"` // Cache-Control: max-age/s-maxage (seconds, 0 = not set, uses min if both specified)

	// Storage fields
	StorageMode uint8  `msgpack:"mode"` // 0=Inline, 1=Disk
	StorageID   uint8  `msgpack:"sid"`  // Storage ID: 0=inline, 1+=disk path ID (see DiskMapping)
	DataKey     []byte `msgpack:"key"`  // Encrypted DEK (Data Encryption Key)
	Nonce       []byte `msgpack:"iv"`   // Base IV/nonce for file encryption

	// Namespace and storage tracking for fairness-aware eviction
	NamespaceID uint32 `msgpack:"ns"` // ID of the namespace prefix
	// Usage is tracked per (StorageID, NamespaceID) pair for multi-storage fairness

	// LRU tracking
	LastAccessTime time.Time `msgpack:"la"` // Last access time for LRU index
}

// SetCacheControl parses a Cache-Control header and stores the directives efficiently
func (m *CacheMetadata) SetCacheControl(header string) {
	if header == "" {
		return
	}
	cd := ParseCacheControl(header)

	// Pack boolean flags into bitset
	m.CCFlags = 0
	if cd.NoStore {
		m.CCFlags |= CCFlagNoStore
	}
	if cd.NoCache {
		m.CCFlags |= CCFlagNoCache
	}
	if cd.Private {
		m.CCFlags |= CCFlagPrivate
	}
	if cd.MustRevalidate {
		m.CCFlags |= CCFlagMustRevalidate
	}

	// Combine max-age and s-maxage: use minimum if both present, otherwise use whichever is set
	if cd.MaxAgeSet && cd.SMaxAgeSet {
		// Both set - use minimum
		minAge := cd.MaxAge
		if cd.SMaxAge < cd.MaxAge {
			minAge = cd.SMaxAge
		}
		if minAge >= 0 && minAge <= time.Duration(0x7FFFFFFF)*time.Second {
			m.CCMaxAge = int32(minAge / time.Second)
		}
	} else if cd.SMaxAgeSet {
		// Only s-maxage set
		if cd.SMaxAge >= 0 && cd.SMaxAge <= time.Duration(0x7FFFFFFF)*time.Second {
			m.CCMaxAge = int32(cd.SMaxAge / time.Second)
		}
	} else if cd.MaxAgeSet {
		// Only max-age set
		if cd.MaxAge >= 0 && cd.MaxAge <= time.Duration(0x7FFFFFFF)*time.Second {
			m.CCMaxAge = int32(cd.MaxAge / time.Second)
		}
	}
}

// GetCacheDirectives returns the parsed cache directives
func (m *CacheMetadata) GetCacheDirectives() CacheDirectives {
	cd := CacheDirectives{
		NoStore:        (m.CCFlags & CCFlagNoStore) != 0,
		NoCache:        (m.CCFlags & CCFlagNoCache) != 0,
		Private:        (m.CCFlags & CCFlagPrivate) != 0,
		MustRevalidate: (m.CCFlags & CCFlagMustRevalidate) != 0,
	}
	if m.CCMaxAge > 0 {
		cd.MaxAge = time.Duration(m.CCMaxAge) * time.Second
		cd.MaxAgeSet = true
		// For shared cache, s-maxage has same value (we stored the minimum/only one)
		cd.SMaxAge = cd.MaxAge
		cd.SMaxAgeSet = true
	}
	return cd
}

// GetCacheControlHeader reconstructs the Cache-Control header string for HTTP responses
func (m *CacheMetadata) GetCacheControlHeader() string {
	if m.CCFlags == 0 && m.CCMaxAge == 0 {
		return "" // No cache-control directives set
	}

	var parts []string
	if (m.CCFlags & CCFlagNoStore) != 0 {
		parts = append(parts, "no-store")
	}
	if (m.CCFlags & CCFlagNoCache) != 0 {
		parts = append(parts, "no-cache")
	}
	if (m.CCFlags & CCFlagPrivate) != 0 {
		parts = append(parts, "private")
	}
	if (m.CCFlags & CCFlagMustRevalidate) != 0 {
		parts = append(parts, "must-revalidate")
	}
	if m.CCMaxAge > 0 {
		// Return both s-maxage and max-age with same value for compatibility
		parts = append(parts, fmt.Sprintf("s-maxage=%d", m.CCMaxAge))
		parts = append(parts, fmt.Sprintf("max-age=%d", m.CCMaxAge))
	}
	return strings.Join(parts, ", ")
}

// DiskMapping stores the mapping of disk IDs to directory paths
type DiskMapping struct {
	ID        uint8  `msgpack:"id"`
	Directory string `msgpack:"dir"`
}

// MasterKeyFile represents the encrypted master key file format
// The master key is encrypted with each issuer private key
type MasterKeyFile struct {
	// Keys maps public key fingerprint to encrypted master key
	Keys map[string][]byte `json:"keys"`
}

// ComputeObjectHash computes the SHA256 hash of a normalized URL.
// This identifies the logical object (URL) regardless of version/ETag.
func ComputeObjectHash(pelicanURL string) string {
	normalized := normalizeURL(pelicanURL)
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// ComputeInstanceHash computes the SHA256 hash combining ETag and objectHash.
// This identifies a specific version of an object.
// If etag is empty, uses empty string (for objects without ETag support).
func ComputeInstanceHash(etag, objectHash string) string {
	combined := etag + ":" + objectHash
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// normalizeURL normalizes a pelican URL for consistent hashing
func normalizeURL(pelicanURL string) string {
	// Parse the URL
	u, err := url.Parse(pelicanURL)
	if err != nil {
		// If parsing fails, just clean the path
		return path.Clean(pelicanURL)
	}

	// Rebuild with normalized components
	normalized := u.Scheme + "://" + u.Host + path.Clean(u.Path)
	return strings.ToLower(normalized)
}

// GetInstanceStoragePath returns the 2-level directory path for storing a file
// Given hash "42561abfe18ba...", returns "42/56/1abfe18ba..."
func GetInstanceStoragePath(hash string) string {
	if len(hash) < 4 {
		return hash
	}
	return fmt.Sprintf("%s/%s/%s", hash[0:2], hash[2:4], hash[4:])
}

// MetaKey returns the BadgerDB key for metadata
func MetaKey(instanceHash string) []byte {
	return []byte(PrefixMeta + instanceHash)
}

// StateKey returns the BadgerDB key for block state bitmap
func StateKey(instanceHash string) []byte {
	return []byte(PrefixState + instanceHash)
}

// InlineKey returns the BadgerDB key for inline data
func InlineKey(instanceHash string) []byte {
	return []byte(PrefixInline + instanceHash)
}

// ETagKey returns the BadgerDB key for ETag lookup
// Maps objectHash -> latest ETag for that object
func ETagKey(objectHash string) []byte {
	return []byte(PrefixETag + objectHash)
}

// NamespaceKey returns the BadgerDB key for a namespace prefix mapping
func NamespaceKey(prefix string) []byte {
	return []byte(PrefixNamespace + prefix)
}

// LRUKey returns the BadgerDB key for LRU tracking
// Format: l:<storage_id>:<namespace_id>:<timestamp_ns>:<instance_hash>
func LRUKey(storageID uint8, namespaceID uint32, timestamp time.Time, instanceHash string) []byte {
	return []byte(fmt.Sprintf("%s%d:%d:%019d:%s", PrefixLRU, storageID, namespaceID, timestamp.UnixNano(), instanceHash))
}

// ParseLRUKey parses an LRU key and returns storageID, namespaceID, timestamp, and instanceHash
func ParseLRUKey(key []byte) (storageID uint8, namespaceID uint32, timestamp time.Time, instanceHash string, err error) {
	keyStr := string(key)
	if !strings.HasPrefix(keyStr, PrefixLRU) {
		err = fmt.Errorf("invalid LRU key prefix: %s", keyStr)
		return
	}
	keyStr = keyStr[len(PrefixLRU):]

	parts := strings.SplitN(keyStr, ":", 4)
	if len(parts) != 4 {
		err = fmt.Errorf("invalid LRU key format: %s", keyStr)
		return
	}

	var sid, nid uint32
	var n int
	_, err = fmt.Sscanf(parts[0], "%d", &sid)
	if err != nil {
		return
	}
	storageID = uint8(sid)

	_, err = fmt.Sscanf(parts[1], "%d", &nid)
	if err != nil {
		return
	}
	namespaceID = nid

	var tsNano int64
	n, err = fmt.Sscanf(parts[2], "%d", &tsNano)
	if err != nil || n != 1 {
		err = fmt.Errorf("invalid timestamp in LRU key: %s", parts[2])
		return
	}
	timestamp = time.Unix(0, tsNano)

	instanceHash = parts[3]
	return
}

// UsageKey returns the BadgerDB key for namespace usage counter per storage
// Format: u:<storage_id>:<namespace_id>
func UsageKey(storageID uint8, namespaceID uint32) []byte {
	return []byte(fmt.Sprintf("%s%d:%d", PrefixUsage, storageID, namespaceID))
}

// ParseUsageKey extracts the storage ID and namespace ID from a usage key
func ParseUsageKey(key []byte) (storageID uint8, namespaceID uint32, err error) {
	keyStr := string(key)
	if !strings.HasPrefix(keyStr, PrefixUsage) {
		err = fmt.Errorf("invalid usage key prefix: %s", keyStr)
		return
	}
	var sid, nid uint32
	_, err = fmt.Sscanf(keyStr[len(PrefixUsage):], "%d:%d", &sid, &nid)
	if err != nil {
		return
	}
	storageID = uint8(sid)
	namespaceID = nid
	return
}

// CalculateBlockCount returns the number of blocks needed for a given content length
func CalculateBlockCount(contentLength int64) uint32 {
	if contentLength <= 0 {
		return 0
	}
	return uint32((contentLength + BlockDataSize - 1) / BlockDataSize)
}

// BlockOffset returns the byte offset in the file for a given block number
func BlockOffset(blockNum uint32) int64 {
	return int64(blockNum) * BlockTotalSize
}

// ContentOffsetToBlock converts a content byte offset to a block number
func ContentOffsetToBlock(contentOffset int64) uint32 {
	if contentOffset < 0 {
		return 0
	}
	return uint32(contentOffset / BlockDataSize)
}

// ContentOffsetWithinBlock returns the offset within a block for a content offset
func ContentOffsetWithinBlock(contentOffset int64) int {
	return int(contentOffset % BlockDataSize)
}

// PurgeFirstKey returns the BadgerDB key for purge first tracking
func PurgeFirstKey(instanceHash string) []byte {
	return []byte(PrefixPurgeFirst + instanceHash)
}
