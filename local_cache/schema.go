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

// Storage ID constants.
// The StorageID field in CacheMetadata doubles as the storage-mode indicator:
// 0 means inline (data lives in BadgerDB), 1–255 mean disk-backed storage in
// the directory mapped to that ID.
const (
	// StorageIDInline is the storage ID for inline data stored in BadgerDB
	StorageIDInline uint8 = 0
	// StorageIDFirstDisk is the storage ID for the first configured disk directory.
	// Additional directories use StorageIDFirstDisk+1, +2, etc.
	StorageIDFirstDisk uint8 = 1
)

// StorageDirConfig describes one disk-backed storage directory.
// Multiple directories can be configured to spread data across devices;
// each directory has its own maximum size and optional watermark overrides.
type StorageDirConfig struct {
	// Path is the directory that will hold an "objects/" subdirectory
	// and, for the first directory, the database.
	Path string
	// MaxSize is the maximum number of bytes stored on this directory.
	// If 0, auto-detected from the filesystem at startup.
	MaxSize uint64
	// HighWaterMarkPercentage overrides the global high-water mark for this
	// directory.  0 means use the global default.
	HighWaterMarkPercentage int
	// LowWaterMarkPercentage overrides the global low-water mark for this
	// directory.  0 means use the global default.
	LowWaterMarkPercentage int
}

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

// Cache-Control flag bits — canonical definitions are in cache_control.go
// (ccNoStore, ccNoCache, ccPrivate, ccMustRevalidate).  These aliases are
// kept for any callers that reference the CCFlag* names directly.
const (
	CCFlagNoStore        = ccNoStore
	CCFlagNoCache        = ccNoCache
	CCFlagPrivate        = ccPrivate
	CCFlagMustRevalidate = ccMustRevalidate
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
	OriginVerified  bool         `msgpack:"ov"`           // True if checksum came from origin
	VerifyAttempted bool         `msgpack:"va,omitempty"` // True if we tried to get origin checksum
}

// CacheMetadata stores all metadata about a cached object
// Serialized using MessagePack for efficiency
type CacheMetadata struct {
	// Validation fields
	ETag          string     `msgpack:"etag"`         // HTTP ETag header
	LastModified  time.Time  `msgpack:"lm"`           // HTTP Last-Modified header
	Expires       time.Time  `msgpack:"exp"`          // HTTP Expires header
	LastValidated time.Time  `msgpack:"lv"`           // When we last validated with origin
	Completed     time.Time  `msgpack:"c"`            // When download was completed
	Checksums     []Checksum `msgpack:"ck,omitempty"` // Object checksums

	// Identification fields
	ContentType   string   `msgpack:"ct"`            // MIME type
	ContentLength int64    `msgpack:"cl"`            // Total object size in bytes
	VaryHeaders   []string `msgpack:"vh,omitempty"`  // Headers that affect caching
	SourceURL     string   `msgpack:"url,omitempty"` // Original URL including federation
	ObjectHash    string   `msgpack:"oh"`            // Hash of the URL (for ETag table cleanup)

	// Cache-Control directives (efficient packed representation)
	CCFlags  uint8 `msgpack:"ccf,omitempty"`  // Bitset: 0x01=no-store, 0x02=no-cache, 0x04=private, 0x08=must-revalidate
	CCMaxAge int32 `msgpack:"ccma,omitempty"` // Merged max-age/s-maxage freshness lifetime (seconds, 0 = not set, max of both if both specified)

	// Storage fields.
	// StorageID encodes both location type and directory identity:
	//   0         = inline (data stored directly in BadgerDB)
	//   1 .. 255  = disk-backed (directory identified by this ID)
	StorageID uint8  `msgpack:"sid"`
	DataKey   []byte `msgpack:"key"` // Encrypted DEK (Data Encryption Key)
	Nonce     []byte `msgpack:"iv"`  // Base IV/nonce for file encryption

	// Namespace and storage tracking for fairness-aware eviction
	NamespaceID uint32 `msgpack:"ns"` // ID of the namespace prefix
	// Usage is tracked per (StorageID, NamespaceID) pair for multi-storage fairness

	// LRU tracking
	LastAccessTime time.Time `msgpack:"la"` // Last access time for LRU index
}

// IsInline returns true when the object data is stored directly in BadgerDB.
func (m *CacheMetadata) IsInline() bool { return m.StorageID == StorageIDInline }

// IsDisk returns true when the object data is stored on disk.
func (m *CacheMetadata) IsDisk() bool { return m.StorageID != StorageIDInline }

// SetCacheControl parses a Cache-Control header and stores the directives efficiently
func (m *CacheMetadata) SetCacheControl(header string) {
	if header == "" {
		return
	}
	cd := ParseCacheControl(header)

	// The storage flags use the same bit layout as CacheDirectives.flags,
	// but only the lower 4 bits (the directive booleans).  ccMaxAgeSet
	// (0x10) is not persisted in CCFlags because CCMaxAge > 0 already
	// implies "set".
	m.CCFlags = cd.Flags() & 0x0F

	if cd.MaxAgeSet() {
		age := cd.MaxAge()
		if age >= 0 && age <= time.Duration(0x7FFFFFFF)*time.Second {
			m.CCMaxAge = int32(age / time.Second)
		}
	}
}

// GetCacheDirectives returns the parsed cache directives
func (m *CacheMetadata) GetCacheDirectives() CacheDirectives {
	cd := CacheDirectives{
		flags: m.CCFlags & 0x0F, // restore boolean flags
	}
	if m.CCMaxAge > 0 {
		cd.maxAge = time.Duration(m.CCMaxAge) * time.Second
		cd.flags |= ccMaxAgeSet
	}
	return cd
}

// GetCacheControlHeader reconstructs the Cache-Control header string for HTTP responses.
// It returns the origin's directives verbatim when present; when the origin did not
// specify any Cache-Control, it returns "" (callers should use ResponseCacheControl
// instead to get a header that reflects the default policy).
func (m *CacheMetadata) GetCacheControlHeader() string {
	if m.CCFlags == 0 && m.CCMaxAge == 0 {
		return "" // No cache-control directives set
	}

	var parts []string
	if m.CCFlags&ccNoStore != 0 {
		parts = append(parts, "no-store")
	}
	if m.CCFlags&ccNoCache != 0 {
		parts = append(parts, "no-cache")
	}
	if m.CCFlags&ccPrivate != 0 {
		parts = append(parts, "private")
	}
	if m.CCFlags&ccMustRevalidate != 0 {
		parts = append(parts, "must-revalidate")
	}
	if m.CCMaxAge > 0 {
		parts = append(parts, fmt.Sprintf("max-age=%d", m.CCMaxAge))
	}
	return strings.Join(parts, ", ")
}

// ResponseCacheControl returns the Cache-Control header value the cache should
// send to downstream clients.  When the origin specified directives, those are
// forwarded.  When it did not, the cache advertises the remaining freshness
// lifetime (derived from LocalCache_DefaultMaxAge + jitter) as max-age so that
// downstream clients can cache the response without re-contacting the cache
// until revalidation is due.
func (m *CacheMetadata) ResponseCacheControl() string {
	// If the origin specified Cache-Control, build the response header.
	if cc := m.GetCacheControlHeader(); cc != "" {
		// When the origin sets max-age, also advertise s-maxage with the
		// same value so that downstream shared caches honour the
		// directive (RFC 7234 §5.2.2.9).  Skip if s-maxage is already
		// present or the response should not be stored.
		if m.CCMaxAge > 0 && m.CCFlags&ccNoStore == 0 {
			if !strings.Contains(cc, "s-maxage") {
				cc = fmt.Sprintf("s-maxage=%d, %s", m.CCMaxAge, cc)
			}
		}
		return cc
	}

	// No origin directives — compute remaining freshness from the default
	// policy and expose it as max-age.
	remaining := RemainingFreshness(m.LastValidated)
	seconds := int64(remaining / time.Second)
	if seconds <= 0 {
		// Object is stale (or just about to be); tell clients to revalidate.
		return "no-cache, must-revalidate"
	}
	return fmt.Sprintf("max-age=%d", seconds)
}

// DiskMapping stores the mapping of a storage ID to its directory path
// and UUID.  The UUID file is dropped in the directory root so that
// directories can be remounted at different paths and re-associated.
type DiskMapping struct {
	ID        uint8  `msgpack:"id"`
	UUID      string `msgpack:"uuid"`
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
// Given hash "42561abfe18be...", returns "42/56/1abfe18be..."
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
