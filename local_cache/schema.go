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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

// ObjectHash is an HMAC-SHA-256 digest that identifies a logical object
// (URL) regardless of version or ETag.  Using a dedicated type prevents
// accidental confusion with InstanceHash or arbitrary strings.
type ObjectHash string

// InstanceHash is an HMAC-SHA-256 digest that identifies a specific
// version (ETag) of an object.  Using a dedicated type prevents
// accidental confusion with ObjectHash or arbitrary strings.
type InstanceHash string

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
	// KeySalt is the single DB key that stores the random salt used when
	// hashing object/instance names.  The salt prevents an attacker with
	// DB access from correlating hashes with known URLs.
	KeySalt = "_salt"
)

// StorageID identifies a storage location.  0 means inline (data in BadgerDB),
// 1–255 mean disk-backed storage in the directory mapped to that ID.
// Using a dedicated type prevents accidental confusion with NamespaceID or
// arbitrary uint8 values.
type StorageID uint8

// NamespaceID identifies a namespace prefix.  Each distinct prefix registered
// in the cache is assigned a monotonically increasing ID for efficient
// storage and lookup.  Using a dedicated type prevents accidental confusion
// with StorageID or arbitrary uint32 values.
type NamespaceID uint32

const (
	// StorageIDInline is the storage ID for inline data stored in BadgerDB
	StorageIDInline StorageID = 0
	// StorageIDFirstDisk is the storage ID for the first configured disk directory.
	// Additional directories use StorageIDFirstDisk+1, +2, etc.
	StorageIDFirstDisk StorageID = 1
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

// ParseStorageDirsConfig reads the LocalCache.StorageDirs setting from Viper
// and returns parsed StorageDirConfig values.  It accepts two formats for
// backward compatibility:
//
//  1. A list of strings (paths only):
//     LocalCache:
//     StorageDirs:
//     - /mnt/cache1
//     - /mnt/cache2
//
//  2. A list of objects with per-directory configuration:
//     LocalCache:
//     StorageDirs:
//     - Path: /mnt/cache1
//     MaxSize: 500GB
//     HighWaterMarkPercentage: 95
//     LowWaterMarkPercentage: 85
//     - Path: /mnt/cache2
//     MaxSize: 2TB
//
// Returns nil (not an error) when the key is unset or empty.
func ParseStorageDirsConfig() ([]StorageDirConfig, error) {
	raw := param.LocalCache_StorageDirs.GetRaw()
	if raw == nil {
		return nil, nil
	}

	switch v := raw.(type) {
	case []interface{}:
		if len(v) == 0 {
			return nil, nil
		}
		configs := make([]StorageDirConfig, 0, len(v))
		for i, elem := range v {
			switch e := elem.(type) {
			case string:
				// Plain string path (backward-compat format)
				if e == "" {
					return nil, fmt.Errorf("LocalCache.StorageDirs[%d]: empty path", i)
				}
				configs = append(configs, StorageDirConfig{Path: e})
			case map[string]interface{}:
				// Structured entry
				cfg, err := parseStorageDirEntry(i, e)
				if err != nil {
					return nil, err
				}
				configs = append(configs, cfg)
			case map[interface{}]interface{}:
				// YAML sometimes produces map[interface{}]interface{}
				converted := make(map[string]interface{}, len(e))
				for k, val := range e {
					converted[fmt.Sprint(k)] = val
				}
				cfg, err := parseStorageDirEntry(i, converted)
				if err != nil {
					return nil, err
				}
				configs = append(configs, cfg)
			default:
				return nil, fmt.Errorf("LocalCache.StorageDirs[%d]: unsupported type %T", i, elem)
			}
		}
		return configs, nil
	case []string:
		// Viper sometimes resolves stringSlice directly
		if len(v) == 0 {
			return nil, nil
		}
		configs := make([]StorageDirConfig, len(v))
		for i, p := range v {
			if p == "" {
				return nil, fmt.Errorf("LocalCache.StorageDirs[%d]: empty path", i)
			}
			configs[i] = StorageDirConfig{Path: p}
		}
		return configs, nil
	default:
		return nil, fmt.Errorf("LocalCache.StorageDirs: unsupported type %T; expected list of paths or objects", raw)
	}
}

// parseStorageDirEntry converts a map entry into a StorageDirConfig.
func parseStorageDirEntry(idx int, m map[string]interface{}) (StorageDirConfig, error) {
	var cfg StorageDirConfig

	// Path (required)
	switch p := m["Path"].(type) {
	case string:
		cfg.Path = p
	default:
		// Try lowercase key as fallback
		if p2, ok := m["path"].(string); ok {
			cfg.Path = p2
		}
	}
	if cfg.Path == "" {
		return cfg, fmt.Errorf("LocalCache.StorageDirs[%d]: missing or empty Path", idx)
	}

	// MaxSize (optional, string like "500GB" or number of bytes)
	if _, ok := m["MaxSize"]; !ok {
		if v, ok := m["maxsize"]; ok {
			m["MaxSize"] = v
		}
	}
	if v, ok := m["MaxSize"]; ok && v != nil {
		switch s := v.(type) {
		case string:
			if s != "" && s != "0" {
				n, err := utils.ParseBytes(s)
				if err != nil {
					return cfg, fmt.Errorf("LocalCache.StorageDirs[%d].MaxSize: %w", idx, err)
				}
				cfg.MaxSize = n
			}
		case int:
			cfg.MaxSize = uint64(s)
		case int64:
			cfg.MaxSize = uint64(s)
		case float64:
			cfg.MaxSize = uint64(s)
		}
	}

	// HighWaterMarkPercentage (optional)
	if _, ok := m["HighWaterMarkPercentage"]; !ok {
		if v, ok := m["highwatermarkpercentage"]; ok {
			m["HighWaterMarkPercentage"] = v
		}
	}
	if v, ok := m["HighWaterMarkPercentage"]; ok && v != nil {
		switch n := v.(type) {
		case int:
			cfg.HighWaterMarkPercentage = n
		case int64:
			cfg.HighWaterMarkPercentage = int(n)
		case float64:
			cfg.HighWaterMarkPercentage = int(n)
		}
	}

	// LowWaterMarkPercentage (optional)
	if _, ok := m["LowWaterMarkPercentage"]; !ok {
		if v, ok := m["lowwatermarkpercentage"]; ok {
			m["LowWaterMarkPercentage"] = v
		}
	}
	if v, ok := m["LowWaterMarkPercentage"]; ok && v != nil {
		switch n := v.(type) {
		case int:
			cfg.LowWaterMarkPercentage = n
		case int64:
			cfg.LowWaterMarkPercentage = int(n)
		case float64:
			cfg.LowWaterMarkPercentage = int(n)
		}
	}

	return cfg, nil
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
	ChecksumCRC32C ChecksumType = 4
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
//
// # Merge semantics (see CacheDB.MergeMetadata)
//
// Fields are classified into groups that govern how concurrent updates
// are reconciled:
//
//   - Max-time: LastModified, LastValidated, LastAccessTime, Expires,
//     Completed — only advance forward (keep the later timestamp).
//   - Additive: Checksums — union by algorithm; prefer OriginVerified.
//   - Last-writer-wins: ContentType, ContentLength, VaryHeaders,
//     CCFlags, CCMaxAge — the incoming value always replaces the old one.
//   - Set-once: ETag, SourceURL, DataKey, StorageID, NamespaceID — may
//     transition from zero-value to set, but changing a non-zero value
//     to a different non-zero value is an error.  ETag is set-once
//     because it is part of the instance hash; a changed ETag produces
//     a different instance.
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

	// Cache-Control directives (efficient packed representation)
	CCFlags  uint8 `msgpack:"ccf,omitempty"`  // Bitset: 0x01=no-store, 0x02=no-cache, 0x04=private, 0x08=must-revalidate
	CCMaxAge int32 `msgpack:"ccma,omitempty"` // Merged max-age/s-maxage freshness lifetime (seconds, 0 = not set, max of both if both specified)

	// Storage fields.
	// StorageID encodes both location type and directory identity:
	//   0         = inline (data stored directly in BadgerDB)
	//   1 .. 255  = disk-backed (directory identified by this ID)
	StorageID StorageID `msgpack:"sid"`
	DataKey   []byte    `msgpack:"key"` // Encrypted DEK (Data Encryption Key)

	// Namespace and storage tracking for fairness-aware eviction
	NamespaceID NamespaceID `msgpack:"ns"` // ID of the namespace prefix
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
	ID        StorageID `msgpack:"id"`
	UUID      string    `msgpack:"uuid"`
	Directory string    `msgpack:"dir"`
}

// MasterKeyFile represents the encrypted master key file format
// The master key is encrypted with each issuer private key
type MasterKeyFile struct {
	// Keys maps public key fingerprint to encrypted master key
	Keys map[string][]byte `json:"keys"`
}

const (
	// SaltSize is the number of random bytes prepended to object/instance
	// names before hashing.  32 bytes (256 bits) provides a comfortable
	// security margin.
	SaltSize = 32
)

// ComputeObjectHash computes HMAC-SHA-256(salt, normalized URL).
// This identifies the logical object (URL) regardless of version/ETag.
// The salt is generated once per cache database and prevents offline
// correlation of hashes with known URLs.
func ComputeObjectHash(salt []byte, pelicanURL string) ObjectHash {
	normalized := normalizeURL(pelicanURL)
	h := hmac.New(sha256.New, salt)
	h.Write([]byte(normalized))
	return ObjectHash(hex.EncodeToString(h.Sum(nil)))
}

// ComputeInstanceHash computes HMAC-SHA-256(salt, etag + ":" + objectHash).
// This identifies a specific version of an object.
// If etag is empty, uses empty string (for objects without ETag support).
func ComputeInstanceHash(salt []byte, etag string, objectHash ObjectHash) InstanceHash {
	h := hmac.New(sha256.New, salt)
	h.Write([]byte(etag))
	h.Write([]byte{':'})
	h.Write([]byte(objectHash))
	return InstanceHash(hex.EncodeToString(h.Sum(nil)))
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
func GetInstanceStoragePath(hash InstanceHash) string {
	if len(hash) < 4 {
		return string(hash)
	}
	return fmt.Sprintf("%s/%s/%s", hash[0:2], hash[2:4], hash[4:])
}

// MetaKey returns the BadgerDB key for metadata
func MetaKey(instanceHash InstanceHash) []byte {
	return []byte(PrefixMeta + string(instanceHash))
}

// StateKey returns the BadgerDB key for block state bitmap
func StateKey(instanceHash InstanceHash) []byte {
	return []byte(PrefixState + string(instanceHash))
}

// InlineKey returns the BadgerDB key for inline data
func InlineKey(instanceHash InstanceHash) []byte {
	return []byte(PrefixInline + string(instanceHash))
}

// ETagKey returns the BadgerDB key for ETag lookup
// Maps objectHash -> latest ETag for that object
func ETagKey(objectHash ObjectHash) []byte {
	return []byte(PrefixETag + string(objectHash))
}

// NamespaceKey returns the BadgerDB key for a namespace prefix mapping
func NamespaceKey(prefix string) []byte {
	return []byte(PrefixNamespace + prefix)
}

// LRUKey returns the BadgerDB key for LRU tracking
// Format: l:<storage_id>:<namespace_id>:<timestamp_ns>:<instance_hash>
func LRUKey(storageID StorageID, namespaceID NamespaceID, timestamp time.Time, instanceHash InstanceHash) []byte {
	return []byte(fmt.Sprintf("%s%d:%d:%019d:%s", PrefixLRU, storageID, namespaceID, timestamp.UnixNano(), string(instanceHash)))
}

// ParseLRUKey parses an LRU key and returns storageID, namespaceID, timestamp, and instanceHash
func ParseLRUKey(key []byte) (storageID StorageID, namespaceID NamespaceID, timestamp time.Time, instanceHash InstanceHash, err error) {
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
	storageID = StorageID(sid)

	_, err = fmt.Sscanf(parts[1], "%d", &nid)
	if err != nil {
		return
	}
	namespaceID = NamespaceID(nid)

	var tsNano int64
	n, err = fmt.Sscanf(parts[2], "%d", &tsNano)
	if err != nil || n != 1 {
		err = fmt.Errorf("invalid timestamp in LRU key: %s", parts[2])
		return
	}
	timestamp = time.Unix(0, tsNano)

	instanceHash = InstanceHash(parts[3])
	return
}

// UsageKey returns the BadgerDB key for namespace usage counter per storage
// Format: u:<storage_id>:<namespace_id>
func UsageKey(storageID StorageID, namespaceID NamespaceID) []byte {
	return []byte(fmt.Sprintf("%s%d:%d", PrefixUsage, storageID, namespaceID))
}

// ParseUsageKey extracts the storage ID and namespace ID from a usage key
func ParseUsageKey(key []byte) (storageID StorageID, namespaceID NamespaceID, err error) {
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
	storageID = StorageID(sid)
	namespaceID = NamespaceID(nid)
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
func PurgeFirstKey(instanceHash InstanceHash) []byte {
	return []byte(PrefixPurgeFirst + string(instanceHash))
}
