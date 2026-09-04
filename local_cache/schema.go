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
	"net"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/pelicanplatform/pelican/cache_control"
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
	// PrefixAppendIntent records that an AppendWriter is part-way through
	// building an object: aw:<instance_hash> -> msgpack(AppendIntent).
	//
	// A streaming append charges capacity for every chunk it allocates but has
	// no LRU entry until it finishes, so an interrupted one would otherwise be
	// invisible to both eviction and the consistency checker -- it has metadata
	// *and* files, so neither half of RunMetadataScan fires.  This marker is
	// the reclamation handle: NewAppendWriter writes it, Finalize and Abort
	// remove it, and anything left over belongs to a writer that did not
	// survive.  See StorageManager.ReclaimAbandonedAppends.
	PrefixAppendIntent = "aw:"
	// The keys below describe the database as a whole rather than any one
	// object.  They are single, underscore-prefixed keys, they are written at
	// open before any consumer touches a record, and none of them is ever
	// evicted; the prefixes above never collide with them.

	// KeySalt is the single DB key that stores the random salt used when
	// hashing object/instance names.  The salt prevents an attacker with
	// DB access from correlating hashes with known URLs.
	KeySalt = "_salt"

	// KeyStoreMode records whether this database belongs to a cache or to a
	// pstore-backed origin.  The two share this key space, so opening one as
	// the other would silently corrupt it; both check this marker on open.
	KeyStoreMode = "_mode"

	// KeySchemaVersion records the layout of the records in this database:
	// which keys exist, how their values are encoded, and how the hashes that
	// name them are derived.  The value is the decimal ASCII form of a
	// SchemaVersion, so a dump of the database reads plainly.
	//
	// KeyStoreMode says *who* owns the database; this says *what layout* the
	// owner wrote.  See CurrentSchemaVersion and CacheDB.ensureSchemaVersion.
	KeySchemaVersion = "_schema"
)

// SchemaVersion identifies one revision of the on-disk layout of a block store
// database (both the cache and the pstore origin backend share it, since they
// share the key space).
type SchemaVersion uint32

const (
	// CurrentSchemaVersion is the layout this binary reads and writes.
	//
	// Bump it whenever a change makes records written by an older binary
	// unreadable — or, worse, silently misread — by a newer one: a new or
	// renamed key prefix, a different value encoding, or a change to how
	// object/instance hashes are derived — normalizeURL, which decides which
	// spellings of a URL name one object, is exactly that sort of key
	// derivation, and a change there has no other way to announce itself.
	// Purely additive changes that older binaries can ignore do not need a
	// bump.
	//
	// Whoever bumps it is responsible for teaching migrateSchema how to bring
	// a database written under every still-supported older version forward.
	CurrentSchemaVersion SchemaVersion = 1
)

// Prefixes reserved by the pstore origin backend (see docs/pstore-design.md).
// A pstore shares this key space but never opens a cache database and vice
// versa (enforced via KeyStoreMode), so the prefixes cannot collide at
// runtime.  They are declared here so that future cache features do not claim
// them.
const (
	// PrefixDirent stores pstore directory entries, keyed by parent path and
	// name: pd:<parent path>\x00<name>
	PrefixDirent = "pd:"
	// PrefixGarbage stores pstore instances and subtrees awaiting reclamation
	PrefixGarbage = "pg:"
)

// StoreMode identifies which subsystem owns a database.
type StoreMode string

const (
	// StoreModeCache marks a database owned by the local cache.
	StoreModeCache StoreMode = "cache"
	// StoreModePStore marks a database owned by a pstore origin backend.
	StoreModePStore StoreMode = "pstore"
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
	return ParseStorageDirsValue(param.LocalCache_StorageDirs.GetRaw(), param.LocalCache_StorageDirs.GetName())
}

// ParseStorageDirsValue parses an already-fetched StorageDirs setting.  It
// exists so another subsystem configuring the same block store -- the pstore
// origin backend, via Origin.PStoreStorageDirs -- accepts exactly the same two
// formats without duplicating the parsing.
//
// name identifies the setting in error messages.
func ParseStorageDirsValue(raw any, name string) ([]StorageDirConfig, error) {
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
					return nil, fmt.Errorf("%s[%d]: empty path", name, i)
				}
				configs = append(configs, StorageDirConfig{Path: e})
			case map[string]interface{}:
				// Structured entry
				cfg, err := parseStorageDirEntry(name, i, e)
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
				cfg, err := parseStorageDirEntry(name, i, converted)
				if err != nil {
					return nil, err
				}
				configs = append(configs, cfg)
			default:
				return nil, fmt.Errorf("%s[%d]: unsupported type %T", name, i, elem)
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
				return nil, fmt.Errorf("%s[%d]: empty path", name, i)
			}
			configs[i] = StorageDirConfig{Path: p}
		}
		return configs, nil
	default:
		return nil, fmt.Errorf("%s: unsupported type %T; expected list of paths or objects", name, raw)
	}
}

// parseStorageDirEntry converts a map entry into a StorageDirConfig.
func parseStorageDirEntry(name string, idx int, m map[string]interface{}) (StorageDirConfig, error) {
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
		return cfg, fmt.Errorf("%s[%d]: missing or empty Path", name, idx)
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
					return cfg, fmt.Errorf("%s[%d].MaxSize: %w", name, idx, err)
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
//     Completed, DataVerified — only advance forward (keep the later
//     timestamp).
//   - Additive: Checksums — union by algorithm; prefer OriginVerified.
//   - Last-writer-wins: ContentType, ContentLength, VaryHeaders,
//     CCFlags, CCMaxAge — the incoming value always replaces the old one.
//   - Set-once: ETag, SourceURL, DataKey, StorageID, NamespaceID,
//     ChunkSizeCode, ChunkLocations — may transition from zero-value to
//     set, but changing a non-zero value to a different non-zero value
//     is an error.  ETag is set-once because it is part of the instance
//     hash; a changed ETag produces a different instance.  Chunking
//     fields are set-once because changing them would invalidate
//     existing chunk files.
type CacheMetadata struct {
	// Validation fields
	ETag          string     `msgpack:"etag"`         // HTTP ETag header
	LastModified  time.Time  `msgpack:"lm"`           // HTTP Last-Modified header
	Expires       time.Time  `msgpack:"exp"`          // HTTP Expires header
	LastValidated time.Time  `msgpack:"lv"`           // When we last validated with origin
	Completed     time.Time  `msgpack:"c"`            // When download was completed
	Checksums     []Checksum `msgpack:"ck,omitempty"` // Object checksums
	DataVerified  time.Time  `msgpack:"dv,omitempty"` // When the on-disk data was last read back and checksum-verified

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
	// For chunked objects, this is the location of chunk 0.
	StorageID StorageID `msgpack:"sid"`
	DataKey   []byte    `msgpack:"key"` // Encrypted DEK (Data Encryption Key)

	// Chunking fields for large objects spread across multiple storage directories.
	// ChunkSizeCode encodes the chunk size (0 = chunking disabled, see chunking.go).
	// ChunkLocations stores the StorageID for chunks 1, 2, ... (chunk 0 uses StorageID above).
	ChunkSizeCode  ChunkSizeCode   `msgpack:"csc,omitempty"` // 0 = disabled, see ChunkSizeCodeToBytes()
	ChunkLocations []ChunkLocation `msgpack:"chl,omitempty"` // Locations for chunks after chunk 0

	// Namespace and storage tracking for fairness-aware eviction
	NamespaceID NamespaceID `msgpack:"ns"` // ID of the namespace prefix
	// Usage is tracked per (StorageID, NamespaceID) pair for multi-storage fairness

	// LRU tracking
	LastAccessTime time.Time `msgpack:"la"` // Last access time for LRU index
}

// IsInline returns true when the object data is stored directly in BadgerDB.
// A chunked object is never inline, even if its base StorageID is still 0 (unallocated).
func (m *CacheMetadata) IsInline() bool {
	return m.StorageID == StorageIDInline && m.ChunkSizeCode == ChunkingDisabled
}

// IsDisk returns true when the object data is (or will be) stored on disk.
// Chunked objects are always disk-based, even when chunk 0 has not yet been allocated.
func (m *CacheMetadata) IsDisk() bool {
	return m.StorageID != StorageIDInline || m.ChunkSizeCode != ChunkingDisabled
}

// IsChunked returns true when the object is stored across multiple chunk files.
func (m *CacheMetadata) IsChunked() bool {
	return m.ChunkSizeCode != ChunkingDisabled
}

// ChunkCount returns the number of chunks for this object.
// Returns 1 for non-chunked objects.
func (m *CacheMetadata) ChunkCount() int {
	return CalculateChunkCount(m.ContentLength, m.ChunkSizeCode)
}

// GetChunkStorageID returns the StorageID for a specific chunk (0-indexed).
// Chunk 0 uses the base StorageID, chunks 1+ use ChunkLocations.
// Returns StorageIDInline (0) for unallocated chunks (lazy allocation).
func (m *CacheMetadata) GetChunkStorageID(chunkIndex int) StorageID {
	if chunkIndex <= 0 || m.ChunkSizeCode == ChunkingDisabled {
		return m.StorageID
	}
	if chunkIndex-1 < len(m.ChunkLocations) {
		return m.ChunkLocations[chunkIndex-1].StorageID
	}
	// Return 0 (unallocated) if ChunkLocations is incomplete
	return StorageIDInline
}

// IsChunkAllocated returns true if the specified chunk has a storage ID assigned.
// For chunked objects, StorageIDInline (0) means the chunk is not yet allocated.
// For non-chunked objects, always returns true (single storage).
func (m *CacheMetadata) IsChunkAllocated(chunkIndex int) bool {
	if m.ChunkSizeCode == ChunkingDisabled {
		// Non-chunked always uses base StorageID
		return true
	}
	if chunkIndex == 0 {
		// Chunk 0 is allocated if base StorageID is non-zero
		// (0 = inline or unallocated; chunked objects can't be inline, so 0 = unallocated)
		return m.StorageID != StorageIDInline
	}
	if chunkIndex-1 < len(m.ChunkLocations) {
		return m.ChunkLocations[chunkIndex-1].StorageID != StorageIDInline
	}
	return false
}

// SetChunkStorageID sets the StorageID for a specific chunk (0-indexed).
// For chunk 0, sets the base StorageID. For chunks 1+, sets ChunkLocations.
// The ChunkLocations slice must be pre-allocated to the correct size.
func (m *CacheMetadata) SetChunkStorageID(chunkIndex int, storageID StorageID) {
	if chunkIndex <= 0 {
		m.StorageID = storageID
		return
	}
	if chunkIndex-1 < len(m.ChunkLocations) {
		m.ChunkLocations[chunkIndex-1].StorageID = storageID
	}
}

// GetChunkInfo returns information about all chunks for this object.
func (m *CacheMetadata) GetChunkInfo() []ChunkInfo {
	return GetChunkInfo(m.ContentLength, m.ChunkSizeCode, m.ChunkLocations, m.StorageID)
}

// AllStorageIDs returns a deduplicated list of all StorageIDs used by this object.
// For non-chunked objects, returns just the base StorageID.
func (m *CacheMetadata) AllStorageIDs() []StorageID {
	if !m.IsChunked() {
		return []StorageID{m.StorageID}
	}

	seen := make(map[StorageID]bool)
	var result []StorageID

	// Include base StorageID if allocated (non-zero)
	if m.StorageID != StorageIDInline {
		result = append(result, m.StorageID)
		seen[m.StorageID] = true
	}

	for _, loc := range m.ChunkLocations {
		// Skip unallocated chunks (StorageID 0)
		if loc.StorageID != StorageIDInline && !seen[loc.StorageID] {
			result = append(result, loc.StorageID)
			seen[loc.StorageID] = true
		}
	}

	return result
}

// PerDirectoryBytes returns a map from StorageID to the number of content
// bytes that live in each storage directory.  For non-chunked objects the
// entire ContentLength is attributed to the base StorageID.  For chunked
// objects the byte count is split according to each chunk's assigned
// directory.  Unallocated chunks (StorageID 0) are skipped.
func (m *CacheMetadata) PerDirectoryBytes() map[StorageID]int64 {
	result := make(map[StorageID]int64)
	if !m.IsChunked() {
		if m.ContentLength > 0 {
			if m.StorageID == StorageIDInline {
				result[m.StorageID] = m.ContentLength
			} else {
				result[m.StorageID] = CalculateFileSize(m.ContentLength)
			}
		}
		return result
	}
	for _, ci := range m.GetChunkInfo() {
		if ci.StorageID == StorageIDInline {
			continue // unallocated
		}
		result[ci.StorageID] += CalculateFileSize(ci.Size)
	}
	return result
}

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
	// Restore the boolean flags; a positive CCMaxAge implies ccMaxAgeSet,
	// which is why that bit is not persisted separately.
	return CacheDirectives{
		cache_control.FromFlags(m.CCFlags&0x0F, time.Duration(m.CCMaxAge)*time.Second),
	}
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
		// same value so that downstream shared caches honor the
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

// ComputeExpires returns the absolute time at which this object expires.
// It uses the origin-supplied max-age when available, otherwise the
// configured default freshness policy.  The result is based on
// LastValidated (or Completed if LastValidated is zero).
func (m *CacheMetadata) ComputeExpires() time.Time {
	base := m.LastValidated
	if base.IsZero() {
		base = m.Completed
	}
	if base.IsZero() {
		return time.Time{}
	}
	if m.CCMaxAge > 0 {
		return base.Add(time.Duration(m.CCMaxAge) * time.Second)
	}
	return base.Add(DefaultFreshness(base))
}

// EnsureExpires sets the Expires field if it is currently zero.
// Call this after SetCacheControl and after LastValidated is set.
func (m *CacheMetadata) EnsureExpires() {
	if m.Expires.IsZero() {
		m.Expires = m.ComputeExpires()
	}
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

// normalizeURL normalizes a pelican URL for consistent hashing.
//
// Only the scheme and host are folded.  Those are case-insensitive per
// RFC 3986 §6.2.2.1, so folding them makes equivalent URLs hash alike.  The
// path is left exactly as written: object paths are case-sensitive on every
// backend Pelican serves (POSIX, S3, HTTPS), so /ns/Data.txt and /ns/data.txt
// are different objects, and folding them together would give them one cache
// entry from which whichever was fetched last is served for both — a
// collision nothing on the read path detects.  See docs/pstore-design.md §12.
func normalizeURL(pelicanURL string) string {
	// Parse the URL
	u, err := url.Parse(pelicanURL)
	if err != nil {
		// If parsing fails, just clean the path
		return path.Clean(pelicanURL)
	}

	// Rebuild with normalized components
	return strings.ToLower(u.Scheme) + "://" + normalizeHost(u.Host) + path.Clean(u.Path)
}

// normalizeHost folds the authority of a URL so that every spelling of one
// host hashes to one object.
//
// strings.ToLower is the right fold only for an ASCII host.  A domain name may
// be internationalized, and an IDN has two equally valid spellings — the
// Unicode form and its punycode A-label — that no amount of lowercasing brings
// together, with a case fold of its own that IDNA defines and ASCII does not.
// idna.Lookup.ToASCII collapses all of them, so BÜCHER.example,
// bücher.example, and xn--bcher-kva.example name the same cached object.
//
// Three things are deliberately kept away from IDNA:
//
//   - The port is not part of the domain name.  It is split off, left exactly
//     as written, and reattached.
//   - IP literals are not domain names.  A bracketed IPv6 literal in
//     particular is rejected outright by IDNA (both the brackets and the
//     colons are disallowed runes), so literals are only lowercased.
//   - A host IDNA rejects for any other reason — an underscore, say — is
//     lowercased instead.  This function has no error to return and must
//     answer deterministically; a name that cannot be an IDN has no
//     alternative spelling to collapse in the first place.
func normalizeHost(host string) string {
	if host == "" {
		return ""
	}

	hostname, port := host, ""
	if h, p, err := net.SplitHostPort(host); err == nil {
		hostname, port = h, ":"+p
		// SplitHostPort strips the brackets from an IPv6 literal; the host
		// is not spellable without them, so put them back.
		if strings.ContainsRune(hostname, ':') {
			return "[" + strings.ToLower(hostname) + "]" + port
		}
	} else if strings.HasPrefix(hostname, "[") {
		// A bracketed IPv6 literal carrying no port.
		return strings.ToLower(hostname)
	}

	if net.ParseIP(hostname) != nil {
		return strings.ToLower(hostname) + port
	}

	ascii, err := idna.Lookup.ToASCII(hostname)
	if err != nil {
		return strings.ToLower(hostname) + port
	}
	return ascii + port
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

// AppendIntentKey returns the BadgerDB key for an in-flight streaming append.
func AppendIntentKey(instanceHash InstanceHash) []byte {
	return []byte(PrefixAppendIntent + string(instanceHash))
}

// AppendIntent is the record written while an AppendWriter is building an
// object.  StartedAt lets a reclamation pass leave very recent appends alone
// even when it cannot consult the in-process registry of live writers.
type AppendIntent struct {
	StartedAt   time.Time   `msgpack:"started_at"`
	NamespaceID NamespaceID `msgpack:"namespace_id"`
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

// CalculateFileSize returns the exact on-disk file size for a given content
// length.  The last block is only as large as the remaining data plus its
// AES-GCM authentication tag — it is not padded to a full BlockTotalSize.
func CalculateFileSize(contentLength int64) int64 {
	totalBlocks := CalculateBlockCount(contentLength)
	if totalBlocks == 0 {
		return 0
	}
	lastBlockData := contentLength % int64(BlockDataSize)
	if lastBlockData == 0 {
		lastBlockData = int64(BlockDataSize)
	}
	return BlockOffset(totalBlocks-1) + lastBlockData + int64(AuthTagSize)
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
