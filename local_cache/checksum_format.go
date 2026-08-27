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

// Shared checksum naming, encoding, and hashing.
//
// Four places need to agree on which algorithms exist and how they are written
// down: the consistency checker, the cache API's Digest header, the
// introspection output, and the pstore origin backend.  They live here rather
// than in each of those, because four spellings of the same table is four
// chances to disagree -- and the disagreement is not obvious when it happens.
// A digest encoded as hex where RFC 3230 requires base64, for instance,
// reaches the Pelican client as a checksum mismatch against a value identical
// to its own.

package local_cache

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"hash/crc32"
	"strings"

	"github.com/pkg/errors"
)

// ChecksumAlgorithmName returns the RFC 3230 token for a checksum type, as it
// appears in Want-Digest and Digest headers.  Unknown types return "".
func ChecksumAlgorithmName(t ChecksumType) string {
	switch t {
	case ChecksumMD5:
		return "md5"
	case ChecksumSHA1:
		return "sha"
	case ChecksumSHA256:
		return "sha-256"
	case ChecksumCRC32:
		return "crc32"
	case ChecksumCRC32C:
		return "crc32c"
	default:
		return ""
	}
}

// ParseChecksumAlgorithm maps the spellings clients use in Want-Digest onto a
// checksum type.  The second result reports whether the name was recognized.
func ParseChecksumAlgorithm(name string) (ChecksumType, bool) {
	switch strings.TrimSpace(strings.ToLower(name)) {
	case "md5":
		return ChecksumMD5, true
	case "sha", "sha-1", "sha1":
		return ChecksumSHA1, true
	case "sha-256", "sha256":
		return ChecksumSHA256, true
	case "crc32":
		return ChecksumCRC32, true
	case "crc32c":
		return ChecksumCRC32C, true
	default:
		return 0, false
	}
}

// FormatChecksumValue renders a checksum the way RFC 3230 expects for its
// algorithm: message digests are base64, CRCs are lowercase hex.  Unknown
// types return "".
//
// Getting this wrong is not cosmetic.  A client compares the value it computed
// against the one the origin reports and fails the transfer on a mismatch,
// even when the underlying digests are identical.
func FormatChecksumValue(c Checksum) string {
	switch c.Type {
	case ChecksumMD5, ChecksumSHA1, ChecksumSHA256:
		return base64.StdEncoding.EncodeToString(c.Value)
	case ChecksumCRC32, ChecksumCRC32C:
		return hex.EncodeToString(c.Value)
	default:
		return ""
	}
}

// FormatDigestEntry renders one checksum as an RFC 3230 "name=value" pair,
// or "" when the algorithm is not recognized or the digest is empty.
//
// Skipping an empty digest is a deliberate change from the cache's previous
// Digest-header code, which emitted a bare "md5=" for a zero-value
// Checksum{Type: ChecksumMD5}.  Every algorithm here produces a fixed-length
// digest, so an empty Value never means "the digest of nothing" -- it means the
// checksum was never populated.  Advertising it anyway is worse than omitting
// it: RFC 3230 gives a client no way to read "md5=" as "unknown", so the
// Pelican client compares the digest it computed against an empty string and
// fails an otherwise-good transfer as a checksum mismatch.  A missing entry, by
// contrast, is exactly the "no digest available" signal clients already handle.
func FormatDigestEntry(c Checksum) string {
	name := ChecksumAlgorithmName(c.Type)
	value := FormatChecksumValue(c)
	if name == "" || value == "" {
		return ""
	}
	return name + "=" + value
}

// FormatDigestHeader renders a set of checksums as an RFC 3230 Digest header
// value.  Unknown algorithms are skipped.
func FormatDigestHeader(checksums []Checksum) string {
	parts := make([]string, 0, len(checksums))
	for _, c := range checksums {
		if entry := FormatDigestEntry(c); entry != "" {
			parts = append(parts, entry)
		}
	}
	return strings.Join(parts, ", ")
}

// NewChecksumHasher returns a hash for the given checksum type.
func NewChecksumHasher(t ChecksumType) (hash.Hash, error) {
	switch t {
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
		return nil, errors.Errorf("unknown checksum type: %d", t)
	}
}
