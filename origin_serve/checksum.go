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

package origin_serve

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

type (
	// ChecksumType represents the type of checksum
	ChecksumType string

	// Checksummer is an interface for fetching and computing checksums
	Checksummer interface {
		GetChecksum(filename string, checksumType ChecksumType) (string, error)
	}

	// XattrChecksummer uses extended attributes to store and retrieve checksums
	XattrChecksummer struct{}
)

const (
	ChecksumTypeMD5    ChecksumType = "md5"
	ChecksumTypeSHA1   ChecksumType = "sha1"
	ChecksumTypeCRC32  ChecksumType = "crc32"
	ChecksumTypeCRC32C ChecksumType = "crc32c"

	// Extended attribute names for checksums (XRootD format)
	xattrMD5    = "user.XrdCks.md5"
	xattrSHA1   = "user.XrdCks.sha1"
	xattrCRC32  = "user.XrdCks.crc32"
	xattrCRC32C = "user.XrdCks.crc32c"
)

var globalChecksummer Checksummer

// InitializeChecksummer initializes the global checksummer
func InitializeChecksummer() {
	globalChecksummer = &XattrChecksummer{}
}

// GetChecksummer returns the global checksummer
func GetChecksummer() Checksummer {
	if globalChecksummer == nil {
		InitializeChecksummer()
	}
	return globalChecksummer
}

// isValidChecksumType checks if a checksum type string is valid
func isValidChecksumType(checksumType ChecksumType) bool {
	switch checksumType {
	case ChecksumTypeMD5, ChecksumTypeSHA1, ChecksumTypeCRC32, ChecksumTypeCRC32C:
		return true
	default:
		return false
	}
}

// GetChecksum retrieves or computes the checksum for a file
func (xc *XattrChecksummer) GetChecksum(filename string, checksumType ChecksumType) (string, error) {
	// Try to read XRootD-formatted xattr and validate mtime
	bytes, ok, err := readChecksumFromXattr(filename, checksumType)
	if err != nil {
		return "", err
	}
	if !ok {
		// Compute requested checksum and store (along with defaults)
		types := mergeWithDefault([]ChecksumType{checksumType})
		if err := computeAndStoreChecksums(filename, types); err != nil {
			return "", err
		}
		bytes, ok, err = readChecksumFromXattr(filename, checksumType)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.Errorf("failed to retrieve checksum %s after computation", checksumType)
		}
	}
	// Return RFC 3230 value (without algorithm= prefix)
	return rfc3230Value(checksumType, bytes), nil
}

// GetChecksumRFC3230 retrieves the checksum in RFC 3230 format (algorithm=value)
// MD5 and SHA1 are base64-encoded, CRC32 is hex-encoded
func (xc *XattrChecksummer) GetChecksumRFC3230(filename string, checksumType ChecksumType) (string, error) {
	checksum, err := xc.GetChecksum(filename, checksumType)
	if err != nil {
		return "", err
	}

	// Format according to RFC 3230
	switch checksumType {
	case ChecksumTypeMD5:
		return "md5=" + checksum, nil
	case ChecksumTypeSHA1:
		return "sha=" + checksum, nil
	case ChecksumTypeCRC32:
		return "crc32=" + checksum, nil
	case ChecksumTypeCRC32C:
		return "crc32c=" + checksum, nil
	default:
		return "", errors.Errorf("unsupported checksum type for RFC 3230: %s", checksumType)
	}
}

// GetChecksumsRFC3230 returns a list of RFC 3230 digest strings for requested types.
// If any requested checksum is missing or stale, computes all requested plus defaults and stores.
func (xc *XattrChecksummer) GetChecksumsRFC3230(filename string, types []ChecksumType) ([]string, error) {
	// Determine which are present and valid
	haveAll := true
	for _, t := range types {
		_, ok, err := readChecksumFromXattr(filename, t)
		if err != nil {
			return nil, err
		}
		if !ok {
			haveAll = false
		}
	}

	if !haveAll {
		// Compute and store requested + defaults
		allTypes := mergeWithDefault(types)
		if err := computeAndStoreChecksums(filename, allTypes); err != nil {
			return nil, err
		}
	}

	// Build digest strings
	digests := make([]string, 0, len(types))
	for _, t := range types {
		bytes, ok, err := readChecksumFromXattr(filename, t)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.Errorf("checksum %s missing after computation", t)
		}
		digests = append(digests, formatRFC3230(t, bytes))
	}
	return digests, nil
}

// getXattrName returns the extended attribute name for a checksum type
func getXattrName(checksumType ChecksumType) string {
	switch checksumType {
	case ChecksumTypeMD5:
		return xattrMD5
	case ChecksumTypeSHA1:
		return xattrSHA1
	case ChecksumTypeCRC32:
		return xattrCRC32
	case ChecksumTypeCRC32C:
		return xattrCRC32C
	default:
		return ""
	}
}

// computeChecksumBytes computes the checksum for a file and returns raw bytes
func computeChecksumBytes(filename string, checksumType ChecksumType) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open file for checksum")
	}
	defer file.Close()

	switch checksumType {
	case ChecksumTypeMD5:
		hash := md5.New()
		if _, err := io.Copy(hash, file); err != nil {
			return nil, errors.Wrap(err, "failed to compute MD5 checksum")
		}
		return hash.Sum(nil), nil

	case ChecksumTypeSHA1:
		hash := sha1.New()
		if _, err := io.Copy(hash, file); err != nil {
			return nil, errors.Wrap(err, "failed to compute SHA1 checksum")
		}
		return hash.Sum(nil), nil

	case ChecksumTypeCRC32:
		hash := crc32.NewIEEE()
		if _, err := io.Copy(hash, file); err != nil {
			return nil, errors.Wrap(err, "failed to compute CRC32 checksum")
		}
		val := make([]byte, 4)
		binary.BigEndian.PutUint32(val, hash.Sum32())
		return val, nil

	case ChecksumTypeCRC32C:
		hash := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		if _, err := io.Copy(hash, file); err != nil {
			return nil, errors.Wrap(err, "failed to compute CRC32C checksum")
		}
		val := make([]byte, 4)
		binary.BigEndian.PutUint32(val, hash.Sum32())
		return val, nil

	default:
		return nil, errors.Errorf("unsupported checksum type: %s", checksumType)
	}
}

// readChecksumFromXattr reads and validates a checksum from XRootD-formatted xattr.
// Returns (bytes, true) if present and valid; (nil, false) if missing or stale.
func readChecksumFromXattr(filename string, checksumType ChecksumType) ([]byte, bool, error) {
	xattrName := getXattrName(checksumType)
	if xattrName == "" {
		return nil, false, nil
	}
	data, err := xattr.Get(filename, xattrName)
	if err != nil || len(data) == 0 {
		return nil, false, nil
	}
	name, bytes, fileModTime, err := deserializeXRootDChecksum(data)
	if err != nil {
		return nil, false, err
	}
	// Validate algorithm name
	if name != string(checksumType) {
		return nil, false, nil
	}
	// Validate mtime
	fi, err := os.Stat(filename)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to stat file for checksum validation")
	}
	// If the file's current mtime differs, consider stale
	currMTime := fi.ModTime().Unix()
	if currMTime != fileModTime.Unix() {
		return nil, false, nil
	}
	return bytes, true, nil
}

// computeAndStoreChecksums computes all requested checksum types and stores them in XRootD-format xattrs.
// Reads the file once and computes all checksums simultaneously for efficiency.
func computeAndStoreChecksums(filename string, types []ChecksumType) error {
	fi, err := os.Stat(filename)
	if err != nil {
		return errors.Wrap(err, "failed to stat file for checksum computation")
	}
	fileModTime := fi.ModTime()
	start := time.Now()

	// Open file once
	file, err := os.Open(filename)
	if err != nil {
		return errors.Wrap(err, "failed to open file for checksum computation")
	}
	defer file.Close()

	// Create hash instances for all requested types
	type hashResult struct {
		checksumType ChecksumType
		hash         io.Writer
		finalize     func() []byte
	}

	hashes := make([]hashResult, 0, len(types))
	writers := make([]io.Writer, 0, len(types))

	for _, t := range types {
		switch t {
		case ChecksumTypeMD5:
			h := md5.New()
			hashes = append(hashes, hashResult{
				checksumType: t,
				hash:         h,
				finalize:     func() []byte { return h.Sum(nil) },
			})
			writers = append(writers, h)

		case ChecksumTypeSHA1:
			h := sha1.New()
			hashes = append(hashes, hashResult{
				checksumType: t,
				hash:         h,
				finalize:     func() []byte { return h.Sum(nil) },
			})
			writers = append(writers, h)

		case ChecksumTypeCRC32:
			h := crc32.NewIEEE()
			hashes = append(hashes, hashResult{
				checksumType: t,
				hash:         h,
				finalize: func() []byte {
					val := make([]byte, 4)
					binary.BigEndian.PutUint32(val, h.Sum32())
					return val
				},
			})
			writers = append(writers, h)

		case ChecksumTypeCRC32C:
			h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
			hashes = append(hashes, hashResult{
				checksumType: t,
				hash:         h,
				finalize: func() []byte {
					val := make([]byte, 4)
					binary.BigEndian.PutUint32(val, h.Sum32())
					return val
				},
			})
			writers = append(writers, h)
		}
	}

	// Read file once, writing to all hashes simultaneously
	multiWriter := io.MultiWriter(writers...)
	if _, err := io.Copy(multiWriter, file); err != nil {
		return errors.Wrap(err, "failed to compute checksums")
	}

	// Store all computed checksums
	for _, hr := range hashes {
		bytes := hr.finalize()
		bin, err := serializeXRootDChecksum(string(hr.checksumType), bytes, fileModTime, start)
		if err != nil {
			return err
		}
		xattrName := getXattrName(hr.checksumType)
		if xattrName == "" {
			continue
		}
		if err := xattr.Set(filename, xattrName, bin); err != nil {
			// Check if the error is due to xattr size limits
			if err.Error() == "no space left on device" || err.Error() == "Operation not supported" {
				log.Warnf("Failed to store checksum in xattr for %s (%s): xattr storage limit exceeded or not supported. "+
					"Checksum will need to be recomputed on next access. Error: %v", filename, xattrName, err)
			} else {
				log.Debugf("Failed to store checksum in xattr for %s (%s): %v", filename, xattrName, err)
			}
		}
	}
	return nil
}

// mergeWithDefault merges requested types with default list, de-duplicated.
func mergeWithDefault(types []ChecksumType) []ChecksumType {
	def := defaultChecksumTypes()
	m := make(map[ChecksumType]struct{})
	for _, t := range types {
		m[t] = struct{}{}
	}
	for _, t := range def {
		m[t] = struct{}{}
	}
	result := make([]ChecksumType, 0, len(m))
	for t := range m {
		result = append(result, t)
	}
	return result
}

// defaultChecksumTypes returns server-side default checksum algorithms to maintain in xattrs.
// Reads from Origin.DefaultChecksumTypes config; falls back to CRC32C if not configured.
func defaultChecksumTypes() []ChecksumType {
	cfgList := param.Origin_DefaultChecksumTypes.GetStringSlice()
	if len(cfgList) == 0 {
		// Use hardcoded default if not configured
		return []ChecksumType{ChecksumTypeCRC32C}
	}
	result := make([]ChecksumType, 0, len(cfgList))
	for _, alg := range cfgList {
		switch alg {
		case "md5":
			result = append(result, ChecksumTypeMD5)
		case "sha1":
			result = append(result, ChecksumTypeSHA1)
		case "crc32":
			result = append(result, ChecksumTypeCRC32)
		case "crc32c":
			result = append(result, ChecksumTypeCRC32C)
		}
	}
	return result
}

// rfc3230Value converts raw checksum bytes into RFC 3230 value string for the given algorithm.
func rfc3230Value(t ChecksumType, bytes []byte) string {
	switch t {
	case ChecksumTypeMD5, ChecksumTypeSHA1:
		return base64.StdEncoding.EncodeToString(bytes)
	case ChecksumTypeCRC32, ChecksumTypeCRC32C:
		// Represent as lowercase hex
		return fmt.Sprintf("%08x", binary.BigEndian.Uint32(bytes))
	default:
		return ""
	}
}

// formatRFC3230 builds the full RFC 3230 digest string for the given algorithm and bytes.
func formatRFC3230(t ChecksumType, bytes []byte) string {
	switch t {
	case ChecksumTypeMD5:
		return "md5=" + rfc3230Value(t, bytes)
	case ChecksumTypeSHA1:
		return "sha=" + rfc3230Value(t, bytes)
	case ChecksumTypeCRC32:
		return "crc32=" + rfc3230Value(t, bytes)
	case ChecksumTypeCRC32C:
		return "crc32c=" + rfc3230Value(t, bytes)
	default:
		return ""
	}
}
