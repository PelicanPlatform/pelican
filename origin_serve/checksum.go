/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"fmt"
	"hash/crc32"
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	log "github.com/sirupsen/logrus"
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

	// Extended attribute names for checksums
	xattrMD5    = "user.checksum.md5"
	xattrSHA1   = "user.checksum.sha1"
	xattrCRC32  = "user.checksum.crc32"
	xattrCRC32C = "user.checksum.crc32c"
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

// GetChecksum retrieves or computes the checksum for a file
func (xc *XattrChecksummer) GetChecksum(filename string, checksumType ChecksumType) (string, error) {
	// First, try to get the checksum from extended attributes
	xattrName := getXattrName(checksumType)
	if xattrName != "" {
		data, err := xattr.Get(filename, xattrName)
		if err == nil && len(data) > 0 {
			// Check if the cached checksum is still valid
			if isChecksumValid(filename, xattrName) {
				return string(data), nil
			}
			// Cached checksum is stale, will recompute below
		}
	}

	// If not found or invalid, compute the checksum
	checksum, err := computeChecksum(filename, checksumType)
	if err != nil {
		return "", err
	}

	// Store the checksum in extended attributes for future use
	if xattrName != "" {
		if err := xattr.Set(filename, xattrName, []byte(checksum)); err != nil {
			log.Debugf("Failed to store checksum in xattr for %s: %v", filename, err)
		} else {
			// Also store the file modification time
			fileInfo, err := os.Stat(filename)
			if err == nil {
				mtimeAttr := xattrName + ".mtime"
				mtimeStr := fmt.Sprintf("%d", fileInfo.ModTime().Unix())
				if err := xattr.Set(filename, mtimeAttr, []byte(mtimeStr)); err != nil {
					log.Debugf("Failed to store mtime in xattr for %s: %v", filename, err)
				}
			}
		}
	}

	return checksum, nil
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

// isChecksumValid checks if the stored checksum is still valid by comparing file mtime
func isChecksumValid(filename string, xattrName string) bool {
	// Get file modification time
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return false
	}

	// Try to get stored modification time from xattr
	mtimeAttr := xattrName + ".mtime"
	mtimeData, err := xattr.Get(filename, mtimeAttr)
	if err != nil {
		// No stored mtime, checksum is invalid
		return false
	}

	// Parse stored mtime
	var storedMtime int64
	_, err = fmt.Sscanf(string(mtimeData), "%d", &storedMtime)
	if err != nil {
		return false
	}

	// Compare modification times
	return fileInfo.ModTime().Unix() == storedMtime
}

// computeChecksum computes the checksum for a file and returns it in RFC 3230 format
// (base64 for MD5/SHA1, hex for CRC32)
func computeChecksum(filename string, checksumType ChecksumType) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", errors.Wrap(err, "failed to open file for checksum")
	}
	defer file.Close()

	switch checksumType {
	case ChecksumTypeMD5:
		hash := md5.New()
		if _, err := io.Copy(hash, file); err != nil {
			return "", errors.Wrap(err, "failed to compute MD5 checksum")
		}
		return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil

	case ChecksumTypeSHA1:
		hash := sha1.New()
		if _, err := io.Copy(hash, file); err != nil {
			return "", errors.Wrap(err, "failed to compute SHA1 checksum")
		}
		return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil

	case ChecksumTypeCRC32:
		hash := crc32.NewIEEE()
		if _, err := io.Copy(hash, file); err != nil {
			return "", errors.Wrap(err, "failed to compute CRC32 checksum")
		}
		// CRC32 is hex-encoded per RFC 3230 and IANA registry
		return fmt.Sprintf("%08x", hash.Sum32()), nil

	case ChecksumTypeCRC32C:
		hash := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		if _, err := io.Copy(hash, file); err != nil {
			return "", errors.Wrap(err, "failed to compute CRC32C checksum")
		}
		// CRC32C is hex-encoded per RFC 3230 and IANA registry
		return fmt.Sprintf("%08x", hash.Sum32()), nil

	default:
		return "", errors.Errorf("unsupported checksum type: %s", checksumType)
	}
}
