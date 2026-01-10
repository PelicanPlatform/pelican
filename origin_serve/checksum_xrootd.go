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
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// XRootD checksum format according to the spec:
// char      Name[NameSize];       // Checksum algorithm name (max 15 chars + null)
// union {
//   long long fmTime;             // File's mtime when checksum was computed
//   void*     envP;               // Not used in storage (we use fmTime)
// };
// int       csTime;               // Delta from fmTime when checksum was computed
// short     Rsvd1;                // Reserved field
// char      Rsvd2;                // Reserved field
// char      Length;               // Length, in bytes, of the checksum value
// char      Value[ValSize];       // The binary checksum value (max 64 bytes)

const (
	xrootdNameSize  = 16
	xrootdValueSize = 64
)

// SerializeXRootDChecksum serializes a checksum into XRootD binary format
// Returns the binary representation suitable for storage in xattr user.XrdCks.$(NAME)
func SerializeXRootDChecksum(name string, checksumBytes []byte, fileModTime time.Time) ([]byte, error) {
	if len(name) >= xrootdNameSize {
		return nil, fmt.Errorf("checksum name too long: %d >= %d", len(name), xrootdNameSize)
	}
	if len(checksumBytes) > xrootdValueSize {
		return nil, fmt.Errorf("checksum value too long: %d > %d", len(checksumBytes), xrootdValueSize)
	}

	buf := new(bytes.Buffer)

	// Write name (padded with null terminators)
	nameBytes := make([]byte, xrootdNameSize)
	copy(nameBytes, name)
	buf.Write(nameBytes)

	// Write fmTime (file modification time as Unix timestamp in network byte order)
	fmTime := fileModTime.Unix()
	if err := binary.Write(buf, binary.BigEndian, fmTime); err != nil {
		return nil, err
	}

	// Write csTime (delta from fmTime when checksum was computed - use 0 for now)
	csTime := int32(0)
	if err := binary.Write(buf, binary.BigEndian, csTime); err != nil {
		return nil, err
	}

	// Write reserved fields
	if err := binary.Write(buf, binary.BigEndian, int16(0)); err != nil { // Rsvd1
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, byte(0)); err != nil { // Rsvd2
		return nil, err
	}

	// Write length of checksum value
	if err := binary.Write(buf, binary.BigEndian, byte(len(checksumBytes))); err != nil {
		return nil, err
	}

	// Write checksum value (padded with zeros)
	valueBytes := make([]byte, xrootdValueSize)
	copy(valueBytes, checksumBytes)
	buf.Write(valueBytes)

	return buf.Bytes(), nil
}

// DeserializeXRootDChecksum deserializes XRootD binary checksum format
func DeserializeXRootDChecksum(data []byte) (name string, checksumBytes []byte, fileModTime time.Time, err error) {
	if len(data) < xrootdNameSize+8+4+2+1+1 {
		err = fmt.Errorf("checksum data too short: %d bytes", len(data))
		return
	}

	buf := bytes.NewReader(data)

	// Read name
	nameBytes := make([]byte, xrootdNameSize)
	_, err = buf.Read(nameBytes)
	if err != nil {
		return
	}
	// Find null terminator
	name = string(bytes.TrimRight(nameBytes, "\x00"))

	// Read fmTime (file modification time)
	var fmTime int64
	err = binary.Read(buf, binary.BigEndian, &fmTime)
	if err != nil {
		return
	}
	fileModTime = time.Unix(fmTime, 0)

	// Read csTime (delta from fmTime)
	var csTime int32
	err = binary.Read(buf, binary.BigEndian, &csTime)
	if err != nil {
		return
	}

	// Read reserved fields (Rsvd1)
	var rsvd1 int16
	err = binary.Read(buf, binary.BigEndian, &rsvd1)
	if err != nil {
		return
	}

	// Read reserved field (Rsvd2)
	var rsvd2 byte
	err = binary.Read(buf, binary.BigEndian, &rsvd2)
	if err != nil {
		return
	}

	// Read length of checksum value
	var length byte
	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}

	// Read checksum value
	valueBytes := make([]byte, xrootdValueSize)
	_, err = buf.Read(valueBytes)
	if err != nil {
		return
	}

	checksumBytes = valueBytes[:length]
	return
}

// ComputeXRootDChecksum computes a checksum and returns it in XRootD binary format
// This is useful for storing checksums in XRootD-compatible attributes
func ComputeXRootDChecksum(filePath string, algorithm string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file modification time for XRootD format
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	var h hash.Hash
	var xrootdAlgName string

	switch algorithm {
	case "md5":
		h = md5.New()
		xrootdAlgName = "md5"
	case "sha1", "sha":
		h = md5.New() // Default to MD5 for XRootD storage
		xrootdAlgName = "md5"
	case "crc32":
		h = crc32.NewIEEE()
		xrootdAlgName = "crc32"
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Read file and compute hash
	_, err = io.Copy(h, file)
	if err != nil {
		return nil, err
	}

	checksumBytes := h.Sum(nil)
	xrootdData, err := SerializeXRootDChecksum(xrootdAlgName, checksumBytes, fileInfo.ModTime())
	if err != nil {
		log.WithError(err).Warnf("Failed to serialize XRootD checksum for %s", filePath)
		return nil, err
	}

	return xrootdData, nil
}
