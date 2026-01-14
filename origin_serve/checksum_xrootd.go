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
	"encoding/binary"
	"fmt"
	"time"
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
	xrootdNameSize   = 16
	xrootdValueSize  = 64
	xrootdBinarySize = xrootdNameSize + 8 + 4 + 2 + 1 + 1 + xrootdValueSize // Total fixed size: 96 bytes
)

// serializeXRootDChecksum serializes a checksum into XRootD binary format.
// Returns the binary representation suitable for storage in xattr user.XrdCks.$(NAME).
// checksumStartTime is the time when the checksum computation started; the delta
// from fileModTime to checksumStartTime is recorded in the csTime field.
func serializeXRootDChecksum(name string, checksumBytes []byte, fileModTime, checksumStartTime time.Time) ([]byte, error) {
	// Enforce that checksum names fit in the fixed-size name field (including null terminator)
	if len(name) >= xrootdNameSize {
		return nil, fmt.Errorf("checksum name too long: %d >= %d", len(name), xrootdNameSize)
	}
	if len(checksumBytes) > xrootdValueSize {
		return nil, fmt.Errorf("checksum value too long: %d > %d", len(checksumBytes), xrootdValueSize)
	}

	// Pre-reserve the exact size needed for XRootD format
	buf := bytes.NewBuffer(make([]byte, 0, xrootdBinarySize))

	// Write name (padded with null terminators)
	nameBytes := make([]byte, xrootdNameSize)
	copy(nameBytes, name)
	buf.Write(nameBytes)

	// Write fmTime (file modification time as Unix timestamp in network byte order)
	fmTime := fileModTime.Unix()
	if err := binary.Write(buf, binary.BigEndian, fmTime); err != nil {
		return nil, err
	}

	// Write csTime (delta from fmTime when checksum was computed)
	// Calculated as seconds between file modification time and checksum start time
	csTime := int32(checksumStartTime.Unix() - fileModTime.Unix())
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

// deserializeXRootDChecksum deserializes XRootD binary checksum format.
func deserializeXRootDChecksum(data []byte) (name string, checksumBytes []byte, fileModTime time.Time, err error) {
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
