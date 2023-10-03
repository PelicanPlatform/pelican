//go:build linux
// +build linux

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// Given a local filename, create a unique identifier from filesystem
// metadata; anytime the file contents change, the unique identifier
// should also change.  The hash changes once every 24 hours to allow
// the shadow origin to do garbage collection.
//
// The current algorithm to generate the unique identifier is to
// take the concatenation of the following byte buffers:
//
// - basename of the path.
// - inode # as a 64-bit integer serialized to a byte buffer, represented in network order.
// - ctime # as a double serialized to a buffer.
// - Current unix epoch time, as integer, divided by 86400
//
// and then running it through a SHA256 sum to produce a digest.
//
// The hex digest of the SHA256 sum is returned along with the file size
func unique_hash(filePath string) (string, uint64, error) {
	log.Debugf("Creating a unique hash for filename %s", filePath)

	var st syscall.Stat_t
	if err := syscall.Stat(filePath, &st); err != nil {
		log.Debugln("Error while stat'ing file for metadata:", err)
		return "", 0, err
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, st.Ino); err != nil {
		log.Debugln("Error while writing inode to buffer:", err)
		return "", 0, err
	}
	if err := binary.Write(buf, binary.BigEndian, st.Ctim.Sec); err != nil {
		log.Debugln("Error while writing ctime to buffer:", err)
		return "", 0, err
	}
	if err := binary.Write(buf, binary.BigEndian, st.Ctim.Nsec); err != nil {
		log.Debugln("Error while writing ctime nanoseconds to buffer:", err)
		return "", 0, err
	}
	if err := binary.Write(buf, binary.BigEndian, time.Now().Unix()/86400); err != nil {
		log.Debugln("Error while writing current Unix time to buffer:", err)
		return "", 0, err
	}

	digest := sha256.New()
	digest.Write([]byte(filePath))
	digest.Write(buf.Bytes())

	return fmt.Sprintf("%x", digest.Sum(nil)), uint64(st.Size), nil
}
