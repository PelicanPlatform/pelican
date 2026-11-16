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

package unix_cksum

import (
	"encoding/binary"
	"hash"
)

// unix_cksum.go implements a Go-native UNIX cksum
// The result is the same as GNU coreutils cksum utility
// The specification ("the spec") is The Open Group Base Specifications Issue 8, IEEE Std 1003.1-2024
// The spec can be found here: https://pubs.opengroup.org/onlinepubs/9799919799/utilities/cksum.html

// Known limitation: n is uint64, which means any file larger than (1 << 64) bytes
// will result in integer overflow. Not a big issue because 1 << 64 is huge.
type digest struct {
	reg uint32 // The register that holds the result computed so far
	n   uint64 // The counter that holds the number of bytes read so far
}

// The lookup table used to process one byte at a time
// Build once on package import, and read-only
// Since Go does not provide mechanism to mark it as read-only,
// this table should never be exposed to the outside of the package
// Prefer package-level var assignment over init() because it
// makes data flow clear
var table = makeTable()

// The generator polynomial used by UNIX cksum, with the most significant bit (MSB) removed
// It is defined in ISO/IEC 8802-3:1996 standard (Ethernet)
const magic = 0x04C11DB7

func NewCksum() hash.Hash32 {
	return new(digest)
}

// makeTable build the table once on package import
func makeTable() (tab [256]uint32) {

	// We treat each byte as an message, and compute the corresponding
	// register state after processing the entire message. The final
	// register state is saved to the table, indexed by the message
	for msg := range tab {

		// The register holds the result which tells the reader
		// whether the next 32 bits from the original message is flipped or no
		var register uint32

		// Process one bit at a time
		for i := range 8 {
			registerMsb := (register >> 31) & 1
			msgCurrBit := (msg >> (7 - i)) & 1
			actualBit := registerMsb ^ uint32(msgCurrBit)
			register <<= 1
			if actualBit == 1 {
				register ^= magic
			}
		}

		tab[msg] = register
	}
	return tab
}

// update updates the register of the digest by the given msg
// However, this function will not touch the internal state of the
// digest struct
func updateRegister(reg uint32, msg []byte) uint32 {
	for _, m := range msg {
		regTop8 := byte(reg >> 24)
		actualBits := regTop8 ^ m
		reg = (reg << 8) ^ table[actualBits]
	}
	return reg
}

// ================ Implement the io.Writer interface ================
func (d *digest) Write(p []byte) (int, error) {
	d.reg = updateRegister(d.reg, p)
	d.n += uint64(len(p))
	return len(p), nil
}

// ================ Implement the hash.Hash interface ================
func (d *digest) Sum(b []byte) []byte {
	return binary.BigEndian.AppendUint32(b, d.Sum32())
}

func (d *digest) Reset() {
	d.reg = 0
	d.n = 0
}

func (d *digest) Size() int {
	return 4
}

func (d *digest) BlockSize() int {
	return 1
}

// ================ Implement the hash.Hash32 interface ================
func (d *digest) Sum32() uint32 {
	// Append the file size to the hash, in little endian
	fileSize := make([]byte, 0)
	for n := d.n; n > 0; n >>= 8 {
		fileSize = append(fileSize, byte(n))
	}
	register := updateRegister(d.reg, fileSize)

	// Return inverted result as per the spec
	return ^register
}
