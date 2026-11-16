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
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/test_utils"
)

// TestMakeTable compares the lookup table implemented by us with the
// reference table specified by POSIX standard
func TestMakeTable(t *testing.T) {
	// The reference table specified by POSIX standard for the IEEE generator polynomial
	refTable := [256]uint32{
		0x00000000,
		0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
		0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6,
		0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
		0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac,
		0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8, 0x6ed82b7f,
		0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a,
		0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
		0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58,
		0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033,
		0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027, 0xddb056fe,
		0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
		0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4,
		0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
		0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5,
		0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
		0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca, 0x7897ab07,
		0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c,
		0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1,
		0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
		0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b,
		0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698,
		0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d,
		0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
		0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2, 0xc6bcf05f,
		0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
		0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80,
		0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
		0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a,
		0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e, 0x21dc2629,
		0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c,
		0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
		0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e,
		0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65,
		0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601, 0xdea580d8,
		0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
		0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2,
		0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
		0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74,
		0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
		0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c, 0x7b827d21,
		0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a,
		0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e, 0x18197087,
		0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
		0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d,
		0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce,
		0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb,
		0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
		0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4, 0x89b8fd09,
		0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
		0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf,
		0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4,
	}

	// Compare table entries one by one
	for i := range table {
		assert.Equal(t, refTable[i], table[i])
	}
}

func TestSize(t *testing.T) {
	digest := NewCksum()
	assert.Equal(t, 4, digest.Size())
}

func TestBlockSize(t *testing.T) {
	digest := NewCksum()
	assert.Equal(t, 1, digest.BlockSize())
}

// TestResetFuzz checks if Reset can reliably resets the internal state
// no matter what its current internal state is
func TestResetFuzz(t *testing.T) {
	// Log the seed for reproducibility
	seed := time.Now().UnixNano()
	t.Logf("Seed=%d", seed)
	r := rand.New(rand.NewSource(seed))

	for range 1 << 10 {
		// Compute the hash. We don't care about the result
		// We just want to mutate the internal state
		d := NewCksum()
		buf := make([]byte, r.Int31n(1<<10))
		r.Read(buf)
		written, err := d.Write(buf)
		require.Equal(t, len(buf), written)
		require.NoError(t, err)

		d.Reset()
		assert.Equal(t, uint32(0), d.(*digest).reg)
		assert.Equal(t, uint64(0), d.(*digest).n)
	}
}

// The test table shared by TestSum and TestSum32TableDriven
var testcases = []struct {
	name   string
	input  []byte
	expect uint32 // pre-computed by coreutils cksum
}{
	{"empty-file", []byte{}, 0xffffffff},
	{"1-9", []byte("123456789"), 0x377a6011},
	{"a-z", []byte("abcdefghijklmnopqrstuvwxyz"), 0xa1b937a8},
	{"A-Z", []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0x4dab0cf3},
	{"the-answer-to-life-the-universe-and-everything", []byte{42}, 0xf1270933},
}

// TestSum checks if the cksum is appended to the provided byte slice buffer
// in big endian (convention in Go hash standard library), and the internal
// state is intact
func TestSum(t *testing.T) {
	for _, e := range testcases {
		// Compute the hash
		d := NewCksum()
		written, err := d.Write([]byte(e.input))
		require.Equal(t, len(e.input), written)
		require.NoError(t, err)
		reg := d.(*digest).reg // Save for later
		n := d.(*digest).n     // Save for later

		// Check the output value
		buf := make([]byte, 0)
		buf = d.Sum(buf)
		expect := make([]byte, 4)
		binary.BigEndian.PutUint32(expect, e.expect)
		assert.Equal(t, expect, buf)

		// Check the claim: Sum should not change the underlying hash state
		assert.Equal(t, reg, d.(*digest).reg)
		assert.Equal(t, n, d.(*digest).n)
	}
}

// TestSum32TableDriven is a table-driven test to check the correctness
// of the cksum logic by comparing the result of our implementation against
// a set of pre-computed hash derived from coreutils cksum.
// It acts as a fallback of the fuzz test TestSum32Fuzz.
func TestSum32TableDriven(t *testing.T) {
	for _, e := range testcases {
		t.Run(e.name, func(t *testing.T) {
			digest := NewCksum()
			written, err := digest.Write(e.input)
			require.Equal(t, len(e.input), written)
			require.NoError(t, err)
			assert.Equal(t, e.expect, digest.Sum32())
		})
	}
}

// TestSum32SplitWriteFuzz checks the consistency of our implementation.
// A chunk of bytes should derive the same cksum, no matter the byte
// are dumped into the Write method as a whole, or it's chopped off into multiple
// pieces and fed into the Write method with order preserved.
func TestSum32SplitWriteFuzz(t *testing.T) {
	// Log the seed for reproducibility
	seed := time.Now().UnixNano()
	t.Logf("Seed=%d", seed)
	r := rand.New(rand.NewSource(seed))

	for range 1 << 10 {
		// Generate random bytes
		bufLen := r.Int31n(1<<10) + 1 // if bufLen == 0, next Int31n will panic
		buf := make([]byte, bufLen)
		r.Read(buf)

		// Split the buffer
		split := r.Int31n(bufLen)
		bufUpper := buf[:split]
		bufLower := buf[split:]

		// The result should be consistent:
		// hash by whole buf == hash upper the hash lower
		// Write as a complete buffer
		d0 := NewCksum()
		written, err := d0.Write(buf)
		require.Equal(t, len(buf), written)
		require.NoError(t, err)
		cksumWhole := d0.Sum32()

		// Split write
		d1 := NewCksum()
		written, err = d1.Write(bufUpper)
		require.Equal(t, len(bufUpper), written)
		require.NoError(t, err)
		written, err = d1.Write(bufLower)
		require.Equal(t, len(bufLower), written)
		require.NoError(t, err)
		cksumSplit := d1.Sum32()

		// Compare
		assert.Equal(t, cksumWhole, cksumSplit)
	}
}

// TestSum32Stress is a stress test that computes the cksum of 4 GiB + 1 byte of data
func TestSum32Stress(t *testing.T) {
	test_utils.SkipIfShort(t, "The code protected by the stress test rarely changes. Skip it for short run.")

	pattern := "abcdefg\n"
	buf := bytes.Repeat([]byte(pattern), 1<<9) // 4 KiB buffer
	d := NewCksum()
	for range 1 << 20 { // Write 4 GiB first
		d.Write(buf)
	}
	require.Equal(t, uint64(1<<32), d.(*digest).n, "Should have written 4 GiB so far")

	// Write 1 more byte to test the uint32 boundary
	// It will catch the implementation drift if the byte counter, n, is
	// ever changed to uint32 type
	written, err := d.Write([]byte("a"))
	require.Equal(t, 1, written, "Failed on the last 1 byte")
	require.NoError(t, err, "Should never return error. Failed on the last 1 byte")
	require.Equal(t, uint64(1<<32+1), d.(*digest).n, "Should have written 4 GiB + 1 byte so far")

	// Expected value from GNU coreutils:
	// yes abcdefg | head -c $(( (1 << 32) + 1 )) | cksum
	assert.Equal(t, uint32(0xf19922a6), d.Sum32())
}

// TestSum32Fuzz is a fuzz test written by hand, it generates 4 * 1024 pieces of test files, computes
// the cksum on our implementation and GNU coreutils cksum implementation, and finally compares them
// The fuzz test is opportunistic because not all platforms are installed with GNU coreutils.
func TestSum32Fuzz(t *testing.T) {
	// Run the fuzz test opportunistically
	if _, err := exec.LookPath("cksum"); err != nil {
		t.Skip("cksum is not in PATH. Skipping the fuzz test for self-made UNIX cksum.")
	}

	// Create a temp directory for test files
	tempDir := t.TempDir()

	// Save the random seed so a failure can be reproduced
	seed := time.Now().UnixNano()
	t.Logf("Seed=%d", seed)
	r := rand.New(rand.NewSource(seed))

	// Generate one digest struct and use it for the entire test
	d := NewCksum()

	// Run 4 batches, with each batch generate 1024 test files
	for i := range 1 << 2 {
		fileNames := make([]string, 1<<10)             // Collect all file names, relative to tempDir
		actualCksums := make(map[string]uint32, 1<<10) // Collect checksums computed by our implementation
		actualSizes := make(map[string]uint64, 1<<10)  // Collect file sizes computed by our implementation

		// Generate 1024 test files for this batch, and compute cksum with our implementation
		for j := range 1 << 10 {
			// Generate random bytes
			buf := make([]byte, r.Int31n(1<<16))
			r.Read(buf)

			// Create the test file
			fileName := fmt.Sprintf("f-%d", j)
			filePath := filepath.Join(tempDir, fileName)
			err := os.WriteFile(filePath, buf, os.FileMode(0o644))
			require.NoError(t, err, "Failed to create the test file: "+filePath)
			fileNames[j] = fileName

			// Compute cksum and file size with our implementation
			d.Write(buf)
			actualCksums[fileName] = d.Sum32()
			actualSizes[fileName] = d.(*digest).n
			d.Reset()
		}

		// Fork and exec coreutils cksum once per batch, with all test files fed into it
		// This significantly reduce the fork + exec syscall overhead just for spawning the cksum process
		// Pass bare file names and run cksum inside tempDir: 1024 full temp paths exceed
		// the 32,767-character command line limit on Windows
		cmd := exec.Command("cksum", fileNames...)
		cmd.Dir = tempDir
		out, err := cmd.Output()
		require.NoError(t, err, "Failed to exec cksum command on batch "+fmt.Sprintf("%d", i))
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		require.Equal(t, 1<<10, len(lines), "cksum did not return all results")

		// Parse output and compare
		// cksum output format: <checksum> <file size> <file name>
		for _, line := range lines {
			// Parsing
			fields := strings.Fields(line)
			expectCksum, err := strconv.ParseUint(fields[0], 10, 32)
			require.NoError(t, err, "Failed to parse to uint32 from string "+fields[0])
			expectSize, err := strconv.ParseUint(fields[1], 10, 64)
			require.NoError(t, err, "Failed to parse to uint64 from string "+fields[1])

			// Comparing
			actualCksum, ok := actualCksums[fields[2]]
			require.True(t, ok, "Failed to find the actual cksum for the file "+fields[2])
			assert.Equal(t, uint32(expectCksum), actualCksum, "Checksum not equal on file "+fields[2])
			actualSize, ok := actualSizes[fields[2]]
			require.True(t, ok, "Failed to find the actual file size for the file "+fields[2])
			assert.Equal(t, expectSize, actualSize, "File size not equal on file "+fields[2])
		}
	}
}
