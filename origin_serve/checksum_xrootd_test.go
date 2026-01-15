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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test serialization and deserialization roundtrip
func TestXRootDChecksumSerialization(t *testing.T) {
	testTime := time.Unix(1609459200, 0)     // 2021-01-01 00:00:00 UTC
	checksumTime := time.Unix(1609459205, 0) // 5 seconds later

	tests := []struct {
		name      string
		alg       string
		checksum  []byte
		wantError bool
	}{
		{
			name:     "MD5 checksum",
			alg:      "md5",
			checksum: []byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92},
		},
		{
			name:     "SHA1 checksum",
			alg:      "sha1",
			checksum: []byte{0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09},
		},
		{
			name:     "CRC32 checksum",
			alg:      "crc32",
			checksum: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:      "Name too long",
			alg:       "this_is_a_very_long_name_that_exceeds_limit",
			checksum:  []byte{0x00},
			wantError: true,
		},
		{
			name:      "Checksum too long",
			alg:       "test",
			checksum:  make([]byte, 100),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			serialized, err := serializeXRootDChecksum(tt.alg, tt.checksum, testTime, checksumTime)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Expected size: 16 (name) + 8 (fmTime) + 4 (csTime) + 2 (Rsvd1) + 1 (Rsvd2) + 1 (Length) + 64 (Value)
			assert.Equal(t, xrootdBinarySize, len(serialized))

			// Deserialize
			name, checksum, fileModTime, err := deserializeXRootDChecksum(serialized)
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tt.alg, name)
			assert.Equal(t, tt.checksum, checksum)
			assert.Equal(t, testTime.Unix(), fileModTime.Unix())
		})
	}
}
