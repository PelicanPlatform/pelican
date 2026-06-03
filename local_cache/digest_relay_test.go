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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
)

// TestFormatDigestHeader checks the RFC 3230 encoding per algorithm: MD5/SHA
// are base64, CRC32/CRC32C are lowercase hex, and unknown types are skipped.
func TestFormatDigestHeader(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", formatDigestHeader(nil))
		assert.Equal(t, "", formatDigestHeader([]Checksum{}))
	})

	t.Run("crc32c is hex", func(t *testing.T) {
		got := formatDigestHeader([]Checksum{
			{Type: ChecksumCRC32C, Value: []byte{0x57, 0x4a, 0x2b, 0xf2}},
		})
		assert.Equal(t, "crc32c=574a2bf2", got)
	})

	t.Run("md5 is base64", func(t *testing.T) {
		// 16 zero bytes -> base64 of all-zero MD5-length input.
		got := formatDigestHeader([]Checksum{
			{Type: ChecksumMD5, Value: make([]byte, 16)},
		})
		assert.Equal(t, "md5=AAAAAAAAAAAAAAAAAAAAAA==", got)
	})

	t.Run("multiple joined with comma-space", func(t *testing.T) {
		got := formatDigestHeader([]Checksum{
			{Type: ChecksumMD5, Value: make([]byte, 16)},
			{Type: ChecksumCRC32C, Value: []byte{0x00, 0x00, 0x00, 0x01}},
		})
		assert.Equal(t, "md5=AAAAAAAAAAAAAAAAAAAAAA==, crc32c=00000001", got)
	})
}

// TestClientChecksumsToCache verifies algorithm mapping and that a server
// (OriginVerified) checksum wins over a client-computed one of the same type,
// so the same algorithm is never emitted twice.
func TestClientChecksumsToCache(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		assert.Nil(t, clientChecksumsToCache(nil))
	})

	t.Run("dedups crc32c across server and client", func(t *testing.T) {
		res := &client.TransferResults{
			ServerChecksums: []client.ChecksumInfo{
				{Algorithm: client.AlgMD5, Value: []byte("0123456789abcdef")},
				{Algorithm: client.AlgCRC32C, Value: []byte{1, 2, 3, 4}},
			},
			ClientChecksums: []client.ChecksumInfo{
				// Same algorithm as a server entry -- must be dropped.
				{Algorithm: client.AlgCRC32C, Value: []byte{9, 9, 9, 9}},
			},
		}
		out := clientChecksumsToCache(res)
		require.Len(t, out, 2, "crc32c should appear exactly once")

		byType := map[ChecksumType]Checksum{}
		for _, c := range out {
			byType[c.Type] = c
		}
		// The server's crc32c (OriginVerified) must win.
		crc, ok := byType[ChecksumCRC32C]
		require.True(t, ok)
		assert.True(t, crc.OriginVerified, "server checksum should win over client")
		assert.Equal(t, []byte{1, 2, 3, 4}, crc.Value)
		assert.True(t, byType[ChecksumMD5].OriginVerified)
	})

	t.Run("client-only checksum is kept and not origin-verified", func(t *testing.T) {
		res := &client.TransferResults{
			ClientChecksums: []client.ChecksumInfo{
				{Algorithm: client.AlgCRC32C, Value: []byte{5, 6, 7, 8}},
			},
		}
		out := clientChecksumsToCache(res)
		require.Len(t, out, 1)
		assert.Equal(t, ChecksumCRC32C, out[0].Type)
		assert.False(t, out[0].OriginVerified)
	})
}

// TestStatChecksumsToCache verifies the hex-decode + name mapping for the
// digests returned by client.DoStat (used on an uncached HEAD), and that
// malformed/unknown entries are skipped without error.
func TestStatChecksumsToCache(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Nil(t, statChecksumsToCache(nil))
		assert.Nil(t, statChecksumsToCache(map[string]string{}))
	})

	t.Run("decodes known algorithms", func(t *testing.T) {
		out := statChecksumsToCache(map[string]string{
			"crc32c": "574a2bf2",
			"md5":    "00112233445566778899aabbccddeeff",
		})
		byType := map[ChecksumType]Checksum{}
		for _, c := range out {
			byType[c.Type] = c
			assert.True(t, c.OriginVerified, "origin stat checksums are origin-verified")
		}
		require.Contains(t, byType, ChecksumCRC32C)
		assert.Equal(t, []byte{0x57, 0x4a, 0x2b, 0xf2}, byType[ChecksumCRC32C].Value)
		require.Contains(t, byType, ChecksumMD5)
		assert.Len(t, byType[ChecksumMD5].Value, 16)
	})

	t.Run("skips unknown algorithm and malformed hex", func(t *testing.T) {
		out := statChecksumsToCache(map[string]string{
			"crc32c":    "574a2bf2",
			"bogus-alg": "deadbeef",
			"md5":       "nothexnothex", // odd length / non-hex
		})
		// Only crc32c survives.
		require.Len(t, out, 1)
		assert.Equal(t, ChecksumCRC32C, out[0].Type)
	})
}

// TestFormatDigestHeaderRoundTrip ties the two halves together: checksums that
// the cache persisted (via clientChecksumsToCache) format into a valid RFC 3230
// header that mirrors what the POSIXv2 origin emits (crc32c as hex).
func TestFormatDigestHeaderRoundTrip(t *testing.T) {
	res := &client.TransferResults{
		ServerChecksums: []client.ChecksumInfo{
			{Algorithm: client.AlgCRC32C, Value: []byte{0x57, 0x4a, 0x2b, 0xf2}},
		},
	}
	cks := clientChecksumsToCache(res)
	header := formatDigestHeader(cks)
	assert.Equal(t, "crc32c=574a2bf2", header)
}
