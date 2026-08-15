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

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestServiceDigestDefaults verifies that per-service digest memory drives
// the default verification set: unknown services get the platform default
// (CRC32C), while services that previously reported digests get those.
func TestServiceDigestDefaults(t *testing.T) {
	// Unknown service: platform default.
	assert.Equal(t, []ChecksumType{AlgDefault}, defaultChecksumTypesForService("origin-a.example.com:8443"))

	// A service that reported MD5 becomes the default for that service only.
	rememberServiceDigests("origin-a.example.com:8443", []ChecksumInfo{
		{Algorithm: AlgMD5, Value: []byte{0x01}},
	})
	assert.Equal(t, []ChecksumType{AlgMD5}, defaultChecksumTypesForService("origin-a.example.com:8443"))
	assert.Equal(t, []ChecksumType{AlgDefault}, defaultChecksumTypesForService("origin-b.example.com:8443"))

	// A later report (e.g. after a server upgrade) replaces the remembered set.
	rememberServiceDigests("origin-a.example.com:8443", []ChecksumInfo{
		{Algorithm: AlgCRC32C, Value: []byte{0x02}},
		{Algorithm: AlgMD5, Value: []byte{0x03}},
	})
	assert.Equal(t, []ChecksumType{AlgCRC32C, AlgMD5}, defaultChecksumTypesForService("origin-a.example.com:8443"))

	// Empty reports and empty hosts must not poison the cache.
	rememberServiceDigests("origin-a.example.com:8443", nil)
	assert.Equal(t, []ChecksumType{AlgCRC32C, AlgMD5}, defaultChecksumTypesForService("origin-a.example.com:8443"))
	rememberServiceDigests("", []ChecksumInfo{{Algorithm: AlgSHA1}})
	assert.Equal(t, []ChecksumType{AlgDefault}, defaultChecksumTypesForService(""))
}
