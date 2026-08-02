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

package server_structs

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestOriginStorageType_IsPosixLike pins down which backends count as
// "POSIX-like" so a future contributor can't silently flip an entry and have
// every downstream call site (self-test, director-test, etc.) start treating
// a remote-protocol backend as local.
func TestOriginStorageType_IsPosixLike(t *testing.T) {
	cases := []struct {
		in       OriginStorageType
		expected bool
	}{
		{OriginStoragePosix, true},
		{OriginStoragePosixv2, true},

		{OriginStorageSSH, false},
		{OriginStorageS3, false},
		{OriginStorageHTTPS, false},
		{OriginStorageGlobus, false},
		{OriginStorageXRoot, false},

		// Unknown / unset values must not be treated as POSIX-like.
		{OriginStorageType(""), false},
		{OriginStorageType("does-not-exist"), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.in), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.in.IsPosixLike())
		})
	}
}

// TestParseExportVolume pins the docker-style split that both export
// construction and standalone-mode validation depend on.  They read the same
// configuration for different purposes, and a disagreement about where the
// federation prefix begins would let a prefix pass validation and then be
// served under a different name.
func TestParseExportVolume(t *testing.T) {
	for _, tc := range []struct {
		name string
		// storage is written slash-separated and compared after cleaning for
		// the running platform: it names a location on this host.
		volume     string
		storage    string
		federation string
	}{
		{"both-sides", "/srv/data:/public", "/srv/data", "/public"},
		{"bare-value-names-both", "/srv/data", "/srv/data", "/srv/data"},
		{"root-federation-prefix", "/srv/data:/", "/srv/data", "/"},
		{"paths-are-cleaned", "/srv//data/:/public/", "/srv/data", "/public"},
		// The split takes the first colon, so a storage prefix containing one
		// cannot be expressed; the caller sees the truncation rather than a
		// silently different prefix.
		{"second-colon-belongs-to-the-federation-side", "C:/data:/public", "C", "/data:/public"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage, federation := ParseExportVolume(tc.volume)
			assert.Equal(t, filepath.Clean(tc.storage), storage)

			// A federation prefix is the path half of a URL, so it is
			// slash-separated everywhere.  Cleaning it as a filesystem path
			// would make it "\public" on Windows and stop it matching
			// anything, including the check that rejects a root prefix.
			assert.Equal(t, tc.federation, federation)
			assert.NotContains(t, federation, "\\",
				"a federation prefix must never pick up the platform separator")
		})
	}
}
