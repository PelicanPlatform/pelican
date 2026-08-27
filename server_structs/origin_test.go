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

// TestOriginStorageType_SupportsSelfTest pins down which backends accept the
// write-read probe, so a future contributor can't silently flip an entry and
// have the origin self-test and director test start probing a remote-protocol
// backend -- which would mean egress and credentials on every health check.
func TestOriginStorageType_SupportsSelfTest(t *testing.T) {
	cases := []struct {
		in       OriginStorageType
		expected bool
	}{
		{OriginStoragePosix, true},
		{OriginStoragePosixv2, true},
		// pstore is not a POSIX filesystem, but it is local and writable.
		{OriginStoragePStore, true},

		{OriginStorageSSH, false},
		{OriginStorageS3, false},
		{OriginStorageS3v2, false},
		{OriginStorageHTTPS, false},
		{OriginStorageHTTPSv2, false},
		{OriginStorageGlobus, false},
		{OriginStorageGlobusv2, false},
		{OriginStorageXRoot, false},

		// Unknown / unset values must not be probed.
		{OriginStorageType(""), false},
		{OriginStorageType("does-not-exist"), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.in), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.in.SupportsSelfTest())
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

// TestOriginStorageType_IsPosixLike pins the distinction that matters most
// here: pstore can self-test, but its StoragePrefix is not a host path.
// Conflating the two would send a directory walk, a stat, or an os.Root at a
// path inside the store's namespace -- "/" being an ordinary value for it.
func TestOriginStorageType_IsPosixLike(t *testing.T) {
	for _, hostPath := range []OriginStorageType{
		OriginStoragePosix, OriginStoragePosixv2,
	} {
		assert.True(t, hostPath.IsPosixLike(), "%s stores data at a host path", hostPath)
	}
	for _, notHostPath := range []OriginStorageType{
		OriginStoragePStore, OriginStorageSSH, OriginStorageS3, OriginStorageS3v2,
		OriginStorageHTTPS, OriginStorageHTTPSv2, OriginStorageGlobus,
		OriginStorageGlobusv2, OriginStorageXRoot,
	} {
		assert.False(t, notHostPath.IsPosixLike(),
			"%s does not store data at a host path", notHostPath)
	}

	// The two predicates disagree on pstore, and that disagreement is the point.
	assert.True(t, OriginStoragePStore.SupportsSelfTest())
	assert.False(t, OriginStoragePStore.IsPosixLike())
}

// TestOriginStorageType_UsesXRootD pins the other half: pstore is served
// directly by the pelican process and must never launch XRootD.
func TestOriginStorageType_UsesXRootD(t *testing.T) {
	for _, native := range []OriginStorageType{
		OriginStoragePosixv2, OriginStorageSSH, OriginStorageS3v2,
		OriginStorageHTTPSv2, OriginStorageGlobusv2, OriginStoragePStore,
	} {
		assert.False(t, native.UsesXRootD(), "%s is served natively", native)
	}
	for _, xrootd := range []OriginStorageType{
		OriginStoragePosix, OriginStorageS3, OriginStorageHTTPS,
		OriginStorageGlobus, OriginStorageXRoot,
	} {
		assert.True(t, xrootd.UsesXRootD(), "%s is fronted by XRootD", xrootd)
	}
}

// TestParseOriginStorageType covers the pstore spelling reaching the parser.
func TestParseOriginStorageType(t *testing.T) {
	got, err := ParseOriginStorageType("pstore")
	assert.NoError(t, err)
	assert.Equal(t, OriginStoragePStore, got)

	_, err = ParseOriginStorageType("nonsense")
	assert.ErrorIs(t, err, ErrUnknownOriginStorageType)
}
