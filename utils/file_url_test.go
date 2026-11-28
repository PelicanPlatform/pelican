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

package utils

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileURLRoundTrip: a local path survives being spelled as a file URL and
// read back, including characters that must be percent-encoded.  A name
// containing "%41" must come back as written, not decoded a second time into
// "A".
func TestFileURLRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"plain.dat", "with space.dat", "a%41.dat", "hash#query?.dat"} {
		if runtime.GOOS == "windows" && strings.ContainsAny(name, "?") {
			continue // not a legal Windows file name
		}
		path := filepath.Join(dir, name)
		parsed, err := url.Parse(PathToFileURL(path).String())
		require.NoError(t, err)
		assert.Equal(t, "file", parsed.Scheme)
		assert.Empty(t, parsed.Host)
		assert.Equal(t, path, FileURLToPath(parsed), "round trip of %q", name)
	}
}

// TestFileURLWindowsDriveLetter: a drive-letter path gains the leading slash
// RFC 8089 requires (file:///C:/...), and loses it again on the way back.
func TestFileURLWindowsDriveLetter(t *testing.T) {
	if runtime.GOOS != "windows" {
		// The conversion is only defined where filepath understands drive
		// letters; elsewhere C:/x is a relative path.
		u := PathToFileURL("C:/data/obj")
		assert.Equal(t, "/C:/data/obj", u.Path, "the leading slash is added whatever the platform")
		return
	}
	path := `C:\data\obj.dat`
	u := PathToFileURL(path)
	assert.Equal(t, "file:///C:/data/obj.dat", u.String())
	parsed, err := url.Parse(u.String())
	require.NoError(t, err)
	assert.Equal(t, path, FileURLToPath(parsed))
}

// TestFileURLNeverNamesAHost: a path with repeated leading slashes still
// yields a URL for this machine, so a redirect built from it cannot be read
// as pointing at another host.
func TestFileURLNeverNamesAHost(t *testing.T) {
	for _, path := range []string{"//evil.example/x", "///evil.example/x", `\\evil.example\x`} {
		u := PathToFileURL(path)
		parsed, err := url.Parse(u.String())
		require.NoError(t, err)
		assert.Empty(t, parsed.Host, "%q", path)
		assert.False(t, strings.HasPrefix(parsed.Path, "//"), "%q became %q", path, parsed.Path)
	}
}
