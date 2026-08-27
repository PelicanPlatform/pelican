/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestCheckCacheSentinelLocation(t *testing.T) {
	t.Run("sentinel-not-set", func(t *testing.T) {
		server_utils.ResetTestState()
		err := CheckCacheSentinelLocation()
		assert.NoError(t, err)
	})

	t.Run("sentinel-contains-dir", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Cache_SentinelLocation.Set("/test.txt"))
		err := CheckCacheSentinelLocation()
		require.Error(t, err)
		assert.Equal(t, "invalid Cache.SentinelLocation path. File must not contain a directory. Got /test.txt", err.Error())
	})

	t.Run("sentinel-dne", func(t *testing.T) {
		tmpDir := t.TempDir()
		server_utils.ResetTestState()
		require.NoError(t, param.Cache_SentinelLocation.Set("test.txt"))
		require.NoError(t, param.Cache_NamespaceLocation.Set(tmpDir))
		err := CheckCacheSentinelLocation()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open Cache.SentinelLocation")
	})

	t.Run("sentinel-exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		server_utils.ResetTestState()

		require.NoError(t, param.Cache_SentinelLocation.Set("test.txt"))
		require.NoError(t, param.Cache_NamespaceLocation.Set(tmpDir))

		file, err := os.Create(filepath.Join(tmpDir, "test.txt"))
		require.NoError(t, err)
		file.Close()

		err = CheckCacheSentinelLocation()
		require.NoError(t, err)
	})
}

// TestDirectorTestFilePattern guards the regex that the director-evict endpoint uses to
// decide whether to act on a caller-supplied path (see HandleDirectorEvictRequest). The
// endpoint mints a privileged eviction token, so any path that matches this pattern can be
// evicted from the cache. A pattern that is too loose is a security hole (arbitrary
// eviction / path traversal); one that is too strict silently breaks director-test
// cleanup. Both failure modes are caught here.
func TestDirectorTestFilePattern(t *testing.T) {
	// Paths are assembled from the server_utils constants rather than hardcoded so the test
	// keeps validating the real shape if those constants ever change.
	// base is the valid prefix: "/pelican/monitoring/directorTest"
	base := server_utils.MonitoringBaseNs + "/" + server_utils.DirectorTestDir
	// prefix is a valid path up to (but not including) the filename:
	// "/pelican/monitoring/directorTest/<director-id>/<date>"
	prefix := base + "/director-1.example.com/2026-06-16"
	// validTxt / validCinfo are the two real filenames the cache writes.
	validTxt := prefix + "/" + server_utils.DirectorTest.String() + "-abc123.txt"
	validCinfo := prefix + "/" + server_utils.DirectorTest.String() + "-abc123.txt.cinfo"

	tests := []struct {
		name string
		path string
		want bool
	}{
		// --- Paths that MUST be accepted ---
		{"valid txt file", validTxt, true},
		{"valid cinfo file", validCinfo, true},
		{"director-id with dots and dashes", base + "/director-1.example.com/2026-06-16/" + server_utils.DirectorTest.String() + "-x", true},
		{"director-id with port-like segment", base + "/director-1.example.com:8443/2026-06-16/" + server_utils.DirectorTest.String() + "-x.txt", true},
		{"suffix with extra dashes and dots", prefix + "/" + server_utils.DirectorTest.String() + "-2026-06-16T00.00.00Z.cinfo", true},

		// --- Path traversal: the headline security cases ---
		{"traversal in director-id", base + "/../../etc/passwd/2026-06-16/" + server_utils.DirectorTest.String() + "-x", false},
		{"traversal via dotdot filename", prefix + "/" + server_utils.DirectorTest.String() + "-/../../../etc/passwd", false},
		{"absolute escape after prefix", server_utils.MonitoringBaseNs + "/../../../../etc/passwd", false},
		{"dotdot as date segment", base + "/director-1.example.com/../" + server_utils.DirectorTest.String() + "-x", false},

		// --- Structural violations ---
		{"empty path", "", false},
		{"prefix only, no filename", prefix, false},
		{"prefix with trailing slash", prefix + "/", false},
		{"missing director-id segment", base + "/2026-06-16/" + server_utils.DirectorTest.String() + "-x", false},
		{"missing date segment", base + "/director-1.example.com/" + server_utils.DirectorTest.String() + "-x", false},
		{"empty director-id (double slash)", base + "//2026-06-16/" + server_utils.DirectorTest.String() + "-x", false},
		{"double slash before filename", prefix + "//" + server_utils.DirectorTest.String() + "-x", false},
		{"extra nested directory", prefix + "/extra/" + server_utils.DirectorTest.String() + "-x", false},

		// --- Date-segment validation ---
		{"date wrong format (no dashes)", base + "/director-1.example.com/20260616/" + server_utils.DirectorTest.String() + "-x", false},
		{"date too short", base + "/director-1.example.com/2026-6-16/" + server_utils.DirectorTest.String() + "-x", false},
		{"date with trailing junk", base + "/director-1.example.com/2026-06-16x/" + server_utils.DirectorTest.String() + "-x", false},

		// --- Filename / prefix violations ---
		{"wrong filename prefix", prefix + "/self-test-x", false},
		{"missing dash after director-test", prefix + "/" + server_utils.DirectorTest.String() + "x", false},
		{"empty suffix after dash", prefix + "/" + server_utils.DirectorTest.String() + "-", false},
		{"wrong base namespace", "/pelican/evil/directorTest/director-1.example.com/2026-06-16/" + server_utils.DirectorTest.String() + "-x", false},
		{"wrong subdirectory", server_utils.MonitoringBaseNs + "/selfTest/director-1.example.com/2026-06-16/" + server_utils.DirectorTest.String() + "-x", false},
		{"not anchored at start", "junk" + validTxt, false},
		{"leading dir before base", "/var/lib" + validTxt, false},

		// --- Control-character / injection rejection. [^/] alone would accept these
		// because it only excludes "/"; the pattern uses [^/[:cntrl:]] so control chars
		// are rejected (defends against log injection via the %s-formatted path and
		// against malformed paths reaching the evict/token machinery). ---
		{"trailing newline", validTxt + "\n", false},
		{"trailing carriage return", validTxt + "\r", false},
		{"trailing NUL", validTxt + "\x00", false},
		{"newline embedded in suffix", prefix + "/" + server_utils.DirectorTest.String() + "-foo\nbar", false},
		{"carriage return embedded in suffix", prefix + "/" + server_utils.DirectorTest.String() + "-foo\rbar", false},
		{"tab embedded in suffix", prefix + "/" + server_utils.DirectorTest.String() + "-foo\tbar", false},
		{"newline embedded in director-id", base + "/director-1.ex\nample.com/2026-06-16/" + server_utils.DirectorTest.String() + "-x", false},
		{"newline then traversal", validTxt + "\n/etc/passwd", false},
		{"leading newline", "\n" + validTxt, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, directorTestFilePattern.MatchString(tc.path),
				"path %q: expected match=%v", tc.path, tc.want)
		})
	}
}

// TestDateSubdirPattern covers the helper that selects which day-directories are eligible
// for wholesale cleanup. A false positive here means cleanupOldFilesInDir could recurse
// into an unexpected directory, so non-date names must be firmly rejected.
func TestDateSubdirPattern(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid date", "2026-06-16", true},
		{"valid leap day", "2024-02-29", true},
		{"empty", "", false},
		{"single-digit month", "2026-6-16", false},
		{"no dashes", "20260616", false},
		{"trailing slash", "2026-06-16/", false},
		{"leading junk", "x2026-06-16", false},
		{"trailing junk", "2026-06-16x", false},
		{"dotdot", "..", false},
		{"embedded newline", "2026-06-16\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, dateSubdirPattern.MatchString(tc.in), "input %q", tc.in)
		})
	}
}
