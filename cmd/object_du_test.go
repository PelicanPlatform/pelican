//go:build client

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

package main

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeCollectionPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"osdf:///data/", "/data"},
		{"osdf:///data", "/data"},
		{"osdf:///data/sub/", "/data/sub"},
		{"pelican://origin.example.com:8443/foo/bar/", "/foo/bar"},
		{"/plain/path/", "/plain/path"},
		{"/plain/path?q=1", "/plain/path"},
		{"osdf:///", "/"},
		{"osdf://host", "/"},
		// Duplicate slashes anywhere in the path must collapse; otherwise the
		// ancestor math would treat "/a//b" as a strict descendant of "/a/"
		// rather than "/a", producing bogus subtree totals.
		{"osdf:///foo//bar/", "/foo/bar"},
		{"osdf:///foo///bar//baz", "/foo/bar/baz"},
		{"/plain//path", "/plain/path"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, normalizeCollectionPath(c.in), "input %q", c.in)
	}
}

func TestNormalizeEntryPath(t *testing.T) {
	assert.Equal(t, "/foo", normalizeEntryPath("/foo/"))
	assert.Equal(t, "/foo/bar", normalizeEntryPath("/foo/bar"))
	assert.Equal(t, "/", normalizeEntryPath("/"))
	// Listing entries can arrive with doubled slashes from origins that don't
	// re-canonicalize before serving; normalize them here so the ancestor
	// walk keys match normalizeCollectionPath's output.
	assert.Equal(t, "/foo/bar", normalizeEntryPath("/foo//bar"))
	assert.Equal(t, "/foo/bar", normalizeEntryPath("//foo/bar/"))
	assert.Equal(t, "/", normalizeEntryPath(""))
}

func TestDepthFromRoot(t *testing.T) {
	assert.Equal(t, 0, depthFromRoot("/a", "/a"))
	assert.Equal(t, 1, depthFromRoot("/a", "/a/b"))
	assert.Equal(t, 2, depthFromRoot("/a", "/a/b/c"))
	assert.Equal(t, 0, depthFromRoot("/", "/"))
	assert.Equal(t, 1, depthFromRoot("/", "/a"))
	// Non-descendant should still normalize to something reasonable
	// (we don't drive user output from this path in practice).
	assert.Equal(t, 0, depthFromRoot("/a/b", "/a/b"))
}

func TestForEachAncestorInclusiveWalksToRoot(t *testing.T) {
	var visited []string
	forEachAncestorInclusive("/a/b/c", "/a", func(p string) {
		visited = append(visited, p)
	})
	assert.Equal(t, []string{"/a/b/c", "/a/b", "/a"}, visited)
}

func TestForEachAncestorInclusiveStopsAtRoot(t *testing.T) {
	var visited []string
	forEachAncestorInclusive("/a", "/a", func(p string) {
		visited = append(visited, p)
	})
	assert.Equal(t, []string{"/a"}, visited)
}

func TestFormatDuLineDefault(t *testing.T) {
	line := formatDuLine(duReport{Path: "/a", Bytes: 12345}, false, false)
	assert.Equal(t, "12345\t/a", line)
}

func TestFormatDuLineHumanReadable(t *testing.T) {
	// humanize.IBytes uses binary units (KiB, MiB, ...).
	// 1_048_576 -> "1.0 MiB"
	line := formatDuLine(duReport{Path: "/a", Bytes: 1_048_576}, true, false)
	assert.Equal(t, "1.0 MiB\t/a", line)
}

func TestFormatDuLineWithCount(t *testing.T) {
	line := formatDuLine(duReport{Path: "/a", Bytes: 100, Objects: 3, Collections: 2}, false, true)
	assert.Equal(t, "100\t3\t2\t/a", line)
}

// TestDuShorthandBindings guards two flag-shorthand bindings people rely on
// muscle memory for: `-h` must set --human-readable (matching GNU du), and
// `--help` must still trigger cobra's help path rather than the flag we
// pre-registered so cobra wouldn't grab `-h` for itself. Both would regress
// silently without an explicit test.
func TestDuShorthandBindings(t *testing.T) {
	// Reset the flag values on the shared duCmd between subtests -- these
	// stick around across parses because duCmd is a package-level singleton.
	reset := func() {
		duCmd.Flags().VisitAll(func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
	}

	t.Run("-h binds to --human-readable", func(t *testing.T) {
		reset()
		require.NoError(t, duCmd.ParseFlags([]string{"-h", "osdf:///x"}))
		v, err := duCmd.Flags().GetBool("human-readable")
		require.NoError(t, err)
		assert.True(t, v, "-h should set --human-readable=true")
		hv, err := duCmd.Flags().GetBool("help")
		require.NoError(t, err)
		assert.False(t, hv, "-h must not toggle --help")
	})

	t.Run("--help still toggles help", func(t *testing.T) {
		reset()
		require.NoError(t, duCmd.ParseFlags([]string{"--help"}))
		hv, err := duCmd.Flags().GetBool("help")
		require.NoError(t, err)
		assert.True(t, hv)
	})
}
