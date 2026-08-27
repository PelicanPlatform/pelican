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

package pstore

import (
	"bytes"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitAndJoinPath(t *testing.T) {
	cases := []struct {
		in     string
		parent string
		name   string
	}{
		{"/a", "/", "a"},
		{"/a/b", "/a", "b"},
		{"/a/b/c", "/a/b", "c"},
		{"/deeply/nested/path/object.dat", "/deeply/nested/path", "object.dat"},
	}
	for _, tc := range cases {
		parent, name := splitPath(tc.in)
		assert.Equal(t, tc.parent, parent, "parent of %s", tc.in)
		assert.Equal(t, tc.name, name, "name of %s", tc.in)
		assert.Equal(t, tc.in, joinPath(parent, name), "round trip of %s", tc.in)
	}
}

func TestPathFromKeyRoundTrip(t *testing.T) {
	for _, p := range []string{"/a", "/a/b", "/a/b/c.dat", "/x-y/z.0"} {
		got, ok := pathFromKey(direntKey(p))
		require.True(t, ok, "key for %s should decode", p)
		assert.Equal(t, p, got)
	}
}

// TestDirentKeyOrdering pins the ordering property the whole index rests on:
// because every key ends in the bare name, a directory's children sort by
// name with no terminator games.  The sibling set /a (a directory), /a.b, and
// /a0b is the case that breaks a full-path key layout, where /a's marker would
// sort between the two files.
func TestDirentKeyOrdering(t *testing.T) {
	keys := [][]byte{
		direntKey("/a0b"),
		direntKey("/a.b"),
		direntKey("/a"),
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })

	names := make([]string, len(keys))
	for i, k := range keys {
		p, ok := pathFromKey(k)
		require.True(t, ok)
		names[i] = p
	}
	assert.Equal(t, []string{"/a", "/a.b", "/a0b"}, names,
		"entries must sort by name regardless of the bytes that follow")
}

// TestSiblingPrefixIsolation checks that a subtree's descendant range cannot
// swallow a sibling whose name merely shares a prefix.  /a's descendants live
// under "pd:/a/" while /a-b's children live under "pd:/a-b\x00", and the two
// diverge at '-' (0x2D) versus '/' (0x2F).
func TestSiblingPrefixIsolation(t *testing.T) {
	descPrefix := descendantsPrefix("/a")

	assert.True(t, bytes.HasPrefix(direntKey("/a/q/r"), descPrefix),
		"a grandchild of /a must fall inside /a's descendant range")
	assert.False(t, bytes.HasPrefix(direntKey("/a-b/x"), descPrefix),
		"a child of sibling /a-b must fall outside /a's descendant range")
	assert.False(t, bytes.HasPrefix(direntKey("/a0b"), descPrefix),
		"sibling file /a0b must fall outside /a's descendant range")

	childPrefix := childrenPrefix("/a")
	assert.True(t, bytes.HasPrefix(direntKey("/a/b"), childPrefix))
	assert.False(t, bytes.HasPrefix(direntKey("/a/b/c"), childPrefix),
		"a grandchild must not appear in the direct-children range")
	assert.False(t, bytes.HasPrefix(direntKey("/a-b"), childPrefix))
}

// TestRootDescendantsCoverEverything documents the root special case: every
// parent path begins with "/", so the root's subtree is the whole index.
func TestRootDescendantsCoverEverything(t *testing.T) {
	prefix := descendantsPrefix("/")
	for _, p := range []string{"/a", "/a/b", "/z/y/x"} {
		assert.True(t, bytes.HasPrefix(direntKey(p), prefix), "%s should be under the root", p)
	}
}

func TestValidatePath(t *testing.T) {
	valid := []string{"/", "/a", "/a/b", "/a b/c", "/a-b/c.d", "/Case/Sensitive"}
	for _, p := range valid {
		assert.NoError(t, validatePath(p), "%q should be valid", p)
	}

	// NUL is rejected because the key encoding uses it as the separator; a
	// name containing one would make pd:/a\x00b ambiguous between the file
	// /a/b and a file literally named "a\x00b" at the root.
	assert.ErrorIs(t, validatePath("/a\x00b"), ErrInvalidPath)
	assert.ErrorIs(t, validatePath("a/b"), ErrInvalidPath, "relative paths are rejected")
}

func TestCleanRelative(t *testing.T) {
	cases := map[string]string{
		"/a/b":      "/a/b",
		"a/b":       "/a/b",
		"/a//b":     "/a/b",
		"/a/./b":    "/a/b",
		"/a/c/../b": "/a/b",
		"/a/b/":     "/a/b",
		"/":         "/",
		"/Data.txt": "/Data.txt",
	}
	for in, want := range cases {
		got, err := cleanRelative(in)
		require.NoError(t, err, "cleaning %q", in)
		assert.Equal(t, want, got, "cleaning %q", in)
	}

	// Escaping the root resolves to "/" via path.Clean rather than reaching
	// outside it, which is the behavior the origin's traversal tests expect.
	got, err := cleanRelative("/../../etc/passwd")
	require.NoError(t, err)
	assert.Equal(t, "/etc/passwd", got, "traversal must be clamped to the root")

	_, err = cleanRelative("")
	assert.ErrorIs(t, err, ErrInvalidPath)

	_, err = cleanRelative("/bad\x00name")
	assert.ErrorIs(t, err, ErrInvalidPath)
}

// TestCaseSensitivity guards against the case-folding bug that affects the
// cache's URL hashing (see docs/pstore-design.md §12): pstore paths must be
// case-sensitive, since POSIX and S3 origins are.
func TestCaseSensitivity(t *testing.T) {
	assert.NotEqual(t, direntKey("/ns/Data.txt"), direntKey("/ns/data.txt"),
		"paths differing only in case must be distinct entries")
}

func TestDirentEncodeRoundTrip(t *testing.T) {
	in := &Dirent{
		Type:       EntryFile,
		Generation: "deadbeef",
		Size:       4096,
		MTimeNanos: 1234567890,
		Mode:       0644,
	}
	b, err := encodeDirent(in)
	require.NoError(t, err)
	out, err := decodeDirent(b)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}
