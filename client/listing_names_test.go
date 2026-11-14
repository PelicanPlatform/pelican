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
	"net/url"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// namesWorthEscaping is the table both listing tests share.  A name whose
// encoded and decoded spellings are identical can never catch a mistake
// here, so most of these are names that differ: '%' fails loudly, '#' and
// '?' fail silently by naming something else, and the rest are characters
// that a person will eventually put in a filename.
var namesWorthEscaping = []string{
	"plain.txt",
	"with space.txt",
	"literal%.txt",
	"a%zz.txt",
	"pct%25.txt",
	"hash#frag.txt",
	"question?mark.txt",
	"plus+sign.txt",
	"amp&eq=1.txt",
	"semi;colon.txt",
	"star*name.txt",
	"quote'single.txt",
	"brack[et].txt",
	"back\\slash.txt",
	"日本語.txt",
	"tab\tname.txt",
}

// TestEscapeNamespacePathRoundTrips is the property the split between
// FileInfo.Name and FileInfo.EscapedPath rests on: the escaped form has to
// parse as a URL and decode back to the name we started with.  Without it
// the two fields could drift apart and a caller using EscapedPath would
// reach a different object than the one Name describes.
func TestEscapeNamespacePathRoundTrips(t *testing.T) {
	for _, name := range namesWorthEscaping {
		decoded := "/my-namespace/" + name
		escaped := escapeNamespacePath(decoded)

		parsed, err := url.Parse("pelican://example.org" + escaped)
		require.NoError(t, err, "escaped form of %q does not parse: %q", name, escaped)
		assert.Equal(t, decoded, parsed.Path,
			"%q does not survive the round trip through %q", name, escaped)
	}
}

// TestEscapeNamespacePathKeepsSeparators guards the one thing a naive
// url.PathEscape of the whole string would get wrong.
func TestEscapeNamespacePathKeepsSeparators(t *testing.T) {
	assert.Equal(t, "/a/b/c.txt", escapeNamespacePath("/a/b/c.txt"))
	assert.Equal(t, "/dir%20with%20space/child.txt",
		escapeNamespacePath("/dir with space/child.txt"))
}

// TestEscapeNamespacePathHandlesWhatJoinPathDropped is the regression.
// url.JoinPath returns ("", err) for a name holding an invalid percent
// escape, and the error used to be discarded, so these two objects were
// emitted with an empty name and disappeared from the listing entirely.
func TestEscapeNamespacePathHandlesWhatJoinPathDropped(t *testing.T) {
	for _, name := range []string{"literal%.txt", "a%zz.txt"} {
		joined, err := url.JoinPath("/my-namespace", name)
		require.Error(t, err, "url.JoinPath unexpectedly accepted %q", name)
		require.Empty(t, joined, "the dropped-name failure mode has changed")

		escaped := escapeNamespacePath("/my-namespace/" + name)
		assert.NotEmpty(t, escaped)
		parsed, err := url.Parse("pelican://example.org" + escaped)
		require.NoError(t, err)
		assert.Equal(t, "/my-namespace/"+name, parsed.Path)
	}
}

// TestEscapedPathBaseIsStillAddressable covers the step PelicanFS.ReadDir
// takes: it reports path.Base of an entry as the name, and io/fs requires
// that name to be one the same filesystem's Open accepts.  Taking the base
// of the decoded Name would hand back a bare "a#b.txt", which parses into a
// different object with a fragment, or "a%zz.txt", which does not parse at
// all.  Taking it from EscapedPath has to survive both.
func TestEscapedPathBaseIsStillAddressable(t *testing.T) {
	for _, name := range namesWorthEscaping {
		escapedBase := path.Base(escapeNamespacePath("/my-namespace/" + name))

		parsed, err := url.Parse("pelican://example.org/my-namespace/" + escapedBase)
		require.NoError(t, err, "base name %q does not parse", escapedBase)
		assert.Equal(t, "/my-namespace/"+name, parsed.Path,
			"base of %q reaches the wrong object", name)
		assert.Empty(t, parsed.Fragment, "%q leaked a fragment", name)
		assert.Empty(t, parsed.RawQuery, "%q leaked a query", name)
	}
}
