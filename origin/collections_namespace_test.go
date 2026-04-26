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

package origin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/server_utils"
)

// TestNamespaceWithinExport pins the contract that collections may
// be created at any sub-path of an exported prefix — not only at the
// prefix itself. The handler used to require an exact equality
// against export.FederationPrefix, which forced operators to either
// export every collection's path explicitly or to scaffold every
// collection at the top of an export. Per the design ticket, an
// origin exporting `/org/foo` must accept a collection rooted at
// `/org/foo/projectA` or any deeper path.
func TestNamespaceWithinExport(t *testing.T) {
	exports := []server_utils.OriginExport{
		{FederationPrefix: "/org/foo"},
		{FederationPrefix: "/data/cms"},
	}

	t.Run("exact-prefix match accepted", func(t *testing.T) {
		assert.True(t, namespaceWithinExport("/org/foo", exports),
			"a collection rooted exactly at an export's prefix is the simplest case")
	})

	t.Run("immediate sub-path accepted", func(t *testing.T) {
		assert.True(t, namespaceWithinExport("/org/foo/projectA", exports),
			"the new flexibility: one level beneath an exported prefix")
	})

	t.Run("deep sub-path accepted", func(t *testing.T) {
		assert.True(t, namespaceWithinExport("/org/foo/team/2026", exports),
			"any depth below an exported prefix is fine — operators may want a per-year or per-project tree")
	})

	t.Run("matches against second export entry", func(t *testing.T) {
		assert.True(t, namespaceWithinExport("/data/cms/runC", exports),
			"each entry in the export list is consulted independently")
	})

	t.Run("similar but distinct prefix rejected", func(t *testing.T) {
		assert.False(t, namespaceWithinExport("/org/foobar", exports),
			"`/org/foo` MUST NOT match `/org/foobar` — the next byte after the prefix has to be a path separator, not just any continuation")
	})

	t.Run("similar prefix at depth rejected", func(t *testing.T) {
		assert.False(t, namespaceWithinExport("/org/foobar/x", exports),
			"the path-separator guard applies regardless of how deep the requested namespace goes")
	})

	t.Run("unrelated namespace rejected", func(t *testing.T) {
		assert.False(t, namespaceWithinExport("/somewhere/else", exports),
			"a path that doesn't share any export's prefix has nothing to anchor on")
	})

	t.Run("trailing slash on requested namespace also accepted", func(t *testing.T) {
		// path.Clean would normally normalize this, but the handler
		// passes the raw namespace through. The HasPrefix check
		// produces the right answer either way: "/org/foo/" starts
		// with "/org/foo/" so it matches the descendant clause.
		assert.True(t, namespaceWithinExport("/org/foo/", exports))
	})

	t.Run("empty namespace rejected", func(t *testing.T) {
		assert.False(t, namespaceWithinExport("", exports),
			"an empty namespace is never valid — collections must live somewhere")
	})

	t.Run("relative path rejected", func(t *testing.T) {
		assert.False(t, namespaceWithinExport("org/foo", exports),
			"the namespace must be absolute (start with `/`) to match the path-shape invariant the ACL layer relies on elsewhere")
	})

	t.Run("namespace longer than prefix without separator rejected", func(t *testing.T) {
		// Explicit "the next byte must be `/`" assertion.
		assert.False(t, namespaceWithinExport("/org/fooX", exports))
	})

	t.Run("export with empty prefix never matches", func(t *testing.T) {
		// Defensively guard against a misconfigured export with an
		// empty FederationPrefix — without the empty-check inside
		// namespaceWithinExport, every requested namespace would
		// match it because every string starts with "".
		ex := []server_utils.OriginExport{{FederationPrefix: ""}}
		assert.False(t, namespaceWithinExport("/anything", ex),
			"exports with an empty FederationPrefix must not be treated as wildcards")
	})

	t.Run("no exports configured rejects everything", func(t *testing.T) {
		assert.False(t, namespaceWithinExport("/org/foo", nil))
		assert.False(t, namespaceWithinExport("/org/foo", []server_utils.OriginExport{}))
	})
}
