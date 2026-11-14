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

package lotman

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDiskCapacityOfResolvesMissingPath pins the behavior that keeps a V2 cache
// bootable: InitLotman builds the root lot before NewPersistentCache creates the
// storage directories, so the path it is asked to size does not exist yet. A
// bare statfs would fail with ENOENT and abort startup.
func TestDiskCapacityOfResolvesMissingPath(t *testing.T) {
	base := t.TempDir()

	baseTotal, _, err := diskCapacityOf(base)
	require.NoError(t, err)
	require.Positive(t, baseTotal)

	// Several levels of not-yet-created directory, as the launcher passes
	// (<StorageLocation>/persistent-cache before the cache has made it).
	missing := filepath.Join(base, "persistent-cache", "objects", "deeper")
	total, _, err := diskCapacityOf(missing)
	require.NoError(t, err, "a path that does not exist yet must resolve to its filesystem, not fail")
	require.Equal(t, baseTotal, total, "should report the capacity of the filesystem that will host it")
}

// TestLotDiskPathsOverride covers the V1/V2 split: V1 leaves the override unset
// and falls back to Cache.DataLocations, while the V2 launcher installs the
// persistent cache's own storage directories.
func TestLotDiskPathsOverride(t *testing.T) {
	t.Cleanup(func() { SetLotDiskPaths(nil) })

	SetLotDiskPaths(nil)
	require.Empty(t, getLotDiskPaths(), "V1 must see no override")

	SetLotDiskPaths([]string{"/srv/cache-a", "/srv/cache-b"})
	require.Equal(t, []string{"/srv/cache-a", "/srv/cache-b"}, getLotDiskPaths())

	// The getter must hand back a copy; mutating it must not corrupt the state.
	got := getLotDiskPaths()
	got[0] = "/mutated"
	require.Equal(t, []string{"/srv/cache-a", "/srv/cache-b"}, getLotDiskPaths())
}
