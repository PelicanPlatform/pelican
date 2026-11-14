//go:build !windows

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

package local_cache

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assumeNameFolding makes the names view believe the filesystem does (or
// does not) fold names, so the exact view can be tested on any filesystem.
// The tests' names never differ only in case, so pretending changes nothing
// else.
func assumeNameFolding(t *testing.T, folds bool) {
	prev := tierNameFoldingProbe
	tierNameFoldingProbe = func(*posixTierBackend) (bool, error) { return folds, nil }
	t.Cleanup(func() { tierNameFoldingProbe = prev })
}

func TestTierExactNameSpelling(t *testing.T) {
	name, ok := newTierExactName("pelican://fed/public/data/set@1/My%20file%25.bin")
	require.True(t, ok)
	assert.Equal(t, "names/public/data/set@1/My file%.bin", name.currentPath(), "names are kept exactly")

	for _, sourceURL := range []string{
		"",
		"pelican://fed/ns/a%2Fb",      // would decode into a/b
		"pelican://fed/ns/nul%00byte", // not a file name
		"pelican://fed/ns/" + strings.Repeat("x", 300),    // too long
		"pelican://fed/ns//double",                        // not canonical
		"pelican://fed/ns/./dot",                          // not canonical
		"pelican://fed/ns/" + strings.Repeat("y", 256),    // too long by one
		"pelican://fed/ns/" + strings.Repeat("z", 10_000), // far too long
	} {
		_, ok := newTierExactName(sourceURL)
		assert.False(t, ok, "%q cannot be named", sourceURL)
	}
	_, ok = newTierLogicalName("pelican://fed/ns/a%2Fb", "e", false)
	assert.False(t, ok, "the versioned view must not let an encoded slash take another object's name either")
}

// TestTierExactNamesView follows an object through an exact-names view: its
// name is its federation path, unescaped, with no versions beside it, and it
// always leads to the current version or to nothing.
func TestTierExactNamesView(t *testing.T) {
	assumeNameFolding(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{NamesView: "exact"})
	env.public["/public"] = true

	const (
		sourceURL = "pelican://fed.example/public/data/set@1/My%20file%25.bin"
		name      = "names/public/data/set@1/My file%.bin"
		dir       = "names/public/data/set@1"
	)
	v1 := bytes.Repeat([]byte("version one\n"), 400)
	v2 := bytes.Repeat([]byte("version two\n"), 400)
	start := time.Now().Add(-time.Hour)
	listing := func() []string {
		entries, err := os.ReadDir(filepath.Join(env.dir, filepath.FromSlash(dir)))
		if err != nil {
			return nil
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return names
	}

	h1 := env.storeVersion(t, ctx, sourceURL, `"v1"`, v1, start)
	require.NoError(t, env.uploader.processObject(ctx, h1))
	got, err := env.readName(t, name)
	require.NoError(t, err, "the exact name must resolve within an os.Root")
	assert.Equal(t, v1, got)
	assert.Equal(t, []string{"My file%.bin"}, listing(), "no versions beside the name")
	assert.True(t, strings.HasPrefix(env.readlink(name), "../../../../objects/"), "the link is relative: %s", env.readlink(name))

	// A newer version takes the name; an older one tiered later does not.
	h2 := env.storeVersion(t, ctx, sourceURL, `"v2"`, v2, start.Add(time.Minute))
	require.NoError(t, env.uploader.processObject(ctx, h2))
	got, err = env.readName(t, name)
	require.NoError(t, err)
	assert.Equal(t, v2, got)
	h0 := env.storeVersion(t, ctx, sourceURL, `"v0"`, bytes.Repeat([]byte("version zero\n"), 400), start.Add(-time.Minute))
	require.NoError(t, env.db.SetLatestETag(env.db.ObjectHash(sourceURL), `"v2"`, start.Add(time.Minute)))
	require.NoError(t, env.uploader.processObject(ctx, h0))
	got, err = env.readName(t, name)
	require.NoError(t, err)
	assert.Equal(t, v2, got, "only the current version has the name")
	assert.Equal(t, []string{"My file%.bin"}, listing())

	// The sweep restores a lost name, removes what does not belong -- a
	// versioned-style link, a link to a superseded version, a stray file --
	// and gives no name to a version that is not current.
	require.NoError(t, os.Remove(filepath.Join(env.dir, filepath.FromSlash(name))))
	plant := func(dest, file string) {
		require.NoError(t, os.Symlink(dest, filepath.Join(env.dir, filepath.FromSlash(dir), file)))
	}
	plant("My file%.bin@v1", "My file%.bin")
	plant("../../../../objects/"+env.target.objectKey(h1), "My file%.bin@v1")
	plant("../../../../objects/"+env.target.objectKey(h1), "Other.bin")
	require.NoError(t, os.WriteFile(filepath.Join(env.dir, filepath.FromSlash(dir), "stray.txt"), []byte("x"), 0o644))
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Equal(t, []string{"My file%.bin"}, listing())
	got, err = env.readName(t, name)
	require.NoError(t, err)
	assert.Equal(t, v2, got)
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Equal(t, []string{"My file%.bin"}, listing(), "a healthy view stays as it is")

	// Learning of a version that is not on the target withdraws the name at
	// once; once that version is tiered, the name leads to it.
	h3 := env.storeVersion(t, ctx, sourceURL, `"v3"`, bytes.Repeat([]byte("version three\n"), 400), time.Now())
	assert.Empty(t, env.readlink(name), "the name must not serve a superseded version")
	require.NoError(t, env.uploader.processObject(ctx, h3))
	assert.NotEmpty(t, env.readlink(name))

	// Deleting the current version withdraws its name and the emptied
	// directories.
	require.NoError(t, env.storage.Delete(h3))
	assert.Empty(t, env.readlink(name))
	for _, h := range []InstanceHash{h0, h1, h2} {
		require.NoError(t, env.storage.Delete(h))
	}
	assert.NoDirExists(t, filepath.Join(env.dir, "names", "public"))
}

// TestTierExactNamesViewSwitch: a tree left by the other spelling is
// replaced by the sweep, in either direction.
func TestTierExactNamesViewSwitch(t *testing.T) {
	assumeNameFolding(t, false)
	const sourceURL = "pelican://fed/public/switch.bin"
	data := bytes.Repeat([]byte("s"), 4096)

	for _, tc := range []struct{ from, to string }{{"versioned", "exact"}, {"exact", "versioned"}} {
		t.Run(tc.from+"To"+tc.to, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			env := newPosixTierEnv(t, ctx, TierTargetConfig{NamesView: tc.from})
			env.public["/public"] = true
			hash := env.storeVersion(t, ctx, sourceURL, "e", data, time.Now())
			require.NoError(t, env.uploader.processObject(ctx, hash))

			// The same tree, read by a view with the other spelling.
			posix, ok := env.target.backend.(*posixTierBackend)
			require.True(t, ok)
			names, err := newTierNameView(posix, true, tc.to == "exact")
			require.NoError(t, err)
			env.target.names = names
			require.NoError(t, env.checker.RunTierScan(ctx))

			entries, err := os.ReadDir(filepath.Join(env.dir, "names", "public"))
			require.NoError(t, err)
			var got []string
			for _, e := range entries {
				got = append(got, e.Name())
			}
			want := []string{"switch.bin"}
			if tc.to == "versioned" {
				want = []string{"switch.bin", "switch.bin@e"}
			}
			assert.ElementsMatch(t, want, got)
			read, err := env.readName(t, "names/public/switch.bin")
			require.NoError(t, err)
			assert.Equal(t, data, read)
		})
	}
}

// TestTierExactNamesViewRefusedWhenFolding: exact names cannot be kept apart
// on a filesystem that folds them, so such a target does not open.
func TestTierExactNamesViewRefusedWhenFolding(t *testing.T) {
	assumeNameFolding(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := TierTargetConfig{ProviderURL: fileTargetURL(filepath.Join(t.TempDir(), "shared")), MaxSize: 1 << 30, NamesView: "exact"}
	require.NoError(t, cfg.validate())
	_, err := newTierTarget(ctx, cfg)
	assert.ErrorContains(t, err, "NamesView: exact")

	// The default spelling copes by escaping.
	cfg.NamesView = ""
	target, err := newTierTarget(ctx, cfg)
	require.NoError(t, err)
	assert.True(t, target.names.foldSafe)
	_ = target.Close()
}

func TestTierNamesViewConfig(t *testing.T) {
	good := TierTargetConfig{ProviderURL: "file:///mnt/shared/cache", MaxSize: 1, NamesView: "Exact"}
	require.NoError(t, good.validate())
	assert.True(t, good.exactNames(), "the value is not case-sensitive")
	assert.True(t, good.namesViewEnabled())

	off := TierTargetConfig{ProviderURL: "file:///mnt/shared/cache", MaxSize: 1, NamesView: "None"}
	require.NoError(t, off.validate())
	assert.False(t, off.namesViewEnabled())
	assert.False(t, off.exactNames())

	for name, cfg := range map[string]TierTargetConfig{
		"unknown value":   {ProviderURL: "file:///mnt/x", MaxSize: 1, NamesView: "flat"},
		"not shared":      {ProviderURL: "s3://bucket", MaxSize: 1, NamesView: "exact"},
		"not shared, too": {WebDavUrl: "https://door.example/data", MaxSize: 1, NamesView: "versioned"},
	} {
		assert.Error(t, cfg.validate(), name)
	}
}
