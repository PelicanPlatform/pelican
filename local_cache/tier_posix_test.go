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
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/utils"
)

// These tests run against a real directory, which is the only honest way to
// test a backend whose whole job is what a filesystem does: renames,
// permissions, symlinks.

// fileTargetURL is the ProviderURL naming dir.
func fileTargetURL(dir string) string { return utils.PathToFileURL(dir).String() }

// newPosixBackend opens a backend on a fresh directory.
func newPosixBackend(t *testing.T) (*posixTierBackend, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "shared")
	b, err := newPosixTierBackend(TierTargetConfig{ProviderURL: fileTargetURL(dir), MaxSize: 1 << 30})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b, dir
}

// withUmask runs the test under a restrictive umask, so a write that leans on
// the umask for its mode shows up as unreadable.  The umask is process-wide,
// so tests using this must not run in parallel.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

// TestPosixTierBackendContract runs the TierBackend contract against a real
// directory.
func TestPosixTierBackendContract(t *testing.T) {
	withUmask(t, 0o077)
	ctx := context.Background()
	b, dir := newPosixBackend(t)

	put := func(key string, data []byte) TierObjectInfo {
		t.Helper()
		info, err := b.Put(ctx, key, "", int64(len(data)), bytes.NewReader(data))
		require.NoError(t, err)
		return info
	}
	read := func(key string, offset int64, expect *TierObjectInfo) ([]byte, error) {
		rc, err := b.OpenRange(ctx, key, offset, expect)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}

	data := []byte("the quick brown fox jumps over the lazy dog")
	info := put("ab/cd/abcdef", data)
	assert.Equal(t, int64(len(data)), info.Size)
	assert.NotEmpty(t, info.ETag)

	t.Run("ReadsAndRanges", func(t *testing.T) {
		got, err := read("ab/cd/abcdef", 0, &info)
		require.NoError(t, err)
		assert.Equal(t, data, got)
		got, err = read("ab/cd/abcdef", 4, nil)
		require.NoError(t, err)
		assert.Equal(t, data[4:], got)

		stat, exists, err := b.Stat(ctx, "ab/cd/abcdef")
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, info, stat, "Stat must report the copy Put stored")

		_, exists, err = b.Stat(ctx, "ab/cd/missing")
		require.NoError(t, err)
		assert.False(t, exists, "a missing object is not an error")
	})

	t.Run("ModesIgnoreTheUmask", func(t *testing.T) {
		// Other users read these files directly; a umask of 077 must not
		// lock them out, nor may anything be left writable by them.
		fi, err := os.Stat(filepath.Join(dir, "objects", "ab", "cd", "abcdef"))
		require.NoError(t, err)
		assert.Equal(t, posixFileMode, fi.Mode().Perm())
		for _, d := range []string{"", "objects", "objects/ab", "objects/ab/cd", "names", ".pelican-tmp"} {
			fi, err := os.Stat(filepath.Join(dir, d))
			require.NoError(t, err)
			assert.Equal(t, posixDirMode, fi.Mode().Perm(), "directory %q", d)
		}
	})

	t.Run("ReplacementIsDetected", func(t *testing.T) {
		replaced := put("ab/cd/replaced", data)
		// A same-length rewrite by the cache: a new file renamed into place.
		put("ab/cd/replaced", bytes.ToUpper(data))
		_, err := read("ab/cd/replaced", 0, &replaced)
		assert.ErrorIs(t, err, ErrTierObjectChanged)

		// A same-length rewrite in place, as another writer would do it.
		inPlace := put("ab/cd/inplace", data)
		path := filepath.Join(dir, "objects", "ab", "cd", "inplace")
		require.NoError(t, os.Chmod(path, 0o644))
		later := inPlace.ModTime.Add(time.Second)
		require.NoError(t, os.WriteFile(path, bytes.ToUpper(data), 0o644))
		require.NoError(t, os.Chtimes(path, later, later))
		_, err = read("ab/cd/inplace", 0, &inPlace)
		assert.ErrorIs(t, err, ErrTierObjectChanged)
		current, _, err := b.Stat(ctx, "ab/cd/inplace")
		require.NoError(t, err)
		assert.NotEqual(t, inPlace.ETag, current.ETag)
	})

	t.Run("ShortWriteLeavesNothing", func(t *testing.T) {
		_, err := b.Put(ctx, "ab/cd/short", "", 100, bytes.NewReader(data))
		require.Error(t, err)
		_, exists, err := b.Stat(ctx, "ab/cd/short")
		require.NoError(t, err)
		assert.False(t, exists, "a short write must not commit")
		leftovers, err := os.ReadDir(filepath.Join(dir, posixTempDir))
		require.NoError(t, err)
		assert.Empty(t, leftovers, "a failed write must clean up its temporary file")

		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err = b.Put(cancelled, "ab/cd/cancelled", "", int64(len(data)), bytes.NewReader(data))
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("KeysStayInTheObjectsTree", func(t *testing.T) {
		for _, key := range []string{"../names/x", "/etc/passwd", "a/../../x", "", "."} {
			_, err := b.Put(ctx, key, "", 1, strings.NewReader("x"))
			assert.Error(t, err, "key %q", key)
		}
	})

	t.Run("DeleteIsIdempotent", func(t *testing.T) {
		put("ab/cd/doomed", data)
		require.NoError(t, b.Delete(ctx, "ab/cd/doomed"))
		require.NoError(t, b.Delete(ctx, "ab/cd/doomed"))
		_, exists, err := b.Stat(ctx, "ab/cd/doomed")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("ListIsInKeyOrder", func(t *testing.T) {
		// '-' sorts before '/', so "ab/c-d" must come before "ab/cd/...":
		// a naive depth-first walk would get this backwards.
		put("ab/c-d", data)
		put("ab/c/x", data)
		put("a-b", data)
		var keys []string
		require.NoError(t, b.List(ctx, func(key string, size int64, _ time.Time) error {
			keys = append(keys, key)
			return nil
		}))
		assert.IsIncreasing(t, keys)
		assert.Contains(t, keys, "ab/c-d")
		assert.Contains(t, keys, "ab/cd/abcdef")
		for _, key := range keys {
			assert.False(t, strings.HasPrefix(key, "names"), "the names view is not part of the key space")
		}
	})

	t.Run("RedirectsAreFileURLs", func(t *testing.T) {
		raw, err := b.RedirectURL(ctx, "ab/cd/abcdef", time.Minute, nil)
		require.NoError(t, err)
		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Equal(t, "file", u.Scheme)
		assert.Empty(t, u.Host)
		assert.Equal(t, filepath.Join(dir, "objects", "ab", "cd", "abcdef"), utils.FileURLToPath(u))

		probe, ok := b.probeRedirect(ctx)
		require.True(t, ok)
		assert.True(t, strings.HasPrefix(probe, "file:///"))
	})

	t.Run("ReapsOnlyAbandonedTemporaryFiles", func(t *testing.T) {
		abandoned := filepath.Join(dir, posixTempDir, "put-abandoned")
		require.NoError(t, os.WriteFile(abandoned, data, 0o600))
		old := time.Now().Add(-time.Hour)
		require.NoError(t, os.Chtimes(abandoned, old, old))
		busy, release := b.newTempName("put")
		defer release()
		require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(busy)), data, 0o600))
		require.NoError(t, os.Chtimes(filepath.Join(dir, filepath.FromSlash(busy)), old, old))

		reaped, err := b.ReapStaleUploads(ctx, time.Minute)
		require.NoError(t, err)
		assert.Equal(t, 1, reaped)
		assert.NoFileExists(t, abandoned)
		assert.FileExists(t, filepath.Join(dir, filepath.FromSlash(busy)), "a write in progress must be spared")
	})
}

// TestPosixTierRefusesSharedWritableDirectories: a target someone else can
// write is one where they could plant links users trust, so it is refused
// at startup and fails its liveness probe if it becomes one later.
func TestPosixTierRefusesSharedWritableDirectories(t *testing.T) {
	t.Run("AtStartup", func(t *testing.T) {
		for _, sub := range []string{"", "names", "objects", ".pelican-tmp"} {
			dir := filepath.Join(t.TempDir(), "shared")
			cfg := TierTargetConfig{ProviderURL: fileTargetURL(dir), MaxSize: 1 << 30}
			b, err := newPosixTierBackend(cfg)
			require.NoError(t, err)
			require.NoError(t, b.Close())

			require.NoError(t, os.Chmod(filepath.Join(dir, sub), 0o777))
			_, err = newPosixTierBackend(cfg)
			require.Error(t, err, "a world-writable %q must be refused", sub)
			assert.Contains(t, err.Error(), "chmod go-w")
		}
	})

	t.Run("ASymlinkedSubdirectory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "shared")
		require.NoError(t, os.Mkdir(dir, 0o755))
		require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(dir, "names")))
		_, err := newPosixTierBackend(TierTargetConfig{ProviderURL: fileTargetURL(dir), MaxSize: 1 << 30})
		require.Error(t, err)
	})

	t.Run("MissingParentIsNotCreated", func(t *testing.T) {
		// Only the leaf directory is created: a missing parent usually means
		// the shared filesystem is not mounted.
		dir := filepath.Join(t.TempDir(), "not-mounted", "shared")
		_, err := newPosixTierBackend(TierTargetConfig{ProviderURL: fileTargetURL(dir), MaxSize: 1 << 30})
		require.Error(t, err)
		assert.NoDirExists(t, filepath.Dir(dir))
	})

	t.Run("OnTheLivenessProbe", func(t *testing.T) {
		ctx := context.Background()
		dir := filepath.Join(t.TempDir(), "shared")
		target, err := newTierTarget(ctx, TierTargetConfig{ProviderURL: fileTargetURL(dir), MaxSize: 1 << 30})
		require.NoError(t, err)
		t.Cleanup(func() { _ = target.Close() })
		require.NoError(t, target.probe(ctx))

		require.NoError(t, os.Chmod(filepath.Join(dir, "names"), 0o775))
		require.Error(t, target.probe(ctx))
		assert.False(t, target.healthy.Load(), "a target others can write must leave rotation")

		require.NoError(t, os.Chmod(filepath.Join(dir, "names"), 0o755))
		require.NoError(t, target.probe(ctx))
	})
}

// TestTierNameEncoding pins the names-view spelling, in particular that it
// stays injective: no two object versions may share a link.
func TestTierNameEncoding(t *testing.T) {
	name, ok := newTierLogicalName("pelican://fed.example/ns/dir/file.dat", `"abc123"`, false)
	require.True(t, ok)
	assert.Equal(t, "names/ns/dir/file.dat@abc123", name.versionPath(), "a strong tag loses its quotes")
	assert.Equal(t, "names/ns/dir/file.dat", name.currentPath())

	// Object "a@b" at version "c" must not collide with object "a" at
	// version "b@c".
	first, ok := newTierLogicalName("pelican://fed/ns/a@b", "c", false)
	require.True(t, ok)
	second, ok := newTierLogicalName("pelican://fed/ns/a", "b@c", false)
	require.True(t, ok)
	assert.NotEqual(t, first.versionPath(), second.versionPath())
	assert.Equal(t, "names/ns/a%40b@c", first.versionPath())
	assert.Equal(t, "names/ns/a@b%40c", second.versionPath())

	// A literal "%40" is not confused with an escaped '@'.
	third, ok := newTierLogicalName("pelican://fed/ns/a%2540b", "c", false)
	require.True(t, ok)
	assert.NotEqual(t, first.versionPath(), third.versionPath())

	// A weak tag keeps its marker and cannot collide with the strong tag.
	weak, ok := newTierLogicalName("pelican://fed/ns/f", `W/"x"`, false)
	require.True(t, ok)
	strong, ok := newTierLogicalName("pelican://fed/ns/f", `"x"`, false)
	require.True(t, ok)
	assert.NotEqual(t, weak.versionPath(), strong.versionPath())
	assert.NotContains(t, strings.TrimPrefix(weak.versionPath(), "names/ns/"), "/")

	// Control characters are escaped.
	ctl, ok := newTierLogicalName("pelican://fed/ns/new%0Aline", "e", false)
	require.True(t, ok)
	assert.Equal(t, "names/ns/new%0Aline@e", ctl.versionPath())

	// Names a filesystem cannot hold are left out rather than truncated.
	_, ok = newTierLogicalName("pelican://fed/ns/"+strings.Repeat("x", 300), "e", false)
	assert.False(t, ok)
	_, ok = newTierLogicalName("", "e", false)
	assert.False(t, ok)
}

// posixTierEnv is a tiering environment with a shared-filesystem target.
type posixTierEnv struct {
	*tierTestEnv
	dir     string
	checker *ConsistencyChecker
	// public is consulted by the target's exposure policy.
	public map[string]bool
}

func newPosixTierEnv(t *testing.T, ctx context.Context, cfg TierTargetConfig) *posixTierEnv {
	t.Helper()
	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()
	dir := filepath.Join(t.TempDir(), "shared")
	cfg.ProviderURL = fileTargetURL(dir)
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 1 << 30
	}
	require.NoError(t, cfg.validate())

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(func() { storage.Close() })
	registered, err := storage.RegisterTierTargets(ctx, []TierTargetConfig{cfg})
	require.NoError(t, err)
	require.Len(t, registered, 1)

	env := &posixTierEnv{tierTestEnv: &tierTestEnv{db: db, storage: storage}, dir: dir, public: map[string]bool{}}
	for id := range registered {
		env.tierID = id
	}
	env.target = storage.getTierTarget(env.tierID)
	for id := range storage.GetDirs() {
		env.diskID = id
	}
	storage.SetTierExposurePolicy(func(objectPath string) (bool, bool) {
		for prefix, public := range env.public {
			if strings.HasPrefix(objectPath, prefix+"/") {
				return public, true
			}
		}
		return false, true
	})
	env.eviction = NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: map[StorageID]EvictionDirConfig{
			env.diskID: {MaxSize: 1 << 30},
			env.tierID: {MaxSize: cfg.MaxSize, NoPlacement: true},
		},
	})
	env.uploader = newTierUploader(db, storage, env.eviction, 1024)
	env.checker = NewConsistencyChecker(db, storage, ConsistencyConfig{MinAgeForCleanup: 0})
	return env
}

// storeVersion stores one version of a named object on local disk, as a
// completed fetch would, and records it as the latest when latest is set.
func (env *posixTierEnv) storeVersion(t *testing.T, ctx context.Context, sourceURL, etag string, data []byte, observed time.Time) InstanceHash {
	t.Helper()
	hash := env.db.InstanceHash(etag, env.db.ObjectHash(sourceURL))
	storeTestObject(t, ctx, env.storage, hash, data, env.diskID, NamespaceID(1))
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	meta.SourceURL = sourceURL
	meta.ETag = etag
	require.NoError(t, env.storage.SetMetadata(hash, meta))
	require.NoError(t, env.db.SetLatestETag(env.db.ObjectHash(sourceURL), etag, observed))
	return hash
}

// names opens the names view the way a careful reader would: confined to
// the target's directory, which refuses absolute symlinks.
func (env *posixTierEnv) readName(t *testing.T, name string) ([]byte, error) {
	t.Helper()
	root, err := os.OpenRoot(env.dir)
	require.NoError(t, err)
	defer root.Close()
	return root.ReadFile(name)
}

// linkedTo returns the object whose file the names-view entry name is a hard
// link to, or "" if it is missing or is not a link to any object's file.
func (env *posixTierEnv) linkedTo(t *testing.T, name string) InstanceHash {
	t.Helper()
	info, err := os.Lstat(filepath.Join(env.dir, filepath.FromSlash(name)))
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	var found InstanceHash
	objects := filepath.Join(env.dir, posixObjectsDir)
	require.NoError(t, filepath.WalkDir(objects, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return err
		}
		objectInfo, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if os.SameFile(info, objectInfo) {
			rel, err := filepath.Rel(objects, p)
			if err != nil {
				return err
			}
			found = env.target.hashFromKey(filepath.ToSlash(rel))
		}
		return nil
	}))
	return found
}

// linkName makes name a hard link to the object's file, as the view would
// -- or as something that does not belong there.
func (env *posixTierEnv) linkName(t *testing.T, hash InstanceHash, name string) {
	t.Helper()
	p := filepath.Join(env.dir, filepath.FromSlash(name))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	object := filepath.Join(env.dir, posixObjectsDir, filepath.FromSlash(env.target.objectKey(hash)))
	require.NoError(t, os.Link(object, p))
}

// TestTierNamesViewLifecycle follows one object through the names view:
// tiering publishes it, a new version takes over the bare name, eviction
// withdraws each version, and no name outlives its object.
func TestTierNamesViewLifecycle(t *testing.T) {
	withUmask(t, 0o077)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{})
	env.public["/public"] = true

	const sourceURL = "pelican://fed.example/public/data/set@1/file.bin"
	v1 := bytes.Repeat([]byte("version one\n"), 400)
	v2 := bytes.Repeat([]byte("version two\n"), 400)
	start := time.Now().Add(-time.Hour)

	h1 := env.storeVersion(t, ctx, sourceURL, `"v1"`, v1, start)
	require.NoError(t, env.uploader.processObject(ctx, h1))
	meta, err := env.storage.GetMetadata(h1)
	require.NoError(t, err)
	require.Equal(t, env.tierID, meta.StorageID, "a public object is tiered to the shared filesystem")

	const (
		bare     = "names/public/data/set%401/file.bin"
		version1 = bare + "@v1"
		version2 = bare + "@v2"
	)
	got, err := env.readName(t, version1)
	require.NoError(t, err)
	assert.Equal(t, v1, got)
	got, err = env.readName(t, bare)
	require.NoError(t, err, "the bare name must resolve within an os.Root")
	assert.Equal(t, v1, got)
	assert.Equal(t, h1, env.linkedTo(t, bare), "the bare name is the object's own file")
	assert.Equal(t, h1, env.linkedTo(t, version1))
	for _, d := range []string{"names/public", "names/public/data", "names/public/data/set%401"} {
		fi, err := os.Stat(filepath.Join(env.dir, filepath.FromSlash(d)))
		require.NoError(t, err)
		assert.Equal(t, posixDirMode, fi.Mode().Perm(), "directory %s", d)
	}

	// A newer version, once tiered, takes over the bare name; the old
	// version stays reachable under its own name until it is evicted.
	h2 := env.storeVersion(t, ctx, sourceURL, `"v2"`, v2, start.Add(time.Minute))
	require.NoError(t, env.uploader.processObject(ctx, h2))
	assert.Equal(t, h2, env.linkedTo(t, bare))
	got, err = env.readName(t, bare)
	require.NoError(t, err)
	assert.Equal(t, v2, got)
	got, err = env.readName(t, version1)
	require.NoError(t, err)
	assert.Equal(t, v1, got)

	// An older version that happens to be tiered later does not take the
	// bare name back.
	h0 := env.storeVersion(t, ctx, sourceURL, `"v0"`, bytes.Repeat([]byte("version zero\n"), 400), start.Add(-time.Minute))
	require.NoError(t, env.uploader.processObject(ctx, h0))
	assert.Equal(t, h0, env.linkedTo(t, bare+"@v0"))
	assert.Equal(t, h2, env.linkedTo(t, bare), "only the latest version is the bare name")
	require.NoError(t, env.storage.Delete(h0))

	// Deleting the old version withdraws its link and leaves the bare name.
	require.NoError(t, env.storage.Delete(h1))
	assert.Empty(t, env.linkedTo(t, version1))
	assert.Equal(t, h2, env.linkedTo(t, bare))

	// Evicting the current version withdraws both, and the now-empty
	// directories go with them.
	require.NoError(t, env.db.UpdateLRU(h2, 0))
	evicted, _, _, err := env.storage.EvictByLRU(env.tierID, NamespaceID(1), 0, 0)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	assert.Empty(t, env.linkedTo(t, version2))
	assert.Empty(t, env.linkedTo(t, bare))
	assert.NoDirExists(t, filepath.Join(env.dir, "names", "public"))
	assert.DirExists(t, filepath.Join(env.dir, "names"))
}

// TestTierNamesViewSweepRepairs: the sweep rebuilds the view from metadata,
// restoring what is missing and removing what is stale or foreign, and never
// mistakes the view for orphaned objects.
func TestTierNamesViewSweepRepairs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{})
	env.public["/public"] = true

	const sourceURL = "pelican://fed.example/public/keep.bin"
	data := bytes.Repeat([]byte("keep\n"), 1000)
	hash := env.storeVersion(t, ctx, sourceURL, "e1", data, time.Now().Add(-time.Hour))
	require.NoError(t, env.uploader.processObject(ctx, hash))
	key := env.target.objectKey(hash)

	names := filepath.Join(env.dir, "names")
	// orphan makes name a file that was once linked to an object since
	// deleted, as a crash between deleting an object and its names leaves.
	orphan := func(name string) {
		p := filepath.Join(names, filepath.FromSlash(name))
		gone := filepath.Join(t.TempDir(), "gone")
		require.NoError(t, os.WriteFile(gone, data, 0o644))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.Link(gone, p))
		require.NoError(t, os.Remove(gone))
	}
	// Damage: the object's bare name is lost (as after a crash) and its
	// version name is a file with the right bytes that is not the object ...
	require.NoError(t, os.Remove(filepath.Join(names, "public", "keep.bin")))
	require.NoError(t, os.Remove(filepath.Join(names, "public", "keep.bin@e1")))
	require.NoError(t, os.WriteFile(filepath.Join(names, "public", "keep.bin@e1"), data, 0o644))
	// ... a version name and a bare name outlived their object ...
	orphan("public/gone.bin@x")
	orphan("public/gone.bin")
	// ... a link to a real object sits under the wrong name ...
	env.linkName(t, hash, "names/public/impostor.bin@e1")
	// ... a symlink to the object and a stray file were planted ...
	require.NoError(t, os.Symlink(filepath.Join(env.dir, "objects", filepath.FromSlash(key)), filepath.Join(names, "public", "symlink.bin@e1")))
	require.NoError(t, os.WriteFile(filepath.Join(names, "public", "stray.txt"), []byte("x"), 0o644))
	// ... and an empty directory was left behind.
	require.NoError(t, os.MkdirAll(filepath.Join(names, "empty", "deeper"), 0o755))

	label := env.target.metricLabel()
	removedBefore := testutil.ToFloat64(tierSweepRemovedTotal.WithLabelValues(label, tierSweepRemovedNameLink))
	restoredBefore := testutil.ToFloat64(tierNameLinksRestoredTotal.WithLabelValues(label))
	remoteBefore := testutil.ToFloat64(tierSweepRemovedTotal.WithLabelValues(label, tierSweepRemovedRemoteObject))
	require.NoError(t, env.checker.RunTierScan(ctx))

	got, err := env.readName(t, "names/public/keep.bin")
	require.NoError(t, err)
	assert.Equal(t, data, got, "the lost links are restored")
	entries, err := os.ReadDir(filepath.Join(names, "public"))
	require.NoError(t, err)
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	assert.ElementsMatch(t, []string{"keep.bin", "keep.bin@e1"}, left)
	assert.NoDirExists(t, filepath.Join(names, "empty"))
	assert.Equal(t, restoredBefore+2, testutil.ToFloat64(tierNameLinksRestoredTotal.WithLabelValues(label)))
	assert.Equal(t, removedBefore+6, testutil.ToFloat64(tierSweepRemovedTotal.WithLabelValues(label, tierSweepRemovedNameLink)))
	assert.Equal(t, remoteBefore, testutil.ToFloat64(tierSweepRemovedTotal.WithLabelValues(label, tierSweepRemovedRemoteObject)),
		"nothing in the names view is an orphaned object")
	exists, err := env.target.objectExists(ctx, hash)
	require.NoError(t, err)
	assert.True(t, exists)

	// A healthy view costs the sweep nothing to change.
	removedBefore = testutil.ToFloat64(tierSweepRemovedTotal.WithLabelValues(label, tierSweepRemovedNameLink))
	restoredBefore = testutil.ToFloat64(tierNameLinksRestoredTotal.WithLabelValues(label))
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Equal(t, removedBefore, testutil.ToFloat64(tierSweepRemovedTotal.WithLabelValues(label, tierSweepRemovedNameLink)))
	assert.Equal(t, restoredBefore, testutil.ToFloat64(tierNameLinksRestoredTotal.WithLabelValues(label)))

	// The bare name is withdrawn the moment the cache learns of a newer
	// version that is not on the target -- not an hour later.
	require.NoError(t, env.db.SetLatestETag(env.db.ObjectHash(sourceURL), "e2", time.Now()))
	assert.Empty(t, env.linkedTo(t, "names/public/keep.bin"))
	assert.Equal(t, hash, env.linkedTo(t, "names/public/keep.bin@e1"), "the version itself is still valid")
	// ...and one put back on the superseded version is removed.
	env.linkName(t, hash, "names/public/keep.bin")
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Empty(t, env.linkedTo(t, "names/public/keep.bin"))

	// An object whose namespace stops being public leaves the view.
	env.public["/public"] = false
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Empty(t, env.linkedTo(t, "names/public/keep.bin@e1"))
}

// TestTierNamesViewDisabled: with the view turned off nothing is linked, and
// a tree left from before is emptied by the sweep.
func TestTierNamesViewDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{NamesView: "none"})
	env.public["/public"] = true

	hash := env.storeVersion(t, ctx, "pelican://fed/public/x.bin", "e", bytes.Repeat([]byte("x"), 4096), time.Now())
	require.NoError(t, env.uploader.processObject(ctx, hash))
	meta, err := env.storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Equal(t, env.tierID, meta.StorageID, "the target still tiers")
	assert.Empty(t, env.linkedTo(t, "names/public/x.bin"))

	env.linkName(t, hash, "names/leftover")
	require.NoError(t, env.checker.RunTierScan(ctx))
	entries, err := os.ReadDir(filepath.Join(env.dir, "names"))
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestTierSharedFilesystemHoldsOnlyExposableObjects: an object that needs a
// token stays off a shared filesystem -- where every local user could read
// it -- unless the operator lists its namespace, and nothing is decided
// before the namespace list is known.
func TestTierSharedFilesystemHoldsOnlyExposableObjects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{ExposedNamespaces: []string{"/listed"}})
	env.public["/public"] = true
	data := bytes.Repeat([]byte("p"), 4096)

	tierOf := func(hash InstanceHash) StorageID {
		require.NoError(t, env.uploader.processObject(ctx, hash))
		meta, err := env.storage.GetMetadata(hash)
		require.NoError(t, err)
		return meta.StorageID
	}

	private := env.storeVersion(t, ctx, "pelican://fed/private/secret.bin", "e", data, time.Now())
	assert.Equal(t, env.diskID, tierOf(private), "a private object must stay on local storage")

	listed := env.storeVersion(t, ctx, "pelican://fed/listed/shared.bin", "e", data, time.Now())
	assert.Equal(t, env.tierID, tierOf(listed), "a listed namespace may be exposed")
	got, err := env.readName(t, "names/listed/shared.bin")
	require.NoError(t, err)
	assert.Equal(t, data, got)

	public := env.storeVersion(t, ctx, "pelican://fed/public/open.bin", "e", data, time.Now())
	env.storage.SetTierExposurePolicy(func(string) (bool, bool) { return false, false })
	assert.Equal(t, env.diskID, tierOf(public), "nothing is exposed before the namespace list is known")
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Equal(t, listed, env.linkedTo(t, "names/listed/shared.bin"), "an unknown answer withdraws nothing")
}

// TestTierSharedFilesystemConfig covers the file:// spellings the
// configuration accepts and refuses.
func TestTierSharedFilesystemConfig(t *testing.T) {
	good := TierTargetConfig{ProviderURL: "file:///mnt/shared/cache", Prefix: "site", MaxSize: 1,
		ExposedNamespaces: []string{"/ns/sub/"}}
	require.NoError(t, good.validate())
	assert.True(t, good.IsSharedFilesystem())
	assert.Equal(t, "/mnt/shared/cache/site", good.SharedFilesystemDir())
	assert.Equal(t, "file", good.TransportScheme())
	assert.Equal(t, []string{"/ns/sub"}, good.ExposedNamespaces)
	assert.True(t, good.exposesNamespace("/ns/sub/x"))
	assert.False(t, good.exposesNamespace("/ns/subx"))

	for name, cfg := range map[string]TierTargetConfig{
		"remote host":       {ProviderURL: "file://nfs.example.org/export", MaxSize: 1},
		"relative":          {ProviderURL: "file:relative/dir", MaxSize: 1},
		"query":             {ProviderURL: "file:///mnt/x?mode=1", MaxSize: 1},
		"dot-dot prefix":    {ProviderURL: "file:///mnt/x", Prefix: "../escape", MaxSize: 1},
		"relative exposure": {ProviderURL: "file:///mnt/x", ExposedNamespaces: []string{"ns"}, MaxSize: 1},
		"keys on s3":        {ProviderURL: "s3://bucket", NamesView: "none", MaxSize: 1},
		"unknown view":      {ProviderURL: "file:///mnt/x", NamesView: "flat", MaxSize: 1},
	} {
		err := cfg.validate()
		assert.Error(t, err, name)
	}
	localhost := TierTargetConfig{ProviderURL: "file://localhost/mnt/x", MaxSize: 1}
	assert.NoError(t, localhost.validate())
}

// TestTierSharedFilesystemRedirect: a tiered object is served to a client
// that can follow file:// redirects by pointing it at the object's path, in
// a form the client's own containment accepts.
func TestTierSharedFilesystemRedirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{})
	env.public["/public"] = true

	assert.True(t, env.target.canRedirect)
	assert.Equal(t, "file", env.target.redirectScheme)
	assert.False(t, env.target.redirectSendsCredentials("cache.example.org"),
		"a file:// redirect carries no header anywhere")

	data := bytes.Repeat([]byte("redirect me\n"), 500)
	hash := env.storeVersion(t, ctx, "pelican://fed/public/r.bin", "e", data, time.Now())
	require.NoError(t, env.uploader.processObject(ctx, hash))
	raw, err := env.target.redirectURL(ctx, hash, time.Minute, nil)
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)

	// Resolve it the way the client does: relative to an os.Root on the
	// shared directory.
	rel, err := filepath.Rel(env.dir, utils.FileURLToPath(u))
	require.NoError(t, err)
	root, err := os.OpenRoot(env.dir)
	require.NoError(t, err)
	defer root.Close()
	got, err := root.ReadFile(rel)
	require.NoError(t, err)
	assert.Equal(t, data, got)
	fi, err := root.Lstat(rel)
	require.NoError(t, err)
	assert.True(t, fi.Mode().IsRegular(), "redirects name the object, not a link")
}

// TestTierNameEncodingFoldSafe: on a filesystem that folds case or Unicode
// normalization, names that differ only that way must still map to links
// that differ after folding.
func TestTierNameEncodingFoldSafe(t *testing.T) {
	fold := func(s string) string { return strings.ToLower(s) }
	upper, ok := newTierLogicalName("pelican://fed/ns/Data.bin", `"Ab"`, true)
	require.True(t, ok)
	lower, ok := newTierLogicalName("pelican://fed/ns/data.bin", `"ab"`, true)
	require.True(t, ok)
	assert.Equal(t, "names/ns/%44ata.bin@%41b", upper.versionPath())
	assert.NotEqual(t, fold(upper.versionPath()), fold(lower.versionPath()))

	nfc, ok := newTierLogicalName("pelican://fed/ns/café", "e", true)
	require.True(t, ok)
	nfd, ok := newTierLogicalName("pelican://fed/ns/café", "e", true)
	require.True(t, ok)
	assert.NotEqual(t, nfc.versionPath(), nfd.versionPath())
	assert.Equal(t, "names/ns/caf%C3%A9@e", nfc.versionPath(), "non-ASCII bytes are escaped")
}

// TestTierNamesViewFoldingFilesystem: two objects whose names differ only
// in case each resolve to their own bytes through the view, whatever the
// filesystem under the test does with case -- and the probe's verdict
// matches what the filesystem actually does.
func TestTierNamesViewFoldingFilesystem(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{})
	env.public["/public"] = true

	probe := filepath.Join(t.TempDir(), "Probe")
	require.NoError(t, os.WriteFile(probe, nil, 0o644))
	_, err := os.Lstat(filepath.Join(filepath.Dir(probe), "probe"))
	foldsCase := err == nil
	if foldsCase {
		assert.True(t, env.target.names.foldSafe, "a case-folding filesystem must be detected")
	}

	upper := bytes.Repeat([]byte("UPPER\n"), 1000)
	lower := bytes.Repeat([]byte("lower\n"), 1000)
	hu := env.storeVersion(t, ctx, "pelican://fed/public/Data.bin", "e", upper, time.Now())
	hl := env.storeVersion(t, ctx, "pelican://fed/public/data.bin", "e", lower, time.Now())
	require.NoError(t, env.uploader.processObject(ctx, hu))
	require.NoError(t, env.uploader.processObject(ctx, hl))

	for hash, want := range map[InstanceHash][]byte{hu: upper, hl: lower} {
		meta, err := env.storage.GetMetadata(hash)
		require.NoError(t, err)
		name, ok := env.target.names.logicalName(meta.SourceURL, meta.ETag)
		require.True(t, ok)
		got, err := env.readName(t, name.currentPath())
		require.NoError(t, err)
		assert.Equal(t, want, got, "%s must resolve to its own object", meta.SourceURL)
	}
	// And the sweep does not fight over them.
	label := env.target.metricLabel()
	before := testutil.ToFloat64(tierNameLinksRestoredTotal.WithLabelValues(label))
	require.NoError(t, env.checker.RunTierScan(ctx))
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Equal(t, before, testutil.ToFloat64(tierNameLinksRestoredTotal.WithLabelValues(label)))
}

// TestTierNamesViewCollisions: names that would collide are resolved once
// and stay resolved.  A path that is not in canonical form is not named at
// all (it would share a link with its canonical spelling), and of two
// versions whose tags differ only in quoting, the one holding the name when
// the sweep runs keeps it.
func TestTierNamesViewCollisions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{})
	env.public["/public"] = true
	data := bytes.Repeat([]byte("c"), 4096)

	_, ok := newTierLogicalName("pelican://fed/public//x.bin", "e", false)
	assert.False(t, ok, "a non-canonical path is not named")

	first := env.storeVersion(t, ctx, "pelican://fed/public/q.bin", `"x"`, data, time.Now().Add(-time.Minute))
	require.NoError(t, env.uploader.processObject(ctx, first))
	second := env.storeVersion(t, ctx, "pelican://fed/public/q.bin", `x`, data, time.Now())
	require.NoError(t, env.uploader.processObject(ctx, second))
	holder := env.linkedTo(t, "names/public/q.bin@x")
	assert.Contains(t, []InstanceHash{first, second}, holder)

	label := env.target.metricLabel()
	restored := testutil.ToFloat64(tierNameLinksRestoredTotal.WithLabelValues(label))
	removed := testutil.ToFloat64(tierSweepRemovedTotal.WithLabelValues(label, tierSweepRemovedNameLink))
	require.NoError(t, env.checker.RunTierScan(ctx))
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Equal(t, holder, env.linkedTo(t, "names/public/q.bin@x"), "the sweep keeps the name where it is")
	assert.Equal(t, restored, testutil.ToFloat64(tierNameLinksRestoredTotal.WithLabelValues(label)), "no flapping")
	assert.Equal(t, removed, testutil.ToFloat64(tierSweepRemovedTotal.WithLabelValues(label, tierSweepRemovedNameLink)))
}

// TestTierNamesViewPausedWhileUnhealthy: while the target fails its liveness
// probe -- perhaps because someone else can now write the tree -- the cache
// neither publishes into the view nor reconciles it.
func TestTierNamesViewPausedWhileUnhealthy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{})
	env.public["/public"] = true

	hash := env.storeVersion(t, ctx, "pelican://fed/public/u.bin", "e", bytes.Repeat([]byte("u"), 4096), time.Now())
	require.NoError(t, env.uploader.processObject(ctx, hash))
	require.Equal(t, hash, env.linkedTo(t, "names/public/u.bin"))
	require.NoError(t, os.Remove(filepath.Join(env.dir, "names", "public", "u.bin")))
	env.linkName(t, hash, "names/public/other")

	env.target.healthy.Store(false)
	env.storage.publishTierName(env.target, hash)
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Empty(t, env.linkedTo(t, "names/public/u.bin"), "nothing is published while unhealthy")
	assert.Equal(t, hash, env.linkedTo(t, "names/public/other"), "nothing is reconciled while unhealthy")

	env.target.healthy.Store(true)
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Equal(t, hash, env.linkedTo(t, "names/public/u.bin"))
	assert.Empty(t, env.linkedTo(t, "names/public/other"))
}

// TestTierNamesViewKeepsLinksWhenNamespaceVanishes: a namespace that drops
// out of the director's list (its origin is down) is unknown, not private,
// so its links survive the sweep.
func TestTierNamesViewKeepsLinksWhenNamespaceVanishes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := newPosixTierEnv(t, ctx, TierTargetConfig{})
	env.public["/public"] = true
	hash := env.storeVersion(t, ctx, "pelican://fed/public/v.bin", "e", bytes.Repeat([]byte("v"), 4096), time.Now())
	require.NoError(t, env.uploader.processObject(ctx, hash))

	env.storage.SetTierExposurePolicy(func(string) (bool, bool) { return false, false })
	require.NoError(t, env.checker.RunTierScan(ctx))
	assert.Equal(t, hash, env.linkedTo(t, "names/public/v.bin@e"))
	assert.Equal(t, hash, env.linkedTo(t, "names/public/v.bin"))
}
