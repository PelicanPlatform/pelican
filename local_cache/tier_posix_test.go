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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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

	public := env.storeVersion(t, ctx, "pelican://fed/public/open.bin", "e", data, time.Now())
	env.storage.SetTierExposurePolicy(func(string) (bool, bool) { return false, false })
	assert.Equal(t, env.diskID, tierOf(public), "nothing is exposed before the namespace list is known")
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
		"keys on s3":        {ProviderURL: "s3://bucket", ExposedNamespaces: []string{"/ns"}, MaxSize: 1},
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
