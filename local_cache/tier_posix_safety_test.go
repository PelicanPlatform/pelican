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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// The cache reaches a shared-filesystem target through an open handle, but
// everyone else -- redirected clients, people browsing the names view --
// goes by path.  These tests cover what keeps the path honest, and what
// keeps a hung mount from wedging the cache.

// TestPosixTierRefusesInsecureAncestors: a target under a directory others
// can write (and that is not sticky) could be renamed away and replaced, so
// it is refused, whether the path reaches it directly or through a symlink.
func TestPosixTierRefusesInsecureAncestors(t *testing.T) {
	open := func(dir string) error {
		b, err := newPosixTierBackend(TierTargetConfig{ProviderURL: fileTargetURL(dir), MaxSize: 1 << 30})
		if err == nil {
			_ = b.Close()
		}
		return err
	}

	t.Run("GroupWritableParent", func(t *testing.T) {
		project := filepath.Join(t.TempDir(), "project")
		require.NoError(t, os.Mkdir(project, 0o755))
		require.NoError(t, os.Chmod(project, 0o775))
		err := open(filepath.Join(project, "pelican"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Put the target under a directory the cache's user owns")
		assert.Contains(t, err.Error(), project)
	})

	t.Run("StickyParentIsAccepted", func(t *testing.T) {
		// A sticky directory (like /tmp) lets others create entries but not
		// rename or remove the cache's.
		shared := filepath.Join(t.TempDir(), "shared")
		require.NoError(t, os.Mkdir(shared, 0o755))
		require.NoError(t, os.Chmod(shared, 0o777|os.ModeSticky))
		require.NoError(t, open(filepath.Join(shared, "pelican")))
	})

	t.Run("SymlinkIntoAWritableDirectory", func(t *testing.T) {
		base := t.TempDir()
		project := filepath.Join(base, "project")
		require.NoError(t, os.Mkdir(project, 0o755))
		require.NoError(t, os.Mkdir(filepath.Join(project, "pelican"), 0o755))
		require.NoError(t, os.Chmod(project, 0o777))
		safe := filepath.Join(base, "safe")
		require.NoError(t, os.Mkdir(safe, 0o755))
		require.NoError(t, os.Symlink(filepath.Join(project, "pelican"), filepath.Join(safe, "link")))
		err := open(filepath.Join(safe, "link"))
		require.Error(t, err, "the path resolves through a directory others can write")
	})

	t.Run("SymlinkThroughSafeDirectoriesIsAccepted", func(t *testing.T) {
		base := t.TempDir()
		real := filepath.Join(base, "real")
		require.NoError(t, os.Mkdir(real, 0o755))
		require.NoError(t, os.Symlink("real", filepath.Join(base, "link")))
		require.NoError(t, open(filepath.Join(base, "link", "pelican")))
	})

	t.Run("BecomingWritableFailsTheProbe", func(t *testing.T) {
		ctx := context.Background()
		project := filepath.Join(t.TempDir(), "project")
		require.NoError(t, os.Mkdir(project, 0o755))
		target, err := newTierTarget(ctx, TierTargetConfig{ProviderURL: fileTargetURL(filepath.Join(project, "pelican")), MaxSize: 1 << 30})
		require.NoError(t, err)
		t.Cleanup(func() { _ = target.Close() })
		require.NoError(t, target.probe(ctx))
		require.NoError(t, os.Chmod(project, 0o775))
		require.Error(t, target.probe(ctx))
	})
}

// TestPosixTierDetectsSwappedTarget is the attack the ancestor rule exists
// for, played out anyway (here the swapper is the test, which owns the
// parent): the target directory is renamed away and a look-alike put in its
// place.  The cache, reading through its handle, still sees its own files;
// a client reading by path would see the planted ones.  The liveness probe
// must notice, so the target stops being handed to clients.
func TestPosixTierDetectsSwappedTarget(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dir := filepath.Join(base, "pelican")
	target, err := newTierTarget(ctx, TierTargetConfig{ProviderURL: fileTargetURL(dir), MaxSize: 1 << 30})
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })

	genuine := []byte("genuine data")
	const key = "ab/cd/abcdef"
	require.NoError(t, discardInfo(target.backend.Put(ctx, key, "", int64(len(genuine)), bytes.NewReader(genuine))))
	require.NoError(t, target.probe(ctx))

	require.NoError(t, os.Rename(dir, filepath.Join(base, "moved")))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "objects", "ab", "cd"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "objects", "ab", "cd", "abcdef"), []byte("evil data!!!"), 0o644))
	for _, sub := range []string{"names", ".pelican-tmp"} {
		require.NoError(t, os.Mkdir(filepath.Join(dir, sub), 0o755))
	}

	// The cache's handle is unaffected...
	rc, err := target.backend.OpenRange(ctx, key, 0, nil)
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	rc.Close()
	require.NoError(t, err)
	assert.Equal(t, genuine, got)
	// ...but the path now leads somewhere else, and the probe says so.
	err = target.probe(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer the directory the cache opened")
	assert.False(t, target.healthy.Load())

	// Putting the real directory back restores the target.
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.Rename(filepath.Join(base, "moved"), dir))
	require.NoError(t, target.probe(ctx))
}

// TestPosixTierSymlinkedSubdirectoryFailsTheProbe: a fixed subdirectory
// replaced by a symlink after startup -- whoever controls the link's target
// would control the tree -- takes the target out of rotation.
func TestPosixTierSymlinkedSubdirectoryFailsTheProbe(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "pelican")
	target, err := newTierTarget(ctx, TierTargetConfig{ProviderURL: fileTargetURL(dir), MaxSize: 1 << 30})
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })
	require.NoError(t, target.probe(ctx))

	elsewhere := t.TempDir()
	require.NoError(t, os.Remove(filepath.Join(dir, "names")))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(dir, "names")))
	err = target.probe(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

// TestPosixFSAbandonsHungCalls: a call that does not return by its deadline
// is abandoned, and while it stays blocked further calls fail at once rather
// than piling up; when it finally returns, the filesystem is usable again
// and whatever the late call acquired is released.
func TestPosixFSAbandonsHungCalls(t *testing.T) {
	p := &posixFS{timeout: 50 * time.Millisecond}
	release := make(chan struct{})
	var lateResult atomic.Int64

	_, err := posixCall(p, func() (int, error) {
		<-release
		return 42, nil
	}, func(v int, _ error) { lateResult.Store(int64(v)) })
	require.ErrorIs(t, err, errTargetNotResponding)
	assert.EqualValues(t, 1, p.stuck.Load())

	var ran atomic.Bool
	_, err = posixCall(p, func() (int, error) { ran.Store(true); return 0, nil }, nil)
	require.ErrorIs(t, err, errTargetNotResponding)
	assert.False(t, ran.Load(), "a call behind a stuck one must not be started")

	close(release)
	require.Eventually(t, func() bool { return p.stuck.Load() == 0 }, 5*time.Second, 5*time.Millisecond)
	assert.EqualValues(t, 42, lateResult.Load(), "the late result is handed to its cleanup")
	v, err := posixCall(p, func() (int, error) { return 7, nil }, nil)
	require.NoError(t, err)
	assert.Equal(t, 7, v)
}

// hungBackend is a TierBackend whose writes block until released, standing
// in for a hard-mounted filesystem whose server went away.
type hungBackend struct {
	TierBackend
	release chan struct{}
	puts    atomic.Int32
}

func (h *hungBackend) Put(context.Context, string, string, int64, io.Reader) (TierObjectInfo, error) {
	h.puts.Add(1)
	<-h.release
	return TierObjectInfo{}, io.ErrUnexpectedEOF
}

// TestTierProbeBoundedWhenBackendHangs: a probe of a target that ignores its
// context still returns at its deadline and reports the target down, and no
// second probe is started while the first is stuck.
func TestTierProbeBoundedWhenBackendHangs(t *testing.T) {
	backend := &hungBackend{release: make(chan struct{})}
	target := &tierTarget{
		cfg:          TierTargetConfig{ProviderURL: "file:///hung"},
		backend:      backend,
		probeTimeout: 50 * time.Millisecond,
	}
	target.healthy.Store(true)

	require.ErrorIs(t, target.probe(context.Background()), errTargetNotResponding)
	assert.False(t, target.healthy.Load())
	err := target.probe(context.Background())
	require.ErrorIs(t, err, errTargetNotResponding)
	assert.Contains(t, err.Error(), "previous liveness probe has not returned")
	assert.EqualValues(t, 1, backend.puts.Load(), "a stuck probe must not be stacked")

	close(backend.release)
	require.Eventually(t, func() bool { return !target.probeRunning.Load() }, 5*time.Second, 5*time.Millisecond)
	err = target.probe(context.Background())
	require.Error(t, err)
	assert.NotErrorIs(t, err, errTargetNotResponding, "once the stuck probe returns, probing resumes")
	assert.EqualValues(t, 2, backend.puts.Load())
}

// TestAnonymousReadVerdict: only a namespace the cache knows of, without
// public reads, is a verdict of "private".  A path no advertised namespace
// covers -- its origin is down, or the director just restarted -- is
// unknown, and nothing may be withdrawn on its strength.
func TestAnonymousReadVerdict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, ctx := errgroup.WithContext(ctx)
	ac := newAuthConfig(ctx, egrp)

	allowed, known := ac.anonymousReadVerdict("/public/x")
	assert.False(t, allowed)
	assert.False(t, known, "nothing is known before the namespace list loads")

	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAd{
		{Path: "/public", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
		{Path: "/private", Caps: server_structs.Capabilities{Reads: true}},
	}))
	allowed, known = ac.anonymousReadVerdict("/public/x")
	assert.True(t, allowed)
	assert.True(t, known)
	allowed, known = ac.anonymousReadVerdict("/private/x")
	assert.False(t, allowed)
	assert.True(t, known)
	allowed, known = ac.anonymousReadVerdict("/vanished/x")
	assert.False(t, allowed)
	assert.False(t, known, "a namespace absent from the list is unknown, not private")
}

// TestTierSharedFilesystemServing runs the cache's GET path against a
// shared-filesystem target: a client that advertises file:// support is
// redirected to the object's path, and once the target's path stops leading
// to the cache's files, the same client is served through the cache's own
// handle instead.
func TestTierSharedFilesystemServing(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(context.Background())
	egrp, _ := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = egrp.Wait()
	})
	config.SetFederation(pelican_url.FederationDiscovery{
		DiscoveryEndpoint: "https://cache.example:8443",
		DirectorEndpoint:  "https://cache.example:8443",
	})

	base := t.TempDir()
	dir := filepath.Join(base, "shared")
	setTierTargets(t, []interface{}{map[string]interface{}{"ProviderURL": fileTargetURL(dir), "MaxSize": "1GB"}})
	require.NoError(t, param.Cache_TieringThreshold.Set("1KB"))

	tmpDir := t.TempDir()
	pc, err := NewPersistentCache(ctx, egrp, PersistentCacheConfig{
		Mode:        CacheModeServer,
		BaseDir:     tmpDir,
		StorageDirs: []StorageDirConfig{{Path: tmpDir}},
		DeferConfig: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	require.NoError(t, pc.ac.updateConfig([]server_structs.NamespaceAd{{
		Path: "/test",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}}))
	var target *tierTarget
	for _, tt := range pc.storage.tierTargets {
		target = tt
	}
	require.NotNil(t, target)

	const objectPath = "/test/shared.bin"
	const etag = "shared-etag"
	normalized := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(normalized)
	instanceHash := pc.db.InstanceHash(etag, objectHash)
	var diskID StorageID
	for id := range pc.storage.GetDirs() {
		diskID = id
	}
	data := bytes.Repeat([]byte("shared filesystem bytes\n"), 400)
	storeTestObject(t, ctx, pc.storage, instanceHash, data, diskID, NamespaceID(1))
	require.NoError(t, pc.db.SetLatestETag(objectHash, etag, time.Now()))
	stored, err := pc.storage.GetMetadata(instanceHash)
	require.NoError(t, err)
	stored.ETag = etag
	stored.SourceURL = normalized
	require.NoError(t, pc.storage.SetMetadata(instanceHash, stored))
	pc.tierUploader.MaybeEnqueue(instanceHash)
	require.Eventually(t, func() bool {
		meta, err := pc.storage.GetMetadata(instanceHash)
		return err == nil && meta != nil && meta.StorageID == target.id
	}, 15*time.Second, 20*time.Millisecond, "the public object should be tiered to the shared filesystem")

	srv := httptest.NewServer(http.HandlerFunc(pc.serveObject))
	t.Cleanup(srv.Close)
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func() *http.Response {
		req, err := http.NewRequest(http.MethodGet, srv.URL+objectPath, nil)
		require.NoError(t, err)
		req.Header.Set(server_structs.AcceptRedirectHeader, server_structs.RedirectSchemeFile)
		resp, err := noFollow.Do(req)
		require.NoError(t, err)
		return resp
	}

	resp := get()
	resp.Body.Close()
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, "file://"), location)

	// Swap the directory out from under the cache.
	require.NoError(t, os.Rename(dir, filepath.Join(base, "moved")))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "objects"), 0o755))
	require.Error(t, target.probe(ctx))

	resp = get()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a client must not be sent down a path that no longer leads to the cache's files")
	assert.Equal(t, data, body, "the cache serves its own copy through its handle")
}

// TestPosixTierCreatesPrefixLevels: a multi-level Prefix is created below
// the named directory, each level with the cache's directory mode; the
// named directory's own parent must already exist.
func TestPosixTierCreatesPrefixLevels(t *testing.T) {
	withUmask(t, 0o077)
	base := t.TempDir()
	b, err := newPosixTierBackend(TierTargetConfig{ProviderURL: fileTargetURL(filepath.Join(base, "mount")),
		Prefix: "site/sub", MaxSize: 1 << 30})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	for _, d := range []string{"mount", "mount/site", "mount/site/sub", "mount/site/sub/objects"} {
		info, err := os.Stat(filepath.Join(base, d))
		require.NoError(t, err)
		assert.Equal(t, posixDirMode, info.Mode().Perm(), d)
	}
}
