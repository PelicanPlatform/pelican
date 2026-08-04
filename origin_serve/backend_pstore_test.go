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

package origin_serve

import (
	"context"
	"io"
	"net/http"
	"os"
	"syscall"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// newPStoreTestBackend builds the backend the origin handler would build,
// through the real configuration path.
func newPStoreTestBackend(t *testing.T, storagePrefix string) *pstoreBackend {
	t.Helper()
	local_cache.InitIssuerKeyForTests(t)
	ResetPStoreState()
	t.Cleanup(ResetPStoreState)

	require.NoError(t, param.Origin_PStoreLocation.Set(t.TempDir()))

	baseCtx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, egrpCtx := errgroup.WithContext(baseCtx)
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

	logger := func(*http.Request, error) {}
	backend, err := newPStoreBackend(ctx, server_utils.OriginExport{
		FederationPrefix: "/test",
		StoragePrefix:    storagePrefix,
	}, logger)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })
	return backend
}

// TestPStoreBackendServesThroughWebDAV drives the store through the exact
// webdav.FileSystem the origin handler is given, so the afero adapter, the
// storage-prefix join, and the store all participate.
func TestPStoreBackendServesThroughWebDAV(t *testing.T) {
	backend := newPStoreTestBackend(t, "/")
	fs := backend.FileSystem()
	ctx := t.Context()

	require.NoError(t, backend.CheckAvailability())

	require.NoError(t, fs.Mkdir(ctx, "/data", 0755))

	f, err := fs.OpenFile(ctx, "/data/object.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("served from pstore"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	r, err := fs.OpenFile(ctx, "/data/object.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer r.Close()
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "served from pstore", string(got))

	fi, err := fs.Stat(ctx, "/data/object.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(len("served from pstore")), fi.Size())

	// The handler sets the ETag response header from this.
	tagger, ok := fi.(webdav.ETager)
	require.True(t, ok, "pstore FileInfo must implement webdav.ETager")
	tag, err := tagger.ETag(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, tag)
}

// TestPStoreBackendPropfindListing covers the directory read the WebDAV
// PROPFIND handler performs.
func TestPStoreBackendPropfindListing(t *testing.T) {
	backend := newPStoreTestBackend(t, "/")
	fs := backend.FileSystem()
	ctx := t.Context()

	require.NoError(t, fs.Mkdir(ctx, "/dir", 0755))
	for _, name := range []string{"c.txt", "a.txt", "b.txt"} {
		f, err := fs.OpenFile(ctx, "/dir/"+name, os.O_WRONLY|os.O_CREATE, 0644)
		require.NoError(t, err)
		_, err = f.Write([]byte(name))
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}
	require.NoError(t, fs.Mkdir(ctx, "/dir/sub", 0755))

	d, err := fs.OpenFile(ctx, "/dir", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer d.Close()

	infos, err := d.Readdir(-1)
	require.NoError(t, err)
	names := make([]string, len(infos))
	for i, fi := range infos {
		names[i] = fi.Name()
	}
	assert.Equal(t, []string{"a.txt", "b.txt", "c.txt", "sub"}, names,
		"direct children only, in name order")
}

// TestPStoreBackendHonorsStoragePrefix checks that an export mapped onto a
// subtree of the store sees only that subtree.
func TestPStoreBackendHonorsStoragePrefix(t *testing.T) {
	backend := newPStoreTestBackend(t, "/exports/one")
	fs := backend.FileSystem()
	ctx := t.Context()

	// The adapter joins the prefix onto request paths, so the intermediate
	// directories have to exist in the store first.
	require.NoError(t, fs.Mkdir(ctx, "/", 0755))

	f, err := fs.OpenFile(ctx, "/inside.txt", os.O_WRONLY|os.O_CREATE, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("scoped"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// The object landed under the prefix in the underlying store, not at the
	// store root.
	d, err := backend.store.Stat("/exports/one/inside.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(len("scoped")), d.Size)

	_, err = backend.store.Stat("/inside.txt")
	assert.Error(t, err, "nothing is written outside the export's prefix")
}

// TestPStoreBackendRemoveAndRename exercises DELETE and MOVE.
func TestPStoreBackendRemoveAndRename(t *testing.T) {
	backend := newPStoreTestBackend(t, "/")
	fs := backend.FileSystem()
	ctx := t.Context()

	f, err := fs.OpenFile(ctx, "/a.txt", os.O_WRONLY|os.O_CREATE, 0644)
	require.NoError(t, err)
	_, err = f.Write([]byte("payload"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.NoError(t, fs.Rename(ctx, "/a.txt", "/b.txt"))
	_, err = fs.Stat(ctx, "/a.txt")
	assert.True(t, os.IsNotExist(err))

	r, err := fs.OpenFile(ctx, "/b.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	assert.Equal(t, "payload", string(got))

	require.NoError(t, fs.RemoveAll(ctx, "/b.txt"))
	_, err = fs.Stat(ctx, "/b.txt")
	assert.True(t, os.IsNotExist(err))
}

// TestPStoreBackendRequiresEgrp documents why the context must carry the
// process error group: the store starts background workers that outlive the
// call.
func TestPStoreBackendRequiresEgrp(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)
	ResetPStoreState()
	t.Cleanup(ResetPStoreState)
	require.NoError(t, param.Origin_PStoreLocation.Set(t.TempDir()))

	_, err := newPStoreBackend(t.Context(), server_utils.OriginExport{
		FederationPrefix: "/test",
		StoragePrefix:    "/",
	}, func(*http.Request, error) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error group")
}

// TestPStoreBackendReportsCapacity checks the backend satisfies the optional
// interface the PUT path uses to refuse an oversized upload up front.
func TestPStoreBackendReportsCapacity(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)
	ResetPStoreState()
	t.Cleanup(ResetPStoreState)

	dir := t.TempDir()
	require.NoError(t, param.Origin_PStoreLocation.Set(dir))
	// Shaped as viper delivers a YAML list of objects.
	require.NoError(t, param.Origin_PStoreStorageDirs.Set([]any{
		map[string]any{"Path": dir, "MaxSize": "256KB"},
	}))
	t.Cleanup(func() { _ = param.Origin_PStoreStorageDirs.Set(nil) })

	baseCtx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, egrpCtx := errgroup.WithContext(baseCtx)
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

	backend, err := newPStoreBackend(ctx, server_utils.OriginExport{
		FederationPrefix: "/test",
		StoragePrefix:    "/",
	}, func(*http.Request, error) {})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	reporter, ok := server_utils.OriginBackend(backend).(server_utils.CapacityReporter)
	require.True(t, ok, "pstore must report capacity so PUT can pre-flight")

	assert.NoError(t, reporter.HasCapacityFor(1024))

	err = reporter.HasCapacityFor(10 << 20)
	require.Error(t, err)
	assert.ErrorIs(t, err, syscall.ENOSPC,
		"the refusal must be ENOSPC, which MapToHTTPStatus turns into 507")
	assert.Equal(t, http.StatusInsufficientStorage, NewErrorHandler().MapToHTTPStatus(err))
}

// TestENOSPCMapsTo507 pins the error-to-status fix. ENOSPC was missing from
// the syscall switch, so an out-of-space write fell through to the string
// matcher and surfaced as a 500.
func TestENOSPCMapsTo507(t *testing.T) {
	eh := NewErrorHandler()

	assert.Equal(t, http.StatusInsufficientStorage, eh.MapToHTTPStatus(syscall.ENOSPC))
	assert.Equal(t, http.StatusInsufficientStorage, eh.MapToHTTPStatus(syscall.EDQUOT))
	assert.Equal(t, http.StatusInsufficientStorage,
		eh.MapToHTTPStatus(&os.PathError{Op: "write", Path: "/x", Err: syscall.ENOSPC}),
		"the error arrives wrapped in a PathError from the filesystem layer")
	assert.Equal(t, http.StatusInsufficientStorage,
		eh.MapToHTTPStatus(errors.Wrap(syscall.ENOSPC, "the store is full")),
		"and wrapped again with context by the store")
}

// TestPStoreBackendAutoCreatesParents covers the wrapper the POSIX backend
// also relies on: clients PUT into prefixes that do not exist yet, without an
// explicit MKCOL, and the write must create them rather than fail.
func TestPStoreBackendAutoCreatesParents(t *testing.T) {
	backend := newPStoreTestBackend(t, "/")
	fs := backend.FileSystem()
	ctx := t.Context()

	f, err := fs.OpenFile(ctx, "/deep/nested/new/object.txt", os.O_WRONLY|os.O_CREATE, 0644)
	require.NoError(t, err, "a PUT into a fresh prefix must create its parents")
	_, err = f.Write([]byte("auto"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	got, err := backend.store.ReadAll("/deep/nested/new/object.txt")
	require.NoError(t, err)
	assert.Equal(t, "auto", string(got))

	di, err := fs.Stat(ctx, "/deep/nested")
	require.NoError(t, err)
	assert.True(t, di.IsDir())
}

// TestPStoreBackendsShareOneStore covers two exports mapped onto the same
// store directory.
//
// A store takes an exclusive lock on its directory, so two independent opens
// of one directory cannot both succeed. The exports therefore share a single
// store, each scoped to its own subtree by StoragePrefix.
func TestPStoreBackendsShareOneStore(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)
	ResetPStoreState()
	t.Cleanup(ResetPStoreState)
	require.NoError(t, param.Origin_PStoreLocation.Set(t.TempDir()))

	baseCtx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, egrpCtx := errgroup.WithContext(baseCtx)
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)
	logger := func(*http.Request, error) {}

	first, err := newPStoreBackend(ctx, server_utils.OriginExport{
		FederationPrefix: "/one", StoragePrefix: "/exports/one",
	}, logger)
	require.NoError(t, err)

	second, err := newPStoreBackend(ctx, server_utils.OriginExport{
		FederationPrefix: "/two", StoragePrefix: "/exports/two",
	}, logger)
	require.NoError(t, err, "a second export on the same store must not fail on the lock")
	t.Cleanup(func() { assert.NoError(t, first.Close()) })

	assert.Same(t, first.store, second.store, "both exports use one store")

	// Each export writes into its own subtree and cannot see the other's.
	writeThrough := func(b *pstoreBackend, name, body string) {
		t.Helper()
		f, wErr := b.FileSystem().OpenFile(ctx, name, os.O_WRONLY|os.O_CREATE, 0644)
		require.NoError(t, wErr)
		_, wErr = f.Write([]byte(body))
		require.NoError(t, wErr)
		require.NoError(t, f.Close())
	}
	writeThrough(first, "/data.txt", "from one")
	writeThrough(second, "/data.txt", "from two")

	oneBody, err := first.store.ReadAll("/exports/one/data.txt")
	require.NoError(t, err)
	assert.Equal(t, "from one", string(oneBody))

	twoBody, err := second.store.ReadAll("/exports/two/data.txt")
	require.NoError(t, err)
	assert.Equal(t, "from two", string(twoBody))

	// Neither export sees the other's object at its own path.
	_, err = first.FileSystem().Stat(ctx, "/data.txt")
	require.NoError(t, err)
	fi, err := first.FileSystem().Stat(ctx, "/data.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(len("from one")), fi.Size(), "each export is scoped to its prefix")
}
