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
	"context"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
)

// newTestStore opens a store in a temporary directory and closes it on
// cleanup.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, _ := errgroup.WithContext(ctx)

	s, err := Open(ctx, egrp, Config{BaseDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })
	return s
}

func TestOpenAndClose(t *testing.T) {
	s := newTestStore(t)

	root, err := s.Stat("/")
	require.NoError(t, err)
	assert.True(t, root.IsDir(), "the root is always a directory")
}

// TestStoreModeRejectsCacheDatabase covers the guard that keeps a pstore and a
// cache from operating on the same key space.  A database already claimed by
// the cache must be refused rather than silently corrupted.
func TestStoreModeRejectsCacheDatabase(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dir := t.TempDir()

	db, err := local_cache.NewCacheDB(ctx, dir)
	require.NoError(t, err)
	require.NoError(t, db.EnsureStoreMode(local_cache.StoreModeCache))
	require.NoError(t, db.Close())

	egrp, _ := errgroup.WithContext(ctx)
	_, err = Open(ctx, egrp, Config{BaseDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache")
}

// TestStoreModeRejectsUnmarkedNonEmptyDatabase covers the legacy case: a cache
// database predating the marker holds data but claims nothing.  pstore always
// writes a marker, so such a database can only be a cache and must not be
// adopted.
func TestStoreModeRejectsUnmarkedNonEmptyDatabase(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dir := t.TempDir()

	db, err := local_cache.NewCacheDB(ctx, dir)
	require.NoError(t, err)
	// Write a record without claiming a mode, as a pre-marker cache would.
	require.NoError(t, db.SetNamespaceMapping("/legacy", 1))
	require.NoError(t, db.Close())

	egrp, _ := errgroup.WithContext(ctx)
	_, err = Open(ctx, egrp, Config{BaseDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pre-existing cache")
}

// TestStoreModePersistsAcrossReopen confirms a pstore reopens its own database
// and that the cache is then locked out of it.
func TestStoreModePersistsAcrossReopen(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dir := t.TempDir()
	egrp, _ := errgroup.WithContext(ctx)

	s, err := Open(ctx, egrp, Config{BaseDir: dir})
	require.NoError(t, err)
	require.NoError(t, s.Mkdir("/persisted"))
	require.NoError(t, s.Close())

	s2, err := Open(ctx, egrp, Config{BaseDir: dir})
	require.NoError(t, err)
	d, err := s2.Stat("/persisted")
	require.NoError(t, err)
	assert.True(t, d.IsDir())
	require.NoError(t, s2.Close())

	db, err := local_cache.NewCacheDB(ctx, dir)
	require.NoError(t, err)
	defer db.Close()
	err = db.EnsureStoreMode(local_cache.StoreModeCache)
	require.Error(t, err, "a cache must not open a pstore database")
	assert.Contains(t, err.Error(), "pstore")
}

func TestMkdirAndStat(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Mkdir("/proj"))
	d, err := s.Stat("/proj")
	require.NoError(t, err)
	assert.True(t, d.IsDir())

	assert.ErrorIs(t, s.Mkdir("/proj"), ErrExist, "re-creating a directory fails")
	assert.ErrorIs(t, s.Mkdir("/missing/deep"), ErrNotExist, "the parent must exist")

	_, err = s.Stat("/nope")
	assert.ErrorIs(t, err, ErrNotExist)
}

func TestMkdirAll(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.MkdirAll("/a/b/c"))
	for _, p := range []string{"/a", "/a/b", "/a/b/c"} {
		d, err := s.Stat(p)
		require.NoError(t, err, "%s should exist", p)
		assert.True(t, d.IsDir(), "%s should be a directory", p)
	}

	assert.NoError(t, s.MkdirAll("/a/b/c"), "MkdirAll is idempotent")
	assert.NoError(t, s.MkdirAll("/"), "MkdirAll on the root is a no-op")
}

// TestListReturnsOnlyDirectChildren is the central property of the index: a
// listing is one contiguous range holding exactly the direct children, with
// no descendants to filter out and no subtrees to seek past.
func TestListReturnsOnlyDirectChildren(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.MkdirAll("/d/sub/deeper"))
	require.NoError(t, s.Mkdir("/d/other"))
	require.NoError(t, s.Mkdir("/elsewhere"))

	entries, more, err := s.List("/d", "", 0)
	require.NoError(t, err)
	assert.False(t, more)

	names := entryNames(entries)
	assert.Equal(t, []string{"other", "sub"}, names,
		"only direct children, in name order")
}

// TestListOrderingWithAwkwardSiblings is the runtime counterpart to
// TestDirentKeyOrdering: the siblings that would break a full-path key layout
// must come back in plain name order.
func TestListOrderingWithAwkwardSiblings(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Mkdir("/a"))
	require.NoError(t, s.Mkdir("/a.b"))
	require.NoError(t, s.Mkdir("/a0b"))
	require.NoError(t, s.Mkdir("/a-b"))
	// Give /a descendants, which a full-path layout would interleave with
	// its siblings.
	require.NoError(t, s.MkdirAll("/a/x/y"))
	require.NoError(t, s.Mkdir("/a-b/child"))

	entries, _, err := s.List("/", "", 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "a-b", "a.b", "a0b"}, entryNames(entries))
}

func TestListPagination(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Mkdir("/d"))
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		require.NoError(t, s.Mkdir("/d/"+n))
	}

	first, more, err := s.List("/d", "", 2)
	require.NoError(t, err)
	assert.True(t, more)
	assert.Equal(t, []string{"a", "b"}, entryNames(first))

	second, more, err := s.List("/d", "b", 2)
	require.NoError(t, err)
	assert.True(t, more)
	assert.Equal(t, []string{"c", "d"}, entryNames(second))

	third, more, err := s.List("/d", "d", 2)
	require.NoError(t, err)
	assert.False(t, more, "the final page reports no remainder")
	assert.Equal(t, []string{"e"}, entryNames(third))
}

func TestListErrors(t *testing.T) {
	s := newTestStore(t)

	_, _, err := s.List("/missing", "", 0)
	assert.ErrorIs(t, err, ErrNotExist)

	// A file is not listable.
	require.NoError(t, s.Mkdir("/d"))
	require.NoError(t, putFileForTest(s, "/d/f", 10))
	_, _, err = s.List("/d/f", "", 0)
	assert.ErrorIs(t, err, ErrNotDir)
}

func TestListEmptyDirectory(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Mkdir("/empty"))
	entries, more, err := s.List("/empty", "", 0)
	require.NoError(t, err)
	assert.False(t, more)
	assert.Empty(t, entries, "an empty directory is a real, listable entry")
}

// putFileForTest writes a file dirent directly, without object data.  The
// write path arrives in a later phase; index-level tests only need an entry of
// the right type to exist.
func putFileForTest(s *Store, name string, size int64) error {
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return err
	}
	return s.bdb.Update(func(txn *badger.Txn) error {
		return putDirent(txn, cleanPath, &Dirent{
			Type:       EntryFile,
			Generation: "testgen",
			Size:       size,
			MTimeNanos: time.Now().UnixNano(),
			Mode:       uint32(defaultFileMode),
		})
	})
}

func entryNames(entries []ListEntry) []string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name
	}
	return names
}
