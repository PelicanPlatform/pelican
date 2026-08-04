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
	"context"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
)

// writeObject stores content at name through the normal write path.
func writeObject(t *testing.T, s *Store, name string, content []byte) {
	t.Helper()
	w, err := s.Create(name)
	require.NoError(t, err)
	n, err := w.Write(content)
	require.NoError(t, err)
	require.Equal(t, len(content), n)
	require.NoError(t, w.Close())
}

func randomBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rng := rand.New(rand.NewSource(seed))
	_, _ = rng.Read(b)
	return b
}

// TestWriteReadRoundTrip covers all three write tiers: inline, buffered with
// an exact length, and streamed past the spill threshold.
func TestWriteReadRoundTrip(t *testing.T) {
	s := newTestStore(t)

	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"tiny inline", 10},
		{"just under inline threshold", 4095},
		{"just over inline threshold", 4097},
		{"buffered", 1 << 20},
		{"just under spill threshold", spillThreshold - 1},
		{"streamed past spill", spillThreshold + (1 << 20)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := randomBytes(tc.size, int64(tc.size)+1)
			path := "/obj-" + strconv.Itoa(tc.size)

			writeObject(t, s, path, content)

			d, err := s.Stat(path)
			require.NoError(t, err)
			assert.False(t, d.IsDir())
			assert.Equal(t, int64(tc.size), d.Size, "dirent records the object size")
			assert.NotEmpty(t, d.Generation, "every version carries a generation")

			got, err := s.ReadAll(path)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(content, got), "content round-trips")
		})
	}
}

// TestWriteInIncrements checks that a caller streaming in small pieces gets
// the same result as one big write, including across the spill boundary.
func TestWriteInIncrements(t *testing.T) {
	s := newTestStore(t)

	content := randomBytes(spillThreshold+(2<<20), 99)
	w, err := s.Create("/streamed")
	require.NoError(t, err)
	for off := 0; off < len(content); off += 7919 {
		end := off + 7919
		if end > len(content) {
			end = len(content)
		}
		_, wErr := w.Write(content[off:end])
		require.NoError(t, wErr)
	}
	require.NoError(t, w.Close())

	got, err := s.ReadAll("/streamed")
	require.NoError(t, err)
	assert.True(t, bytes.Equal(content, got))
}

// TestWriteIsInvisibleUntilClose is the atomicity property: a reader sees
// either the old version or the new one, never a partial write.
func TestWriteIsInvisibleUntilClose(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", []byte("original"))

	w, err := s.Create("/obj")
	require.NoError(t, err)
	_, err = w.Write([]byte("replacement"))
	require.NoError(t, err)

	got, err := s.ReadAll("/obj")
	require.NoError(t, err)
	assert.Equal(t, "original", string(got), "the pending write is not visible")

	require.NoError(t, w.Close())
	got, err = s.ReadAll("/obj")
	require.NoError(t, err)
	assert.Equal(t, "replacement", string(got), "close swaps the version in")
}

// TestOverwriteChangesGeneration confirms each version gets a fresh token,
// which is what the ETag and the storage key are derived from.
func TestOverwriteChangesGeneration(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", []byte("v1"))
	first, err := s.Stat("/obj")
	require.NoError(t, err)

	writeObject(t, s, "/obj", []byte("v2"))
	second, err := s.Stat("/obj")
	require.NoError(t, err)

	assert.NotEqual(t, first.Generation, second.Generation)
	// etagFor is injective, so comparing two ETags adds nothing over comparing
	// the generations.  What is worth pinning is the rendering itself: the
	// origin emits this verbatim, and a strong entity tag must be quoted.
	assert.Equal(t, `"`+second.Generation+`"`, etagFor(second.Generation))
	assert.Empty(t, etagFor(""), "a directory has no entity tag")
}

// TestReaderSurvivesOverwrite is the reason reader pinning exists: a reader
// holding the old version must keep working after it is superseded and the
// janitor has run.
func TestReaderSurvivesOverwrite(t *testing.T) {
	s := newTestStore(t)

	original := randomBytes(256<<10, 5)
	writeObject(t, s, "/obj", original)

	r, err := s.OpenRead("/obj")
	require.NoError(t, err)
	defer r.Close()

	// Read a little, so the handle is genuinely mid-stream.
	head := make([]byte, 1024)
	_, err = io.ReadFull(r, head)
	require.NoError(t, err)

	writeObject(t, s, "/obj", []byte("replacement"))

	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.InstancesPinned, "the pinned version must be skipped")
	assert.Equal(t, 0, stats.InstancesFreed)

	rest, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(original, append(head, rest...)),
		"the open reader still sees the version it opened")
}

// TestGCReclaimsSupersededVersionOnceUnpinned completes the previous test:
// after the reader closes, the next pass frees the old version.
func TestGCReclaimsSupersededVersionOnceUnpinned(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", randomBytes(64<<10, 6))
	r, err := s.OpenRead("/obj")
	require.NoError(t, err)
	oldHash := instanceHashFor(s.db, r.Dirent().Generation)

	writeObject(t, s, "/obj", []byte("replacement"))

	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, stats.InstancesPinned)

	require.NoError(t, r.Close())

	stats, err = s.RunGC(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.InstancesFreed)
	assert.Equal(t, 0, stats.InstancesPinned)

	meta, err := s.db.GetMetadata(oldHash)
	require.NoError(t, err)
	assert.Nil(t, meta, "the superseded version is gone")
}

func TestRemoveFile(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", []byte("bye"))
	require.NoError(t, s.Remove("/obj"))

	_, err := s.Stat("/obj")
	assert.ErrorIs(t, err, ErrNotExist)

	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.InstancesFreed, "the deleted object's bytes are reclaimed")
}

func TestRemoveDirectory(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Mkdir("/d"))
	require.NoError(t, s.Remove("/d"), "an empty directory can be removed")

	require.NoError(t, s.Mkdir("/d2"))
	writeObject(t, s, "/d2/f", []byte("x"))
	assert.ErrorIs(t, s.Remove("/d2"), ErrNotEmpty, "a populated directory cannot")
}

// TestRemoveAllDrainsSubtree covers the detach-then-drain path: the subtree
// disappears at once and the janitor reclaims it afterwards.
//
// The subtree is deliberately larger than one removal transaction.  A small
// one is removed inline and never reaches the janitor at all, so a masking
// bug that never actually reclaimed anything would pass unnoticed.
func TestRemoveAllDrainsSubtree(t *testing.T) {
	s := newTestStore(t)

	makeDeferredSubtree(t, s, "/tree")
	writeObject(t, s, "/tree/a/b/marker", []byte("gone"))
	marker, err := s.Stat("/tree/a/b/marker")
	require.NoError(t, err)
	markerHash := instanceHashFor(s.db, marker.Generation)
	writeObject(t, s, "/outside", []byte("keep"))

	require.NoError(t, s.RemoveAll("/tree"))
	require.Equal(t, 1, s.detached.len(), "a deferred removal is masked while it drains")

	_, err = s.Stat("/tree")
	assert.ErrorIs(t, err, ErrNotExist, "the subtree is unreachable immediately")
	_, err = s.Stat("/tree/a/b/marker")
	assert.ErrorIs(t, err, ErrNotExist)

	// Drain until the queue is genuinely empty, and insist that it empties:
	// masking without reclaiming would leave every one of these bytes on disk.
	// A pass that finishes the subtree only *enqueues* its objects, so the
	// loop has to run until a pass does nothing at all.
	drained := false
	for range 20 {
		stats, gErr := s.RunGC(t.Context())
		require.NoError(t, gErr)
		idle := stats.InstancesFreed == 0 && stats.SubtreeEntriesRemoved == 0 &&
			stats.InstancesPinned == 0 && !stats.HitBatchLimit
		if idle && s.detached.len() == 0 {
			drained = true
			break
		}
	}
	require.True(t, drained, "the janitor must finish draining the detached subtree")
	assert.Zero(t, s.detached.len(), "the mask lifts once nothing is left in the index")

	// Nothing of the subtree survives in either the index or block storage.
	require.NoError(t, s.bdb.View(func(txn *badger.Txn) error {
		return walkSubtree(txn, "/tree", func(entryPath string, _ *Dirent) error {
			return assertNoEntry(entryPath)
		})
	}))
	meta, err := s.db.GetMetadata(markerHash)
	require.NoError(t, err)
	assert.Nil(t, meta, "the removed objects' bytes are reclaimed, not merely hidden")

	got, err := s.ReadAll("/outside")
	require.NoError(t, err)
	assert.Equal(t, "keep", string(got), "an unrelated object is untouched")
}

// assertNoEntry turns a surviving index key into an error the walk reports.
func assertNoEntry(entryPath string) error {
	return errors.Errorf("%s still has an index entry after the drain", entryPath)
}

func TestRemoveAllMissingIsNotAnError(t *testing.T) {
	s := newTestStore(t)
	assert.NoError(t, s.RemoveAll("/never-existed"))
}

// TestRenameFileMovesNoData checks the central rename property: the entry
// moves, the object's identity does not, so the content is unchanged and no
// data file is touched.
func TestRenameFileMovesNoData(t *testing.T) {
	s := newTestStore(t)

	content := randomBytes(128<<10, 11)
	writeObject(t, s, "/a", content)
	before, err := s.Stat("/a")
	require.NoError(t, err)

	require.NoError(t, s.Mkdir("/dst"))
	require.NoError(t, s.Rename("/a", "/dst/b"))

	_, err = s.Stat("/a")
	assert.ErrorIs(t, err, ErrNotExist)

	after, err := s.Stat("/dst/b")
	require.NoError(t, err)
	assert.Equal(t, before.Generation, after.Generation,
		"identity comes from the generation, not the path")

	got, err := s.ReadAll("/dst/b")
	require.NoError(t, err)
	assert.True(t, bytes.Equal(content, got))
}

func TestRenameDirectoryRebasesDescendants(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.MkdirAll("/old/sub"))
	writeObject(t, s, "/old/f1", []byte("one"))
	writeObject(t, s, "/old/sub/f2", []byte("two"))
	// A sibling sharing a prefix must not be dragged along.
	require.NoError(t, s.Mkdir("/old-sibling"))
	writeObject(t, s, "/old-sibling/f3", []byte("three"))

	require.NoError(t, s.Rename("/old", "/new"))

	for path, want := range map[string]string{
		"/new/f1":         "one",
		"/new/sub/f2":     "two",
		"/old-sibling/f3": "three",
	} {
		got, err := s.ReadAll(path)
		require.NoError(t, err, "%s should be readable", path)
		assert.Equal(t, want, string(got))
	}

	_, err := s.Stat("/old")
	assert.ErrorIs(t, err, ErrNotExist)
	_, err = s.Stat("/old/sub/f2")
	assert.ErrorIs(t, err, ErrNotExist)
}

func TestRenameRejectsMoveBeneathItself(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.MkdirAll("/d/sub"))
	err := s.Rename("/d", "/d/sub/d")
	assert.ErrorIs(t, err, ErrInvalidPath)
}

func TestRenameReplacesDestinationFile(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/src", []byte("source"))
	writeObject(t, s, "/dst", []byte("destination"))

	require.NoError(t, s.Rename("/src", "/dst"))
	got, err := s.ReadAll("/dst")
	require.NoError(t, err)
	assert.Equal(t, "source", string(got))

	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.InstancesFreed, "the replaced version is reclaimed")
}

func TestConditionalWrites(t *testing.T) {
	s := newTestStore(t)

	t.Run("require absent on a new object", func(t *testing.T) {
		w, err := s.Create("/fresh")
		require.NoError(t, err)
		w.RequireAbsent()
		_, err = w.Write([]byte("x"))
		require.NoError(t, err)
		assert.NoError(t, w.Close())
	})

	t.Run("require absent on an existing object", func(t *testing.T) {
		w, err := s.Create("/fresh")
		require.NoError(t, err)
		w.RequireAbsent()
		_, err = w.Write([]byte("y"))
		require.NoError(t, err)
		assert.ErrorIs(t, w.Close(), ErrExist)

		got, rErr := s.ReadAll("/fresh")
		require.NoError(t, rErr)
		assert.Equal(t, "x", string(got), "the refused write left the object alone")
	})

	t.Run("require matching generation", func(t *testing.T) {
		current, err := s.Stat("/fresh")
		require.NoError(t, err)

		w, err := s.Create("/fresh")
		require.NoError(t, err)
		w.RequireGeneration(current.Generation)
		_, err = w.Write([]byte("updated"))
		require.NoError(t, err)
		assert.NoError(t, w.Close())
	})

	t.Run("require stale generation", func(t *testing.T) {
		w, err := s.Create("/fresh")
		require.NoError(t, err)
		w.RequireGeneration("0000000000000000")
		_, err = w.Write([]byte("nope"))
		require.NoError(t, err)
		assert.ErrorIs(t, w.Close(), ErrPreconditionFailed)

		got, rErr := s.ReadAll("/fresh")
		require.NoError(t, rErr)
		assert.Equal(t, "updated", string(got))
	})
}

func TestWriteErrors(t *testing.T) {
	s := newTestStore(t)

	_, err := s.Create("/missing/f")
	assert.ErrorIs(t, err, ErrNotExist, "the parent must exist")

	require.NoError(t, s.Mkdir("/d"))
	_, err = s.Create("/d")
	assert.ErrorIs(t, err, ErrIsDir, "a directory cannot be overwritten by a file")

	_, err = s.OpenRead("/d")
	assert.ErrorIs(t, err, ErrIsDir)

	_, err = s.OpenRead("/nothing")
	assert.ErrorIs(t, err, ErrNotExist)
}

// TestAbortLeavesNothingBehind confirms a torn-off upload neither appears in
// the namespace nor holds capacity.
func TestAbortLeavesNothingBehind(t *testing.T) {
	s := newTestStore(t)

	usedBefore, _ := s.capacity.aggregateUsage()

	w, err := s.Create("/aborted")
	require.NoError(t, err)
	_, err = w.Write(randomBytes(spillThreshold+1024, 12))
	require.NoError(t, err)
	require.NoError(t, w.Abort())

	_, err = s.Stat("/aborted")
	assert.ErrorIs(t, err, ErrNotExist)

	usedAfter, _ := s.capacity.aggregateUsage()
	assert.Equal(t, usedBefore, usedAfter, "an aborted write releases its reservation")
}

// TestDetachedSubtreeDescendantsAreInvisible guards a consequence of
// path-derived keys that is easy to reintroduce.
//
// RemoveAll on a subtree too large for one transaction unlinks the directory
// and leaves the janitor to drain its descendants, but a lookup here is a
// single point get that never consults ancestors -- that is precisely why
// listing a directory is cheap. So a descendant's key outlives its parent, and
// without explicit masking a deep path would still resolve after its tree was
// deleted.
func TestDetachedSubtreeDescendantsAreInvisible(t *testing.T) {
	s := newTestStore(t)

	makeDeferredSubtree(t, s, "/tree")
	require.NoError(t, s.RemoveAll("/tree"))
	require.Equal(t, 1, s.detached.len(), "a large subtree is masked while it drains")

	for _, p := range []string{"/tree", "/tree/a", "/tree/a/b", "/tree/a/b/f0"} {
		_, err := s.Stat(p)
		assert.ErrorIs(t, err, ErrNotExist, "%s must not resolve after its tree is removed", p)
	}

	_, err := s.OpenRead("/tree/a/b/f0")
	assert.ErrorIs(t, err, ErrNotExist, "a detached object cannot be opened")

	_, _, err = s.List("/tree/a", "", 0)
	assert.ErrorIs(t, err, ErrNotExist, "a detached directory cannot be listed")

	// Writing into a tree that is still draining is refused outright rather
	// than placed where the drain will delete it.
	_, err = s.Create("/tree/a/new")
	assert.ErrorIs(t, err, ErrDraining)
}

// TestDetachedMaskClearsAfterDrain confirms the mask is not permanent: once
// the janitor has drained the tree the path is reusable.
func TestDetachedMaskClearsAfterDrain(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.MkdirAll("/tree/a"))
	writeObject(t, s, "/tree/a/f", []byte("data"))
	require.NoError(t, s.RemoveAll("/tree"))

	for range 5 {
		if _, err := s.RunGC(t.Context()); err != nil {
			t.Fatalf("gc pass failed: %v", err)
		}
		if s.detached.len() == 0 {
			break
		}
	}
	require.Equal(t, 0, s.detached.len(), "the mask lifts once the tree is drained")

	// The path is free again.
	require.NoError(t, s.MkdirAll("/tree/a"))
	writeObject(t, s, "/tree/a/f", []byte("fresh"))
	got, err := s.ReadAll("/tree/a/f")
	require.NoError(t, err)
	assert.Equal(t, "fresh", string(got))
}

// TestDetachedMaskSurvivesReopen covers the crash case: a store that stopped
// mid-drain must not expose the half-deleted tree when it comes back.
func TestDetachedMaskSurvivesReopen(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dir := t.TempDir()
	egrp, _ := errgroup.WithContext(ctx)

	s, err := Open(ctx, egrp, Config{BaseDir: dir})
	require.NoError(t, err)
	makeDeferredSubtree(t, s, "/tree")
	require.NoError(t, s.RemoveAll("/tree"))
	require.Equal(t, 1, s.detached.len())
	// Close without draining, standing in for a crash.
	require.NoError(t, s.Close())

	s2, err := Open(ctx, egrp, Config{BaseDir: dir})
	require.NoError(t, err)
	defer s2.Close()

	assert.Equal(t, 1, s2.detached.len(), "the pending drain is recovered from the queue")
	_, err = s2.Stat("/tree/a/b/f0")
	assert.ErrorIs(t, err, ErrNotExist, "a half-deleted tree stays invisible across a restart")
}

// TestRemoveAllLargeSubtreeDrainsAcrossPasses exercises the batching: a
// subtree bigger than one transaction is drained over several passes and is
// invisible throughout.
func TestRemoveAllLargeSubtreeDrainsAcrossPasses(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Mkdir("/big"))
	const count = subtreeBatchSize + 50
	for i := range count {
		writeObject(t, s, "/big/f"+strconv.Itoa(i), []byte("x"))
	}

	require.NoError(t, s.RemoveAll("/big"))
	_, err := s.Stat("/big/f0")
	assert.ErrorIs(t, err, ErrNotExist)

	passes := 0
	for s.detached.len() > 0 && passes < 20 {
		_, gErr := s.RunGC(t.Context())
		require.NoError(t, gErr)
		passes++
	}
	assert.Zero(t, s.detached.len(), "the subtree drains across passes")
	assert.Greater(t, passes, 1, "a subtree this size needs more than one pass")
}

// TestSubtreeRecreatedImmediately is the case where masking and draining
// could collide: a tree is removed and the same paths recreated at once.
//
// Because a subtree that fits in one transaction is removed inline, there is
// no window at all -- the paths are free the moment RemoveAll returns. That is
// the whole reason removal is not deferred by default.
func TestSubtreeRecreatedImmediately(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.MkdirAll("/tree/a"))
	writeObject(t, s, "/tree/a/f", []byte("original"))
	original, err := s.Stat("/tree/a/f")
	require.NoError(t, err)

	require.NoError(t, s.RemoveAll("/tree"))
	assert.Zero(t, s.detached.len(), "a small subtree needs no mask; it is already gone")

	// Recreate the very same paths straight away.
	require.NoError(t, s.MkdirAll("/tree/a"))
	writeObject(t, s, "/tree/a/f", []byte("recreated"))

	got, err := s.ReadAll("/tree/a/f")
	require.NoError(t, err)
	assert.Equal(t, "recreated", string(got))

	recreated, err := s.Stat("/tree/a/f")
	require.NoError(t, err)
	assert.NotEqual(t, original.Generation, recreated.Generation,
		"the recreated object is a new version, not the old one resurfacing")

	// A GC pass must not disturb the recreated tree.
	for range 5 {
		_, gErr := s.RunGC(t.Context())
		require.NoError(t, gErr)
	}
	after, err := s.ReadAll("/tree/a/f")
	require.NoError(t, err, "reclamation must not touch the recreated object")
	assert.Equal(t, "recreated", string(after))

	oldMeta, err := s.db.GetMetadata(instanceHashFor(s.db, original.Generation))
	require.NoError(t, err)
	assert.Nil(t, oldMeta, "the removed version was reclaimed")
}

// TestLargeSubtreeRecreatedWhileDraining covers the case that cannot be made
// instantaneous.  A subtree too large to remove in one transaction is drained
// in the background, and its descendants still occupy the keys a recreated
// tree would use -- so recreation is refused until the drain finishes, rather
// than writing data the drain would then delete.
func TestLargeSubtreeRecreatedWhileDraining(t *testing.T) {
	s := newTestStore(t)

	makeDeferredSubtree(t, s, "/tree")
	require.NoError(t, s.RemoveAll("/tree"))
	require.Equal(t, 1, s.detached.len())

	err := s.MkdirAll("/tree/a")
	assert.ErrorIs(t, err, ErrDraining, "recreating a draining tree is refused, not silently lost")

	// Once drained, the paths are free again.
	for range 20 {
		if _, gErr := s.RunGC(t.Context()); gErr != nil {
			t.Fatalf("gc pass failed: %v", gErr)
		}
		if s.detached.len() == 0 {
			break
		}
	}
	require.Zero(t, s.detached.len())

	require.NoError(t, s.MkdirAll("/tree/a/b"))
	writeObject(t, s, "/tree/a/b/f0", []byte("recreated"))
	got, err := s.ReadAll("/tree/a/b/f0")
	require.NoError(t, err)
	assert.Equal(t, "recreated", string(got))
}

// makeDeferredSubtree builds a subtree larger than one removal transaction, so
// RemoveAll must detach it and leave the janitor to drain.
func makeDeferredSubtree(t *testing.T, s *Store, root string) {
	t.Helper()
	require.NoError(t, s.MkdirAll(root+"/a/b"))
	for i := range subtreeBatchSize + 50 {
		writeObject(t, s, root+"/a/b/f"+strconv.Itoa(i), []byte("x"))
	}
}

// TestGCReportsBacklog drives the signal the janitor uses to speed up: a sweep
// that fills its batch says so, and one that clears the queue does not.
func TestGCReportsBacklog(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Mkdir("/many"))
	// Enough objects that deleting them all outruns a single sweep.
	for i := range janitorBatchSize + 100 {
		writeObject(t, s, "/many/f"+strconv.Itoa(i), []byte("x"))
		require.NoError(t, s.Remove("/many/f"+strconv.Itoa(i)))
	}

	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	assert.True(t, stats.HitBatchLimit,
		"a queue larger than one batch must ask for another sweep sooner")
	assert.Equal(t, janitorBatchSize, stats.InstancesFreed)

	// Drain the rest.
	for range 10 {
		stats, err = s.RunGC(t.Context())
		require.NoError(t, err)
		if !stats.HitBatchLimit {
			break
		}
	}
	assert.False(t, stats.HitBatchLimit, "an emptied queue stops asking")
}

// ---------------------------------------------------------------------------
// Draining subtrees and rename
// ---------------------------------------------------------------------------

// TestRenameOntoADrainingSubtreeIsRefused guards the worst failure the store
// had: a rename whose destination was a subtree still being reclaimed.
//
// Create, Mkdir and MkdirAll all consult the drain queue; Rename did not, and
// its resolves go through the masking resolver, which reports a detached path
// as ErrNotExist.  The destination therefore looked free, the rename
// "succeeded", the source was rebased onto keys the janitor was about to walk,
// and the drain then deleted both trees -- with no error reported anywhere.
func TestRenameOntoADrainingSubtreeIsRefused(t *testing.T) {
	s := newTestStore(t)

	makeDeferredSubtree(t, s, "/tree")
	require.NoError(t, s.MkdirAll("/src/inner"))
	writeObject(t, s, "/src/inner/precious", []byte("precious"))

	require.NoError(t, s.RemoveAll("/tree"))
	require.Equal(t, 1, s.detached.len(), "the subtree is too large to remove inline")

	err := s.Rename("/src", "/tree")
	require.Error(t, err, "renaming onto a draining subtree must not appear to succeed")
	assert.ErrorIs(t, err, ErrDraining)

	// The source survived, entry and content both.
	d, err := s.Stat("/src/inner/precious")
	require.NoError(t, err)
	assert.False(t, d.IsDir())
	got, err := s.ReadAll("/src/inner/precious")
	require.NoError(t, err)
	assert.Equal(t, "precious", string(got))

	// A descendant of the draining root is no better a destination...
	assert.ErrorIs(t, s.Rename("/src", "/tree/a"), ErrDraining)
	// ...and renaming out of one is refused rather than resurrecting it.
	assert.ErrorIs(t, s.Rename("/tree/a", "/moved"), ErrDraining)
	_, err = s.Stat("/moved")
	assert.ErrorIs(t, err, ErrNotExist)

	// Once the drain completes the source is still intact and the path frees up.
	for range 20 {
		_, gErr := s.RunGC(t.Context())
		require.NoError(t, gErr)
		if s.detached.len() == 0 {
			break
		}
	}
	require.Zero(t, s.detached.len())

	got, err = s.ReadAll("/src/inner/precious")
	require.NoError(t, err)
	assert.Equal(t, "precious", string(got), "the drain must not have touched the source")

	require.NoError(t, s.Rename("/src", "/tree"))
	got, err = s.ReadAll("/tree/inner/precious")
	require.NoError(t, err)
	assert.Equal(t, "precious", string(got))
}

// TestRenameOfAnEnormousDirectoryIsRefusedClearly covers the other rename
// limit.  A directory rename rewrites every descendant key in one transaction,
// and BadgerDB caps how much that transaction may hold; past the cap the
// commit failed with "Txn is too big to fit into one request", which is not
// something a client can act on.  The refusal must be typed and the tree
// untouched.
func TestRenameOfAnEnormousDirectoryIsRefusedClearly(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Mkdir("/huge"))
	require.NoError(t, s.bdb.Update(func(txn *badger.Txn) error {
		for i := range renameSubtreeLimit + 1 {
			if err := putDirent(txn, "/huge/f"+strconv.Itoa(i), &Dirent{
				Type: EntryFile,
				Mode: uint32(defaultFileMode),
			}); err != nil {
				return err
			}
		}
		return nil
	}))

	err := s.Rename("/huge", "/renamed")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotSupported)
	assert.Contains(t, err.Error(), "smaller groups", "the message has to be actionable")

	// Nothing moved.
	_, err = s.Stat("/renamed")
	assert.ErrorIs(t, err, ErrNotExist)
	_, err = s.Stat("/huge/f0")
	assert.NoError(t, err, "a refused rename leaves the source exactly as it was")
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestConcurrentOverwriteAndOpenNeverFailsSpuriously drives the race between
// resolving a path and opening the version it names.
//
// An overwrite commits between those two steps, the superseded version is
// queued, and the janitor -- finding it unpinned -- reclaims it, so the open
// fails on a version that was current a moment earlier.  The error is not
// ErrNotExist, so it reaches the client as a 500 for an object that existed
// throughout.  Not one open here is allowed to fail.
func TestConcurrentOverwriteAndOpenNeverFailsSpuriously(t *testing.T) {
	s := newTestStore(t)

	content := randomBytes(32<<10, 51)
	writeObject(t, s, "/hot", content)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var grp errgroup.Group

	// A steady stream of overwrites, each superseding a version a reader may
	// have just resolved.
	grp.Go(func() error {
		for ctx.Err() == nil {
			w, err := s.Create("/hot")
			if err != nil {
				return errors.Wrap(err, "overwriter failed to create")
			}
			if _, wErr := w.Write(content); wErr != nil {
				_ = w.Abort()
				return errors.Wrap(wErr, "overwriter failed to write")
			}
			if cErr := w.Close(); cErr != nil {
				return errors.Wrap(cErr, "overwriter failed to close")
			}
		}
		return nil
	})

	// ...and a janitor racing to reclaim what the overwrites supersede.
	grp.Go(func() error {
		for ctx.Err() == nil {
			if _, err := s.RunGC(ctx); err != nil {
				return errors.Wrap(err, "gc pass failed")
			}
		}
		return nil
	})

	grp.Go(func() error {
		// Stopping the other two is this goroutine's job, so the group drains
		// as soon as the sampling is done.
		defer cancel()
		for i := range 2000 {
			r, err := s.OpenRead("/hot")
			if err != nil {
				return errors.Wrapf(err, "open %d of an object that exists throughout failed", i)
			}
			if cErr := r.Close(); cErr != nil {
				return errors.Wrap(cErr, "closing a reader failed")
			}
		}
		return nil
	})

	require.NoError(t, grp.Wait())
}

// ---------------------------------------------------------------------------
// Crash safety
// ---------------------------------------------------------------------------

// TestCrashBetweenMaterializeAndCommitLeavesNoUnqueuedOrphan covers the window
// the design claims does not exist.
//
// materialize writes the metadata record, the block state, the data files and
// the usage charge before the commit transaction runs.  Process death in there
// would otherwise leave bytes charged to the usage counters with no dirent
// pointing at them and nothing in the reclamation queue -- recoverable only by
// an offline fsck --repair.  Queueing the version before materialization
// starts, and clearing that entry in the transaction that makes it reachable,
// turns the crash into ordinary janitor work.
func TestCrashBetweenMaterializeAndCommitLeavesNoUnqueuedOrphan(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	dir := t.TempDir()
	cfg := Config{
		BaseDir:     dir,
		StorageDirs: []local_cache.StorageDirConfig{{Path: dir, MaxSize: 64 << 20}},
	}

	s, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	baseline, _ := s.Usage()

	w, err := s.CreateSized("/crashed", 2<<20)
	require.NoError(t, err)
	_, err = w.Write(randomBytes(2<<20, 31))
	require.NoError(t, err)

	// Stand in for process death between materialization and the commit that
	// would install the object: everything is on disk and charged, nothing
	// points at it, and Close is never reached.
	require.NoError(t, w.beginMaterialize())
	_, err = w.materialize()
	require.NoError(t, err)
	hash := w.instanceHash
	require.NoError(t, s.Close())

	s2, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	defer s2.Close()

	_, err = s2.Stat("/crashed")
	assert.ErrorIs(t, err, ErrNotExist, "the half-written version is not reachable")

	meta, err := s2.db.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "its bytes really are on disk")
	orphaned, _ := s2.Usage()
	require.Greater(t, orphaned, baseline, "and really are charged against the store")

	// The janitor reclaims it unaided; no offline fsck required.
	stats, err := s2.RunGC(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.InstancesFreed, "the orphan was queued, not stranded")

	meta, err = s2.db.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, meta)
	recovered, _ := s2.Usage()
	assert.Equal(t, baseline, recovered, "and the capacity it held comes back")
}

// TestSuccessfulWriteLeavesNothingQueued is the other half: the crash-window
// marker must not survive a write that lands, or every object would arrive
// with a reclamation entry against it.
func TestSuccessfulWriteLeavesNothingQueued(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/clean", randomBytes(spillThreshold+(1<<20), 61))

	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	assert.Zero(t, stats.InstancesFreed, "a committed object is not garbage")
	assert.Zero(t, stats.InstancesPinned)

	got, err := s.ReadAll("/clean")
	require.NoError(t, err)
	assert.Len(t, got, spillThreshold+(1<<20))
}

// TestRefusedZeroLengthWriteLeavesNoMetadata covers the catalog leak the abort
// path has to avoid: materialize stores an inline record even for a zero-byte
// object, so a discard that skipped cleanup unless bytes had been written would
// leave a refused conditional write's m: record behind with nothing referencing
// it.
func TestRefusedZeroLengthWriteLeavesNoMetadata(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/f", []byte("existing"))

	w, err := s.Create("/f")
	require.NoError(t, err)
	w.RequireAbsent()
	// Not one byte is written, so the object materializes as an empty inline
	// record before the commit refuses it.
	assert.ErrorIs(t, w.Close(), ErrExist)

	meta, err := s.db.GetMetadata(instanceHashFor(s.db, w.Generation()))
	require.NoError(t, err)
	assert.Nil(t, meta, "the refused write leaves no metadata record behind")

	got, err := s.ReadAll("/f")
	require.NoError(t, err)
	assert.Equal(t, "existing", string(got), "and the existing object is untouched")
}

// TestZeroLengthObjectRoundTrips is the companion property: an empty object is
// a real object, and refusing one write must not have broken writing one.
func TestZeroLengthObjectRoundTrips(t *testing.T) {
	s := newTestStore(t)

	w, err := s.Create("/empty")
	require.NoError(t, err)
	require.NoError(t, w.Close())

	d, err := s.Stat("/empty")
	require.NoError(t, err)
	assert.Zero(t, d.Size)

	got, err := s.ReadAll("/empty")
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestConcurrentWritesToOnePathElectOneWinner covers the commit race between
// two writers to the same path.
//
// The index is serializable, so BadgerDB aborts the second of two commits that
// touch the same entry rather than serializing it.  Surfaced as-is that is a
// bare "Transaction Conflict. Please retry", which the origin would turn into a
// 500 -- for something that is an ordinary concurrent PUT and entirely
// retryable.  Close retries it internally instead.
func TestConcurrentWritesToOnePathElectOneWinner(t *testing.T) {
	const writers = 8

	t.Run("unconditional writes all land", func(t *testing.T) {
		s := newTestStore(t)

		var (
			start = make(chan struct{})
			grp   errgroup.Group
			mu    sync.Mutex
			seen  []string
		)
		for i := range writers {
			grp.Go(func() error {
				w, err := s.Create("/contended")
				if err != nil {
					return err
				}
				if _, wErr := w.Write([]byte("payload-" + strconv.Itoa(i))); wErr != nil {
					_ = w.Abort()
					return wErr
				}
				mu.Lock()
				seen = append(seen, w.Generation())
				mu.Unlock()

				// Commit all of them at once, which is what makes the
				// transactions overlap.
				<-start
				return w.Close()
			})
		}
		close(start)
		require.NoError(t, grp.Wait(),
			"a concurrent commit must be retried, not reported as a conflict")

		// Exactly one version is installed, and it is one of the writers'.
		d, err := s.Stat("/contended")
		require.NoError(t, err)
		assert.Contains(t, seen, d.Generation)

		got, err := s.ReadAll("/contended")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(got), "payload-"))

		// The seven superseded versions are queued and reclaimed, and nothing
		// is stranded: the queue empties and only the winner's bytes remain.
		drainQueue(t, s)
		assertQueueEmpty(t, s)
		assertOnlyInstancesRemain(t, s, instanceHashFor(s.db, d.Generation))
	})

	t.Run("require-absent elects exactly one", func(t *testing.T) {
		s := newTestStore(t)

		var (
			start   = make(chan struct{})
			grp     errgroup.Group
			mu      sync.Mutex
			winners []string
			losers  []error
		)
		for i := range writers {
			grp.Go(func() error {
				w, err := s.Create("/exclusive")
				if err != nil {
					return err
				}
				w.RequireAbsent()
				if _, wErr := w.Write([]byte("payload-" + strconv.Itoa(i))); wErr != nil {
					_ = w.Abort()
					return wErr
				}

				<-start
				cErr := w.Close()
				mu.Lock()
				defer mu.Unlock()
				if cErr == nil {
					winners = append(winners, w.Generation())
				} else {
					losers = append(losers, cErr)
				}
				return nil
			})
		}
		close(start)
		require.NoError(t, grp.Wait())

		// This is the property a naive retry breaks: re-running the commit
		// against the state read before the first attempt would let a second
		// writer's RequireAbsent pass after the first had already installed.
		require.Len(t, winners, 1, "If-None-Match: * must admit exactly one writer")
		assert.Len(t, losers, writers-1)
		for _, err := range losers {
			assert.ErrorIs(t, err, ErrExist,
				"a loser is refused on the precondition, not on a database conflict")
			assert.NotErrorIs(t, err, ErrConflict)
		}

		d, err := s.Stat("/exclusive")
		require.NoError(t, err)
		assert.Equal(t, winners[0], d.Generation)

		// The refused writers' instances are queued by their own crash-window
		// marker and reclaimed; none is left charged against the store.
		drainQueue(t, s)
		assertQueueEmpty(t, s)
		assertOnlyInstancesRemain(t, s, instanceHashFor(s.db, d.Generation))
	})
}

// drainQueue runs reclamation passes until one does nothing.
func drainQueue(t *testing.T, s *Store) {
	t.Helper()
	for range 20 {
		stats, err := s.RunGC(t.Context())
		require.NoError(t, err)
		if stats.InstancesFreed == 0 && stats.InstancesPinned == 0 &&
			stats.SubtreeEntriesRemoved == 0 && !stats.HitBatchLimit {
			return
		}
	}
	t.Fatal("the reclamation queue never emptied")
}

// assertQueueEmpty checks that nothing is left waiting for the janitor.
func assertQueueEmpty(t *testing.T, s *Store) {
	t.Helper()
	instances, subtrees, _, err := s.collectGarbage()
	require.NoError(t, err)
	assert.Empty(t, instances, "no object version may be left queued")
	assert.Empty(t, subtrees, "no subtree may be left queued")
}

// assertOnlyInstancesRemain checks that the catalog holds metadata for exactly
// the given versions -- nothing orphaned, nothing over-reclaimed.
func assertOnlyInstancesRemain(t *testing.T, s *Store, want ...local_cache.InstanceHash) {
	t.Helper()

	wanted := make(map[local_cache.InstanceHash]bool, len(want))
	for _, h := range want {
		wanted[h] = true
		meta, err := s.db.GetMetadata(h)
		require.NoError(t, err)
		assert.NotNil(t, meta, "the installed version %s must still be present", h)
	}

	var surplus []string
	require.NoError(t, s.bdb.View(func(txn *badger.Txn) error {
		prefix := []byte(local_cache.PrefixMeta)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			h := local_cache.InstanceHash(it.Item().Key()[len(prefix):])
			if !wanted[h] {
				surplus = append(surplus, string(h))
			}
		}
		return nil
	}))
	assert.Empty(t, surplus, "no object version may be left orphaned in the catalog")
}

// TestJanitorReclaimsAbandonedStreamingWrites covers the one leak the pg:
// queue structurally cannot see.
//
// A write is queued for reclamation at the start of materialization, which
// covers everything from there to the commit.  Before that the object is a
// partly written stream: chunk files allocated and charged, tracked only by
// the block store's own append-in-flight marker, with nothing in the pg: queue
// referring to it.  The block store reclaims those from a sweep the cache
// drives out of its eviction manager -- which a pstore never constructs, so on
// an origin the sweep simply never ran.
func TestJanitorReclaimsAbandonedStreamingWrites(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	dir := t.TempDir()
	cfg := Config{
		BaseDir:     dir,
		StorageDirs: []local_cache.StorageDirConfig{{Path: dir, MaxSize: 64 << 20}},
	}

	s, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	baseline, _ := s.Usage()

	w, err := s.CreateSized("/abandoned", 4<<20)
	require.NoError(t, err)
	_, err = w.Write(randomBytes(4<<20, 41))
	require.NoError(t, err)
	hash := w.instanceHash

	// Never finalized, never aborted: the handle simply goes away with the
	// process.  Reopening also clears the block store's live-writer registry,
	// which is what makes the leftover indistinguishable from a crash.
	require.NoError(t, s.Close())

	s2, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	defer s2.Close()

	meta, err := s2.db.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "the interrupted stream's chunks are on disk")
	require.True(t, meta.Completed.IsZero(), "and it was never finalized")

	leaked, _ := s2.Usage()
	require.Greater(t, leaked, baseline, "and its chunks are charged against the store")

	// Nothing in the reclamation queue refers to it, which is precisely why
	// the append sweep has to exist.
	instances, _, _, err := s2.collectGarbage()
	require.NoError(t, err)
	require.NotContains(t, instances, newQueuedInstance(string(hash)))

	// A pass at the real grace period leaves it alone: an upload that is
	// merely slow must never be deleted out from under its client.
	stats, err := s2.RunGC(t.Context())
	require.NoError(t, err)
	assert.Zero(t, stats.AbandonedAppendsReclaimed,
		"a freshly abandoned write is still within the grace period")
	meta, err = s2.db.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)

	// Backdate the record past the grace period, standing in for the passage
	// of time, and the janitor reclaims it -- no separate ticker, no eviction
	// manager, just the ordinary sweep.
	require.NoError(t, s2.db.SetAppendIntent(hash, local_cache.AppendIntent{
		StartedAt: time.Now().Add(-2 * appendReclaimGrace),
	}))

	stats, err = s2.RunGC(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.AbandonedAppendsReclaimed)

	meta, err = s2.db.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, meta, "the abandoned stream is gone")

	recovered, _ := s2.Usage()
	assert.Equal(t, baseline, recovered, "and the capacity it held comes back")
}

// TestAppendSweepLeavesLiveWritersAlone is the safety half: an upload in
// progress in this process must survive the sweep however long it takes, since
// the grace period cannot distinguish slow from dead.
func TestAppendSweepLeavesLiveWritersAlone(t *testing.T) {
	s := newTestStore(t)

	w, err := s.CreateSized("/slow", 4<<20)
	require.NoError(t, err)
	_, err = w.Write(randomBytes(2<<20, 43))
	require.NoError(t, err)

	// Zero grace: only the live-writer registry can save it.
	n, err := s.ReclaimAbandonedAppends(0)
	require.NoError(t, err)
	assert.Zero(t, n, "a writer this process still holds is not abandoned")

	// And the write completes normally afterwards.
	_, err = w.Write(randomBytes(2<<20, 44))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	got, err := s.ReadAll("/slow")
	require.NoError(t, err)
	assert.Len(t, got, 4<<20)

	// A finished write leaves no marker for a later sweep to trip over.
	n, err = s.ReclaimAbandonedAppends(0)
	require.NoError(t, err)
	assert.Zero(t, n)
	d, err := s.Stat("/slow")
	require.NoError(t, err)
	assert.Equal(t, int64(4<<20), d.Size)
}
