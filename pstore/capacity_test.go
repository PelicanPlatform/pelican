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
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
)

// newBoundedStore opens a store whose single directory has a hard ceiling.
func newBoundedStore(t *testing.T, maxBytes uint64) *Store {
	t.Helper()
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, _ := errgroup.WithContext(ctx)

	dir := t.TempDir()
	s, err := Open(ctx, egrp, Config{
		BaseDir:     dir,
		StorageDirs: []local_cache.StorageDirConfig{{Path: dir, MaxSize: maxBytes}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })
	return s
}

func TestCapacityCeilingFromConfig(t *testing.T) {
	const limit = 1 << 20
	s := newBoundedStore(t, limit)

	used, max := s.Usage()
	assert.Equal(t, int64(limit), max, "the configured MaxSize becomes the ceiling")
	assert.Zero(t, used, "a fresh store uses nothing")
}

// TestUnboundedWhenAnyDirIsUnbounded documents the deliberate choice: summing
// the bounded directories would invent a ceiling the operator never set.
func TestUnboundedWhenAnyDirIsUnbounded(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	bounded, unbounded := t.TempDir(), t.TempDir()
	s, err := Open(ctx, egrp, Config{
		BaseDir: t.TempDir(),
		StorageDirs: []local_cache.StorageDirConfig{
			{Path: bounded, MaxSize: 1 << 20},
			{Path: unbounded},
		},
	})
	require.NoError(t, err)
	defer s.Close()

	_, max := s.Usage()
	assert.Zero(t, max, "one unbounded directory makes the store unbounded")
}

// TestWriteBeyondCapacityFailsWithENOSPC is the core enforcement test.  The
// error must be ENOSPC specifically, because that is what the origin maps to
// 507.
func TestWriteBeyondCapacityFailsWithENOSPC(t *testing.T) {
	const limit = 512 << 10
	s := newBoundedStore(t, limit)

	w, err := s.Create("/toobig")
	require.NoError(t, err)

	// Write past the ceiling in increments; the reservation should refuse
	// before the bytes land.
	var writeErr error
	payload := randomBytes(64<<10, 3)
	for range 20 {
		if _, writeErr = w.Write(payload); writeErr != nil {
			break
		}
	}
	require.Error(t, writeErr, "a write past the ceiling must fail")
	assert.ErrorIs(t, writeErr, ErrNoSpace)
	assert.ErrorIs(t, writeErr, syscall.ENOSPC, "callers match on ENOSPC to produce a 507")

	require.NoError(t, w.Abort())

	_, err = s.Stat("/toobig")
	assert.ErrorIs(t, err, ErrNotExist, "the refused object never appears")
}

// TestCapacityReleasedOnDelete confirms space comes back, so a full store
// recovers once an operator deletes something -- the only way it can, since
// there is no eviction.
func TestCapacityReleasedOnDelete(t *testing.T) {
	const limit = 1 << 20
	s := newBoundedStore(t, limit)

	content := randomBytes(256<<10, 4)
	writeObject(t, s, "/first", content)

	usedAfterWrite, _ := s.Usage()
	assert.Greater(t, usedAfterWrite, int64(0), "a stored object consumes capacity")

	require.NoError(t, s.Remove("/first"))
	_, err := s.RunGC(t.Context())
	require.NoError(t, err)

	usedAfterDelete, _ := s.Usage()
	assert.Less(t, usedAfterDelete, usedAfterWrite, "reclaiming the object frees capacity")
}

func TestHasCapacityFor(t *testing.T) {
	const limit = 256 << 10
	s := newBoundedStore(t, limit)

	assert.NoError(t, s.HasCapacityFor(1024), "a small write fits")
	assert.NoError(t, s.HasCapacityFor(0), "an empty write always fits")

	err := s.HasCapacityFor(limit * 2)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoSpace)

	// Accounts for the per-block overhead, so a write of exactly the ceiling
	// does not fit.
	assert.Error(t, s.HasCapacityFor(limit), "the on-disk footprint exceeds the content length")
}

func TestHasCapacityForUnboundedStore(t *testing.T) {
	s := newTestStore(t)
	assert.NoError(t, s.HasCapacityFor(1<<40), "an unbounded store accepts anything")
}

// TestCapacitySurvivesReopen checks the counters are rebuilt from the catalog
// rather than starting at zero, which would let a restart overfill the store.
func TestCapacitySurvivesReopen(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	dir := t.TempDir()
	cfg := Config{
		BaseDir:     dir,
		StorageDirs: []local_cache.StorageDirConfig{{Path: dir, MaxSize: 1 << 20}},
	}

	s, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	writeObject(t, s, "/persisted", randomBytes(128<<10, 8))
	usedBefore, _ := s.Usage()
	require.NoError(t, s.Close())
	require.Greater(t, usedBefore, int64(0))

	s2, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	defer s2.Close()

	usedAfter, max := s2.Usage()
	assert.Equal(t, int64(1<<20), max)
	assert.Equal(t, usedBefore, usedAfter, "usage is recovered from the catalog on reopen")
}

// TestInlineObjectsCountTowardCapacity guards a gap that would let a store be
// filled without limit: objects at or below the inline threshold live in the
// catalog rather than a storage directory, and if that pseudo-directory is not
// tracked, millions of small objects never trigger ENOSPC.
func TestInlineObjectsCountTowardCapacity(t *testing.T) {
	s := newBoundedStore(t, 1<<20)

	before, _ := s.Usage()
	require.Zero(t, before)

	// Comfortably below InlineThreshold, so this never touches a block file.
	writeObject(t, s, "/tiny", []byte("small enough to live in the catalog"))

	after, _ := s.Usage()
	assert.Greater(t, after, before, "an inline object consumes tracked capacity")
}

// TestInlineUsageSurvivesReopen confirms the inline figure is seeded from the
// catalog too, not just accumulated in memory.
func TestInlineUsageSurvivesReopen(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	dir := t.TempDir()
	cfg := Config{
		BaseDir:     dir,
		StorageDirs: []local_cache.StorageDirConfig{{Path: dir, MaxSize: 1 << 20}},
	}

	s, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	writeObject(t, s, "/tiny", []byte("inline payload"))
	usedBefore, _ := s.Usage()
	require.NoError(t, s.Close())
	require.Greater(t, usedBefore, int64(0))

	s2, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	defer s2.Close()

	usedAfter, _ := s2.Usage()
	assert.Equal(t, usedBefore, usedAfter, "inline usage is recovered on reopen")
}

// newMultiDirStore opens a store spanning two directories with independent
// ceilings.
func newMultiDirStore(t *testing.T, sizes ...uint64) *Store {
	t.Helper()
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, _ := errgroup.WithContext(ctx)

	dirs := make([]local_cache.StorageDirConfig, len(sizes))
	for i, sz := range sizes {
		dirs[i] = local_cache.StorageDirConfig{Path: t.TempDir(), MaxSize: sz}
	}
	s, err := Open(ctx, egrp, Config{BaseDir: t.TempDir(), StorageDirs: dirs})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })
	return s
}

// blockDirIDs returns the real storage directories, dropping the inline
// pseudo-directory, which holds no block files and is never a placement
// target.
func blockDirIDs(s *Store) []local_cache.StorageID {
	var ids []local_cache.StorageID
	for _, id := range s.capacity.storageIDs() {
		if id != local_cache.StorageIDInline {
			ids = append(ids, id)
		}
	}
	return ids
}

// TestChooseDirPrefersTheDirectoryWithRoom is the placement half of the
// multi-directory problem.  The block store's default chooser is round-robin,
// which ignores how full each directory is; with a small directory and a large
// one it alternates until the small one overflows.
func TestChooseDirPrefersTheDirectoryWithRoom(t *testing.T) {
	s := newMultiDirStore(t, 1<<20, 64<<20)

	dirIDs := blockDirIDs(s)
	require.Len(t, dirIDs, 2)

	// Name the directories by the ceiling they were configured with rather
	// than by assuming an ID ordering, so the assertions below are about
	// headroom and nothing else.
	var small, large local_cache.StorageID
	for _, id := range dirIDs {
		if _, max := s.capacity.usageOf(id); max == 1<<20 {
			small = id
		} else {
			large = id
		}
	}
	require.NotZero(t, small)
	require.NotZero(t, large)

	assert.Equal(t, large, s.capacity.chooseDir(),
		"the directory with more headroom is chosen")

	// Charge the large directory until the small one has more headroom; the
	// preference must follow, which is exactly what round-robin does not do.
	s.capacity.settle(0, map[local_cache.StorageID]int64{large: (64 << 20) - (512 << 10)})
	assert.Equal(t, small, s.capacity.chooseDir(),
		"a directory that is now the fuller one stops being preferred")

	// And once the small one is fuller still, preference goes back.
	s.capacity.settle(0, map[local_cache.StorageID]int64{small: (1 << 20) - (128 << 10)})
	assert.Equal(t, large, s.capacity.chooseDir(),
		"selection tracks headroom in both directions")
}

// BenchmarkChooseDir measures the per-call cost of the placement chooser,
// which the block store consults once per chunk allocation.
//
// It exists to answer whether the linear scan should be replaced by a
// probabilistic selection over periodically refreshed weights.  The tracker is
// built directly rather than through Open: chooseDir touches nothing but its
// own map -- no syscall, no statfs, no catalog read -- so a real store would
// add setup cost without changing what is being measured.
//
// The realistic sizes are the first two.  A storage directory is a disk an
// operator mounted and listed in the configuration; 2 to 8 is the shape of
// every deployment.  The 64- and 256-directory cases are there to show the
// slope, not because anyone runs them.
func BenchmarkChooseDir(b *testing.B) {
	for _, n := range []int{2, 8, 64, 256} {
		b.Run(strconv.Itoa(n)+"dirs", func(b *testing.B) {
			ct := &capacityTracker{dirs: make(map[local_cache.StorageID]*dirCapacity, n+1)}
			ct.dirs[local_cache.StorageIDInline] = &dirCapacity{}
			for i := range n {
				id := local_cache.StorageIDFirstDisk + local_cache.StorageID(i)
				// Staggered fill levels, so the winner is not the first
				// candidate examined and the comparison actually runs.
				ct.dirs[id] = &dirCapacity{
					maxBytes: 1 << 40,
					used:     int64(i) * (1 << 30),
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sinkStorageID = ct.chooseDir()
			}
		})
	}
}

// sinkStorageID keeps the benchmark's result live so the call is not elided.
var sinkStorageID local_cache.StorageID

// TestWritesRespectPerDirectoryCeilings is the same property observed through
// the public API rather than by poking the chooser.  Every write tier has to
// route through the capacity tracker: the streaming tier goes through the
// block store's chooseDir hook, but the middle (buffered, exact-length) tier
// allocates its file itself, so a hardcoded first directory there would fill
// past its MaxSize while the other sat empty.
func TestWritesRespectPerDirectoryCeilings(t *testing.T) {
	const perDir = 8 << 20
	s := newMultiDirStore(t, perDir, perDir)

	// Inline: charged to the catalog's pseudo-directory.
	for i := range 10 {
		writeObject(t, s, "/inline"+strconv.Itoa(i), randomBytes(1<<10, int64(i)))
	}
	// Buffered exact-length: 24 x 400 KiB is 9.6 MiB, more than either
	// directory can hold on its own.
	for i := range 24 {
		writeObject(t, s, "/mid"+strconv.Itoa(i), randomBytes(400<<10, int64(100+i)))
	}
	// Streamed: past the spill threshold, so the chunk allocator places it.
	w, err := s.CreateSized("/streamed", 1536<<10)
	require.NoError(t, err)
	_, err = w.Write(randomBytes(1536<<10, 7))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	for _, id := range blockDirIDs(s) {
		used, err := usageForDir(s.db, id)
		require.NoError(t, err)
		_, max := s.capacity.usageOf(id)
		require.Equal(t, int64(perDir), max)
		assert.LessOrEqual(t, used, max,
			"storage directory %d exceeded its configured MaxSize", id)
	}

	// The data still reads back, so the spreading did not lose anything.
	got, err := s.ReadAll("/mid0")
	require.NoError(t, err)
	assert.Equal(t, randomBytes(400<<10, 100), got)
}

// TestReserveRequiresADirectoryWithRoom covers the accounting half.  A write
// can pass an aggregate check while no single directory can actually hold the
// chunk it is about to place, which is how a store with total headroom still
// fails a write.
func TestReserveRequiresADirectoryWithRoom(t *testing.T) {
	s := newMultiDirStore(t, 4<<20, 4<<20)

	used, max := s.Usage()
	require.Equal(t, int64(8<<20), max, "the aggregate is the sum of both")
	require.Zero(t, used)

	// Fill both directories to just under their individual ceilings, leaving
	// the aggregate with room but neither directory able to take a big chunk.
	for _, id := range s.capacity.storageIDs() {
		if id == local_cache.StorageIDInline {
			continue
		}
		_, dirMax := s.capacity.usageOf(id)
		s.capacity.settle(0, map[local_cache.StorageID]int64{id: dirMax - (256 << 10)})
	}

	usedNow, maxNow := s.Usage()
	require.Less(t, usedNow, maxNow, "the store still has aggregate headroom")

	// A unit larger than any single directory's remaining room must be
	// refused even though the aggregate would accept it.
	err := s.capacity.reserve(512<<10, 512<<10, 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoSpace)

	// A unit that fits in a directory is still accepted.
	assert.NoError(t, s.capacity.reserve(64<<10, 64<<10, 0))
}

// TestReserveIgnoresPerDirLimitsWhenUnbounded confirms an unbounded directory
// keeps the store usable regardless of the others.
func TestReserveIgnoresPerDirLimitsWhenUnbounded(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	s, err := Open(ctx, egrp, Config{
		BaseDir: t.TempDir(),
		StorageDirs: []local_cache.StorageDirConfig{
			{Path: t.TempDir(), MaxSize: 1 << 10},
			{Path: t.TempDir()},
		},
	})
	require.NoError(t, err)
	defer s.Close()

	assert.NoError(t, s.capacity.reserve(1<<30, 1<<30, 0),
		"an unbounded directory can absorb any single unit")
}

// TestParentDirUsesFilesystemSemantics guards a bug that is invisible on Linux
// and breaks the store on Windows.
//
// parentDir maps a storage manager's "objects" subdirectory back to the
// configured directory so its size limit can be found. That is a filesystem
// path, not a namespace path: using the slash-only path package would find no
// separator in "C:\store\objects", return ".", match no configured limit, and
// leave every directory silently unbounded.
func TestParentDirUsesFilesystemSemantics(t *testing.T) {
	// The separator this platform actually uses must round-trip.
	joined := filepath.Join("store", "objects")
	assert.Equal(t, "store", parentDir(joined))

	// And an absolute path keeps its root.
	abs := filepath.Join(string(filepath.Separator)+"srv", "pstore", "objects")
	assert.Equal(t, filepath.Join(string(filepath.Separator)+"srv", "pstore"), parentDir(abs))
}

// assertWithinCeilings checks the catalog's own usage counters -- not the
// in-memory estimate -- against every configured ceiling.  The counters are
// what the block store charges as it pre-allocates, so they are the figure a
// full disk would actually correspond to.
func assertWithinCeilings(t *testing.T, s *Store) {
	t.Helper()

	total, err := usageForDir(s.db, local_cache.StorageIDInline)
	require.NoError(t, err)
	for _, id := range blockDirIDs(s) {
		used, uErr := usageForDir(s.db, id)
		require.NoError(t, uErr)
		total += used

		if _, max := s.capacity.usageOf(id); max > 0 {
			assert.LessOrEqual(t, used, max,
				"storage directory %d holds %d bytes, past its %d-byte ceiling", id, used, max)
		}
	}
	if _, max := s.Usage(); max > 0 {
		assert.LessOrEqual(t, total, max,
			"the store holds %d bytes, past its %d-byte ceiling", total, max)
	}
}

// TestConcurrentWritesStayWithinTheCeiling is the case a single-writer test
// cannot see.
//
// A streamed write pre-allocates and is charged a whole chunk the moment it
// touches one, so the reservation has to be the chunk-rounded footprint rather
// than the content length -- and the per-directory room test has to count the
// reservations other writers already hold.  With neither in place every
// concurrent writer passed the same check against the same apparently-free
// space, and N writers charged N times what the ceiling allowed.  That is a
// real out-of-space condition, not an accounting slip.
func TestConcurrentWritesStayWithinTheCeiling(t *testing.T) {
	const (
		writers   = 16
		objectLen = 2 << 20
		limit     = 256 << 20
	)
	s := newBoundedStore(t, limit)

	payload := randomBytes(objectLen, 77)

	var (
		ready    sync.WaitGroup
		mu       sync.Mutex
		refusals []error
		grp      errgroup.Group
	)
	release := make(chan struct{})
	ready.Add(writers)

	for i := range writers {
		grp.Go(func() error {
			w, err := s.Create("/concurrent" + strconv.Itoa(i))
			if err != nil {
				ready.Done()
				return err
			}
			_, wErr := w.Write(payload)
			// Every writer reports in whether or not its bytes went down, so
			// the sampling below happens with all of them genuinely in flight
			// and none of them committed.  No timing involved.
			ready.Done()
			<-release

			if wErr != nil {
				mu.Lock()
				refusals = append(refusals, wErr)
				mu.Unlock()
				return w.Abort()
			}
			return w.Close()
		})
	}

	ready.Wait()
	assertWithinCeilings(t, s)

	close(release)
	require.NoError(t, grp.Wait())
	assertWithinCeilings(t, s)

	for _, err := range refusals {
		assert.ErrorIs(t, err, ErrNoSpace,
			"the only failure a writer may see is an explicit refusal")
	}
	assert.Empty(t, refusals, "this store is comfortably large enough for every writer")

	// And the objects are all really there.
	for i := range writers {
		d, err := s.Stat("/concurrent" + strconv.Itoa(i))
		require.NoError(t, err)
		assert.Equal(t, int64(objectLen), d.Size)
	}
}

// TestSpilledObjectFitsInASmallBoundedStore guards the interaction between the
// two write-path constants.  A streaming chunk fixed at 64 MiB while buffering
// stopped at 1 MiB would make every object over a megabyte demand 64 MiB of
// free space in a single directory: a bounded store smaller than that could
// never accept one, and any store whose directories dropped below 64 MiB free
// would refuse writes with tens of megabytes still available.
func TestSpilledObjectFitsInASmallBoundedStore(t *testing.T) {
	const limit = 16 << 20
	s := newBoundedStore(t, limit)

	content := randomBytes(2<<20, 21)
	require.Greater(t, len(content), spillThreshold, "this object must reach the streaming tier")

	// With a declared length the pre-flight check and the write have to agree;
	// the origin turns a disagreement into either a spurious 507 or a PUT that
	// fails halfway through the body.
	require.NoError(t, s.HasCapacityFor(int64(len(content))))

	w, err := s.CreateSized("/sized", int64(len(content)))
	require.NoError(t, err)
	_, err = w.Write(content)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	got, err := s.ReadAll("/sized")
	require.NoError(t, err)
	assert.Equal(t, content, got)

	// And without a declared length, which is what a chunked-encoding PUT
	// looks like.
	writeObject(t, s, "/unsized", content)
	got, err = s.ReadAll("/unsized")
	require.NoError(t, err)
	assert.Equal(t, content, got)

	assertWithinCeilings(t, s)
}

// TestTrailingSeparatorStillBoundsTheStore covers a configuration typo that
// silently disabled every capacity limit.
//
// Per-directory ceilings are matched back to the block store's directories by
// path.  The configured value was used raw while the block store reports the
// cleaned form, so "Path: /srv/pstore/" matched nothing, the directory came up
// unbounded, and one unbounded directory makes the whole store unbounded --
// disabling ENOSPC, the 507 mapping, and everything downstream of them.
func TestTrailingSeparatorStillBoundsTheStore(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	dir := t.TempDir()
	s, err := Open(ctx, egrp, Config{
		BaseDir: dir,
		StorageDirs: []local_cache.StorageDirConfig{
			{Path: dir + string(filepath.Separator), MaxSize: 1 << 20},
		},
	})
	require.NoError(t, err)
	defer s.Close()

	_, max := s.Usage()
	require.Equal(t, int64(1<<20), max,
		"a trailing separator must not turn a bounded store into an unbounded one")

	// The ceiling is not just reported, it is enforced.
	w, err := s.Create("/toobig")
	require.NoError(t, err)
	var writeErr error
	payload := randomBytes(64<<10, 3)
	for range 40 {
		if _, writeErr = w.Write(payload); writeErr != nil {
			break
		}
	}
	require.Error(t, writeErr, "the configured ceiling must actually refuse a write")
	assert.ErrorIs(t, writeErr, ErrNoSpace)
	require.NoError(t, w.Abort())
}
