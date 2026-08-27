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
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
)

// TestIngestChecksums verifies the digests recorded while writing match the
// content, across all three write tiers.
func TestIngestChecksums(t *testing.T) {
	s := newTestStore(t)

	cases := map[string]int{
		"inline":   100,
		"buffered": 1 << 20,
		"streamed": spillThreshold + (1 << 20),
	}
	for name, size := range cases {
		t.Run(name, func(t *testing.T) {
			content := randomBytes(size, int64(size))
			path := "/sum-" + name
			writeObject(t, s, path, content)

			got, err := s.Digests(path)
			require.NoError(t, err)
			byType := digestsByType(got)

			wantMD5 := md5.Sum(content)
			wantSHA1 := sha1.Sum(content)
			wantCRC := crc32.Checksum(content, crc32.MakeTable(crc32.Castagnoli))

			assert.Equal(t, wantMD5[:], byType[local_cache.ChecksumMD5].Value)
			assert.Equal(t, wantSHA1[:], byType[local_cache.ChecksumSHA1].Value)
			assert.Equal(t, wantCRC, binary.BigEndian.Uint32(byType[local_cache.ChecksumCRC32C].Value))
		})
	}
}

// TestChecksumsAreVersionScoped is the advantage over an mtime-validated xattr
// cache: digests belong to the version, so an overwrite cannot leave a stale
// value behind even within the same clock tick.
func TestChecksumsAreVersionScoped(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", []byte("first"))
	first, err := s.Digests("/obj")
	require.NoError(t, err)

	writeObject(t, s, "/obj", []byte("second"))
	second, err := s.Digests("/obj")
	require.NoError(t, err)

	firstMD5 := digestsByType(first)[local_cache.ChecksumMD5].Value
	secondMD5 := digestsByType(second)[local_cache.ChecksumMD5].Value
	assert.NotEqual(t, firstMD5, secondMD5)

	wantMD5 := md5.Sum([]byte("second"))
	assert.Equal(t, wantMD5[:], secondMD5)
}

func TestDigestsErrors(t *testing.T) {
	s := newTestStore(t)

	_, err := s.Digests("/missing")
	assert.ErrorIs(t, err, ErrNotExist)

	require.NoError(t, s.Mkdir("/d"))
	_, err = s.Digests("/d")
	assert.ErrorIs(t, err, ErrIsDir)
}

func TestParseChecksumAlgorithm(t *testing.T) {
	for in, want := range map[string]local_cache.ChecksumType{
		"md5": local_cache.ChecksumMD5, "MD5": local_cache.ChecksumMD5,
		"sha": local_cache.ChecksumSHA1, "sha-1": local_cache.ChecksumSHA1,
		"SHA1":   local_cache.ChecksumSHA1,
		"crc32c": local_cache.ChecksumCRC32C, " crc32c ": local_cache.ChecksumCRC32C,
		"sha-256": local_cache.ChecksumSHA256,
	} {
		got, ok := local_cache.ParseChecksumAlgorithm(in)
		assert.True(t, ok, "parsing %q", in)
		assert.Equal(t, want, got, "parsing %q", in)
	}
	_, ok := local_cache.ParseChecksumAlgorithm("nonsense")
	assert.False(t, ok)
}

// digestsByType indexes a checksum slice for assertions.
func digestsByType(cs []local_cache.Checksum) map[local_cache.ChecksumType]local_cache.Checksum {
	out := make(map[local_cache.ChecksumType]local_cache.Checksum, len(cs))
	for _, c := range cs {
		out[c.Type] = c
	}
	return out
}

// ---------------------------------------------------------------------------
// fsck
// ---------------------------------------------------------------------------

func TestFsckHealthyStore(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.MkdirAll("/a/b"))
	writeObject(t, s, "/a/f1", []byte("one"))
	writeObject(t, s, "/a/b/f2", randomBytes(64<<10, 2))

	report, err := s.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.True(t, report.Healthy(), "a store built through the normal path is clean: %+v", report)
	assert.Equal(t, 4, report.EntriesScanned, "two directories and two files")
	assert.Equal(t, 2, report.DirectoriesScanned)
}

// TestFsckDetectsDanglingEntry simulates metadata lost underneath a live
// entry, which would otherwise surface as an error mid-read.
func TestFsckDetectsDanglingEntry(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/orphan-entry", []byte("data"))
	d, err := s.Stat("/orphan-entry")
	require.NoError(t, err)

	// Delete the metadata behind the entry's back.
	require.NoError(t, s.db.DeleteMetadata(instanceHashFor(s.db, d.Generation)))

	report, err := s.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.False(t, report.Healthy())
	assert.Equal(t, []string{"/orphan-entry"}, report.DanglingEntries)

	// A dry run changes nothing.
	_, err = s.Stat("/orphan-entry")
	assert.NoError(t, err, "the entry survives a read-only pass")

	report, err = s.Fsck(t.Context(), true)
	require.NoError(t, err)
	// `Repaired` is set from the flag that was passed in, so asserting it is
	// asserting that true is true.  What matters is what repair claims to
	// have acted on, and whether it actually did.
	assert.Contains(t, report.Resolved(), "Entries whose object data is missing (removed)")
	assert.Empty(t, report.Unresolved(), "nothing was left for an operator to decide")

	_, err = s.Stat("/orphan-entry")
	assert.ErrorIs(t, err, ErrNotExist, "repair removes the unservable entry")

	// And a second pass finds the store clean, which a repair that only
	// reported would not achieve.
	report, err = s.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.True(t, report.Healthy(), "%+v", report)
}

// TestFsckDetectsOrphanedInstance covers the opposite direction: a version
// no entry refers to, which would hold space indefinitely.
func TestFsckDetectsOrphanedInstance(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", randomBytes(32<<10, 3))
	d, err := s.Stat("/obj")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d.Generation)

	// Drop the entry without queueing the version, as a partial failure
	// outside the normal transaction would.
	require.NoError(t, s.bdb.Update(func(txn *badger.Txn) error {
		return deleteDirent(txn, "/obj")
	}))

	// The version was written moments ago, so the grace period that protects
	// writes in flight covers it; a pass that respects the default reports it
	// as pending rather than as garbage.  Nothing is writing here, so the
	// test waives it explicitly.
	graced, err := s.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.NotContains(t, graced.OrphanedInstances, string(hash),
		"a version this young could still be a write in flight")
	assert.Contains(t, graced.PendingInstances, string(hash))

	report, err := s.FsckWith(t.Context(), FsckOptions{MinAge: FsckNoGracePeriod})
	require.NoError(t, err)
	assert.Contains(t, report.OrphanedInstances, string(hash))

	report, err = s.FsckWith(t.Context(), FsckOptions{Repair: true, MinAge: FsckNoGracePeriod})
	require.NoError(t, err)
	require.Contains(t, report.OrphanedInstances, string(hash))

	// Repair queues it rather than deleting inline, so reclamation still
	// respects reader pins.
	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.InstancesFreed)

	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, meta)
}

// TestFsckIgnoresQueuedInstances checks that a version already awaiting the
// janitor is not double-reported as an orphan.
func TestFsckIgnoresQueuedInstances(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", []byte("v1"))
	writeObject(t, s, "/obj", []byte("v2")) // supersedes v1, queueing it

	report, err := s.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.Empty(t, report.OrphanedInstances,
		"a version already queued for reclamation is not an orphan")
}

// synthHash renders n as an instance hash: fixed-width lowercase hex, so
// ascending n gives ascending BadgerDB key order, which is what the queue
// cursor's merge depends on.
func synthHash(n int) local_cache.InstanceHash {
	return local_cache.InstanceHash(fmt.Sprintf("%064x", n))
}

// enqueueSynthetic puts hashes on the reclamation queue directly, without the
// metadata that would normally accompany them.
func enqueueSynthetic(t *testing.T, s *Store, hashes []local_cache.InstanceHash) {
	t.Helper()
	require.NoError(t, s.bdb.Update(func(txn *badger.Txn) error {
		for _, h := range hashes {
			if err := enqueueInstance(txn, h); err != nil {
				return err
			}
		}
		return nil
	}))
}

// TestQueuedCursorMergesAcrossBatches exercises the queue side of the orphan
// comparison, which is a merge of two hash-ordered scans rather than a set
// held in memory.
//
// The queue is seeded well past one batch so the cursor has to refill and
// resume, and the probes interleave present and absent hashes so both the
// "advance past" and the "stop short" branches run.  A cursor that lost its
// place across a refill would report a queued version as unqueued, and fsck
// --repair would then queue a version the janitor is already holding -- or,
// worse, one that a live write has tombstoned for itself.
func TestQueuedCursorMergesAcrossBatches(t *testing.T) {
	s := newTestStore(t)

	// Two and a half batches' worth, at every other hash.
	const span = fsckBatchSize*5 + 7
	var queued []local_cache.InstanceHash
	for i := 0; i < span; i += 2 {
		queued = append(queued, synthHash(i))
	}
	enqueueSynthetic(t, s, queued)

	c := s.newQueuedCursor(t.Context(), "")
	for i := range span {
		got, err := c.contains(synthHash(i))
		require.NoError(t, err, "probe %d", i)
		require.Equal(t, i%2 == 0, got, "probe %d", i)
	}

	// Past the end of the queue the cursor keeps answering, rather than
	// running off the end of its buffer.
	got, err := c.contains(synthHash(span + 1000))
	require.NoError(t, err)
	assert.False(t, got)
}

// TestQueuedCursorHonorsShard checks the cursor stays inside the slice of the
// instance-hash space it was opened over, since a sharded pass compares only
// that slice's metadata.
func TestQueuedCursorHonorsShard(t *testing.T) {
	s := newTestStore(t)

	inShard := local_cache.InstanceHash("a" + fmt.Sprintf("%063x", 1))
	outOfShard := local_cache.InstanceHash("b" + fmt.Sprintf("%063x", 1))
	enqueueSynthetic(t, s, []local_cache.InstanceHash{inShard, outOfShard})

	c := s.newQueuedCursor(t.Context(), "a")
	got, err := c.contains(inShard)
	require.NoError(t, err)
	assert.True(t, got, "a queued version inside the slice is found")

	c = s.newQueuedCursor(t.Context(), "a")
	got, err = c.contains(outOfShard)
	require.NoError(t, err)
	assert.False(t, got, "a queued version outside the slice is not this pass's business")
}

// TestFsckIgnoresQueuedInstancesWithALargeQueue is the property of
// TestFsckIgnoresQueuedInstances again, with a queue several batches deep.
//
// A backlog is exactly when fsck matters: draining a detached subtree enqueues
// one key per version it unlinks, so a recursive delete leaves the queue far
// larger than the number of objects left in the store.  The real superseded
// entries are spread across the hash space so the real one is reached
// mid-stream rather than in the first batch.
func TestFsckIgnoresQueuedInstancesWithALargeQueue(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj", []byte("v1"))
	writeObject(t, s, "/obj", []byte("v2")) // supersedes v1, queueing it

	// Synthetic entries have no metadata, so they also cover the case of a
	// queued version the janitor has already reclaimed.  They are placed at
	// both ends of the hash space so the cursor has to skip forward over
	// several batches before and after the real one.
	var filler []local_cache.InstanceHash
	for i := range fsckBatchSize * 3 {
		filler = append(filler, synthHash(i))
		filler = append(filler,
			local_cache.InstanceHash("f"+fmt.Sprintf("%063x", i)))
	}
	enqueueSynthetic(t, s, filler)

	report, err := s.FsckWith(t.Context(), FsckOptions{MinAge: FsckNoGracePeriod})
	require.NoError(t, err)
	assert.Empty(t, report.OrphanedInstances,
		"a version already queued for reclamation is not an orphan, however deep the queue")
	assert.Empty(t, report.DanglingEntries)
}

// TestFsckDetectsIncompleteWrite covers a version whose metadata exists but
// whose write never finished.
func TestFsckDetectsIncompleteWrite(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/partial", []byte("data"))
	d, err := s.Stat("/partial")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d.Generation)

	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	meta.Completed = time.Time{}
	require.NoError(t, s.db.SetMetadata(hash, meta))

	report, err := s.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.Equal(t, []string{"/partial"}, report.MissingData)
}

// TestDeepFsckVerifiesData covers the only check that can see at-rest
// corruption.  Everything else in fsck reads the catalog; a flipped bit in a
// block file is invisible until the data is read back and compared against the
// checksums recorded at ingest.
func TestDeepFsckVerifiesData(t *testing.T) {
	s := newTestStore(t)

	// Large enough to land in a block file rather than inline, so there is
	// something on disk to corrupt.
	content := randomBytes(64<<10, 77)
	writeObject(t, s, "/obj.bin", content)

	report, err := s.FsckWith(t.Context(), FsckOptions{Deep: true})
	require.NoError(t, err)
	assert.True(t, report.Healthy(), "an untouched object verifies: %+v", report)
	assert.Equal(t, 1, report.ObjectsVerified)

	ok, err := s.VerifyObject("/obj.bin")
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestDeepFsckDetectsCorruptedData flips bytes underneath the store and
// confirms the deep pass notices, where a shallow pass cannot.
func TestDeepFsckDetectsCorruptedData(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/obj.bin", randomBytes(64<<10, 78))
	d, err := s.Stat("/obj.bin")
	require.NoError(t, err)

	// Corrupt the block file directly, behind the store's back.
	hash := instanceHashFor(s.db, d.Generation)
	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	require.False(t, meta.IsInline(), "the fixture must be on disk to be corruptible")

	dirs := s.storage.GetDirs()
	objPath := filepath.Join(dirs[meta.StorageID], local_cache.GetInstanceStoragePath(hash))
	f, err := os.OpenFile(objPath, os.O_WRONLY, 0)
	require.NoError(t, err, "the block file should exist at %s", objPath)
	_, err = f.WriteAt([]byte{0xde, 0xad, 0xbe, 0xef}, 1024)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// A shallow pass reads only the catalog and sees nothing wrong.
	shallow, err := s.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.True(t, shallow.Healthy(), "the catalog is still consistent: %+v", shallow)

	// The deep pass reads the data and catches it.
	deep, err := s.FsckWith(t.Context(), FsckOptions{Deep: true})
	require.NoError(t, err)
	assert.False(t, deep.Healthy())
	assert.Equal(t, []string{"/obj.bin"}, deep.CorruptObjects)

	ok, _ := s.VerifyObject("/obj.bin")
	assert.False(t, ok, "the object no longer matches its recorded checksums")
}

// ---------------------------------------------------------------------------
// The scheduled scans
// ---------------------------------------------------------------------------

// TestScheduledDataScanPreservesCorruptObjects is the difference between a
// cache and a primary store, and it is a data-loss bug when it is missing.
//
// The data scan is the cache's, and the cache deletes an object whose data no
// longer matches its checksums -- correctly, because the next request refetches
// it from the origin. An origin has no upstream. Running the cache's policy
// against a pstore destroys the only copy, and with it the only record of the
// object's path, size and checksums, after which `fsck --repair` classifies
// the surviving entry as dangling and removes that too.
func TestScheduledDataScanPreservesCorruptObjects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{"inline", []byte("small enough to live in the catalog")},
		{"on disk", randomBytes(64<<10, 101)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			writeObject(t, s, "/obj", tc.content)

			d, err := s.Stat("/obj")
			require.NoError(t, err)
			hash := instanceHashFor(s.db, d.Generation)

			// Corrupt the *recorded* checksum rather than the data, so the
			// mismatch is real and the bytes are still the ones we can assert
			// on afterwards.
			meta, err := s.db.GetMetadata(hash)
			require.NoError(t, err)
			require.NotEmpty(t, meta.Checksums)
			for i := range meta.Checksums {
				meta.Checksums[i].Value = append([]byte(nil), meta.Checksums[i].Value...)
				meta.Checksums[i].Value[0] ^= 0xff
			}
			require.NoError(t, s.db.SetMetadata(hash, meta))

			// Exactly what the scheduled scan runs.
			checker := local_cache.NewConsistencyChecker(s.db, s.storage, newPStoreScanConfig(0))
			require.NoError(t, checker.RunDataScan(t.Context(), nil))
			require.Equal(t, int64(1), checker.GetStats().ChecksumMismatches,
				"the scan must still detect the corruption")

			// The object survives, in full.
			survived, err := s.db.GetMetadata(hash)
			require.NoError(t, err)
			require.NotNil(t, survived, "the only copy's metadata must not be deleted")
			assert.Equal(t, int64(len(tc.content)), survived.ContentLength)

			got, err := s.ReadAll("/obj")
			require.NoError(t, err, "an origin cannot re-fetch what it has lost")
			assert.Equal(t, tc.content, got)

			// And fsck does not then mistake the entry for a dangling one and
			// finish the job.
			report, err := s.FsckWith(t.Context(), FsckOptions{Repair: true, MinAge: FsckNoGracePeriod})
			require.NoError(t, err)
			assert.Empty(t, report.DanglingEntries)
			_, err = s.Stat("/obj")
			assert.NoError(t, err, "the entry, and with it the object's path and size, survives")
		})
	}
}

// TestCacheDataScanStillDeletesCorruptObjects is the other half: the fix above
// must not change what a cache does. A cache SHOULD delete and re-fetch, and
// suppressing that would turn every corrupt cache object into a permanent
// error instead of a self-healing miss.
func TestCacheDataScanStillDeletesCorruptObjects(t *testing.T) {
	s := newTestStore(t)
	writeObject(t, s, "/obj.bin", randomBytes(64<<10, 102))

	d, err := s.Stat("/obj.bin")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d.Generation)

	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	require.False(t, meta.IsInline())
	for i := range meta.Checksums {
		meta.Checksums[i].Value = append([]byte(nil), meta.Checksums[i].Value...)
		meta.Checksums[i].Value[0] ^= 0xff
	}
	require.NoError(t, s.db.SetMetadata(hash, meta))

	// A cache's configuration: no PreserveCorruptObjects.
	checker := local_cache.NewConsistencyChecker(s.db, s.storage, local_cache.ConsistencyConfig{
		ChecksumTypes: ingestAlgorithms,
	})
	require.NoError(t, checker.RunDataScan(t.Context(), nil))
	require.Equal(t, int64(1), checker.GetStats().ChecksumMismatches)

	gone, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, gone, "a cache still discards a corrupt object so the next request refetches it")
}

// TestScheduledDataScanDoesNotBackfillChecksums covers the second way the
// scan was not the read-only pass its callers believed. Backfilling checksums
// for an object that has none is a metadata write, and against a primary store
// it can bless data that is already corrupt.
func TestScheduledDataScanDoesNotBackfillChecksums(t *testing.T) {
	s := newTestStore(t)
	writeObject(t, s, "/obj.bin", randomBytes(64<<10, 103))

	d, err := s.Stat("/obj.bin")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d.Generation)

	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	meta.Checksums = nil
	require.NoError(t, s.db.SetMetadata(hash, meta))

	checker := local_cache.NewConsistencyChecker(s.db, s.storage, newPStoreScanConfig(0))
	require.NoError(t, checker.RunDataScan(t.Context(), nil))

	after, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	assert.Empty(t, after.Checksums, "the scheduled scan writes nothing")
}

// TestDataScanStatisticsAreReportedPerPass pins the accumulation bug: the
// checker totals its statistics across every scan it has ever run, so once a
// single mismatch has been seen the absolute count stays above zero and every
// later pass logs an error about a problem that is no longer there.
func TestDataScanStatisticsAreReportedPerPass(t *testing.T) {
	s := newTestStore(t)
	writeObject(t, s, "/bad.bin", randomBytes(64<<10, 104))

	d, err := s.Stat("/bad.bin")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d.Generation)
	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	for i := range meta.Checksums {
		meta.Checksums[i].Value = append([]byte(nil), meta.Checksums[i].Value...)
		meta.Checksums[i].Value[0] ^= 0xff
	}
	require.NoError(t, s.db.SetMetadata(hash, meta))

	checker := local_cache.NewConsistencyChecker(s.db, s.storage, newPStoreScanConfig(0))

	before := checker.GetStats().ChecksumMismatches
	require.NoError(t, checker.RunDataScan(t.Context(), nil))
	firstPass := checker.GetStats().ChecksumMismatches - before
	assert.Equal(t, int64(1), firstPass)

	// Put the object right again, exactly as an operator restoring from
	// backup would.
	restored, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	for i := range restored.Checksums {
		restored.Checksums[i].Value[0] ^= 0xff
	}
	require.NoError(t, s.db.SetMetadata(hash, restored))

	before = checker.GetStats().ChecksumMismatches
	require.NoError(t, checker.RunDataScan(t.Context(), nil))
	secondPass := checker.GetStats().ChecksumMismatches - before
	assert.Zero(t, secondPass, "the next pass reports what it found, not the running total")
	assert.Positive(t, checker.GetStats().ChecksumMismatches,
		"the running total is what made the absolute count useless")
}

// TestStartIntegrityChecksRunsAndPreservesData covers the scheduled loop
// itself rather than the pass it drives. An unattended job is exactly where a
// scan that deleted the only copy of an object would go unnoticed, so the loop
// has to be exercised end to end and not merely the function it calls.
func TestStartIntegrityChecksRunsAndPreservesData(t *testing.T) {
	s := newTestStore(t)

	content := randomBytes(64<<10, 105)
	writeObject(t, s, "/obj.bin", content)

	d, err := s.Stat("/obj.bin")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d.Generation)
	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	for i := range meta.Checksums {
		meta.Checksums[i].Value = append([]byte(nil), meta.Checksums[i].Value...)
		meta.Checksums[i].Value[0] ^= 0xff
	}
	require.NoError(t, s.db.SetMetadata(hash, meta))

	baseline := dataScanInconsistentTotal(t)

	// A group of its own, so the wait below covers exactly these two loops.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	// Intervals short enough that both loops tick many times over the
	// window below; nothing here sleeps to synchronize.
	s.StartIntegrityChecks(ctx, egrp, IntegrityConfig{
		IndexInterval: time.Millisecond,
		DataInterval:  time.Millisecond,
	})

	// Wait for the data scan to have actually run over the corrupt object, so
	// what follows is about a scan that happened rather than one that has not
	// started yet.  The metric the scan bumps on a mismatch is the signal;
	// nothing here sleeps for a fixed period and hopes.
	require.Eventually(t, func() bool {
		return dataScanInconsistentTotal(t) > baseline
	}, 20*time.Second, 5*time.Millisecond,
		"the scheduled data scan must run and report the mismatch")

	cancel()
	require.NoError(t, egrp.Wait())

	survived, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, survived, "the background scan must never delete the only copy")

	got, err := s.ReadAll("/obj.bin")
	require.NoError(t, err)
	assert.Equal(t, content, got)

	cancel()
	assert.NoError(t, egrp.Wait())
}

// ---------------------------------------------------------------------------
// Usage drift
// ---------------------------------------------------------------------------

// TestFsckRepairPersistsUsageResync is the difference between a repair and a
// no-op. The counters are seeded from the catalog at every open, so resyncing
// only the in-memory copy leaves the drift on disk to be read back on the next
// start -- and an over-counted directory makes the store answer 507 forever
// with no operator remedy.
func TestFsckRepairPersistsUsageResync(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)
	dir := t.TempDir()

	s, err := Open(ctx, egrp, Config{BaseDir: dir})
	require.NoError(t, err)
	writeObject(t, s, "/obj.bin", randomBytes(64<<10, 106))

	d, err := s.Stat("/obj.bin")
	require.NoError(t, err)
	meta, err := s.db.GetMetadata(instanceHashFor(s.db, d.Generation))
	require.NoError(t, err)
	require.False(t, meta.IsInline(), "the fixture must be charged to a storage directory")

	// Inject drift the way a partial failure would: the counter says more is
	// used than the objects actually occupy.
	const drift = 4096
	require.NoError(t, s.db.AddUsage(meta.StorageID, meta.NamespaceID, drift))
	require.NoError(t, s.Close())

	reopened, err := OpenMaintenance(ctx, dir, true)
	require.NoError(t, err)
	before, err := reopened.FsckWith(ctx, FsckOptions{MinAge: FsckNoGracePeriod})
	require.NoError(t, err)
	require.Equal(t, int64(-drift), before.UsageDrift[meta.StorageID],
		"the counter over-reports by exactly what was injected")

	repaired, err := reopened.FsckWith(ctx, FsckOptions{Repair: true, MinAge: FsckNoGracePeriod})
	require.NoError(t, err)
	assert.True(t, repaired.UsageResynced)
	assert.Contains(t, repaired.Resolved(), "Usage counter drift (rewritten from the catalog)")
	require.NoError(t, reopened.Close())

	// The fix has to survive a reopen, because that is where the counter is
	// read from.
	after, err := OpenMaintenance(ctx, dir, false)
	require.NoError(t, err)
	defer after.Close()

	report, err := after.FsckWith(ctx, FsckOptions{MinAge: FsckNoGracePeriod})
	require.NoError(t, err)
	assert.Empty(t, report.UsageDrift, "the drift is gone, not merely recomputed in memory")
	assert.True(t, report.Healthy(), "%+v", report)
}

// TestFsckRepairReportsWhatItCannotFix separates the two lists. Printing
// unrepairable findings under "Repaired the following:" and exiting zero is
// how a monitoring script reads success off a store full of corrupt objects.
func TestFsckRepairReportsWhatItCannotFix(t *testing.T) {
	s := newTestStore(t)

	// Something repair can fix...
	writeObject(t, s, "/dangling", []byte("data"))
	d, err := s.Stat("/dangling")
	require.NoError(t, err)
	require.NoError(t, s.db.DeleteMetadata(instanceHashFor(s.db, d.Generation)))

	// ...and something it cannot.
	writeObject(t, s, "/incomplete", []byte("data"))
	d2, err := s.Stat("/incomplete")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d2.Generation)
	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	meta.Completed = time.Time{}
	require.NoError(t, s.db.SetMetadata(hash, meta))

	report, err := s.FsckWith(t.Context(), FsckOptions{Repair: true, MinAge: FsckNoGracePeriod})
	require.NoError(t, err)

	assert.Contains(t, report.Resolved(), "Entries whose object data is missing (removed)")
	assert.Contains(t, report.Unresolved(), "Writes that never completed")
	assert.NotContains(t, report.Resolved(), "Writes that never completed",
		"repair must not claim a finding it did not act on")
	assert.NotEmpty(t, report.Unresolved(),
		"a caller must have something to exit non-zero on")
}

// TestFsckDeepRepairDoesNotClaimCorruptObjects is the same property under
// --repair --deep, where it is easiest to get wrong: a repair pass over
// checksum-mismatched objects must not report them as repaired and return
// success, because nothing in the store can reconstruct the lost bytes.
func TestFsckDeepRepairDoesNotClaimCorruptObjects(t *testing.T) {
	s := newTestStore(t)
	writeObject(t, s, "/obj.bin", randomBytes(64<<10, 107))

	d, err := s.Stat("/obj.bin")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d.Generation)
	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	dirs := s.storage.GetDirs()
	f, err := os.OpenFile(filepath.Join(dirs[meta.StorageID],
		local_cache.GetInstanceStoragePath(hash)), os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte{0xde, 0xad, 0xbe, 0xef}, 2048)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	report, err := s.FsckWith(t.Context(), FsckOptions{
		Repair: true, Deep: true, MinAge: FsckNoGracePeriod,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"/obj.bin"}, report.CorruptObjects)
	assert.Contains(t, report.Unresolved(),
		"Objects whose data no longer matches its checksums")
	assert.Empty(t, report.Resolved(), "repair acted on nothing here")
	assert.False(t, report.Healthy())

	// The corrupt object is still present: fsck reports, it does not decide.
	_, err = s.Stat("/obj.bin")
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// In-flight writes
// ---------------------------------------------------------------------------

// TestFsckDoesNotReclaimAnInFlightWrite is the hazard the grace period exists
// for. A streaming upload writes its metadata before any directory entry
// exists, so from the catalog it is byte-for-byte a crash-window orphan.
// Repairing one destroys a live upload.
func TestFsckDoesNotReclaimAnInFlightWrite(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Mkdir("/data"))

	// Open a write and stream enough through it to materialize storage,
	// without committing.  This is a real in-flight upload, not a simulation
	// of one.
	h, err := s.Create("/data/uploading.bin")
	require.NoError(t, err)
	payload := randomBytes(spillThreshold+(1<<20), 108)
	_, err = h.Write(payload)
	require.NoError(t, err)

	report, err := s.Fsck(t.Context(), true)
	require.NoError(t, err)
	assert.Empty(t, report.OrphanedInstances,
		"a write in flight must never be classified as garbage")

	// The upload completes and reads back whole.
	require.NoError(t, h.Close())
	got, err := s.ReadAll("/data/uploading.bin")
	require.NoError(t, err)
	assert.Equal(t, payload, got)

	// And once it is committed, the store is clean.
	after, err := s.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.True(t, after.Healthy(), "%+v", after)
}

// TestFsckRepairRefusesAReadOnlyStore checks the guard is fsck's own rather
// than a side effect of BadgerDB's directory lock. Relying on the lock means
// any future live-repair path silently becomes a data-loss path.
func TestFsckRepairRefusesAReadOnlyStore(t *testing.T) {
	ro := buildStoreThenReopenReadOnly(t)

	_, err := ro.Fsck(t.Context(), true)
	assert.ErrorIs(t, err, ErrNotSupported,
		"a repair pass must refuse a read-only store up front")

	// Reporting still works.
	report, err := ro.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.True(t, report.Healthy(), "%+v", report)
}

// TestFsckShardedOrphanScanCoversEverything checks the partitioning that keeps
// the hourly check's memory bounded: each pass examines one slice of the
// instance-hash space, and rotating through them finds every orphan exactly
// once.
func TestFsckShardedOrphanScanCoversEverything(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Mkdir("/data"))

	want := map[string]bool{}
	for i := range 40 {
		name := fmt.Sprintf("/data/obj-%02d", i)
		writeObject(t, s, name, randomBytes(64, int64(i)))
		d, err := s.Stat(name)
		require.NoError(t, err)
		want[string(instanceHashFor(s.db, d.Generation))] = true
		require.NoError(t, s.bdb.Update(func(txn *badger.Txn) error {
			return deleteDirent(txn, name)
		}))
	}

	full, err := s.FsckWith(t.Context(), FsckOptions{MinAge: FsckNoGracePeriod})
	require.NoError(t, err)
	require.Len(t, full.OrphanedInstances, len(want))
	assert.False(t, full.OrphanScanPartial)

	// The same set, gathered one slice at a time.
	const shards = 16
	got := map[string]int{}
	for shard := range shards {
		partial, pErr := s.FsckWith(t.Context(), FsckOptions{
			OrphanShardOf: shards, OrphanShard: shard, MinAge: FsckNoGracePeriod,
		})
		require.NoError(t, pErr)
		assert.True(t, partial.OrphanScanPartial)
		assert.Equal(t, full.EntriesScanned, partial.EntriesScanned,
			"the per-entry checks still cover the whole index")
		for _, h := range partial.OrphanedInstances {
			got[h]++
		}
	}

	assert.Len(t, got, len(want), "every orphan is found across a full rotation")
	for h, n := range got {
		assert.True(t, want[h], "%s is not one of the orphans", h)
		assert.Equal(t, 1, n, "%s was reported by more than one slice", h)
	}
}

// dataScanInconsistentTotal reads the counter of objects a pstore data scan
// found not to match their checksums.
//
// The scheduled loop exposes nothing else a test can wait on, and waiting on
// the clock instead would be a race dressed up as a delay.
//
// It reads the pstore-named counter rather than the block store's
// pelican_cache_data_scan_* one, which a pstore no longer touches: an origin
// reporting its integrity scan as cache activity was the thing that had to
// stop.  See newPStoreScanConfig.
func dataScanInconsistentTotal(t *testing.T) float64 {
	t.Helper()
	return labeledCounterValue(t, "pelican_pstore_data_scan_mismatches_total", nil)
}

// TestTruncateHashIsDeterministicAndDistinct covers the property the reachable
// set depends on: a live version can never be absent from it.
//
// Truncation is only safe because it is deterministic. The same hash always
// yields the same key, so every reachable version puts its own prefix in the
// set and is found again when the metadata scan asks. The reverse -- two
// distinct hashes sharing a key -- is possible in principle and merely means a
// missed orphan, never a reclaimed live object.
func TestTruncateHashIsDeterministicAndDistinct(t *testing.T) {
	t.Parallel()

	a := local_cache.InstanceHash(strings.Repeat("a1b2c3d4", 8))
	b := local_cache.InstanceHash(strings.Repeat("f9e8d7c6", 8))

	require.Equal(t, truncateHash(a), truncateHash(a),
		"the same hash must always produce the same key, or a live version could go missing")
	require.NotEqual(t, truncateHash(a), truncateHash(b))

	// Two hashes agreeing on the first 128 bits and differing afterwards do
	// collide. That is the accepted failure mode, and it is one-directional:
	// it can only hide an orphan.
	shared := strings.Repeat("ab", 16)
	c := local_cache.InstanceHash(shared + strings.Repeat("00", 16))
	d := local_cache.InstanceHash(shared + strings.Repeat("ff", 16))
	require.Equal(t, truncateHash(c), truncateHash(d),
		"a 128-bit prefix collision is expected; the safety argument is the direction, not the odds")

	// A malformed hash must not silently alias onto a well-formed one.
	require.NotEqual(t, truncateHash(a), truncateHash(local_cache.InstanceHash("not-hex")))
}
