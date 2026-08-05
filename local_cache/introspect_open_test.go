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
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// These tests cover OpenCacheDBReadOnly and NewIntrospectAPI -- the offline
// half of `pelican cache introspect`, which had no coverage at all and was
// broken on every platform as a result.
//
// The fault they exist to catch: OpenCacheDBReadOnly used to hand BadgerDB
// opts.ReadOnly = true together with the database encryption key.  BadgerDB
// v4.9.1 cannot read an *encrypted* database that has flushed at least one SST
// file through a read-only handle; Table.fetchIndex reaches y.Check(err), which
// is log.Fatalf, and the process exits printing only "err: invalid argument".
// No error is returned and no defer runs.  Every database NewCacheDB creates is
// encrypted and every cache that has served an object has an SST, so this fired
// on every real cache.  On Windows the same call failed differently and
// harmlessly: "Read-only mode is not supported on Windows".
//
// Because the pre-fix failure mode is a process abort rather than an error, a
// test that trips it takes the whole package's test binary down with it -- that
// is exactly what running TestOpenCacheDBReadOnlyPopulatedCache against the old
// code does, and how the fault was confirmed.

// populatedCacheDir builds a cache directory holding real records, closes it,
// and returns the base directory.  The database is left in the state a stopped
// cache leaves behind: encrypted (as every cache database is), with at least
// one SST file on disk, which together are what BadgerDB's read-only mode could
// not survive.
func populatedCacheDir(t *testing.T) (baseDir string, instHash InstanceHash, sourceURL string) {
	t.Helper()
	InitIssuerKeyForTests(t)

	baseDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, egrpCtx := errgroup.WithContext(ctx)

	db, err := NewCacheDB(egrpCtx, baseDir)
	require.NoError(t, err)
	require.NoError(t, db.EnsureStoreMode(StoreModeCache))

	// A storage manager is what persists the disk mappings that
	// NewStorageManagerReadOnly (and therefore NewIntrospectAPI) needs.
	sm, err := NewStorageManager(db, []string{baseDir}, InlineThreshold, egrp)
	require.NoError(t, err)

	sourceURL = "pelican://example.com/ns/introspect-me.dat"
	objHash := db.ObjectHash(sourceURL)
	instHash = db.InstanceHash("etag-ro", objHash)

	payload := []byte("cache introspection payload")
	meta := &CacheMetadata{
		ETag:          "etag-ro",
		SourceURL:     sourceURL,
		ContentLength: int64(len(payload)),
		ContentType:   "application/octet-stream",
		StorageID:     StorageIDInline,
		NamespaceID:   NamespaceID(1),
		LastModified:  time.Now().Add(-time.Hour),
		Completed:     time.Now(),
	}
	require.NoError(t, sm.StoreInline(egrpCtx, instHash, meta, payload))
	require.NoError(t, db.SetLatestETag(objHash, "etag-ro", time.Now()))
	require.NoError(t, db.SetNamespaceMapping("/ns", NamespaceID(1)))

	sm.Close()

	// Flush the memtable so the database really has an SST on disk.  Without
	// this a small test database can live entirely in the value log and the
	// old read-only open would have survived, which would have made this test
	// pass against the very code it exists to catch.
	require.NoError(t, db.DB().Flatten(2))
	require.NoError(t, db.Close())

	cancel()
	require.NoError(t, egrp.Wait())

	ssts, err := filepath.Glob(filepath.Join(baseDir, dbSubDir, "*.sst"))
	require.NoError(t, err)
	require.NotEmpty(t, ssts, "test setup did not produce an SST file, so it does not "+
		"reproduce the condition that broke read-only opens")

	return baseDir, instHash, sourceURL
}

// TestOpenCacheDBReadOnlyPopulatedCache is the regression test for the abort:
// opening a populated, encrypted cache database for introspection must succeed
// and must be able to read records back.
//
// Against the pre-fix implementation this does not fail -- it kills the test
// binary via log.Fatalf, so the whole package reports FAIL with no test result
// line at all.  There is no way to assert on that from inside the process,
// which is precisely why the fix stops using BadgerDB's read-only mode.
func TestOpenCacheDBReadOnlyPopulatedCache(t *testing.T) {
	baseDir, instHash, sourceURL := populatedCacheDir(t)

	db, err := OpenCacheDBReadOnly(baseDir)
	require.NoError(t, err, "an ordinary populated cache database must open for introspection")
	defer db.Close()

	assert.True(t, db.ReadOnly(), "an introspection handle must report itself read-only")

	// The salt was read, not regenerated: a fresh salt would hash the same URL
	// to a different instance and silently find nothing.
	require.NotEmpty(t, db.Salt())
	assert.Equal(t, instHash, db.InstanceHash("etag-ro", db.ObjectHash(sourceURL)),
		"the introspection handle recomputed a different instance hash, so it did not "+
			"load the salt the records were written under")

	meta, err := db.GetMetadata(instHash)
	require.NoError(t, err)
	require.NotNil(t, meta, "introspection could not read back a record that is in the cache")
	assert.Equal(t, sourceURL, meta.SourceURL)
	assert.Equal(t, "etag-ro", meta.ETag)

	etag, found, err := db.GetLatestETag(db.ObjectHash(sourceURL))
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "etag-ro", etag)

	// And a scan works, which is what every list/stats subcommand runs.
	var scanned int
	require.NoError(t, db.ScanMetadata(func(InstanceHash, *CacheMetadata) error {
		scanned++
		return nil
	}))
	assert.Equal(t, 1, scanned)
}

// TestOpenCacheDBReadOnlyLeavesNoStamp is the property that must not regress
// when the underlying BadgerDB handle stops being read-only: inspecting a
// database must leave its header exactly as it was found.
//
// The database is stripped of both header markers first, so that a stamping
// implementation has somewhere visible to write.  An unmarked database is the
// realistic case too -- it is what every cache deployed before versioning and
// before the store-mode marker looks like, and adopting one is a decision that
// belongs to a writable open, not to a tool that is only looking.
func TestOpenCacheDBReadOnlyLeavesNoStamp(t *testing.T) {
	baseDir, instHash, _ := populatedCacheDir(t)

	writable, err := NewCacheDB(t.Context(), baseDir)
	require.NoError(t, err)
	deleteRawKey(t, writable, KeySchemaVersion)
	deleteRawKey(t, writable, KeyStoreMode)
	require.NoError(t, writable.Close())

	db, err := OpenCacheDBReadOnly(baseDir)
	require.NoError(t, err, "an unmarked database must still be inspectable")
	// Read something, so the open is not the only thing under test.
	meta, err := db.GetMetadata(instHash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	require.NoError(t, db.Close())

	// Look behind CacheDB's back: neither marker may have appeared.
	raw := openRawBadger(t, baseDir)
	requireRawKeyAbsent(t, raw, KeySchemaVersion)
	requireRawKeyAbsent(t, raw, KeyStoreMode)
}

// TestOpenCacheDBReadOnlyRefusesWrites checks the guard that replaced
// BadgerDB's enforcement.  The underlying handle is writable now, so every
// mutating entry point has to refuse on its own; one that forgets would let an
// introspection command quietly modify the cache it was asked to report on.
func TestOpenCacheDBReadOnlyRefusesWrites(t *testing.T) {
	baseDir, instHash, sourceURL := populatedCacheDir(t)

	db, err := OpenCacheDBReadOnly(baseDir)
	require.NoError(t, err)
	defer db.Close()

	objHash := db.ObjectHash(sourceURL)

	mutations := map[string]func() error{
		"SetMetadata":    func() error { return db.SetMetadata(instHash, &CacheMetadata{ETag: "nope"}) },
		"MergeMetadata":  func() error { return db.MergeMetadata(instHash, &CacheMetadata{ETag: "nope"}) },
		"DeleteMetadata": func() error { return db.DeleteMetadata(instHash) },
		"SetLatestETag":  func() error { return db.SetLatestETag(objHash, "nope", time.Now()) },
		"DeleteLatestETag": func() error {
			return db.DeleteLatestETag(objHash)
		},
		"SetNamespaceMapping": func() error { return db.SetNamespaceMapping("/other", NamespaceID(2)) },
		"SaveDiskMapping":     func() error { return db.SaveDiskMapping(DiskMapping{ID: 9, Directory: baseDir}) },
		"SetBlockState":       func() error { return db.SetBlockState(instHash, roaring.New()) },
		"MergeBlockStateWithUsage": func() error {
			return db.MergeBlockStateWithUsage(instHash, roaring.New(), StorageIDInline, 1, -1)
		},
		"MarkBlocksDownloaded": func() error {
			return db.MarkBlocksDownloaded(instHash, 0, 0, StorageIDInline, 1, -1)
		},
		"ClearBlocks":      func() error { return db.ClearBlocks(instHash, []uint32{0}) },
		"DeleteBlockState": func() error { return db.DeleteBlockState(instHash) },
		"SetInlineData":    func() error { return db.SetInlineData(instHash, []byte("nope")) },
		"SetAppendIntent":  func() error { return db.SetAppendIntent(instHash, AppendIntent{}) },
		"DeleteAppendIntent": func() error {
			return db.DeleteAppendIntent(instHash)
		},
		"UpdateLRU":      func() error { return db.UpdateLRU(instHash, 0) },
		"AddUsage":       func() error { return db.AddUsage(StorageIDInline, 1, 128) },
		"ChargeUsage":    func() error { return db.ChargeUsage(StorageIDInline, 1, 128) },
		"SetUsage":       func() error { return db.SetUsage(StorageIDInline, 1, 128) },
		"DeleteObject":   func() error { return db.DeleteObject(instHash) },
		"MarkPurgeFirst": func() error { return db.MarkPurgeFirst(instHash) },
		"UnmarkPurgeFirst": func() error {
			return db.UnmarkPurgeFirst(instHash)
		},
		"PurgeStorageID": func() error { return db.PurgeStorageID(StorageIDInline) },
		"EnsureStoreMode": func() error {
			return db.EnsureStoreMode(StoreModeCache)
		},
		"ReloadSalt": func() error { return db.ReloadSalt() },
		"EvictByLRU": func() error {
			_, _, err := db.EvictByLRU(StorageIDInline, 1, 1, 0, nil)
			return err
		},
		// A batch holds an open BadgerDB write transaction, so each of these
		// cancels the one it took -- the refusal is the assertion, not a reason
		// to leak the transaction until Close.
		"Batch.Set": func() error {
			b := db.NewBatch()
			defer b.Cancel()
			return b.Set([]byte("x"), []byte("y"))
		},
		"Batch.Delete": func() error {
			b := db.NewBatch()
			defer b.Cancel()
			return b.Delete([]byte("x"))
		},
		"Batch.Flush": func() error {
			b := db.NewBatch()
			defer b.Cancel()
			return b.Flush()
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			err := mutate()
			require.Error(t, err, "%s modified a read-only cache database", name)
			assert.ErrorIs(t, err, ErrReadOnly)
			assert.Contains(t, err.Error(), baseDir, "the refusal should name the database")
		})
	}

	// The list above is written by hand, so it goes stale the moment someone
	// adds a mutating method -- and a missing guard is invisible until an
	// introspection command writes to a cache.  Check the list covers every
	// exported method whose name says it writes.
	t.Run("CoversEveryMutatingMethod", func(t *testing.T) {
		writePrefixes := []string{"Set", "Save", "Delete", "Merge", "Mark", "Unmark",
			"Purge", "Add", "Charge", "Evict", "Ensure", "Reload", "Clear", "Update"}
		cacheDBType := reflect.TypeOf(db)
		var found int
		for i := 0; i < cacheDBType.NumMethod(); i++ {
			name := cacheDBType.Method(i).Name
			mutating := false
			for _, prefix := range writePrefixes {
				if strings.HasPrefix(name, prefix) {
					mutating = true
					break
				}
			}
			if !mutating {
				continue
			}
			found++
			assert.Contains(t, mutations, name,
				"CacheDB.%s looks like it writes but is not exercised against a read-only "+
					"handle; add it to the table above (and give it a checkWritable guard)", name)
		}
		// Guard against the loop above quietly matching nothing -- a vacuous
		// pass here would leave the whole table unpoliced.
		require.Greater(t, found, 20, "the reflective scan found almost no mutating methods, "+
			"so it is not actually checking anything")
	})

	// Nothing above reached the database.
	meta, err := db.GetMetadata(instHash)
	require.NoError(t, err)
	require.NotNil(t, meta, "a refused mutation removed the record anyway")
	assert.Equal(t, "etag-ro", meta.ETag)
}

// TestStartGCIsInertOnReadOnlyHandle covers the one mutating path that is not
// an entry point returning an error: value-log GC rewrites the log, so a
// read-only handle must not start it.  The errgroup draining on its own is the
// observable consequence -- a started worker only exits on ctx.Done.
func TestStartGCIsInertOnReadOnlyHandle(t *testing.T) {
	baseDir, _, _ := populatedCacheDir(t)

	db, err := OpenCacheDBReadOnly(baseDir)
	require.NoError(t, err)
	defer db.Close()

	// A context that is never cancelled: if StartGC launched its worker, the
	// worker would still be sitting on its ticker and Wait would block.
	egrp, egrpCtx := errgroup.WithContext(context.Background())
	db.StartGC(egrpCtx, egrp)
	require.NoError(t, egrp.Wait(), "a read-only handle started a garbage collector")
}

// TestOpenCacheDBReadOnlyReportsARunningCache pins the failure mode the fix
// introduces.  An ordinary BadgerDB open takes the directory lock, so offline
// introspection now fails while a cache is running instead of opening beside
// it.  That is the right trade -- the lock also stops a cache from starting up
// underneath an introspection in progress -- but only if the operator is told
// what happened, since BadgerDB's own wording ("Another process is using this
// Badger database") does not name the cache or the way out.
func TestOpenCacheDBReadOnlyReportsARunningCache(t *testing.T) {
	baseDir, _, _ := populatedCacheDir(t)

	// Stand in for the running cache: hold the database open read-write.
	running, err := NewCacheDB(t.Context(), baseDir)
	require.NoError(t, err)
	defer running.Close()

	db, err := OpenCacheDBReadOnly(baseDir)
	if db != nil {
		db.Close()
	}
	require.Error(t, err, "introspection opened a database another process holds")
	msg := err.Error()
	assert.Contains(t, msg, baseDir, "the error should name the cache directory")
	assert.Contains(t, msg, "cache server is running",
		"the error should say why the database is locked")
	assert.Contains(t, msg, "--offline",
		"the error should point the operator at the live path")
}

// TestOpenCacheDBReadOnlyMissingDatabase checks that pointing the CLI at a
// directory with no cache in it says so, rather than creating an empty
// database there and reporting a cache with nothing in it.
func TestOpenCacheDBReadOnlyMissingDatabase(t *testing.T) {
	InitIssuerKeyForTests(t)
	baseDir := t.TempDir()

	db, err := OpenCacheDBReadOnly(baseDir)
	if db != nil {
		db.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no cache database at")

	// And nothing was created on the way to failing: a mistyped path must not
	// leave a stray empty cache database behind.
	_, statErr := os.Stat(filepath.Join(baseDir, dbSubDir))
	assert.True(t, os.IsNotExist(statErr),
		"a failed introspection open created a database directory")
}

// TestOpenCacheDBReadOnlyRefusesNewerSchema keeps the version check on the
// introspection path.  It runs on every platform now, unlike the handle-level
// check in TestSchemaVersionReadOnlyPath, because the open no longer depends on
// BadgerDB's read-only mode.
func TestOpenCacheDBReadOnlyRefusesNewerSchema(t *testing.T) {
	baseDir, _, _ := populatedCacheDir(t)

	writable, err := NewCacheDB(t.Context(), baseDir)
	require.NoError(t, err)
	setRawKey(t, writable, KeySchemaVersion, []byte("999"))
	require.NoError(t, writable.Close())

	db, err := OpenCacheDBReadOnly(baseDir)
	if db != nil {
		db.Close()
	}
	require.Error(t, err, "introspection read a database written under a newer layout")
	assert.Contains(t, err.Error(), "schema version 999")
}

// TestNewIntrospectAPIOffline is the end-to-end check: the constructor the
// `--offline` subcommands call, against a real populated cache directory.
//
// This is the assembly that was broken -- NewIntrospectAPI is the only
// non-test caller of OpenCacheDBReadOnly -- so it is worth exercising past the
// open, through the queries the CLI actually issues.
func TestNewIntrospectAPIOffline(t *testing.T) {
	baseDir, instHash, sourceURL := populatedCacheDir(t)

	api, err := NewIntrospectAPI(baseDir)
	require.NoError(t, err, "offline introspection could not open a stopped cache")
	defer api.Close()

	// `introspect list`
	objects, err := api.ListAllObjects(0, "")
	require.NoError(t, err)
	require.Len(t, objects, 1)
	assert.Equal(t, sourceURL, objects[0].SourceURL)
	assert.Equal(t, string(instHash), objects[0].InstanceHash)
	assert.True(t, objects[0].IsInline)

	// `introspect etags`
	instances, err := api.ListObjectInstances(sourceURL)
	require.NoError(t, err)
	require.Len(t, instances, 1)
	assert.Equal(t, "etag-ro", instances[0].ETag)
	assert.True(t, instances[0].IsLatest, "the stored ETag pointer was not read back")

	// `introspect metadata`
	details, err := api.GetObjectDetails(string(instHash))
	require.NoError(t, err)
	require.NotNil(t, details)
	assert.Equal(t, sourceURL, details.SourceURL)
	assert.Equal(t, "application/octet-stream", details.ContentType)

	// `introspect stats` -- reaches the storage manager's disk mappings and the
	// namespace table as well as the metadata scan.
	stats, err := api.GetCacheStats()
	require.NoError(t, err)
	assert.Equal(t, int64(1), stats.TotalMetadataEntries)
	assert.Greater(t, stats.TotalInlineBytes, int64(0))
	assert.Equal(t, "/ns", stats.NamespaceNames[1])
	assert.Contains(t, stats.DirPaths, uint8(1), "the storage directory mapping was not loaded")

	// `introspect disk-usage` walks the storage directories the read-only
	// manager discovered.
	usage, err := api.GetDiskUsage()
	require.NoError(t, err)
	assert.NotEmpty(t, usage.Directories)
}

// TestNewIntrospectAPILeavesNoStamp is TestOpenCacheDBReadOnlyLeavesNoStamp one
// level up, through the constructor the CLI uses: NewIntrospectAPI also builds
// a storage manager, and that must not write a header marker either.
func TestNewIntrospectAPILeavesNoStamp(t *testing.T) {
	baseDir, _, _ := populatedCacheDir(t)

	writable, err := NewCacheDB(t.Context(), baseDir)
	require.NoError(t, err)
	deleteRawKey(t, writable, KeySchemaVersion)
	deleteRawKey(t, writable, KeyStoreMode)
	require.NoError(t, writable.Close())

	api, err := NewIntrospectAPI(baseDir)
	require.NoError(t, err)
	_, err = api.ListAllObjects(0, "")
	require.NoError(t, err)
	require.NoError(t, api.Close())

	raw := openRawBadger(t, baseDir)
	requireRawKeyAbsent(t, raw, KeySchemaVersion)
	requireRawKeyAbsent(t, raw, KeyStoreMode)
}

// TestIntrospectAPIClosesCleanly guards the shutdown path the CLI depends on:
// every subcommand defers Close, and a Close that hangs leaves the command
// wedged after it has already printed its answer.
func TestIntrospectAPIClosesCleanly(t *testing.T) {
	baseDir, _, _ := populatedCacheDir(t)

	api, err := NewIntrospectAPI(baseDir)
	require.NoError(t, err)

	closed := make(chan error, 1)
	go func() { closed <- api.Close() }()

	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("IntrospectAPIOpen.Close did not return")
	}

	// The directory lock is released with it, so the cache can start again.
	reopened, err := NewCacheDB(t.Context(), baseDir)
	require.NoError(t, err, "introspection did not release the database")
	require.NoError(t, reopened.Close())
}
