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
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openRawBadger opens the underlying BadgerDB directly, bypassing NewCacheDB
// and therefore every check it performs.  Tests use it to inspect a database
// that CacheDB refuses to open.
func openRawBadger(t *testing.T, baseDir string) *badger.DB {
	t.Helper()
	encMgr, err := NewEncryptionManager(baseDir)
	require.NoError(t, err)
	dbKey, err := encMgr.DeriveDBKey()
	require.NoError(t, err)

	opts := badger.DefaultOptions(filepath.Join(baseDir, dbSubDir))
	opts.Logger = newBadgerLogger()
	opts.EncryptionKey = dbKey
	opts.EncryptionKeyRotationDuration = 0
	opts.IndexCacheSize = 64 << 20
	db, err := badger.Open(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// openPlainBadger opens an unencrypted BadgerDB, optionally read-only, for
// tests that need a real read-only handle to wrap in a CacheDB.  See
// TestSchemaVersionReadOnlyPath for why encryption is left off.
func openPlainBadger(t *testing.T, dir string, readOnly bool) *badger.DB {
	t.Helper()
	opts := badger.DefaultOptions(filepath.Join(dir, dbSubDir))
	opts.Logger = newBadgerLogger()
	opts.ReadOnly = readOnly
	db, err := badger.Open(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// requireRawKeyAbsent asserts that a key is missing from a database opened
// outside of CacheDB.
func requireRawKeyAbsent(t *testing.T, db *badger.DB, key string) {
	t.Helper()
	require.NoError(t, db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(key))
		assert.ErrorIs(t, err, badger.ErrKeyNotFound, "key %s should not be present", key)
		return nil
	}))
}

// readRawKey returns the raw value of a database key, and whether it exists.
func readRawKey(t *testing.T, db *CacheDB, key string) ([]byte, bool) {
	t.Helper()
	var out []byte
	var found bool
	require.NoError(t, db.DB().View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		found = true
		return item.Value(func(val []byte) error {
			out = append([]byte(nil), val...)
			return nil
		})
	}))
	return out, found
}

// setRawKey writes a raw value, standing in for a database written by some
// other build of Pelican.
func setRawKey(t *testing.T, db *CacheDB, key string, val []byte) {
	t.Helper()
	require.NoError(t, db.DB().Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), val)
	}))
}

// deleteRawKey removes a raw key, standing in for a database written before
// that key existed.
func deleteRawKey(t *testing.T, db *CacheDB, key string) {
	t.Helper()
	require.NoError(t, db.DB().Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	}))
}

// requireSchemaVersion asserts the stamped schema version.
func requireSchemaVersion(t *testing.T, db *CacheDB, want SchemaVersion) {
	t.Helper()
	val, found := readRawKey(t, db, KeySchemaVersion)
	require.True(t, found, "database carries no schema version marker")
	assert.Equal(t, strconv.FormatUint(uint64(want), 10), string(val))
}

// writeSampleObject stores one metadata record so that the database is not
// merely a set of header keys, and returns its instance hash.
func writeSampleObject(t *testing.T, db *CacheDB) InstanceHash {
	t.Helper()
	objHash := db.ObjectHash("pelican://example.com/ns/object.txt")
	instHash := db.InstanceHash("etag-1", objHash)
	require.NoError(t, db.SetMetadata(instHash, &CacheMetadata{
		ETag:          "etag-1",
		ContentLength: 42,
		Completed:     time.Now(),
	}))
	return instHash
}

// TestSchemaVersionFreshDatabase verifies that a newly created database is
// stamped with the version this binary writes.
func TestSchemaVersionFreshDatabase(t *testing.T) {
	InitIssuerKeyForTests(t)
	ctx := t.Context()

	db, err := NewCacheDB(ctx, t.TempDir())
	require.NoError(t, err)
	defer db.Close()

	requireSchemaVersion(t, db, CurrentSchemaVersion)
}

// TestSchemaVersionAdoptsUnversionedDatabase covers the upgrade path taken by
// every cache deployed before versioning existed: the database holds real
// records but no version marker, so it is adopted as the current schema,
// stamped, and continues to serve its contents.
func TestSchemaVersionAdoptsUnversionedDatabase(t *testing.T) {
	InitIssuerKeyForTests(t)
	ctx := t.Context()
	dir := t.TempDir()

	db, err := NewCacheDB(ctx, dir)
	require.NoError(t, err)
	instHash := writeSampleObject(t, db)
	// Strip the marker: this is what a pre-versioning database looks like.
	deleteRawKey(t, db, KeySchemaVersion)
	_, found := readRawKey(t, db, KeySchemaVersion)
	require.False(t, found)
	require.NoError(t, db.Close())

	reopened, err := NewCacheDB(ctx, dir)
	require.NoError(t, err, "an unversioned cache database must still open")
	defer reopened.Close()

	requireSchemaVersion(t, reopened, CurrentSchemaVersion)

	// Adoption must not disturb the records that were already there.
	meta, err := reopened.GetMetadata(instHash)
	require.NoError(t, err)
	require.NotNil(t, meta, "adoption lost the pre-existing metadata")
	assert.Equal(t, int64(42), meta.ContentLength)

	// And the store mode marker still governs ownership as before.
	require.NoError(t, reopened.EnsureStoreMode(StoreModeCache))
}

// TestSchemaVersionRefusesNewer verifies that a database written under a later
// layout is refused rather than misread, and that the error names both the
// version found and the version supported.
func TestSchemaVersionRefusesNewer(t *testing.T) {
	InitIssuerKeyForTests(t)
	ctx := t.Context()
	dir := t.TempDir()

	future := CurrentSchemaVersion + 1
	db, err := NewCacheDB(ctx, dir)
	require.NoError(t, err)
	writeSampleObject(t, db)
	setRawKey(t, db, KeySchemaVersion, []byte(strconv.FormatUint(uint64(future), 10)))
	require.NoError(t, db.Close())

	reopened, err := NewCacheDB(ctx, dir)
	require.Error(t, err, "a database from a newer Pelican must not open")
	if reopened != nil {
		reopened.Close()
	}
	assert.Contains(t, err.Error(), "schema version "+strconv.FormatUint(uint64(future), 10),
		"error should name the version found")
	assert.Contains(t, err.Error(), "version "+strconv.FormatUint(uint64(CurrentSchemaVersion), 10),
		"error should name the version supported")
	assert.Contains(t, err.Error(), dir, "error should name the database")
}

// TestSchemaVersionRefusalLeavesDatabaseUntouched verifies that refusing a
// newer database does not write anything into it -- an old binary must not
// leave fingerprints on a database it could not read.
func TestSchemaVersionRefusalLeavesDatabaseUntouched(t *testing.T) {
	InitIssuerKeyForTests(t)
	ctx := t.Context()
	dir := t.TempDir()

	future := CurrentSchemaVersion + 1
	db, err := NewCacheDB(ctx, dir)
	require.NoError(t, err)
	writeSampleObject(t, db)
	// Remove the markers a fresh open would otherwise write, so that a stray
	// write during the refused open is visible.
	deleteRawKey(t, db, KeySalt)
	deleteRawKey(t, db, KeyStoreMode)
	setRawKey(t, db, KeySchemaVersion, []byte(strconv.FormatUint(uint64(future), 10)))
	require.NoError(t, db.Close())

	refused, err := NewCacheDB(ctx, dir)
	require.Error(t, err)
	if refused != nil {
		refused.Close()
	}

	// Inspect the database behind CacheDB's back: the refused open must have
	// written neither a salt nor a store mode marker.
	raw := openRawBadger(t, dir)
	requireRawKeyAbsent(t, raw, KeySalt)
	requireRawKeyAbsent(t, raw, KeyStoreMode)
}

// TestSchemaVersionReadOnlyPath exercises VerifySchemaVersion against a
// genuinely read-only BadgerDB handle -- the strongest possible statement of
// the claim the function makes, since badger rejects any Update on such a
// handle and a stamping implementation would fail outright rather than merely
// leaving a key behind.
//
// The handle is built by hand rather than through OpenCacheDBReadOnly, which
// no longer uses BadgerDB's read-only mode at all (see the comment there: it
// aborts the process on an encrypted database with SST data, and is
// unsupported on Windows).  Wrapping a plain read-only handle in a CacheDB
// exercises exactly the code under test: VerifySchemaVersion reads one key and
// touches nothing else.
//
// The introspection path itself is covered end to end, on every platform, by
// TestOpenCacheDBReadOnlyLeavesNoStamp and
// TestOpenCacheDBReadOnlyRefusesNewerSchema in introspect_open_test.go.
func TestSchemaVersionReadOnlyPath(t *testing.T) {
	// BadgerDB refuses read-only mode on Windows outright ("Read-only mode is
	// not supported on Windows"), so there is no read-only handle to wrap and
	// nothing here to exercise.  This costs no coverage of the introspection
	// path, which does not depend on that mode; it only means this particular
	// way of proving VerifySchemaVersion never writes is unavailable there.
	if runtime.GOOS == "windows" {
		t.Skip("BadgerDB does not support read-only mode on Windows")
	}

	t.Run("UnversionedDatabaseAccepted", func(t *testing.T) {
		dir := t.TempDir()
		seed := openPlainBadger(t, dir, false)
		require.NoError(t, seed.Update(func(txn *badger.Txn) error {
			return txn.Set(MetaKey("instance"), []byte("record"))
		}))
		require.NoError(t, seed.Close())

		ro := openPlainBadger(t, dir, true)
		cdb := &CacheDB{db: ro, baseDir: dir}
		require.NoError(t, cdb.VerifySchemaVersion(),
			"introspecting a pre-versioning database must not fail")

		// ...and nothing was stamped.
		require.NoError(t, ro.View(func(txn *badger.Txn) error {
			_, err := txn.Get([]byte(KeySchemaVersion))
			assert.ErrorIs(t, err, badger.ErrKeyNotFound, "read-only path wrote a stamp")
			return nil
		}))
	})

	t.Run("CurrentVersionAccepted", func(t *testing.T) {
		dir := t.TempDir()
		seed := openPlainBadger(t, dir, false)
		require.NoError(t, seed.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte(KeySchemaVersion),
				[]byte(strconv.FormatUint(uint64(CurrentSchemaVersion), 10)))
		}))
		require.NoError(t, seed.Close())

		cdb := &CacheDB{db: openPlainBadger(t, dir, true), baseDir: dir}
		require.NoError(t, cdb.VerifySchemaVersion())
	})

	t.Run("NewerVersionRefused", func(t *testing.T) {
		dir := t.TempDir()
		future := CurrentSchemaVersion + 1
		seed := openPlainBadger(t, dir, false)
		require.NoError(t, seed.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte(KeySchemaVersion),
				[]byte(strconv.FormatUint(uint64(future), 10)))
		}))
		require.NoError(t, seed.Close())

		cdb := &CacheDB{db: openPlainBadger(t, dir, true), baseDir: dir}
		err := cdb.VerifySchemaVersion()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "schema version "+strconv.FormatUint(uint64(future), 10),
			"error should name the version found")
		assert.Contains(t, err.Error(), "version "+strconv.FormatUint(uint64(CurrentSchemaVersion), 10),
			"error should name the version supported")
	})
}

// TestSchemaVersionOlderWithoutMigration pins the behavior of the migration
// seam.  No Pelican has ever written a version below CurrentSchemaVersion, so
// a marker claiming one cannot be honored: there is no migration to run and
// interpreting the records under today's rules is the very thing versioning
// exists to prevent.  The refusal names the version, so whoever adds schema
// version 2 sees immediately where the migration belongs (migrateSchema).
func TestSchemaVersionOlderWithoutMigration(t *testing.T) {
	InitIssuerKeyForTests(t)
	ctx := t.Context()
	dir := t.TempDir()

	db, err := NewCacheDB(ctx, dir)
	require.NoError(t, err)
	setRawKey(t, db, KeySchemaVersion, []byte("0"))
	require.NoError(t, db.Close())

	reopened, err := NewCacheDB(ctx, dir)
	require.Error(t, err)
	if reopened != nil {
		reopened.Close()
	}
	assert.Contains(t, err.Error(), "no migration is available from schema version 0")
}

// TestSchemaVersionMalformedMarker verifies that a marker that is not a
// version number is reported rather than silently treated as version zero.
func TestSchemaVersionMalformedMarker(t *testing.T) {
	InitIssuerKeyForTests(t)
	ctx := t.Context()
	dir := t.TempDir()

	db, err := NewCacheDB(ctx, dir)
	require.NoError(t, err)
	setRawKey(t, db, KeySchemaVersion, []byte("not-a-version"))
	require.NoError(t, db.Close())

	reopened, err := NewCacheDB(ctx, dir)
	require.Error(t, err)
	if reopened != nil {
		reopened.Close()
	}
	assert.Contains(t, err.Error(), "not a version number")
}

// TestSchemaVersionAndStoreModeCoexist verifies that the two header markers do
// not interfere: the version stamp must not make an otherwise empty database
// look "used" to store mode adoption, and a mode mismatch must still fail with
// the mode error.
func TestSchemaVersionAndStoreModeCoexist(t *testing.T) {
	InitIssuerKeyForTests(t)
	ctx := t.Context()

	t.Run("EmptyDatabaseStillAdoptableAsPStore", func(t *testing.T) {
		// A fresh database carries a salt and a schema version before any
		// consumer claims it.  Neither says anything about who owns it, so a
		// pstore -- which may only adopt an otherwise empty database -- must
		// still be able to claim it.
		db, err := NewCacheDB(ctx, t.TempDir())
		require.NoError(t, err)
		defer db.Close()

		requireSchemaVersion(t, db, CurrentSchemaVersion)
		require.NoError(t, db.EnsureStoreMode(StoreModePStore),
			"the schema version stamp must not block pstore adoption")
	})

	t.Run("NonEmptyDatabaseStillRefusedForPStore", func(t *testing.T) {
		db, err := NewCacheDB(ctx, t.TempDir())
		require.NoError(t, err)
		defer db.Close()

		writeSampleObject(t, db)
		err = db.EnsureStoreMode(StoreModePStore)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no store mode marker")
	})

	t.Run("ModeMismatchStillFails", func(t *testing.T) {
		dir := t.TempDir()
		db, err := NewCacheDB(ctx, dir)
		require.NoError(t, err)
		require.NoError(t, db.EnsureStoreMode(StoreModeCache))
		requireSchemaVersion(t, db, CurrentSchemaVersion)
		require.NoError(t, db.Close())

		reopened, err := NewCacheDB(ctx, dir)
		require.NoError(t, err, "the version check must not reject a well-formed database")
		defer reopened.Close()

		err = reopened.EnsureStoreMode(StoreModePStore)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "belongs to a \"cache\" store")
	})

	t.Run("VersionRefusalPrecedesModeCheck", func(t *testing.T) {
		// A database owned by a pstore and written under a newer layout is
		// refused for its version, not misreported as a mode problem: the mode
		// marker is itself a record written under a layout we cannot read.
		dir := t.TempDir()
		db, err := NewCacheDB(ctx, dir)
		require.NoError(t, err)
		require.NoError(t, db.EnsureStoreMode(StoreModePStore))
		setRawKey(t, db, KeySchemaVersion,
			[]byte(strconv.FormatUint(uint64(CurrentSchemaVersion+1), 10)))
		require.NoError(t, db.Close())

		reopened, err := NewCacheDB(ctx, dir)
		require.Error(t, err)
		if reopened != nil {
			reopened.Close()
		}
		assert.Contains(t, err.Error(), "schema version")
		assert.NotContains(t, err.Error(), "belongs to a",
			"the version refusal must not be reported as a store mode problem")
	})
}
