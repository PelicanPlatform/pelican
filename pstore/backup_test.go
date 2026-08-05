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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/backup_keys"
	"github.com/pelicanplatform/pelican/local_cache"
)

// testIssuerKeys builds a keyring standing in for the origin's issuer keys.
//
// Snapshots are sealed to keys derived from these, so a test can play out a
// rotation simply by handing different subsets of the same keyring to the
// writer and the reader.
func testIssuerKeys(t *testing.T, keyIDs ...string) map[string]jwk.Key {
	t.Helper()
	keys := make(map[string]jwk.Key, len(keyIDs))
	for _, keyID := range keyIDs {
		raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		key, err := jwk.FromRaw(raw)
		require.NoError(t, err)
		require.NoError(t, key.Set(jwk.KeyIDKey, keyID))
		keys[keyID] = key
	}
	return keys
}

// testBackupKeys is a keyring for tests that only need a snapshot to be
// sealed to something, without caring what.
func testBackupKeys(t *testing.T) BackupKeys {
	t.Helper()
	return BackupKeys{IssuerKeys: testIssuerKeys(t, "kid-a", "kid-b")}
}

// sealSnapshot takes a snapshot of s and returns it with the keys that open it.
//
// There is one container and it is sealed, so a test that just wants "a
// snapshot of this store" needs a keyring; producing one here keeps that from
// being restated a dozen times, and folds in the two assertions every snapshot
// owes regardless of what the caller is really testing.
func sealSnapshot(t *testing.T, s *Store) ([]byte, BackupKeys) {
	t.Helper()
	keys := testBackupKeys(t)

	var snapshot bytes.Buffer
	version, err := s.BackupEncrypted(&snapshot, keys)
	require.NoError(t, err)
	require.NotZero(t, version, "a snapshot reports the version it covers")
	require.NotZero(t, snapshot.Len())
	return snapshot.Bytes(), keys
}

// TestBackupRestoreRoundTrip is the recovery path an operator depends on: a
// catalog snapshot taken from one store, loaded into an empty one, yields the
// same namespace.
func TestBackupRestoreRoundTrip(t *testing.T) {
	source := newTestStore(t)

	require.NoError(t, source.MkdirAll("/data/sub"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))
	writeObject(t, source, "/data/sub/b.txt", []byte("beta"))

	snapshot, keys := sealSnapshot(t, source)

	// Restore into a fresh store.
	local_cache.InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	target, err := Open(ctx, egrp, Config{BaseDir: t.TempDir()})
	require.NoError(t, err)
	defer target.Close()

	require.NoError(t, target.Restore(bytes.NewReader(snapshot), keys))

	// The namespace came back.
	entries, _, err := target.List("/data", "", 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"a.txt", "sub"}, entryNames(entries))

	d, err := target.Stat("/data/sub/b.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(4), d.Size)

	// Generations survive, so ETags stay stable across a restore.
	srcDirent, err := source.Stat("/data/a.txt")
	require.NoError(t, err)
	dstDirent, err := target.Stat("/data/a.txt")
	require.NoError(t, err)
	assert.Equal(t, srcDirent.Generation, dstDirent.Generation)
}

// TestBackupIsSafeOnALiveStore covers the property that makes periodic
// backups viable at all: the snapshot streams at a fixed read timestamp, so it
// is a coherent moment rather than a smear across the writes that happened
// while it ran.
//
// "It did not return an error" is not that property.  The writer here appends
// objects in a known order, so a coherent snapshot can only contain a *prefix*
// of them -- a snapshot holding number 7 but not number 3 would mean the pass
// read at two different timestamps.  That is what is asserted, along with
// every restored entry being intact.
func TestBackupIsSafeOnALiveStore(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Mkdir("/live"))
	writeObject(t, s, "/live/before.txt", []byte("before"))

	const payload = "x"
	var (
		ready   = make(chan struct{})
		stop    = make(chan struct{})
		done    = make(chan struct{})
		written int
		// testing does not support require/assert from a non-test goroutine,
		// so the writer reports back rather than failing in place.
		writeErr error
	)
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			h, err := s.Create(fmt.Sprintf("/live/during-%04d.txt", i))
			if err == nil {
				_, err = h.Write([]byte(payload))
			}
			if err == nil {
				err = h.Close()
			}
			if err != nil {
				writeErr = err
				return
			}
			written = i + 1
			if i == 0 {
				// The backup starts only once the store is demonstrably being
				// written to, so the overlap is not left to timing.
				close(ready)
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	<-ready
	keys := testBackupKeys(t)
	var snapshot bytes.Buffer
	_, err := s.BackupEncrypted(&snapshot, keys)
	close(stop)
	<-done

	require.NoError(t, err, "a snapshot must not fail because writes are in flight")
	require.NoError(t, writeErr, "writes must not fail because a snapshot is running")
	require.Greater(t, written, 0)

	// Load the snapshot into a fresh store and inspect what it actually
	// captured.
	local_cache.InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)
	target, err := Open(ctx, egrp, Config{BaseDir: t.TempDir()})
	require.NoError(t, err)
	defer target.Close()
	require.NoError(t, target.Restore(&snapshot, keys))

	entries, _, err := target.List("/live", "", 0)
	require.NoError(t, err)

	captured := map[string]bool{}
	for _, e := range entries {
		captured[e.Name] = true
		d, sErr := target.Stat("/live/" + e.Name)
		require.NoError(t, sErr, "every entry in a snapshot is complete")
		if e.Name != "before.txt" {
			assert.Equal(t, int64(len(payload)), d.Size,
				"%s was captured mid-write", e.Name)
		}
	}
	assert.True(t, captured["before.txt"],
		"an object written before the snapshot started must be in it")

	// The writer appended in order, so the captured set must be a prefix.
	seen := 0
	for i := 0; i < written; i++ {
		if captured[fmt.Sprintf("during-%04d.txt", i)] {
			seen = i + 1
		}
	}
	for i := 0; i < seen; i++ {
		assert.True(t, captured[fmt.Sprintf("during-%04d.txt", i)],
			"a coherent snapshot holds a prefix of the writes, but during-%04d.txt is missing "+
				"while a later one is present", i)
	}
}

func TestRestoreRefusesANonEmptyStore(t *testing.T) {
	source := newTestStore(t)
	writeObject(t, source, "/a.txt", []byte("alpha"))

	snapshot, keys := sealSnapshot(t, source)

	// Restoring into the store it came from would interleave namespaces.
	err := source.Restore(bytes.NewReader(snapshot), keys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already holds objects")
}

func TestRestoreRefusedOnAReadOnlyStore(t *testing.T) {
	ro := buildStoreThenReopenReadOnly(t)
	assert.ErrorIs(t, ro.Restore(bytes.NewReader(nil), BackupKeys{}), ErrNotSupported)
}

// TestSnapshotWritesAtomically checks that a pass publishes a name only when
// there is a complete backup under it.
//
// The success path alone proves nothing -- an implementation that writes
// straight to the final name passes it.  The failing pass is the test: a
// backup that dies part-way through must leave the directory as it found it,
// with no half-written file under a name that pruning would count towards
// retention and a recovery would reach for.
func TestSnapshotWritesAtomically(t *testing.T) {
	t.Run("success publishes a complete, restorable file", func(t *testing.T) {
		s := newTestStore(t)
		writeObject(t, s, "/a.txt", []byte("alpha"))

		keys := testBackupKeys(t)
		dir := t.TempDir()
		require.NoError(t, s.snapshotOnce(BackupConfig{Dir: dir, Interval: time.Hour, Keys: keys}))

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.True(t, strings.HasPrefix(entries[0].Name(), metadataBackupPrefix))
		assert.True(t, strings.HasSuffix(entries[0].Name(), ".pmb"),
			"no .partial file survives a successful pass")

		// Published means restorable, not merely present.
		f, err := os.Open(filepath.Join(dir, entries[0].Name()))
		require.NoError(t, err)
		defer f.Close()
		target := newTestStore(t)
		require.NoError(t, target.Restore(f, keys))
		d, err := target.Stat("/a.txt")
		require.NoError(t, err)
		assert.Equal(t, int64(5), d.Size)
	})

	t.Run("failure publishes nothing", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("directory permissions do not deny writes here")
		}
		s := newTestStore(t)
		writeObject(t, s, "/a.txt", []byte("alpha"))

		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0500))
		t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

		require.Error(t, s.snapshotOnce(BackupConfig{
			Dir: dir, Interval: time.Hour, Keys: testBackupKeys(t),
		}))

		require.NoError(t, os.Chmod(dir, 0700))
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries,
			"a failed pass publishes nothing at all -- not the final name, and not a "+
				"leftover .partial")
	})

	t.Run("a partial from a crashed pass is never taken for a backup", func(t *testing.T) {
		// The temporary name is load-bearing, not cosmetic: whatever a crash
		// leaves behind must not count towards retention (which would evict a
		// real backup) and must not be reachable as one.
		s := newTestStore(t)
		writeObject(t, s, "/a.txt", []byte("alpha"))

		dir := t.TempDir()
		crashed := filepath.Join(dir,
			metadataBackupPrefix+"20260101T000000Z.pmb.partial")
		require.NoError(t, os.WriteFile(crashed, []byte("half a backup"), 0600))

		keys := testBackupKeys(t)
		require.NoError(t, s.snapshotOnce(BackupConfig{
			Dir: dir, Interval: time.Hour, Keep: 1, Keys: keys,
		}))

		var published []string
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".pmb") {
				published = append(published, e.Name())
			}
		}
		require.Len(t, published, 1, "the fragment is not a backup")

		_, err = os.Stat(crashed)
		assert.NoError(t, err, "pruning leaves what it does not recognize alone")

		f, err := os.Open(filepath.Join(dir, published[0]))
		require.NoError(t, err)
		defer f.Close()
		target := newTestStore(t)
		assert.NoError(t, target.Restore(f, keys), "the one published file is complete")
	})
}

// TestRestoreRefusesAFileThatIsNotASnapshot covers the front door of the one
// container an operator can be holding.
//
// It matters because of what BadgerDB's own loader does with a file it should
// refuse: it treats a clean EOF at any frame boundary as the end of a complete
// backup, so a raw dump cut short restores with no error and fewer objects --
// or none.  For a primary store that is the worst kind of failure, silent and
// discovered during a recovery.  The magic on the front of every snapshot is
// what makes such a file recognizable as not-a-snapshot, and the error has to
// say that rather than anything about keys: "this is not a backup" and "this
// backup will not open" send an operator to entirely different places.
func TestRestoreRefusesAFileThatIsNotASnapshot(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	t.Run("a bare BadgerDB stream", func(t *testing.T) {
		var raw bytes.Buffer
		_, bErr := source.bdb.Backup(&raw, 0)
		require.NoError(t, bErr)

		target := newTestStore(t)
		rErr := target.Restore(bytes.NewReader(raw.Bytes()), testBackupKeys(t))
		require.Error(t, rErr, "BadgerDB's own output is not a pstore snapshot")
		assert.Contains(t, rErr.Error(), "not a pstore metadata backup")

		entries, _, lErr := target.List("/", "", 0)
		require.NoError(t, lErr)
		assert.Empty(t, entries, "it is refused before a single record is written")
	})

	t.Run("an empty file", func(t *testing.T) {
		target := newTestStore(t)
		rErr := target.Restore(bytes.NewReader(nil), testBackupKeys(t))
		require.Error(t, rErr)
		assert.Contains(t, rErr.Error(), "too short")
	})

	t.Run("a file with an unrelated magic", func(t *testing.T) {
		target := newTestStore(t)
		rErr := target.Restore(strings.NewReader("SQLite format 3\x00 and then some"),
			testBackupKeys(t))
		require.Error(t, rErr)
		assert.Contains(t, rErr.Error(), "not a pstore metadata backup")
	})
}

// TestATruncatedSnapshotIsRefused is the reason a snapshot is a sealed
// container rather than a BadgerDB stream written straight out.
//
// Every cut point has to be refused, not merely the ones that happen to land
// mid-record: the terminating chunk is bound into its own nonce, so a stream cut
// short cannot be passed off as one that ended there.  A store cut at 200
// objects exercises enough chunks for the cuts to fall in different places.
func TestATruncatedSnapshotIsRefused(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	for i := range 200 {
		writeObject(t, source, fmt.Sprintf("/data/obj-%03d", i), randomBytes(256, int64(i)))
	}

	full, keys := sealSnapshot(t, source)
	require.Greater(t, len(full), 1024)

	// The store is not inspected after each cut on purpose: BadgerDB's loader
	// writes as it reads and leaves its transaction watermark short when it
	// stops early, so a handle whose restore failed blocks on the next read.
	// That is what the error tells the operator to do something about.
	for _, cut := range []int{
		len(backupMagic),     // the magic and nothing else
		len(backupMagic) + 4, // part-way through the salt
		len(full) / 2,
		len(full) - 1, // one byte short of complete
	} {
		t.Run(fmt.Sprint("cut at ", cut), func(t *testing.T) {
			target := newTestStore(t)
			rErr := target.Restore(bytes.NewReader(full[:cut]), keys)
			require.Error(t, rErr, "a truncated snapshot must not restore")
		})
	}

	t.Run("nothing is written when truncation is caught before the load", func(t *testing.T) {
		// The header is read and authenticated in full before a byte of the
		// body is opened, so damage near the front is refused before a single
		// record lands and the target directory is still usable.
		target := newTestStore(t)
		require.Error(t, target.Restore(bytes.NewReader(full[:len(backupMagic)+4]), keys))

		entries, _, lErr := target.List("/", "", 0)
		require.NoError(t, lErr)
		assert.Empty(t, entries)
	})

	t.Run("altered content is refused", func(t *testing.T) {
		altered := append([]byte(nil), full...)
		// Flip a byte inside the sealed body, past the header.
		_, _, bodyAt := backupHeaderLayout(t, altered)
		altered[bodyAt+16] ^= 0xff
		target := newTestStore(t)
		rErr := target.Restore(bytes.NewReader(altered), keys)
		require.Error(t, rErr, "a damaged snapshot must not restore")
	})

	t.Run("the intact snapshot restores completely", func(t *testing.T) {
		target := newTestStore(t)
		require.NoError(t, target.Restore(bytes.NewReader(full), keys))
		entries, _, lErr := target.List("/data", "", 0)
		require.NoError(t, lErr)
		assert.Len(t, entries, 200, "every object comes back")
	})
}

// TestASnapshotStandsOnItsOwn is the property that lets an operator reach for
// whichever file in the backup directory they like.
//
// Every snapshot is complete, so restoring the newest one needs nothing that
// came before it -- and layering an older one on top is refused, because
// restoring over live records would interleave two namespaces rather than
// replace one.
func TestASnapshotStandsOnItsOwn(t *testing.T) {
	s := newTestStore(t)
	writeObject(t, s, "/a.txt", []byte("alpha"))
	first, firstKeys := sealSnapshot(t, s)

	writeObject(t, s, "/b.txt", []byte("beta"))
	second, secondKeys := sealSnapshot(t, s)

	target := newTestStore(t)
	require.NoError(t, target.Restore(bytes.NewReader(second), secondKeys))
	for _, name := range []string{"/a.txt", "/b.txt"} {
		_, sErr := target.Stat(name)
		assert.NoError(t, sErr, "%s is in the later snapshot without needing the earlier one", name)
	}

	err := target.Restore(bytes.NewReader(first), firstKeys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already holds objects")
}

// TestSnapshotRetention checks that the oldest snapshots are pruned, which is
// what lets an operator roll back to before a corruption rather than only
// forward from the newest one.
func TestSnapshotRetention(t *testing.T) {
	s := newTestStore(t)
	dir := t.TempDir()

	// Stand in for six passes on six different days.
	var names []string
	for day := 1; day <= 6; day++ {
		name := fmt.Sprintf("%s202601%02dT000000Z.pmb", metadataBackupPrefix, day)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("snapshot"), 0600))
		names = append(names, name)
	}
	// Something else in the directory must be left alone.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "operator-notes.txt"), []byte("keep"), 0600))

	require.NoError(t, s.pruneSnapshots(BackupConfig{Dir: dir, Keep: 3}))

	remaining := map[string]bool{}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		remaining[e.Name()] = true
	}

	assert.True(t, remaining["operator-notes.txt"], "unrelated files are untouched")
	for _, n := range names[:3] {
		assert.False(t, remaining[n], "%s is older than the retention window", n)
	}
	for _, n := range names[3:] {
		assert.True(t, remaining[n], "%s is within the retention window", n)
	}
}

func TestSnapshotRetentionKeepsEverythingWhenZero(t *testing.T) {
	s := newTestStore(t)
	dir := t.TempDir()
	for day := 1; day <= 3; day++ {
		name := fmt.Sprintf("%s202601%02dT000000Z.pmb", metadataBackupPrefix, day)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("s"), 0600))
	}

	require.NoError(t, s.pruneSnapshots(BackupConfig{Dir: dir, Keep: 0}))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 3, "zero retention keeps every snapshot")
}

// TestRestoreIntoAFreshDirectoryViaMaintenance follows the path the CLI
// actually takes.  The round-trip test above restores through Open, which
// adopts an empty database; the CLI restores through OpenMaintenance, which
// refuses an unmarked non-empty one.  A fresh directory is the only sensible
// restore target, so OpenMaintenance has to apply the same adoption rule --
// otherwise the CLI could not restore anywhere at all.
func TestRestoreIntoAFreshDirectoryViaMaintenance(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	snapshot, keys := sealSnapshot(t, source)

	// A brand-new directory, as an operator recovering onto clean disk would
	// have.
	fresh := t.TempDir()
	target, err := OpenMaintenance(t.Context(), fresh, true)
	require.NoError(t, err, "restore must be able to populate an empty directory")
	require.NoError(t, target.Restore(bytes.NewReader(snapshot), keys))

	entries, _, err := target.List("/data", "", 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"a.txt"}, entryNames(entries))
	require.NoError(t, target.Close())

	// Reopening read-only now works, because the restore claimed the store.
	reopened, err := OpenMaintenance(t.Context(), fresh, false)
	require.NoError(t, err)
	defer reopened.Close()
	report, err := reopened.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.Equal(t, 2, report.EntriesScanned, "the restored namespace checks out")
}

// TestMaintenanceStillRefusesAnUnmarkedNonEmptyDatabase confirms the adoption
// rule did not become permissive: a cache predating the marker must never be
// claimed as a pstore, even when writes are allowed.
func TestMaintenanceStillRefusesAnUnmarkedNonEmptyDatabase(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dir := t.TempDir()

	db, err := local_cache.NewCacheDB(ctx, dir)
	require.NoError(t, err)
	require.NoError(t, db.SetNamespaceMapping("/legacy", 1))
	require.NoError(t, db.Close())

	_, err = OpenMaintenance(ctx, dir, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pre-existing cache")
}

// TestBackupKeyRoundTrip covers the sealed-snapshot path, which is what any
// snapshot leaving the machine should use.
func TestBackupKeyRoundTrip(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	encoded, err := generateBackupKey()
	require.NoError(t, err)
	key, err := ParseBackupKey(encoded)
	require.NoError(t, err)

	var sealed bytes.Buffer
	_, err = source.BackupEncrypted(&sealed, BackupKeys{BackupKey: key})
	require.NoError(t, err)

	// The namespace must not be readable in the file.  A snapshot is a logical
	// dump: written in the clear it would carry every one of these paths.
	assert.NotContains(t, sealed.String(), "a.txt",
		"an encrypted snapshot must not leak object paths")

	misdirected := newTestStore(t)
	err = misdirected.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "none of the available keys match",
		"restoring a sealed snapshot with nothing to open it must say so")

	target := newTestStore(t)
	require.NoError(t, target.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{BackupKey: key}))

	// The namespace comes back...
	d, err := target.Stat("/data/a.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(5), d.Size)

	// ...but not the object content, because a snapshot covers the catalog
	// only.  Reading needs the block files too, which is exactly why the CLI
	// says so at backup time.
	_, err = target.ReadAll("/data/a.txt")
	assert.Error(t, err, "a catalog-only restore cannot serve data")
}

// TestFullRecoveryFromSnapshotAndData is the real recovery drill: a snapshot
// restored alongside the block files and the master key gives back readable
// objects.
func TestFullRecoveryFromSnapshotAndData(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	// Build a store and snapshot it.
	sourceDir := t.TempDir()
	source, err := Open(ctx, egrp, Config{BaseDir: sourceDir})
	require.NoError(t, err)
	require.NoError(t, source.MkdirAll("/data/sub"))
	writeObject(t, source, "/data/small.txt", []byte("inline payload"))
	big := randomBytes(64<<10, 91)
	writeObject(t, source, "/data/sub/big.bin", big)

	encoded, err := generateBackupKey()
	require.NoError(t, err)
	key, err := ParseBackupKey(encoded)
	require.NoError(t, err)

	var sealed bytes.Buffer
	_, err = source.BackupEncrypted(&sealed, BackupKeys{BackupKey: key})
	require.NoError(t, err)
	require.NoError(t, source.Close())

	// Recover onto fresh disk: the block files and master key are restored by
	// ordinary means, the catalog from the snapshot.
	recoverDir := t.TempDir()
	copyTree(t, filepath.Join(sourceDir, "objects"), filepath.Join(recoverDir, "objects"))
	copyFile(t, filepath.Join(sourceDir, "masterkey.json"), filepath.Join(recoverDir, "masterkey.json"))

	loader, err := OpenMaintenance(ctx, recoverDir, true)
	require.NoError(t, err)
	require.NoError(t, loader.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{BackupKey: key}))
	// A restore replaces everything the store cached at open -- the hash salt
	// and the storage-directory mapping -- so the handle must be reopened
	// before the data is readable.
	require.NoError(t, loader.Close())

	recovered, err := OpenMaintenance(ctx, recoverDir, false)
	require.NoError(t, err)
	defer recovered.Close()

	// Both objects read back intact.
	small, err := recovered.ReadAll("/data/small.txt")
	require.NoError(t, err)
	assert.Equal(t, "inline payload", string(small))

	large, err := recovered.ReadAll("/data/sub/big.bin")
	require.NoError(t, err)
	assert.True(t, bytes.Equal(big, large))

	// And a deep check confirms the recovered data matches its checksums.
	report, err := recovered.FsckWith(ctx, FsckOptions{Deep: true})
	require.NoError(t, err)
	assert.True(t, report.Healthy(), "the recovered store verifies: %+v", report)
	assert.Equal(t, 2, report.ObjectsVerified)
}

// TestExportRecoversToPlainFiles covers getting data out without Pelican at
// all, which is what an operator wants when the origin will not start.
func TestExportRecoversToPlainFiles(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.MkdirAll("/data/sub"))
	writeObject(t, s, "/data/one.txt", []byte("first"))
	writeObject(t, s, "/data/sub/two.txt", []byte("second"))

	dest := t.TempDir()
	report, err := s.Export(t.Context(), ExportOptions{Root: "/data", Dest: dest, Verify: true})
	require.NoError(t, err)
	assert.Equal(t, 2, report.FilesWritten)
	assert.Empty(t, report.Failed)

	one, err := os.ReadFile(filepath.Join(dest, "one.txt"))
	require.NoError(t, err)
	assert.Equal(t, "first", string(one))

	two, err := os.ReadFile(filepath.Join(dest, "sub", "two.txt"))
	require.NoError(t, err)
	assert.Equal(t, "second", string(two))
}

// TestExportContinuesPastBadObjects is the property that matters on a damaged
// store: recovering most of the data and being told exactly what was lost
// beats stopping at the first bad block.
func TestExportContinuesPastBadObjects(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Mkdir("/data"))
	writeObject(t, s, "/data/good.txt", []byte("readable"))
	writeObject(t, s, "/data/bad.bin", randomBytes(64<<10, 92))

	// Destroy one object's data behind the store's back.
	d, err := s.Stat("/data/bad.bin")
	require.NoError(t, err)
	hash := instanceHashFor(s.db, d.Generation)
	meta, err := s.db.GetMetadata(hash)
	require.NoError(t, err)
	dirs := s.storage.GetDirs()
	require.NoError(t, os.Remove(filepath.Join(dirs[meta.StorageID],
		local_cache.GetInstanceStoragePath(hash))))

	dest := t.TempDir()
	report, err := s.Export(t.Context(), ExportOptions{Root: "/data", Dest: dest})
	require.NoError(t, err, "a damaged object must not abort the whole export")
	assert.Equal(t, 1, report.FilesWritten)
	assert.Contains(t, report.Failed, "/data/bad.bin")

	good, err := os.ReadFile(filepath.Join(dest, "good.txt"))
	require.NoError(t, err)
	assert.Equal(t, "readable", string(good))
}

// TestExportRefusesEscapingPaths guards the destination against a damaged or
// hand-edited catalog.
//
// The mapping function is checked directly *and* through Export, because a
// correct destinationFor that Export forgets to call protects nothing.  The
// escaping entry is written straight into the index, since the ordinary write
// path validates paths and could not produce one.
func TestExportRefusesEscapingPaths(t *testing.T) {
	_, err := destinationFor("/data", "/data/../../etc/passwd", "/tmp/dest")
	assert.Error(t, err)

	ok, err := destinationFor("/data", "/data/sub/f.txt", "/tmp/dest")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/tmp/dest", "sub", "f.txt"), ok)

	s := newTestStore(t)
	require.NoError(t, s.Mkdir("/data"))
	writeObject(t, s, "/data/good.txt", []byte("fine"))

	// A child of /data whose name climbs out of the subtree, as operator
	// surgery or a corrupt record could leave behind.  The ordinary write
	// path validates names and could never produce this one.
	require.NoError(t, s.bdb.Update(func(txn *badger.Txn) error {
		return putDirent(txn, "/data/..", &Dirent{Type: EntryFile, Generation: "deadbeef"})
	}))

	dest := filepath.Join(t.TempDir(), "out")
	report, err := s.Export(t.Context(), ExportOptions{Root: "/data", Dest: dest})
	require.NoError(t, err)
	assert.Equal(t, 1, report.FilesWritten, "the legitimate object still comes out")
	require.Contains(t, report.Failed, "/data/..")
	assert.Contains(t, report.Failed["/data/.."], "outside the destination")

	siblings, err := os.ReadDir(filepath.Dir(dest))
	require.NoError(t, err)
	require.Len(t, siblings, 1, "nothing was written beside the destination")
	assert.Equal(t, filepath.Base(dest), siblings[0].Name())
}

// TestExportResumeSkipsWhatIsAlreadyThere covers re-running an interrupted
// recovery.  Without --resume every file the first run wrote comes back as a
// failure, which is indistinguishable from real corruption at exactly the
// moment an operator needs to tell the difference.
func TestExportResumeSkipsWhatIsAlreadyThere(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.MkdirAll("/data/sub"))
	writeObject(t, s, "/data/one.txt", []byte("first"))
	writeObject(t, s, "/data/sub/two.txt", []byte("second"))

	dest := t.TempDir()
	first, err := s.Export(t.Context(), ExportOptions{Root: "/data", Dest: dest})
	require.NoError(t, err)
	require.Equal(t, 2, first.FilesWritten)

	// Re-running without --resume reports every file as a failure, which is
	// the behavior --resume exists to fix.
	plain, err := s.Export(t.Context(), ExportOptions{Root: "/data", Dest: dest})
	require.NoError(t, err)
	assert.Len(t, plain.Failed, 2)
	assert.Zero(t, plain.AlreadyPresent)

	resumed, err := s.Export(t.Context(), ExportOptions{Root: "/data", Dest: dest, Resume: true})
	require.NoError(t, err)
	assert.Empty(t, resumed.Failed, "already-written files are not failures")
	assert.Equal(t, 2, resumed.AlreadyPresent)
	assert.Zero(t, resumed.FilesWritten)

	// A genuinely missing file is still exported by the resumed run, and the
	// files already there are left untouched.
	require.NoError(t, os.Remove(filepath.Join(dest, "one.txt")))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "sub", "two.txt"), []byte("edited"), 0600))

	third, err := s.Export(t.Context(), ExportOptions{Root: "/data", Dest: dest, Resume: true})
	require.NoError(t, err)
	assert.Equal(t, 1, third.FilesWritten)
	assert.Equal(t, 1, third.AlreadyPresent)
	assert.Empty(t, third.Failed)

	got, err := os.ReadFile(filepath.Join(dest, "sub", "two.txt"))
	require.NoError(t, err)
	assert.Equal(t, "edited", string(got), "a resume never overwrites what is already there")
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	require.NoError(t, filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rErr := filepath.Rel(src, p)
		if rErr != nil {
			return rErr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0750)
		}
		data, rErr := os.ReadFile(p)
		if rErr != nil {
			return rErr
		}
		return os.WriteFile(target, data, info.Mode())
	}))
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, data, 0600))
}

func TestBackupKeyErrors(t *testing.T) {
	s := newTestStore(t)
	writeObject(t, s, "/a.txt", []byte("alpha"))

	encoded, err := generateBackupKey()
	require.NoError(t, err)
	key, err := ParseBackupKey(encoded)
	require.NoError(t, err)

	var sealed bytes.Buffer
	_, err = s.BackupEncrypted(&sealed, BackupKeys{BackupKey: key})
	require.NoError(t, err)

	t.Run("wrong key", func(t *testing.T) {
		otherEncoded, gErr := generateBackupKey()
		require.NoError(t, gErr)
		other, gErr := ParseBackupKey(otherEncoded)
		require.NoError(t, gErr)

		target := newTestStore(t)
		rErr := target.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{BackupKey: other})
		require.Error(t, rErr)
		assert.Contains(t, rErr.Error(), "could not be decrypted")
	})

	t.Run("truncated", func(t *testing.T) {
		cut := sealed.Bytes()[:sealed.Len()/2]
		target := newTestStore(t)
		rErr := target.Restore(bytes.NewReader(cut), BackupKeys{BackupKey: key})
		require.Error(t, rErr, "a truncated snapshot must not restore silently")
	})

	t.Run("tampered", func(t *testing.T) {
		altered := make([]byte, sealed.Len())
		copy(altered, sealed.Bytes())
		// Flip a byte inside the final sealed chunk.
		altered[len(altered)-10] ^= 0xff
		target := newTestStore(t)
		rErr := target.Restore(bytes.NewReader(altered), BackupKeys{BackupKey: key})
		require.Error(t, rErr)
	})

	t.Run("header tampered", func(t *testing.T) {
		// The header -- the salt and the whole recipient list -- is bound in as
		// additional data, so an archive whose envelope has been edited cannot
		// be passed off as a different but valid one.  The byte flipped here is
		// inside the recorded key ID, which leaves every length field intact:
		// the envelope still opens, and the body is what refuses.
		altered := make([]byte, sealed.Len())
		copy(altered, sealed.Bytes())
		_, envelopeAt, _ := backupHeaderLayout(t, altered)
		altered[envelopeAt+4+15] ^= 0xff
		target := newTestStore(t)
		rErr := target.Restore(bytes.NewReader(altered), BackupKeys{BackupKey: key})
		require.Error(t, rErr)
	})

	t.Run("bad key encoding", func(t *testing.T) {
		_, pErr := ParseBackupKey("not base64!!")
		assert.Error(t, pErr)
		_, pErr = ParseBackupKey("c2hvcnQ=")
		assert.ErrorContains(t, pErr, "must be 32 bytes")
	})
}

// TestExportRecoversNestedSubset covers recovering part of a tree rather than
// all of it, which is the common case: one project's prefix out of a store
// holding many.
func TestExportRecoversNestedSubset(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.MkdirAll("/projects/alpha/data/raw"))
	require.NoError(t, s.MkdirAll("/projects/beta"))
	writeObject(t, s, "/projects/alpha/readme.txt", []byte("alpha readme"))
	writeObject(t, s, "/projects/alpha/data/set.csv", []byte("1,2,3"))
	writeObject(t, s, "/projects/alpha/data/raw/deep.bin", randomBytes(8<<10, 55))
	writeObject(t, s, "/projects/beta/other.txt", []byte("should not appear"))

	dest := t.TempDir()
	report, err := s.Export(t.Context(), ExportOptions{
		Root: "/projects/alpha", Dest: dest, Verify: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, report.FilesWritten)
	assert.Empty(t, report.Failed)

	// The subtree is rebased on the destination, not reproduced from the root.
	for rel, want := range map[string]string{
		filepath.Join("readme.txt"):      "alpha readme",
		filepath.Join("data", "set.csv"): "1,2,3",
	} {
		got, rErr := os.ReadFile(filepath.Join(dest, rel))
		require.NoError(t, rErr, "%s should have been exported", rel)
		assert.Equal(t, want, string(got))
	}
	_, err = os.Stat(filepath.Join(dest, "data", "raw", "deep.bin"))
	assert.NoError(t, err, "nesting below the root is preserved")

	// Nothing outside the requested subtree came along.
	_, err = os.Stat(filepath.Join(dest, "other.txt"))
	assert.True(t, os.IsNotExist(err))
	entries, err := os.ReadDir(dest)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "only the subtree's own children are at the top level")
}

// TestExportDryRunWritesNothing lets an operator see the scope of a recovery
// before committing disk to it.
func TestExportDryRunWritesNothing(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.MkdirAll("/tree/sub"))
	writeObject(t, s, "/tree/a.txt", []byte("aaa"))
	writeObject(t, s, "/tree/sub/b.txt", []byte("bbbb"))

	dest := filepath.Join(t.TempDir(), "not-created-yet")
	report, err := s.Export(t.Context(), ExportOptions{Root: "/tree", Dest: dest, DryRun: true})
	require.NoError(t, err)
	assert.Equal(t, 2, report.FilesWritten)
	assert.Equal(t, int64(7), report.BytesWritten)

	_, err = os.Stat(dest)
	assert.True(t, os.IsNotExist(err), "a dry run creates nothing")
}

// TestAnUnsupportedFormatVersionIsRefused covers the version byte in the magic.
//
// The container is versioned so that changing the format later has somewhere to
// go.  What that costs is a file this build cannot read, and the only safe
// answer is to say so by number: the layout behind the magic is version-
// specific, so decoding on a guess would either fail with a cryptographic error
// naming nothing useful or parse into the wrong shape.
//
// The versions below stand for a byte below the supported one, one plausibly
// from a later release, and a byte that is simply garbage.  A file with an
// unrelated magic is checked alongside them, because "I do not read this
// version" and "this is not a snapshot" send an operator to different places
// and must not collapse into one message.
func TestAnUnsupportedFormatVersionIsRefused(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	encoded, err := generateBackupKey()
	require.NoError(t, err)
	key, err := ParseBackupKey(encoded)
	require.NoError(t, err)

	var current bytes.Buffer
	_, err = source.BackupEncrypted(&current, BackupKeys{BackupKey: key})
	require.NoError(t, err)
	require.Equal(t, backupMagic, string(current.Bytes()[:len(backupMagic)]),
		"a snapshot is written in the current format")
	require.Equal(t, byte(backupFormatVersion), backupMagic[len(backupMagicPrefix)],
		"the magic's version byte and backupFormatVersion must not drift apart")

	for _, version := range []byte{0x00, 0x05, 0xff} {
		t.Run(fmt.Sprintf("version %#02x", version), func(t *testing.T) {
			other := append([]byte(nil), current.Bytes()...)
			other[len(backupMagic)-1] = version

			target := newTestStore(t)
			rErr := target.Restore(bytes.NewReader(other), BackupKeys{BackupKey: key})
			require.Error(t, rErr, "a version this build does not read must not be decoded")
			// The error has to name both numbers: the operator's next move is to
			// find the build that wrote it, and "wrong key or altered file" would
			// send them after the wrong problem entirely.
			assert.Contains(t, rErr.Error(), fmt.Sprintf("version %d", version))
			assert.Contains(t, rErr.Error(),
				fmt.Sprintf("only version %d", backupFormatVersion))
		})
	}

	t.Run("a file that is not a snapshot at all says so instead", func(t *testing.T) {
		target := newTestStore(t)
		rErr := target.Restore(strings.NewReader("PELICAN-SOMETHING-ELSE\x00\x01 and a body"),
			BackupKeys{BackupKey: key})
		require.Error(t, rErr)
		assert.NotContains(t, rErr.Error(), "format version",
			"an unrelated file is not a version mismatch")
	})

	t.Run("the untouched archive still restores", func(t *testing.T) {
		target := newTestStore(t)
		require.NoError(t,
			target.Restore(bytes.NewReader(current.Bytes()), BackupKeys{BackupKey: key}))
	})
}

// ---------------------------------------------------------------------------
// Issuer-derived backup keys
// ---------------------------------------------------------------------------

// TestSnapshotOpensWithAnyIssuerKey is the property the multi-recipient
// envelope exists for.
//
// A snapshot is sealed to every issuer key that was current when it was
// written, so an operator holding any one of them can restore it. Without that,
// a snapshot would be tied to whichever key happened to be active at the
// moment, and an origin that rotates keys would accumulate archives that only
// one specific key opens.
func TestSnapshotOpensWithAnyIssuerKey(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data/sub"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))
	writeObject(t, source, "/data/sub/b.txt", []byte("beta"))

	all := testIssuerKeys(t, "kid-a", "kid-b", "kid-c")

	var sealed bytes.Buffer
	_, err := source.BackupEncrypted(&sealed, BackupKeys{IssuerKeys: all})
	require.NoError(t, err)

	assert.NotContains(t, sealed.String(), "a.txt",
		"an encrypted snapshot must not leak object paths")

	for keyID := range all {
		t.Run(keyID, func(t *testing.T) {
			only := map[string]jwk.Key{keyID: all[keyID]}
			target := newTestStore(t)
			require.NoError(t,
				target.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{IssuerKeys: only}),
				"any one of the keys it was sealed to must open it")

			entries, lErr := listNames(target, "/data")
			require.NoError(t, lErr)
			assert.Equal(t, []string{"a.txt", "sub"}, entries)
		})
	}
}

// TestSnapshotSurvivesAKeyRotation plays out the rotation an origin actually
// performs: a new key is added, then the old one is retired.
//
// An archive written while both were live must still open afterwards with the
// key that survived. An archive written before the new key existed opens only
// with the retired one -- and when that is gone, the error has to name the key
// IDs it was sealed to, because that is the only thing that tells an operator
// what to go and find.
func TestSnapshotSurvivesAKeyRotation(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	keys := testIssuerKeys(t, "old", "new")
	oldOnly := map[string]jwk.Key{"old": keys["old"]}
	newOnly := map[string]jwk.Key{"new": keys["new"]}

	// Written while only the old key existed.
	var beforeRotation bytes.Buffer
	_, err := source.BackupEncrypted(&beforeRotation, BackupKeys{IssuerKeys: oldOnly})
	require.NoError(t, err)

	// Written during the overlap, when both keys were current.
	var duringRotation bytes.Buffer
	_, err = source.BackupEncrypted(&duringRotation, BackupKeys{IssuerKeys: keys})
	require.NoError(t, err)

	t.Run("an overlapping archive opens with the key that survived", func(t *testing.T) {
		target := newTestStore(t)
		require.NoError(t, target.Restore(bytes.NewReader(duringRotation.Bytes()),
			BackupKeys{IssuerKeys: newOnly}))
		entries, lErr := listNames(target, "/data")
		require.NoError(t, lErr)
		assert.Equal(t, []string{"a.txt"}, entries)
	})

	t.Run("an archive sealed only to the retired key names it", func(t *testing.T) {
		target := newTestStore(t)
		rErr := target.Restore(bytes.NewReader(beforeRotation.Bytes()),
			BackupKeys{IssuerKeys: newOnly})
		require.Error(t, rErr)

		var noKey *ErrNoMatchingKey
		require.ErrorAs(t, rErr, &noKey)
		assert.Equal(t, []string{"old"}, noKey.SealedKeyIDs,
			"the error must name the key the archive needs")
		assert.Contains(t, rErr.Error(), "old")
	})

	t.Run("an archive sealed only to the retired key still opens with it", func(t *testing.T) {
		target := newTestStore(t)
		require.NoError(t, target.Restore(bytes.NewReader(beforeRotation.Bytes()),
			BackupKeys{IssuerKeys: oldOnly}),
			"retiring a key elsewhere does not invalidate the archives it sealed")
	})
}

// TestSnapshotOpensWithTheEscrowedKeyAlone is the disaster path: the origin is
// gone, its issuer keys with it, and all that is left is the key an operator
// printed with "metadata-backup-key" and filed away.
func TestSnapshotOpensWithTheEscrowedKeyAlone(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	issuerKeys := testIssuerKeys(t, "kid-a", "kid-b")

	var sealed bytes.Buffer
	_, err := source.BackupEncrypted(&sealed, BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)

	// What the operator saved: the derived private key, round-tripped through
	// the base64 form a key file holds.
	escrowed, err := DeriveBackupKey(issuerKeys["kid-b"])
	require.NoError(t, err)
	fromFile, err := ParseBackupKey(FormatBackupKey(escrowed))
	require.NoError(t, err)

	target := newTestStore(t)
	require.NoError(t,
		target.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{BackupKey: fromFile}),
		"the escrowed key alone must open the archive, with no issuer keys present")

	entries, err := listNames(target, "/data")
	require.NoError(t, err)
	assert.Equal(t, []string{"a.txt"}, entries)

	t.Run("an unrelated key does not", func(t *testing.T) {
		stranger, dErr := DeriveBackupKey(testIssuerKeys(t, "elsewhere")["elsewhere"])
		require.NoError(t, dErr)
		other := newTestStore(t)
		rErr := other.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{BackupKey: stranger})
		require.Error(t, rErr)
		var noKey *ErrNoMatchingKey
		assert.ErrorAs(t, rErr, &noKey)
	})
}

// TestBackupKeysAreDomainSeparated checks the pstore side of the property
// backup_keys exists to provide: the key that opens a pstore snapshot is not
// the key that opens a server database backup, so escrowing one does not hand
// over the other.
func TestBackupKeysAreDomainSeparated(t *testing.T) {
	issuerKey := testIssuerKeys(t, "kid")["kid"]

	pstoreKey, err := DeriveBackupKey(issuerKey)
	require.NoError(t, err)
	databaseKey, _, err := backup_keys.DeriveKeyPair(issuerKey, backup_keys.LabelDatabase)
	require.NoError(t, err)
	require.NotEqual(t, databaseKey[:], pstoreKey)

	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	var sealed bytes.Buffer
	_, err = source.BackupEncrypted(&sealed, BackupKeys{BackupKey: pstoreKey})
	require.NoError(t, err)

	target := newTestStore(t)
	rErr := target.Restore(bytes.NewReader(sealed.Bytes()),
		BackupKeys{BackupKey: databaseKey[:]})
	require.Error(t, rErr, "the database backup key must not open a pstore snapshot")
	var noKey *ErrNoMatchingKey
	assert.ErrorAs(t, rErr, &noKey)
}

// TestBackupKeyReplacesTheIssuerKeys pins the semantics of
// `metadata-backup --key-file`: the key it names is an override, not an
// addition.
//
// The distinction matters to the operator who passes it precisely because they
// want a backup that does not depend on this host's keys. If the issuer keys
// were also recipients, the archive would still be openable by whoever holds
// them, which is the property they were trying to avoid.
func TestBackupKeyReplacesTheIssuerKeys(t *testing.T) {
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	issuerKeys := testIssuerKeys(t, "kid-a")
	encoded, err := generateBackupKey()
	require.NoError(t, err)
	override, err := ParseBackupKey(encoded)
	require.NoError(t, err)

	var sealed bytes.Buffer
	_, err = source.BackupEncrypted(&sealed, BackupKeys{
		IssuerKeys: issuerKeys, BackupKey: override,
	})
	require.NoError(t, err)

	target := newTestStore(t)
	require.NoError(t,
		target.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{BackupKey: override}))

	other := newTestStore(t)
	rErr := other.Restore(bytes.NewReader(sealed.Bytes()), BackupKeys{IssuerKeys: issuerKeys})
	require.Error(t, rErr, "an override must exclude the issuer keys, not join them")
	var noKey *ErrNoMatchingKey
	require.ErrorAs(t, rErr, &noKey)
	require.Len(t, noKey.SealedKeyIDs, 1)
	assert.True(t, strings.HasPrefix(noKey.SealedKeyIDs[0], "backup-key:"),
		"an explicitly supplied key is identified by fingerprint, not by an issuer key ID")
}

// TestSnapshotRefusesToWriteWithoutKeys is the whole point of the rule: there
// is no configuration, and no combination of missing keys, that produces a
// cleartext dump of the namespace. A backup either encrypts or fails.
func TestSnapshotRefusesToWriteWithoutKeys(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.MkdirAll("/data"))
	writeObject(t, s, "/data/a.txt", []byte("alpha"))

	var out bytes.Buffer
	_, err := s.BackupEncrypted(&out, BackupKeys{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no keys are available")
	assert.NotContains(t, out.String(), "a.txt",
		"a refused backup must not have leaked the namespace on its way out")

	t.Run("the scheduled backup writes nothing either", func(t *testing.T) {
		dir := t.TempDir()
		require.Error(t, s.snapshotOnce(BackupConfig{Dir: dir, Interval: time.Hour}))

		entries, rErr := os.ReadDir(dir)
		require.NoError(t, rErr)
		for _, e := range entries {
			// The partial file is removed on failure; nothing may survive that
			// pruning would later count as a backup.
			assert.Fail(t, "a failed snapshot left a file behind", e.Name())
		}
	})
}

// TestEveryWrittenSnapshotIsSealed guards the absence of an unencrypted path.
//
// The scheduled backup is the one that runs unattended, so it is the one where
// a cleartext dump would go unnoticed. Every file it publishes must carry an
// encrypted magic and must not contain a path from the catalog.
func TestEveryWrittenSnapshotIsSealed(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.MkdirAll("/data"))
	writeObject(t, s, "/data/secret-name.txt", []byte("alpha"))

	dir := t.TempDir()
	require.NoError(t, s.snapshotOnce(BackupConfig{
		Dir:      dir,
		Interval: time.Hour,
		Keys:     BackupKeys{IssuerKeys: testIssuerKeys(t, "kid-a")},
	}))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	require.NoError(t, err)
	assert.True(t, looksEncrypted(body), "a published snapshot must be sealed")
	assert.NotContains(t, string(body), "secret-name.txt")
}

// ---------------------------------------------------------------------------
// The three-level key hierarchy
// ---------------------------------------------------------------------------

// backupHeaderLayout locates the parts of a header inside a sealed archive, so
// the tampering tests can edit one field without disturbing any other.
//
// It parses rather than assuming fixed offsets: the envelope is
// variable-length, and a test that hard-codes where the body starts would
// silently stop testing anything the first time a key ID changed length.
func backupHeaderLayout(t *testing.T, archive []byte) (saltAt, envelopeAt, bodyAt int) {
	t.Helper()
	require.Greater(t, len(archive), len(backupMagic)+backupSaltSize+2)
	require.Equal(t, backupMagic, string(archive[:len(backupMagic)]))

	saltAt = len(backupMagic)
	envelopeAt = saltAt + backupSaltSize
	at := envelopeAt
	count := int(binary.BigEndian.Uint16(archive[at : at+2]))
	require.Positive(t, count)
	at += 2
	for range count {
		for range 2 { // the key ID, then the sealed backup key
			require.Less(t, at+2, len(archive))
			n := int(binary.BigEndian.Uint16(archive[at : at+2]))
			at += 2 + n
		}
	}
	require.Less(t, at, len(archive))
	return saltAt, envelopeAt, at
}

// sealOneObject writes a small store's catalog out under keys, which is all
// most of the key-hierarchy tests need.
func sealOneObject(t *testing.T, keys BackupKeys) []byte {
	t.Helper()
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	var sealed bytes.Buffer
	_, err := source.BackupEncrypted(&sealed, keys)
	require.NoError(t, err)
	return sealed.Bytes()
}

// restoresCleanly reports whether an archive opens with keys and brings the
// namespace back.
func restoresCleanly(t *testing.T, archive []byte, keys BackupKeys) error {
	t.Helper()
	target := newTestStore(t)
	if err := target.Restore(bytes.NewReader(archive), keys); err != nil {
		return err
	}
	entries, err := listNames(target, "/data")
	require.NoError(t, err)
	assert.Equal(t, []string{"a.txt"}, entries)
	return nil
}

// TestThreeWaysToOpenASnapshot is the whole point of the hierarchy: a recovery
// happens on whatever the operator still has, and which of the three levels
// that is cannot be predicted when the backup is written.
//
// Each path is exercised on its own, with nothing else supplied -- in
// particular the per-file key opens the archive with no issuer key present
// anywhere, which is what makes it safe to hand a single archive to someone.
func TestThreeWaysToOpenASnapshot(t *testing.T) {
	issuerKeys := testIssuerKeys(t, "kid-a", "kid-b")
	archive := sealOneObject(t, BackupKeys{IssuerKeys: issuerKeys})

	t.Run("level 1: an issuer key", func(t *testing.T) {
		require.NoError(t, restoresCleanly(t, archive,
			BackupKeys{IssuerKeys: map[string]jwk.Key{"kid-b": issuerKeys["kid-b"]}}))
	})

	t.Run("level 2: the backup key alone", func(t *testing.T) {
		// Escrowed from an issuer key the reader no longer has, and
		// round-tripped through the base64 form a key file holds.
		escrowed, err := DeriveBackupKey(issuerKeys["kid-b"])
		require.NoError(t, err)
		fromFile, err := ParseBackupKey(FormatBackupKey(escrowed))
		require.NoError(t, err)

		require.NoError(t, restoresCleanly(t, archive, BackupKeys{BackupKey: fromFile}))
	})

	t.Run("level 3: this file's key alone", func(t *testing.T) {
		fileKey, err := DeriveFileKey(bytes.NewReader(archive),
			BackupKeys{IssuerKeys: issuerKeys})
		require.NoError(t, err)
		fromFile, err := ParseBackupKey(FormatBackupKey(fileKey))
		require.NoError(t, err)

		require.NoError(t, restoresCleanly(t, archive, BackupKeys{FileKey: fromFile}),
			"a per-file key must open its archive with no issuer key and no backup key")
	})

	t.Run("the three keys are all different", func(t *testing.T) {
		backupKey, err := DeriveBackupKey(issuerKeys["kid-a"])
		require.NoError(t, err)
		fileKey, err := DeriveFileKey(bytes.NewReader(archive),
			BackupKeys{IssuerKeys: issuerKeys})
		require.NoError(t, err)

		assert.NotEqual(t, backupKey, fileKey,
			"a per-file key that equalled the backup key would be no narrower than it")

		assert.NotContains(t, string(archive), string(backupKey),
			"the backup key travels sealed, never in the clear")
		assert.NotContains(t, string(archive), string(fileKey),
			"the per-file key is derived, never stored")
	})
}

// TestEveryArchiveHasItsOwnKey is what makes handing out one archive's key
// safe.
//
// Two snapshots taken back to back from the same store, under the same issuer
// keys, must be encrypted under different keys -- and neither key may open the
// other file. Without the per-archive salt both would derive the same key and
// giving away one would give away the series.
func TestEveryArchiveHasItsOwnKey(t *testing.T) {
	issuerKeys := testIssuerKeys(t, "kid-a")

	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	var first, second bytes.Buffer
	_, err := source.BackupEncrypted(&first, BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)
	_, err = source.BackupEncrypted(&second, BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)

	firstSalt, _, _ := backupHeaderLayout(t, first.Bytes())
	assert.NotEqual(t,
		first.Bytes()[firstSalt:firstSalt+backupSaltSize],
		second.Bytes()[firstSalt:firstSalt+backupSaltSize],
		"each snapshot draws its own salt")

	firstKey, err := DeriveFileKey(bytes.NewReader(first.Bytes()),
		BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)
	secondKey, err := DeriveFileKey(bytes.NewReader(second.Bytes()),
		BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)
	require.NotEqual(t, firstKey, secondKey, "two snapshots must not share a key")

	// The derivation is deterministic, so asking twice gives the same answer --
	// which is what lets the key be re-derived rather than stored.
	again, err := DeriveFileKey(bytes.NewReader(first.Bytes()),
		BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)
	assert.Equal(t, firstKey, again)

	require.NoError(t, restoresCleanly(t, first.Bytes(), BackupKeys{FileKey: firstKey}))
	require.NoError(t, restoresCleanly(t, second.Bytes(), BackupKeys{FileKey: secondKey}))

	crossed := restoresCleanly(t, second.Bytes(), BackupKeys{FileKey: firstKey})
	require.Error(t, crossed, "one archive's key must not open another")
	assert.Contains(t, crossed.Error(), "could not be decrypted")
}

// TestEscrowedBackupKeyDerivesAFileKey covers the recovery that has to work
// when nothing of the origin survives: an operator holding only the escrowed
// level-2 key, on a machine that has never held this origin's issuer keys, can
// still produce the key for one named archive and hand that on.
func TestEscrowedBackupKeyDerivesAFileKey(t *testing.T) {
	issuerKeys := testIssuerKeys(t, "kid-a", "kid-b")
	archive := sealOneObject(t, BackupKeys{IssuerKeys: issuerKeys})

	for _, keyID := range []string{"kid-a", "kid-b"} {
		t.Run("escrowed from "+keyID, func(t *testing.T) {
			// Any of the origin's backup keys works, not only the one the
			// archive happened to derive its own key from: the archive carries
			// that key sealed to every recipient.
			escrowed, err := DeriveBackupKey(issuerKeys[keyID])
			require.NoError(t, err)

			fileKey, err := DeriveFileKey(bytes.NewReader(archive),
				BackupKeys{BackupKey: escrowed})
			require.NoError(t, err)

			viaIssuer, err := DeriveFileKey(bytes.NewReader(archive),
				BackupKeys{IssuerKeys: issuerKeys})
			require.NoError(t, err)
			assert.Equal(t, viaIssuer, fileKey,
				"the escrowed key must reach the same per-file key the issuer keys do")

			require.NoError(t, restoresCleanly(t, archive, BackupKeys{FileKey: fileKey}))
		})
	}

	// The level-3 key really is HKDF over the level-2 key and the salt sitting
	// in the file, and nothing else -- checked against the primitive rather
	// than against the implementation that produced it, so a change to the
	// envelope cannot quietly change what "derived from the intermediate key
	// plus the salt in the backup" means.
	t.Run("it is HKDF over the backup key and the salt in the file", func(t *testing.T) {
		saltAt, _, _ := backupHeaderLayout(t, archive)
		salt := archive[saltAt : saltAt+backupSaltSize]

		// kid-a sorts first, so its backup key is the archive's own.
		canonical, err := DeriveBackupKey(issuerKeys["kid-a"])
		require.NoError(t, err)
		want, err := deriveFileKey(canonical, salt)
		require.NoError(t, err)

		got, err := DeriveFileKey(bytes.NewReader(archive), BackupKeys{IssuerKeys: issuerKeys})
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("a stranger's backup key derives nothing", func(t *testing.T) {
		stranger, err := DeriveBackupKey(testIssuerKeys(t, "elsewhere")["elsewhere"])
		require.NoError(t, err)
		_, err = DeriveFileKey(bytes.NewReader(archive), BackupKeys{BackupKey: stranger})
		require.Error(t, err)
		var noKey *ErrNoMatchingKey
		assert.ErrorAs(t, err, &noKey)
	})
}

// TestHeaderIsBoundToTheBody covers the AAD binding one field at a time.
//
// Every one of these edits leaves a structurally valid archive behind, so
// nothing but the authentication catches them. The salt and the sealed backup
// key are the two new fields, and both have to be covered or an attacker could
// point an archive at a key of their choosing or graft one archive's envelope
// onto another's body.
func TestHeaderIsBoundToTheBody(t *testing.T) {
	issuerKeys := testIssuerKeys(t, "kid-a")

	// Both archives cover the same store under the same keys, so their headers
	// are laid out identically -- same salt length, same recipients, same key
	// IDs -- and every field below is byte-for-byte substitutable between them.
	// Only the cryptography can tell them apart. (The bodies differ in length by
	// a byte or two, because a catalog carries commit timestamps and compresses
	// slightly differently each pass; the body splice therefore replaces the
	// whole tail rather than an equal-length window.)
	source := newTestStore(t)
	require.NoError(t, source.MkdirAll("/data"))
	writeObject(t, source, "/data/a.txt", []byte("alpha"))

	var a, b bytes.Buffer
	_, err := source.BackupEncrypted(&a, BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)
	_, err = source.BackupEncrypted(&b, BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)

	saltAt, envelopeAt, bodyAt := backupHeaderLayout(t, a.Bytes())
	otherSaltAt, otherEnvelopeAt, otherBodyAt := backupHeaderLayout(t, b.Bytes())
	require.Equal(t, []int{saltAt, envelopeAt, bodyAt},
		[]int{otherSaltAt, otherEnvelopeAt, otherBodyAt},
		"the two headers must be the same shape for the splices to mean anything")

	for _, tc := range []struct {
		name string
		from int
		// to is exclusive; -1 splices everything from `from` to the end, which
		// is how the body is swapped despite the two differing in length.
		to    int
		about string
	}{
		{"the salt", saltAt, envelopeAt,
			"swapping the salt would silently change which key the archive claims to want"},
		{"the sealed backup key", envelopeAt, bodyAt,
			"the envelope must not be liftable from another archive"},
		{"the body", bodyAt, -1,
			"chunks must not be spliceable between archives"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var spliced []byte
			if tc.to < 0 {
				spliced = append(append([]byte(nil), a.Bytes()[:tc.from]...),
					b.Bytes()[tc.from:]...)
			} else {
				spliced = append([]byte(nil), a.Bytes()...)
				copy(spliced[tc.from:tc.to], b.Bytes()[tc.from:tc.to])
			}
			require.NotEqual(t, a.Bytes(), spliced, "the splice changed nothing")

			rErr := restoresCleanly(t, spliced, BackupKeys{IssuerKeys: issuerKeys})
			require.Error(t, rErr, tc.about)
		})
	}

	t.Run("the untouched archive still restores", func(t *testing.T) {
		require.NoError(t, restoresCleanly(t, a.Bytes(), BackupKeys{IssuerKeys: issuerKeys}))
	})
}

// TestAPerFileKeyCannotWriteASnapshot keeps the level-3 key one-directional.
//
// It is the key that gets handed out, so it must not be usable to produce a new
// archive that would then look like one the origin wrote.
func TestAPerFileKeyCannotWriteASnapshot(t *testing.T) {
	issuerKeys := testIssuerKeys(t, "kid-a")
	archive := sealOneObject(t, BackupKeys{IssuerKeys: issuerKeys})
	fileKey, err := DeriveFileKey(bytes.NewReader(archive), BackupKeys{IssuerKeys: issuerKeys})
	require.NoError(t, err)

	s := newTestStore(t)
	require.NoError(t, s.MkdirAll("/data"))
	writeObject(t, s, "/data/secret-name.txt", []byte("alpha"))

	var out bytes.Buffer
	_, err = s.BackupEncrypted(&out, BackupKeys{FileKey: fileKey})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot seal a new one")
	assert.NotContains(t, out.String(), "secret-name.txt",
		"a refused backup must not have leaked the namespace on its way out")
}

// listNames returns the direct children of a directory, for the many
// assertions that only care about what came back.
func listNames(s *Store, dir string) ([]string, error) {
	entries, _, err := s.List(dir, "", 0)
	if err != nil {
		return nil, err
	}
	return entryNames(entries), nil
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

// fakeTimer stands in for the timer a scheduled loop waits on, so a test
// decides exactly when a run starts.
//
// Everything is unbuffered on purpose.  A real time.Timer's channel holds one
// pending fire, which is precisely the behavior these tests exist to rule out;
// a fake that buffered would reproduce the bug it is meant to detect.  With
// unbuffered channels, a fire that nobody is waiting for blocks instead of
// queueing, and the test says so by name rather than hanging silently.
type fakeTimer struct {
	// armed receives the duration passed to the constructor and to every
	// Reset, so a test can see *when* the next wait was set up relative to the
	// work finishing -- which is the whole property under test.
	armed chan time.Duration
	fires chan time.Time
	// stopped is closed when the loop releases the timer, which is how a test
	// tells a clean shutdown from a leak.
	stopped chan struct{}
}

func newFakeTimer() *fakeTimer {
	return &fakeTimer{
		armed:   make(chan time.Duration, 8),
		fires:   make(chan time.Time),
		stopped: make(chan struct{}),
	}
}

// new is the schedule's timer factory: the loop asks for one timer and keeps
// resetting it.
func (f *fakeTimer) new(d time.Duration) periodicTimer {
	f.armed <- d
	return f
}

func (f *fakeTimer) Chan() <-chan time.Time { return f.fires }
func (f *fakeTimer) Reset(d time.Duration)  { f.armed <- d }
func (f *fakeTimer) Stop()                  { close(f.stopped) }

// fire releases one run and blocks until the loop takes it, so the test always
// knows the loop was waiting rather than busy.
func (f *fakeTimer) fire(t *testing.T) {
	t.Helper()
	select {
	case f.fires <- time.Now():
	case <-time.After(testScheduleTimeout):
		t.Fatal("the loop was not waiting on its timer")
	}
}

// armedFor returns the duration the next wait was set to, failing rather than
// hanging if the loop never armed one.
func (f *fakeTimer) armedFor(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-f.armed:
		return d
	case <-time.After(testScheduleTimeout):
		t.Fatal("the loop never armed its timer")
		return 0
	}
}

// testScheduleTimeout bounds the waits above.  It is a failure deadline, not a
// synchronization delay: every assertion below completes as soon as the loop
// reaches the point it is waiting for, and this is only how long a test is
// willing to wait before declaring the loop stuck.
const testScheduleTimeout = 30 * time.Second

// TestScheduledRunsAreSpacedFromTheEndOfTheLastRun is the property a ticker did
// not have.
//
// A ticker fires on a fixed cadence regardless of how long the body takes, so a
// pass that overruns its interval finds a tick already waiting when it finishes
// and starts again immediately.  With a 24-hour interval and a 24-hour data
// scan, an origin scans continuously -- and nothing in the configuration says
// so.  What is asserted here is the mechanism that fixes it: the next wait is
// armed only *after* the work returns, so an overrun can never produce
// back-to-back runs.
func TestScheduledRunsAreSpacedFromTheEndOfTheLastRun(t *testing.T) {
	timer := newFakeTimer()
	started := make(chan struct{})
	finish := make(chan struct{})
	done := make(chan struct{})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		defer close(done)
		runPeriodically(ctx, time.Hour, schedule{newTimer: timer.new, now: time.Now},
			"test pass", func() {
				started <- struct{}{}
				<-finish
			})
	}()

	// Nothing runs until the first wait elapses.
	assert.Equal(t, time.Hour, timer.armedFor(t), "the loop waits before its first run")
	select {
	case <-started:
		t.Fatal("a run began before the interval elapsed")
	default:
	}

	// One fire starts one run, which then overruns: while it is in flight the
	// timer has not been re-armed, so there is nowhere for a second fire to
	// come from. A ticker would have had one waiting.
	timer.fire(t)
	<-started
	select {
	case d := <-timer.armed:
		t.Fatalf("the next run was scheduled %s into the previous one, so an overrunning "+
			"pass would be followed immediately by another", d)
	default:
	}

	// Only once the run finishes is the next interval armed.
	finish <- struct{}{}
	assert.Equal(t, time.Hour, timer.armedFor(t),
		"the gap is measured from the end of the run, not from its start")

	// And that next interval really does gate the next run.
	timer.fire(t)
	<-started
	finish <- struct{}{}
	assert.Equal(t, time.Hour, timer.armedFor(t))

	// Cancellation is prompt and releases the timer: the loop is waiting on the
	// timer it just armed, and must leave through the context instead.
	cancel()
	select {
	case <-done:
	case <-time.After(testScheduleTimeout):
		t.Fatal("the loop did not return when its context was cancelled")
	}
	select {
	case <-timer.stopped:
	default:
		t.Fatal("the loop returned without releasing its timer")
	}
}

// TestAnOverrunningRunIsReported covers the operator's only signal that the
// configured interval is faster than the store's size allows.
//
// The run still completes and the next one is still scheduled -- the loop does
// not intervene -- so a log line is the whole of the feedback, and it has to
// say what the consequence is rather than only reporting two durations.
func TestAnOverrunningRunIsReported(t *testing.T) {
	hook := test.NewGlobal()
	t.Cleanup(hook.Reset)

	// A clock the test advances itself: the loop reads it once before the work
	// and once after, so handing back two readings an hour apart makes a
	// one-minute interval overrun without anything taking any time at all.
	readings := []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
	}
	now := func() time.Time {
		at := readings[0]
		if len(readings) > 1 {
			readings = readings[1:]
		}
		return at
	}

	timer := newFakeTimer()
	ran := make(chan struct{})
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		defer close(done)
		runPeriodically(ctx, time.Minute, schedule{newTimer: timer.new, now: now},
			"data scan", func() { ran <- struct{}{} })
	}()

	require.Equal(t, time.Minute, timer.armedFor(t))
	timer.fire(t)
	<-ran
	require.Equal(t, time.Minute, timer.armedFor(t),
		"an overrun does not stop the loop from scheduling the next run")

	cancel()
	<-done

	var overrun *logrus.Entry
	for _, entry := range hook.AllEntries() {
		if strings.Contains(entry.Message, "took 1h0m0s") {
			overrun = entry
		}
	}
	require.NotNil(t, overrun, "an overrunning run must be reported")
	assert.Equal(t, logrus.WarnLevel, overrun.Level)
	assert.Contains(t, overrun.Message, "data scan", "the message names the pass that overran")
	assert.Contains(t, overrun.Message, "longer than its configured interval of 1m0s")
	assert.Contains(t, overrun.Message, "Lengthen the interval",
		"the message has to say what to do about it, not only that it happened")
}

// TestARunThatFitsIsNotReported keeps the warning above meaningful: an origin
// whose checks comfortably fit their interval must not be told anything.
func TestARunThatFitsIsNotReported(t *testing.T) {
	hook := test.NewGlobal()
	t.Cleanup(hook.Reset)

	timer := newFakeTimer()
	ran := make(chan struct{})
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		defer close(done)
		runPeriodically(ctx, time.Hour, schedule{newTimer: timer.new, now: time.Now},
			"index check", func() { ran <- struct{}{} })
	}()

	require.Equal(t, time.Hour, timer.armedFor(t))
	timer.fire(t)
	<-ran
	require.Equal(t, time.Hour, timer.armedFor(t))

	cancel()
	<-done

	for _, entry := range hook.AllEntries() {
		assert.NotContains(t, entry.Message, "longer than its configured interval")
	}
}

// TestScheduledBackupsSnapshotAtStartupThenOnTheInterval pins the two halves of
// the backup loop's schedule together.
//
// The startup snapshot is what catches an unwritable backup directory now
// rather than an interval from now, and what keeps a store that dies in its
// first hour from having no metadata backup at all. The interval after it is a
// gap, not a cadence: a snapshot of a large catalog is not instant, and the
// default is six hours.
func TestScheduledBackupsSnapshotAtStartupThenOnTheInterval(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.MkdirAll("/data"))
	writeObject(t, s, "/data/a.txt", []byte("alpha"))

	dir := t.TempDir()
	cfg := BackupConfig{Dir: dir, Interval: 6 * time.Hour, Keys: testBackupKeys(t)}

	timer := newFakeTimer()
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		defer close(done)
		s.runBackupLoop(ctx, cfg, schedule{newTimer: timer.new, now: time.Now})
	}()

	// The loop reaching its first wait means the startup snapshot has already
	// been taken.
	require.Equal(t, 6*time.Hour, timer.armedFor(t))
	require.Len(t, publishedSnapshots(t, dir), 1,
		"a snapshot is taken at startup, not an interval later")

	// Each subsequent interval takes another, and the next wait is armed only
	// once that one is on disk.
	//
	// The store gains an object first, so what proves the second pass ran is
	// the published snapshot's contents rather than a file count: snapshot
	// names carry a one-second timestamp, and two passes inside the same second
	// -- which is what driving the schedule by hand produces -- land on the
	// same name.
	writeObject(t, s, "/data/b.txt", []byte("beta"))
	timer.fire(t)
	require.Equal(t, 6*time.Hour, timer.armedFor(t))

	published := publishedSnapshots(t, dir)
	require.NotEmpty(t, published)
	f, err := os.Open(filepath.Join(dir, published[len(published)-1]))
	require.NoError(t, err)
	defer f.Close()

	target := newTestStore(t)
	require.NoError(t, target.Restore(f, cfg.Keys))
	names, err := listNames(target, "/data")
	require.NoError(t, err)
	assert.Equal(t, []string{"a.txt", "b.txt"}, names,
		"the snapshot published on the interval covers what the store held at that point")

	cancel()
	select {
	case <-done:
	case <-time.After(testScheduleTimeout):
		t.Fatal("the backup loop did not return when its context was cancelled")
	}
}

// publishedSnapshots lists the complete snapshots in a backup directory,
// ignoring the .partial files a pass in flight may have left.
func publishedSnapshots(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), metadataBackupPrefix) && strings.HasSuffix(e.Name(), ".pmb") {
			names = append(names, e.Name())
		}
	}
	return names
}
