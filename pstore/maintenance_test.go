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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
)

// buildStoreThenReopenReadOnly populates a store, closes it, and reopens it
// the way the CLI does.
func buildStoreThenReopenReadOnly(t *testing.T) *Store {
	t.Helper()
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	egrp, _ := errgroup.WithContext(ctx)
	dir := t.TempDir()

	s, err := Open(ctx, egrp, Config{BaseDir: dir})
	require.NoError(t, err)
	require.NoError(t, s.MkdirAll("/data/sub"))
	writeObject(t, s, "/data/a.txt", []byte("alpha"))
	writeObject(t, s, "/data/sub/b.bin", randomBytes(4096, 21))
	require.NoError(t, s.Close())

	ro, err := OpenMaintenance(t.Context(), dir, false)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, ro.Close()) })
	return ro
}

func TestOpenMaintenanceReads(t *testing.T) {
	ro := buildStoreThenReopenReadOnly(t)
	assert.True(t, ro.ReadOnly())

	entries, _, err := ro.List("/data", "", 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"a.txt", "sub"}, entryNames(entries))

	d, err := ro.Stat("/data/a.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(5), d.Size)

	got, err := ro.ReadAll("/data/a.txt")
	require.NoError(t, err)
	assert.Equal(t, "alpha", string(got))

	digests, err := ro.Digests("/data/a.txt")
	require.NoError(t, err)
	assert.NotEmpty(t, digests, "checksums recorded at ingest survive a reopen")
}

// TestOpenMaintenanceRefusesWrites checks the guard on every mutating entry
// point, so a CLI mistake fails clearly rather than deep inside BadgerDB.
func TestOpenMaintenanceRefusesWrites(t *testing.T) {
	ro := buildStoreThenReopenReadOnly(t)

	assert.ErrorIs(t, ro.Mkdir("/nope"), ErrNotSupported)
	assert.ErrorIs(t, ro.MkdirAll("/nope/deep"), ErrNotSupported)
	assert.ErrorIs(t, ro.Remove("/data/a.txt"), ErrNotSupported)
	assert.ErrorIs(t, ro.RemoveAll("/data"), ErrNotSupported)
	assert.ErrorIs(t, ro.Rename("/data/a.txt", "/data/c.txt"), ErrNotSupported)

	_, err := ro.Create("/data/new.txt")
	assert.ErrorIs(t, err, ErrNotSupported)

	// The store is untouched.
	_, err = ro.Stat("/data/a.txt")
	assert.NoError(t, err)
}

// TestOpenMaintenanceFsckIsUsable is the CLI's main job: report on a stopped
// store without changing it.
func TestOpenMaintenanceFsckIsUsable(t *testing.T) {
	ro := buildStoreThenReopenReadOnly(t)

	report, err := ro.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.True(t, report.Healthy(), "a normally-built store checks out clean: %+v", report)
	assert.Equal(t, 4, report.EntriesScanned)
}

// TestOpenMaintenanceRejectsACacheDatabase keeps the CLI from interpreting a
// cache's records as pstore ones.  Read-only mode cannot write a marker, so a
// database without one is refused rather than adopted.
func TestOpenMaintenanceRejectsACacheDatabase(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dir := t.TempDir()

	db, err := local_cache.NewCacheDB(ctx, dir)
	require.NoError(t, err)
	require.NoError(t, db.EnsureStoreMode(local_cache.StoreModeCache))
	require.NoError(t, db.Close())

	_, err = OpenMaintenance(t.Context(), dir, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache")
}

// TestOpenMaintenanceRefusesRepairWithoutWrites is the guard that must not be
// the directory lock.
//
// A repair pass unlinks entries and queues object versions for reclamation.
// Today the only thing stopping it from running against a live store is
// BadgerDB refusing to open the directory twice -- which is a property of how
// the CLI happens to get in, not of fsck. Asserting the refusal here pins it
// to fsck itself, so that a future live-repair path has to make a deliberate
// decision rather than inheriting one.
func TestOpenMaintenanceRefusesRepairWithoutWrites(t *testing.T) {
	ro := buildStoreThenReopenReadOnly(t)

	_, err := ro.Fsck(t.Context(), true)
	require.ErrorIs(t, err, ErrNotSupported)

	// The store is untouched and still reportable.
	report, err := ro.Fsck(t.Context(), false)
	require.NoError(t, err)
	assert.True(t, report.Healthy(), "%+v", report)
	assert.Equal(t, 4, report.EntriesScanned)
}

// TestOpenMaintenanceFsckScansInBoundedBatches checks the pass still sees
// every entry once its scans are split across transactions.
//
// The batching exists so that an hourly check over millions of objects does
// not pin BadgerDB's read watermark for its whole duration; an off-by-one in
// the resume key would either skip entries or deliver them twice, and both
// are silent.
func TestOpenMaintenanceFsckScansInBoundedBatches(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Mkdir("/many"))

	// More entries than one batch, so the resume path is exercised rather
	// than just the first pass.
	const count = fsckBatchSize + 37
	for i := range count {
		writeObject(t, s, fmt.Sprintf("/many/obj-%05d", i), []byte("x"))
	}

	report, err := s.FsckWith(t.Context(), FsckOptions{MinAge: FsckNoGracePeriod})
	require.NoError(t, err)
	assert.Equal(t, count+1, report.EntriesScanned,
		"every entry is delivered exactly once across batch boundaries")
	assert.Equal(t, 1, report.DirectoriesScanned)
	assert.True(t, report.Healthy(), "%+v", report)
}
