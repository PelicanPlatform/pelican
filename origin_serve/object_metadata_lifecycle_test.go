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
	"os"
	"testing"
	"time"

	"github.com/spf13/afero"
)

// buildTrackingFS spins up the layer stack used by a TrackAccess-on
// namespace and returns the wrapped aferoFileSystem, the DAO, and
// the underlying memfs so tests can simulate out-of-band changes
// via memfs primitives.
func buildTrackingFS(t *testing.T, namespace string) (*aferoFileSystem, *objectMetadataDAO, afero.Fs, func()) {
	t.Helper()
	mem := afero.NewMemMapFs()
	autoFs := newAutoCreateDirFs(mem)

	db := newObjectMetadataTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	b := newSQLiteBatcher(ctx, db, 64, 20*time.Millisecond)
	dao := newObjectMetadataDAO(db, b)

	afs := newAferoFileSystem(autoFs, "", nil)
	afs.setObservation(&observationConfig{
		namespace:  namespace,
		trackExtra: false,
		dao:        dao,
		cache:      newObservationCache(64),
	})

	cleanup := func() {
		cancel()
		b.Stop()
	}
	return afs, dao, mem, cleanup
}

// flush forces a best-effort write to land before assertions read
// the table.
func flushBatcher(t *testing.T, dao *objectMetadataDAO) {
	t.Helper()
	if err := dao.batcher.EnqueueDurable(context.Background(), "SELECT 1"); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// TestLifecycle_CommitObserveModifyDelete drives the full
// caller-driven + observation-driven event sequence end-to-end:
//
//  1. RecordCommit (via the close hook helper) lands a fresh commit.
//  2. A subsequent Stat with the same etag is a no-op (cache hit).
//  3. Out-of-band mtime change via mem.Chtimes flips the synthesised
//     ETag; the next Stat records external_modify.
//  4. Out-of-band remove via mem.Remove makes the next Stat return
//     ENOENT; observation records external_delete.
//
// The history table should record exactly that sequence.
func TestLifecycle_CommitObserveModifyDelete(t *testing.T) {
	afs, dao, mem, cleanup := buildTrackingFS(t, "/exp")
	defer cleanup()
	ctx := context.Background()

	// Plant the file directly (we're not testing PUT here, just the
	// observation cycle once the file exists).
	if err := afero.WriteFile(mem, "/data/x.bin", []byte("hello"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// And emit a Commit event as if POSC just finalized it.
	info, _ := mem.Stat("/data/x.bin")
	wrapped := withBackendETag(info)
	commitHook := RecordCommitCloseHook(dao, "/exp", false)
	if err := commitHook(ctx, "/data/x.bin", wrapped); err != nil {
		t.Fatalf("commit hook: %v", err)
	}
	flushBatcher(t, dao)

	live, _ := dao.LookupLive(ctx, "/exp", "/exp/data/x.bin")
	if live == nil {
		t.Fatal("commit did not create a live row")
	}
	originalETag := live.ETag

	// Stat with the same etag — cache hit; no new history rows.
	if _, err := afs.Stat(ctx, "/data/x.bin"); err != nil {
		t.Fatalf("stat 1: %v", err)
	}
	flushBatcher(t, dao)
	rows, _ := dao.ListHistory(ctx, "/exp", "/exp/data/x.bin", 100)
	commitCount := countEvents(rows, ObjectEventCommit)
	modifyCount := countEvents(rows, ObjectEventExternalModify)
	if commitCount != 1 || modifyCount != 0 {
		t.Fatalf("after Stat-no-change: commit=%d modify=%d (want 1,0)", commitCount, modifyCount)
	}

	// External modify: bump mtime → synthesised etag changes.
	newTime := time.Now().Add(time.Hour)
	if err := mem.Chtimes("/data/x.bin", newTime, newTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if _, err := afs.Stat(ctx, "/data/x.bin"); err != nil {
		t.Fatalf("stat 2: %v", err)
	}
	flushBatcher(t, dao)
	rows, _ = dao.ListHistory(ctx, "/exp", "/exp/data/x.bin", 100)
	if got := countEvents(rows, ObjectEventExternalModify); got != 1 {
		t.Fatalf("after out-of-band modify: external_modify=%d (want 1)", got)
	}
	live, _ = dao.LookupLive(ctx, "/exp", "/exp/data/x.bin")
	if live.ETag == originalETag {
		t.Fatalf("live etag did not advance after external modify")
	}

	// External delete: remove the file out-of-band; next Stat
	// returns ENOENT and observation records the delete.
	if err := mem.Remove("/data/x.bin"); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if _, err := afs.Stat(ctx, "/data/x.bin"); err == nil {
		t.Fatal("expected ENOENT from Stat after remove")
	}
	flushBatcher(t, dao)
	live, _ = dao.LookupLive(ctx, "/exp", "/exp/data/x.bin")
	if live != nil {
		t.Fatalf("live row should be gone after external_delete; got %#v", live)
	}
	rows, _ = dao.ListHistory(ctx, "/exp", "/exp/data/x.bin", 100)
	if got := countEvents(rows, ObjectEventExternalDelete); got != 1 {
		t.Fatalf("after out-of-band delete: external_delete=%d (want 1)", got)
	}
}

// TestLifecycle_ListingModeSkipsObservation simulates the listing
// path: a Stat from a context with the listing-mode flag must not
// touch the DB at all (cache miss + no row → would normally create
// rows; listing mode short-circuits).
func TestLifecycle_ListingModeSkipsObservation(t *testing.T) {
	afs, dao, mem, cleanup := buildTrackingFS(t, "/exp")
	defer cleanup()
	ctx := withListingMode(context.Background())

	if err := afero.WriteFile(mem, "/legacy.bin", []byte("legacy"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for i := 0; i < 50; i++ {
		if _, err := afs.Stat(ctx, "/legacy.bin"); err != nil {
			t.Fatalf("stat: %v", err)
		}
	}
	flushBatcher(t, dao)

	live, _ := dao.LookupLive(ctx, "/exp", "/exp/legacy.bin")
	if live != nil {
		t.Fatalf("listing-mode Stat created a live row: %#v", live)
	}
	rows, _ := dao.ListHistory(ctx, "/exp", "/exp/legacy.bin", 100)
	if len(rows) != 0 {
		t.Fatalf("listing-mode Stat created history rows: %d", len(rows))
	}
}

// TestLifecycle_RecordRenameAndDelete drives RecordRename then
// RecordDelete via the aferoFileSystem Rename / RemoveAll paths and
// asserts the history reflects the lifecycle.
func TestLifecycle_RecordRenameAndDelete(t *testing.T) {
	afs, dao, mem, cleanup := buildTrackingFS(t, "/exp")
	defer cleanup()
	ctx := context.Background()

	// Seed via RecordCommit hook so we have a live row. File on
	// memfs is at the export-relative path (that's what production
	// webdav.Handler hands to fs.OpenFile after Prefix-stripping).
	if err := afero.WriteFile(mem, "/orig.bin", []byte("data"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	info, _ := mem.Stat("/orig.bin")
	if err := RecordCommitCloseHook(dao, "/exp", false)(ctx, "/orig.bin", withBackendETag(info)); err != nil {
		t.Fatalf("commit: %v", err)
	}
	flushBatcher(t, dao)

	if err := afs.Rename(ctx, "/orig.bin", "/renamed.bin"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	flushBatcher(t, dao)

	live, _ := dao.LookupLive(ctx, "/exp", "/exp/renamed.bin")
	if live == nil {
		t.Fatal("renamed path missing from live state")
	}
	if old, _ := dao.LookupLive(ctx, "/exp", "/exp/orig.bin"); old != nil {
		t.Fatalf("old path still in live state after rename: %#v", old)
	}
	// History on the old path should carry a 'rename' event.
	oldRows, _ := dao.ListHistory(ctx, "/exp", "/exp/orig.bin", 100)
	if got := countEvents(oldRows, ObjectEventRename); got != 1 {
		t.Fatalf("rename history on old path = %d, want 1", got)
	}

	if err := afs.RemoveAll(ctx, "/renamed.bin"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	flushBatcher(t, dao)
	if live, _ := dao.LookupLive(ctx, "/exp", "/exp/renamed.bin"); live != nil {
		t.Fatalf("live row survived RemoveAll: %#v", live)
	}
	newRows, _ := dao.ListHistory(ctx, "/exp", "/exp/renamed.bin", 100)
	if got := countEvents(newRows, ObjectEventDelete); got != 1 {
		t.Fatalf("delete history on renamed path = %d, want 1", got)
	}
}

func countEvents(rows []*ObjectMetadataHistoryRow, want ObjectMetadataEvent) int {
	n := 0
	for _, r := range rows {
		if r.EventType == string(want) {
			n++
		}
	}
	return n
}

// Compile-time sanity that the helpers exist (the test functions
// above already use them, but this keeps the link tight).
var (
	_ = context.Background
	_ = os.FileInfo(nil)
)
