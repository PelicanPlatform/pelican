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

// File object_metadata_p1_fixes_test.go contains the regression
// tests for the three P1 bugs surfaced during pre-PR review:
//
//   P1.1 — handleENOENT must fire external_delete even when the
//          observation cache is cold (the DAO row alone is enough
//          evidence that the object existed and is now gone).
//
//   P1.2 — sqliteBatcher.Stop() must not lose ops to a shutdown
//          race. Every op a caller successfully began enqueueing
//          either lands in the final flush OR fails with a
//          caller-side error; no op gets stranded.
//
//   P1.3 — objectMetadataPruner must hard-delete soft-deleted
//          live rows older than retention, not just history rows.
//          Without this, busy-delete namespaces accumulate
//          `object_metadata` rows forever.

package origin_serve

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/server_utils"
)

// ============================================================
// P1.1 — cold-cache external_delete
// ============================================================

// TestExternalDelete_FiresWhenCacheCold seeds a live row in the
// DAO directly (no cache warming), then drives an ENOENT through
// handleENOENT. The fix path: cache miss → LookupLive → DAO row
// present → RecordExternalDelete. Before the fix, the function
// returned early on cache miss and the DAO row was never
// soft-deleted.
func TestExternalDelete_FiresWhenCacheCold(t *testing.T) {
	d, _, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	// Plant a live row directly. Cache stays empty.
	if err := d.RecordCommit(ctx, ObjectMetadataEventInput{
		Namespace: "/x", ObjectPath: "/x/cold.bin", Size: 7,
		ETag: `"e"`, EtagSource: EtagSourceBackend, BackendMtime: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := d.batcher.FlushNow(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	live, _ := d.LookupLive(ctx, "/x", "/x/cold.bin")
	if live == nil {
		t.Fatal("test setup error: live row missing")
	}

	obs := &observationConfig{
		namespace: "/x",
		dao:       d,
		// Empty cache — this is the whole point. The fix must
		// not require a cache hit to fire external_delete.
		cache: newObservationCache(16),
	}

	obs.handleENOENT(ctx, "/x/cold.bin")
	if err := d.batcher.FlushNow(ctx); err != nil {
		t.Fatalf("flush 2: %v", err)
	}

	if got, _ := d.LookupLive(ctx, "/x", "/x/cold.bin"); got != nil {
		t.Fatalf("live row survived external_delete on cold cache: %#v", got)
	}
	hist, _ := d.ListHistory(ctx, "/x", "/x/cold.bin", 10)
	if countEvents(hist, ObjectEventExternalDelete) != 1 {
		t.Fatalf("external_delete history rows = %d (want 1)", countEvents(hist, ObjectEventExternalDelete))
	}
}

// TestExternalDelete_ColdCacheTruePositiveOnly — when the cache is
// cold AND there's no DAO row, ENOENT is a true negative (a typo'd
// GET). The fix must NOT enqueue spurious external_delete events
// in that case.
func TestExternalDelete_ColdCacheTruePositiveOnly(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	obs := &observationConfig{
		namespace: "/x",
		dao:       d,
		cache:     newObservationCache(16),
	}

	obs.handleENOENT(ctx, "/x/never-existed.bin")
	_ = d.batcher.FlushNow(ctx)

	var n int64
	db.Model(&ObjectMetadataHistoryRow{}).Where("event_type = ?", "external_delete").Count(&n)
	if n != 0 {
		t.Fatalf("spurious external_delete event fired on a path we never saw: %d", n)
	}
}

// ============================================================
// P1.2 — Stop() shutdown race
// ============================================================

// TestBatcher_StopNoLostOpsUnderConcurrency hammers the batcher
// with concurrent durable enqueues and calls Stop in the middle.
// Every Enqueue call must return either (a) a successful nil (op
// committed in the final flush) or (b) an explicit error
// ("already closed", ctx-cancelled, or commit error). It must NOT
// hang or panic, which the pre-fix code could do via the
// "op-stranded-after-flusher-exited" race.
func TestBatcher_StopNoLostOpsUnderConcurrency(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 8, 20*time.Millisecond)

	const senders = 50
	var (
		wg           sync.WaitGroup
		ok           atomic.Int64
		failed       atomic.Int64
		hangBudget   = 5 * time.Second
		hangDeadline = time.After(hangBudget)
	)
	wg.Add(senders)
	for i := 0; i < senders; i++ {
		go func(i int) {
			defer wg.Done()
			err := b.EnqueueDurable(ctx,
				"INSERT INTO kv(key,value) VALUES(?,?)",
				fmt.Sprintf("k-%d", i), "v")
			if err == nil {
				ok.Add(1)
			} else {
				failed.Add(1)
			}
		}(i)
	}

	// Wedge in a Stop while senders are running.
	time.Sleep(2 * time.Millisecond)
	b.Stop()

	// All senders must return.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-hangDeadline:
		t.Fatalf("senders hung after Stop; ok=%d failed=%d (sum %d / %d total)",
			ok.Load(), failed.Load(), ok.Load()+failed.Load(), senders)
	}

	total := ok.Load() + failed.Load()
	if total != senders {
		t.Fatalf("total accounted = %d, want %d", total, senders)
	}
	// At least *some* committed — the Stop happened after a
	// 2ms head start, so it'd be very surprising for zero to land.
	if ok.Load() == 0 {
		t.Log("warning: zero ops committed — possible Stop timing flake, " +
			"but no op was lost (each returned cleanly)")
	}

	// Spot-check: the rows that ok'd are actually in the DB.
	var inDB int64
	db.Raw("SELECT COUNT(*) FROM kv").Scan(&inDB)
	if inDB != ok.Load() {
		t.Fatalf("ok=%d but DB has %d rows — op accounting drifted", ok.Load(), inDB)
	}
}

// TestBatcher_StopReturnsPromptly catches a different shutdown bug:
// if enqueueWG.Wait() were called before all in-flight senders
// could complete their sends (eg if a single durable sender were
// stuck on op.done because the flusher exited prematurely), Stop
// would hang. We bound Stop's wall-clock to assert promptness.
func TestBatcher_StopReturnsPromptly(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 4, 50*time.Millisecond)

	// Issue a few durable enqueues so there are pending ops at
	// the moment of Stop.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = b.EnqueueDurable(ctx, "INSERT INTO kv(key,value) VALUES(?,?)",
				fmt.Sprintf("p-%d", i), "v")
		}(i)
	}
	time.Sleep(2 * time.Millisecond)

	start := time.Now()
	b.Stop()
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("Stop took %v, want < 500ms", took)
	}
	wg.Wait()
}

// ============================================================
// P1.3 — soft-deleted live rows pruned
// ============================================================

// TestPruner_HardDeletesSoftDeletedLiveRows seeds a soft-deleted
// live row aged past the retention window and asserts the pruner
// hard-deletes it. Live rows still inside the retention window
// (or not soft-deleted at all) must be left alone.
func TestPruner_HardDeletesSoftDeletedLiveRows(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour)

	// Aged soft-deleted: should be hard-deleted by the pruner.
	// Fresh soft-deleted: should be kept.
	// Live (no deleted_at): should be kept regardless of age.
	rows := []*ObjectMetadataRow{
		{Namespace: "/x", ObjectPath: "/x/aged-soft", Size: 1, ETag: `"e"`, EtagSource: "backend",
			BackendMtime: old, CreatedAt: old, LastModified: old, DeletedAt: &old},
		{Namespace: "/x", ObjectPath: "/x/fresh-soft", Size: 2, ETag: `"e"`, EtagSource: "backend",
			BackendMtime: now, CreatedAt: now, LastModified: now, DeletedAt: &now},
		{Namespace: "/x", ObjectPath: "/x/aged-live", Size: 3, ETag: `"e"`, EtagSource: "backend",
			BackendMtime: old, CreatedAt: old, LastModified: old},
	}
	for _, r := range rows {
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("seed %q: %v", r.ObjectPath, err)
		}
	}

	rd := 7 // 7-day retention; the 40-day-old soft-deleted row should go
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/x",
			Metadata:         &server_utils.OriginExportMetadata{HistoryRetentionDays: &rd},
		},
	}
	pruner := newObjectMetadataPruner(d, exports, time.Hour, 100)
	pruner.onePass(ctx)

	// Aged-soft: gone.
	var n int64
	db.Model(&ObjectMetadataRow{}).Where("object_path = ?", "/x/aged-soft").Count(&n)
	if n != 0 {
		t.Fatalf("aged soft-deleted row not hard-deleted: %d remaining", n)
	}
	// Fresh-soft: kept (deleted_at fresh).
	db.Model(&ObjectMetadataRow{}).Where("object_path = ?", "/x/fresh-soft").Count(&n)
	if n != 1 {
		t.Fatalf("fresh soft-deleted row was hard-deleted (should keep): %d", n)
	}
	// Live: kept (no deleted_at).
	db.Model(&ObjectMetadataRow{}).Where("object_path = ?", "/x/aged-live").Count(&n)
	if n != 1 {
		t.Fatalf("aged LIVE row was hard-deleted (should keep): %d", n)
	}
}

// TestPruner_HardDeleteRespectsBatchSize — the soft-deleted-row
// path uses the same per-pass batch budget as history; one pass
// across many soft-deleted rows should drain them all by looping
// internally.
func TestPruner_HardDeleteRespectsBatchSize(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	old := time.Now().Add(-90 * 24 * time.Hour).UTC()
	const N = 25
	for i := 0; i < N; i++ {
		r := &ObjectMetadataRow{
			Namespace: "/y", ObjectPath: fmt.Sprintf("/y/s-%d", i),
			Size: int64(i), ETag: `"e"`, EtagSource: "backend",
			BackendMtime: old, CreatedAt: old, LastModified: old, DeletedAt: &old,
		}
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	rd := 30
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/y",
			Metadata:         &server_utils.OriginExportMetadata{HistoryRetentionDays: &rd},
		},
	}
	// batch=4 → 7 iterations to drain 25 rows
	pruner := newObjectMetadataPruner(d, exports, time.Hour, 4)
	pruner.onePass(ctx)

	var n int64
	db.Model(&ObjectMetadataRow{}).Where("namespace = ?", "/y").Count(&n)
	if n != 0 {
		t.Fatalf("%d soft-deleted rows survived a full pass", n)
	}
}
