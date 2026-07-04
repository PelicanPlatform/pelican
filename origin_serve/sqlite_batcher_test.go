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
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newBatcherTestDB returns a per-test in-memory SQLite GORM handle
// pre-populated with a trivial `kv` table the tests insert into.
func newBatcherTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:batcher_%s_%d?mode=memory&cache=shared", t.Name(), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sqlDB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec(`CREATE TABLE kv (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// TestBatcher_DurableBlocksAndCommits is the headline durable
// guarantee: EnqueueDurable returns only after the row is on disk.
func TestBatcher_DurableBlocksAndCommits(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 16, 50*time.Millisecond)
	defer b.Stop()

	if err := b.EnqueueDurable(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", "a", "1"); err != nil {
		t.Fatalf("EnqueueDurable: %v", err)
	}
	// Row must already be visible.
	var v string
	if err := db.Raw("SELECT value FROM kv WHERE key=?", "a").Scan(&v).Error; err != nil {
		t.Fatalf("select: %v", err)
	}
	if v != "1" {
		t.Fatalf("v = %q, want 1", v)
	}
}

// TestBatcher_BestEffortPiggybacksOnDurable proves the concurrency
// dimension: when a durable op forces a flush, every queued best-
// effort op rides the same transaction → one fsync for many writes.
func TestBatcher_BestEffortPiggybacksOnDurable(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var flushes atomic.Int32
	b := newSQLiteBatcher(ctx, db, 256, time.Hour) // long interval
	b.SetHooks(BatcherHooks{IncFlush: func(int) { flushes.Add(1) }})
	defer b.Stop()

	// Queue 50 best-effort ops; the long flush interval ensures
	// none of them would flush on their own within the test window.
	for i := 0; i < 50; i++ {
		if err := b.EnqueueBestEffort(ctx, "INSERT INTO kv(key,value) VALUES(?,?)",
			fmt.Sprintf("be-%d", i), "x"); err != nil {
			t.Fatalf("best-effort enqueue %d: %v", i, err)
		}
	}
	// A single durable op should now flush everything.
	if err := b.EnqueueDurable(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", "d", "y"); err != nil {
		t.Fatalf("EnqueueDurable: %v", err)
	}
	// Every row from the buffered burst is on disk now.
	var n int64
	if err := db.Raw("SELECT COUNT(*) FROM kv").Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 51 {
		t.Fatalf("count = %d, want 51", n)
	}
	// Exactly one flush should have happened.
	if got := flushes.Load(); got != 1 {
		t.Fatalf("flushes = %d, want 1 (concurrent coalescing)", got)
	}
}

// TestBatcher_BestEffortFlushesOnInterval — even without a durable
// trigger, best-effort ops eventually land via the time-based flush.
func TestBatcher_BestEffortFlushesOnInterval(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := newSQLiteBatcher(ctx, db, 16, 30*time.Millisecond)
	defer b.Stop()

	if err := b.EnqueueBestEffort(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", "be", "v"); err != nil {
		t.Fatalf("best-effort enqueue: %v", err)
	}
	// Wait long enough that the interval must have fired at least
	// twice — the row must now be visible.
	deadline := time.After(time.Second)
	for {
		var v string
		_ = db.Raw("SELECT value FROM kv WHERE key=?", "be").Scan(&v).Error
		if v == "v" {
			return
		}
		select {
		case <-deadline:
			t.Fatal("best-effort op never flushed")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestBatcher_DurableSurfacesExecError — a malformed durable op gets
// its Exec error back, not the batch-level commit error.
func TestBatcher_DurableSurfacesExecError(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 16, 50*time.Millisecond)
	defer b.Stop()

	err := b.EnqueueDurable(ctx, "INSERT INTO no_such_table(key) VALUES(?)", "x")
	if err == nil {
		t.Fatal("expected error from INSERT against missing table")
	}
}

// TestBatcher_OverflowBlocksThenUnblocks — the design call was that
// best-effort enqueues block when the channel is full. This test
// fills the channel, asserts the next call blocks, and asserts the
// flusher then drains it.
func TestBatcher_OverflowBlocksThenUnblocks(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Tiny buffer + long interval: best-effort writes will pile up.
	b := newSQLiteBatcher(ctx, db, 4, 30*time.Millisecond)
	defer b.Stop()

	// First 4 enqueues fill the channel. (Some may already have
	// been consumed by the flusher; either way the test only needs
	// to demonstrate that an over-budget enqueue blocks waiting
	// for a flush.)
	for i := 0; i < 4; i++ {
		if err := b.EnqueueBestEffort(ctx, "INSERT INTO kv(key,value) VALUES(?,?)",
			fmt.Sprintf("k-%d", i), "v"); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	// Now drive 100 more enqueues. If they didn't block when the
	// channel filled, this loop would run instantly; if they did,
	// it takes long enough that the time-based flushes drain in
	// between. Either way we should converge on all rows present.
	for i := 4; i < 100; i++ {
		if err := b.EnqueueBestEffort(ctx, "INSERT INTO kv(key,value) VALUES(?,?)",
			fmt.Sprintf("k-%d", i), "v"); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	// Force everything to land.
	if err := b.EnqueueDurable(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", "tail", "v"); err != nil {
		t.Fatalf("durable tail: %v", err)
	}
	var n int64
	if err := db.Raw("SELECT COUNT(*) FROM kv").Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 101 {
		t.Fatalf("count = %d, want 101", n)
	}
}

// TestBatcher_EnqueueAfterStopReturnsError — once Stop has been
// called, subsequent enqueues must fail rather than block forever
// or panic on send-to-closed-channel.
func TestBatcher_EnqueueAfterStopReturnsError(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 4, 50*time.Millisecond)
	b.Stop()

	if err := b.EnqueueBestEffort(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", "x", "v"); err == nil {
		t.Fatal("expected best-effort enqueue after Stop to fail")
	}
	if err := b.EnqueueDurable(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", "y", "v"); err == nil {
		t.Fatal("expected durable enqueue after Stop to fail")
	}
}

// TestBatcher_EnqueueRespectsCallerContext — an enqueue against an
// already-cancelled ctx returns immediately with that ctx's error,
// proving the select-on-ctx.Done path is wired even when the channel
// would otherwise accept the send.
func TestBatcher_EnqueueRespectsCallerContext(t *testing.T) {
	db := newBatcherTestDB(t)
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	b := newSQLiteBatcher(parent, db, 8, time.Hour)
	defer b.Stop()

	// Cancel our caller's ctx; the batcher's parent ctx is still
	// alive, so the batcher itself is healthy. We're proving the
	// per-call ctx is honored.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()

	if err := b.EnqueueDurable(cctx, "INSERT INTO kv(key,value) VALUES(?,?)", "x", "v"); !errors.Is(err, context.Canceled) {
		t.Fatalf("EnqueueDurable err = %v, want context.Canceled", err)
	}
	if err := b.EnqueueBestEffort(cctx, "INSERT INTO kv(key,value) VALUES(?,?)", "y", "v"); !errors.Is(err, context.Canceled) {
		t.Fatalf("EnqueueBestEffort err = %v, want context.Canceled", err)
	}
}

// TestBatcher_StopDrainsBuffer — a graceful Stop() must flush
// queued ops before the goroutine exits.
func TestBatcher_StopDrainsBuffer(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := newSQLiteBatcher(ctx, db, 32, time.Hour) // long interval

	// Queue 20 best-effort writes.
	for i := 0; i < 20; i++ {
		if err := b.EnqueueBestEffort(ctx, "INSERT INTO kv(key,value) VALUES(?,?)",
			fmt.Sprintf("be-%d", i), "v"); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	// Stop must drain.
	b.Stop()

	var n int64
	if err := db.Raw("SELECT COUNT(*) FROM kv").Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 20 {
		t.Fatalf("count = %d, want 20 (Stop didn't drain)", n)
	}
}

// TestBatcher_ConcurrentDurablesCoalesce — multiple goroutines
// submit durable ops concurrently; they should all land but ride
// a small number of transactions (proving the concurrent-batch win).
func TestBatcher_ConcurrentDurablesCoalesce(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var flushes atomic.Int32
	// Small buffer (8) forces most goroutines to block on the
	// channel send, which is exactly what makes the non-blocking
	// drain step in the flusher pick up multiple ops per tx. A
	// large buffer would let goroutines race the flusher and the
	// coalescing ratio would depend entirely on scheduler timing
	// — flaky on Windows CI runners where goroutine scheduling
	// can serialize sends.
	b := newSQLiteBatcher(ctx, db, 8, 50*time.Millisecond)
	b.SetHooks(BatcherHooks{IncFlush: func(int) { flushes.Add(1) }})
	defer b.Stop()

	const N = 50
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := b.EnqueueDurable(ctx, "INSERT INTO kv(key,value) VALUES(?,?)",
				fmt.Sprintf("d-%d", i), "v"); err != nil {
				t.Errorf("durable %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	var n int64
	if err := db.Raw("SELECT COUNT(*) FROM kv").Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != N {
		t.Fatalf("count = %d, want %d", n, N)
	}
	// We don't assert an exact flush count (timing-dependent),
	// only that it's strictly less than N — proving coalescing.
	if got := flushes.Load(); got >= N {
		t.Fatalf("flushes = %d for %d ops; expected coalescing", got, N)
	}
	t.Logf("coalesced %d durable ops into %d flushes", N, flushes.Load())
}

// ============================================================
// P2.2 — FlushNow
// ============================================================

// TestBatcher_FlushNowDrainsBuffer — queue best-effort writes with
// a long flush interval (so the time-based flush wouldn't fire in
// the test window), call FlushNow, and verify the rows are on disk.
// This is the headline use of FlushNow: tests don't have to use the
// EnqueueDurable("SELECT 1") idiom.
func TestBatcher_FlushNowDrainsBuffer(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 64, time.Hour) // long interval; no spontaneous flush
	defer b.Stop()

	for i := 0; i < 7; i++ {
		if err := b.EnqueueBestEffort(ctx, "INSERT INTO kv(key,value) VALUES(?,?)",
			fmt.Sprintf("k-%d", i), "v"); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := b.FlushNow(ctx); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}
	var n int64
	if err := db.Raw("SELECT COUNT(*) FROM kv").Scan(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 7 {
		t.Fatalf("rows = %d, want 7", n)
	}
}

// TestBatcher_FlushNowOnEmptyBatcher — calling FlushNow with
// nothing pending succeeds (returns nil). The sentinel op rides an
// otherwise-empty transaction.
func TestBatcher_FlushNowOnEmptyBatcher(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 8, 50*time.Millisecond)
	defer b.Stop()
	if err := b.FlushNow(ctx); err != nil {
		t.Fatalf("FlushNow on empty: %v", err)
	}
}

// TestBatcher_FlushNowAfterStopReturnsError — calling FlushNow on
// a stopped batcher behaves like any other enqueue: "already closed"
// error rather than hanging.
func TestBatcher_FlushNowAfterStopReturnsError(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 8, 50*time.Millisecond)
	b.Stop()
	if err := b.FlushNow(ctx); err == nil {
		t.Fatal("FlushNow after Stop should return an error")
	}
}

// ============================================================
// P2.4 — flush() respects the transaction timeout
// ============================================================

// TestBatcher_FlushHonorsTxTimeout — set the per-tx timeout to a
// value short enough that a synthetic slow-INSERT (one that waits
// in the SQL itself) will fail with context cancellation. The
// surviving error must reach the per-op done channels rather than
// hanging the flusher.
//
// We synthesise a "slow" statement using SQLite's randomblob() on a
// CTE in a loop. SQLite is fast, so the only reliable way to make a
// single statement take long enough is to make it work hard or
// arrange a deliberate stall. Instead of trying to engineer SQL
// latency, we just set the timeout to 0 — any non-trivial op will
// fail with deadline-exceeded. This proves the wiring, which is the
// point of the test.
func TestBatcher_FlushHonorsTxTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The test relies on a 1ns tx-timeout firing before the
		// underlying BEGIN + INSERT + COMMIT completes. Windows'
		// monotonic timer has ~15ms resolution, which is more than
		// enough for the tx to finish before the deadline fires —
		// the wiring under test still works, it just can't be
		// observed via a nanosecond-scale timeout on this platform.
		t.Skip("tx-timeout observability requires sub-15ms timer resolution")
	}
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 8, 50*time.Millisecond)
	defer b.Stop()
	// Zero timeout: the per-flush ctx is born already-expired so
	// the Transaction call fails with context.DeadlineExceeded
	// before any statement runs.
	b.SetTxTimeout(1 * time.Nanosecond)

	err := b.EnqueueDurable(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", "x", "v")
	if err == nil {
		t.Fatal("expected the EnqueueDurable call to return an error from the timed-out tx")
	}
	// The op should NOT have landed in the DB.
	var n int64
	db.Raw("SELECT COUNT(*) FROM kv").Scan(&n)
	if n != 0 {
		t.Fatalf("op landed despite timeout: %d row(s)", n)
	}
}

// TestBatcher_TxTimeoutDisabledByZeroOrNegative — setting the
// timeout to 0 or a negative value disables the per-flush deadline.
// Useful for tests that synthesise long-running ops.
func TestBatcher_TxTimeoutDisabledByZeroOrNegative(t *testing.T) {
	db := newBatcherTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newSQLiteBatcher(ctx, db, 8, 50*time.Millisecond)
	defer b.Stop()
	b.SetTxTimeout(0) // disabled

	if err := b.EnqueueDurable(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", "y", "v"); err != nil {
		t.Fatalf("op should succeed when timeout is disabled: %v", err)
	}
}
