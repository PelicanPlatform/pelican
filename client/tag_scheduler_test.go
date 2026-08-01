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

package client

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/error_codes"
)

// makeFile builds a minimal *clientTransferFile whose first attempt
// targets `host`. Suitable for feeding TagScheduler in tests.
func makeFile(host string) *clientTransferFile {
	return &clientTransferFile{
		uuid:  uuid.New(),
		jobId: uuid.New(),
		file: &transferFile{
			attempts: []transferAttemptDetails{
				{Url: &url.URL{Scheme: "https", Host: host, Path: "/x"}},
			},
			remoteURL: &url.URL{Scheme: "pelican", Host: "ns", Path: "/x"},
		},
	}
}

// startScheduler starts `sched` under a throwaway errgroup, dispatching to
// `out`, and registers cleanup that stops it and waits for the goroutine.
// Tests that want submissions to pile up in the FIFOs simply pass an
// unbuffered `out` that nothing reads.
func startScheduler(t *testing.T, ctx context.Context, sched *TagScheduler, out chan *clientTransferFile) {
	t.Helper()
	egrp, _ := errgroup.WithContext(ctx)
	sched.Start(ctx, egrp, out)
	t.Cleanup(func() {
		sched.Stop()
		require.NoError(t, egrp.Wait())
	})
}

// drainOut consumes files from `out` and, for each one, invokes any
// scheduler hooks the caller asked for. It returns a slice of
// "host of dispatched file" strings, in dispatch order.
//
// The caller controls how each dispatched file "completes" via the
// per-file callback: it receives the host string and returns true
// once the test wants that transfer to fire schedDone. The callback
// may also fire schedFirstByte at its own discretion.
func drainOut(ctx context.Context, t *testing.T, out <-chan *clientTransferFile, n int, complete func(host string, f *clientTransferFile)) []string {
	t.Helper()
	got := make([]string, 0, n)
	for i := 0; i < n; i++ {
		select {
		case f := <-out:
			host := f.file.attempts[0].Url.Host
			got = append(got, host)
			if complete != nil {
				complete(host, f)
			}
		case <-ctx.Done():
			t.Fatalf("timed out after %d dispatches (wanted %d)", len(got), n)
		}
	}
	return got
}

// TestTagSchedulerAcceptsAndDispatches: with generous caps, all
// admitted transfers should be dispatched to the worker channel, and a
// single tag's transfers must come out in submission order (the per-tag
// queue is a FIFO; only the choice *between* tags is randomized).
func TestTagSchedulerAcceptsAndDispatches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sched := NewTagScheduler(100, SchedulerConfig{
		PerTagStarvingPercent: 90,
		PerTagActivePercent:   90,
		PendingBufferSize:     100,
		PerTagPendingSize:     50,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile)
	startScheduler(t, ctx, sched, out)

	// Each file carries a distinct remote path so the dispatch order can be
	// compared against the submission order.
	const N = 10
	submitted := make([]string, 0, N)
	for i := 0; i < N; i++ {
		f := makeFile("originA")
		f.file.remoteURL.Path = fmt.Sprintf("/obj-%d", i)
		submitted = append(submitted, f.file.remoteURL.Path)
		require.NoError(t, sched.Submit(ctx, "originA", f))
	}
	dispatched := make([]string, 0, N)
	got := drainOut(ctx, t, out, N, func(_ string, f *clientTransferFile) {
		dispatched = append(dispatched, f.file.remoteURL.Path)
		// Simulate the transfer completing immediately.
		f.file.schedDone()
	})
	assert.Len(t, got, N)
	for _, h := range got {
		assert.Equal(t, "originA", h)
	}
	assert.Equal(t, submitted, dispatched, "a single tag must be dispatched in FIFO order")
}

// TestTagSchedulerGlobalBufferFullRejects: when total pending reaches
// PendingBufferSize, further submissions are rejected with 429.
func TestTagSchedulerGlobalBufferFullRejects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 50, // caps at 2, so files accumulate in the queue
		PerTagActivePercent:   50,
		PendingBufferSize:     3,
		PerTagPendingSize:     100, // large; hit the global cap first
		EMAWindow:             5 * time.Second,
	})
	// Nothing reads `out`, so submissions enqueue without a worker draining
	// them.
	startScheduler(t, ctx, sched, make(chan *clientTransferFile))

	// Fill the buffer with 3 admits; the scheduler will hold them
	// (starving cap = 2, so at most 2 dispatch attempts fire before a
	// worker is consumed — but we have no workers, so they sit).
	for i := 0; i < 3; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	// The 4th should be rejected.
	err := sched.Submit(ctx, "originA", makeFile("originA"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyRequests)
}

// TestTagSchedulerPerTagPendingFullRejects: when a single tag's FIFO
// hits PerTagPendingSize, further submissions FOR THAT TAG are 429'd
// even if the global buffer still has room.
func TestTagSchedulerPerTagPendingFullRejects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 25, // 1 slot; ensures nothing drains
		PerTagActivePercent:   25,
		PendingBufferSize:     100,
		PerTagPendingSize:     2,
		EMAWindow:             5 * time.Second,
	})
	startScheduler(t, ctx, sched, make(chan *clientTransferFile))

	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	// Third for originA should 429.
	err := sched.Submit(ctx, "originA", makeFile("originA"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyRequests)
	// A different tag with an empty queue should still be admitted.
	require.NoError(t, sched.Submit(ctx, "originB", makeFile("originB")))
}

// TestTagSchedulerStarvingCap: the scheduler will not dispatch more
// than PerTagStarvingPercent% of the pool for a tag whose transfers
// haven't produced a first byte.
func TestTagSchedulerStarvingCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(10, SchedulerConfig{
		PerTagStarvingPercent: 30, // cap = ceil(10*0.30) = 3
		PerTagActivePercent:   90,
		PendingBufferSize:     100,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile, 100)
	startScheduler(t, ctx, sched, out)

	// Admit 10 transfers for one tag.  Do NOT fire first-byte or done.
	for i := 0; i < 10; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	// Only 3 should be dispatched (starving cap); the other 7 sit in the
	// FIFO, and stay there — nothing releases a starving slot.
	require.Eventually(t, func() bool { return len(out) == 3 }, time.Second, 10*time.Millisecond,
		"starving cap should hold dispatch at ceil(30%)")

	// Assert the resting state rather than watching the clock for a
	// non-event: a tag at its starving cap with a non-empty FIFO is not
	// eligible for dispatch, so nothing more can come out until a first-byte
	// or done event arrives, and none is coming.
	var snap SchedulerSnapshot
	require.Eventually(t, func() bool {
		snap = sched.Snapshot(ctx)
		return snap.Tags["originA"].Starving == 3 && snap.Tags["originA"].Pending == 7
	}, time.Second, 10*time.Millisecond, "expected 3 starving and 7 queued, got %+v", snap.Tags["originA"])
	assert.Equal(t, 3, snap.Tags["originA"].Active, "every dispatched transfer is still in flight")
	assert.Equal(t, 3, len(out))
}

// TestTagSchedulerFirstByteReleasesStarvingSlot: once a dispatched
// transfer fires schedFirstByte, the starving count drops and the
// scheduler can dispatch another transfer for that tag.
func TestTagSchedulerFirstByteReleasesStarvingSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(10, SchedulerConfig{
		PerTagStarvingPercent: 30,
		PerTagActivePercent:   90,
		PendingBufferSize:     100,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile, 100)
	startScheduler(t, ctx, sched, out)

	for i := 0; i < 10; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	// Wait for 3 dispatches to land.
	require.Eventually(t, func() bool { return len(out) == 3 }, time.Second, 10*time.Millisecond)
	// Signal first-byte on all three; scheduler should then release
	// them from the starving bucket and dispatch 3 more.
	for i := 0; i < 3; i++ {
		(<-out).file.schedFirstByte()
	}
	require.Eventually(t, func() bool { return len(out) == 3 }, time.Second, 10*time.Millisecond)
}

// TestTagSchedulerActiveCap: even after first-byte, no more than
// PerTagActivePercent% of the pool may hold a single tag's transfers.
func TestTagSchedulerActiveCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(10, SchedulerConfig{
		PerTagStarvingPercent: 90, // cap at 9
		PerTagActivePercent:   40, // active cap at ceil(10*0.40) = 4
		PendingBufferSize:     100,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile, 100)
	startScheduler(t, ctx, sched, out)

	for i := 0; i < 10; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	// Wait for 4 to dispatch and fire first-byte on each so we move
	// out of the starving bucket, but do NOT fire schedDone.
	require.Eventually(t, func() bool { return len(out) == 4 }, time.Second, 10*time.Millisecond)
	firstFour := make([]*clientTransferFile, 4)
	for i := 0; i < 4; i++ {
		firstFour[i] = <-out
		firstFour[i].file.schedFirstByte()
	}
	// Active cap should hold at 4; nothing more dispatches until a schedDone
	// fires. As above, assert the resting state instead of waiting out a
	// non-event: a tag at its active cap with a non-empty FIFO cannot be
	// picked for dispatch.
	var snap SchedulerSnapshot
	require.Eventually(t, func() bool {
		snap = sched.Snapshot(ctx)
		st := snap.Tags["originA"]
		// Starving reaching 0 is what proves all four first-byte events have
		// been processed; active and pending alone were already at these
		// values before any of them landed.
		return st.Active == 4 && st.Starving == 0 && st.Pending == 6
	}, time.Second, 10*time.Millisecond, "expected 4 active, 0 starving and 6 queued, got %+v", snap.Tags["originA"])
	assert.Equal(t, 0, len(out), "active cap should prevent further dispatch until a done")

	firstFour[0].file.schedDone()
	require.Eventually(t, func() bool { return len(out) == 1 }, time.Second, 10*time.Millisecond)
}

// TestTagSchedulerFairnessAcrossTags: with two tags each backlogged
// far past the starving cap, both should progress in an interleaved
// fashion (no tag monopolises the pool).
func TestTagSchedulerFairnessAcrossTags(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(10, SchedulerConfig{
		PerTagStarvingPercent: 25, // cap = 3 per tag
		PerTagActivePercent:   90,
		PendingBufferSize:     100,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile, 100)
	startScheduler(t, ctx, sched, out)

	for i := 0; i < 10; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	for i := 0; i < 10; i++ {
		require.NoError(t, sched.Submit(ctx, "originB", makeFile("originB")))
	}
	// Wait for 6 total dispatches (3 per tag under starving caps).
	require.Eventually(t, func() bool { return len(out) == 6 }, time.Second, 10*time.Millisecond)

	got := make(map[string]int)
	for len(out) > 0 {
		f := <-out
		got[f.file.attempts[0].Url.Host]++
	}
	assert.Equal(t, 3, got["originA"], "each tag caps at 3 while starving")
	assert.Equal(t, 3, got["originB"], "each tag caps at 3 while starving")
}

// TestTagSchedulerSnapshot: Snapshot() returns a coherent view whose
// invariants match what we drove in — admits + rejects add up to the
// submit attempts, per-tag pending/active/starving are non-negative,
// and rejects show up in the global reject reason breakdown.
//
// Exact per-step counts race with the scheduler goroutine's dispatch
// loop, so we assert on the sum rather than the split.
func TestTagSchedulerSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Small pool + tight per-tag caps so we're guaranteed to see
	// per-tag pending-queue rejections after enough submits.
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 25, // starving cap = 1
		PerTagActivePercent:   50, // active cap = 2
		PendingBufferSize:     100,
		PerTagPendingSize:     3,
		EMAWindow:             5 * time.Second,
	})
	// No consumer on `out`; buffered so dispatch doesn't block.
	out := make(chan *clientTransferFile, 100)
	startScheduler(t, ctx, sched, out)

	// Submit enough for originA that we're guaranteed to see rejects
	// once its FIFO fills (starving cap = 1, active cap = 2 ⇒ at
	// most 2 in-flight; with per-tag FIFO = 3 the extras eventually
	// 429).
	const nSubmits = 20
	accepted, rejected := 0, 0
	for i := 0; i < nSubmits; i++ {
		if err := sched.Submit(ctx, "originA", makeFile("originA")); err == nil {
			accepted++
		} else {
			require.ErrorIs(t, err, ErrTooManyRequests)
			rejected++
		}
	}
	require.Greater(t, rejected, 0, "at least one 429 expected once the per-tag FIFO fills")

	snap := sched.Snapshot(ctx)
	require.NotNil(t, snap.Tags)

	// Global invariants.
	assert.Equal(t, 4, snap.Global.WorkerCount)
	assert.Equal(t, 1, snap.Global.StarvingCap, "starving cap = ceil(25%%×4)")
	assert.Equal(t, 2, snap.Global.ActiveCap, "active cap = ceil(50%%×4)")
	assert.Equal(t, uint64(accepted), snap.Global.TotalAdmits,
		"scheduler-tracked admits should match the Submit-side accepted count")
	assert.Equal(t, uint64(rejected), snap.Global.TotalRejects,
		"scheduler-tracked rejects should match the Submit-side rejected count")
	assert.Equal(t, snap.Global.TotalRejects,
		snap.Global.TotalRejectsGlobal+snap.Global.TotalRejectsPerTag,
		"rejects split into global + per_tag adds up to the total")

	// Per-tag: only originA touched.
	a, ok := snap.Tags["originA"]
	require.True(t, ok)
	assert.Equal(t, uint64(accepted), a.Admits)
	assert.Equal(t, uint64(rejected), a.Rejects)
	assert.GreaterOrEqual(t, a.Pending, 0)
	assert.GreaterOrEqual(t, a.Active, 0)
	assert.GreaterOrEqual(t, a.Starving, 0)
	assert.LessOrEqual(t, a.Starving, a.Active,
		"starving is a subset of active — never larger")
	assert.LessOrEqual(t, a.Active, snap.Global.ActiveCap,
		"active respects the per-tag active cap")

	// A never-mentioned tag should be absent from the snapshot.
	_, present := snap.Tags["originB"]
	assert.False(t, present, "tags with zero activity should not appear in the snapshot")
}

// TestTagSchedulerConcurrentSubmit: many submissions from parallel
// goroutines should each get a deterministic accept-or-429 answer
// without deadlock.
func TestTagSchedulerConcurrentSubmit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sched := NewTagScheduler(20, SchedulerConfig{
		PerTagStarvingPercent: 100,
		PerTagActivePercent:   100,
		PendingBufferSize:     50,
		PerTagPendingSize:     50,
		EMAWindow:             time.Second,
	})
	out := make(chan *clientTransferFile, 500)
	startScheduler(t, ctx, sched, out)

	var wg sync.WaitGroup
	var accepted, rejected int64
	var mu sync.Mutex
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sched.Submit(ctx, "originA", makeFile("originA"))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				accepted++
			} else if errors.Is(err, ErrTooManyRequests) {
				rejected++
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(200), accepted+rejected, "every submission should resolve")
}

// TestTagSchedulerRejectClassifiesCacheOverloaded: a rejection due to the
// global pending buffer being full is classified as ShedCacheOverloaded.
func TestTagSchedulerRejectClassifiesCacheOverloaded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 50,
		PerTagActivePercent:   50,
		PendingBufferSize:     3,
		PerTagPendingSize:     100, // large; hit the global cap first
		EMAWindow:             5 * time.Second,
	})
	// No worker draining out, so submissions enqueue and fill the buffer.
	startScheduler(t, ctx, sched, make(chan *clientTransferFile))

	for i := 0; i < 3; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	err := sched.Submit(ctx, "originA", makeFile("originA"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyRequests)
	var rej *SchedulerRejection
	require.ErrorAs(t, err, &rej)
	assert.Equal(t, ShedCacheOverloaded, rej.Reason)
}

// TestTagSchedulerRejectClassifiesOriginUnresponsive: when a per-tag FIFO fills
// while the origin is holding its starving cap (dispatched fetches that never
// produced a first byte), the rejection is classified as ShedOriginUnresponsive.
func TestTagSchedulerRejectClassifiesOriginUnresponsive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 25, // starving cap = 1 (the limiter)
		PerTagActivePercent:   90, // active cap high, not the limiter
		PendingBufferSize:     100,
		PerTagPendingSize:     2,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile, 100)
	startScheduler(t, ctx, sched, out)

	// First submit dispatches and becomes starving (no first-byte fired).
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	require.Eventually(t, func() bool { return len(out) == 1 }, time.Second, 10*time.Millisecond)
	// Two more fill the per-tag FIFO (dispatch blocked by the starving cap).
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	// Fourth overflows the FIFO -> reject. starving == starvingCap -> unresponsive.
	err := sched.Submit(ctx, "originA", makeFile("originA"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyRequests)
	var rej *SchedulerRejection
	require.ErrorAs(t, err, &rej)
	assert.Equal(t, ShedOriginUnresponsive, rej.Reason)
	assert.Equal(t, "originA", rej.Tag)
}

// TestTagSchedulerRejectClassifiesOriginSlow: when a per-tag FIFO fills while
// the origin is at its active cap (delivering data, but holding its share of
// the pool) rather than its starving cap, the rejection is classified as
// ShedOriginSlow.
func TestTagSchedulerRejectClassifiesOriginSlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 90, // starving cap high, not the limiter
		PerTagActivePercent:   25, // active cap = 1 (the limiter)
		PendingBufferSize:     100,
		PerTagPendingSize:     2,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile, 100)
	startScheduler(t, ctx, sched, out)

	// One dispatches (active == 1 == activeCap). starving (1) stays below the
	// high starving cap, so the FIFO-full reject classifies as slow, not
	// unresponsive.
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	require.Eventually(t, func() bool { return len(out) == 1 }, time.Second, 10*time.Millisecond)
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	err := sched.Submit(ctx, "originA", makeFile("originA"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyRequests)
	var rej *SchedulerRejection
	require.ErrorAs(t, err, &rej)
	assert.Equal(t, ShedOriginSlow, rej.Reason)
}

// A transfer that fails before producing any body must release both its
// active and starving slots; otherwise a string of early failures would
// permanently consume the tag's (small) starving budget and wedge the tag.
func TestTagSchedulerStarvingReleasedOnEarlyFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 25, // starving cap = 1: the limiter
		PerTagActivePercent:   90,
		PendingBufferSize:     100,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile)
	startScheduler(t, ctx, sched, out)

	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))

	// First dispatch holds the whole starving budget. Fail it without a
	// first byte; the queued transfer must then dispatch.
	first := <-out
	first.file.schedDone()
	select {
	case second := <-out:
		second.file.schedFirstByte()
		second.file.schedDone()
	case <-ctx.Done():
		t.Fatal("second transfer never dispatched: early failure did not release the starving slot")
	}

	// All slots must drain back to zero (no double-decrement, no leak).
	require.Eventually(t, func() bool {
		snap := sched.Snapshot(ctx)
		st := snap.Tags["originA"]
		return st.Active == 0 && st.Starving == 0
	}, 2*time.Second, 10*time.Millisecond)
}

// Transfers still queued when the scheduler stops must be handed to the
// onDrop hook (which the engine uses to synthesize failure results) rather
// than silently discarded — otherwise their jobs would wait forever.
func TestTagSchedulerStopDrainsQueued(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PendingBufferSize: 100,
		PerTagPendingSize: 100,
		EMAWindow:         5 * time.Second,
	})
	var dropped []*clientTransferFile
	sched.onDrop = func(f *clientTransferFile) { dropped = append(dropped, f) }
	// No reader on out: everything admitted stays queued.
	startScheduler(t, ctx, sched, make(chan *clientTransferFile))

	const N = 3
	for i := 0; i < N; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	// Stop returns only after the scheduler goroutine has drained the
	// FIFOs, so reading `dropped` afterwards is race-free.
	sched.Stop()
	assert.Len(t, dropped, N, "every queued transfer must be surfaced via onDrop at shutdown")
}

// Submissions racing shutdown must shed like any other rejection (so the
// caller synthesizes a failure result) instead of dropping the transfer.
func TestTagSchedulerSubmitAfterStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{PendingBufferSize: 10})
	startScheduler(t, ctx, sched, make(chan *clientTransferFile))
	sched.Stop()

	err := sched.Submit(ctx, "originA", makeFile("originA"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyRequests)
	var rej *SchedulerRejection
	require.ErrorAs(t, err, &rej)
	assert.Equal(t, ShedCacheOverloaded, rej.Reason)
}

// Stop is safe to call repeatedly, concurrently, and on a scheduler that was
// never started.
func TestTagSchedulerStopIsIdempotent(t *testing.T) {
	// Never started: must return promptly rather than wait on a goroutine
	// that does not exist.
	neverStarted := NewTagScheduler(4, SchedulerConfig{})
	done := make(chan struct{})
	go func() { neverStarted.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop on a never-started scheduler hung")
	}

	// Started: concurrent Stops must all return without panicking.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{})
	startScheduler(t, ctx, sched, make(chan *clientTransferFile))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); sched.Stop() }()
	}
	wg.Wait()
}

// Fully-idle tags must be evicted after the grace period so per-tag state
// (and the monitoring snapshot / Prometheus label set derived from it) does
// not grow forever with every origin the cache has ever contacted. Tags with
// queued or in-flight work, a still-decaying EMA, or recent activity stay:
// the periodic sweep is the only thing that removes a tag, so counters
// hitting zero on their own must not.
func TestTagSchedulerEvictsIdleTags(t *testing.T) {
	sched := NewTagScheduler(4, SchedulerConfig{}) // EMAWindow 0 → grace floor (10s)
	now := time.Now()
	stale := now.Add(-time.Minute)

	// Idle: counters only, no other state — must be evicted.
	idle := sched.tagFor("idle")
	idle.admits, idle.rejects, idle.lastSeen = 5, 2, stale
	// Queued: a pending transfer pins the tag.
	queued := sched.tagFor("queued")
	queued.admits, queued.lastSeen = 1, stale
	queued.fifo.PushBack(makeFile("queued"))
	// In-flight: active transfer pins the tag.
	busy := sched.tagFor("busy")
	busy.admits, busy.active, busy.lastSeen = 1, 1, stale
	// Starving: a dispatched transfer still awaiting a first byte pins it.
	starved := sched.tagFor("starved")
	starved.admits, starved.active, starved.starving, starved.lastSeen = 1, 1, 1, stale
	// Decaying: a residual EMA pins the tag.
	decaying := sched.tagFor("decaying")
	decaying.admits, decaying.ema, decaying.lastSeen = 1, 0.5, stale
	// Recent: activity within the grace period pins the tag.
	recent := sched.tagFor("recent")
	recent.admits, recent.lastSeen = 1, now

	sched.evictIdleTags(now)

	assert.NotContains(t, sched.tags, "idle")
	assert.Contains(t, sched.tags, "queued")
	assert.Contains(t, sched.tags, "busy")
	assert.Contains(t, sched.tags, "starved")
	assert.Contains(t, sched.tags, "decaying")
	assert.Contains(t, sched.tags, "recent")

	// A tag whose transfers have all finished is not evicted on the spot —
	// only once it has been idle through the grace period.
	settled := sched.tagFor("settled")
	settled.admits, settled.lastSeen = 3, now
	sched.evictIdleTags(now)
	assert.Contains(t, sched.tags, "settled",
		"a tag that just went idle keeps its counters until the grace period elapses")
	settled.lastSeen = stale
	sched.evictIdleTags(now)
	assert.NotContains(t, sched.tags, "settled")

	// The evicted tag no longer appears in snapshots (buildSnapshot runs on
	// the scheduler goroutine; calling it directly is safe on a scheduler
	// that was never started).
	snap := sched.buildSnapshot()
	assert.NotContains(t, snap.Tags, "idle")
	assert.NotContains(t, snap.Tags, "settled")
	assert.Contains(t, snap.Tags, "busy")
}

// When the global pending buffer is full, a tag with an empty queue may
// still enqueue one entry. Without this reservation, a few saturated origins
// could pin the global buffer and starve every healthy origin out of
// admission entirely — inverting the fairness the scheduler exists for.
func TestTagSchedulerGlobalBufferReservesForIdleTags(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 25, // starving cap 1: originA's queue backs up
		PerTagActivePercent:   90,
		PendingBufferSize:     2,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	// No consumer on out: dispatched work parks, queues build.
	startScheduler(t, ctx, sched, make(chan *clientTransferFile))

	// Saturate the global buffer with one origin.
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	// Same origin again: global buffer is full and its queue is non-empty →
	// shed.
	err := sched.Submit(ctx, "originA", makeFile("originA"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyRequests)

	// A different, idle origin must still get its one reserved slot…
	require.NoError(t, sched.Submit(ctx, "originB", makeFile("originB")),
		"an idle origin must not be locked out by other origins pinning the global buffer")
	// …but only one: with something queued it is subject to the global cap
	// like everyone else.
	err = sched.Submit(ctx, "originB", makeFile("originB"))
	require.Error(t, err)
	var rej *SchedulerRejection
	require.ErrorAs(t, err, &rej)
	assert.Equal(t, ShedCacheOverloaded, rej.Reason,
		"an origin under its own caps must not be blamed for pool-wide saturation")
}

// classifyShed attributes a shed to the origin only when the origin's own
// in-flight composition is the limit; a tag whose queue backed up purely
// because of pool-wide contention is reported as cache_overloaded, not
// blamed as slow.
func TestTagSchedulerClassifyShedHonesty(t *testing.T) {
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 25, // starving cap 1
		PerTagActivePercent:   50, // active cap 2
	})
	// Unknown tag: nothing in flight → pool contention, not the origin's fault.
	assert.Equal(t, ShedCacheOverloaded, sched.classifyShed("unknownTag"))
	// Known but wholly idle: same verdict.
	sched.tagFor("idleTag")
	assert.Equal(t, ShedCacheOverloaded, sched.classifyShed("idleTag"))
	// At the starving cap: first-byte-less fetches dominate → unresponsive.
	starved := sched.tagFor("starved")
	starved.active, starved.starving = 1, 1
	assert.Equal(t, ShedOriginUnresponsive, sched.classifyShed("starved"))
	// At the active cap, delivering data → merely slow.
	sched.tagFor("slow").active = 2
	assert.Equal(t, ShedOriginSlow, sched.classifyShed("slow"))
}

// TestTagSchedulerCapRounding pins the percent-to-slots conversion across
// pool sizes and percentages. The caps round up, so a small pool can never
// produce a cap of zero — which would make the tag permanently ineligible
// for dispatch and wedge every transfer for that origin. Out-of-range
// percentages mean "no per-tag limit" and yield the whole pool.
func TestTagSchedulerCapRounding(t *testing.T) {
	for _, tc := range []struct {
		workers int
		pct     int
		want    int
	}{
		{workers: 1, pct: 1, want: 1},
		{workers: 1, pct: 25, want: 1},
		{workers: 1, pct: 99, want: 1},
		{workers: 2, pct: 25, want: 1},
		{workers: 3, pct: 25, want: 1},
		{workers: 4, pct: 25, want: 1},
		{workers: 5, pct: 25, want: 2},
		{workers: 100, pct: 25, want: 25},
		{workers: 100, pct: 90, want: 90},
		{workers: 100, pct: 33, want: 33},
		// A non-positive or >=100 percentage disables the cap.
		{workers: 10, pct: 0, want: 10},
		{workers: 10, pct: -1, want: 10},
		{workers: 10, pct: 100, want: 10},
		{workers: 10, pct: 150, want: 10},
		// The constructor floors the pool at one worker.
		{workers: 0, pct: 25, want: 1},
		{workers: -5, pct: 50, want: 1},
	} {
		t.Run(fmt.Sprintf("workers=%d_pct=%d", tc.workers, tc.pct), func(t *testing.T) {
			starving := NewTagScheduler(tc.workers, SchedulerConfig{PerTagStarvingPercent: tc.pct})
			assert.Equal(t, tc.want, starving.starvingCap())
			active := NewTagScheduler(tc.workers, SchedulerConfig{PerTagActivePercent: tc.pct})
			assert.Equal(t, tc.want, active.activeCap())
			assert.GreaterOrEqual(t, starving.starvingCap(), 1, "a cap of zero would wedge the tag")
		})
	}
}

// TestTagSchedulerLateFirstByteDoesNotDoubleRelease pins that a first-byte
// signal arriving after the transfer already completed is ignored.
//
// Completion and first-byte are not mutually exclusive: an upload can
// abandon its transfer (stopped-transfer timeout, error on the side channel)
// while the transport is still running, and the transport may afterwards
// report a negotiated 100-continue, a first response byte, or enough request
// body drained. If schedDone merely read the flag instead of claiming it,
// that late signal would decrement the tag's starving count a second time
// and hand some other in-flight transfer's slot away.
func TestTagSchedulerLateFirstByteDoesNotDoubleRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sched := NewTagScheduler(10, SchedulerConfig{
		PerTagStarvingPercent: 20, // starving cap = 2
		PerTagActivePercent:   90,
		PendingBufferSize:     100,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile, 100)
	startScheduler(t, ctx, sched, out)

	// Exactly three, so that once all three are dispatched the tag's queue is
	// empty. That matters: with nothing left to dispatch, a wrongly released
	// slot cannot be immediately refilled, so it stays visible in the counters
	// instead of being masked by the replacement transfer.
	for i := 0; i < 3; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	require.Eventually(t, func() bool { return len(out) == 2 }, 5*time.Second, time.Millisecond,
		"starving cap should hold dispatch at 2")
	fileA := <-out
	fileB := <-out

	// A completes without ever producing a byte: it gives back one starving
	// slot, which lets the last queued transfer dispatch.
	fileA.file.schedDone()
	require.Eventually(t, func() bool { return len(out) == 1 }, 5*time.Second, time.Millisecond)
	fileC := <-out

	// Now A's transport reports a first byte, too late to mean anything. If
	// that were honored it would release a second slot for a transfer that has
	// already finished.
	fileA.file.schedFirstByte()

	// B completing is the discriminator. It is a real event, so it is queued
	// behind anything A's late call may have emitted and is processed after it.
	//
	// Both of B's counts come off together, so the tag lands on one active and
	// one starving (C). Had A's late call also been honored, the starving count
	// would already have been decremented once too often, and the tag would
	// land on one active and *zero* starving -- a state this wait never
	// accepts, and one the correct sequence never passes through.
	fileB.file.schedDone()
	require.Eventually(t, func() bool {
		st := sched.Snapshot(ctx).Tags["originA"]
		return st.Active == 1 && st.Starving == 1
	}, 5*time.Second, time.Millisecond,
		"expected one in flight and still starving; a late first byte must not release a slot")

	st := sched.Snapshot(ctx).Tags["originA"]
	assert.Zero(t, st.Pending, "all three were dispatched, so nothing is queued")
	assert.Equal(t, 0, len(out), "with an empty queue there is nothing left to dispatch")

	fileC.file.schedDone()
}

// TestTagSchedulerDoneFiresOncePerFile pins the scheduler's side of the
// completion contract: one schedDone returns exactly one slot, so a tag whose
// files are run one after another keeps making progress rather than stalling
// at its cap.
//
// This drives the hook directly. That a worker fires it once per file rather
// than once for its whole lifetime is runTransferWorkerFile's side of the
// contract and is not exercised here.
func TestTagSchedulerDoneFiresOncePerFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 25, // starving cap = 1, so files go through one at a time
		PerTagActivePercent:   90,
		PendingBufferSize:     100,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	out := make(chan *clientTransferFile)
	startScheduler(t, ctx, sched, out)

	const N = 8
	for i := 0; i < N; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	// Take one, finish it, take the next. If a slot were ever not returned the
	// starving cap would block and this drain would time out.
	drainOut(ctx, t, out, N, func(_ string, f *clientTransferFile) {
		f.file.schedDone()
	})

	var snap SchedulerSnapshot
	require.Eventually(t, func() bool {
		snap = sched.Snapshot(ctx)
		return snap.Global.TotalAdmits == N && snap.Global.TotalPending == 0
	}, time.Second, 10*time.Millisecond, "expected all %d admitted and drained, got %+v", N, snap.Global)
	// The tag may already have been evicted; if it is still present every
	// counter must be back at zero.
	if st, ok := snap.Tags["originA"]; ok {
		assert.Zero(t, st.Active, "every dispatched file returned its slot")
		assert.Zero(t, st.Starving)
		assert.Zero(t, st.Pending)
	}
}

// TestTagSchedulerEMAWeighting pins that the fairness draw actually consults
// the EMA: a tag that has been holding workers recently carries a higher EMA
// and therefore a smaller weight, so it is picked less often than a tag that
// has been quiet. Without this the "fair" scheduler would be plain random
// selection among eligible tags.
func TestTagSchedulerEMAWeighting(t *testing.T) {
	sched := NewTagScheduler(100, SchedulerConfig{
		PerTagStarvingPercent: 90,
		PerTagActivePercent:   90,
		EMAWindow:             time.Second,
	})
	// Drive the EMA directly rather than through dispatch so the test states
	// the weighting rule itself: "busy" has been holding workers, "quiet"
	// has not.
	busy := sched.tagFor("busy")
	quiet := sched.tagFor("quiet")
	busy.active = 50
	quiet.active = 0
	sched.lastTick = time.Now().Add(-time.Second)
	sched.tickEMA()

	require.Greater(t, busy.ema, quiet.ema, "the busy tag should carry the larger EMA")
	require.Less(t, busy.weight, quiet.weight, "a larger EMA must mean a smaller draw weight")
	// A tag holding half the pool for a full window should end up with an EMA
	// on that order, not a token amount -- the weighting is only meaningful if
	// the EMA actually tracks occupancy.
	assert.Greater(t, busy.ema, 25.0, "EMA should approach the ~50 workers held")
	assert.InDelta(t, 1.0/(1.0+busy.ema), busy.weight, 1e-9, "weight is 1/(1+EMA)")
	assert.Zero(t, quiet.ema, "a tag that held nothing decays to zero")
	assert.InDelta(t, 1.0, quiet.weight, 1e-9, "an idle tag draws at full weight")

	// With both tags backlogged and eligible, the quiet tag must win the draw
	// markedly more often. The seed does not make the sequence reproducible --
	// map iteration order still varies -- so this rests on the margin instead:
	// the weights differ by ~30x, which puts the observed split (roughly 975 to
	// 25) tens of standard deviations away from the assertion boundary.
	sched.rng = rand.New(rand.NewPCG(1, 2))
	busy.active, quiet.active = 0, 0 // eligible for dispatch, EMA retained
	for i := 0; i < 4; i++ {
		busy.fifo.PushBack(makeFile("busy"))
		quiet.fifo.PushBack(makeFile("quiet"))
	}
	picks := map[string]int{}
	for i := 0; i < 1000; i++ {
		st, ok := sched.pickForDispatch()
		require.True(t, ok)
		switch st {
		case busy:
			picks["busy"]++
		case quiet:
			picks["quiet"]++
		default:
			t.Fatal("pickForDispatch returned an unknown tag")
		}
	}
	assert.Greater(t, picks["quiet"], picks["busy"],
		"the tag with the lower EMA should be drawn more often (quiet=%d busy=%d)",
		picks["quiet"], picks["busy"])

	// A zero EMAWindow disables the weighting entirely: a tag holding the pool
	// keeps the full weight it was created with, so the draw stays uniform.
	flat := NewTagScheduler(10, SchedulerConfig{EMAWindow: 0})
	a, b := flat.tagFor("a"), flat.tagFor("b")
	a.active = 9
	flat.lastTick = time.Now().Add(-time.Second)
	flat.tickEMA()
	assert.Zero(t, a.ema, "a zero window must leave the EMA untouched")
	assert.Equal(t, 1.0, a.weight, "and therefore the weight at its initial value")
	assert.Equal(t, a.weight, b.weight, "EMA updates are disabled, so weights stay equal")
}

// TestTagSchedulerGlobalBufferOvershootIsBounded pins the size of the
// reservation that lets a tag with an empty FIFO enqueue past the global
// pending limit. The reservation exists so a handful of saturated origins
// cannot pin the global buffer and lock every healthy origin out of
// admission, but it does mean the real ceiling is the configured buffer plus
// one entry per distinct tag rather than the configured buffer alone.
func TestTagSchedulerGlobalBufferOvershootIsBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sched := NewTagScheduler(10, SchedulerConfig{
		PerTagStarvingPercent: 10, // starving cap = 1
		PerTagActivePercent:   90,
		PendingBufferSize:     2,
		PerTagPendingSize:     100,
		EMAWindow:             5 * time.Second,
	})
	// Nothing reads `out`, so everything admitted stays queued.
	out := make(chan *clientTransferFile)
	startScheduler(t, ctx, sched, out)

	const tags = 10
	admitted := 0
	for i := 0; i < tags; i++ {
		tag := fmt.Sprintf("origin-%02d", i)
		// Each tag's first submission is always admitted (the reservation);
		// the second competes for the global buffer.
		for j := 0; j < 2; j++ {
			if err := sched.Submit(ctx, tag, makeFile(tag)); err == nil {
				admitted++
			}
		}
	}

	var snap SchedulerSnapshot
	require.Eventually(t, func() bool {
		snap = sched.Snapshot(ctx)
		return snap.Global.TotalAdmits == uint64(admitted)
	}, time.Second, 10*time.Millisecond)

	// Every tag got at least its one reserved entry, so no origin was locked
	// out. (The first tag submitted gets both of its entries in, because the
	// global buffer still had room when they arrived.)
	assert.GreaterOrEqual(t, admitted, tags,
		"each distinct tag must be able to enqueue one entry even with the global buffer full")
	for i := 0; i < tags; i++ {
		tag := fmt.Sprintf("origin-%02d", i)
		assert.NotZero(t, snap.Tags[tag].Pending+snap.Tags[tag].Active,
			"tag %s was locked out of admission entirely", tag)
	}
	// ...and the overshoot is exactly that: at most one entry per tag on top
	// of the configured buffer, never unbounded.
	assert.LessOrEqual(t, snap.Global.TotalPending, sched.cfg.PendingBufferSize+tags,
		"overshoot must stay bounded by one entry per distinct tag")
}

// TestTagSchedulerSnapshotAfterStop pins that a snapshot requested after the
// scheduler has stopped returns the zero value promptly instead of blocking
// on a goroutine that will never answer. The cache's metrics publisher races
// shutdown on every restart, and a blocked Snapshot there would wedge the
// errgroup.
func TestTagSchedulerSnapshotAfterStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 50,
		PerTagActivePercent:   90,
		PendingBufferSize:     10,
		PerTagPendingSize:     10,
		EMAWindow:             time.Second,
	})
	out := make(chan *clientTransferFile, 4)
	egrp, _ := errgroup.WithContext(ctx)
	sched.Start(ctx, egrp, out)
	require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	sched.Stop()
	require.NoError(t, egrp.Wait())

	done := make(chan SchedulerSnapshot, 1)
	go func() { done <- sched.Snapshot(ctx) }()
	select {
	case snap := <-done:
		assert.Zero(t, snap.Global.WorkerCount, "a stopped scheduler reports the zero snapshot")
		assert.Nil(t, snap.Tags)
	case <-ctx.Done():
		t.Fatal("Snapshot blocked after the scheduler stopped")
	}
}

// TestTagSchedulerRunExitOnContextReleasesWaiters pins that the scheduler
// releases everything waiting on it when its context is cancelled, not only
// when Stop() is what ended it. Submit, Snapshot, and the event hooks all
// use the same internal stop signal as their escape hatch, so a run loop
// that exited without closing it would leave those callers stuck until some
// later Stop() call happened to arrive.
func TestTagSchedulerRunExitOnContextReleasesWaiters(t *testing.T) {
	outer, outerCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer outerCancel()
	schedCtx, schedCancel := context.WithCancel(outer)

	sched := NewTagScheduler(4, SchedulerConfig{
		PerTagStarvingPercent: 50,
		PerTagActivePercent:   90,
		PendingBufferSize:     10,
		PerTagPendingSize:     10,
		EMAWindow:             time.Second,
	})
	out := make(chan *clientTransferFile)
	egrp, _ := errgroup.WithContext(outer)
	sched.Start(schedCtx, egrp, out)

	schedCancel()
	require.NoError(t, egrp.Wait())

	// Submitting against a context that is still live must still return
	// promptly, shedding rather than hanging.
	done := make(chan error, 1)
	go func() { done <- sched.Submit(outer, "originA", makeFile("originA")) }()
	select {
	case err := <-done:
		require.Error(t, err, "a submission to a dead scheduler must shed, not succeed")
		assert.ErrorIs(t, err, ErrTooManyRequests)
	case <-outer.Done():
		t.Fatal("Submit blocked after the scheduler's context was cancelled")
	}

	// Snapshot likewise, and Stop() must remain safe to call afterwards.
	snapDone := make(chan SchedulerSnapshot, 1)
	go func() { snapDone <- sched.Snapshot(outer) }()
	select {
	case <-snapDone:
	case <-outer.Done():
		t.Fatal("Snapshot blocked after the scheduler's context was cancelled")
	}
	assert.NotPanics(t, sched.Stop)
}

// TestSchedulerRejectionIsRetryable pins that a shed performed by this
// process's own scheduler is classified the same way as the identical shed
// observed remotely as an HTTP 429: retryable, carrying the typed Pelican
// error for its reason. The whole point of the shed is that the caller tries
// again elsewhere or later, so a rejection that reads as fatal would defeat
// it.
func TestSchedulerRejectionIsRetryable(t *testing.T) {
	for _, tc := range []struct {
		reason   ShedReason
		wantCode int
	}{
		{ShedOriginUnresponsive, 6008},
		{ShedOriginSlow, 6009},
		{ShedCacheOverloaded, 6010},
	} {
		t.Run(string(tc.reason), func(t *testing.T) {
			rej := &SchedulerRejection{Reason: tc.reason, Tag: "originA"}
			assert.True(t, IsRetryable(rej), "a shed must be retryable")
			assert.ErrorIs(t, rej, ErrTooManyRequests, "existing sentinel checks must keep working")
			var pe *error_codes.PelicanError
			require.ErrorAs(t, rej, &pe)
			assert.Equal(t, tc.wantCode, pe.Code())
			assert.True(t, pe.IsRetryable())
			assert.NotEmpty(t, rej.Error(), "a rejection built as a literal still renders a message")
		})
	}
}

// TestDeriveSchedulerTag pins the tag derivation, including the degenerate
// inputs. Everything that cannot name an upstream host shares the empty tag,
// and therefore shares one set of caps -- so what each degenerate input maps to
// is worth stating explicitly, even though every one of them is unreachable
// from the current call sites.
func TestDeriveSchedulerTag(t *testing.T) {
	assert.Equal(t, "originA", deriveSchedulerTag(makeFile("originA")))

	assert.Empty(t, deriveSchedulerTag(nil), "nil file")
	assert.Empty(t, deriveSchedulerTag(&clientTransferFile{}), "nil inner file")
	assert.Empty(t, deriveSchedulerTag(&clientTransferFile{file: &transferFile{}}), "no attempts")

	noUrl := &clientTransferFile{file: &transferFile{
		attempts: []transferAttemptDetails{{Url: nil}},
	}}
	assert.Empty(t, deriveSchedulerTag(noUrl), "attempt with no URL")

	// The tag is the host alone: the same origin serving different paths is
	// one tag, and the same host on a different scheme is still that host.
	withPort := &clientTransferFile{file: &transferFile{
		attempts: []transferAttemptDetails{
			{Url: &url.URL{Scheme: "https", Host: "origin.example.com:8443", Path: "/deep/path"}},
		},
	}}
	assert.Equal(t, "origin.example.com:8443", deriveSchedulerTag(withPort))
}
