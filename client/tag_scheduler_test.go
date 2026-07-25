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
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
// admitted transfers should be dispatched in-order to the worker
// channel.
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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

	const N = 10
	for i := 0; i < N; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	got := drainOut(ctx, t, out, N, func(_ string, f *clientTransferFile) {
		// Simulate the transfer completing immediately.
		f.file.schedDone()
	})
	assert.Len(t, got, N)
	for _, h := range got {
		assert.Equal(t, "originA", h)
	}
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
	// Don't Start yet — we want submissions to enqueue without a worker
	// draining them.
	sched.out = make(chan *clientTransferFile)
	sched.stopped = make(chan struct{})
	go sched.run(ctx)
	t.Cleanup(sched.Stop)

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
	sched.out = make(chan *clientTransferFile)
	sched.stopped = make(chan struct{})
	go sched.run(ctx)
	t.Cleanup(sched.Stop)

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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

	// Admit 10 transfers for one tag.  Do NOT fire first-byte or done.
	for i := 0; i < 10; i++ {
		require.NoError(t, sched.Submit(ctx, "originA", makeFile("originA")))
	}
	// Give the scheduler a moment to attempt to dispatch.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && len(out) < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	// Only 3 should be dispatched (starving cap); the other 7 sit
	// in the FIFO.
	assert.Equal(t, 3, len(out), "starving cap should hold dispatch at ceil(30%%)")
	// Wait an extra beat and confirm we still don't overshoot.
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 3, len(out), "no further dispatch until first byte or done")
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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

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
	// Active cap should hold at 4; nothing more dispatches until a
	// schedDone fires.
	time.Sleep(200 * time.Millisecond)
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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

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
	sched.out = make(chan *clientTransferFile)
	sched.stopped = make(chan struct{})
	go sched.run(ctx)
	t.Cleanup(sched.Stop)

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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

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
	sched.Start(ctx, out)
	t.Cleanup(sched.Stop)

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
