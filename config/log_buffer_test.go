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

package config

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBuffer builds a LogRingBuffer wired to the production hot path but
// with hand-picked batchLines/maxBytes so a unit test can push the
// eviction/compression logic without piping in megabytes of synthetic log
// data. The returned buffer does NOT install a logrus hook -- tests call
// Fire directly to preserve determinism.
func newTestBuffer(t *testing.T, batchLines, maxBytes int) *LogRingBuffer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	buf := &LogRingBuffer{
		maxBytes:   maxBytes,
		batchLines: batchLines,
		pending:    &bytes.Buffer{},
		nextSeq:    1,
		formatter: &log.TextFormatter{
			DisableColors:          true,
			DisableLevelTruncation: true,
			FullTimestamp:          true,
		},
		compressQueue: make(chan *logRingBatch, 1),
		workerCtx:     ctx,
		workerCancel:  cancel,
	}
	buf.workerWG.Add(1)
	go buf.compressLoop()
	t.Cleanup(func() {
		cancel()
		select {
		case <-buf.compressQueue:
		default:
		}
		close(buf.compressQueue)
		buf.workerWG.Wait()
	})
	return buf
}

// fire feeds a single entry into the buffer. Level is passed explicitly so
// the tests can drive the buffer through both the "always buffer" and
// "gate on effective level" branches of shouldBuffer.
func fire(t *testing.T, buf *LogRingBuffer, level log.Level, msg string) {
	t.Helper()
	entry := log.NewEntry(log.StandardLogger())
	entry.Level = level
	entry.Message = msg
	entry.Time = time.Now()
	require.NoError(t, buf.Fire(entry))
}

// TestLogBuffer_BatchFinalization checks the primary invariant: once
// batchLines entries have been fed in, a batch is finalized and the
// pending buffer resets. Subsequent lines land in a fresh pending buffer.
func TestLogBuffer_BatchFinalization(t *testing.T) {
	buf := newTestBuffer(t, 5, 1<<20)
	for i := 0; i < 5; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("line %d", i))
	}
	assert.Equal(t, 1, buf.BatchCount(), "one full batch should finalize at batchLines")
	assert.Equal(t, 0, buf.PendingLineCount(), "pending must reset after finalize")

	fire(t, buf, log.InfoLevel, "post-finalize")
	assert.Equal(t, 1, buf.PendingLineCount(), "the next line lands in a fresh pending batch")
}

// TestLogBuffer_EvictionRespectsCap confirms the buffer honors the byte cap
// by dropping oldest batches. We push far more lines than the cap allows,
// then assert (a) many batches were evicted, (b) the surviving batches are
// the newest ones (by comparing the oldest surviving seq against the seq
// of the very first push).
func TestLogBuffer_EvictionRespectsCap(t *testing.T) {
	buf := newTestBuffer(t, 5, 300)
	for round := 0; round < 20; round++ {
		for i := 0; i < 5; i++ {
			fire(t, buf, log.InfoLevel, fmt.Sprintf("round %d line %d filler", round, i))
		}
	}
	require.GreaterOrEqual(t, buf.BatchCount(), 1, "the tail batch is never evicted")
	require.Less(t, buf.BatchCount(), 20, "many earlier batches must have been evicted")

	// The oldest seq the buffer still returns must be well past 1
	// (which was the seq of the very first push). We use TailSince(0)
	// to get whatever content is currently held and read its FirstSeq.
	tail := buf.TailSince(0, 0)
	assert.Greater(t, tail.FirstSeq, int64(1),
		"eviction must have advanced the oldest seq past the very first push")
}

// TestLogBuffer_LevelGating exercises the always-buffer-info+ rule.
func TestLogBuffer_LevelGating(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	for _, lvl := range []log.Level{log.PanicLevel, log.FatalLevel, log.ErrorLevel, log.WarnLevel, log.InfoLevel} {
		fire(t, buf, lvl, fmt.Sprintf("%s message", lvl))
	}
	assert.Equal(t, 5, buf.PendingLineCount(),
		"info and above must always be buffered regardless of effective level")
}

// TestShouldBufferReadsEffectiveLevel covers the debug/trace side of the
// gate: shouldBuffer must return true for debug when the effective level
// is debug, false when the effective level is info. GetEffectiveLogLevel
// is served from an atomic cache updated only by SetLogging (and the
// other level-changing sites), so the test drives it via SetLogging
// rather than log.SetLevel -- the latter bypasses the cache by design
// (that's how the hook-based filter tree keeps logrus's level pinned to
// TraceLevel while the effective level tracks the operator's ask).
func TestShouldBufferReadsEffectiveLevel(t *testing.T) {
	prev := GetEffectiveLogLevel()
	t.Cleanup(func() { SetLogging(prev) })

	SetLogging(log.InfoLevel)
	assert.True(t, shouldBuffer(log.InfoLevel), "info always buffered")
	assert.False(t, shouldBuffer(log.DebugLevel), "debug excluded when effective is info")

	SetLogging(log.DebugLevel)
	assert.True(t, shouldBuffer(log.DebugLevel), "debug included when effective is debug")
	assert.False(t, shouldBuffer(log.TraceLevel), "trace excluded when effective is debug")

	SetLogging(log.TraceLevel)
	assert.True(t, shouldBuffer(log.TraceLevel), "trace included when effective is trace")
}

// TestLogBuffer_CompressorSkipOnBacklog: with the compression queue
// perpetually blocked (no worker draining it), every finalized batch must
// remain Raw. TailSince still returns correct content because its decoder
// handles both states.
func TestLogBuffer_CompressorSkipOnBacklog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	buf := &LogRingBuffer{
		maxBytes:   1 << 20,
		batchLines: 2,
		pending:    &bytes.Buffer{},
		nextSeq:    1,
		formatter: &log.TextFormatter{
			DisableColors:          true,
			DisableLevelTruncation: true,
			FullTimestamp:          true,
		},
		compressQueue: make(chan *logRingBatch, 1),
		workerCtx:     ctx,
		workerCancel:  cancel,
	}
	t.Cleanup(cancel)

	// Fill the slot so every send-in-Fire selects the default branch.
	buf.compressQueue <- &logRingBatch{}

	for i := 0; i < 6; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("padded content line %d", i))
	}
	require.GreaterOrEqual(t, buf.BatchCount(), 1)
	// TailSince still returns intelligible content even though nothing
	// has been compressed.
	tail := buf.TailSince(0, 0)
	assert.Contains(t, string(tail.Content), "padded content")
}

// TestLogBuffer_TailSinceRoundTrips checks that TailSince content is
// consistent with what was fed in: firing N lines and requesting
// TailSince(0) yields exactly N newline-terminated lines with the source
// text embedded.
func TestLogBuffer_TailSinceRoundTrips(t *testing.T) {
	buf := newTestBuffer(t, 10, 1<<20)
	for i := 0; i < 25; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("line %02d marker", i))
	}
	require.Eventually(t, func() bool {
		// Wait for at least one batch to compress -- exercises the
		// decompress path inside TailSince.
		tail := buf.TailSince(0, 0)
		return bytes.Count(tail.Content, []byte("\n")) == 25
	}, time.Second, 5*time.Millisecond)

	tail := buf.TailSince(0, 0)
	for i := 0; i < 25; i++ {
		assert.Contains(t, string(tail.Content), fmt.Sprintf("line %02d marker", i),
			"TailSince(0) must include every fired line")
	}
	assert.Equal(t, int64(25), tail.LastSeq,
		"LastSeq must equal the seq of the newest line")
	assert.Equal(t, int64(1), tail.FirstSeq,
		"nothing has been evicted so FirstSeq matches the first-assigned seq")
}

// TestLogBuffer_TailSinceIsIncremental exercises the cursor semantics: a
// second TailSince call passing the first call's cursor must return only
// the lines emitted after the first call, and the cursor advances to the
// new newest seq.
func TestLogBuffer_TailSinceIsIncremental(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	for i := 0; i < 5; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("first-batch line %d", i))
	}
	first := buf.TailSince(0, 0)
	require.Equal(t, 5, bytes.Count(first.Content, []byte("\n")))
	require.Equal(t, int64(5), first.LastSeq)

	// Nothing new: same cursor in, empty content back.
	empty := buf.TailSince(first.LastSeq, 0)
	assert.Empty(t, empty.Content, "no new lines means empty content")
	assert.Equal(t, first.LastSeq, empty.LastSeq, "cursor stays put when nothing is new")

	// Fire more lines; second TailSince returns only the delta.
	for i := 0; i < 3; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("second-batch line %d", i))
	}
	second := buf.TailSince(first.LastSeq, 0)
	assert.Equal(t, 3, bytes.Count(second.Content, []byte("\n")),
		"only the 3 new lines should come back")
	assert.Contains(t, string(second.Content), "second-batch line 0")
	assert.NotContains(t, string(second.Content), "first-batch",
		"lines already delivered must not appear again")
	assert.Equal(t, int64(8), second.LastSeq)
}

// TestLogBuffer_TailSinceSkipsInsideBatch exercises the case where the
// caller's cursor falls in the middle of a finalized batch: TailSince
// must skip the already-seen prefix by walking newlines within the
// payload, not just returning the whole batch.
func TestLogBuffer_TailSinceSkipsInsideBatch(t *testing.T) {
	buf := newTestBuffer(t, 5, 1<<20)
	// Two full batches: seqs 1-5 and 6-10.
	for i := 0; i < 10; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("body-%02d", i+1))
	}
	require.Equal(t, 2, buf.BatchCount())

	// Cursor at seq 7 -- inside the second batch. Expect seqs 8, 9, 10.
	tail := buf.TailSince(7, 0)
	assert.Equal(t, 3, bytes.Count(tail.Content, []byte("\n")))
	assert.NotContains(t, string(tail.Content), "body-07",
		"the line already seen at the cursor must not be re-emitted")
	assert.Contains(t, string(tail.Content), "body-08")
	assert.Contains(t, string(tail.Content), "body-10")
	assert.Equal(t, int64(10), tail.LastSeq)
}

// TestLogBuffer_TailSincePendingOnly checks that TailSince includes lines
// in the pending buffer even before they've been finalized into a batch.
func TestLogBuffer_TailSincePendingOnly(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	for i := 0; i < 3; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("pending-only-%d", i))
	}
	assert.Equal(t, 0, buf.BatchCount(), "nothing finalized yet")
	assert.Equal(t, 3, buf.PendingLineCount())

	tail := buf.TailSince(0, 0)
	assert.Equal(t, 3, bytes.Count(tail.Content, []byte("\n")))
	assert.Contains(t, string(tail.Content), "pending-only-0")
	assert.Contains(t, string(tail.Content), "pending-only-2")
	assert.Equal(t, int64(3), tail.LastSeq)
}

// TestLogBuffer_TailSinceReportsEviction confirms that the oldest seq
// still visible via TailSince advances after eviction, so a caller
// resuming from a stale cursor sees the buffer's current window rather
// than duplicates.
func TestLogBuffer_TailSinceReportsEviction(t *testing.T) {
	buf := newTestBuffer(t, 5, 200)
	for round := 0; round < 20; round++ {
		for i := 0; i < 5; i++ {
			fire(t, buf, log.InfoLevel, strings.Repeat("filler ", 10))
		}
	}
	tail := buf.TailSince(0, 0)
	assert.Greater(t, tail.FirstSeq, int64(1),
		"FirstSeq must advance past 1 once early batches are evicted")
	assert.LessOrEqual(t, tail.FirstSeq, tail.LastSeq,
		"FirstSeq and LastSeq must be consistent (FirstSeq <= LastSeq)")
}

// TestLogBuffer_TailSinceHonorsLimit confirms that when the buffer
// contains far more lines than the caller's limit, TailSince drops the
// oldest and returns exactly `limit` newest lines. LastSeq stays at the
// buffer's newest and FirstSeq advances to reflect the truncated window
// so a subsequent scroll-up (TailBefore(FirstSeq)) picks up the dropped
// history.
func TestLogBuffer_TailSinceHonorsLimit(t *testing.T) {
	buf := newTestBuffer(t, 10, 1<<20)
	for i := 0; i < 100; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("body-%03d", i+1))
	}

	tail := buf.TailSince(0, 30)
	assert.Equal(t, 30, bytes.Count(tail.Content, []byte("\n")),
		"limit=30 must return exactly 30 lines")
	assert.Equal(t, int64(100), tail.LastSeq,
		"LastSeq must point at the newest fired line")
	assert.Equal(t, int64(71), tail.FirstSeq,
		"FirstSeq must advance to the first seq in the truncated window")
	assert.Contains(t, string(tail.Content), "body-071")
	assert.Contains(t, string(tail.Content), "body-100")
	assert.NotContains(t, string(tail.Content), "body-070",
		"lines older than the truncation must not appear in the response")

	// limit=0 must behave exactly like the pre-limit API -- return
	// everything held.
	full := buf.TailSince(0, 0)
	assert.Equal(t, 100, bytes.Count(full.Content, []byte("\n")))
	assert.Equal(t, int64(1), full.FirstSeq)
}

// TestLogBuffer_TailBeforeRoundsToBatch confirms that TailBefore returns
// whole batches even when the caller asks for fewer lines than the batch
// contains -- so the same batch is not decompressed twice as the user
// scrolls further backwards.
func TestLogBuffer_TailBeforeRoundsToBatch(t *testing.T) {
	buf := newTestBuffer(t, 10, 1<<20)
	// Three full batches of 10 lines each -- seqs 1-10, 11-20, 21-30.
	for i := 0; i < 30; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("body-%02d", i+1))
	}
	require.Equal(t, 3, buf.BatchCount())

	// Ask for just 3 lines before seq 21 (i.e. the seq range that opens
	// with the batch containing seqs 11-20). The server must round up to
	// the whole 10-line batch.
	tail := buf.TailBefore(21, 3)
	assert.Equal(t, 10, bytes.Count(tail.Content, []byte("\n")),
		"count is a hint; whole batches are the pagination unit")
	assert.Equal(t, int64(11), tail.FirstSeq)
	assert.Equal(t, int64(20), tail.LastSeq)
	assert.Contains(t, string(tail.Content), "body-11")
	assert.Contains(t, string(tail.Content), "body-20")
	assert.NotContains(t, string(tail.Content), "body-21",
		"batch straddling the cursor must be clipped to seq < before")
}

// TestLogBuffer_TailBeforeSpansMultipleBatches: when count exceeds one
// batch's worth, TailBefore accumulates whole batches oldest-side until
// the total covers the request.
func TestLogBuffer_TailBeforeSpansMultipleBatches(t *testing.T) {
	buf := newTestBuffer(t, 5, 1<<20)
	// Six batches of 5 lines each -- seqs 1-5, 6-10, ..., 26-30.
	for i := 0; i < 30; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("body-%02d", i+1))
	}
	require.Equal(t, 6, buf.BatchCount())

	// Ask for 12 lines before seq 31; expect 3 whole batches (seqs 16-30).
	tail := buf.TailBefore(31, 12)
	assert.Equal(t, 15, bytes.Count(tail.Content, []byte("\n")),
		"12-line request must round up to 3 whole 5-line batches (15 lines)")
	assert.Equal(t, int64(16), tail.FirstSeq)
	assert.Equal(t, int64(30), tail.LastSeq)
}

// TestLogBuffer_TailBeforePaginates: successive TailBefore calls anchored
// at the previous call's FirstSeq walk backwards batch-by-batch and
// eventually reach the wall (Reached == true).
func TestLogBuffer_TailBeforePaginates(t *testing.T) {
	buf := newTestBuffer(t, 5, 1<<20)
	for i := 0; i < 20; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("body-%02d", i+1))
	}
	require.Equal(t, 4, buf.BatchCount())

	seen := map[int64]bool{}
	before := int64(21) // "give me content older than the newest line"
	for step := 0; step < 10; step++ {
		tail := buf.TailBefore(before, 5)
		if len(tail.Content) == 0 {
			break
		}
		require.Greater(t, tail.LastSeq, int64(0))
		for seq := tail.FirstSeq; seq <= tail.LastSeq; seq++ {
			require.False(t, seen[seq], "TailBefore must not resend the same seq twice")
			seen[seq] = true
		}
		if tail.Reached {
			break
		}
		before = tail.FirstSeq
	}
	assert.Equal(t, 20, len(seen), "pagination must cover every seq 1..20 exactly once")
}

// TestLogBuffer_TailBeforePendingStraddle covers the unusual case where
// `before` falls inside the pending buffer: no batches have finalized
// yet and the caller asks for older content. TailBefore should return
// pending lines with seq < before.
func TestLogBuffer_TailBeforePendingStraddle(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	for i := 0; i < 5; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("pending-%d", i))
	}
	tail := buf.TailBefore(4, 10)
	// Lines with seq < 4 -- seqs 1, 2, 3.
	assert.Equal(t, 3, bytes.Count(tail.Content, []byte("\n")))
	assert.Contains(t, string(tail.Content), "pending-0")
	assert.Contains(t, string(tail.Content), "pending-2")
	assert.NotContains(t, string(tail.Content), "pending-3")
	assert.Equal(t, int64(1), tail.FirstSeq)
	assert.Equal(t, int64(3), tail.LastSeq)
}
