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
	"sync"
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

// fireAt feeds an entry stamped with a caller-chosen time, so a test can
// assert on the buffer's reported span rather than on wall-clock timing.
func fireAt(t *testing.T, buf *LogRingBuffer, when time.Time, msg string) {
	t.Helper()
	entry := log.NewEntry(log.StandardLogger())
	entry.Level = log.InfoLevel
	entry.Message = msg
	entry.Time = when
	require.NoError(t, buf.Fire(entry))
}

// TestLogBuffer_SpanSurvivesCompression is the regression guard for the field
// copy in compressOne: that function replaces the batch it compresses instead
// of mutating it, so a field it forgets to carry across is lost within
// milliseconds of the batch being sealed -- long before any operator reads it.
// The test therefore waits for compression to have actually happened rather
// than reading the span straight after the seal.
func TestLogBuffer_SpanSurvivesCompression(t *testing.T) {
	buf := newTestBuffer(t, 5, 1<<20)
	first := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		fireAt(t, buf, first.Add(time.Duration(i)*time.Minute), fmt.Sprintf("line %d", i))
	}
	require.Equal(t, 1, buf.BatchCount(), "five lines at batchLines=5 seal one batch")
	require.Eventually(t, func() bool { return buf.CompressedBatchCount() == 1 },
		2*time.Second, 5*time.Millisecond, "the worker should compress the sealed batch")

	oldest, newest, ok := buf.Span()
	require.True(t, ok, "a buffer holding dated lines must report a span")
	assert.True(t, oldest.Equal(first), "oldest must be the first line's time, got %v", oldest)
	assert.True(t, newest.Equal(first.Add(4*time.Minute)),
		"newest must be the last line's time, got %v", newest)
}

// TestLogBuffer_SpanCoversPendingLines covers the other end: lines that have
// not been sealed into a batch are held just as much as batched ones, and on a
// quiet server they are all there is.
func TestLogBuffer_SpanCoversPendingLines(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	first := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	fireAt(t, buf, first, "only line")
	fireAt(t, buf, first.Add(time.Minute), "second line")
	require.Equal(t, 0, buf.BatchCount(), "batchLines=100 keeps these pending")

	oldest, newest, ok := buf.Span()
	require.True(t, ok)
	assert.True(t, oldest.Equal(first))
	assert.True(t, newest.Equal(first.Add(time.Minute)))
}

// TestLogBuffer_SpanFollowsEviction confirms the span describes what is still
// held rather than what was ever written: the oldest end has to advance as
// batches are evicted, or the viewer would offer a download of history the
// buffer no longer has.
func TestLogBuffer_SpanFollowsEviction(t *testing.T) {
	buf := newTestBuffer(t, 5, 300)
	first := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		fireAt(t, buf, first.Add(time.Duration(i)*time.Minute),
			fmt.Sprintf("line %d with enough text to fill the cap", i))
	}
	require.Less(t, buf.BatchCount(), 20, "the cap must have evicted early batches")

	oldest, _, ok := buf.Span()
	require.True(t, ok)
	assert.True(t, oldest.After(first),
		"the oldest end must advance past evicted lines, got %v", oldest)
}

// TestLogBuffer_SpanIgnoresUndatedLines covers an entry constructed without a
// time -- not something logrus itself produces, but the zero value is what a
// hand-built entry carries. One undated line must not blank the range, and a
// buffer of nothing but undated lines must report no range at all rather than
// year zero.
func TestLogBuffer_SpanIgnoresUndatedLines(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	dated := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	fireAt(t, buf, dated, "dated line")
	fireAt(t, buf, time.Time{}, "undated line")

	oldest, newest, ok := buf.Span()
	require.True(t, ok, "one undated line must not suppress the whole span")
	assert.True(t, oldest.Equal(dated))
	assert.True(t, newest.Equal(dated), "the undated line must not become the newest end")

	empty := newTestBuffer(t, 100, 1<<20)
	fireAt(t, empty, time.Time{}, "undated only")
	_, _, ok = empty.Span()
	assert.False(t, ok, "a buffer with nothing datable reports no span")
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

	// A limit of 0 means unbounded: everything held is returned.
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

// Detaching the buffer rebuilds logrus's global hook set, as does every
// level change. Both are read-modify-write over the same global, so they
// have to be serialized: an interleaving drops whichever set was written
// first, which would silently take the log file's writer hook with it.
func TestLogBuffer_StopIsSafeAgainstConcurrentLevelChanges(t *testing.T) {
	prev := GetEffectiveLogLevel()
	t.Cleanup(func() {
		StopLogRingBuffer()
		SetLogging(prev)
	})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if i%2 == 0 {
					StartLogRingBuffer(context.Background())
					StopLogRingBuffer()
				} else {
					SetLogging(log.InfoLevel)
					SetLogging(log.DebugLevel)
				}
			}
		}(i)
	}
	wg.Wait()

	// The censor must still be installed: losing it is the failure this
	// guards against, and it is the hook that writes the log file.
	StartLogRingBuffer(context.Background())
	log.Info("after concurrent teardown")
	assert.NotNil(t, GlobalLogRingBuffer(), "the buffer should be installed")
}

// A client polling with a cursor whose lines have since been evicted must be
// told how many it missed. Cursors are opaque, so this is the only way it can
// distinguish "nothing has happened" from "the server outran me".
func TestLogBuffer_ReportsEvictedLinesAsDropped(t *testing.T) {
	buf := newTestBuffer(t, 5, 200)
	for i := 0; i < 5; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("early line %d", i))
	}
	// Read once so we hold a realistic cursor, then outrun it by enough to
	// force eviction of everything it covered.
	cursor := buf.TailSince(0, 0).LastSeq
	require.Greater(t, cursor, int64(0))
	for i := 0; i < 100; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("later line %d with filler text", i))
	}

	tail := buf.TailSince(cursor, 0)
	assert.Positive(t, tail.Dropped, "eviction past the caller's cursor must be reported")
	assert.Equal(t, tail.FirstSeq-cursor-1, tail.Dropped,
		"the count must be exactly the seq range missing between the cursor and the content")
}

// Trimming to `limit` also leaves a hole, and the caller has to be able to
// tell -- otherwise a bounded initial load looks like the whole history.
func TestLogBuffer_ReportsLimitTrimAsDropped(t *testing.T) {
	buf := newTestBuffer(t, 1000, 1<<20)
	for i := 0; i < 100; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("line %d", i))
	}

	tail := buf.TailSince(0, 10)
	assert.Equal(t, 10, bytes.Count(tail.Content, []byte("\n")))
	assert.Equal(t, int64(90), tail.Dropped, "the 90 trimmed lines must be reported")
}

// A caller that is keeping up sees no gap, so the viewer must not show a
// break in an unbroken stream.
func TestLogBuffer_NoDropReportedWhenCallerKeepsUp(t *testing.T) {
	buf := newTestBuffer(t, 1000, 1<<20)
	for i := 0; i < 10; i++ {
		fire(t, buf, log.InfoLevel, fmt.Sprintf("line %d", i))
	}
	cursor := buf.TailSince(0, 0).LastSeq

	// An idle poll, then a poll that picks up new lines: neither is a gap.
	assert.Zero(t, buf.TailSince(cursor, 0).Dropped)
	fire(t, buf, log.InfoLevel, "fresh line")
	tail := buf.TailSince(cursor, 0)
	assert.Zero(t, tail.Dropped)
	assert.Contains(t, string(tail.Content), "fresh line")

	// A first load (no cursor) is not a gap either: the caller never had
	// the older lines to lose.
	assert.Zero(t, buf.TailSince(0, 0).Dropped)
}

// Fire runs on every log line in the process while readers serve the log-read
// API concurrently, so the two paths must be safe together and reads must not
// hold the buffer's mutex across their decompression work.
func TestLogBuffer_ConcurrentFireAndTail(t *testing.T) {
	buf := newTestBuffer(t, 50, 64<<10)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				fire(t, buf, log.InfoLevel, fmt.Sprintf("writer-%d-line-%d", id, i))
			}
		}(w)
	}
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				buf.TailSince(0, 100)
				buf.TailBefore(buf.TailSince(0, 0).LastSeq, 20)
			}
		}()
	}

	// Readers run until the writers are done, then drain.
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(stop)
	}()
	wg.Wait()

	assert.LessOrEqual(t, buf.StoredBytes()+buf.PendingBytes(), 2*(64<<10),
		"concurrent writers must not push the buffer past its budget")
}

// The web server logs every request path at Info, including for requests that
// match no route, so line content and line length are both attacker-chosen.
// Memory must stay bounded by Logging.Buffer.MaxSize no matter how few lines
// it takes to get there -- eviction works in whole batches, so a pending
// buffer that only seals on a line count never reclaims anything.
func TestLogBuffer_BoundedByMaxSizeWithLongLines(t *testing.T) {
	const maxBytes = 1 << 20
	// Production defaults: a line budget high enough that byte pressure
	// arrives long before the line counter would seal a batch.
	buf := newTestBuffer(t, 10000, maxBytes)

	huge := strings.Repeat("A", 500<<10)
	for i := 0; i < 200; i++ {
		fire(t, buf, log.InfoLevel, huge)
	}

	held := buf.StoredBytes() + buf.PendingBytes()
	assert.LessOrEqual(t, held, 2*maxBytes,
		"the buffer must stay near its configured cap regardless of line length")
}

// A single over-long line must not be able to flush every other line out of
// the buffer, which would let a caller erase recent history on demand.
func TestLogBuffer_TruncatesOverlongLines(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	fire(t, buf, log.InfoLevel, "keep-me")
	fire(t, buf, log.InfoLevel, strings.Repeat("B", 1<<20))

	content := buf.TailSince(0, 0).Content
	assert.Contains(t, string(content), "keep-me",
		"an over-long line should not evict the lines around it")
	assert.Contains(t, string(content), "...[truncated]")
	// Line-oriented paging depends on every stored line ending in a newline.
	assert.Equal(t, 2, bytes.Count(content, []byte("\n")))
	assert.Less(t, len(content), 2*maxBufferedLineBytes)
}

// sampleBearerToken is shaped to satisfy bearerTokenRegexStr: two "ey"-prefixed
// segments of at least 18 characters and a signature of at least 64.
const sampleBearerToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiJ1c2VyMSIsInNjb3BlIjoic3RvcmFnZS5yZWFkOi8ifQ." +
	"c2lnbmF0dXJlYnl0ZXNjMmxuYm1GMGRYSmxZbmwwWlhOemFXZHVZWFIxY21WaWVYUmxjdw"

// The buffer is readable by anyone holding pelican.log_read, a lesser
// privilege than admin, so it must not retain credentials the on-disk log
// censors. XRootD's forwarded output carries these tokens as query
// parameters, and the signature is the part that makes a token replayable.
func TestLogBuffer_RedactsBearerTokensInMessage(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	fire(t, buf, log.InfoLevel,
		"XrdPfc_Cache: info Attach() pelican://example.com/foo?&authz=Bearer%20"+sampleBearerToken)

	content := string(buf.TailSince(0, 0).Content)
	assert.NotContains(t, content, sampleBearerToken)
	assert.Contains(t, content, "REDACTED")
	// The header and payload survive: they identify the issuer and subject,
	// which is what makes a censored log useful for triage.
	assert.Contains(t, content, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9")
}

// The censor rewrites the "url" field as well as the message, so the buffer
// must cover both.
func TestLogBuffer_RedactsBearerTokensInURLField(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	entry := log.NewEntry(log.StandardLogger())
	entry.Level = log.InfoLevel
	entry.Time = time.Now()
	entry.Message = "GET"
	entry.Data = log.Fields{"url": "https://example.com/f?authz=Bearer%20" + sampleBearerToken}
	require.NoError(t, buf.Fire(entry))

	content := string(buf.TailSince(0, 0).Content)
	assert.NotContains(t, content, sampleBearerToken)
	assert.Contains(t, content, "REDACTED")
}

// Redaction must not disturb the entry logrus goes on to hand the remaining
// hooks; the buffer censors a copy.
func TestLogBuffer_RedactionLeavesCallerEntryIntact(t *testing.T) {
	buf := newTestBuffer(t, 100, 1<<20)
	raw := "authz=Bearer%20" + sampleBearerToken
	entry := log.NewEntry(log.StandardLogger())
	entry.Level = log.InfoLevel
	entry.Time = time.Now()
	entry.Message = raw
	entry.Data = log.Fields{"url": "https://example.com/?" + raw}
	require.NoError(t, buf.Fire(entry))

	assert.Equal(t, raw, entry.Message)
	assert.Equal(t, "https://example.com/?"+raw, entry.Data["url"])
}
