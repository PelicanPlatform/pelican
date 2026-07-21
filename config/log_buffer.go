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
	"crypto/rand"
	"encoding/hex"
	"io"
	"math"
	"sync"
	"sync/atomic"

	"github.com/pierrec/lz4/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

// LogRingBatchState marks whether a batch's payload has been LZ4-compressed
// yet. Uncompressed batches occur when the compression worker is behind the
// producer -- see LogRingBuffer.finalize.
type LogRingBatchState int

const (
	logRingBatchRaw        LogRingBatchState = iota // payload is stored uncompressed
	logRingBatchCompressed                          // payload is stored as LZ4 frame
)

// logRingBatch is one immutable slab of log lines held by LogRingBuffer.
// FirstSeq is the sequence number of the first line in the batch; combined
// with LineCount it identifies the seq range [FirstSeq, FirstSeq+LineCount)
// covered by the batch. The API layer never sees these -- callers use the
// TailSince cursor (an opaque seq) instead.
type logRingBatch struct {
	FirstSeq  int64
	LineCount int
	State     LogRingBatchState
	Payload   []byte // LZ4-compressed or raw depending on State
	RawSize   int    // decompressed byte count (matches on-disk text size)
}

// lastSeq is the sequence number of the last line in the batch (inclusive).
func (b *logRingBatch) lastSeq() int64 {
	return b.FirstSeq + int64(b.LineCount) - 1
}

// LogRingBuffer captures a bounded window of recent log lines in memory so
// a server admin can read them back through the web UI or the log-read API
// without having to shell in and tail the log file. The buffer is only
// activated inside a server process and it is entirely off when the client
// is running standalone.
//
// Every line is assigned a monotonic seq. Consumers page through the buffer
// with TailSince(since): everything with seq > since is returned. seq is
// opaque to consumers; the buffer's internal layout (batches, pending
// buffer, LZ4 compression) is not exposed.
type LogRingBuffer struct {
	// instanceID is a random hex token generated at StartLogRingBuffer.
	// It's returned on every read so a client watching this buffer can
	// tell when the server was restarted (the ID changes) and reset its
	// local state. Immutable after construction, so no lock needed.
	instanceID string

	mu              sync.Mutex
	maxBytes        int
	batchLines      int
	batches         []*logRingBatch
	total           int // sum of len(batch.Payload) across all batches; drives eviction
	pending         *bytes.Buffer
	pendingCount    int
	pendingFirstSeq int64 // seq of the first line in the current pending buffer (0 when empty)
	nextSeq         int64 // seq to assign to the next incoming line
	formatter       log.Formatter

	// The compression worker owns compressQueue exclusively; producers use a
	// non-blocking select-with-default so a slow compressor never blocks the
	// hot log path. When the send fails we mark the batch as Raw and skip
	// compression entirely -- exactly the behavior called for by the design.
	compressQueue chan *logRingBatch
	workerCtx     context.Context
	workerCancel  context.CancelFunc
	workerWG      sync.WaitGroup

	closed atomic.Bool
}

// globalLogBuffer is the process-wide ring installed via StartLogRingBuffer.
// Nil (via the atomic.Pointer zero value) until the server calls
// StartLogRingBuffer, and cleared in StopLogRingBuffer so tests and clean
// shutdowns don't leak the compression goroutine.
var globalLogBuffer atomic.Pointer[LogRingBuffer]

// GlobalLogRingBuffer returns the server-side log ring buffer if it has been
// installed. nil indicates "buffering is off".
func GlobalLogRingBuffer() *LogRingBuffer {
	return globalLogBuffer.Load()
}

// InstanceID returns the random token assigned when this buffer was
// started. Returns "" for a nil receiver so the API layer can serve
// disabled/uninstalled buffers uniformly.
func (b *LogRingBuffer) InstanceID() string {
	if b == nil {
		return ""
	}
	return b.instanceID
}

// StartLogRingBuffer wires the ring buffer into logrus and starts its
// background compression worker. Idempotent for repeat InitServer callers
// -- a second call finds the buffer already installed and returns. Not
// safe against concurrent callers; InitServer is invoked serially so we
// don't guard for that.
//
// ctx is the server-lifetime context; when it fires, the worker shuts down
// and any pending compression drains.
//
// The buffer's memory footprint is bounded by Logging.Buffer.MaxSize
// (default 1 MB) and the compression worker is a single goroutine that
// sleeps when idle.
func StartLogRingBuffer(ctx context.Context) {
	if existing := globalLogBuffer.Load(); existing != nil {
		return
	}

	// MaxSize is a human-readable byte-size string (e.g. "1MB", "512K") so
	// operators don't have to think in raw bytes. A malformed value falls
	// back to the 1 MiB default rather than refusing to install the buffer
	// -- log-viewer misconfiguration should not block server startup, and
	// the failure is logged so the operator sees it.
	const defaultMaxBytes = 1 << 20
	maxBytes := defaultMaxBytes
	if raw := param.Logging_Buffer_MaxSize.GetString(); raw != "" {
		parsed, err := utils.ParseBytes(raw)
		// The upper-bound check keeps the uint64→int conversion safe on
		// every platform: on 32-bit builds int is 31-bit signed, so
		// anything above ~2 GB would wrap; on 64-bit builds a value
		// with the top bit set (an operator setting "16EB") would go
		// negative. Refuse absurd sizes explicitly rather than
		// silently misinterpreting them.
		switch {
		case err != nil, parsed == 0:
			log.Warnf("invalid %s value %q; falling back to 1MB: %v",
				param.Logging_Buffer_MaxSize.GetName(), raw, err)
		case parsed > math.MaxInt:
			log.Warnf("%s value %q exceeds addressable range; falling back to 1MB",
				param.Logging_Buffer_MaxSize.GetName(), raw)
		default:
			maxBytes = int(parsed)
		}
	}
	batchLines := param.Logging_Buffer_BatchLines.GetInt()
	if batchLines <= 0 {
		batchLines = 10000
	}

	// 8 random bytes → 16 hex chars is plenty of uniqueness for restart
	// detection.
	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		// crypto/rand.Read can't actually fail on any platform we
		// support -- but if it does, fall back to a fixed marker
		// rather than blocking server startup.
		log.Warnf("log buffer: crypto/rand.Read failed: %v; instance ID will be static", err)
	}
	instanceID := hex.EncodeToString(idBytes[:])

	workerCtx, cancel := context.WithCancel(ctx)
	buf := &LogRingBuffer{
		instanceID: instanceID,
		maxBytes:   maxBytes,
		batchLines: batchLines,
		pending:    &bytes.Buffer{},
		// Seq numbering starts at 1 so a cursor of 0 means "give me everything
		// currently held".
		nextSeq: 1,
		// A private DisableColors formatter so buffered payloads never carry
		// ANSI escapes -- the viewer and gzip download stay diff-clean and
		// human-readable.
		formatter: &log.TextFormatter{
			DisableColors:          true,
			DisableLevelTruncation: true,
			FullTimestamp:          true,
		},
		// One-slot channel: if the compressor is still busy on the previous
		// batch when a new one is ready, the send fails and we skip
		// compression -- the "skip if backlogged" behavior called for by
		// the design.
		compressQueue: make(chan *logRingBatch, 1),
		workerCtx:     workerCtx,
		workerCancel:  cancel,
	}
	buf.workerWG.Add(1)
	go buf.compressLoop()

	globalLogBuffer.Store(buf)
	log.AddHook(&logRingBufferHook{buf: buf})
}

// StopLogRingBuffer detaches the ring buffer from logrus (best-effort --
// logrus does not expose per-hook removal, so we mark the buffer closed and
// its Fire becomes a no-op) and drains the compression worker. Safe to call
// multiple times.
func StopLogRingBuffer() {
	buf := globalLogBuffer.Swap(nil)
	if buf == nil {
		return
	}
	buf.closed.Store(true)
	buf.workerCancel()
	// Close the queue so the compress loop returns even if it happened to be
	// parked on <-buf.compressQueue between messages.
	close(buf.compressQueue)
	buf.workerWG.Wait()
}

// logRingBufferHook is the logrus hook that pumps entries into the buffer.
// Kept as a small stub struct so we can add/remove the hook via pointer
// identity without dragging LogRingBuffer's internals into logrus's hook
// interface.
type logRingBufferHook struct {
	buf *LogRingBuffer
}

// Levels returns every log level so the buffer sees the full stream. Actual
// level gating happens inside Fire so the buffer can decide to only buffer
// debug/trace when it is currently enabled.
func (h *logRingBufferHook) Levels() []log.Level {
	return log.AllLevels
}

func (h *logRingBufferHook) Fire(entry *log.Entry) error {
	return h.buf.Fire(entry)
}

// shouldBuffer implements the level gate:
//
//	info, warn, error, fatal, panic: always buffered
//	debug, trace:                    only when they are actually enabled
//
// The effective level comes from GetEffectiveLogLevel (which knows about
// the hook-based filtering initFilterLogging installs); logrus's own
// GetLevel is often pinned to TraceLevel so hooks see everything even when
// the operator asked for info-only output.
func shouldBuffer(level log.Level) bool {
	if level <= log.InfoLevel {
		return true
	}
	return level <= GetEffectiveLogLevel()
}

// Fire is the hot path for the buffer. It formats the entry, assigns a seq,
// appends it to the pending buffer, and finalizes when we hit batchLines.
// All serialization happens under buf.mu; compression itself runs in the
// worker goroutine so the caller returns promptly.
func (b *LogRingBuffer) Fire(entry *log.Entry) error {
	if b == nil || b.closed.Load() {
		return nil
	}
	if !shouldBuffer(entry.Level) {
		return nil
	}
	line, err := b.formatter.Format(entry)
	if err != nil {
		return errors.Wrap(err, "log buffer: formatting entry")
	}

	b.mu.Lock()
	seq := b.nextSeq
	b.nextSeq++
	if b.pendingCount == 0 {
		b.pendingFirstSeq = seq
	}
	b.pending.Write(line)
	b.pendingCount++

	if b.pendingCount >= b.batchLines {
		batch := b.finalizeLocked()
		b.batches = append(b.batches, batch)
		b.total += len(batch.Payload)
		// Try to hand the raw batch off for compression. A failed send means
		// the worker is still busy with the previous batch, so we skip
		// compression on this one and leave it Raw.
		select {
		case b.compressQueue <- batch:
		default:
		}
		b.evictLocked()
	}
	b.mu.Unlock()
	return nil
}

// finalizeLocked seals the pending buffer into a logRingBatch. Caller must
// hold b.mu.
func (b *LogRingBuffer) finalizeLocked() *logRingBatch {
	payload := make([]byte, b.pending.Len())
	copy(payload, b.pending.Bytes())
	batch := &logRingBatch{
		FirstSeq:  b.pendingFirstSeq,
		LineCount: b.pendingCount,
		State:     logRingBatchRaw,
		Payload:   payload,
		RawSize:   len(payload),
	}
	b.pending.Reset()
	b.pendingCount = 0
	b.pendingFirstSeq = 0
	return batch
}

// evictLocked drops the oldest batches until total <= maxBytes. The byte
// cap is a soft target: we never drop the last surviving batch. Under
// heavy write pressure with one very large batch, that means the buffer
// can hold more than maxBytes.
//
// Caller holds b.mu.
func (b *LogRingBuffer) evictLocked() {
	for b.total > b.maxBytes && len(b.batches) > 1 {
		oldest := b.batches[0]
		b.total -= len(oldest.Payload)
		b.batches = b.batches[1:]
	}
}

// compressLoop is the sole reader of compressQueue. It picks up one batch
// at a time, compresses it with LZ4, and swaps the compressed payload back
// into the batch in place. If the batch has been evicted while compression
// was running (possible under heavy load), the swap is a no-op.
func (b *LogRingBuffer) compressLoop() {
	defer b.workerWG.Done()
	for {
		select {
		case <-b.workerCtx.Done():
			return
		case batch, ok := <-b.compressQueue:
			if !ok {
				return
			}
			b.compressOne(batch)
		}
	}
}

func (b *LogRingBuffer) compressOne(batch *logRingBatch) {
	// Take a stable snapshot of the raw bytes without holding the mutex --
	// batch payloads are immutable after finalize (compressLoop is the only
	// writer of Payload) so a lock-free read is safe.
	raw := batch.Payload
	if raw == nil {
		return
	}
	var out bytes.Buffer
	w := lz4.NewWriter(&out)
	if _, err := w.Write(raw); err != nil {
		log.Debugln("log buffer: LZ4 write failed; leaving batch uncompressed:", err)
		return
	}
	if err := w.Close(); err != nil {
		log.Debugln("log buffer: LZ4 close failed; leaving batch uncompressed:", err)
		return
	}
	compressed := out.Bytes()

	// Build a REPLACEMENT batch rather than mutating `batch` in place.
	// Batches are treated as immutable once they land in b.batches, so a
	// reader that holds the original pointer (with or without the mutex)
	// sees a consistent Raw view -- fields never observe a partial
	// update.
	replacement := &logRingBatch{
		FirstSeq:  batch.FirstSeq,
		LineCount: batch.LineCount,
		State:     logRingBatchCompressed,
		Payload:   compressed,
		RawSize:   batch.RawSize,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	// Locate the batch by pointer identity. If it was evicted while we
	// were compressing, drop the compressed result on the floor.
	for i, existing := range b.batches {
		if existing == batch {
			b.total = b.total - len(batch.Payload) + len(compressed)
			b.batches[i] = replacement
			b.evictLocked()
			return
		}
	}
}

// LogTail is one page of TailSince / TailBefore output. Content is the
// raw log text (newline-terminated lines concatenated in seq order); the
// two seq fields describe the range covered by that content.
//
//   - FirstSeq is the oldest seq in Content; pass it back as the next
//     TailBefore call's `before` to page further backwards.
//   - LastSeq is the newest seq in Content; pass it back as the next
//     TailSince call's `since` to page forward.
//
// When Content is empty, both FirstSeq and LastSeq collapse to the
// caller's input cursor -- polling remains anchored at the same point.
//
// Reached is true when TailBefore has walked off the oldest line the
// buffer currently holds: FirstSeq == oldest-held seq at the time of the
// call, so a subsequent TailBefore with the same cursor would return
// nothing new. Callers use this to disable a "load older" affordance
// once history is exhausted.
type LogTail struct {
	Content  []byte
	FirstSeq int64
	LastSeq  int64
	Reached  bool
}

// TailSince returns lines held by the buffer with seq > since. A `since`
// of 0 (or any value below the oldest currently-held seq) yields the
// entire currently-held content. `limit` caps the number of lines
// returned; when the delta exceeds `limit`, the OLDEST lines are
// dropped and only the newest `limit` lines are returned (so a client
// resuming after a long absence still sees "the latest activity"
// without a mega-response). A `limit` of 0 or less means unbounded.
// The response is a single []byte -- newline-terminated log lines
// concatenated in seq order -- so the API layer can hand it straight
// to the wire.
func (b *LogRingBuffer) TailSince(since int64, limit int) LogTail {
	if b == nil {
		return LogTail{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	out := &bytes.Buffer{}
	firstSeqInContent := int64(-1)

	// Walk finalized batches in insertion order. Skip batches entirely
	// consumed by the caller; for a batch straddling `since`, drop the
	// already-seen prefix by counting newlines in the payload.
	for _, batch := range b.batches {
		if batch.lastSeq() <= since {
			continue
		}
		payload, err := decodeBatchPayload(batch)
		if err != nil {
			// A decompress failure on a batch we just stored is a
			// server-side bug rather than a caller problem; drop this
			// slab from the response instead of failing the whole call
			// so a corrupted batch doesn't blank the viewer.
			log.Debugln("log buffer: TailSince skipping unreadable batch:", err)
			continue
		}
		effectiveFirst := batch.FirstSeq
		if since >= batch.FirstSeq {
			// `since` is inside this batch: skip (since - FirstSeq + 1)
			// lines, keep the rest.
			skip := int(since - batch.FirstSeq + 1)
			payload = skipNLines(payload, skip)
			effectiveFirst = since + 1
		}
		if firstSeqInContent < 0 {
			firstSeqInContent = effectiveFirst
		}
		out.Write(payload)
	}

	// Pending buffer -- the tail that hasn't been finalized yet.
	if b.pendingCount > 0 {
		pendingLastSeq := b.pendingFirstSeq + int64(b.pendingCount) - 1
		if pendingLastSeq > since {
			payload := b.pending.Bytes()
			effectiveFirst := b.pendingFirstSeq
			if since >= b.pendingFirstSeq {
				skip := int(since - b.pendingFirstSeq + 1)
				payload = skipNLines(payload, skip)
				effectiveFirst = since + 1
			}
			if firstSeqInContent < 0 {
				firstSeqInContent = effectiveFirst
			}
			out.Write(payload)
		}
	}

	content := out.Bytes()
	newest := b.newestSeqLocked()

	// Apply the limit: if we've accumulated more than `limit` lines,
	// drop the OLDEST lines and advance firstSeqInContent accordingly.
	// This gives a client resuming from a stale cursor a bounded reply
	// focused on the most recent activity; the older lines they
	// technically requested can still be reached via TailBefore.
	if limit > 0 && firstSeqInContent >= 0 {
		totalLines := int(newest - firstSeqInContent + 1)
		if totalLines > limit {
			drop := totalLines - limit
			content = skipNLines(content, drop)
			firstSeqInContent += int64(drop)
		}
	}

	tail := LogTail{
		Content:  content,
		FirstSeq: since,
		LastSeq:  since,
	}
	if firstSeqInContent >= 0 {
		tail.FirstSeq = firstSeqInContent
	}
	if newest > since {
		tail.LastSeq = newest
	}
	// TailSince's `Reached` is meaningful only for the scroll-up path
	// (TailBefore), so leave it at its zero value here -- the forward
	// tail never runs out of "newer" history in a well-defined sense.
	return tail
}

// TailBefore returns log lines with seq < before, accumulating at least
// `count` lines by walking batches from newest to oldest. Whole batches
// are the unit of decompression: if a batch straddles the cursor, its
// trailing (already-seen) lines are trimmed but the rest of the batch's
// content is included in a single decompress. Subsequent TailBefore
// calls with a smaller `before` cursor never revisit the same batch, so
// the same LZ4 frame is decompressed at most once per scroll session.
//
// A `count` of 0 (or negative) uses the buffer's batchLines setting as
// the default, so the natural pagination unit is "one batch's worth" of
// history.
//
// FirstSeq in the response is the oldest seq included -- pass it back
// as the next TailBefore call's `before` to page further backwards.
// Reached is true when the returned content includes the oldest line the
// buffer currently holds; the caller can disable its scroll-up affordance
// at that point.
func (b *LogRingBuffer) TailBefore(before int64, count int) LogTail {
	if b == nil {
		return LogTail{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if count <= 0 {
		count = b.batchLines
	}

	// chunks are collected NEWEST-first (matching the reverse walk) and
	// reversed at the end for the wire, which stays oldest-first.
	type chunk struct {
		bytes    []byte
		firstSeq int64
		lines    int
	}
	var chunks []chunk
	totalLines := 0

	// Pending first (it lives at the newest end of the buffer). Only
	// relevant when `before` is high enough that any pending seq falls
	// under it -- unusual for a scroll-up call but correct if it happens.
	if b.pendingCount > 0 && b.pendingFirstSeq < before {
		pendingLastSeq := b.pendingFirstSeq + int64(b.pendingCount) - 1
		payload := append([]byte(nil), b.pending.Bytes()...)
		lines := b.pendingCount
		if pendingLastSeq >= before {
			keep := int(before - b.pendingFirstSeq)
			payload = takeFirstNLines(payload, keep)
			lines = keep
		}
		if lines > 0 {
			chunks = append(chunks, chunk{
				bytes:    payload,
				firstSeq: b.pendingFirstSeq,
				lines:    lines,
			})
			totalLines += lines
		}
	}

	// Now walk finalized batches newest-to-oldest until we've collected
	// at least `count` lines. Each batch is decompressed at most once.
	for i := len(b.batches) - 1; i >= 0 && totalLines < count; i-- {
		batch := b.batches[i]
		if batch.FirstSeq >= before {
			continue
		}
		payload, err := decodeBatchPayload(batch)
		if err != nil {
			log.Debugln("log buffer: TailBefore skipping unreadable batch:", err)
			continue
		}
		lines := batch.LineCount
		if batch.lastSeq() >= before {
			// Straddle: trim to lines with seq < before.
			keep := int(before - batch.FirstSeq)
			payload = takeFirstNLines(payload, keep)
			lines = keep
		}
		if lines <= 0 {
			continue
		}
		chunks = append(chunks, chunk{
			bytes:    payload,
			firstSeq: batch.FirstSeq,
			lines:    lines,
		})
		totalLines += lines
	}

	oldestHeld := b.oldestSeqLocked()
	tail := LogTail{
		FirstSeq: before,
		LastSeq:  before,
		// If the caller's cursor is already at (or below) the wall, the
		// caller has exhausted history even before we return anything.
		Reached: before <= oldestHeld,
	}
	if len(chunks) == 0 {
		return tail
	}
	// Emit chunks in oldest-first order (reverse of collection order).
	out := &bytes.Buffer{}
	for i := len(chunks) - 1; i >= 0; i-- {
		out.Write(chunks[i].bytes)
	}
	tail.Content = out.Bytes()
	tail.FirstSeq = chunks[len(chunks)-1].firstSeq
	// LastSeq of returned content is (before - 1) at most -- but if a
	// straddling chunk was trimmed, its last kept seq equals (before-1),
	// and non-straddling chunks span up to their batch's lastSeq. The
	// first chunk we collected (newest-side) carries the newest seq.
	newestChunk := chunks[0]
	tail.LastSeq = newestChunk.firstSeq + int64(newestChunk.lines) - 1
	// Reached: we walked back until FirstSeq is at (or below) the oldest
	// held line -- there's nothing older to fetch on the next call.
	tail.Reached = tail.FirstSeq <= oldestHeld
	return tail
}

// takeFirstNLines returns the first n newline-terminated lines from buf.
// If buf contains fewer than n lines, the whole slice is returned.
func takeFirstNLines(buf []byte, n int) []byte {
	idx := 0
	for k := 0; k < n && idx < len(buf); k++ {
		j := bytes.IndexByte(buf[idx:], '\n')
		if j < 0 {
			return buf
		}
		idx += j + 1
	}
	return buf[:idx]
}

// oldestSeqLocked returns the seq of the oldest line the buffer holds. When
// the buffer is empty, returns nextSeq so callers can detect "nothing to
// prune" by comparing against their own tracked oldest. Caller holds b.mu.
func (b *LogRingBuffer) oldestSeqLocked() int64 {
	if len(b.batches) > 0 {
		return b.batches[0].FirstSeq
	}
	if b.pendingCount > 0 {
		return b.pendingFirstSeq
	}
	return b.nextSeq
}

// newestSeqLocked returns the seq of the newest line the buffer holds, or
// 0 when the buffer is empty. Caller holds b.mu.
func (b *LogRingBuffer) newestSeqLocked() int64 {
	if b.pendingCount > 0 {
		return b.pendingFirstSeq + int64(b.pendingCount) - 1
	}
	if len(b.batches) > 0 {
		last := b.batches[len(b.batches)-1]
		return last.lastSeq()
	}
	return 0
}

// decodeBatchPayload returns a fresh copy of the batch's uncompressed
// bytes. Callers own the returned slice.
func decodeBatchPayload(batch *logRingBatch) ([]byte, error) {
	if batch.State == logRingBatchRaw {
		out := make([]byte, len(batch.Payload))
		copy(out, batch.Payload)
		return out, nil
	}
	r := lz4.NewReader(bytes.NewReader(batch.Payload))
	out := bytes.NewBuffer(make([]byte, 0, batch.RawSize))
	if _, err := io.Copy(out, r); err != nil {
		return nil, errors.Wrap(err, "log buffer: LZ4 decompress")
	}
	return out.Bytes(), nil
}

// skipNLines advances past the first n newline-terminated lines in buf and
// returns the trailing slice. If buf contains fewer than n lines, returns
// an empty slice. Log lines are always \n-terminated (the logrus text
// formatter appends one), so this is exact rather than heuristic.
func skipNLines(buf []byte, n int) []byte {
	for n > 0 && len(buf) > 0 {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			return nil
		}
		buf = buf[i+1:]
		n--
	}
	return buf
}

// StoredBytes returns the current byte total across all held batches. Not
// part of the public API; test-only.
func (b *LogRingBuffer) StoredBytes() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}

// BatchCount returns how many finalized batches are currently held. Not
// part of the public API; test-only.
func (b *LogRingBuffer) BatchCount() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.batches)
}

// PendingLineCount returns the number of lines currently in the pending
// buffer (not yet finalized into a batch). Test-only.
func (b *LogRingBuffer) PendingLineCount() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pendingCount
}
