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

// File sqlite_batcher.go is a write-behind transaction coalescer for
// the origin's SQLite handle. Callers submit either "durable" or
// "best-effort" SQL ops; a single goroutine drains the queue and
// commits batches as one transaction.
//
// Two batching dimensions:
//
//  1. **Time/size batching of best-effort ops.** Reduces fsync cost
//     for high-volume best-effort writes (Stat-detected external
//     observations, atime debouncer flushes, background checksum
//     recomputations). A flush fires whenever the buffer fills,
//     whenever the flush interval elapses, or whenever a durable
//     op arrives.
//
//  2. **Concurrent-op coalescing of durable ops.** If multiple
//     durable writes land in the buffer before the next flush, they
//     ride one transaction → one fsync. Each caller's `done`
//     channel still receives the per-op outcome.
//
// Overflow policy is **block**: when the enqueue channel is full,
// EnqueueBestEffort blocks until the flusher drains capacity. We
// deliberately do NOT drop observations — the user wants explicit
// back-pressure so a sustained burst is visible in Stat latency
// rather than silently lost.

package origin_serve

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// batchStmt is a single SQL statement to be executed.
type batchStmt struct {
	sql  string
	args []any
}

// batchOp is one queued unit of work. It may carry multiple
// statements that must execute together inside the same transaction
// (e.g. "INSERT history row" + "UPSERT live row" for a RecordCommit).
// If any statement in the list errors, the whole op rolls back —
// but the batch as a whole still rolls back, so the rest of the
// batch is also undone. Callers that don't want that fate-sharing
// should split into separate ops.
type batchOp struct {
	stmts []batchStmt
	// done is non-nil for durable ops. The flusher closes / sends
	// on it with the per-op error after the COMMIT returns. nil
	// for best-effort ops — the caller has already moved on.
	done chan error
	// durable indicates the op should force an immediate flush.
	durable bool
}

// sqliteBatcher coalesces writes against a single GORM DB handle. A
// single flusher goroutine reads from the buffered channel and
// commits batches.
type sqliteBatcher struct {
	db            *gorm.DB
	ch            chan *batchOp
	flushInterval time.Duration

	// txTimeout caps each db.Transaction call inside flush(). If
	// the underlying DB hangs (lock storm, full disk, NFS stall),
	// the flusher would otherwise wedge indefinitely with every
	// caller blocked behind it. A per-flush ctx with this timeout
	// turns "DB hung" into "every op in the batch gets a
	// timeout error and the flusher moves on."
	//
	// Default is 30s, set by newSQLiteBatcher. Tests can override
	// via SetTxTimeout.
	txTimeout time.Duration

	// metrics hooks (nil-tolerant)
	hooks BatcherHooks

	wg     sync.WaitGroup
	cancel context.CancelFunc

	// enqueueWG tracks callers that have passed the closed-check
	// but have not yet completed their send onto `ch`. Stop()
	// waits for it to reach zero *before* cancelling the flusher,
	// guaranteeing every op a caller successfully started enqueuing
	// either lands in the flusher's drain pass OR fails with a
	// caller-side error (closed batcher / ctx cancellation).
	// Without this, a race between "caller about to send" and
	// "flusher draining the channel and exiting" could leave a
	// durable op stranded with no one to ack its done channel.
	enqueueWG sync.WaitGroup

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

// BatcherHooks lets the metrics package observe batcher activity
// without the batcher importing prometheus.
type BatcherHooks struct {
	// IncFlush is called once per successful or failed COMMIT. The
	// `size` is the number of ops in the batch.
	IncFlush func(size int)
	// IncError is called once per failed COMMIT. (Each failed op
	// also reports its own error via its `done` channel.)
	IncError func()
	// ObserveBatchAge records how long the oldest op waited from
	// enqueue to flush.
	ObserveBatchAge func(d time.Duration)
	// ObserveEnqueueWait is called only when an Enqueue had to
	// block on the channel send (i.e., the in-memory buffer was
	// full). The `durability` label is "durable" or "best_effort".
	// A non-zero count here means callers are paying real
	// back-pressure latency; operators should bump
	// Origin.Metadata.BatchBufferSize.
	ObserveEnqueueWait func(durability string, d time.Duration)
}

// newSQLiteBatcher constructs a batcher and starts its flusher
// goroutine. Caller must invoke Stop() to drain and shut down.
//
// `bufferSize` is the depth of the in-memory channel. When full,
// EnqueueBestEffort blocks the calling goroutine until the flusher
// makes room. `flushInterval` is the maximum age of a best-effort
// op before it is forced to disk.
func newSQLiteBatcher(ctx context.Context, db *gorm.DB, bufferSize int, flushInterval time.Duration) *sqliteBatcher {
	if bufferSize <= 0 {
		bufferSize = 256
	}
	if flushInterval <= 0 {
		flushInterval = 50 * time.Millisecond
	}
	childCtx, cancel := context.WithCancel(ctx)
	b := &sqliteBatcher{
		db:            db,
		ch:            make(chan *batchOp, bufferSize),
		flushInterval: flushInterval,
		txTimeout:     30 * time.Second,
		cancel:        cancel,
	}
	b.wg.Add(1)
	go b.run(childCtx)
	return b
}

// SetHooks wires metrics callbacks. Safe to call once at startup; not
// safe for concurrent reconfiguration.
func (b *sqliteBatcher) SetHooks(h BatcherHooks) { b.hooks = h }

// SetTxTimeout overrides the per-flush transaction timeout. Intended
// for tests; production callers should leave the default in place.
// A value <= 0 disables the timeout (the flush ctx is the parent
// ctx, which is only cancelled at Stop time).
func (b *sqliteBatcher) SetTxTimeout(d time.Duration) { b.txTimeout = d }

// FlushNow forces a synchronous flush of any pending ops and returns
// only after the resulting transaction has committed (or errored).
// Implementation: enqueue a sentinel durable op with no statements.
// The flusher's "durable arrived → flush immediately" rule fires;
// the sentinel rides the same transaction as any best-effort ops
// already queued ahead of it; the sentinel's `done` channel ack's
// after the commit.
//
// Use this in tests instead of the older `EnqueueDurable(ctx, "SELECT 1")`
// idiom — it's clearer at the call site and doesn't muddy the SQL log.
// Production callers shouldn't need it; the default flush cadence
// covers the hot path.
func (b *sqliteBatcher) FlushNow(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.beginEnqueue(); err != nil {
		return err
	}
	op := &batchOp{
		// Empty stmts: the flusher's per-op loop iterates zero
		// times, so this op contributes nothing to the SQL the
		// transaction executes. Its done channel still gets
		// ack'd when the surrounding batch commits.
		done:    make(chan error, 1),
		durable: true,
	}
	sendErr := b.sendWithWaitMetric(ctx, op, "durable")
	b.enqueueWG.Done()
	if sendErr != nil {
		return sendErr
	}
	select {
	case err := <-op.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// BatchedStmt is the public alias the DAO uses to compose a
// multi-statement op via EnqueueDurableBatch / EnqueueBestEffortBatch.
type BatchedStmt struct {
	SQL  string
	Args []any
}

// EnqueueDurableBatch is the multi-statement sibling of
// EnqueueDurable. All statements run inside one transaction; on any
// statement error, the entire batch rolls back and the caller sees
// that statement's error. Useful for things like
// "INSERT history row + UPSERT live row" where partial application
// is meaningless.
func (b *sqliteBatcher) EnqueueDurableBatch(ctx context.Context, stmts []BatchedStmt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := b.beginEnqueue(); err != nil {
		return err
	}
	op := &batchOp{
		stmts:   convertStmts(stmts),
		done:    make(chan error, 1),
		durable: true,
	}
	sendErr := b.sendWithWaitMetric(ctx, op, "durable")
	b.enqueueWG.Done()
	if sendErr != nil {
		return sendErr
	}
	select {
	case err := <-op.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// EnqueueBestEffortBatch is the multi-statement sibling of
// EnqueueBestEffort. Same fate-sharing semantics as
// EnqueueDurableBatch: all statements or none.
func (b *sqliteBatcher) EnqueueBestEffortBatch(ctx context.Context, stmts []BatchedStmt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(stmts) == 0 {
		return nil
	}
	if err := b.beginEnqueue(); err != nil {
		return err
	}
	op := &batchOp{stmts: convertStmts(stmts)}
	sendErr := b.sendWithWaitMetric(ctx, op, "best_effort")
	b.enqueueWG.Done()
	return sendErr
}

func convertStmts(in []BatchedStmt) []batchStmt {
	out := make([]batchStmt, len(in))
	for i, s := range in {
		out[i] = batchStmt{sql: s.SQL, args: s.Args}
	}
	return out
}

// EnqueueDurable submits one statement and blocks until the
// containing transaction has committed. Returns the COMMIT error (or
// the Exec error, if the statement itself failed). The op
// participates in a coalesced batch with any other ops the flusher
// has buffered at the moment of the next flush.
func (b *sqliteBatcher) EnqueueDurable(ctx context.Context, stmt string, args ...any) error {
	// If the caller's context is already done, bail before doing
	// anything else. Go's select { case ch<-x; case <-done } picks
	// fairly when both are ready, so without this explicit check a
	// cancelled-ctx + room-in-buffer caller might still see their
	// op enqueued.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.beginEnqueue(); err != nil {
		return err
	}
	op := &batchOp{
		stmts:   []batchStmt{{sql: stmt, args: args}},
		done:    make(chan error, 1),
		durable: true,
	}
	sendErr := b.sendWithWaitMetric(ctx, op, "durable")
	// Release the enqueue-in-flight count as soon as either the
	// send landed or the caller bailed. Stop() can now safely
	// cancel the flusher; if we did land the op, it's in the
	// channel and will be picked up by the drain pass.
	b.enqueueWG.Done()
	if sendErr != nil {
		return sendErr
	}
	select {
	case err := <-op.done:
		return err
	case <-ctx.Done():
		// The op may still complete in the background; we
		// surface ctx.Err() to the caller but the row may still
		// end up persisted.
		return ctx.Err()
	}
}

// beginEnqueue is the locked-once entry-point shared by every
// Enqueue variant. It atomically checks the closed flag and bumps
// the in-flight counter so Stop() can't race ahead and start
// cancelling the flusher while a sender is mid-Add.
func (b *sqliteBatcher) beginEnqueue() error {
	b.closeMu.Lock()
	if b.closed {
		err := b.closeErr
		b.closeMu.Unlock()
		if err == nil {
			err = errors.New("sqlite batcher: already closed")
		}
		return err
	}
	b.enqueueWG.Add(1)
	b.closeMu.Unlock()
	return nil
}

// sendWithWaitMetric tries a non-blocking channel send first; if
// the buffer is full it falls back to a blocking send and times the
// wait, reporting it via ObserveEnqueueWait. This is how we surface
// "the batcher buffer is undersized" to operators without adding
// latency to the happy path.
func (b *sqliteBatcher) sendWithWaitMetric(ctx context.Context, op *batchOp, durability string) error {
	// Happy path: buffer has room, send is instant.
	select {
	case b.ch <- op:
		return nil
	default:
	}
	// Slow path: time the wait so a non-zero ObserveEnqueueWait
	// histogram count tells operators back-pressure fired.
	waitStart := time.Now()
	select {
	case b.ch <- op:
		if b.hooks.ObserveEnqueueWait != nil {
			b.hooks.ObserveEnqueueWait(durability, time.Since(waitStart))
		}
		return nil
	case <-ctx.Done():
		if b.hooks.ObserveEnqueueWait != nil {
			b.hooks.ObserveEnqueueWait(durability, time.Since(waitStart))
		}
		return ctx.Err()
	}
}

// EnqueueBestEffort submits one statement that may complete
// asynchronously. The caller does not wait for the COMMIT. If the
// channel is full this *blocks* until the flusher makes room — the
// design call was explicit (no silent drops).
//
// Pass a cancellable ctx if the caller wants to abandon the enqueue
// instead of back-pressuring on the batcher.
func (b *sqliteBatcher) EnqueueBestEffort(ctx context.Context, stmt string, args ...any) error {
	// See EnqueueDurable: explicit pre-check so cancelled-ctx
	// callers bail deterministically rather than racing the chan
	// send.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.beginEnqueue(); err != nil {
		return err
	}
	op := &batchOp{stmts: []batchStmt{{sql: stmt, args: args}}}
	sendErr := b.sendWithWaitMetric(ctx, op, "best_effort")
	b.enqueueWG.Done()
	return sendErr
}

// Stop drains pending ops with a final flush and waits for the
// flusher goroutine to exit. Safe to call more than once.
//
// Shutdown order:
//  1. Set closed under closeMu. Subsequent enqueue calls see the
//     flag and bail with "already closed" before bumping the
//     in-flight counter.
//  2. Wait for the in-flight counter to drain. Any caller that
//     passed the closed-check before we set the flag is allowed
//     to complete its send onto the channel.
//  3. Cancel the flusher's ctx. The flusher's drain loop reads
//     every op left in the channel (including the ones from
//     step 2) and flushes one final batch.
//  4. Wait for the flusher to exit.
//
// This ordering means: any op a caller successfully began enqueueing
// either lands in the final flush OR fails with a send-time error
// (ctx cancellation). No durable op gets stranded with no flusher
// to ack its done channel.
func (b *sqliteBatcher) Stop() {
	b.closeMu.Lock()
	if b.closed {
		b.closeMu.Unlock()
		b.wg.Wait()
		return
	}
	b.closed = true
	b.closeMu.Unlock()
	b.enqueueWG.Wait()
	b.cancel()
	b.wg.Wait()
}

// run is the flusher goroutine. It pulls ops off the channel and
// builds a batch, flushing on:
//   - durable op arrived
//   - flush interval elapsed
//   - channel reads N back-to-back (size cap to bound tx size)
//   - context cancelled (graceful shutdown: final flush)
func (b *sqliteBatcher) run(ctx context.Context) {
	defer b.wg.Done()
	const maxBatchSize = 1024 // hard upper bound; protects WAL

	var (
		batch []*batchOp
		timer *time.Timer
	)
	timerC := func() <-chan time.Time {
		if timer == nil {
			return nil
		}
		return timer.C
	}
	armTimer := func() {
		if timer != nil {
			return
		}
		timer = time.NewTimer(b.flushInterval)
	}
	disarmTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer = nil
	}

	for {
		select {
		case <-ctx.Done():
			// Drain whatever is in the channel and do a final
			// flush. We loop with a non-blocking read until the
			// channel is empty.
		Draining:
			for {
				select {
				case op := <-b.ch:
					batch = append(batch, op)
				default:
					break Draining
				}
			}
			if len(batch) > 0 {
				b.flush(batch)
				batch = nil
			}
			disarmTimer()
			return

		case op := <-b.ch:
			batch = append(batch, op)
			// Opportunistic drain: pull any other ops already in
			// the channel into this batch *without blocking*. This
			// is what gives us cross-goroutine durable coalescing —
			// when many concurrent callers race to EnqueueDurable
			// they all land in one transaction.
			hasDurable := op.durable
		DrainNonBlock:
			for len(batch) < maxBatchSize {
				select {
				case more := <-b.ch:
					batch = append(batch, more)
					if more.durable {
						hasDurable = true
					}
				default:
					break DrainNonBlock
				}
			}
			if hasDurable || len(batch) >= maxBatchSize {
				disarmTimer()
				b.flush(batch)
				batch = nil
			} else {
				armTimer()
			}

		case <-timerC():
			timer = nil
			if len(batch) > 0 {
				b.flush(batch)
				batch = nil
			}
		}
	}
}

// flush commits a transaction containing every op in `batch`. Each
// op's `done` channel receives the per-op outcome — either the
// per-statement Exec error, or the transaction-level COMMIT error
// if Exec succeeded but COMMIT failed.
func (b *sqliteBatcher) flush(batch []*batchOp) {
	if len(batch) == 0 {
		return
	}
	enqueuedAt := time.Now()

	// Per-op exec error captured here; commit error propagated to
	// every op afterwards.
	execErrs := make([]error, len(batch))

	// Per-flush context with a timeout. If the underlying DB
	// hangs (lock storm, full disk, NFS stall), the Transaction
	// call would otherwise wedge forever and every caller
	// behind us would block on op.done. A non-zero txTimeout
	// turns that into "the batch fails with ctx.DeadlineExceeded
	// and every op sees the timeout error" — the flusher moves on
	// and subsequent batches get a fresh attempt.
	txCtx := context.Background()
	var cancelTx context.CancelFunc
	if b.txTimeout > 0 {
		txCtx, cancelTx = context.WithTimeout(context.Background(), b.txTimeout)
		defer cancelTx()
	}
	commitErr := b.db.WithContext(txCtx).Transaction(func(tx *gorm.DB) error {
		for i, op := range batch {
			for _, s := range op.stmts {
				if err := tx.Exec(s.sql, s.args...).Error; err != nil {
					// Capture and fate-share with the rest of
					// the batch: returning here rolls back the
					// transaction. The per-op done channels all
					// receive the surviving error below.
					execErrs[i] = err
					return err
				}
			}
		}
		return nil
	})

	if commitErr != nil && b.hooks.IncError != nil {
		b.hooks.IncError()
	}
	if b.hooks.IncFlush != nil {
		b.hooks.IncFlush(len(batch))
	}
	if b.hooks.ObserveBatchAge != nil {
		b.hooks.ObserveBatchAge(time.Since(enqueuedAt))
	}

	for i, op := range batch {
		if op.done == nil {
			// Best-effort op: log the per-op exec error (the
			// caller asked not to be told).
			if e := opErr(execErrs[i], commitErr); e != nil {
				log.Debugf("sqlite batcher: best-effort op %d failed: %v", i, e)
			}
			continue
		}
		op.done <- opErr(execErrs[i], commitErr)
		close(op.done)
	}
}

// opErr picks the most specific error for an op: its own exec error
// if any, otherwise the batch-level commit error.
func opErr(execErr, commitErr error) error {
	if execErr != nil {
		return execErr
	}
	return commitErr
}
