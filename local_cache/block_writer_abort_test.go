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

package local_cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/VividCortex/ewma"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/error_codes"
)

// tornBlockEnv is a storage manager holding one empty disk object of
// tornObjectBlocks blocks, ready to be filled by a BlockWriter.
type tornBlockEnv struct {
	db      *CacheDB
	storage *StorageManager
	hash    InstanceHash
	data    []byte
}

const tornObjectBlocks = 8

func newTornBlockEnv(t *testing.T, contentLength int64) *tornBlockEnv {
	t.Helper()
	InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tmpDir := t.TempDir()
	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(func() { storage.Close() })
	var diskID StorageID
	for id := range storage.GetDirs() {
		diskID = id
	}

	env := &tornBlockEnv{db: db, storage: storage, hash: InstanceHash(fmt.Sprintf("%064d", 7))}
	env.data = make([]byte, tornObjectBlocks*BlockDataSize-17) // last block short
	for i := range env.data {
		env.data[i] = byte(i % 253)
	}
	_, err = storage.InitDiskStorage(ctx, env.hash, contentLength, diskID, 1)
	require.NoError(t, err)
	return env
}

// presentBlocks reports which blocks the database says are downloaded.
func (e *tornBlockEnv) presentBlocks(t *testing.T) []uint32 {
	t.Helper()
	bm, err := e.db.GetBlockState(e.hash)
	require.NoError(t, err)
	return bm.ToArray()
}

// checkWholeBlocks verifies that every block marked present decrypts to the
// right bytes.
func (e *tornBlockEnv) checkWholeBlocks(t *testing.T) {
	t.Helper()
	for _, b := range e.presentBlocks(t) {
		start := int64(b) * BlockDataSize
		end := min(start+BlockDataSize, int64(len(e.data)))
		got, err := e.storage.ReadBlocks(e.hash, start, int(end-start))
		require.NoError(t, err, "block %d is marked present but does not read back", b)
		assert.True(t, bytes.Equal(e.data[start:end], got), "block %d holds the wrong bytes", b)
	}
}

// A transfer that stops part-way through a block must not leave that block
// marked present: it would be a short, mis-encrypted block that every reader
// trips over (AES-GCM rejects it) and that resumption then skips as done.
const tornCut = 3*BlockDataSize + 100

// TestBlockWriterCloseDropsTornBlock checks the BlockWriter itself: closing a
// writer whose input stopped mid-block keeps the whole blocks and discards the
// fragment, while the object's genuinely short final block is still written.
func TestBlockWriterCloseDropsTornBlock(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)

	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:tornCut])
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	assert.Equal(t, []uint32{0, 1, 2}, env.presentBlocks(t), "the torn fourth block must not be marked present")
	env.checkWholeBlocks(t)

	// The final block is short by design and is written.
	last := uint32(tornObjectBlocks - 1)
	bw, err = env.storage.NewBlockWriter(env.hash, last, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[int64(last)*BlockDataSize:])
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	assert.Contains(t, env.presentBlocks(t), last)
	env.checkWholeBlocks(t)

	// ...but not if it is itself cut short.
	env2 := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	bw, err = env2.storage.NewBlockWriter(env2.hash, last, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env2.data[int64(last)*BlockDataSize : len(env2.data)-5])
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	assert.Empty(t, env2.presentBlocks(t), "a truncated final block must not be marked present")
}

// TestBlockWriterAbort checks the explicit error path: an aborted writer keeps
// the whole blocks it already wrote, drops the fragment, and -- for an object
// of unknown size -- does not mistake where it stopped for the end.
func TestBlockWriterAbort(t *testing.T) {
	env := newTornBlockEnv(t, -1)
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:tornCut])
	require.NoError(t, err)
	bw.Abort()
	_, err = bw.Write([]byte("x"))
	assert.Error(t, err, "an aborted writer is closed")
	assert.NoError(t, bw.Close(), "closing an aborted writer is a no-op")

	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), meta.ContentLength, "an aborted unknown-size download has not found its length")
	assert.True(t, meta.Completed.IsZero())
	assert.NotContains(t, env.presentBlocks(t), uint32(3))
}

// newTestFetchOp builds a fetch operation the way FetchBlocksAsync does.
func newTestFetchOp(totalBytes int64) *fetchOperation {
	op := &fetchOperation{
		chunkComplete: make(map[int64]chan struct{}),
		doneCh:        make(chan struct{}),
		cancelFn:      func() {},
		totalBytes:    totalBytes,
		startTime:     time.Now(),
		rate:          ewma.NewMovingAverage(10),
	}
	op.rate.Set(float64(DefaultInitialRate))
	return op
}

// TestOriginFetchFailureLeavesNoTornBlock drives BlockFetcherV2's handling of
// an origin range transfer -- the code that runs between the transfer engine
// and the BlockWriter, including the engine's own close of the writer --
// through a transfer that fails, and one whose context is cancelled,
// part-way through a block.
func TestOriginFetchFailureLeavesNoTornBlock(t *testing.T) {
	reset := error_codes.NewContact_ConnectionResetError(&client.NetworkResetError{})
	condemning := errors.New("download error after server response started: 500: upstream verification failed")
	for _, tc := range []struct {
		name   string
		err    error
		cancel bool
		want   []uint32
	}{
		// A benign stop keeps the whole blocks and drops the torn one.
		{name: "ConnectionReset", err: reset, want: []uint32{0, 1, 2}},
		{name: "ContextCancelled", err: context.Canceled, cancel: true, want: []uint32{0, 1, 2}},
		// A condemning failure publishes nothing more: the blocks still
		// waiting to be written are discarded, not marked present for a
		// reader to serve before the object is dropped.
		{name: "CondemningError", err: condemning, want: []uint32{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
			meta, err := env.storage.GetMetadata(env.hash)
			require.NoError(t, err)
			bf := &BlockFetcherV2{
				storage:         env.storage,
				instanceHash:    env.hash,
				meta:            meta,
				prefetchTimeout: time.Minute,
				activeFetches:   make(map[fetchKey]*fetchOperation),
			}
			op := newTestFetchOp(int64(len(env.data)))
			inner, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
			require.NoError(t, err)
			writer := &blockWriter{inner: inner, op: op, bf: bf,
				lastSemRelease: time.Now(), lastRateUpdate: time.Now(), lastFlush: time.Now()}

			// The body the transfer engine delivered before failing.
			_, err = writer.Write(env.data[:tornCut])
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			results := make(chan client.TransferResults, 1)
			jobID := uuid.New()
			// The transfer engine closes the writer itself when the
			// transfer ends, with the transfer's error, before
			// BlockFetcherV2 sees the result.
			var closer io.Closer = writer
			if cwe, ok := closer.(interface{ CloseWithError(error) error }); ok {
				require.NoError(t, cwe.CloseWithError(tc.err))
			} else {
				require.NoError(t, writer.Close())
			}
			if tc.cancel {
				cancel()
			} else {
				results <- client.TransferResults{JobId: jobID, Error: tc.err}
			}
			bf.awaitTransfer(ctx, op, results, jobID.String(), writer, false, nil)
			require.Error(t, op.err)

			assert.Equal(t, tc.want, env.presentBlocks(t), "the torn fourth block must not be marked present")
			env.checkWholeBlocks(t)
		})
	}
}

// TestNoStoreStreamSeesTransferFailure checks the other writer the transfer
// engine closes with the transfer's error: a no-store download streamed
// through a pipe must hand its reader the failure, not a clean end of file
// that makes a truncated body look complete.
func TestNoStoreStreamSeesTransferFailure(t *testing.T) {
	pr, pw := io.Pipe()
	dw := &decisionWriter{decided: true, pipeMode: true, pipeWriter: pw}
	go func() {
		_, _ = dw.Write([]byte("partial body"))
		_ = dw.CloseWithError(errors.New("connection reset by peer"))
	}()
	got, err := io.ReadAll(pr)
	assert.Equal(t, "partial body", string(got))
	require.Error(t, err, "a failed transfer must not read as a complete body")
}

// TestOriginFetchDropsAnotherVersion checks the cache's half of refusing a
// range from a replaced object (the transfer engine's half, refusing the
// response before writing it, is tested in the client): a fetch that failed
// because the origin now serves another version drops the cached instance,
// which can no longer be completed, and a benign failure leaves it alone.
func TestOriginFetchDropsAnotherVersion(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	bf := &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta,
		activeFetches: make(map[fetchKey]*fetchOperation)}

	bf.dropIfCondemned(error_codes.NewContact_ConnectionResetError(&client.NetworkResetError{}), true)
	kept, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	require.NotNil(t, kept, "a benign failure keeps the instance")

	// Wrapped the way the transfer engine reports an attempt's error.
	changed := fmt.Errorf("transfer failed: %w",
		errors.Wrap(client.ErrObjectVersionChanged, `origin sent entity tag "v2"; expected "v1"`))
	bf.dropIfCondemned(changed, false)
	gone, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Nil(t, gone, "an instance the origin no longer serves is dropped")
}

// TestOriginFetchDropsWhatAFailureCondemns checks that a range fetch or
// background fill that wrote part of a body and then failed in a way that
// condemns it -- here, a failure reported in the X-Transfer-Status trailer --
// drops the instance, rather than leave its blocks marked present for a later
// read to complete the object from, and that the object's readers are told.
// A fetch that failed before writing anything condemns nothing.
func TestOriginFetchDropsWhatAFailureCondemns(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	bf := &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta, blockState: state,
		activeFetches: make(map[fetchKey]*fetchOperation)}
	trailer := error_codes.NewTransferError(errors.New("download error after server response started: 500: upstream verification failed"))

	bf.dropIfCondemned(trailer, false)
	kept, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	require.NotNil(t, kept, "a fetch that wrote nothing condemns nothing")

	rr, err := NewRangeReader(env.storage, env.hash, 0, -1, nil)
	require.NoError(t, err)
	defer rr.Close()
	bf.dropIfCondemned(trailer, true)
	gone, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Nil(t, gone, "the blocks a condemned fetch wrote must not be kept")
	assert.Error(t, rr.WaitForCompletion(context.Background()), "a reader of the dropped copy must be told")
	_, err = rr.Read(make([]byte, 10))
	assert.Error(t, err)
}

// fillAllButLast writes every block but the object's (short) last one into
// env through a fresh writer and returns it, still open; the last block was
// already fetched by an earlier write, as a tail read would.
func fillAllButLast(t *testing.T, env *tornBlockEnv, onComplete func()) *BlockWriter {
	t.Helper()
	last := uint32(tornObjectBlocks - 1)
	bw, err := env.storage.NewBlockWriter(env.hash, last, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[int64(last)*BlockDataSize:])
	require.NoError(t, err)
	require.NoError(t, bw.Close())

	bw, err = env.storage.NewBlockWriter(env.hash, 0, nil, onComplete)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:int64(last)*BlockDataSize])
	require.NoError(t, err)
	return bw
}

// TestBlockWriterStopEarlyCompletesTheObject checks that a write stopped early
// for a reason that says nothing against its data -- cancelled, or cut off by
// the connection -- after filling the object's last hole marks the object
// complete, as Close would: otherwise nothing ever would.  Abort, which is for
// condemned data, must not.
func TestBlockWriterStopEarlyCompletesTheObject(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	completed := false
	bw := fillAllButLast(t, env, func() { completed = true })
	bw.StopEarly()
	bw.StopEarly() // harmless
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.False(t, meta.Completed.IsZero(), "an object with every block present is complete")
	assert.True(t, completed, "the completion callback must run")
	env.checkWholeBlocks(t)

	env = newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	fillAllButLast(t, env, func() { t.Error("an aborted write must not complete the object") }).Abort()
	meta, err = env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.True(t, meta.Completed.IsZero())
}

// TestTransferEndDecidesHowTheWriteEnds checks the writers the transfer engine
// closes with the transfer's error: a benign stop completes an object whose
// last hole was filled, and a failure a server reported does not.
func TestTransferEndDecidesHowTheWriteEnds(t *testing.T) {
	trailerErr := error_codes.NewTransferError(errors.New("download error after server response started: 500: upstream verification failed"))
	for _, tc := range []struct {
		name     string
		err      error
		complete bool
	}{
		{name: "IdleCancel", err: context.Canceled, complete: true},
		{name: "ConnectionCut", err: error_codes.NewTransferError(io.ErrUnexpectedEOF), complete: true},
		{name: "TrailerFailure", err: trailerErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
			dw := &decisionWriter{decided: true, diskMode: true, blockWriter: fillAllButLast(t, env, nil)}
			require.NoError(t, dw.CloseWithError(tc.err))
			meta, err := env.storage.GetMetadata(env.hash)
			require.NoError(t, err)
			assert.Equal(t, tc.complete, !meta.Completed.IsZero())
		})
	}
}

// TestWriterOfACondemnedObjectMarksNothing checks that once an object has been
// condemned -- another writer found its data bad, and it is being dropped --
// a writer still running, such as a fill of another gap, marks none of its
// blocks present: those rows would outlive the delete, and be taken for
// blocks of the object when it is next fetched under the same hash.
func TestWriterOfACondemnedObjectMarksNothing(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:2*BlockDataSize])
	require.NoError(t, err)

	state.condemn(errors.New("another fill's data failed verification"))
	_, err = bw.Write(env.data[2*BlockDataSize:])
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	assert.Empty(t, env.presentBlocks(t), "nothing of a condemned object may be marked present")
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.True(t, meta.Completed.IsZero(), "nor may it be completed")
}
