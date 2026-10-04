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
	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{name: "TransferError"},
		{name: "ContextCancelled", cancel: true},
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
				transferErr := errors.New("connection reset by peer")
				if tc.cancel {
					transferErr = context.Canceled
				}
				require.NoError(t, cwe.CloseWithError(transferErr))
			} else {
				require.NoError(t, writer.Close())
			}
			if tc.cancel {
				cancel()
			} else {
				results <- client.TransferResults{JobId: jobID, Error: errors.New("connection reset by peer")}
			}
			bf.awaitTransfer(ctx, op, results, jobID.String(), writer, false, nil)
			require.Error(t, op.err)

			assert.Equal(t, []uint32{0, 1, 2}, env.presentBlocks(t), "the torn fourth block must not be marked present")
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
// which can no longer be completed, and any other failure leaves it alone.
func TestOriginFetchDropsAnotherVersion(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	bf := &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta,
		activeFetches: make(map[fetchKey]*fetchOperation)}

	bf.dropIfVersionChanged(errors.New("connection reset by peer"))
	kept, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	require.NotNil(t, kept, "an ordinary failure keeps the instance")

	// Wrapped the way the transfer engine reports an attempt's error.
	changed := fmt.Errorf("transfer failed: %w",
		errors.Wrap(client.ErrObjectVersionChanged, `origin sent entity tag "v2"; expected "v1"`))
	bf.dropIfVersionChanged(changed)
	gone, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Nil(t, gone, "an instance the origin no longer serves is dropped")
}
