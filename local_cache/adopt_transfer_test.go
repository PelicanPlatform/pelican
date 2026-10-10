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
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestAdoptedTransferWithoutResultIsAFailure checks that a whole-object
// download whose transfer client goes away without reporting the job is
// treated as failed: its writer is aborted, so an object of unknown size is
// not finalized wherever its input happened to stop.
func TestAdoptedTransferWithoutResultIsAFailure(t *testing.T) {
	env := newTornBlockEnv(t, -1)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, config.InitClient())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = te.Shutdown() })
	tc, err := te.NewClient()
	require.NoError(t, err)

	inner, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	// The part of the body that arrived before the transfer stopped.
	_, err = inner.Write(env.data[:tornCut])
	require.NoError(t, err)
	dw := &decisionWriter{decided: true, diskMode: true, blockWriter: inner}
	bf := &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta,
		prefetchTimeout: time.Minute, activeFetches: make(map[fetchKey]*fetchOperation)}

	resultChan := make(chan *client.TransferResults, 1)
	resultChan <- nil // what performDownload forwards when the client closes first
	exitErr := make(chan error, 1)
	egrp, _ := errgroup.WithContext(ctx)
	var wg sync.WaitGroup
	bf.AdoptTransfer(ctx, func() {}, tc, dw, resultChan, egrp, &wg, func(err error) { exitErr <- err })
	require.Error(t, <-exitErr, "a transfer that reported nothing has not succeeded")
	wg.Wait()

	meta, err = env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), meta.ContentLength, "the object must not be finalized at the cut")
	assert.True(t, meta.Completed.IsZero())
	assert.NotContains(t, env.presentBlocks(t), uint32(3))
}

// adoptHarness is an adopted whole-object download of a known-size object
// whose body has arrived up to tornCut, driven by a fake transfer engine: its
// cancel function reports `onCancel` as the transfer's result.
type adoptHarness struct {
	env       *tornBlockEnv
	bf        *BlockFetcherV2
	exitErr   chan error
	cancelled chan struct{}
	wg        sync.WaitGroup
}

func startAdoptHarness(t *testing.T, idleAfter time.Duration, onCancel *client.TransferResults, beforeStart ...func(*adoptHarness)) *adoptHarness {
	t.Helper()
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, config.InitClient())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = te.Shutdown() })
	tc, err := te.NewClient()
	require.NoError(t, err)

	inner, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = inner.Write(env.data[:tornCut])
	require.NoError(t, err)
	dw := &decisionWriter{decided: true, diskMode: true, blockWriter: inner, dl: &persistentDownload{}}
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)

	h := &adoptHarness{
		env:       env,
		bf:        &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta, blockState: state, prefetchTimeout: idleAfter, activeFetches: make(map[fetchKey]*fetchOperation)},
		exitErr:   make(chan error, 1),
		cancelled: make(chan struct{}),
	}
	resultChan := make(chan *client.TransferResults)
	var once sync.Once
	cancelTransfer := func() {
		once.Do(func() {
			close(h.cancelled)
			go func() { resultChan <- onCancel }()
		})
	}
	for _, f := range beforeStart {
		f(h)
	}
	egrp, _ := errgroup.WithContext(ctx)
	h.bf.AdoptTransfer(ctx, cancelTransfer, tc, dw, resultChan, egrp, &h.wg, func(err error) { h.exitErr <- err })
	return h
}

func (h *adoptHarness) wasCancelled() bool {
	select {
	case <-h.cancelled:
		return true
	default:
		return false
	}
}

// TestAdoptedTransferIdleCancelKeepsWholeBlocks checks that once no reader is
// left, an adopted download is really cancelled -- the transfer itself, not
// only the fetcher's bookkeeping -- and that the blocks it had written are
// kept, with only the fragment after them dropped.
func TestAdoptedTransferIdleCancelKeepsWholeBlocks(t *testing.T) {
	h := startAdoptHarness(t, time.Nanosecond, &client.TransferResults{Error: context.Canceled})

	err := <-h.exitErr
	h.wg.Wait()
	assert.True(t, h.wasCancelled(), "the transfer itself must be cancelled")
	assert.ErrorIs(t, err, errAdoptedTransferIdle)
	assert.Equal(t, []uint32{0, 1, 2}, h.env.presentBlocks(t), "whole blocks are kept, the torn fourth is not")
	h.env.checkWholeBlocks(t)
}

// TestAdoptedTransferNotIdleWhileAReaderIsAttached checks that a reader
// attached to a download keeps it going however long it goes without reading
// -- a slow client must not cost the cache its copy -- and that the idle
// timeout starts once the last reader detaches.
func TestAdoptedTransferNotIdleWhileAReaderIsAttached(t *testing.T) {
	var detach func()
	h := startAdoptHarness(t, time.Nanosecond, &client.TransferResults{Error: context.Canceled},
		func(h *adoptHarness) { detach = h.bf.blockState.AttachReader() })

	// The idle check runs every few milliseconds.
	assert.Never(t, h.wasCancelled, time.Second, 20*time.Millisecond,
		"an attached reader must keep the download from going idle")
	detach()
	detach() // harmless
	require.Eventually(t, h.wasCancelled, 10*time.Second, 50*time.Millisecond,
		"with no reader left, the download goes idle")
	assert.ErrorIs(t, <-h.exitErr, errAdoptedTransferIdle)
	h.wg.Wait()
}

// TestAdoptedTransferFinishedBeforeIdleCancelSucceeds checks that a transfer
// that completes while its idle cancellation is under way is a success, not
// an "idle" failure.
func TestAdoptedTransferFinishedBeforeIdleCancelSucceeds(t *testing.T) {
	h := startAdoptHarness(t, time.Nanosecond, &client.TransferResults{})
	assert.NoError(t, <-h.exitErr)
	h.wg.Wait()
	assert.True(t, h.wasCancelled())
}

// TestRangeReaderCountsAsAnOpenReader checks that every RangeReader of an
// object, however it was made, is counted on the object's shared block state
// from creation until it closes -- once, however often it is closed.
func TestRangeReaderCountsAsAnOpenReader(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	open := func() bool { o, _ := state.readerActivity(); return o }

	rr, err := NewRangeReader(env.storage, env.hash, 0, -1, nil)
	require.NoError(t, err)
	assert.True(t, open())
	other, err := NewRangeReader(env.storage, env.hash, 0, -1, nil)
	require.NoError(t, err)
	require.NoError(t, rr.Close())
	require.NoError(t, rr.Close())
	assert.True(t, open(), "a second Close must not detach another reader")
	require.NoError(t, other.Close())
	assert.False(t, open())
}

// TestAdoptedTransferIdleCancelKeepsTheRealError checks that a transfer that
// fails for a reason of its own while its idle cancellation is under way --
// here, a checksum mismatch found once the whole body had arrived -- is
// reported with that reason, not as an idle stop, which would keep the bad
// bytes.
func TestAdoptedTransferIdleCancelKeepsTheRealError(t *testing.T) {
	mismatch := error_codes.NewTransfer_ChecksumMismatchError(&client.ChecksumMismatchError{})
	h := startAdoptHarness(t, time.Nanosecond, &client.TransferResults{Error: mismatch})
	err := <-h.exitErr
	h.wg.Wait()
	assert.True(t, h.wasCancelled())
	var m *client.ChecksumMismatchError
	assert.True(t, errors.As(err, &m), "the download must end in the mismatch, not %v", err)
}

// TestInlineDownloadNeedsAWholeResult checks that a small download held in
// memory is stored only once its transfer has reported success and
// delivered the whole object: a transfer client that went away without
// reporting, or a body shorter than the object, must not be stored as the
// complete object.
func TestInlineDownloadNeedsAWholeResult(t *testing.T) {
	dw := &decisionWriter{decided: true, inlineMode: true, buffer: []byte("the first part of an object")}
	dl := &persistentDownload{completionDone: make(chan struct{})}
	assert.ErrorIs(t, finishInlineDownload(dl, dw, nil, -1), errAdoptedTransferUnreported,
		"a transfer that never reported is not a success")
	assert.Error(t, finishInlineDownload(dl, dw, &client.TransferResults{}, 100),
		"a body shorter than the object is not the object")
}

// TestRangeFetchWhoseClientClosesIsNotASuccess checks that a range fetch
// whose transfer client closes without reporting the job fails, rather than
// reporting success for blocks it may never have written.
func TestRangeFetchWhoseClientClosesIsNotASuccess(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	bf := &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta,
		prefetchTimeout: time.Minute, activeFetches: make(map[fetchKey]*fetchOperation)}
	op := newTestFetchOp(int64(len(env.data)))
	inner, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	writer := &blockWriter{inner: inner, op: op, bf: bf,
		lastSemRelease: time.Now(), lastRateUpdate: time.Now(), lastFlush: time.Now()}
	results := make(chan client.TransferResults)
	close(results)
	bf.awaitTransfer(context.Background(), op, results, "job", writer, false, nil)
	assert.Error(t, op.err)
}

// TestAdoptedTransferIdleCancelKeepsACondemningError checks that a result in
// which one attempt was cancelled is not put down to the idle stop when
// another attempt's error condemns the data: the writer side, which saw the
// same result, has already discarded it.
func TestAdoptedTransferIdleCancelKeepsACondemningError(t *testing.T) {
	notFound := client.StatusCodeError(404)
	te := client.NewTransferErrors()
	te.AddError(&notFound)
	te.AddError(error_codes.NewTransferError(context.Canceled))
	h := startAdoptHarness(t, time.Nanosecond, &client.TransferResults{Error: te})
	err := <-h.exitErr
	h.wg.Wait()
	assert.True(t, h.wasCancelled())
	assert.NotErrorIs(t, err, errAdoptedTransferIdle)
	assert.False(t, transferStopKeepsData(err), "the download must end in the condemning error, not %v", err)
}
