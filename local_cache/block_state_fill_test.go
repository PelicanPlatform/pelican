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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestBlockFillCoversOneGap checks how a background fill is placed: from the
// missing block to the next block present, or to the limit given, never over
// a block another fill is writing; and that only one fill covers a block.
func TestBlockFillCoversOneGap(t *testing.T) {
	present := roaring.New()
	present.AddRange(0, 10)  // blocks 0-9
	present.AddRange(50, 60) // blocks 50-59
	obs := NewObjectBlockState(present)

	assert.Nil(t, obs.beginFill(5, 99), "a present block needs no fill")
	f := obs.beginFill(10, 99)
	require.NotNil(t, f)
	assert.Equal(t, [2]uint32{10, 49}, [2]uint32{f.start, f.end}, "a fill stops at the next present block")
	assert.Nil(t, obs.beginFill(30, 99), "a block another fill covers needs no second fill")

	tail := obs.beginFill(60, 99)
	require.NotNil(t, tail)
	assert.Equal(t, [2]uint32{60, 99}, [2]uint32{tail.start, tail.end}, "with nothing present after it, a fill runs to the limit")

	obs.endFill(f)
	g := obs.beginFill(20, 70)
	require.NotNil(t, g)
	assert.Equal(t, [2]uint32{20, 49}, [2]uint32{g.start, g.end})
	obs.endFill(g)
	obs.endFill(tail)
	assert.Nil(t, obs.beginFill(50, 99), "block 50 is present")

	// A reader waiting on a block a fill covers wakes when the fill ends
	// without writing it, and then fetches it itself.
	f = obs.beginFill(12, 12)
	require.NotNil(t, f)
	done := make(chan bool)
	go func() { done <- obs.WaitForBlock(context.Background(), 12) }()
	obs.endFill(f)
	assert.False(t, <-done)

	// No fill starts into an object being dropped as bad.
	obs.condemn(errors.New("condemned"))
	assert.Nil(t, obs.beginFill(70, 99), "a condemned object gets no new fill")
}

// TestBackgroundFillPinsItsObject checks that a background fill pins the
// object for as long as it runs -- it can outlive the reader that started it
// by the prefetch timeout -- so that eviction does not delete the object
// under it.
func TestBackgroundFillPinsItsObject(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, config.InitClient())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = te.Shutdown() })

	// A federation that never answers, so the fill stays in progress.
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(hang.Close)
	t.Cleanup(func() { close(release) })

	downloadCtx, downloadCancel := context.WithCancel(ctx)
	pc := &PersistentCache{storage: env.storage, te: te,
		downloadCtx: downloadCtx, downloadCancel: downloadCancel}
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	res := &objectResolution{instanceHash: env.hash, pelicanURL: "pelican://" + strings.TrimPrefix(hang.URL, "http://") + "/test/object", meta: meta}

	covered, started := pc.startFill(res, state, 0, tornObjectBlocks-1)
	require.True(t, covered)
	require.NotNil(t, started)
	assert.True(t, env.storage.IsObjectPinned(env.hash), "a fill in progress must pin its object")

	downloadCancel()
	pc.downloadWg.Wait()
	<-started
	assert.False(t, env.storage.IsObjectPinned(env.hash), "the pin goes with the fill")
}

// TestCondemnedFillPublishesNothingToItsReaders checks that a fill whose
// transfer fails in a way that condemns its data does not publish the blocks
// it had not yet flushed: the transfer engine aborts the writer before the
// fetcher sees the result and drops the object, and a reader woken by those
// blocks would serve them before anything had marked the object bad.  The
// reader instead fails with the reason.
func TestCondemnedFillPublishesNothingToItsReaders(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	fill := state.beginFill(0, tornObjectBlocks-1)
	require.NotNil(t, fill)

	rr, err := NewRangeReader(env.storage, env.hash, 0, -1, nil)
	require.NoError(t, err)
	defer rr.Close()
	type readResult struct {
		n   int
		err error
	}
	read := make(chan readResult, 1)
	go func() {
		n, err := rr.Read(make([]byte, BlockDataSize))
		read <- readResult{n, err}
	}()

	// The fill's body arrives, all of it still in the write batch; then the
	// transfer reports a failure from the X-Transfer-Status trailer.
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:tornObjectBlocks*BlockDataSize-BlockDataSize])
	require.NoError(t, err)
	trailer := error_codes.NewTransferError(errors.New("download error after server response started: 500: upstream verification failed"))
	require.NoError(t, endWrite(bw, trailer))
	assert.False(t, state.Contains(0), "a condemned write must publish nothing more")

	bf := &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta, blockState: state,
		activeFetches: make(map[fetchKey]*fetchOperation)}
	bf.dropIfCondemned(trailer, true)
	state.endFill(fill)
	res := <-read
	assert.Error(t, res.err, "the reader must not be served the condemned bytes")
	assert.Zero(t, res.n)
}

// TestRangeReadWaitsForTheFillItReliedOn checks that a read of a range --
// which an HTTP Range request is -- reports success only once the fill that
// wrote its blocks has reported, and reports the fill's condemnation if it
// was condemned: the blocks reach the reader before the verdict does.
func TestRangeReadWaitsForTheFillItReliedOn(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	fill := state.beginFill(0, 1)
	require.NotNil(t, fill)

	rr, err := NewRangeReader(env.storage, env.hash, 0, -1, nil)
	require.NoError(t, err)
	defer rr.Close()
	rr.LimitFill([]RangeRequest{{Start: 0, End: 2*BlockDataSize - 1}})
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(rr, make([]byte, 2*BlockDataSize))
		read <- err
	}()

	// The fill writes its blocks and flushes them as it goes, so readers
	// see them before the transfer has reported.
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:2*BlockDataSize])
	require.NoError(t, err)
	require.NoError(t, bw.Flush())
	require.NoError(t, <-read, "the reader has its bytes")

	verdict := make(chan error, 1)
	go func() { verdict <- rr.WaitForCompletion(context.Background()) }()
	assert.Never(t, func() bool { return len(verdict) > 0 }, 200*time.Millisecond, 10*time.Millisecond,
		"a range read must not report before the fill it relied on has")
	trailer := error_codes.NewTransferError(errors.New("download error after server response started: 500: upstream verification failed"))
	require.NoError(t, endWrite(bw, trailer))
	bf := &BlockFetcherV2{storage: env.storage, instanceHash: env.hash, meta: meta, blockState: state,
		activeFetches: make(map[fetchKey]*fetchOperation)}
	bf.dropIfCondemned(trailer, true)
	state.endFill(fill)
	assert.Error(t, <-verdict, "the range read must report that its bytes came from a condemned copy")
}

// returnsWithin reports what fn returned, failing the test if it has not
// returned within ten seconds.
func returnsWithin(t *testing.T, fn func() error) error {
	t.Helper()
	res := make(chan error, 1)
	go func() { res <- fn() }()
	select {
	case err := <-res:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("did not return")
		return nil
	}
}

// TestReaderWaitsForTheFillThatWroteItsBlocks checks that a reader waits for
// the verdict of a fill still writing the blocks it served, even when every
// block was already on disk when it got there and it never had to wait for
// one.  A fill publishes its blocks as it flushes them, before its transfer
// has reported; a verdict that condemns them must reach the reader.
func TestReaderWaitsForTheFillThatWroteItsBlocks(t *testing.T) {
	obs := NewObjectBlockState(nil)
	fill := obs.beginFill(0, 9)
	require.NotNil(t, fill)
	obs.AddRange(0, 9) // the fill has flushed every block, and not yet reported
	rr := &RangeReader{blockState: obs, end: 10*BlockDataSize - 1}
	require.NoError(t, rr.ensureBlocks(t.Context(), 0, 9))

	res := make(chan error, 1)
	go func() { res <- rr.WaitForCompletion(t.Context()) }()
	assert.Never(t, func() bool { return len(res) > 0 }, 200*time.Millisecond, 10*time.Millisecond,
		"the reader must wait for the verdict of the fill that wrote its blocks")
	condemnation := errors.New("the upstream's verification failed")
	obs.condemn(condemnation)
	obs.endFill(fill)
	select {
	case err := <-res:
		assert.ErrorIs(t, err, condemnation)
	case <-time.After(10 * time.Second):
		t.Fatal("WaitForCompletion did not return once the fill had reported")
	}
}

// TestWholeReadWaitsForTheDownloadItJoined checks the same for a reader of
// the whole object that joined a whole-object download as a cache hit and
// found every block written: it waits for the download's verdict.
func TestWholeReadWaitsForTheDownloadItJoined(t *testing.T) {
	const size = 10 * BlockDataSize
	obs := NewObjectBlockState(nil)
	obs.SetDownloading()
	obs.AddRange(0, 9)
	rr := &RangeReader{blockState: obs, end: size - 1, meta: &CacheMetadata{ContentLength: size}}
	require.NoError(t, rr.ensureBlocks(t.Context(), 0, 9))

	res := make(chan error, 1)
	go func() { res <- rr.WaitForCompletion(t.Context()) }()
	assert.Never(t, func() bool { return len(res) > 0 }, 200*time.Millisecond, 10*time.Millisecond,
		"a whole-object read must wait for the verdict of the download it joined")
	condemnation := errors.New("checksum mismatch")
	obs.condemn(condemnation)
	obs.ClearDownloading()
	select {
	case err := <-res:
		assert.ErrorIs(t, err, condemnation)
	case <-time.After(10 * time.Second):
		t.Fatal("WaitForCompletion did not return once the download had reported")
	}
}

// TestReaderDoesNotWaitForOtherFills checks that a reader does not wait for
// a fill of blocks it did not serve, nor a range read for a whole-object
// download: neither wrote what it served.
func TestReaderDoesNotWaitForOtherFills(t *testing.T) {
	obs := NewObjectBlockState(nil)
	elsewhere := obs.beginFill(100, 109)
	require.NotNil(t, elsewhere)
	defer obs.endFill(elsewhere)
	obs.SetDownloading()
	defer obs.ClearDownloading()
	obs.AddRange(0, 9)
	rr := &RangeReader{blockState: obs, end: 10*BlockDataSize - 1, meta: &CacheMetadata{ContentLength: 200 * BlockDataSize}}
	require.NoError(t, rr.ensureBlocks(t.Context(), 0, 9))
	assert.NoError(t, returnsWithin(t, func() error { return rr.WaitForCompletion(t.Context()) }))
}

// TestCancelledWaitIsNeverLeftAsleep checks that a WaitForBlock whose
// context is cancelled returns, however the wakeup it sends its waiting
// goroutine is ordered against that goroutine going to sleep.  The order
// forced here -- the waiter, having checked that it was not cancelled, goes
// to sleep only once the caller has begun to wake it -- is the one in which
// a wakeup sent without the lock is lost, and the call would then wait for
// the next block written, which from a stalled transfer may never come.
func TestCancelledWaitIsNeverLeftAsleep(t *testing.T) {
	obs := NewObjectBlockState(nil)
	obs.SetDownloading() // block 0 is due, so WaitForBlock sleeps for it
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waking := make(chan struct{})
	var once sync.Once
	obs.waitHooks = &blockWaitHooks{
		beforeSleep: func() { once.Do(func() { cancel(); <-waking }) },
		onCancel:    func() { close(waking) },
	}

	returned := make(chan bool, 1)
	go func() { returned <- obs.WaitForBlock(ctx, 0) }()
	select {
	case found := <-returned:
		assert.False(t, found)
	case <-time.After(10 * time.Second):
		t.Fatal("WaitForBlock did not return after its context was cancelled")
	}
}
