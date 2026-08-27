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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin down the blocking policy of RangeReader.WaitForCompletion.
// The serving path calls it after http.ServeContent so a verification failure
// detected only after the body finishes (e.g. an origin/local checksum
// mismatch) can be surfaced via the X-Transfer-Status trailer.
//
// The critical invariant: a partial range read must NEVER block on the
// completion of the backing download.  A 1 KB range of a multi-GB object
// cannot wait for the remaining gigabytes to finish downloading just to learn
// that the trailer should say "200: OK".

// TestRangeReader_WaitForCompletion_PartialRangeDoesNotBlock is the regression
// test for a bug that was almost introduced: simulate an origin whose backing
// download never finishes (the completion channel is never closed, modelling
// an origin that hangs before the last byte), then call WaitForCompletion on
// a reader that asked for a tiny slice.  It must return ~immediately.
func TestRangeReader_WaitForCompletion_PartialRangeDoesNotBlock(t *testing.T) {
	// Never-closing channel simulates a backing full-object download that
	// never completes -- exactly the "origin that never sends the last
	// byte" scenario.
	neverDone := make(chan struct{})

	rr := &RangeReader{
		meta:           &CacheMetadata{ContentLength: 1_000_000_000}, // 1 GB object
		start:          1024,
		end:            2047, // 1 KB slice; not a full read
		completionDone: neverDone,
		completionErr:  func() error { return errors.New("should never be observed") },
	}

	// A generous bound -- the call must return essentially instantly.  If
	// the policy is wrong (e.g. always-block), the test would hang here and
	// the wrapping go-test timeout would fire, but we want a clear failure.
	done := make(chan error, 1)
	go func() {
		done <- rr.WaitForCompletion(context.Background())
	}()

	select {
	case err := <-done:
		assert.NoError(t, err,
			"partial range read must not surface a completion error before "+
				"the download has finished (verification hasn't run yet)")
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForCompletion blocked on a partial-range read while " +
			"the backing download was incomplete -- a 1 KB range of a multi-GB " +
			"object must never wait for the rest of the download")
	}
}

// TestRangeReader_WaitForCompletion_PartialRangeSurfacesCompletedError verifies
// the other half of the policy: when verification has *already* completed
// before WaitForCompletion is called (e.g. the range request happened to come
// in just after the backing download finished), the partial read should still
// surface the error -- it just won't wait for it.
func TestRangeReader_WaitForCompletion_PartialRangeSurfacesCompletedError(t *testing.T) {
	done := make(chan struct{})
	close(done) // download already done at the time of the call
	wantErr := errors.New("origin/local checksum mismatch")

	rr := &RangeReader{
		meta:           &CacheMetadata{ContentLength: 1_000_000_000},
		start:          1024,
		end:            2047,
		completionDone: done,
		completionErr:  func() error { return wantErr },
	}

	assert.ErrorIs(t, rr.WaitForCompletion(context.Background()), wantErr,
		"partial range read should surface an error that has already been "+
			"recorded by the backing download")
}

// TestRangeReader_WaitForCompletion_FullReadBlocksAndReportsError verifies
// the active case: a full-object read DOES block on completion (so the
// verification error can be reported in the trailer), and returns the error
// once the download closes the completion channel.
func TestRangeReader_WaitForCompletion_FullReadBlocksAndReportsError(t *testing.T) {
	done := make(chan struct{})
	const size = 16384
	var observed error
	rr := &RangeReader{
		meta:           &CacheMetadata{ContentLength: size},
		start:          0,
		end:            size - 1, // full read
		completionDone: done,
		completionErr:  func() error { return errors.New("checksum mismatch") },
	}

	finished := make(chan struct{})
	go func() {
		observed = rr.WaitForCompletion(context.Background())
		close(finished)
	}()

	// Should still be blocked because the download hasn't completed.
	select {
	case <-finished:
		t.Fatal("full-read WaitForCompletion returned before the backing download finished")
	case <-time.After(50 * time.Millisecond):
	}

	// Closing the completion channel must unblock the waiter and surface
	// the error.
	close(done)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("full-read WaitForCompletion did not unblock after the download completed")
	}
	require.Error(t, observed)
	assert.Contains(t, observed.Error(), "checksum mismatch")
}

// TestRangeReader_WaitForCompletion_FullReadHonorsContextCancel verifies that
// the full-read wait respects the caller's context so a client disconnect or
// server shutdown doesn't strand the response on a hung backing download.
// Cancellation returns nil -- we don't fabricate a "500" trailer just because
// the client gave up waiting.
func TestRangeReader_WaitForCompletion_FullReadHonorsContextCancel(t *testing.T) {
	const size = 16384
	rr := &RangeReader{
		meta:           &CacheMetadata{ContentLength: size},
		start:          0,
		end:            size - 1,
		completionDone: make(chan struct{}), // never closed
		completionErr:  func() error { return errors.New("should not be reported on ctx cancel") },
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- rr.WaitForCompletion(ctx)
	}()

	// Confirm it's actually blocked before cancellation.
	select {
	case <-done:
		t.Fatal("full-read WaitForCompletion returned before context cancel")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err,
			"context cancel should return nil, not a synthesised error")
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForCompletion did not respect context cancellation")
	}
}

// TestRangeReader_WaitForCompletion_NoBackingDownload covers the cache-hit
// path: a reader with no completion channel (no in-flight download) must
// return nil immediately and not panic.
func TestRangeReader_WaitForCompletion_NoBackingDownload(t *testing.T) {
	rr := &RangeReader{
		meta:  &CacheMetadata{ContentLength: 16384},
		start: 0,
		end:   16383,
		// completionDone / completionErr deliberately unset
	}
	assert.NoError(t, rr.WaitForCompletion(context.Background()))
}

// TestRangeReader_WaitForCompletion_NilReceiverIsSafe is a defensive
// check; callers shouldn't pass nil but it's cheap to guard.
func TestRangeReader_WaitForCompletion_NilReceiverIsSafe(t *testing.T) {
	var rr *RangeReader
	assert.NoError(t, rr.WaitForCompletion(context.Background()))
}

// TestRangeReader_isFullRead pins down which ranges count as "full" for the
// blocking-policy decision.
func TestRangeReader_isFullRead(t *testing.T) {
	cases := []struct {
		name           string
		contentLength  int64
		start, end     int64
		expectFullRead bool
	}{
		{"full range of known size", 1000, 0, 999, true},
		{"start past zero", 1000, 1, 999, false},
		{"end before final byte", 1000, 0, 998, false},
		{"single-byte range from start", 1000, 0, 0, false},
		// Unknown size (chunked) is conservatively NOT a full read so the
		// waiter never blocks indefinitely on a length it doesn't know.
		{"unknown content length", -1, 0, 999, false},
		{"zero content length", 0, 0, -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := &RangeReader{
				meta:  &CacheMetadata{ContentLength: tc.contentLength},
				start: tc.start,
				end:   tc.end,
			}
			assert.Equal(t, tc.expectFullRead, rr.isFullRead())
		})
	}
}
