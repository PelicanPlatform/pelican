//go:build !windows

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFailedHandOffReleasesWaitingReaders checks that a download that has
// marked its object as downloading, and then fails before a fetcher adopts
// its transfer, wakes the readers already waiting for it, rather than leave
// them to wait until their own contexts end.  The failure here is the
// object being evicted in that window, which makes creating the fetcher
// fail.
func TestFailedHandOffReleasesWaitingReaders(t *testing.T) {
	const size = 4 << 20
	origin := newStallingOrigin(size, 256<<10, `"v1"`)
	env := newStubFedCache(t, origin)

	lastBlock := ContentOffsetToBlock(size - 1)
	waited := make(chan bool, 1)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Minute)
	defer waitCancel()
	env.pc.beforeHandOff = func(dl *persistentDownload) {
		// A reader that found the download -- as a cache hit would, now
		// that the latest-ETag mapping is stored -- waits for a block the
		// stalled origin never sends.
		state, err := env.pc.storage.GetSharedBlockState(dl.instanceHash)
		require.NoError(t, err)
		go func() { waited <- state.WaitForBlock(waitCtx, lastBlock) }()
		require.Eventually(t, func() bool { return state.waiters() > 0 }, 10*time.Second, time.Millisecond)
		require.NoError(t, env.pc.storage.Delete(dl.instanceHash))
	}

	_, err := env.pc.Get(context.Background(), "/test/obj.bin", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "block fetcher")

	select {
	case got := <-waited:
		assert.False(t, got, "the block was never written")
	case <-time.After(10 * time.Second):
		t.Fatal("a reader waiting for the download was not released when the hand-off failed")
	}
}
