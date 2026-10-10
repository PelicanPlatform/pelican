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
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

const (
	clientGoneObject  = "/test/obj.bin"
	clientGoneSize    = 4 << 20
	clientGoneStallAt = 256 << 10
)

// TestServedReaderOfAGoneClientLetsTheTransferGoIdle checks that when an
// HTTP client goes away while the cache's handler is waiting for a block
// from a stalled download, the handler stops waiting, its reader detaches
// from the object, and the download -- with no reader left -- goes idle and
// is cancelled, rather than all of it waiting until the transfer itself
// times out.
func TestServedReaderOfAGoneClientLetsTheTransferGoIdle(t *testing.T) {
	origin := newStallingOrigin(clientGoneSize, clientGoneStallAt, `"v1"`)
	env := newStubFedCache(t, origin)
	require.NoError(t, param.LocalCache_PrefetchTimeout.Set(300*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.cacheURL+clientGoneObject, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.ReadFull(resp.Body, make([]byte, 64<<10))
	require.NoError(t, err)

	state := env.blockState(t, clientGoneObject)
	require.Eventually(t, func() bool { return state.waiters() > 0 && origin.stalled.Load() > 0 },
		10*time.Second, 5*time.Millisecond, "the handler must be waiting on the stalled download")
	open, _ := state.readerActivity()
	require.True(t, open)

	cancel()
	assert.Eventually(t, func() bool { open, _ := state.readerActivity(); return !open },
		5*time.Second, 5*time.Millisecond, "the gone client's reader must detach")
	assert.Eventually(t, func() bool { return origin.stalled.Load() == 0 },
		5*time.Second, 5*time.Millisecond, "with no reader left, the transfer must go idle and be cancelled")
}

// TestGetReaderStopsWaitingWhenItsContextEnds checks that a reader from Get
// reads under the context it was got with: a read waiting for a block from
// a stalled download returns once that context ends.
func TestGetReaderStopsWaitingWhenItsContextEnds(t *testing.T) {
	origin := newStallingOrigin(clientGoneSize, clientGoneStallAt, `"v1"`)
	env := newStubFedCache(t, origin)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := env.pc.Get(ctx, clientGoneObject, "")
	require.NoError(t, err)
	defer r.Close()
	copied := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, r)
		copied <- err
	}()

	state := env.blockState(t, clientGoneObject)
	require.Eventually(t, func() bool { return state.waiters() > 0 && origin.stalled.Load() > 0 },
		10*time.Second, 5*time.Millisecond, "the reader must be waiting on the stalled download")
	cancel()
	select {
	case err := <-copied:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		t.Fatal("a read waiting for a block did not return when its context ended")
	}
}

// TestNoStoreReaderOfAGoneClientEndsItsTransfer checks the same for a
// response the origin says not to store, which the cache streams to its one
// client through a pipe from the origin's transfer: when the client goes
// while the handler waits on the pipe for a stalled origin, the handler's
// read returns and the transfer is stopped, rather than both waiting until
// the transfer times out.
func TestNoStoreReaderOfAGoneClientEndsItsTransfer(t *testing.T) {
	origin := newStallingOrigin(clientGoneSize, clientGoneStallAt, `"v1"`)
	origin.cacheControl = "no-store"
	env := newStubFedCache(t, origin)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.cacheURL+clientGoneObject, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "none", resp.Header.Get("Accept-Ranges"), "the response must be streamed, not stored")
	// Read everything the origin sent before it stalled, so that the
	// handler is left waiting on the pipe, not writing to the client.
	_, err = io.ReadFull(resp.Body, make([]byte, clientGoneStallAt))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return origin.stalled.Load() > 0 },
		10*time.Second, 5*time.Millisecond, "the origin's transfer must be stalled")

	cancel()
	assert.Eventually(t, func() bool { return origin.stalled.Load() == 0 },
		5*time.Second, 5*time.Millisecond, "the transfer of a no-store response whose client has gone must stop")
}

// TestGetNoStoreReaderStopsWhenItsContextEnds checks that a reader of a
// no-store response from Get reads under the context it was got with.
func TestGetNoStoreReaderStopsWhenItsContextEnds(t *testing.T) {
	origin := newStallingOrigin(clientGoneSize, clientGoneStallAt, `"v1"`)
	origin.cacheControl = "no-store"
	env := newStubFedCache(t, origin)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := env.pc.Get(ctx, clientGoneObject, "")
	require.NoError(t, err)
	defer r.Close()
	copied := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, r)
		copied <- err
	}()
	require.Eventually(t, func() bool { return origin.stalled.Load() > 0 },
		10*time.Second, 5*time.Millisecond, "the origin's transfer must be stalled")

	cancel()
	select {
	case err := <-copied:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		t.Fatal("a read of a no-store response did not return when its context ended")
	}
	assert.Eventually(t, func() bool { return origin.stalled.Load() == 0 },
		5*time.Second, 5*time.Millisecond, "the transfer must stop")
}
