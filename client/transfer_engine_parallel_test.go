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

package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
)

// fetchBarrier holds every object fetch until `want` of them are in flight at
// once, which is a condition to wait on rather than a duration to sleep for.
// When the property holds this costs nothing: the last arrival releases the
// rest immediately.  When it does not, no arrival ever will, so the barrier
// carries its own deadline -- comfortably inside the test binary's, so that a
// serialized implementation is a reported failure rather than a killed run.
type fetchBarrier struct {
	mu       sync.Mutex
	cond     *sync.Cond
	inFlight int
	maxSeen  int
	want     int
	released bool
}

const fetchBarrierTimeout = 60 * time.Second

func newFetchBarrier(ctx context.Context, want int) *fetchBarrier {
	b := &fetchBarrier{want: want}
	b.cond = sync.NewCond(&b.mu)
	ctx, cancel := context.WithTimeout(ctx, fetchBarrierTimeout)
	go func() {
		defer cancel()
		<-ctx.Done()
		b.mu.Lock()
		b.released = true
		b.cond.Broadcast()
		b.mu.Unlock()
	}()
	return b
}

func (b *fetchBarrier) arrive() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inFlight++
	if b.inFlight > b.maxSeen {
		b.maxSeen = b.inFlight
	}
	if b.inFlight >= b.want {
		b.released = true
		b.cond.Broadcast()
	}
	for !b.released {
		b.cond.Wait()
	}
	b.inFlight--
}

func (b *fetchBarrier) max() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxSeen
}

// TestOneClientRunsSourcesTogether: the objects named on one command line must
// transfer together, not one after another.
//
// Each source used to be its own TransferEngine call that returned only once
// that object was done, so a command naming many small objects ran them
// strictly in sequence and left the worker pool idle.  Submitting them all to
// one client puts them in flight at once, bounded by Client.WorkerCount
// rather than by anything the caller arranges.
func TestOneClientRunsSourcesTogether(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	pelican_url.ResetState()
	t.Cleanup(pelican_url.ResetState)

	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	const workers = 4
	barrier := newFetchBarrier(ctx, workers)

	const contents = "hello"
	fed := test_utils.NewStubFederation(t, test_utils.StubFederationOptions{
		Contents: contents,
		OnFetch: func(string) int {
			barrier.arrive()
			return 0
		},
	})
	fed.InitClient(t, map[param.Param]any{param.Client_WorkerCount: workers})

	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, te.Shutdown())
	}()

	destDir := t.TempDir()
	sources := []string{"/test/a", "/test/b", "/test/c", "/test/d", "/test/e", "/test/f"}
	results, err := getAllThroughOneClient(t, ctx, te, sources, destDir)
	require.NoError(t, err)
	require.Len(t, results, len(sources))

	assert.Equal(t, workers, barrier.max(),
		"all %d workers must be busy at once; a lower number means the sources ran in sequence", workers)
}
