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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
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
	bf.AdoptTransfer(ctx, tc, dw, resultChan, egrp, &wg, func(err error) { exitErr <- err })
	require.Error(t, <-exitErr, "a transfer that reported nothing has not succeeded")
	wg.Wait()

	meta, err = env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), meta.ContentLength, "the object must not be finalized at the cut")
	assert.True(t, meta.Completed.IsZero())
	assert.NotContains(t, env.presentBlocks(t), uint32(3))
}
