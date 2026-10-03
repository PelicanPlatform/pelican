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
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
)

// clientBookkeeping reports how many clients the engine still has entries for.
func clientBookkeeping(te *TransferEngine) (work int, results int) {
	te.clientLock.RLock()
	defer te.clientLock.RUnlock()
	return len(te.workMap), len(te.resultsMap)
}

// TestEngineReapsFinishedClients: a client that has shut down cleanly must
// leave nothing behind on the engine.
//
// runMux used to mark a closed client by setting its workMap entry to nil and
// closing its results channel, but never removed either entry.  Both maps
// therefore only grew: an engine that outlived its clients -- the cache, the
// client agent, or any command that makes a client per object -- accumulated
// an entry pair for every client it had ever made, and runMux rebuilt its
// select cases by walking the whole workMap on every pass, so the cost of each
// pass grew with the number of clients retired rather than live.
func TestEngineReapsFinishedClients(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	pelican_url.ResetState()
	t.Cleanup(pelican_url.ResetState)

	const contents = "hello"
	fed := test_utils.NewStubFederation(t, test_utils.StubFederationOptions{Contents: contents})
	fed.InitClient(t, nil)

	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, te.Shutdown())
	}()

	destDir := t.TempDir()

	// A client that transferred something, repeatedly: exercises retirement
	// via finishJob, where the results channel closes as the last job retires.
	for _, name := range []string{"one", "two", "three", "four", "five"} {
		tc, err := te.NewClient()
		require.NoError(t, err)
		objectUrl := &url.URL{Path: "/test/" + name}
		tj, err := tc.NewTransferJob(ctx, objectUrl, path.Join(destDir, name), false, false)
		require.NoError(t, err)
		require.NoError(t, tc.Submit(tj))
		results, err := tc.Shutdown()
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.NoError(t, results[0].Error)
	}

	// A client that was closed without ever submitting work: exercises the
	// other retirement path, where runMux sees the work channel close with no
	// active jobs.
	for i := 0; i < 5; i++ {
		tc, err := te.NewClient()
		require.NoError(t, err)
		_, err = tc.Shutdown()
		require.NoError(t, err)
	}

	// Reaping happens on runMux's next pass, so this is a condition to wait
	// for rather than something true the instant Shutdown returns.
	require.Eventually(t, func() bool {
		work, results := clientBookkeeping(te)
		return work == 0 && results == 0
	}, 10*time.Second, 10*time.Millisecond,
		"the engine must not keep bookkeeping for clients that have finished")
}
