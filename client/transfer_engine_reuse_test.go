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
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestEngineSharesDirectorResponseAcrossObjects pins the federation-side cost
// of the shape users actually type:
//
//	pelican object get osdf://URL1 osdf://URL2 ... /some/destination
//
// Every one of those sources used to build its own TransferEngine, and with it
// an empty director-response cache, so the director was asked about every
// object -- twice each, because the pre-flight stat that decides the local
// filename went around the cache as well.  A workflow naming a few hundred
// objects put a few hundred queries through the director to learn one thing.
//
// One engine for the whole command makes it one query, however many objects
// share the namespace.  The cache is keyed by namespace prefix, so this is the
// property to hold on to: the count must not scale with the number of sources.
func TestEngineSharesDirectorResponseAcrossObjects(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	// Federation discovery is cached process-wide, so a previous test's
	// entry would otherwise decide what this one discovers.
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

	// A directory destination with several non-recursive sources: the case
	// that pays for the pre-flight stat as well as the transfer.  Every source
	// becomes a job on one client, which is the shape `pelican object get`
	// uses.
	destDir := t.TempDir()
	sources := []string{"/test/one.txt", "/test/two.txt", "/test/three.txt", "/test/four.txt", "/test/five.txt"}
	results, err := getAllThroughOneClient(t, ctx, te, sources, destDir)
	require.NoError(t, err)
	require.Len(t, results, len(sources))

	assert.Equal(t, int64(1), fed.DirectorQueries.Load(),
		"%d objects from one namespace must cost one director query, not one (or two) per object",
		len(sources))

	for _, src := range sources {
		downloaded, err := os.ReadFile(path.Join(destDir, path.Base(src)))
		require.NoError(t, err, "%s was not downloaded", src)
		assert.Equal(t, contents, string(downloaded))
	}
}

// TestEngineSharesAuthenticatedDirectorResponse covers the same property for a
// namespace that demands a token.
//
// A transfer that holds a credential asks the director a second time, because
// the answer may depend on what is presented.  That second question has its own
// cache entry, fingerprinted by the token so it can never answer a caller
// bearing a different one -- but several paths stored that entry and no path
// ever read it back, which left a token-protected namespace paying a round trip
// per object no matter how warm the cache was.
//
// Two queries total, then: one anonymous, one credentialed.  Not two per object.
func TestEngineSharesAuthenticatedDirectorResponse(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	pelican_url.ResetState()
	t.Cleanup(pelican_url.ResetState)

	const contents = "hello"
	fed := test_utils.NewStubFederation(t, test_utils.StubFederationOptions{Contents: contents, RequireToken: true})
	fed.InitClient(t, nil)

	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	defer cancel()

	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, te.Shutdown())
	}()

	destDir := t.TempDir()
	sources := []string{"/test/one.txt", "/test/two.txt", "/test/three.txt", "/test/four.txt", "/test/five.txt"}
	// The token is handed over rather than acquired, so no issuer is needed;
	// acquisition is off so the generator does not judge this stand-in against
	// the namespace's scopes and discard it.
	results, err := getAllThroughOneClient(t, ctx, te, sources, destDir,
		WithToken("a-test-token"), WithAcquireToken(false))
	require.NoError(t, err)
	require.Len(t, results, len(sources))

	assert.Equal(t, int64(2), fed.DirectorQueries.Load(),
		"%d objects must cost one anonymous plus one credentialed director query, not a pair per object",
		len(sources))
}

// getAllThroughOneClient plans and submits every source as a job on a single
// transfer client, the way the object commands do, and waits for them all.
func getAllThroughOneClient(t *testing.T, ctx context.Context, te *TransferEngine, sources []string, destDir string, options ...TransferOption) ([]TransferResults, error) {
	t.Helper()
	tc, err := te.NewClient(options...)
	require.NoError(t, err)
	for _, src := range sources {
		plan, planErr := te.PlanDownload(ctx, src, destDir, false, options...)
		require.NoError(t, planErr, "failed to plan %s", src)
		tj, jobErr := tc.NewTransferJob(ctx, plan.RemoteURL, plan.LocalPath, false, plan.Recursive)
		require.NoError(t, jobErr, "failed to create a job for %s", src)
		require.NoError(t, tc.Submit(tj))
	}
	return tc.Shutdown()
}
