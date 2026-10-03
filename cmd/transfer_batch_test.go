//go:build client

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

package main

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
)

// batchDeadline bounds how long a test waits for submitAndDrain to return.
// It only matters when the property under test is broken, in which case the
// call never returns on its own.
const batchDeadline = 60 * time.Second

// startBatch builds an engine and client against fed and runs submitAndDrain
// on its own goroutine, so that a call that never returns is a reported
// failure rather than a hung test.
func startBatch(t *testing.T, fed *test_utils.StubFederation, sources []string,
	newJob func(ctx context.Context, engine *client.TransferEngine, tc *client.TransferClient, src string) (*client.TransferJob, error),
) <-chan batchOutcome {
	t.Helper()
	fed.InitClient(t, nil)

	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	t.Cleanup(cancel)

	engine, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = engine.Shutdown() })
	tc, err := engine.NewClient()
	require.NoError(t, err)

	outcome := make(chan batchOutcome, 1)
	go func() {
		results, failedIdx, err := submitAndDrain(ctx, tc, sources, func(ctx context.Context, src string) (*client.TransferJob, error) {
			return newJob(ctx, engine, tc, src)
		})
		outcome <- batchOutcome{results, failedIdx, err}
	}()
	return outcome
}

type batchOutcome struct {
	results   [][]client.TransferResults
	failedIdx int
	err       error
}

// downloadJob is the job `pelican object get` builds for src.
func downloadJob(t *testing.T, ctx context.Context, engine *client.TransferEngine, tc *client.TransferClient, src string) (*client.TransferJob, error) {
	plan, err := engine.PlanDownload(ctx, src, t.TempDir(), false)
	if err != nil {
		return nil, err
	}
	return tc.NewTransferJob(ctx, plan.RemoteURL, plan.LocalPath, false, plan.Recursive)
}

// TestSubmitAndDrainJoinsTheSubmitter: when a transfer fails, the batch must
// not return while its submitter is still working.
//
// The submitter plans sources as it goes, and planning can be a director query
// or a stat.  It used to run on the caller's context, which nothing cancelled,
// and submitAndDrain returned on the first failing result without waiting for
// it -- so a submitter part-way through planning outlived the call for as long
// as that query took, and here, forever.
func TestSubmitAndDrainJoinsTheSubmitter(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	pelican_url.ResetState()
	t.Cleanup(pelican_url.ResetState)

	fed := test_utils.NewStubFederation(t, test_utils.StubFederationOptions{
		Contents: "hello",
		OnFetch: func(objectPath string) int {
			if objectPath == "/test/fails" {
				return http.StatusInternalServerError
			}
			return 0
		},
	})

	var blockedReturned atomic.Bool
	sawCancel := make(chan struct{})
	outcome := startBatch(t, fed, []string{"/test/fails", "/test/blocked"},
		func(ctx context.Context, engine *client.TransferEngine, tc *client.TransferClient, src string) (*client.TransferJob, error) {
			if src != "/test/blocked" {
				return downloadJob(t, ctx, engine, tc, src)
			}
			// Stands in for a director query that takes as long as it
			// takes: it ends only when the batch cancels it.
			defer blockedReturned.Store(true)
			select {
			case <-ctx.Done():
				close(sawCancel)
				return nil, ctx.Err()
			case <-time.After(batchDeadline):
				return nil, errors.New("the failing batch never cancelled the submitter")
			}
		})

	var got batchOutcome
	select {
	case got = <-outcome:
	case <-time.After(batchDeadline):
		t.Fatal("submitAndDrain did not return after a transfer failed")
	}

	assert.True(t, blockedReturned.Load(),
		"submitAndDrain returned while its submitter was still planning a source")
	select {
	case <-sawCancel:
	default:
		t.Error("the submitter was not cancelled; it returned for some other reason")
	}
	require.Error(t, got.err)
	assert.Equal(t, 0, got.failedIdx, "the failure is the transfer of the first source")
	assert.NotErrorIs(t, got.err, context.Canceled,
		"the cancellation that followed the failure must not be reported in its place")
}

// TestSubmitAndDrainPlanFailureEndsTheBatch: a source that cannot be planned
// ends the batch -- transfers already running are cancelled rather than left
// to finish -- and is what gets reported.
//
// Planning failures used to close the client and stop submitting, but leave
// whatever was in flight to run to completion.  Cancelling them fixes that and
// raises a second problem: each cancelled transfer then fails with
// context.Canceled, and only the first failure may be kept or the cause is
// lost.
func TestSubmitAndDrainPlanFailureEndsTheBatch(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	pelican_url.ResetState()
	t.Cleanup(pelican_url.ResetState)

	// The first source's fetch hangs until the test ends, so the batch can
	// only return if that transfer is cancelled.
	release := make(chan struct{})
	fed := test_utils.NewStubFederation(t, test_utils.StubFederationOptions{
		Contents: "hello",
		OnFetch: func(objectPath string) int {
			if objectPath == "/test/hangs" {
				<-release
			}
			return 0
		},
	})
	// Registered after the stub, so it runs first: the server's Close waits
	// for its handlers.
	t.Cleanup(func() { close(release) })

	planErr := errors.New("this source cannot be planned")
	outcome := startBatch(t, fed, []string{"/test/hangs", "/test/unplannable"},
		func(ctx context.Context, engine *client.TransferEngine, tc *client.TransferClient, src string) (*client.TransferJob, error) {
			if src == "/test/unplannable" {
				return nil, planErr
			}
			return downloadJob(t, ctx, engine, tc, src)
		})

	var got batchOutcome
	select {
	case got = <-outcome:
	case <-time.After(batchDeadline):
		t.Fatal("submitAndDrain waited on a running transfer after a source failed to plan")
	}

	assert.Equal(t, 1, got.failedIdx, "the failure is the planning of the second source")
	assert.ErrorIs(t, got.err, planErr,
		"the cancelled transfer's error must not be reported in place of the cause")
}
