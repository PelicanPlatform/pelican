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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// newSubmitTestEngine builds the smallest TransferEngine that
// createTransferFiles and submitFile actually touch. Nothing reads te.files,
// so a submission that reaches the raw channel parks there until its context
// is cancelled -- which is the state this file needs to exercise.
func newSubmitTestEngine(ctx context.Context) *TransferEngine {
	return &TransferEngine{
		ctx:     ctx,
		files:   make(chan *clientTransferFile),
		results: make(chan *clientTransferResults, 16),
	}
}

// newSubmitTestJob builds a non-recursive download job pointed at one object
// server. createTransferFiles takes the straight-line path for this shape:
// build the attempt list, count the file, submit it.
func newSubmitTestJob(ctx context.Context, host string) *clientTransferJob {
	return &clientTransferJob{
		uuid: uuid.New(),
		job: &TransferJob{
			uuid:      uuid.New(),
			ctx:       ctx,
			xferType:  transferTypeDownload,
			localPath: "/dev/null",
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   "example-federation.org",
				Path:   "/ns/object",
			},
			dirResp: server_structs.DirectorResponse{
				ObjectServers: []*url.URL{{Scheme: "https", Host: host, Path: "/ns/object"}},
			},
		},
	}
}

// TestCreateTransferFilesSubmitErrorDoesNotOrphanJob pins what happens when a
// file is counted against a job and then fails to reach the worker pool for a
// reason other than a scheduler shed -- in practice, the job's context being
// cancelled while the job handler is parked handing the file off.
//
// No result is ever produced for such a file. If the job kept the file in its
// activeXfer count and reported no lookup error, the job would
// never be considered finished: activeXfer would never reach zero, the
// client's results channel would never close, and TransferClient.Shutdown()
// would block forever. The cache hits this path per download, so the leak is
// one goroutine and one wedged job per cancelled request.
func TestCreateTransferFilesSubmitErrorDoesNotOrphanJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	te := newSubmitTestEngine(ctx)

	jobCtx, jobCancel := context.WithCancel(ctx)
	job := newSubmitTestJob(jobCtx, "origin.example.com")

	// createTransferFiles parks in the handoff because nothing reads te.files.
	errCh := make(chan error, 1)
	go func() { errCh <- te.createTransferFiles(job) }()

	// Wait until the file has actually been counted and the handoff is under
	// way; cancelling before that would exercise a different path.
	require.Eventually(t, func() bool { return job.job.activeXfer.Load() == 1 },
		5*time.Second, time.Millisecond, "expected the file to be counted before submission")

	jobCancel()

	var err error
	select {
	case err = <-errCh:
	case <-ctx.Done():
		t.Fatal("createTransferFiles never returned after the job context was cancelled")
	}

	// The error has to reach the caller: runJobHandler stores it as the job's
	// lookupErr, which is what tells runMux the job is over.
	require.Error(t, err, "a submission failure must be reported, not swallowed")
	assert.ErrorIs(t, err, context.Canceled)

	// And the bookkeeping has to be undone, because no result is coming for a
	// file that was never queued.
	assert.Zero(t, job.job.activeXfer.Load(), "active count must not outlive the failed submission")
	assert.Empty(t, te.results, "a submission that never happened produces no result")
}

// TestCreateTransferFilesSchedulerRejectionCompletesJob pins the other half of
// the contract. A scheduler shed is not a lookup failure: submitFile has
// already pushed a synthetic failure result for the file, so the counts must
// stay as they are and the job must be allowed to complete normally through
// that result. Reporting a lookup error here instead would double-count the
// failure; rolling the counts back would leave a result with nothing to
// decrement.
func TestCreateTransferFilesSchedulerRejectionCompletesJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	te := newSubmitTestEngine(ctx)

	// A scheduler with no room at all: every submission is shed.
	sched := NewTagScheduler(1, SchedulerConfig{
		PerTagStarvingPercent: 50,
		PerTagActivePercent:   50,
		PendingBufferSize:     1,
		PerTagPendingSize:     1,
		EMAWindow:             time.Second,
	})
	te.scheduler = sched
	egrp, _ := errgroup.WithContext(ctx)
	sched.Start(ctx, egrp, te.files)
	t.Cleanup(func() {
		sched.Stop()
		require.NoError(t, egrp.Wait())
	})

	// Fill the one pending slot so the next submission has nowhere to go. The
	// scheduler cannot dispatch it because nothing reads te.files.
	require.NoError(t, sched.Submit(ctx, "origin.example.com", makeFile("origin.example.com")))
	require.Eventually(t, func() bool {
		return sched.Snapshot(ctx).Global.TotalAdmits == 1
	}, 5*time.Second, time.Millisecond)

	job := newSubmitTestJob(ctx, "origin.example.com")
	require.NoError(t, te.createTransferFiles(job),
		"a shed is reported through the results channel, not as a lookup failure")

	assert.Equal(t, int64(1), job.job.activeXfer.Load(),
		"the synthetic result has not been consumed yet, so it is still outstanding")

	// Exactly one result, carrying the retryable throttle error and enough
	// context for the job-status displays that consume it.
	require.Len(t, te.results, 1, "a shed file produces exactly one synthetic result")
	res := <-te.results
	assert.Equal(t, job.job.uuid, res.results.JobId)
	assert.ErrorIs(t, res.results.Error, ErrTooManyRequests)
	assert.True(t, IsRetryable(res.results.Error), "a shed must be retryable")
	assert.NotNil(t, res.results.Attempts, "job status displays expect a non-nil attempt list")
}

// TestSchedulerShutdownDrainsQueuedFilesToResults pins the drain that runs
// when a scheduler stops with transfers still queued. Those transfers will
// never run, and their jobs are waiting on a result for each one, so the
// scheduler hands them to the engine's onDrop hook which turns each into a
// synthetic failure result. Without it a cache shutting down would leave
// every queued transfer's job waiting forever.
func TestSchedulerShutdownDrainsQueuedFilesToResults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	te := newSubmitTestEngine(ctx)

	sched := NewTagScheduler(1, SchedulerConfig{
		PerTagStarvingPercent: 50,
		PerTagActivePercent:   50,
		PendingBufferSize:     10,
		PerTagPendingSize:     10,
		EMAWindow:             time.Second,
	})
	te.scheduler = sched
	// Stands in for the hook NewTransferEngine installs; that the engine
	// actually installs it is asserted separately, by
	// TestTransferEngineInstallsSchedulerDrainHook.
	sched.onDrop = func(file *clientTransferFile) {
		select {
		case te.results <- synthesizeRejectionResult(file, errors.New("transfer engine shut down before the transfer could be dispatched")):
		case <-te.ctx.Done():
		}
	}
	egrp, _ := errgroup.WithContext(ctx)
	sched.Start(ctx, egrp, te.files)

	// Queue several files for a job. Nothing reads te.files, so the scheduler
	// parks on its first dispatch and the rest stay in the FIFO.
	job := newSubmitTestJob(ctx, "origin.example.com")
	const queued = 5
	for i := 0; i < queued; i++ {
		f := makeFile("origin.example.com")
		f.jobId = job.job.uuid
		f.file.job = job.job
		job.job.activeXfer.Add(1)
		require.NoError(t, sched.Submit(ctx, "origin.example.com", f))
	}
	require.Eventually(t, func() bool {
		return sched.Snapshot(ctx).Global.TotalAdmits == queued
	}, 5*time.Second, time.Millisecond)

	sched.Stop()
	require.NoError(t, egrp.Wait())

	// Every file the scheduler was still holding owes its job a result. The
	// one it had parked on mid-dispatch is not in the FIFO any more, so it is
	// the only one that does not come back this way.
	drained := len(te.results)
	assert.GreaterOrEqual(t, drained, queued-1,
		"queued transfers must not vanish without a result; their job would wait on them forever")
	for i := 0; i < drained; i++ {
		res := <-te.results
		assert.Equal(t, job.job.uuid, res.results.JobId)
		require.Error(t, res.results.Error)
		assert.NotNil(t, res.results.Attempts,
			"a drained transfer still needs the fields job status displays read")
	}
}

// TestTransferEngineInstallsSchedulerDrainHook pins the wiring the test above
// stands in for: without it, transfers still queued when the engine shuts down
// are dropped silently and the jobs waiting on them never complete.
func TestTransferEngineInstallsSchedulerDrainHook(t *testing.T) {
	// The real constructor refuses to build an engine until the client is
	// initialized; without this the test only passes when some earlier test in
	// the package happened to do it.
	test_utils.InitClient(t, map[param.Param]any{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sched := NewTagScheduler(1, SchedulerConfig{
		PerTagStarvingPercent: 50,
		PerTagActivePercent:   50,
		PendingBufferSize:     10,
		PerTagPendingSize:     10,
		EMAWindow:             time.Second,
	})
	te, err := NewTransferEngine(ctx, WithWorkerCount(1), WithScheduler(sched))
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		_ = te.Shutdown()
	})

	require.Same(t, sched, te.scheduler, "the configured scheduler must be the one the engine uses")
	require.NotNil(t, sched.onDrop,
		"the engine must give the scheduler somewhere to hand undispatched transfers at shutdown")
}
