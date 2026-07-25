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

package client_agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJobCompletionCallbackFires verifies the manager invokes the registered
// completion callback exactly once per job when it reaches a terminal state, and
// that CreateJobWithID honors the caller-supplied ID (both are what the transfer
// server relies on for eager, durable terminal-state persistence).
func TestJobCompletionCallbackFires(t *testing.T) {
	tm := NewTransferManager(context.Background(), 5, nil)
	defer func() { _ = tm.Shutdown() }()

	var mu sync.Mutex
	calls := map[string]int{}
	lastStatus := map[string]string{}
	tm.SetJobCompletionCallback(func(job *TransferJob) {
		mu.Lock()
		calls[job.ID]++
		lastStatus[job.ID] = job.Status
		mu.Unlock()
	})

	// An operation the executor doesn't handle fails immediately (no network),
	// but still drives the full job lifecycle to a terminal state.
	const jobID = "caller-supplied-id"
	job, err := tm.CreateJobWithID(jobID, []TransferRequest{
		{Operation: "benchmark-noop", Source: "x", Destination: "y"},
	}, nil)
	require.NoError(t, err)
	require.Equal(t, jobID, job.ID, "CreateJobWithID must use the caller-supplied ID")

	job.wg.Wait() // callback fires (deferred) before wg.Done, so it has run by now

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, calls[jobID], "completion callback must fire exactly once")
	assert.Equal(t, StatusFailed, lastStatus[jobID], "a failed transfer must reach StatusFailed")
}

// TestEvictTerminalJobsFromMemory verifies the store-independent reaper (used by
// the transfer server, which runs the manager with no persistent store): a
// terminal job older than the grace is dropped from memory, while a recently
// finished job, a still-running job, and a terminal job that a client is still
// streaming are all kept.
func TestEvictTerminalJobsFromMemory(t *testing.T) {
	tm := NewTransferManager(context.Background(), 5, nil)
	defer func() { _ = tm.Shutdown() }()

	past := time.Now().Add(-10 * time.Minute)
	recent := time.Now()

	watched := &TransferJob{ID: "watched", Status: StatusCompleted, CompletedAt: &past}
	watched.subscriberCount.Store(1)

	tm.mu.Lock()
	tm.jobs["old"] = &TransferJob{ID: "old", Status: StatusCompleted, CompletedAt: &past}
	tm.jobs["recent"] = &TransferJob{ID: "recent", Status: StatusCompleted, CompletedAt: &recent}
	tm.jobs["running"] = &TransferJob{ID: "running", Status: StatusRunning}
	tm.jobs["watched"] = watched
	tm.mu.Unlock()

	tm.evictTerminalJobsFromMemory(5 * time.Minute)

	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, oldExists := tm.jobs["old"]
	_, recentExists := tm.jobs["recent"]
	_, runningExists := tm.jobs["running"]
	_, watchedExists := tm.jobs["watched"]
	assert.False(t, oldExists, "an aged terminal job must be evicted")
	assert.True(t, recentExists, "a job finished within the grace must be kept")
	assert.True(t, runningExists, "a non-terminal job must never be evicted")
	assert.True(t, watchedExists, "a terminal job with an active event-stream subscriber must be kept")
}

// TestCreateJobAdmissionControl verifies the manager rejects new submissions once
// the number of non-terminal jobs reaches the admission bound (maxJobs *
// maxQueuedJobFactor), so a client cannot exhaust memory/goroutines by flooding
// submissions.
func TestCreateJobAdmissionControl(t *testing.T) {
	orig := maxQueuedJobFactor
	maxQueuedJobFactor = 1
	defer func() { maxQueuedJobFactor = orig }()

	// bound = maxJobs(2) * factor(1) = 2
	tm := NewTransferManager(context.Background(), 2, nil)
	defer func() { _ = tm.Shutdown() }()

	tm.mu.Lock()
	tm.jobs["p1"] = &TransferJob{ID: "p1", Status: StatusPending}
	tm.jobs["p2"] = &TransferJob{ID: "p2", Status: StatusRunning}
	tm.mu.Unlock()

	_, err := tm.CreateJobWithID("p3", []TransferRequest{
		{Operation: "benchmark-noop", Source: "x", Destination: "y"},
	}, nil)
	require.ErrorIs(t, err, ErrTooManyJobs, "submissions past the bound must be rejected")
}
