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
