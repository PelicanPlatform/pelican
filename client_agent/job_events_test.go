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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSubscribeJobDeliversEvents verifies the job-event hub delivers the running
// and terminal transitions to a subscriber registered before the job ran, and
// that the terminal event carries the failure error.
func TestSubscribeJobDeliversEvents(t *testing.T) {
	tm := NewTransferManager(context.Background(), 5, nil)
	defer func() { _ = tm.Shutdown() }()

	// Subscribe BEFORE creating the job (the documented race-free ordering).
	events, unsub := tm.SubscribeJob("evt-job")
	defer unsub()

	_, err := tm.CreateJobWithID("evt-job", []TransferRequest{
		{Operation: "benchmark-noop", Source: "x", Destination: "y"},
	}, nil)
	require.NoError(t, err)

	var got []string
	timeout := time.After(5 * time.Second)
	for terminal := false; !terminal; {
		select {
		case ev := <-events:
			require.Equal(t, "evt-job", ev.JobID)
			got = append(got, ev.Status)
			if IsTerminalStatus(ev.Status) {
				assert.Equal(t, StatusFailed, ev.Status, "an unhandled operation fails")
				assert.NotEmpty(t, ev.Error, "the terminal event must carry the failure error")
				terminal = true
			}
		case <-timeout:
			t.Fatalf("did not receive a terminal event; got %v", got)
		}
	}
	assert.Contains(t, got, StatusRunning, "should have observed the running transition")
	assert.Contains(t, got, StatusFailed)
}

// TestSubscribeAfterTerminalUsesCurrentStatus documents the other half of the
// race contract: a subscriber that registers AFTER the job finished receives no
// event, but the terminal status is visible via GetJob — so an SSE handler that
// emits the current status after subscribing never blocks forever.
func TestSubscribeAfterTerminalUsesCurrentStatus(t *testing.T) {
	tm := NewTransferManager(context.Background(), 5, nil)
	defer func() { _ = tm.Shutdown() }()

	job, err := tm.CreateJobWithID("done-job", []TransferRequest{
		{Operation: "benchmark-noop", Source: "x", Destination: "y"},
	}, nil)
	require.NoError(t, err)
	job.wg.Wait() // job is terminal

	events, unsub := tm.SubscribeJob("done-job")
	defer unsub()

	// The current status (read after subscribing) is authoritative.
	cur, err := tm.GetJob("done-job")
	require.NoError(t, err)
	require.True(t, IsTerminalStatus(cur.Status))

	// No further event arrives (nothing to deliver post-terminal).
	select {
	case ev := <-events:
		t.Fatalf("unexpected event after terminal: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}
