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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStreamJobEventsSSE exercises the shared SSE core used by both the transfer
// server and the client agent: the synchronous-submit path (create a job, then
// stream its status to terminal over one connection) and the watch path
// (streaming an already-terminal job returns its final status immediately).
func TestStreamJobEventsSSE(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tm := NewTransferManager(context.Background(), 5, nil)
	defer func() { _ = tm.Shutdown() }()

	r := gin.New()
	r.POST("/jobs", func(c *gin.Context) {
		job, err := tm.CreateJobWithID("sync-job", []TransferRequest{
			{Operation: "benchmark-noop", Source: "x", Destination: "y"},
		}, nil)
		require.NoError(t, err)
		tm.StreamJobEvents(c, job.ID, "")
	})
	r.GET("/jobs/:id/events", func(c *gin.Context) {
		tm.StreamJobEvents(c, c.Param("id"), "")
	})

	// Synchronous submit: the response is an SSE stream whose first event carries
	// the job ID (for the client to persist) and which ends with the terminal
	// event — the whole transfer in one call.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/jobs", nil)
	req.Header.Set("Accept", "text/event-stream")
	r.ServeHTTP(w, req)

	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")
	body := w.Body.String()
	assert.Contains(t, body, `"job_id":"sync-job"`, "every event must carry the job ID")
	assert.Contains(t, body, `"status":"failed"`, "the stream must end with the terminal status")
	assert.Contains(t, body, "event: status")

	// Watch an already-terminal job: the current status is emitted immediately
	// and the stream closes (no hang). Channel-delivered streaming of the
	// running->terminal transitions is covered by TestSubscribeJobDeliversEvents.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/jobs/sync-job/events", nil)
	r.ServeHTTP(w2, req2)
	assert.Contains(t, w2.Body.String(), `"status":"failed"`)
}

// TestStreamJobEventsRecoversDroppedTerminal is a regression test for the
// best-effort event buffer: if a job's terminal event is dropped because a slow
// subscriber's buffer was full, the stream must still report completion (via the
// keepalive re-read of the current status) rather than hang on keepalives
// forever. We reproduce the drop deterministically by transitioning the job to
// terminal in memory without ever publishing an event on the channel.
func TestStreamJobEventsRecoversDroppedTerminal(t *testing.T) {
	gin.SetMode(gin.TestMode)

	orig := sseKeepAliveInterval
	sseKeepAliveInterval = 15 * time.Millisecond
	defer func() { sseKeepAliveInterval = orig }()

	tm := NewTransferManager(context.Background(), 5, nil)
	defer func() { _ = tm.Shutdown() }()

	// Insert a running job directly so the stream starts non-terminal and enters
	// its event loop. No terminal event is ever published on the subscriber
	// channel — that models the dropped-from-full-buffer case.
	tm.mu.Lock()
	tm.jobs["stuck-job"] = &TransferJob{ID: "stuck-job", Status: StatusRunning}
	tm.mu.Unlock()

	r := gin.New()
	r.GET("/jobs/:id/events", func(c *gin.Context) {
		tm.StreamJobEvents(c, c.Param("id"), "")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/jobs/stuck-job/events", nil)
	req.Header.Set("Accept", "text/event-stream")

	done := make(chan struct{})
	go func() {
		r.ServeHTTP(w, req)
		close(done)
	}()

	// Let the stream emit the initial running status and settle into its loop,
	// then flip the job to terminal in memory without publishing an event.
	time.Sleep(50 * time.Millisecond)
	tm.mu.Lock()
	tm.jobs["stuck-job"].Status = StatusCompleted
	tm.mu.Unlock()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("StreamJobEvents hung: a dropped terminal event was never recovered on the keepalive tick")
	}
	assert.Contains(t, w.Body.String(), `"status":"completed"`,
		"the stream must report the terminal status recovered on the keepalive tick")
}
