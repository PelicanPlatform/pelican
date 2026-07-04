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
