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

package transfer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestTransferJobEventsSSEOverHTTP exercises the transfer server's SSE endpoint
// over real HTTP end-to-end (previously only the benchmark drove it): submit a
// job, then stream /jobs/:id/events and confirm the stream carries the job ID and
// ends with a terminal status rather than hanging.
func TestTransferJobEventsSSEOverHTTP(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tok := generateTransferToken(t, "sse-user")

	jreq := TransferJobCreateRequest{
		Transfers: []TransferItem{
			{Operation: "get", Source: "pelican:///test/hello.txt", Destination: "/tmp/hello.txt"},
		},
	}
	w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
	require.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
	var resp TransferJobResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.JobID)

	// Stream the job's status as Server-Sent Events. The source is unreachable so
	// the job terminates quickly; ServeHTTP returns when the stream closes.
	req, err := http.NewRequest(http.MethodGet, "/api/v1.0/transfer/jobs/"+resp.JobID+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "text/event-stream")
	ws := httptest.NewRecorder()
	engine.ServeHTTP(ws, req)

	require.Equal(t, http.StatusOK, ws.Code)
	assert.Contains(t, ws.Header().Get("Content-Type"), "text/event-stream")
	body := ws.Body.String()
	assert.Contains(t, body, "event: status")
	assert.Contains(t, body, resp.JobID, "every event carries the job ID")
	terminal := strings.Contains(body, `"status":"failed"`) ||
		strings.Contains(body, `"status":"completed"`) ||
		strings.Contains(body, `"status":"cancelled"`)
	assert.True(t, terminal, "the SSE stream must end with a terminal status; got: %s", body)
}

// TestTransferServerRestartMarksInflightJobsFailed simulates a real restart: a
// transfer_jobs row left in flight (no completed_at) when the server stopped must
// be reported as failed — not stuck — after a fresh manager and a fresh route
// registration run over the same database. This covers the whole
// startup-reconcile → GET path, not just reconcileInterruptedJobs in isolation.
func TestTransferServerRestartMarksInflightJobsFailed(t *testing.T) {
	_, db := setupTestEnvironment(t)
	tok := generateTransferToken(t, "restart-user")
	issuer := param.Server_ExternalWebUrl.GetString()

	// The auth middleware resolves (issuer, subject) → user; create that same
	// user so the job row we insert is owned by the token's identity.
	user, err := database.GetOrCreateUser(db, "restart-user", "restart-user", issuer, database.CreatorSelf())
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, db.Create(&TransferJob{
		ID: "inflight-restart", UserID: user.ID, RequestBody: "{}",
		CreatedAt: now, UpdatedAt: now, // completed_at NULL => in flight
	}).Error)

	// "Restart": a fresh manager + fresh route registration over the SAME DB
	// re-runs reconcileInterruptedJobs at startup.
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()
	tm2 := client_agent.NewTransferManager(ctx, 5, nil)
	engine2 := gin.New()
	engine2.Use(gin.Recovery())
	require.NoError(t, registerTransferRoutes(ctx, engine2, egrp, db, tm2))

	// On the restarted server the orphaned job must report failed, not stuck.
	w := doRequest(t, engine2, "GET", "/api/v1.0/transfer/jobs/inflight-restart", nil, tok)
	require.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())
	var status TransferJobStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
	assert.Equal(t, "failed", status.Status, "an interrupted job must be failed after restart")
	assert.Contains(t, status.Error, "interrupted", "it must carry the restart error")
}
