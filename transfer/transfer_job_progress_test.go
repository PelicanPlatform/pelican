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

// A job the transfer manager still holds reports real counters, which may
// legitimately be zero before anything has moved.  The point of the pointer is
// that this case is distinguishable from the evicted one below.
func TestTransferJobStatusCarriesProgressForLiveJob(t *testing.T) {
	engine, _ := setupTestEnvironment(t)
	tok := generateTransferToken(t, "progress-user")

	jreq := TransferJobCreateRequest{
		Transfers: []TransferItem{
			{
				Operation:   "get",
				Source:      "pelican:///test/file.txt",
				Destination: "/tmp/file.txt",
			},
		},
	}
	w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
	require.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())
	var created TransferJobResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	t.Run("get", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/jobs/"+created.JobID, nil, tok)
		require.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())
		var status TransferJobStatus
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
		require.NotNil(t, status.Progress, "a job still in memory must report progress")
		assert.Equal(t, 1, status.Progress.TransfersTotal)
		assert.GreaterOrEqual(t, status.Progress.BytesTransferred, int64(0))
	})

	t.Run("list", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/jobs", nil, tok)
		require.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())
		var listResp TransferJobListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		require.NotEmpty(t, listResp.Jobs)
		for _, job := range listResp.Jobs {
			if job.JobID == created.JobID {
				require.NotNil(t, job.Progress, "a job still in memory must report progress in the list")
				assert.Equal(t, 1, job.Progress.TransfersTotal)
				return
			}
		}
		t.Fatalf("job %s missing from the list", created.JobID)
	})
}

// A job whose status is rebuilt from the durable record has no byte counts
// behind it.  Reporting zero there would be a lie that a reader could not tell
// from a job that genuinely has not moved any bytes, so the field is absent.
func TestTransferJobStatusOmitsProgressForEvictedJob(t *testing.T) {
	_, db := setupTestEnvironment(t)
	tok := generateTransferToken(t, "evicted-user")
	issuer := param.Server_ExternalWebUrl.GetString()

	user, err := database.GetOrCreateUser(db, "evicted-user", "evicted-user", issuer, database.CreatorSelf())
	require.NoError(t, err)

	now := time.Now()
	completed := now.Add(-time.Minute)
	require.NoError(t, db.Create(&TransferJob{
		ID: "evicted-job", UserID: user.ID, RequestBody: "{}",
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now, CompletedAt: &completed,
	}).Error)

	// A fresh manager over the same DB: the row survives, the in-memory job
	// does not -- exactly what a server restart leaves behind.
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer cancel()
	tm := client_agent.NewTransferManager(ctx, 5, nil)
	engine := gin.New()
	engine.Use(gin.Recovery())
	require.NoError(t, registerTransferRoutes(ctx, engine, egrp, db, tm))

	t.Run("get", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/jobs/evicted-job", nil, tok)
		require.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())
		var status TransferJobStatus
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
		assert.Nil(t, status.Progress, "an evicted job must not invent byte counts")
		// The field has to be genuinely absent, not a zeroed object.
		var raw map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
		assert.NotContains(t, raw, "progress")
	})

	t.Run("list", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/jobs", nil, tok)
		require.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())
		var listResp TransferJobListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		require.NotEmpty(t, listResp.Jobs)
		for _, job := range listResp.Jobs {
			if job.JobID == "evicted-job" {
				assert.Nil(t, job.Progress, "an evicted job must not invent byte counts in the list")
				return
			}
		}
		t.Fatalf("job evicted-job missing from the list")
	})
}
