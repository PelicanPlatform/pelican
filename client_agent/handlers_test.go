/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateJob(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create transfer manager
	ctx := context.Background()
	tm := NewTransferManager(ctx, 5, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create server
	server := &Server{
		transferManager: tm,
		router:          gin.New(),
	}
	server.setupRoutes()

	// Create test request
	jobReq := JobRequest{
		Transfers: []TransferRequest{
			{
				Operation:   "get",
				Source:      "osdf:///test/file.txt",
				Destination: "/tmp/test.txt",
				Recursive:   false,
			},
		},
	}

	body, err := json.Marshal(jobReq)
	require.NoError(t, err)

	// Make request
	req, _ := http.NewRequest("POST", "/api/v1/xfer/jobs", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	// Check response
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp JobResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.JobID)
	assert.Equal(t, StatusPending, resp.Status)
	assert.Len(t, resp.Transfers, 1)
	assert.Equal(t, "get", resp.Transfers[0].Operation)
}

func TestGetJobStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := context.Background()
	tm := NewTransferManager(ctx, 5, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create a job
	job, err := tm.CreateJob([]TransferRequest{
		{
			Operation:   "get",
			Source:      "osdf:///test/file.txt",
			Destination: "/tmp/test.txt",
		},
	}, nil)
	require.NoError(t, err)

	// Create server
	server := &Server{
		transferManager: tm,
		router:          gin.New(),
	}
	server.setupRoutes()

	// Get job status
	req, _ := http.NewRequest("GET", "/api/v1/xfer/jobs/"+job.ID, nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var status JobStatus
	err = json.Unmarshal(w.Body.Bytes(), &status)
	require.NoError(t, err)

	assert.Equal(t, job.ID, status.JobID)
	assert.Contains(t, []string{StatusPending, StatusRunning}, status.Status)
	assert.Len(t, status.Transfers, 1)
	assert.NotNil(t, status.Progress)
}

func TestCancelJob(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := context.Background()
	tm := NewTransferManager(ctx, 5, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create a job
	job, err := tm.CreateJob([]TransferRequest{
		{
			Operation:   "get",
			Source:      "osdf:///test/file.txt",
			Destination: "/tmp/test.txt",
		},
	}, nil)
	require.NoError(t, err)

	// Wait a moment for job to start
	time.Sleep(100 * time.Millisecond)

	// Create server
	server := &Server{
		transferManager: tm,
		router:          gin.New(),
	}
	server.setupRoutes()

	// Cancel job
	req, _ := http.NewRequest("DELETE", "/api/v1/xfer/jobs/"+job.ID, nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CancelResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, job.ID, resp.JobID)
	assert.GreaterOrEqual(t, resp.TransfersCancelled+resp.TransfersCompleted, 1)
}

func TestListJobs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := context.Background()
	tm := NewTransferManager(ctx, 5, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create multiple jobs
	for i := 0; i < 3; i++ {
		_, err := tm.CreateJob([]TransferRequest{
			{
				Operation:   "get",
				Source:      "osdf:///test/file.txt",
				Destination: "/tmp/test.txt",
			},
		}, nil)
		require.NoError(t, err)
	}

	// Create server
	server := &Server{
		transferManager: tm,
		router:          gin.New(),
	}
	server.setupRoutes()

	// List jobs
	req, _ := http.NewRequest("GET", "/api/v1/xfer/jobs?limit=10&offset=0", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp JobListResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, 3, resp.Total)
	assert.LessOrEqual(t, len(resp.Jobs), 10)
}

func TestHealthCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := &Server{
		router: gin.New(),
	}
	server.setupRoutes()

	req, _ := http.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "ok", resp.Status)
	assert.NotEmpty(t, resp.Version)
	assert.GreaterOrEqual(t, resp.UptimeSeconds, int64(0))
}

func TestInvalidJobRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := context.Background()
	tm := NewTransferManager(ctx, 5, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	server := &Server{
		transferManager: tm,
		router:          gin.New(),
	}
	server.setupRoutes()

	// Invalid request - no transfers
	jobReq := JobRequest{
		Transfers: []TransferRequest{},
	}

	body, _ := json.Marshal(jobReq)
	req, _ := http.NewRequest("POST", "/api/v1/xfer/jobs", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &errResp)
	require.NoError(t, err)

	assert.Equal(t, ErrCodeInvalidRequest, errResp.Code)
	assert.Contains(t, errResp.Error, "Transfers")
}

func TestGetJobNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := context.Background()
	tm := NewTransferManager(ctx, 5, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	server := &Server{
		transferManager: tm,
		router:          gin.New(),
	}
	server.setupRoutes()

	req, _ := http.NewRequest("GET", "/api/v1/xfer/jobs/nonexistent-id", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var errResp ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &errResp)
	require.NoError(t, err)

	assert.Equal(t, ErrCodeNotFound, errResp.Code)
}

func TestTransferManagerConcurrency(t *testing.T) {
	ctx := context.Background()
	maxJobs := 2
	tm := NewTransferManager(ctx, maxJobs, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create more jobs than the limit
	jobCount := 5
	jobs := make([]*TransferJob, jobCount)

	for i := 0; i < jobCount; i++ {
		job, err := tm.CreateJob([]TransferRequest{
			{
				Operation:   "get",
				Source:      "osdf:///test/file.txt",
				Destination: "/tmp/test.txt",
			},
		}, nil)
		require.NoError(t, err)
		jobs[i] = job
	}

	// Wait for jobs to start
	time.Sleep(500 * time.Millisecond)

	// Count running jobs (should not exceed maxJobs)
	runningCount := 0
	for _, job := range jobs {
		if job.Status == StatusRunning {
			runningCount++
		}
	}

	assert.LessOrEqual(t, runningCount, maxJobs, "Running jobs should not exceed max concurrent jobs")
}

func TestShutdownHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm := NewTransferManager(ctx, 5, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	server := &Server{
		transferManager: tm,
		router:          gin.New(),
		ctx:             ctx,
		cancel:          cancel,
		started:         false, // Don't mark as started to prevent actual shutdown
	}

	server.setupRoutes()

	// Make shutdown request
	req, _ := http.NewRequest("POST", "/shutdown", nil)
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "Server shutdown initiated", resp["message"])

	// Wait a bit for the shutdown goroutine to attempt execution
	time.Sleep(200 * time.Millisecond)

	// The shutdown should have been called (even if it errors due to not being started)
	// The important part is that the handler responds correctly
}
