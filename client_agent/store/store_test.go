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

package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) (*Store, string) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewStore(dbPath)
	require.NoError(t, err)
	require.NotNil(t, store)

	t.Cleanup(func() {
		store.Close()
		os.RemoveAll(tmpDir)
	})

	return store, dbPath
}

func TestNewStore(t *testing.T) {
	store, _ := setupTestDB(t)
	assert.NotNil(t, store)
	assert.NotNil(t, store.db)
}

func TestCreateAndGetJob(t *testing.T) {
	store, _ := setupTestDB(t)

	jobID := "test-job-1"
	status := "pending"
	createdAt := time.Now()
	optionsJSON := `{"token":"test-token","caches":["cache1","cache2"]}`

	// Create job
	err := store.CreateJob(jobID, status, createdAt, optionsJSON, 0)
	require.NoError(t, err)

	// Get job
	jobData, err := store.GetJob(jobID)
	require.NoError(t, err)
	job, ok := jobData.(*StoredJob)
	require.True(t, ok)
	assert.Equal(t, jobID, job.ID)
	assert.Equal(t, status, job.Status)
	assert.Equal(t, createdAt.Unix(), job.CreatedAt)
	assert.NotNil(t, job.Options)
	assert.Equal(t, "test-token", job.Options["token"])
	caches, ok := job.Options["caches"].([]interface{})
	require.True(t, ok)
	assert.Len(t, caches, 2)
}

func TestUpdateJobStatus(t *testing.T) {
	store, _ := setupTestDB(t)

	jobID := "test-job-2"
	err := store.CreateJob(jobID, "pending", time.Now(), "{}", 0)
	require.NoError(t, err)

	// Update status
	err = store.UpdateJobStatus(jobID, "running")
	require.NoError(t, err)

	// Verify update
	jobData, err := store.GetJob(jobID)
	require.NoError(t, err)
	job, ok := jobData.(*StoredJob)
	require.True(t, ok)
	assert.Equal(t, "running", job.Status)
}

func TestUpdateJobTimes(t *testing.T) {
	store, _ := setupTestDB(t)

	jobID := "test-job-3"
	err := store.CreateJob(jobID, "pending", time.Now(), "{}", 0)
	require.NoError(t, err)

	// Update started_at
	startedAt := time.Now()
	err = store.UpdateJobTimes(jobID, &startedAt, nil)
	require.NoError(t, err)

	jobData, err := store.GetJob(jobID)
	require.NoError(t, err)
	job, ok := jobData.(*StoredJob)
	require.True(t, ok)
	assert.NotNil(t, job.StartedAt)
	assert.Equal(t, startedAt.Unix(), job.StartedAt.Unix())

	// Update completed_at
	completedAt := time.Now().Add(5 * time.Second)
	err = store.UpdateJobTimes(jobID, nil, &completedAt)
	require.NoError(t, err)

	jobData, err = store.GetJob(jobID)
	require.NoError(t, err)
	job, ok = jobData.(*StoredJob)
	require.True(t, ok)
	assert.NotNil(t, job.CompletedAt)
	assert.Equal(t, completedAt.Unix(), job.CompletedAt.Unix())
}

func TestListJobs(t *testing.T) {
	store, _ := setupTestDB(t)

	// Create multiple jobs
	for i := 0; i < 5; i++ {
		jobID := "test-job-" + string(rune(i))
		status := "pending"
		if i%2 == 0 {
			status = "completed"
		}
		err := store.CreateJob(jobID, status, time.Now(), "{}", 0)
		require.NoError(t, err)
	}

	// List all jobs
	jobsData, total, err := store.ListJobs("", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	jobs, ok := jobsData.([]*StoredJob)
	require.True(t, ok)
	assert.Len(t, jobs, 5)

	// List by status
	jobsData, total, err = store.ListJobs("completed", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	jobs, ok = jobsData.([]*StoredJob)
	require.True(t, ok)
	assert.Len(t, jobs, 3)

	// Test pagination
	jobsData, total, err = store.ListJobs("", 2, 0)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	jobs, ok = jobsData.([]*StoredJob)
	require.True(t, ok)
	assert.Len(t, jobs, 2)
}

func TestCreateAndGetTransfer(t *testing.T) {
	store, _ := setupTestDB(t)

	jobID := "test-job-1"
	err := store.CreateJob(jobID, "pending", time.Now(), "{}", 0)
	require.NoError(t, err)

	transfer := &StoredTransfer{
		ID:          "transfer-1",
		JobID:       jobID,
		Operation:   "get",
		Source:      "/source/path",
		Destination: "/dest/path",
		Recursive:   true,
		Status:      "pending",
		CreatedAt:   time.Now().Unix(),
	}

	err = store.CreateTransfer(transfer)
	require.NoError(t, err)

	// Get transfer
	retrievedData, err := store.GetTransfer(transfer.ID)
	require.NoError(t, err)
	retrieved, ok := retrievedData.(*StoredTransfer)
	require.True(t, ok)
	assert.Equal(t, transfer.ID, retrieved.ID)
	assert.Equal(t, transfer.JobID, retrieved.JobID)
	assert.Equal(t, transfer.Operation, retrieved.Operation)
	assert.Equal(t, transfer.Source, retrieved.Source)
	assert.Equal(t, transfer.Destination, retrieved.Destination)
}

func TestGetTransfersByJob(t *testing.T) {
	store, _ := setupTestDB(t)

	jobID := "test-job-1"
	err := store.CreateJob(jobID, "pending", time.Now(), "{}", 0)
	require.NoError(t, err)

	// Create multiple transfers
	for i := 0; i < 3; i++ {
		transfer := &StoredTransfer{
			ID:          "transfer-" + string(rune(i)),
			JobID:       jobID,
			Operation:   "get",
			Source:      "/source",
			Destination: "/dest",
			Status:      "pending",
			CreatedAt:   time.Now().Unix(),
		}
		err := store.CreateTransfer(transfer)
		require.NoError(t, err)
	}

	// Get transfers by job
	transfersData, err := store.GetTransfersByJob(jobID)
	require.NoError(t, err)
	transfers, ok := transfersData.([]*StoredTransfer)
	require.True(t, ok)
	assert.Len(t, transfers, 3)
	for _, transfer := range transfers {
		assert.Equal(t, jobID, transfer.JobID)
	}
}

func TestUpdateTransferProgress(t *testing.T) {
	store, _ := setupTestDB(t)

	jobID := "test-job-1"
	err := store.CreateJob(jobID, "pending", time.Now(), "{}", 0)
	require.NoError(t, err)

	transfer := &StoredTransfer{
		ID:          "transfer-1",
		JobID:       jobID,
		Operation:   "get",
		Source:      "/source",
		Destination: "/dest",
		Status:      "running",
		CreatedAt:   time.Now().Unix(),
	}
	err = store.CreateTransfer(transfer)
	require.NoError(t, err)

	// Update progress
	err = store.UpdateTransferProgress(transfer.ID, 512, 1024)
	require.NoError(t, err)

	// Verify update
	retrievedData, err := store.GetTransfer(transfer.ID)
	require.NoError(t, err)
	retrieved, ok := retrievedData.(*StoredTransfer)
	require.True(t, ok)
	assert.Equal(t, int64(512), retrieved.BytesTransferred)
	assert.Equal(t, int64(1024), retrieved.TotalBytes)
}

func TestGetRecoverableJobs(t *testing.T) {
	store, _ := setupTestDB(t)

	// Create jobs with different statuses
	statuses := []string{
		"pending",
		"running",
		"completed",
		"failed",
	}

	for i, status := range statuses {
		jobID := "test-job-" + string(rune(i))
		err := store.CreateJob(jobID, status, time.Now(), "{}", 0)
		require.NoError(t, err)
	}

	// Get recoverable jobs (only pending and running)
	jobsData, err := store.GetRecoverableJobs()
	require.NoError(t, err)
	jobs, ok := jobsData.([]*StoredJob)
	require.True(t, ok)
	assert.Len(t, jobs, 2)

	for _, job := range jobs {
		assert.Contains(t, []string{"pending", "running"}, job.Status)
	}
}

func TestArchiveJob(t *testing.T) {
	store, _ := setupTestDB(t)

	jobID := "test-job-1"
	createdAt := time.Now()
	startedAt := createdAt.Add(1 * time.Second)
	completedAt := createdAt.Add(10 * time.Second)

	// Create job
	err := store.CreateJob(jobID, "running", createdAt, "{}", 0)
	require.NoError(t, err)
	err = store.UpdateJobTimes(jobID, &startedAt, nil)
	require.NoError(t, err)

	// Create transfers
	for i := 0; i < 3; i++ {
		transfer := &StoredTransfer{
			ID:          "transfer-" + string(rune(i)),
			JobID:       jobID,
			Operation:   "get",
			Source:      "/source",
			Destination: "/dest",
			Status:      "completed",
			CreatedAt:   createdAt.Unix(),
		}
		err := store.CreateTransfer(transfer)
		require.NoError(t, err)

		// Update progress
		err = store.UpdateTransferProgress(transfer.ID, 1024, 1024)
		require.NoError(t, err)
	}

	// Update job to completed
	err = store.UpdateJobStatus(jobID, "completed")
	require.NoError(t, err)
	err = store.UpdateJobTimes(jobID, nil, &completedAt)
	require.NoError(t, err)

	// Archive job
	err = store.ArchiveJob(jobID)
	require.NoError(t, err)

	// Verify job is no longer in active table
	_, err = store.GetJob(jobID)
	assert.Error(t, err)

	// Verify job is in history
	jobsData, total, err := store.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	jobs, ok := jobsData.([]*HistoricalJob)
	require.True(t, ok)
	assert.Len(t, jobs, 1)
	assert.Equal(t, jobID, jobs[0].ID)
	assert.Equal(t, 3, jobs[0].TransfersCompleted)
	assert.Equal(t, int64(3072), jobs[0].BytesTransferred)
}

func TestPruneHistory(t *testing.T) {
	store, _ := setupTestDB(t)

	// Create old jobs
	oldTime := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 3; i++ {
		jobID := "old-job-" + string(rune(i))
		err := store.CreateJob(jobID, "completed", oldTime, "{}", 0)
		require.NoError(t, err)
		completedAt := oldTime.Add(1 * time.Hour)
		err = store.UpdateJobTimes(jobID, nil, &completedAt)
		require.NoError(t, err)
		err = store.ArchiveJob(jobID)
		require.NoError(t, err)
	}

	// Create recent jobs
	recentTime := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 2; i++ {
		jobID := "recent-job-" + string(rune(i))
		err := store.CreateJob(jobID, "completed", recentTime, "{}", 0)
		require.NoError(t, err)
		completedAt := recentTime.Add(10 * time.Minute)
		err = store.UpdateJobTimes(jobID, nil, &completedAt)
		require.NoError(t, err)
		err = store.ArchiveJob(jobID)
		require.NoError(t, err)
	}

	// Prune old jobs (older than 24 hours)
	pruneThreshold := time.Now().Add(-24 * time.Hour)
	pruned, err := store.PruneHistory(pruneThreshold)
	require.NoError(t, err)
	assert.Equal(t, 3, pruned)

	// Verify only recent jobs remain
	jobsData, total, err := store.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	jobs, ok := jobsData.([]*HistoricalJob)
	require.True(t, ok)
	assert.Len(t, jobs, 2)
}
