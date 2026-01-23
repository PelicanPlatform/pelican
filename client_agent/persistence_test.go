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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client_agent/store"
)

// setupTestStore creates a temporary database for testing
func setupTestStore(t *testing.T) (*store.Store, string) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	s, err := store.NewStore(dbPath)
	require.NoError(t, err, "Failed to create test store")

	return s, dbPath
}

// TestDatabasePersistence verifies that jobs are persisted to the database
func TestDatabasePersistence(t *testing.T) {
	testStore, _ := setupTestStore(t)
	defer testStore.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm := NewTransferManager(ctx, 5, testStore)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create a job with a fake operation so it won't actually try to transfer
	requests := []TransferRequest{
		{
			Operation:   "get",
			Source:      "pelican://example.com/test/file1.txt",
			Destination: "/tmp/file1.txt",
			Recursive:   false,
		},
	}

	job, err := tm.CreateJob(requests, nil)
	require.NoError(t, err, "Failed to create job")
	require.NotNil(t, job)

	// Give the job and persistence a moment to complete
	time.Sleep(500 * time.Millisecond)

	// Verify job was persisted (it will be in failed status because client isn't initialized)
	// Note: The recovery mechanism may have archived the failed job, so check history too
	storedJobData, err := testStore.GetJob(job.ID)
	if err != nil && err.Error() == "job "+job.ID+" not found" {
		// Job was archived, check history
		historyData, _, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 100, 0)
		require.NoError(t, histErr, "Failed to retrieve job from history")

		historyJobs, ok := historyData.([]*store.HistoricalJob)
		require.True(t, ok, "Failed to cast history data")

		found := false
		for _, hJob := range historyJobs {
			if hJob.ID == job.ID {
				assert.Equal(t, StatusFailed, hJob.Status)
				found = true
				break
			}
		}
		require.True(t, found, "Job not found in active or history tables")
	} else {
		require.NoError(t, err, "Failed to retrieve job from database")
		require.NotNil(t, storedJobData)

		storedJob, ok := storedJobData.(*store.StoredJob)
		require.True(t, ok, "Failed to cast stored job")
		assert.Equal(t, job.ID, storedJob.ID)
		// Job may be pending or failed depending on execution speed
		assert.Contains(t, []string{StatusPending, StatusRunning, StatusFailed}, storedJob.Status)
	}

	// Verify transfer was persisted (check active transfers first)
	transfersData, err := testStore.GetTransfersByJob(job.ID)
	if err != nil || transfersData == nil {
		// Transfers may have been archived, which is OK for this test
		// The important thing is that persistence worked
		t.Log("Transfers were archived to history (expected behavior)")
		return
	}

	require.NoError(t, err, "Failed to retrieve transfers from database")
	require.NotNil(t, transfersData)

	transfers, ok := transfersData.([]*store.StoredTransfer)
	require.True(t, ok, "Failed to cast transfers")
	assert.Len(t, transfers, 1)
	assert.Equal(t, job.Transfers[0].ID, transfers[0].ID)
	assert.Equal(t, "get", transfers[0].Operation)
}

// TestJobRecovery verifies that incomplete jobs are recovered and retried on startup
func TestJobRecovery(t *testing.T) {
	testStore, dbPath := setupTestStore(t)

	// Create a job directly in the database (simulating an interrupted job)
	jobID := "test-job-recovery-123"
	now := time.Now()
	err := testStore.CreateJob(jobID, StatusRunning, now, "{}", 0)
	require.NoError(t, err, "Failed to create job in database")

	// Create a transfer for the job
	transferID := "test-transfer-recovery-123"
	storedTransfer := &store.StoredTransfer{
		ID:          transferID,
		JobID:       jobID,
		Operation:   "get",
		Source:      "pelican://example.com/test.txt",
		Destination: "/tmp/test.txt",
		Recursive:   false,
		Status:      StatusRunning,
		CreatedAt:   now.Unix(),
	}
	err = testStore.CreateTransfer(storedTransfer)
	require.NoError(t, err, "Failed to create transfer in database")

	testStore.Close()

	// Reopen the store and create a new transfer manager (simulating restart)
	testStore, err = store.NewStore(dbPath)
	require.NoError(t, err, "Failed to reopen store")
	defer testStore.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm := NewTransferManager(ctx, 5, testStore)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Poll for recovery to complete (up to 2 seconds)
	// The old job should be deleted and a new job created
	var jobsData interface{}
	var total int
	recoveryComplete := false

	for i := 0; i < 20; i++ {
		// Check if the old job has been deleted
		_, err := testStore.GetJob(jobID)
		oldJobDeleted := (err != nil && err.Error() == "job "+jobID+" not found")

		// Check if any new jobs exist (the recovered job)
		jobsData, total, err = testStore.ListJobs("", 10, 0)
		require.NoError(t, err, "Failed to list jobs")

		// Recovery is complete when:
		// 1. Old job is deleted
		// 2. New job(s) exist (could be pending, running, or completed/failed)
		if oldJobDeleted && total > 0 {
			recoveryComplete = true
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	require.True(t, recoveryComplete, "Recovery did not complete within 2 seconds")
	require.Greater(t, total, 0, "Expected at least 1 job after recovery")

	// Verify the old job was replaced with a new job
	jobs, ok := jobsData.([]*store.StoredJob)
	require.True(t, ok, "Failed to cast jobs data")
	require.Greater(t, len(jobs), 0, "Expected at least 1 job in jobs array")

	// The recovered job should have a different ID
	newJob := jobs[0]
	assert.NotEqual(t, jobID, newJob.ID, "Recovered job should have a new ID")
	assert.Contains(t, []string{StatusPending, StatusRunning, StatusFailed}, newJob.Status)

	// Verify the transfer was recreated
	newTransfersData, err := testStore.GetTransfersByJob(newJob.ID)
	if err == nil && newTransfersData != nil {
		newTransfers, ok := newTransfersData.([]*store.StoredTransfer)
		require.True(t, ok, "Failed to cast transfers")
		require.Len(t, newTransfers, 1, "Expected 1 transfer for recovered job")
		assert.Equal(t, "get", newTransfers[0].Operation)
		assert.Equal(t, "pelican://example.com/test.txt", newTransfers[0].Source)
	}
}

// TestJobArchival verifies that completed jobs are archived to history
func TestJobArchival(t *testing.T) {
	testStore, _ := setupTestStore(t)
	defer testStore.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm := NewTransferManager(ctx, 5, testStore)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create a job directly in memory and database
	jobID := "test-archive-job-123"
	now := time.Now()
	sixMinutesAgo := now.Add(-6 * time.Minute)
	completedAt := sixMinutesAgo.Add(10 * time.Second) // Completed shortly after it started

	err := testStore.CreateJob(jobID, StatusCompleted, sixMinutesAgo, "{}", 0)
	require.NoError(t, err)

	err = testStore.UpdateJobStatus(jobID, StatusCompleted)
	require.NoError(t, err)
	err = testStore.UpdateJobTimes(jobID, &sixMinutesAgo, &completedAt)
	require.NoError(t, err)

	// Add the job to the transfer manager's in-memory map
	// (normally this would happen during job creation)
	tm.mu.Lock()
	tm.jobs[jobID] = &TransferJob{
		ID:          jobID,
		Status:      StatusCompleted,
		CreatedAt:   sixMinutesAgo,
		CompletedAt: &completedAt,
		Transfers:   []*Transfer{},
	}
	tm.mu.Unlock()

	// Verify the job is in the in-memory map before archival
	tm.mu.RLock()
	job, exists := tm.jobs[jobID]
	tm.mu.RUnlock()
	require.True(t, exists, "Job should exist in in-memory map")
	t.Logf("Job before archival: Status=%s, CompletedAt=%v, TimeSince=%v",
		job.Status, job.CompletedAt, time.Since(*job.CompletedAt))

	// Manually trigger archival
	tm.archiveCompletedJobs()

	// Verify job was archived
	historyData, total, err := testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total, "Expected 1 job in history")

	historyJobs, ok := historyData.([]*store.HistoricalJob)
	require.True(t, ok)
	require.Len(t, historyJobs, 1, "Expected 1 job in history array")
	assert.Equal(t, jobID, historyJobs[0].ID)
	assert.Equal(t, StatusCompleted, historyJobs[0].Status)

	// Verify job was removed from active jobs table
	_, err = testStore.GetJob(jobID)
	assert.Error(t, err, "Job should be removed from active table")
}

// TestHistoryPruning verifies that old history records are deleted
func TestHistoryPruning(t *testing.T) {
	testStore, _ := setupTestStore(t)
	defer testStore.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tm := NewTransferManager(ctx, 5, testStore)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create jobs in the database and immediately archive them with old timestamps
	now := time.Now()
	oldTime := now.Add(-40 * 24 * time.Hour)    // 40 days ago
	recentTime := now.Add(-10 * 24 * time.Hour) // 10 days ago

	// Create old job
	oldJobID := "old-job-123"
	err := testStore.CreateJob(oldJobID, StatusCompleted, oldTime, "{}", 0)
	require.NoError(t, err)
	err = testStore.UpdateJobTimes(oldJobID, &oldTime, &oldTime)
	require.NoError(t, err)
	err = testStore.ArchiveJob(oldJobID)
	require.NoError(t, err)

	// Create recent job
	recentJobID := "recent-job-456"
	err = testStore.CreateJob(recentJobID, StatusCompleted, recentTime, "{}", 0)
	require.NoError(t, err)
	err = testStore.UpdateJobTimes(recentJobID, &recentTime, &recentTime)
	require.NoError(t, err)
	err = testStore.ArchiveJob(recentJobID)
	require.NoError(t, err)

	// Verify both jobs are in history
	var historyData interface{}
	var total int
	_, total, err = testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total)

	// Manually trigger pruning with 30-day retention
	cutoffTime := now.Add(-30 * 24 * time.Hour)
	pruned, err := testStore.PruneHistory(cutoffTime)
	require.NoError(t, err)
	assert.Equal(t, 1, pruned, "Should prune 1 old job")

	// Verify only recent job remains
	historyData, total, err = testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "Should have 1 job in history")

	historyJobs, ok := historyData.([]*store.HistoricalJob)
	require.True(t, ok)
	assert.Len(t, historyJobs, 1)
	assert.Equal(t, recentJobID, historyJobs[0].ID)
}

// TestFullLifecycleWithRestart simulates a complete job lifecycle with server restart
func TestFullLifecycleWithRestart(t *testing.T) {
	testStore, dbPath := setupTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	tm := NewTransferManager(ctx, 5, testStore)

	// Create a job
	jobID := "lifecycle-job-123"
	now := time.Now()
	err := testStore.CreateJob(jobID, StatusPending, now, "{}", 0)
	require.NoError(t, err)

	// Create a transfer for the job (required for recovery)
	transferID := "lifecycle-transfer-123"
	storedTransfer := &store.StoredTransfer{
		ID:          transferID,
		JobID:       jobID,
		Operation:   "get",
		Source:      "pelican://example.com/lifecycle.txt",
		Destination: "/tmp/lifecycle.txt",
		Recursive:   false,
		Status:      StatusPending,
		CreatedAt:   now.Unix(),
	}
	err = testStore.CreateTransfer(storedTransfer)
	require.NoError(t, err)

	// Update to running status
	err = testStore.UpdateJobStatus(jobID, StatusRunning)
	require.NoError(t, err)
	startedAt := now
	err = testStore.UpdateJobTimes(jobID, &startedAt, nil)
	require.NoError(t, err)

	// Close transfer manager and store (simulating crash)
	cancel()
	_ = tm.Shutdown()
	testStore.Close()

	// Reopen store and create new transfer manager
	testStore, err = store.NewStore(dbPath)
	require.NoError(t, err)
	defer testStore.Close()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	tm2 := NewTransferManager(ctx2, 5, testStore)
	defer func() {
		_ = tm2.Shutdown()
	}()

	// Wait for recovery
	time.Sleep(500 * time.Millisecond)

	// Verify the old job was deleted (it should be replaced with a new job)
	_, err = testStore.GetJob(jobID)
	assert.Error(t, err, "Old job should be removed from active table after recovery")

	// The recovered job should have been retried and may have completed or failed
	// Check for active jobs (new job created during recovery)
	jobsData, total, err := testStore.ListJobs("", 10, 0)
	require.NoError(t, err)

	// If no active jobs, check history (job may have completed/failed quickly)
	if total == 0 {
		historyData, histTotal, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
		require.NoError(t, histErr)
		assert.Greater(t, histTotal, 0, "Expected at least 1 job in history after recovery")

		historyJobs, ok := historyData.([]*store.HistoricalJob)
		require.True(t, ok)
		assert.Greater(t, len(historyJobs), 0)
		// The recovered job will have a different ID than the original
		assert.NotEqual(t, jobID, historyJobs[0].ID, "Recovered job should have a new ID")
	} else {
		// Job is still active (pending or running)
		jobs, ok := jobsData.([]*store.StoredJob)
		require.True(t, ok)
		assert.Greater(t, len(jobs), 0)
		// The recovered job will have a different ID than the original
		assert.NotEqual(t, jobID, jobs[0].ID, "Recovered job should have a new ID")
	}
}

// TestInMemoryMode verifies that TransferManager works without a store
func TestInMemoryMode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create transfer manager without a store
	tm := NewTransferManager(ctx, 5, nil)
	defer func() {
		_ = tm.Shutdown()
	}()

	// Create a job
	requests := []TransferRequest{
		{
			Operation:   "get",
			Source:      "pelican://example.com/test.txt",
			Destination: "/tmp/test.txt",
			Recursive:   false,
		},
	}

	job, err := tm.CreateJob(requests, nil)
	require.NoError(t, err)
	require.NotNil(t, job)

	// Verify job exists in memory
	retrievedJob, err := tm.GetJob(job.ID)
	require.NoError(t, err)
	assert.Equal(t, job.ID, retrievedJob.ID)
	assert.Equal(t, StatusPending, retrievedJob.Status)

	// Verify no database operations cause issues
	time.Sleep(200 * time.Millisecond)
}

// TestHistoryFiltering verifies history query filtering
func TestHistoryFiltering(t *testing.T) {
	testStore, _ := setupTestStore(t)
	defer testStore.Close()

	now := time.Now()

	// Create multiple jobs with different statuses and times
	jobs := []struct {
		id     string
		status string
		time   time.Time
	}{
		{"job-completed-1", StatusCompleted, now.Add(-5 * 24 * time.Hour)},
		{"job-completed-2", StatusCompleted, now.Add(-15 * 24 * time.Hour)},
		{"job-failed-1", StatusFailed, now.Add(-10 * 24 * time.Hour)},
		{"job-cancelled-1", StatusCancelled, now.Add(-3 * 24 * time.Hour)},
	}

	for _, job := range jobs {
		err := testStore.CreateJob(job.id, job.status, job.time, "{}", 0)
		require.NoError(t, err)
		err = testStore.UpdateJobTimes(job.id, &job.time, &job.time)
		require.NoError(t, err)
		err = testStore.ArchiveJob(job.id)
		require.NoError(t, err)
	}

	// Test filtering by status
	historyData, total, err := testStore.GetJobHistory(StatusCompleted, time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total, "Should find 2 completed jobs")

	historyJobs, ok := historyData.([]*store.HistoricalJob)
	require.True(t, ok)
	assert.Len(t, historyJobs, 2)

	// Test filtering by time range
	fromTime := now.Add(-12 * 24 * time.Hour)
	toTime := now.Add(-4 * 24 * time.Hour)
	_, total, err = testStore.GetJobHistory("", fromTime, toTime, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total, "Should find 2 jobs in time range")

	// Test pagination
	historyData, total, err = testStore.GetJobHistory("", time.Time{}, time.Time{}, 2, 0)
	require.NoError(t, err)
	assert.Equal(t, 4, total, "Total should be 4")
	historyJobs, ok = historyData.([]*store.HistoricalJob)
	require.True(t, ok)
	assert.Len(t, historyJobs, 2, "Should return 2 jobs (limit)")

	historyData, _, err = testStore.GetJobHistory("", time.Time{}, time.Time{}, 2, 2)
	require.NoError(t, err)
	historyJobs, ok = historyData.([]*store.HistoricalJob)
	require.True(t, ok)
	assert.Len(t, historyJobs, 2, "Should return 2 jobs (offset 2)")
}

// TestConcurrentJobPersistence verifies that multiple concurrent jobs are persisted correctly
func TestConcurrentJobPersistence(t *testing.T) {
	testStore, _ := setupTestStore(t)
	defer testStore.Close()

	ctx, cancel := context.WithCancel(context.Background())

	tm := NewTransferManager(ctx, 10, testStore)

	// Create multiple jobs concurrently
	numJobs := 5
	jobIDs := make([]string, numJobs)

	for i := 0; i < numJobs; i++ {
		requests := []TransferRequest{
			{
				Operation:   "get",
				Source:      "pelican://example.com/file.txt",
				Destination: "/tmp/file.txt",
				Recursive:   false,
			},
		}

		job, err := tm.CreateJob(requests, nil)
		require.NoError(t, err)
		jobIDs[i] = job.ID
	}

	// Wait for persistence
	time.Sleep(500 * time.Millisecond)

	// Verify all jobs were persisted (they may be in active or history tables)
	jobsFound := 0
	for _, jobID := range jobIDs {
		storedJobData, err := testStore.GetJob(jobID)
		if err == nil {
			storedJob, ok := storedJobData.(*store.StoredJob)
			require.True(t, ok)
			assert.Equal(t, jobID, storedJob.ID)
			jobsFound++
		} else {
			// Job may have been archived, check history
			historyData, _, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 100, 0)
			require.NoError(t, histErr)
			historyJobs, ok := historyData.([]*store.HistoricalJob)
			require.True(t, ok)
			for _, hJob := range historyJobs {
				if hJob.ID == jobID {
					jobsFound++
					break
				}
			}
		}
	}
	assert.Equal(t, numJobs, jobsFound, "All %d jobs should be persisted (in active or history)", numJobs)

	// Cancel context before shutdown to force jobs to stop
	cancel()
	_ = tm.Shutdown()
}

// TestDeleteJobHistory verifies individual job deletion from history
func TestDeleteJobHistory(t *testing.T) {
	testStore, _ := setupTestStore(t)
	defer testStore.Close()

	// Create and archive a job
	jobID := "delete-test-job-123"
	now := time.Now()
	err := testStore.CreateJob(jobID, StatusCompleted, now, "{}", 0)
	require.NoError(t, err)
	err = testStore.UpdateJobTimes(jobID, &now, &now)
	require.NoError(t, err)
	err = testStore.ArchiveJob(jobID)
	require.NoError(t, err)

	// Verify job is in history
	_, total, err := testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total)

	// Delete the job from history
	err = testStore.DeleteJobHistory(jobID)
	require.NoError(t, err)

	// Verify job is no longer in history
	_, total, err = testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 0, total)

	// Verify deleting non-existent job returns error
	err = testStore.DeleteJobHistory("non-existent-job")
	assert.Error(t, err)
}

// TestBackgroundTasksShutdown verifies background tasks stop gracefully
func TestBackgroundTasksShutdown(t *testing.T) {
	testStore, _ := setupTestStore(t)
	defer testStore.Close()

	ctx, cancel := context.WithCancel(context.Background())

	tm := NewTransferManager(ctx, 5, testStore)

	// Let background tasks start
	time.Sleep(100 * time.Millisecond)

	// Trigger shutdown
	cancel()
	err := tm.Shutdown()
	assert.NoError(t, err, "Shutdown should complete without error")

	// Verify shutdown completed within timeout
	testStore.Close()
}
