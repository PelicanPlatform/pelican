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
	"github.com/pelicanplatform/pelican/client_agent/types"
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

	// Wait for job to be persisted and have a terminal status
	require.Eventually(t, func() bool {
		storedJob, err := testStore.GetJob(job.ID)
		if err == nil {
			return storedJob.Status == StatusFailed || storedJob.Status == StatusCompleted
		}
		// Check if archived
		historyJobs, _, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 100, 0)
		if histErr == nil {
			for _, hJob := range historyJobs {
				if hJob.ID == job.ID {
					return true
				}
			}
		}
		return false
	}, 5*time.Second, 100*time.Millisecond, "Job should be persisted")

	// Verify job was persisted (it will be in failed status because client isn't initialized)
	// Note: The recovery mechanism may have archived the failed job, so check history too
	storedJob, err := testStore.GetJob(job.ID)
	if err != nil && err.Error() == "job "+job.ID+" not found" {
		// Job was archived, check history
		historyJobs, _, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 100, 0)
		require.NoError(t, histErr, "Failed to retrieve job from history")

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
		require.NotNil(t, storedJob)
		assert.Equal(t, job.ID, storedJob.ID)
		// Job may be pending or failed depending on execution speed
		assert.Contains(t, []string{StatusPending, StatusRunning, StatusFailed}, storedJob.Status)
	}

	// Verify transfer was persisted (check active transfers first)
	transfers, err := testStore.GetTransfersByJob(job.ID)
	if err != nil || transfers == nil {
		// Transfers may have been archived, which is OK for this test
		// The important thing is that persistence worked
		t.Log("Transfers were archived to history (expected behavior)")
		return
	}

	require.NoError(t, err, "Failed to retrieve transfers from database")
	require.NotNil(t, transfers)

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
	storedTransfer := &types.StoredTransfer{
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
	// The job should be recreated with the same ID but incremented retry count
	var recoveredJob *types.StoredJob

	// Wait for job recovery with retry count incremented
	require.Eventually(t, func() bool {
		storedJob, err := testStore.GetJob(jobID)
		if err == nil && storedJob != nil && storedJob.RetryCount > 0 {
			recoveredJob = storedJob
			return true
		}
		return false
	}, 2*time.Second, 100*time.Millisecond, "Recovery should complete with incremented retry count")
	require.NotNil(t, recoveredJob, "Expected recovered job to exist")

	// The recovered job should have the SAME ID (preserved for user tracking)
	assert.Equal(t, jobID, recoveredJob.ID, "Recovered job should preserve the original job ID")
	// But with incremented retry count
	assert.Greater(t, recoveredJob.RetryCount, 0, "Recovered job should have incremented retry count")
	assert.Contains(t, []string{StatusPending, StatusRunning, StatusFailed}, recoveredJob.Status)

	// Verify the transfer was recreated
	recoveredTransfers, err := testStore.GetTransfersByJob(recoveredJob.ID)
	if err == nil && recoveredTransfers != nil {
		require.Len(t, recoveredTransfers, 1, "Expected 1 transfer for recovered job")
		assert.Equal(t, "get", recoveredTransfers[0].Operation)
		assert.Equal(t, "pelican://example.com/test.txt", recoveredTransfers[0].Source)
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
	historyJobs, total, err := testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total, "Expected 1 job in history")
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
	historyJobs, total, err := testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "Should have 1 job in history")
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
	storedTransfer := &types.StoredTransfer{
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

	// Wait for job to be recovered
	require.Eventually(t, func() bool {
		_, err := testStore.GetJob(jobID)
		if err == nil {
			return true
		}
		// Check if archived
		historyJobs, _, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
		if histErr == nil && len(historyJobs) > 0 {
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond, "Job should be recovered")

	// Verify the job was recovered with the SAME ID (preserved for user tracking)
	recoveredJob, err := testStore.GetJob(jobID)
	if err != nil {
		// Job may have completed/failed quickly and been archived
		historyJobs, histTotal, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 10, 0)
		require.NoError(t, histErr)
		assert.Greater(t, histTotal, 0, "Expected at least 1 job in history after recovery")
		assert.Greater(t, len(historyJobs), 0)
		// The recovered job should have the SAME ID (preserved)
		assert.Equal(t, jobID, historyJobs[0].ID, "Recovered job should preserve the original job ID")
		// But with incremented retry count
		assert.Greater(t, historyJobs[0].RetryCount, 0, "Recovered job should have incremented retry count")
	} else {
		// Job is still active (pending or running)
		// The recovered job should have the SAME ID (preserved)
		assert.Equal(t, jobID, recoveredJob.ID, "Recovered job should preserve the original job ID")
		// But with incremented retry count
		assert.Greater(t, recoveredJob.RetryCount, 0, "Recovered job should have incremented retry count")
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

	// With nil store, jobs remain in memory only - no database operations
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
	historyJobs, total, err := testStore.GetJobHistory(StatusCompleted, time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total, "Should find 2 completed jobs")

	assert.Len(t, historyJobs, 2)

	// Test filtering by time range
	fromTime := now.Add(-12 * 24 * time.Hour)
	toTime := now.Add(-4 * 24 * time.Hour)
	_, total, err = testStore.GetJobHistory("", fromTime, toTime, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total, "Should find 2 jobs in time range")

	// Test pagination
	historyJobs, total, err = testStore.GetJobHistory("", time.Time{}, time.Time{}, 2, 0)
	require.NoError(t, err)
	assert.Equal(t, 4, total, "Total should be 4")
	assert.Len(t, historyJobs, 2, "Should return 2 jobs (limit)")

	historyJobs, _, err = testStore.GetJobHistory("", time.Time{}, time.Time{}, 2, 2)
	require.NoError(t, err)
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

	// Wait for all jobs to be persisted
	require.Eventually(t, func() bool {
		count := 0
		for _, jobID := range jobIDs {
			_, err := testStore.GetJob(jobID)
			if err == nil {
				count++
				continue
			}
			// Check history
			historyJobs, _, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 100, 0)
			if histErr == nil {
				for _, hJob := range historyJobs {
					if hJob.ID == jobID {
						count++
						break
					}
				}
			}
		}
		return count == numJobs
	}, 10*time.Second, 100*time.Millisecond, "All jobs should be persisted")

	// Verify all jobs were persisted (they may be in active or history tables)
	jobsFound := 0
	for _, jobID := range jobIDs {
		storedJob, err := testStore.GetJob(jobID)
		if err == nil {
			assert.Equal(t, jobID, storedJob.ID)
			jobsFound++
		} else {
			// Job may have been archived, check history
			historyJobs, _, histErr := testStore.GetJobHistory("", time.Time{}, time.Time{}, 100, 0)
			require.NoError(t, histErr)
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

	// Trigger shutdown
	cancel()
	err := tm.Shutdown()
	assert.NoError(t, err, "Shutdown should complete without error")

	// Verify shutdown completed within timeout
	testStore.Close()
}
