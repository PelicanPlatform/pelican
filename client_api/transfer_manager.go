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

package client_api

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client"
)

// Transfer represents an individual file transfer
type Transfer struct {
	ID               string
	JobID            string
	Operation        string
	Source           string
	Destination      string
	Recursive        bool
	Status           string
	CreatedAt        time.Time
	StartedAt        *time.Time
	CompletedAt      *time.Time
	BytesTransferred int64
	TotalBytes       int64
	Error            error
	CancelFunc       context.CancelFunc
	ctx              context.Context
}

// TransferJob represents a collection of transfers
type TransferJob struct {
	ID          string
	Status      string
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	Transfers   []*Transfer
	Options     []client.TransferOption
	Error       error
	CancelFunc  context.CancelFunc
	ctx         context.Context
}

// TransferManager manages all transfer jobs and their execution
type TransferManager struct {
	jobs      map[string]*TransferJob
	transfers map[string]*Transfer
	mu        sync.RWMutex
	maxJobs   int
	semaphore chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewTransferManager creates a new transfer manager
func NewTransferManager(ctx context.Context, maxConcurrentJobs int) *TransferManager {
	managerCtx, cancel := context.WithCancel(ctx)

	return &TransferManager{
		jobs:      make(map[string]*TransferJob),
		transfers: make(map[string]*Transfer),
		maxJobs:   maxConcurrentJobs,
		semaphore: make(chan struct{}, maxConcurrentJobs),
		ctx:       managerCtx,
		cancel:    cancel,
	}
}

// CreateJob creates a new transfer job
func (tm *TransferManager) CreateJob(requests []TransferRequest, options []client.TransferOption) (*TransferJob, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	jobID := uuid.New().String()
	jobCtx, jobCancel := context.WithCancel(tm.ctx)

	job := &TransferJob{
		ID:         jobID,
		Status:     StatusPending,
		CreatedAt:  time.Now(),
		Transfers:  make([]*Transfer, 0, len(requests)),
		Options:    options,
		CancelFunc: jobCancel,
		ctx:        jobCtx,
	}

	// Create transfers for the job
	for _, req := range requests {
		transferID := uuid.New().String()
		transferCtx, transferCancel := context.WithCancel(jobCtx)

		transfer := &Transfer{
			ID:          transferID,
			JobID:       jobID,
			Operation:   req.Operation,
			Source:      req.Source,
			Destination: req.Destination,
			Recursive:   req.Recursive,
			Status:      StatusPending,
			CreatedAt:   time.Now(),
			CancelFunc:  transferCancel,
			ctx:         transferCtx,
		}

		job.Transfers = append(job.Transfers, transfer)
		tm.transfers[transferID] = transfer
	}

	tm.jobs[jobID] = job

	// Start the job asynchronously
	tm.wg.Add(1)
	go tm.executeJob(job)

	return job, nil
}

// executeJob runs all transfers in a job
func (tm *TransferManager) executeJob(job *TransferJob) {
	defer tm.wg.Done()

	// Acquire semaphore slot
	select {
	case tm.semaphore <- struct{}{}:
		defer func() { <-tm.semaphore }()
	case <-job.ctx.Done():
		tm.updateJobStatus(job.ID, StatusCancelled, errors.New("job cancelled before execution"))
		return
	}

	// Update job status
	now := time.Now()
	tm.mu.Lock()
	job.Status = StatusRunning
	job.StartedAt = &now
	tm.mu.Unlock()

	log.Infof("Starting job %s with %d transfers", job.ID, len(job.Transfers))

	// Execute transfers sequentially (could be parallelized in future)
	allSucceeded := true
	anyFailed := false

	for _, transfer := range job.Transfers {
		select {
		case <-job.ctx.Done():
			// Job was cancelled
			tm.cancelRemainingTransfers(job)
			tm.updateJobStatus(job.ID, StatusCancelled, nil)
			return
		default:
			if err := tm.executeTransfer(transfer, job.Options); err != nil {
				log.Errorf("Transfer %s failed: %v", transfer.ID, err)
				allSucceeded = false
				anyFailed = true
			}
		}
	}

	// Update final job status
	completedAt := time.Now()
	tm.mu.Lock()
	job.CompletedAt = &completedAt
	if anyFailed {
		job.Status = StatusFailed
		job.Error = errors.New("one or more transfers failed")
	} else if allSucceeded {
		job.Status = StatusCompleted
	}
	tm.mu.Unlock()

	log.Infof("Job %s completed with status %s", job.ID, job.Status)
}

// executeTransfer executes a single transfer
func (tm *TransferManager) executeTransfer(transfer *Transfer, options []client.TransferOption) error {
	now := time.Now()
	tm.mu.Lock()
	transfer.Status = StatusRunning
	transfer.StartedAt = &now
	tm.mu.Unlock()

	log.Debugf("Executing transfer %s: %s %s -> %s", transfer.ID, transfer.Operation, transfer.Source, transfer.Destination)

	var err error
	var results []client.TransferResults

	// Execute the appropriate transfer operation
	switch transfer.Operation {
	case "get":
		results, err = client.DoGet(transfer.ctx, transfer.Source, transfer.Destination, transfer.Recursive, options...)
	case "put":
		results, err = client.DoPut(transfer.ctx, transfer.Source, transfer.Destination, transfer.Recursive, options...)
	case "copy":
		results, err = client.DoCopy(transfer.ctx, transfer.Source, transfer.Destination, transfer.Recursive, options...)
	default:
		err = errors.Errorf("unknown operation: %s", transfer.Operation)
	}

	completedAt := time.Now()
	tm.mu.Lock()
	defer tm.mu.Unlock()

	transfer.CompletedAt = &completedAt

	if err != nil {
		transfer.Status = StatusFailed
		transfer.Error = err
		log.Errorf("Transfer %s failed: %v", transfer.ID, err)
		return err
	}

	// Aggregate results
	var totalBytes int64
	for _, result := range results {
		totalBytes += result.TransferredBytes
	}

	transfer.BytesTransferred = totalBytes
	transfer.TotalBytes = totalBytes
	transfer.Status = StatusCompleted

	log.Debugf("Transfer %s completed successfully: %d bytes", transfer.ID, totalBytes)
	return nil
}

// cancelRemainingTransfers cancels all pending/running transfers in a job
func (tm *TransferManager) cancelRemainingTransfers(job *TransferJob) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for _, transfer := range job.Transfers {
		if transfer.Status == StatusPending || transfer.Status == StatusRunning {
			transfer.Status = StatusCancelled
			if transfer.CompletedAt == nil {
				now := time.Now()
				transfer.CompletedAt = &now
			}
		}
	}
}

// updateJobStatus updates a job's status
func (tm *TransferManager) updateJobStatus(jobID, status string, err error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if job, exists := tm.jobs[jobID]; exists {
		job.Status = status
		if err != nil {
			job.Error = err
		}
		if job.CompletedAt == nil && (status == StatusCompleted || status == StatusFailed || status == StatusCancelled) {
			now := time.Now()
			job.CompletedAt = &now
		}
	}
}

// GetJob retrieves a job by ID
func (tm *TransferManager) GetJob(jobID string) (*TransferJob, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	job, exists := tm.jobs[jobID]
	if !exists {
		return nil, errors.New("job not found")
	}

	return job, nil
}

// GetTransfer retrieves a transfer by ID
func (tm *TransferManager) GetTransfer(transferID string) (*Transfer, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	transfer, exists := tm.transfers[transferID]
	if !exists {
		return nil, errors.New("transfer not found")
	}

	return transfer, nil
}

// CancelJob cancels a job and all its incomplete transfers
func (tm *TransferManager) CancelJob(jobID string) (int, int, error) {
	tm.mu.Lock()
	job, exists := tm.jobs[jobID]
	if !exists {
		tm.mu.Unlock()
		return 0, 0, errors.New("job not found")
	}

	if job.Status == StatusCompleted {
		tm.mu.Unlock()
		return 0, 0, errors.New("job already completed")
	}

	tm.mu.Unlock()

	// Cancel the job context
	job.CancelFunc()

	// Wait a moment for cancellation to propagate
	time.Sleep(100 * time.Millisecond)

	tm.mu.Lock()
	defer tm.mu.Unlock()

	cancelled := 0
	completed := 0

	for _, transfer := range job.Transfers {
		if transfer.Status == StatusCompleted {
			completed++
		} else {
			cancelled++
			if transfer.Status != StatusCancelled {
				transfer.Status = StatusCancelled
				if transfer.CompletedAt == nil {
					now := time.Now()
					transfer.CompletedAt = &now
				}
			}
		}
	}

	job.Status = StatusCancelled
	if job.CompletedAt == nil {
		now := time.Now()
		job.CompletedAt = &now
	}

	return cancelled, completed, nil
}

// ListJobs returns a filtered list of jobs
func (tm *TransferManager) ListJobs(status string, limit, offset int) ([]JobListItem, int) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var filtered []JobListItem

	for _, job := range tm.jobs {
		if status != "" && job.Status != status {
			continue
		}

		item := tm.buildJobListItem(job)
		filtered = append(filtered, item)
	}

	// Apply pagination
	total := len(filtered)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	return filtered[start:end], total
}

// buildJobListItem creates a JobListItem from a TransferJob
func (tm *TransferManager) buildJobListItem(job *TransferJob) JobListItem {
	completed := 0
	total := len(job.Transfers)
	var bytesTransferred, totalBytes int64

	for _, transfer := range job.Transfers {
		if transfer.Status == StatusCompleted {
			completed++
		}
		bytesTransferred += transfer.BytesTransferred
		totalBytes += transfer.TotalBytes
	}

	return JobListItem{
		JobID:              job.ID,
		Status:             job.Status,
		CreatedAt:          job.CreatedAt,
		TransfersCompleted: completed,
		TransfersTotal:     total,
		BytesTransferred:   bytesTransferred,
		TotalBytes:         totalBytes,
	}
}

// GetJobProgress calculates current progress for a job
func (tm *TransferManager) GetJobProgress(job *TransferJob) *JobProgress {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var bytesTransferred, totalBytes int64
	completed := 0
	failed := 0
	total := len(job.Transfers)

	for _, transfer := range job.Transfers {
		bytesTransferred += transfer.BytesTransferred
		if transfer.TotalBytes > 0 {
			totalBytes += transfer.TotalBytes
		}
		if transfer.Status == StatusCompleted {
			completed++
		} else if transfer.Status == StatusFailed {
			failed++
		}
	}

	// Calculate percentage
	percentage := 0.0
	if totalBytes > 0 {
		percentage = float64(bytesTransferred) / float64(totalBytes) * 100
	} else if completed > 0 {
		percentage = float64(completed) / float64(total) * 100
	}

	// Calculate transfer rate in Megabits per second (Mbps)
	// Conversion: bytes/sec → MB/sec → Mbps
	// 1 MB = 1024 * 1024 bytes, 1 byte = 8 bits
	const (
		bytesPerKB  = 1024.0
		bytesPerMB  = bytesPerKB * 1024.0
		bitsPerByte = 8.0
	)

	rate := 0.0
	if job.StartedAt != nil {
		elapsed := time.Since(*job.StartedAt).Seconds()
		if elapsed > 0 {
			bytesPerSecond := float64(bytesTransferred) / elapsed
			megabytesPerSecond := bytesPerSecond / bytesPerMB
			rate = megabytesPerSecond * bitsPerByte // Convert MB/s to Mbps
		}
	}

	return &JobProgress{
		BytesTransferred:   bytesTransferred,
		TotalBytes:         totalBytes,
		Percentage:         percentage,
		TransferRateMbps:   rate,
		TransfersCompleted: completed,
		TransfersTotal:     total,
		TransfersFailed:    failed,
	}
}

// Shutdown gracefully shuts down the transfer manager
func (tm *TransferManager) Shutdown() error {
	log.Info("Shutting down transfer manager...")

	tm.cancel()

	// Wait for all jobs to complete with timeout
	done := make(chan struct{})
	go func() {
		tm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info("Transfer manager shutdown complete")
		return nil
	case <-time.After(30 * time.Second):
		log.Warn("Transfer manager shutdown timed out")
		return errors.New("shutdown timeout")
	}
}
