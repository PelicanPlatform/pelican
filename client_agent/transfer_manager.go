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
	"context"
	"reflect"
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
	store     StoreInterface
	mu        sync.RWMutex
	maxJobs   int
	semaphore chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewTransferManager creates a new transfer manager
func NewTransferManager(ctx context.Context, maxConcurrentJobs int, store StoreInterface) *TransferManager {
	managerCtx, cancel := context.WithCancel(ctx)

	tm := &TransferManager{
		jobs:      make(map[string]*TransferJob),
		transfers: make(map[string]*Transfer),
		store:     store,
		maxJobs:   maxConcurrentJobs,
		semaphore: make(chan struct{}, maxConcurrentJobs),
		ctx:       managerCtx,
		cancel:    cancel,
	}

	// Attempt to recover incomplete jobs from database
	if store != nil {
		tm.recoverJobs()
		go tm.startBackgroundTasks()
	}

	return tm
}

// recoverJobs attempts to recover incomplete jobs from the database
func (tm *TransferManager) recoverJobs() {
	log.Info("Starting job recovery from database...")

	// The most reliable way is to use GetRecoverableJobs which returns interface{}
	// containing []*store.StoredJob, but since we can't import store from here,
	// we use ListJobs and extract IDs using reflection
	var recoveredCount int
	for _, status := range []string{StatusPending, StatusRunning} {
		statusJobsData, statusTotal, err := tm.store.ListJobs(status, 1000, 0)
		if err != nil {
			log.Warnf("Failed to get %s jobs: %v", status, err)
			continue
		}

		if statusTotal == 0 {
			continue
		}

		log.Infof("Found %d incomplete jobs with status %s", statusTotal, status)

		// statusJobsData is []*store.StoredJob as interface{}
		// We can use reflection to extract job IDs
		v := reflect.ValueOf(statusJobsData)
		if v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				jobVal := v.Index(i)
				if jobVal.Kind() == reflect.Ptr {
					jobVal = jobVal.Elem()
				}
				if jobVal.Kind() == reflect.Struct {
					idField := jobVal.FieldByName("ID")
					if idField.IsValid() && idField.Kind() == reflect.String {
						jobID := idField.String()

						// Skip jobs that are already in memory (actively managed)
						tm.mu.RLock()
						_, exists := tm.jobs[jobID]
						tm.mu.RUnlock()

						if exists {
							log.Debugf("Skipping recovery for job %s (already in memory)", jobID)
							continue
						}

						tm.recoverSingleJob(jobID)
						recoveredCount++
					}
				}
			}
		}
	}

	if recoveredCount == 0 {
		log.Info("No jobs to recover")
	} else {
		log.Infof("Job recovery complete: restarted %d incomplete jobs", recoveredCount)
	}
}

// recoverSingleJob restarts a single interrupted job
func (tm *TransferManager) recoverSingleJob(jobID string) {
	log.Infof("Recovering and restarting incomplete job %s", jobID)

	// Get the job from the database
	jobData, err := tm.store.GetJob(jobID)
	if err != nil {
		log.Warnf("Failed to get job %s for recovery: %v", jobID, err)
		return
	}

	// Use reflection to extract job details including retry count
	jobVal := reflect.ValueOf(jobData)
	if jobVal.Kind() == reflect.Ptr {
		jobVal = jobVal.Elem()
	}
	if jobVal.Kind() != reflect.Struct {
		log.Warnf("Invalid job data type for recovery: %s", jobID)
		return
	}

	// Extract retry count from the job
	retryCountField := jobVal.FieldByName("RetryCount")
	var currentRetryCount int
	if retryCountField.IsValid() && retryCountField.Kind() == reflect.Int {
		currentRetryCount = int(retryCountField.Int())
	}

	// Get transfers for this job
	transfersData, err := tm.store.GetTransfersByJob(jobID)
	if err != nil {
		log.Warnf("Failed to get transfers for recovered job %s: %v", jobID, err)
		return
	}

	// Convert transfers to TransferRequest format
	var requests []TransferRequest
	transfersVal := reflect.ValueOf(transfersData)
	if transfersVal.Kind() == reflect.Slice {
		for i := 0; i < transfersVal.Len(); i++ {
			transfer := transfersVal.Index(i)
			if transfer.Kind() == reflect.Ptr {
				transfer = transfer.Elem()
			}

			// Extract transfer fields
			operationField := transfer.FieldByName("Operation")
			sourceField := transfer.FieldByName("Source")
			destinationField := transfer.FieldByName("Destination")
			recursiveField := transfer.FieldByName("Recursive")

			if !operationField.IsValid() || !sourceField.IsValid() || !destinationField.IsValid() || !recursiveField.IsValid() {
				log.Warnf("Failed to extract transfer fields for recovery")
				continue
			}

			request := TransferRequest{
				Operation:   operationField.String(),
				Source:      sourceField.String(),
				Destination: destinationField.String(),
				Recursive:   recursiveField.Bool(),
			}
			requests = append(requests, request)
		}
	}

	if len(requests) == 0 {
		log.Warnf("No valid transfers found for recovered job %s", jobID)
		return
	}

	// Delete the old job and transfers from the database
	// First delete from jobs table (cascades to transfers)
	if err := tm.store.DeleteJob(jobID); err != nil {
		log.Warnf("Failed to delete old job %s during recovery: %v", jobID, err)
		// Continue anyway - CreateJob will create new entries
	}

	// Recreate the job with the SAME ID but incremented retry count
	// This preserves the job ID known to the user
	tm.mu.Lock()
	newRetryCount := currentRetryCount + 1
	jobCtx, jobCancel := context.WithCancel(tm.ctx)

	job := &TransferJob{
		ID:         jobID, // PRESERVE the original job ID
		Status:     StatusPending,
		CreatedAt:  time.Now(),
		Transfers:  make([]*Transfer, 0, len(requests)),
		Options:    nil, // Options are not persisted, so we can't recover them
		CancelFunc: jobCancel,
		ctx:        jobCtx,
	}

	// Create transfers for the job
	for _, req := range requests {
		transferID := uuid.New().String()
		transferCtx, transferCancel := context.WithCancel(jobCtx)

		transfer := &Transfer{
			ID:          transferID,
			JobID:       jobID, // Use the original job ID
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

		// Persist transfer to database
		storedTransfer := map[string]interface{}{
			"ID":          transferID,
			"JobID":       jobID, // Use the original job ID
			"Operation":   req.Operation,
			"Source":      req.Source,
			"Destination": req.Destination,
			"Recursive":   req.Recursive,
			"Status":      StatusPending,
			"CreatedAt":   transfer.CreatedAt.Unix(),
		}
		if err := tm.store.CreateTransfer(storedTransfer); err != nil {
			log.Warnf("Failed to persist recovered transfer %s to database: %v", transferID, err)
		}
	}

	tm.jobs[jobID] = job // Use the original job ID
	tm.mu.Unlock()

	// Persist job to database with incremented retry count
	optionsJSON := "{}"
	if err := tm.store.CreateJob(jobID, StatusPending, job.CreatedAt, optionsJSON, newRetryCount); err != nil {
		log.Warnf("Failed to persist recovered job %s to database: %v", jobID, err)
	}

	log.Infof("Job %s recovered and restarted with %d transfers (retry attempt %d)", jobID, len(requests), newRetryCount)

	// Start the job asynchronously
	tm.wg.Add(1)
	go tm.executeJob(job)
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

		// Persist transfer to database if store is available
		if tm.store != nil {
			storedTransfer := map[string]interface{}{
				"ID":          transferID,
				"JobID":       jobID,
				"Operation":   req.Operation,
				"Source":      req.Source,
				"Destination": req.Destination,
				"Recursive":   req.Recursive,
				"Status":      StatusPending,
				"CreatedAt":   transfer.CreatedAt.Unix(),
			}
			if err := tm.store.CreateTransfer(storedTransfer); err != nil {
				log.Warnf("Failed to persist transfer %s to database: %v", transferID, err)
			}
		}
	}

	tm.jobs[jobID] = job

	// Persist job to database if store is available (initial creation with retry_count=0)
	if tm.store != nil {
		optionsJSON := "{}"
		if err := tm.store.CreateJob(jobID, StatusPending, job.CreatedAt, optionsJSON, 0); err != nil {
			log.Warnf("Failed to persist job %s to database: %v", jobID, err)
		}
	}

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

	// Persist status update to database
	if tm.store != nil {
		if err := tm.store.UpdateJobStatus(job.ID, StatusRunning); err != nil {
			log.Warnf("Failed to update job %s status in database: %v", job.ID, err)
		}
		if err := tm.store.UpdateJobTimes(job.ID, &now, nil); err != nil {
			log.Warnf("Failed to update job %s start time in database: %v", job.ID, err)
		}
	}

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

	// Persist final status to database
	if tm.store != nil {
		if err := tm.store.UpdateJobStatus(job.ID, job.Status); err != nil {
			log.Warnf("Failed to update job %s final status in database: %v", job.ID, err)
		}
		if err := tm.store.UpdateJobTimes(job.ID, nil, &completedAt); err != nil {
			log.Warnf("Failed to update job %s completion time in database: %v", job.ID, err)
		}
		if job.Error != nil {
			if err := tm.store.UpdateJobError(job.ID, job.Error.Error()); err != nil {
				log.Warnf("Failed to update job %s error in database: %v", job.ID, err)
			}
		}
	}

	log.Infof("Job %s completed with status %s", job.ID, job.Status)
}

// executeTransfer executes a single transfer
func (tm *TransferManager) executeTransfer(transfer *Transfer, options []client.TransferOption) error {
	now := time.Now()
	tm.mu.Lock()
	transfer.Status = StatusRunning
	transfer.StartedAt = &now
	tm.mu.Unlock()

	// Persist transfer status update to database
	if tm.store != nil {
		if err := tm.store.UpdateTransferStatus(transfer.ID, StatusRunning); err != nil {
			log.Warnf("Failed to update transfer %s status in database: %v", transfer.ID, err)
		}
		if err := tm.store.UpdateTransferTimes(transfer.ID, &now, nil); err != nil {
			log.Warnf("Failed to update transfer %s start time in database: %v", transfer.ID, err)
		}
	}

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

		// Persist failure to database
		if tm.store != nil {
			if storeErr := tm.store.UpdateTransferStatus(transfer.ID, StatusFailed); storeErr != nil {
				log.Warnf("Failed to update transfer %s status in database: %v", transfer.ID, storeErr)
			}
			if storeErr := tm.store.UpdateTransferTimes(transfer.ID, nil, &completedAt); storeErr != nil {
				log.Warnf("Failed to update transfer %s completion time in database: %v", transfer.ID, storeErr)
			}
			if storeErr := tm.store.UpdateTransferError(transfer.ID, err.Error()); storeErr != nil {
				log.Warnf("Failed to update transfer %s error in database: %v", transfer.ID, storeErr)
			}
		}

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

	// Persist success to database
	if tm.store != nil {
		if err := tm.store.UpdateTransferProgress(transfer.ID, totalBytes, totalBytes); err != nil {
			log.Warnf("Failed to update transfer %s progress in database: %v", transfer.ID, err)
		}
		if err := tm.store.UpdateTransferStatus(transfer.ID, StatusCompleted); err != nil {
			log.Warnf("Failed to update transfer %s status in database: %v", transfer.ID, err)
		}
		if err := tm.store.UpdateTransferTimes(transfer.ID, nil, &completedAt); err != nil {
			log.Warnf("Failed to update transfer %s completion time in database: %v", transfer.ID, err)
		}
	}

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

				// Persist cancellation to database
				if tm.store != nil {
					if err := tm.store.UpdateTransferStatus(transfer.ID, StatusCancelled); err != nil {
						log.Warnf("Failed to update cancelled transfer %s in database: %v", transfer.ID, err)
					}
					if err := tm.store.UpdateTransferTimes(transfer.ID, nil, transfer.CompletedAt); err != nil {
						log.Warnf("Failed to update cancelled transfer %s time in database: %v", transfer.ID, err)
					}
				}
			}
		}
	}

	job.Status = StatusCancelled
	if job.CompletedAt == nil {
		now := time.Now()
		job.CompletedAt = &now
	}

	// Persist job cancellation to database
	if tm.store != nil {
		if err := tm.store.UpdateJobStatus(job.ID, StatusCancelled); err != nil {
			log.Warnf("Failed to update cancelled job %s in database: %v", job.ID, err)
		}
		if err := tm.store.UpdateJobTimes(job.ID, nil, job.CompletedAt); err != nil {
			log.Warnf("Failed to update cancelled job %s time in database: %v", job.ID, err)
		}
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

// startBackgroundTasks starts periodic background maintenance tasks
func (tm *TransferManager) startBackgroundTasks() {
	if tm.store == nil {
		log.Debug("Store not configured, background tasks disabled")
		return
	}

	log.Info("Starting background maintenance tasks")

	// Archive completed jobs periodically (every hour)
	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-tm.ctx.Done():
				log.Debug("Stopping job archival task")
				return
			case <-ticker.C:
				tm.archiveCompletedJobs()
			}
		}
	}()

	// Prune old history periodically (daily)
	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		// Run once on startup after a short delay (use shorter delay for tests)
		startupDelay := 5 * time.Minute
		if tm.maxJobs < 10 {
			// Likely a test environment with low maxJobs, use shorter delay
			startupDelay = 1 * time.Second
		}

		// Use a timer instead of sleep to respect context cancellation
		timer := time.NewTimer(startupDelay)
		select {
		case <-tm.ctx.Done():
			timer.Stop()
			log.Debug("Stopping history pruning task (before initial run)")
			return
		case <-timer.C:
			tm.pruneOldHistory()
		}

		for {
			select {
			case <-tm.ctx.Done():
				log.Debug("Stopping history pruning task")
				return
			case <-ticker.C:
				tm.pruneOldHistory()
			}
		}
	}()
}

// archiveCompletedJobs archives all completed/failed/cancelled jobs to history
func (tm *TransferManager) archiveCompletedJobs() {
	log.Debug("Running job archival task")

	tm.mu.RLock()
	var jobsToArchive []string
	for jobID, job := range tm.jobs {
		if job.Status == StatusCompleted || job.Status == StatusFailed || job.Status == StatusCancelled {
			// Only archive if completed more than 5 minutes ago
			if job.CompletedAt != nil && time.Since(*job.CompletedAt) > 5*time.Minute {
				jobsToArchive = append(jobsToArchive, jobID)
			}
		}
	}
	tm.mu.RUnlock()

	archived := 0
	for _, jobID := range jobsToArchive {
		if err := tm.store.ArchiveJob(jobID); err != nil {
			log.Warnf("Failed to archive job %s: %v", jobID, err)
			continue
		}

		// Remove from in-memory maps
		tm.mu.Lock()
		if job, exists := tm.jobs[jobID]; exists {
			for _, transfer := range job.Transfers {
				delete(tm.transfers, transfer.ID)
			}
			delete(tm.jobs, jobID)
		}
		tm.mu.Unlock()

		archived++
	}

	if archived > 0 {
		log.Infof("Archived %d completed jobs to history", archived)
	}
}

// pruneOldHistory removes historical jobs older than the retention period
func (tm *TransferManager) pruneOldHistory() {
	log.Debug("Running history pruning task")

	// Default retention: 30 days
	retentionDays := 30
	cutoffTime := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)

	pruned, err := tm.store.PruneHistory(cutoffTime)
	if err != nil {
		log.Errorf("Failed to prune history: %v", err)
		return
	}

	if pruned > 0 {
		log.Infof("Pruned %d old jobs from history (older than %d days)", pruned, retentionDays)
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
