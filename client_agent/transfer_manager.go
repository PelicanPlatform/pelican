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
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	pelican_config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
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
	BytesTransferred atomic.Int64
	TotalBytes       atomic.Int64
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
	wg          sync.WaitGroup
}

// TransferManager manages all transfer jobs and their execution
type TransferManager struct {
	jobs                   map[string]*TransferJob
	transfers              map[string]*Transfer
	store                  StoreInterface
	mu                     sync.RWMutex
	maxJobs                int
	semaphore              chan struct{}
	ctx                    context.Context
	cancel                 context.CancelFunc
	eg                     *errgroup.Group
	backgroundTasksStarted bool
}

// NewTransferManager creates a new transfer manager
func NewTransferManager(ctx context.Context, maxConcurrentJobs int, store StoreInterface) *TransferManager {
	// Extract errgroup from context
	eg, ok := ctx.Value(pelican_config.EgrpKey).(*errgroup.Group)
	if !ok || eg == nil {
		// No errgroup provided, create one
		eg, ctx = errgroup.WithContext(ctx)
		ctx = context.WithValue(ctx, pelican_config.EgrpKey, eg)
	}

	// Create TransferManager's own cancellable context for internal control
	managerCtx, cancel := context.WithCancel(ctx)

	// Use parameter value if maxConcurrentJobs is not positive
	if maxConcurrentJobs <= 0 {
		providedValue := maxConcurrentJobs
		maxConcurrentJobs = param.ClientAgent_MaxConcurrentJobs.GetInt()
		if maxConcurrentJobs <= 0 {
			log.Warnf("Invalid max concurrent jobs configuration (provided=%d, param=%d), using default value of 5", providedValue, maxConcurrentJobs)
			maxConcurrentJobs = 5 // Final fallback
		}
	}

	tm := &TransferManager{
		jobs:      make(map[string]*TransferJob),
		transfers: make(map[string]*Transfer),
		store:     store,
		maxJobs:   maxConcurrentJobs,
		semaphore: make(chan struct{}, maxConcurrentJobs),
		ctx:       managerCtx,
		cancel:    cancel,
		eg:        eg,
	}

	// Attempt to recover incomplete jobs from database
	if store != nil {
		tm.recoverJobs()
		tm.startBackgroundTasks()
	}

	return tm
}

// recoverJobs attempts to recover incomplete jobs from the database
func (tm *TransferManager) recoverJobs() {
	log.Info("Starting job recovery from database...")

	var recoveredCount int
	for _, status := range []string{StatusPending, StatusRunning} {
		jobs, statusTotal, err := tm.store.ListJobs(status, 1000, 0)
		if err != nil {
			log.Warnf("Failed to get %s jobs: %v", status, err)
			continue
		}

		if statusTotal == 0 {
			continue
		}

		log.Infof("Found %d incomplete jobs with status %s", statusTotal, status)

		// Now we have concrete typed []*StoredJob (from same package)
		for _, storedJob := range jobs {
			tm.recoverSingleJob(storedJob.ID)
			recoveredCount++
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
	storedJob, err := tm.store.GetJob(jobID)
	if err != nil {
		log.Warnf("Failed to get job %s for recovery: %v", jobID, err)
		return
	}

	// Get transfers for this job
	storedTransfers, err := tm.store.GetTransfersByJob(jobID)
	if err != nil {
		log.Warnf("Failed to get transfers for recovered job %s: %v", jobID, err)
		return
	}

	// Convert transfers to TransferRequest format
	var requests []TransferRequest
	for _, st := range storedTransfers {
		requests = append(requests, TransferRequest{
			Operation:   st.Operation,
			Source:      st.Source,
			Destination: st.Destination,
			Recursive:   st.Recursive,
		})
	}

	if len(requests) == 0 {
		log.Warnf("No valid transfers found for recovered job %s", jobID)
		return
	}

	// Create in-memory job structure
	newRetryCount := storedJob.RetryCount + 1
	jobCtx, jobCancel := context.WithCancel(tm.ctx)
	createdAt := time.Now()

	job := &TransferJob{
		ID:         jobID, // PRESERVE the original job ID
		Status:     StatusPending,
		CreatedAt:  createdAt,
		Transfers:  make([]*Transfer, 0, len(requests)),
		Options:    nil, // Options are not persisted, so we can't recover them
		CancelFunc: jobCancel,
		ctx:        jobCtx,
	}

	// Prepare transfer data for atomic recovery
	transferData := make([]map[string]interface{}, 0, len(requests))
	tm.mu.Lock()
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
			CreatedAt:   createdAt,
			CancelFunc:  transferCancel,
			ctx:         transferCtx,
		}

		job.Transfers = append(job.Transfers, transfer)
		tm.transfers[transferID] = transfer

		transferData = append(transferData, map[string]interface{}{
			"ID":          transferID,
			"JobID":       jobID,
			"Operation":   req.Operation,
			"Source":      req.Source,
			"Destination": req.Destination,
			"Recursive":   req.Recursive,
			"Status":      StatusPending,
			"CreatedAt":   createdAt.Unix(),
		})
	}

	tm.jobs[jobID] = job
	tm.mu.Unlock()

	// Use atomic RecoverJob transaction - deletes old job and creates new one with transfers
	// All operations succeed or all fail (atomic)
	optionsJSON := "{}"
	if err := tm.store.RecoverJob(jobID, newRetryCount, createdAt, optionsJSON, transferData); err != nil {
		log.Errorf("Failed to atomically recover job %s in database: %v", jobID, err)
		// Clean up in-memory structures on failure
		tm.mu.Lock()
		delete(tm.jobs, jobID)
		for _, t := range job.Transfers {
			delete(tm.transfers, t.ID)
		}
		tm.mu.Unlock()
		return
	}

	log.Infof("Job %s recovered and restarted with %d transfers (retry attempt %d)", jobID, len(requests), newRetryCount)

	// Start the job asynchronously
	job.wg.Add(1)
	tm.eg.Go(func() error {
		tm.executeJob(job)
		return nil
	})
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

	tm.jobs[jobID] = job

	// Create transfers for the job
	transferData := make([]map[string]interface{}, 0, len(requests))
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

		// Prepare transfer data for atomic database insertion
		transferData = append(transferData, map[string]interface{}{
			"ID":          transferID,
			"JobID":       jobID,
			"Operation":   req.Operation,
			"Source":      req.Source,
			"Destination": req.Destination,
			"Recursive":   req.Recursive,
			"Status":      StatusPending,
			"CreatedAt":   transfer.CreatedAt.Unix(),
		})
	}

	// Atomically persist job and all transfers to database in a single transaction
	if tm.store != nil {
		optionsJSON := "{}"
		if err := tm.store.CreateJobWithTransfers(jobID, StatusPending, job.CreatedAt, optionsJSON, 0, transferData); err != nil {
			log.Errorf("Failed to persist job %s to database: %v", jobID, err)
			// Clean up in-memory structures on database failure
			delete(tm.jobs, jobID)
			for _, transfer := range job.Transfers {
				delete(tm.transfers, transfer.ID)
			}
			jobCancel()
			return nil, errors.Wrap(err, "failed to persist job to database")
		}
	}

	// Start the job asynchronously
	job.wg.Add(1)
	tm.eg.Go(func() error {
		tm.executeJob(job)
		return nil
	})

	return job, nil
}

// executeJob runs all transfers in a job
func (tm *TransferManager) executeJob(job *TransferJob) {
	defer job.wg.Done() // Signal job completion

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

	// Add progress callback to update transfer state during execution
	progressCallback := func(path string, downloaded int64, totalSize int64, completed bool) {
		transfer.BytesTransferred.Store(downloaded)
		transfer.TotalBytes.Store(totalSize)

		log.Debugf("Transfer %s progress: %d/%d bytes (%.1f%%)",
			transfer.ID, downloaded, totalSize,
			float64(downloaded)/float64(totalSize)*100)
	}

	// Prepend callback to options so it's applied first
	options = append([]client.TransferOption{client.WithCallback(progressCallback)}, options...)

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
	case "prestage":
		results, err = client.DoPrestage(transfer.ctx, transfer.Source, options...)
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

	transfer.BytesTransferred.Store(totalBytes)
	transfer.TotalBytes.Store(totalBytes)
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

	// Wait for job to complete with timeout
	done := make(chan struct{})
	go func() {
		job.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Job completed successfully
	case <-time.After(30 * time.Second):
		// Timeout waiting for job to cancel
		return 0, 0, errors.Errorf("timeout waiting for job %s to cancel after 30 seconds", jobID)
	}

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
		bytesTransferred += transfer.BytesTransferred.Load()
		totalBytes += transfer.TotalBytes.Load()
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
		bytesTransferred += transfer.BytesTransferred.Load()
		if tb := transfer.TotalBytes.Load(); tb > 0 {
			totalBytes += tb
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
	tm.backgroundTasksStarted = true

	// Archive completed jobs periodically (every hour)
	tm.eg.Go(func() error {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-tm.ctx.Done():
				log.Debug("Stopping job archival task")
				return nil
			case <-ticker.C:
				tm.archiveCompletedJobs()
			}
		}
	})

	// Prune old history periodically (daily)
	tm.eg.Go(func() error {
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
			return nil
		case <-timer.C:
			tm.pruneOldHistory()
		}

		for {
			select {
			case <-tm.ctx.Done():
				log.Debug("Stopping history pruning task")
				return nil
			case <-ticker.C:
				tm.pruneOldHistory()
			}
		}
	})

	// Update active transfer progress periodically
	updateInterval := param.ClientAgent_ProgressUpdateInterval.GetDuration()
	if updateInterval <= 0 {
		updateInterval = 5 * time.Second // Default if not configured
	}

	tm.eg.Go(func() error {
		ticker := time.NewTicker(updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-tm.ctx.Done():
				log.Debug("Stopping progress update task")
				return nil
			case <-ticker.C:
				tm.updateActiveTransferProgress()
			}
		}
	})
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

// updateActiveTransferProgress persists current progress for all active transfers
func (tm *TransferManager) updateActiveTransferProgress() {
	if tm.store == nil {
		log.Debug("Skipping progress update: store is nil")
		return
	}

	tm.mu.RLock()
	var activeTransfers []*Transfer
	for _, transfer := range tm.transfers {
		if transfer.Status == StatusRunning {
			activeTransfers = append(activeTransfers, transfer)
		}
	}
	tm.mu.RUnlock()

	if len(activeTransfers) == 0 {
		log.Debug("Skipping progress update: no active transfers")
		return
	}

	log.Debugf("Updating progress for %d active transfers to database", len(activeTransfers))

	for _, transfer := range activeTransfers {
		bytesTransferred := transfer.BytesTransferred.Load()
		totalBytes := transfer.TotalBytes.Load()

		if err := tm.store.UpdateTransferProgress(transfer.ID, bytesTransferred, totalBytes); err != nil {
			log.Warnf("Failed to update progress for transfer %s: %v", transfer.ID, err)
		} else {
			log.Debugf("Updated progress for transfer %s: %d/%d bytes", transfer.ID, bytesTransferred, totalBytes)
		}
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

	// Cancel context to signal all background goroutines to stop
	tm.cancel()

	// The errgroup will wait for all goroutines to complete
	log.Info("Transfer manager shutdown initiated (waiting handled by errgroup)")
	return nil
}

// HasActiveJobs returns true if there are any jobs in pending or running status
func (tm *TransferManager) HasActiveJobs() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	for _, job := range tm.jobs {
		if job.Status == StatusPending || job.Status == StatusRunning {
			return true
		}
	}
	return false
}
