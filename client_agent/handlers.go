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
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/version"
)

var serverStartTime = time.Now()

// CreateJobHandler handles POST /api/v1.0/transfer-agent/jobs
func (s *Server) CreateJobHandler(c *gin.Context) {
	var req JobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  ErrCodeInvalidRequest,
			Error: "Invalid request body: " + err.Error(),
		})
		return
	}

	// Validate transfers
	if len(req.Transfers) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  ErrCodeInvalidRequest,
			Error: "At least one transfer is required",
		})
		return
	}

	// Additional validation for specific operations
	for _, transfer := range req.Transfers {
		if transfer.Operation != "prestage" && transfer.Destination == "" {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  ErrCodeInvalidRequest,
				Error: "Destination is required for " + transfer.Operation + " operations",
			})
			return
		}
	}

	// Build transfer options
	options := buildTransferOptions(req.Options)

	// Create job
	job, err := s.transferManager.CreateJob(req.Transfers, options)
	if err != nil {
		log.Errorf("Failed to create job: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:  ErrCodeInternal,
			Error: "Failed to create job: " + err.Error(),
		})
		return
	}

	// Build response
	transfers := make([]TransferResponse, len(job.Transfers))
	for i, transfer := range job.Transfers {
		transfers[i] = TransferResponse{
			TransferID:  transfer.ID,
			Operation:   transfer.Operation,
			Source:      transfer.Source,
			Destination: transfer.Destination,
			Status:      transfer.Status,
		}
	}

	resp := JobResponse{
		JobID:     job.ID,
		Status:    job.Status,
		CreatedAt: job.CreatedAt,
		Transfers: transfers,
	}

	c.JSON(http.StatusCreated, resp)
}

// GetJobStatusHandler handles GET /api/v1.0/transfer-agent/jobs/:job_id
func (s *Server) GetJobStatusHandler(c *gin.Context) {
	jobID := c.Param("job_id")

	job, err := s.transferManager.GetJob(jobID)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Code:  ErrCodeNotFound,
			Error: "Job not found",
		})
		return
	}

	// Build transfer statuses
	transfers := make([]TransferStatus, len(job.Transfers))
	for i, transfer := range job.Transfers {
		status := TransferStatus{
			TransferID:       transfer.ID,
			JobID:            transfer.JobID,
			Operation:        transfer.Operation,
			Source:           transfer.Source,
			Destination:      transfer.Destination,
			Status:           transfer.Status,
			CreatedAt:        transfer.CreatedAt,
			StartedAt:        transfer.StartedAt,
			CompletedAt:      transfer.CompletedAt,
			BytesTransferred: transfer.BytesTransferred.Load(),
			TotalBytes:       transfer.TotalBytes.Load(),
		}
		if transfer.Error != nil {
			status.Error = transfer.Error.Error()
		}
		transfers[i] = status
	}

	// Get progress
	progress := s.transferManager.GetJobProgress(job)

	// Build job status
	jobStatus := JobStatus{
		JobID:       job.ID,
		Status:      job.Status,
		CreatedAt:   job.CreatedAt,
		StartedAt:   job.StartedAt,
		CompletedAt: job.CompletedAt,
		Progress:    progress,
		Transfers:   transfers,
	}
	if job.Error != nil {
		jobStatus.Error = job.Error.Error()
	}

	c.JSON(http.StatusOK, jobStatus)
}

// CancelJobHandler handles DELETE /api/v1.0/transfer-agent/jobs/:job_id
func (s *Server) CancelJobHandler(c *gin.Context) {
	jobID := c.Param("job_id")

	cancelled, completed, err := s.transferManager.CancelJob(jobID)
	if err != nil {
		if err.Error() == "job not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Code:  ErrCodeNotFound,
				Error: "Job not found",
			})
		} else if err.Error() == "job already completed" {
			c.JSON(http.StatusConflict, ErrorResponse{
				Code:  ErrCodeConflict,
				Error: "Job already completed",
			})
		} else {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  ErrCodeInternal,
				Error: "Failed to cancel job: " + err.Error(),
			})
		}
		return
	}

	c.JSON(http.StatusOK, CancelResponse{
		JobID:              jobID,
		TransfersCancelled: cancelled,
		TransfersCompleted: completed,
	})
}

// ListJobsHandler handles GET /api/v1.0/transfer-agent/jobs
func (s *Server) ListJobsHandler(c *gin.Context) {
	status := c.Query("status")
	limitStr := c.DefaultQuery("limit", "10")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	jobs, total := s.transferManager.ListJobs(status, limit, offset)

	c.JSON(http.StatusOK, JobListResponse{
		Jobs:   jobs,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// StatHandler handles POST /api/v1.0/transfer-agent/stat
func (s *Server) StatHandler(c *gin.Context) {
	var req StatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  ErrCodeInvalidRequest,
			Error: "Invalid request body: " + err.Error(),
		})
		return
	}

	// Build transfer options
	options := buildTransferOptions(req.Options)

	// Perform stat
	info, err := client.DoStat(c.Request.Context(), req.URL, options...)
	if err != nil {
		log.Errorf("Stat failed for %s: %v", req.URL, err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:  ErrCodeInternal,
			Error: "Stat operation failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, StatResponse{
		Name:         info.Name,
		Size:         info.Size,
		ModTime:      info.ModTime,
		IsCollection: info.IsCollection,
		Checksums:    info.Checksums,
	})
}

// ListHandler handles POST /api/v1.0/transfer-agent/list
func (s *Server) ListHandler(c *gin.Context) {
	var req ListRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  ErrCodeInvalidRequest,
			Error: "Invalid request body: " + err.Error(),
		})
		return
	}

	// Build transfer options
	options := buildTransferOptions(req.Options)

	// Perform list
	items, err := client.DoList(c.Request.Context(), req.URL, options...)
	if err != nil {
		log.Errorf("List failed for %s: %v", req.URL, err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:  ErrCodeInternal,
			Error: "List operation failed: " + err.Error(),
		})
		return
	}

	// Convert to response format
	respItems := make([]ListItem, len(items))
	for i, item := range items {
		respItems[i] = ListItem{
			Name:         item.Name,
			Size:         item.Size,
			ModTime:      item.ModTime,
			IsCollection: item.IsCollection,
		}
	}

	c.JSON(http.StatusOK, ListResponse{
		Items: respItems,
	})
}

// DeleteHandler handles POST /api/v1.0/transfer-agent/delete
func (s *Server) DeleteHandler(c *gin.Context) {
	var req DeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  ErrCodeInvalidRequest,
			Error: "Invalid request body: " + err.Error(),
		})
		return
	}

	// Build transfer options
	options := buildTransferOptions(req.Options)

	// Perform delete
	err := client.DoDelete(c.Request.Context(), req.URL, req.Recursive, options...)
	if err != nil {
		log.Errorf("Delete failed for %s: %v", req.URL, err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:  ErrCodeInternal,
			Error: "Delete operation failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, DeleteResponse{
		Message: "Object deleted successfully",
		URL:     req.URL,
	})
}

// HealthHandler handles GET /health
func (s *Server) HealthHandler(c *gin.Context) {
	uptime := time.Since(serverStartTime).Seconds()

	c.JSON(http.StatusOK, HealthResponse{
		Status:        "ok",
		Version:       version.GetVersion(),
		UptimeSeconds: int64(uptime),
	})
}

// GetJobHistoryHandler handles GET /api/v1.0/transfer-agent/history
// Query params: status, from, to, limit, offset
func (s *Server) GetJobHistoryHandler(c *gin.Context) {
	// Check if store is configured
	if s.transferManager.store == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Code:  "HISTORY_UNAVAILABLE",
			Error: "Job history is not available (database not configured)",
		})
		return
	}

	// Parse query parameters
	status := c.Query("status")
	fromStr := c.Query("from")
	toStr := c.Query("to")
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 1000 {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  ErrCodeInvalidRequest,
			Error: "Invalid limit parameter (must be 1-1000)",
		})
		return
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  ErrCodeInvalidRequest,
			Error: "Invalid offset parameter (must be >= 0)",
		})
		return
	}

	// Parse time filters
	var fromTime, toTime time.Time
	if fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  ErrCodeInvalidRequest,
				Error: "Invalid from parameter (must be RFC3339 format)",
			})
			return
		}
		fromTime = t
	}
	if toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  ErrCodeInvalidRequest,
				Error: "Invalid to parameter (must be RFC3339 format)",
			})
			return
		}
		toTime = t
	}

	// Get history from store
	historyData, total, err := s.transferManager.store.GetJobHistory(status, fromTime, toTime, limit, offset)
	if err != nil {
		log.Errorf("Failed to get job history: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:  ErrCodeInternal,
			Error: "Failed to retrieve job history",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"jobs":   historyData,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// DeleteJobHistoryHandler handles DELETE /api/v1.0/transfer-agent/history
// Can delete specific job or prune old history with olderThan param
func (s *Server) DeleteJobHistoryHandler(c *gin.Context) {
	// Check if store is configured
	if s.transferManager.store == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Code:  "HISTORY_UNAVAILABLE",
			Error: "Job history is not available (database not configured)",
		})
		return
	}

	// Check for job ID in path
	jobID := c.Param("job_id")
	olderThanStr := c.Query("older_than")

	if jobID != "" {
		// Delete specific job history
		if err := s.transferManager.store.DeleteJobHistory(jobID); err != nil {
			log.Errorf("Failed to delete job history %s: %v", jobID, err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  ErrCodeInternal,
				Error: "Failed to delete job history",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Job history deleted",
			"job_id":  jobID,
		})
		return
	}

	if olderThanStr != "" {
		// Prune old history
		olderThan, err := time.Parse(time.RFC3339, olderThanStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  ErrCodeInvalidRequest,
				Error: "Invalid older_than parameter (must be RFC3339 format)",
			})
			return
		}

		pruned, err := s.transferManager.store.PruneHistory(olderThan)
		if err != nil {
			log.Errorf("Failed to prune history: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  ErrCodeInternal,
				Error: "Failed to prune job history",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Old job history pruned",
			"pruned":  pruned,
		})
		return
	}

	c.JSON(http.StatusBadRequest, ErrorResponse{
		Code:  ErrCodeInvalidRequest,
		Error: "Must provide either job_id or older_than parameter",
	})
}

// ShutdownHandler handles POST /shutdown
// Initiates a graceful shutdown of the server
func (s *Server) ShutdownHandler(c *gin.Context) {
	log.Info("Shutdown requested via API")

	// Respond immediately before shutting down
	c.JSON(http.StatusOK, gin.H{
		"message": "Server shutdown initiated",
	})

	// Trigger shutdown asynchronously so we can respond first
	go func() {
		// Small delay to ensure response is sent
		time.Sleep(100 * time.Millisecond)
		if err := s.Shutdown(); err != nil {
			log.Errorf("Shutdown error: %v", err)
		}
	}()
}

// buildTransferOptions converts TransferOptions to client.TransferOption slice
func buildTransferOptions(opts TransferOptions) []client.TransferOption {
	var options []client.TransferOption

	// Add token if provided
	if opts.Token != "" {
		options = append(options, client.WithTokenLocation(opts.Token))
	}

	// Add cache URLs if provided
	if len(opts.Caches) > 0 {
		cacheURLs := make([]*url.URL, 0, len(opts.Caches))
		for _, cacheStr := range opts.Caches {
			if cacheURL, err := url.Parse(cacheStr); err == nil {
				cacheURLs = append(cacheURLs, cacheURL)
			} else {
				log.Warnf("Failed to parse cache URL %s: %v", cacheStr, err)
			}
		}
		if len(cacheURLs) > 0 {
			options = append(options, client.WithCaches(cacheURLs...))
		}
	}

	// Note: Additional options like workers, chunk size, etc. can be added
	// as they become available in the client.TransferOption API

	return options
}
