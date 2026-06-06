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
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/client_agent"
)

// handlePing handles GET /api/v1.0/transfer/ping
// This is an unauthenticated endpoint that returns a simple health check,
// allowing clients to discover whether the transfer service is enabled.
func handlePing() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "transfer",
		})
	}
}

// handleCreateTransferJob handles POST /api/v1.0/transfer/jobs
func handleCreateTransferJob(db *gorm.DB, tm *client_agent.TransferManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		var req TransferJobCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  "INVALID_REQUEST",
				Error: "Invalid request body: " + err.Error(),
			})
			return
		}

		// When running on an origin, enforce that every transfer involves
		// at least one path under the origin's federation prefixes.
		if len(allowedPrefixes) > 0 {
			for _, t := range req.Transfers {
				if !transferMatchesPrefixes(t, allowedPrefixes) {
					c.JSON(http.StatusForbidden, ErrorResponse{
						Code:  "PATH_NOT_ALLOWED",
						Error: "Transfer source or destination must be under one of the origin's exported namespaces",
					})
					return
				}
			}
		}

		// Build transfer options, potentially including credential tokens
		options, err := buildTransferOptionsWithCredentials(db, owner, req)
		if err != nil {
			log.Errorf("Failed to build transfer options: %v", err)
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  "INVALID_REQUEST",
				Error: "Failed to resolve credentials: " + err.Error(),
			})
			return
		}

		// Convert to client_agent.TransferRequest format
		agentTransfers := make([]client_agent.TransferRequest, len(req.Transfers))
		for i, t := range req.Transfers {
			agentTransfers[i] = client_agent.TransferRequest{
				Operation:   t.Operation,
				Source:      t.Source,
				Destination: t.Destination,
				Recursive:   t.Recursive,
			}
		}

		// Create the job via the transfer manager
		job, err := tm.CreateJob(agentTransfers, options)
		if err != nil {
			log.Errorf("Failed to create transfer job: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to create transfer job: " + err.Error(),
			})
			return
		}

		// Persist the job record with owner info
		reqBody, _ := json.Marshal(req)
		var srcCredID, dstCredID *string
		if req.SourceCredentialID != "" {
			srcCredID = &req.SourceCredentialID
		}
		if req.DestCredentialID != "" {
			dstCredID = &req.DestCredentialID
		}

		dbJob := TransferJob{
			ID:                 job.ID,
			UserID:             owner.UserID,
			AgentJobID:         &job.ID,
			SourceCredentialID: srcCredID,
			DestCredentialID:   dstCredID,
			RequestBody:        string(reqBody),
			CreatedAt:          job.CreatedAt,
			UpdatedAt:          time.Now(),
		}

		if err := db.Create(&dbJob).Error; err != nil {
			log.Errorf("Failed to persist transfer job: %v", err)
			// The job is already running in the transfer manager; log the DB error but report success
		}

		c.JSON(http.StatusCreated, TransferJobResponse{
			JobID:     job.ID,
			Status:    job.Status,
			CreatedAt: job.CreatedAt,
			Transfers: req.Transfers,
		})
	}
}

// handleGetTransferJob handles GET /api/v1.0/transfer/jobs/:job_id
func handleGetTransferJob(db *gorm.DB, tm *client_agent.TransferManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		jobID := c.Param("job_id")

		// Verify ownership via DB
		var dbJob TransferJob
		if err := db.Where("id = ? AND user_id = ?",
			jobID, owner.UserID).First(&dbJob).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, ErrorResponse{
					Code:  "NOT_FOUND",
					Error: "Transfer job not found",
				})
			} else {
				c.JSON(http.StatusInternalServerError, ErrorResponse{
					Code:  "INTERNAL",
					Error: "Failed to retrieve transfer job",
				})
			}
			return
		}

		// Get live status from transfer manager
		job, err := tm.GetJob(jobID)
		if err != nil {
			// Job may have been evicted from memory; derive status from
			// saved metadata, or fall back to "unknown".
			c.JSON(http.StatusOK, TransferJobStatus{
				JobID:              dbJob.ID,
				Status:             deriveJobStatus(dbJob),
				CreatedAt:          dbJob.CreatedAt,
				CompletedAt:        dbJob.CompletedAt,
				SourceCredentialID: derefStringPtr(dbJob.SourceCredentialID),
				DestCredentialID:   derefStringPtr(dbJob.DestCredentialID),
				Error:              dbJob.Error,
			})
			return
		}

		// Sync completion metadata to the transfer_jobs row
		updates := map[string]any{
			"updated_at": time.Now(),
		}
		if job.CompletedAt != nil {
			updates["completed_at"] = job.CompletedAt
		}
		if job.Error != nil {
			updates["error"] = job.Error.Error()
		}
		if len(updates) > 1 {
			db.Model(&TransferJob{}).Where("id = ?", jobID).Updates(updates)
		}

		c.JSON(http.StatusOK, TransferJobStatus{
			JobID:              job.ID,
			Status:             job.Status,
			CreatedAt:          job.CreatedAt,
			CompletedAt:        job.CompletedAt,
			SourceCredentialID: derefStringPtr(dbJob.SourceCredentialID),
			DestCredentialID:   derefStringPtr(dbJob.DestCredentialID),
			Error:              errorToString(job.Error),
		})
	}
}

// handleListTransferJobs handles GET /api/v1.0/transfer/jobs
func handleListTransferJobs(db *gorm.DB, tm *client_agent.TransferManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

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

		query := db.Where("transfer_jobs.user_id = ?", owner.UserID)

		var total int64
		query.Model(&TransferJob{}).Count(&total)

		var jobs []TransferJob
		if err := query.Order("transfer_jobs.created_at DESC").Limit(limit).Offset(offset).Find(&jobs).Error; err != nil {
			log.Errorf("Failed to list transfer jobs: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to retrieve transfer jobs",
			})
			return
		}

		resp := make([]TransferJobStatus, 0, len(jobs))
		for _, job := range jobs {
			// Prefer live status from the transfer manager; fall back to
			// metadata-derived status for evicted jobs.
			jobStatus := deriveJobStatus(job)
			if liveJob, err := tm.GetJob(job.ID); err == nil {
				jobStatus = liveJob.Status
			}

			// If the caller filtered by status, skip non-matching jobs.
			if status != "" && jobStatus != status {
				continue
			}

			resp = append(resp, TransferJobStatus{
				JobID:              job.ID,
				Status:             jobStatus,
				CreatedAt:          job.CreatedAt,
				CompletedAt:        job.CompletedAt,
				SourceCredentialID: derefStringPtr(job.SourceCredentialID),
				DestCredentialID:   derefStringPtr(job.DestCredentialID),
				Error:              job.Error,
			})
		}

		c.JSON(http.StatusOK, TransferJobListResponse{
			Jobs:   resp,
			Total:  int(total),
			Limit:  limit,
			Offset: offset,
		})
	}
}

// handleCancelTransferJob handles DELETE /api/v1.0/transfer/jobs/:job_id
func handleCancelTransferJob(db *gorm.DB, tm *client_agent.TransferManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		jobID := c.Param("job_id")

		// Verify ownership
		var dbJob TransferJob
		if err := db.Where("id = ? AND user_id = ?",
			jobID, owner.UserID).First(&dbJob).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, ErrorResponse{
					Code:  "NOT_FOUND",
					Error: "Transfer job not found",
				})
			} else {
				c.JSON(http.StatusInternalServerError, ErrorResponse{
					Code:  "INTERNAL",
					Error: "Failed to retrieve transfer job",
				})
			}
			return
		}

		cancelled, completed, err := tm.CancelJob(jobID)
		if err != nil {
			if err.Error() == "job not found" {
				// Job already evicted from memory; record completion time
				now := time.Now()
				db.Model(&TransferJob{}).Where("id = ?", jobID).Updates(map[string]interface{}{
					"updated_at":   now,
					"completed_at": now,
				})
				c.JSON(http.StatusOK, gin.H{
					"job_id":  jobID,
					"message": "Job cancelled",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to cancel job: " + err.Error(),
			})
			return
		}

		// Record completion time; the agent job's own status tracks "cancelled"
		now := time.Now()
		db.Model(&TransferJob{}).Where("id = ?", jobID).Updates(map[string]interface{}{
			"updated_at":   now,
			"completed_at": now,
		})

		c.JSON(http.StatusOK, gin.H{
			"job_id":              jobID,
			"transfers_cancelled": cancelled,
			"transfers_completed": completed,
		})
	}
}

// buildTransferOptionsWithCredentials builds client.TransferOption slice,
// using dynamic token providers so credentials are resolved at transfer
// execution time rather than at job submission time.
func buildTransferOptionsWithCredentials(db *gorm.DB, owner ownerIdentity, req TransferJobCreateRequest) ([]client.TransferOption, error) {
	var options []client.TransferOption

	// If a source credential is specified, verify it exists now but provide
	// a dynamic provider so the token is fetched fresh at execution time.
	// For TPC, the source token is sent to the source server (via HEAD) and
	// also forwarded as TransferHeaderAuthorization to the destination.
	if req.SourceCredentialID != "" {
		if _, err := getOwnedCredential(db, req.SourceCredentialID, owner); err != nil {
			return nil, errors.Wrap(err, "failed to resolve source credential")
		}
		provider := newCredentialTokenProvider(db, req.SourceCredentialID, owner)
		options = append(options, client.WithSourceTokenProvider(provider))
	}

	// If a destination credential is specified, provide its token as the
	// main Authorization header sent to the destination server.
	if req.DestCredentialID != "" {
		if _, err := getOwnedCredential(db, req.DestCredentialID, owner); err != nil {
			return nil, errors.Wrap(err, "failed to resolve destination credential")
		}
		provider := newCredentialTokenProvider(db, req.DestCredentialID, owner)
		options = append(options, client.WithTokenProvider(provider))
	}

	// Apply other options
	if len(req.Options.Caches) > 0 {
		cacheURLs := make([]*url.URL, 0, len(req.Options.Caches))
		for _, cacheStr := range req.Options.Caches {
			cacheURL, err := url.Parse(cacheStr)
			if err != nil {
				return nil, errors.Wrapf(err, "invalid cache URL: %s", cacheStr)
			}
			cacheURLs = append(cacheURLs, cacheURL)
		}
		options = append(options, client.WithCaches(cacheURLs...))
	}

	return options, nil
}

func derefStringPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func errorToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// deriveJobStatus infers a transfer job's status from its persisted metadata
// when the in-memory agent job is no longer available (e.g. after eviction or
// server restart).  The heuristic is:
//   - CompletedAt set + Error non-empty → "failed"
//   - CompletedAt set + no Error        → "completed"
//   - otherwise                         → "unknown"
func deriveJobStatus(job TransferJob) string {
	if job.CompletedAt != nil {
		if job.Error != "" {
			return "failed"
		}
		return "completed"
	}
	return "unknown"
}

// Ensure uuid is used (it's imported for potential future use in job IDs)
var _ = uuid.New

// transferMatchesPrefixes returns true if the transfer item's source or
// destination path falls under at least one of the given federation prefixes.
func transferMatchesPrefixes(t TransferItem, prefixes []string) bool {
	srcPath := extractPath(t.Source)
	dstPath := extractPath(t.Destination)
	for _, prefix := range prefixes {
		if pathUnderPrefix(srcPath, prefix) || pathUnderPrefix(dstPath, prefix) {
			return true
		}
	}
	return false
}

// extractPath returns the path component of a URL string.  For bare paths
// (no scheme) it returns the input cleaned.  For URLs it strips the
// scheme and authority portions.
func extractPath(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" {
		return path.Clean(u.Path)
	}
	return path.Clean(raw)
}

// pathUnderPrefix reports whether p is equal to or nested under prefix.
// Both are expected to be cleaned absolute paths.
func pathUnderPrefix(p, prefix string) bool {
	if p == "" || prefix == "" {
		return false
	}
	// Ensure consistent trailing-slash handling
	cleanPrefix := strings.TrimRight(prefix, "/")
	cleanPath := strings.TrimRight(p, "/")
	if cleanPath == cleanPrefix {
		return true
	}
	return strings.HasPrefix(cleanPath, cleanPrefix+"/")
}
