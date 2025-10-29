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
	"time"
)

// TransferRequest represents a single transfer operation within a job
type TransferRequest struct {
	Operation   string `json:"operation" binding:"required,oneof=get put copy"`
	Source      string `json:"source" binding:"required"`
	Destination string `json:"destination" binding:"required"`
	Recursive   bool   `json:"recursive"`
}

// JobRequest represents a request to create a new transfer job
type JobRequest struct {
	Transfers []TransferRequest `json:"transfers" binding:"required,min=1,dive"`
	Options   TransferOptions   `json:"options"`
}

// TransferOptions contains options that apply to all transfers in a job
type TransferOptions struct {
	Token      string   `json:"token,omitempty"`
	Caches     []string `json:"caches,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	PackOption string   `json:"pack_option,omitempty"`
}

// JobResponse is returned when a job is created
type JobResponse struct {
	JobID     string             `json:"job_id"`
	Status    string             `json:"status"`
	CreatedAt time.Time          `json:"created_at"`
	Transfers []TransferResponse `json:"transfers"`
}

// TransferResponse represents the initial response for a transfer
type TransferResponse struct {
	TransferID  string `json:"transfer_id"`
	Operation   string `json:"operation"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Status      string `json:"status"`
}

// JobStatus represents the full status of a job including all transfers
type JobStatus struct {
	JobID       string           `json:"job_id"`
	Status      string           `json:"status"`
	CreatedAt   time.Time        `json:"created_at"`
	StartedAt   *time.Time       `json:"started_at"`
	CompletedAt *time.Time       `json:"completed_at"`
	Progress    *JobProgress     `json:"progress,omitempty"`
	Transfers   []TransferStatus `json:"transfers"`
	Error       string           `json:"error,omitempty"`
}

// JobProgress tracks overall job progress
type JobProgress struct {
	BytesTransferred   int64   `json:"bytes_transferred"`
	TotalBytes         int64   `json:"total_bytes"`
	Percentage         float64 `json:"percentage"`
	TransferRateMbps   float64 `json:"transfer_rate_mbps"`
	TransfersCompleted int     `json:"transfers_completed"`
	TransfersTotal     int     `json:"transfers_total"`
	TransfersFailed    int     `json:"transfers_failed"`
}

// TransferStatus represents detailed status of a single transfer
type TransferStatus struct {
	TransferID       string     `json:"transfer_id"`
	JobID            string     `json:"job_id"`
	Operation        string     `json:"operation"`
	Source           string     `json:"source"`
	Destination      string     `json:"destination"`
	Status           string     `json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
	StartedAt        *time.Time `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at"`
	BytesTransferred int64      `json:"bytes_transferred"`
	TotalBytes       int64      `json:"total_bytes"`
	TransferRateMbps float64    `json:"transfer_rate_mbps"`
	Error            string     `json:"error,omitempty"`
}

// JobListItem represents a job in a list response
type JobListItem struct {
	JobID              string    `json:"job_id"`
	Status             string    `json:"status"`
	CreatedAt          time.Time `json:"created_at"`
	TransfersCompleted int       `json:"transfers_completed"`
	TransfersTotal     int       `json:"transfers_total"`
	BytesTransferred   int64     `json:"bytes_transferred"`
	TotalBytes         int64     `json:"total_bytes"`
}

// JobListResponse represents a paginated list of jobs
type JobListResponse struct {
	Jobs   []JobListItem `json:"jobs"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

// CancelResponse is returned when a job is cancelled
type CancelResponse struct {
	JobID              string `json:"job_id"`
	Status             string `json:"status"`
	Message            string `json:"message"`
	TransfersCancelled int    `json:"transfers_cancelled"`
	TransfersCompleted int    `json:"transfers_completed"`
}

// HealthResponse represents server health status
type HealthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// StatRequest represents a request to stat a remote object
type StatRequest struct {
	URL     string          `json:"url" binding:"required"`
	Options TransferOptions `json:"options"`
}

// StatResponse represents file stat information
type StatResponse struct {
	Name         string            `json:"name"`
	Size         int64             `json:"size"`
	IsCollection bool              `json:"is_collection"`
	ModTime      time.Time         `json:"mod_time"`
	Checksums    map[string]string `json:"checksums,omitempty"`
}

// ListRequest represents a request to list a remote directory
type ListRequest struct {
	URL     string          `json:"url" binding:"required"`
	Options TransferOptions `json:"options"`
}

// ListItem represents an item in a directory listing
type ListItem struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	IsCollection bool      `json:"is_collection"`
	ModTime      time.Time `json:"mod_time"`
}

// ListResponse represents a directory listing
type ListResponse struct {
	Items []ListItem `json:"items"`
}

// DeleteRequest represents a request to delete a remote object
type DeleteRequest struct {
	URL       string          `json:"url" binding:"required"`
	Recursive bool            `json:"recursive"`
	Options   TransferOptions `json:"options"`
}

// DeleteResponse represents the result of a delete operation
type DeleteResponse struct {
	Message string `json:"message"`
	URL     string `json:"url"`
}

// Error codes
const (
	ErrCodeInvalidRequest = "INVALID_REQUEST"
	ErrCodeNotFound       = "NOT_FOUND"
	ErrCodeUnauthorized   = "UNAUTHORIZED"
	ErrCodeInternal       = "INTERNAL_ERROR"
	ErrCodeTimeout        = "TIMEOUT"
	ErrCodeCancelled      = "CANCELLED"
	ErrCodeTransferFailed = "TRANSFER_FAILED"
	ErrCodeConflict       = "CONFLICT"
)

// Job and transfer status constants
const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)
