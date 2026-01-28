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
	"time"

	"github.com/pelicanplatform/pelican/client_agent/types"
)

// StoreInterface defines the interface for persistent storage operations
// This interface is implemented by client_api/store.Store to avoid import cycles
type StoreInterface interface {
	// Job operations
	CreateJob(jobID, status string, createdAt time.Time, optionsJSON string, retryCount int) error
	CreateJobWithTransfers(jobID, status string, createdAt time.Time, optionsJSON string, retryCount int, transfers []map[string]interface{}) error
	UpdateJobStatus(jobID, status string) error
	UpdateJobTimes(jobID string, startedAt, completedAt *time.Time) error
	UpdateJobError(jobID, errorMsg string) error
	GetJob(jobID string) (*types.StoredJob, error)
	ListJobs(status string, limit, offset int) ([]*types.StoredJob, int, error)
	DeleteJob(jobID string) error

	// Transfer operations
	CreateTransfer(transfer interface{}) error
	UpdateTransferStatus(transferID, status string) error
	UpdateTransferProgress(transferID string, bytesTransferred, totalBytes int64) error
	UpdateTransferTimes(transferID string, startedAt, completedAt *time.Time) error
	UpdateTransferError(transferID, errorMsg string) error
	GetTransfer(transferID string) (*types.StoredTransfer, error)
	GetTransfersByJob(jobID string) ([]*types.StoredTransfer, error)

	// Recovery operations
	GetRecoverableJobs() ([]*types.StoredJob, error)
	RecoverJob(jobID string, retryCount int, createdAt time.Time, optionsJSON string, transfers []map[string]interface{}) error

	// History operations
	ArchiveJob(jobID string) error
	GetJobHistory(status string, from, to time.Time, limit, offset int) ([]*types.HistoricalJob, int, error)
	DeleteJobHistory(jobID string) error
	PruneHistory(olderThan time.Time) (int, error)

	// Lifecycle
	Close() error
}
