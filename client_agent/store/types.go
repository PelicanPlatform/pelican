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

package store

import (
	"time"
)

// StoredJob represents a job stored in the database
type StoredJob struct {
	ID           string
	Status       string
	CreatedAt    int64
	StartedAt    *time.Time
	CompletedAt  *time.Time
	Options      map[string]interface{} // JSON-decoded options
	ErrorMessage string
	RetryCount   int // Number of times this job has been retried
}

// StoredTransfer represents a transfer stored in the database
type StoredTransfer struct {
	ID               string
	JobID            string
	Operation        string // "get", "put", "copy"
	Source           string
	Destination      string
	Recursive        bool
	Status           string
	CreatedAt        int64
	StartedAt        *time.Time
	CompletedAt      *time.Time
	BytesTransferred int64
	TotalBytes       int64
	ErrorMessage     string
}

// HistoricalJob represents a job in the history table
type HistoricalJob struct {
	ID                 string
	Status             string
	CreatedAt          int64
	StartedAt          *time.Time
	CompletedAt        *time.Time
	ErrorMessage       string
	TransfersCompleted int
	TransfersFailed    int
	TransfersTotal     int
	BytesTransferred   int64
	TotalBytes         int64
	RetryCount         int // Number of times this job was retried before completion
}
