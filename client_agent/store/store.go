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
	"database/sql"
	"embed"
	"encoding/json"
	"time"

	_ "github.com/glebarez/sqlite" // SQLite driver
	"github.com/pkg/errors"
	"github.com/pressly/goose/v3"
	log "github.com/sirupsen/logrus"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// Store provides persistent storage for jobs and transfers
type Store struct {
	db *sql.DB
}

// NewStore creates a new Store instance and runs migrations
func NewStore(dbPath string) (*Store, error) {
	// Open SQLite database
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, errors.Wrap(err, "failed to open database")
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to ping database")
	}

	// Set connection pool settings
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	store := &Store{db: db}

	// Run migrations
	if err := store.runMigrations(); err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to run migrations")
	}

	log.Infof("Database initialized at %s", dbPath)
	return store, nil
}

// runMigrations applies database migrations using goose
func (s *Store) runMigrations() error {
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("sqlite3"); err != nil {
		return errors.Wrap(err, "failed to set goose dialect")
	}

	if err := goose.Up(s.db, "migrations"); err != nil {
		return errors.Wrap(err, "failed to apply migrations")
	}

	return nil
}

// Close closes the database connection
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateJob inserts a new job into the database
func (s *Store) CreateJob(jobID, status string, createdAt time.Time, optionsJSON string, retryCount int) error {
	query := `INSERT INTO jobs (id, status, created_at, options, retry_count) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, jobID, status, createdAt.Unix(), optionsJSON, retryCount)
	if err != nil {
		return errors.Wrap(err, "failed to insert job")
	}

	log.Debugf("Created job %s in database (retry_count=%d)", jobID, retryCount)
	return nil
}

// UpdateJobStatus updates the status of a job
func (s *Store) UpdateJobStatus(jobID, status string) error {
	query := `UPDATE jobs SET status = ? WHERE id = ?`
	result, err := s.db.Exec(query, status, jobID)
	if err != nil {
		return errors.Wrap(err, "failed to update job status")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}

	if rows == 0 {
		return errors.Errorf("job %s not found", jobID)
	}

	return nil
}

// UpdateJobTimes updates the started_at or completed_at timestamps
func (s *Store) UpdateJobTimes(jobID string, startedAt, completedAt *time.Time) error {
	if startedAt != nil {
		query := `UPDATE jobs SET started_at = ? WHERE id = ?`
		if _, err := s.db.Exec(query, startedAt.Unix(), jobID); err != nil {
			return errors.Wrap(err, "failed to update job started_at")
		}
	}

	if completedAt != nil {
		query := `UPDATE jobs SET completed_at = ? WHERE id = ?`
		if _, err := s.db.Exec(query, completedAt.Unix(), jobID); err != nil {
			return errors.Wrap(err, "failed to update job completed_at")
		}
	}

	return nil
}

// UpdateJobError updates the error message for a job
func (s *Store) UpdateJobError(jobID, errorMsg string) error {
	query := `UPDATE jobs SET error_message = ? WHERE id = ?`
	_, err := s.db.Exec(query, errorMsg, jobID)
	return errors.Wrap(err, "failed to update job error")
}

// GetJob retrieves a job by ID
func (s *Store) GetJob(jobID string) (interface{}, error) {
	query := `SELECT id, status, created_at, started_at, completed_at, options, error_message, retry_count
	          FROM jobs WHERE id = ?`

	var job StoredJob
	var startedAt, completedAt sql.NullInt64
	var options, errorMsg sql.NullString

	err := s.db.QueryRow(query, jobID).Scan(
		&job.ID, &job.Status, &job.CreatedAt,
		&startedAt, &completedAt, &options, &errorMsg, &job.RetryCount,
	)

	if err == sql.ErrNoRows {
		return nil, errors.Errorf("job %s not found", jobID)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to query job")
	}

	// Convert nullable fields
	if startedAt.Valid {
		t := time.Unix(startedAt.Int64, 0)
		job.StartedAt = &t
	}
	if completedAt.Valid {
		t := time.Unix(completedAt.Int64, 0)
		job.CompletedAt = &t
	}
	if options.Valid {
		if err := json.Unmarshal([]byte(options.String), &job.Options); err != nil {
			log.Warnf("Failed to unmarshal job options: %v", err)
			job.Options = make(map[string]interface{})
		}
	} else {
		job.Options = make(map[string]interface{})
	}
	if errorMsg.Valid {
		job.ErrorMessage = errorMsg.String
	}

	return &job, nil
}

// ListJobs retrieves jobs with optional filtering
func (s *Store) ListJobs(status string, limit, offset int) (interface{}, int, error) {
	// Build query with filters
	query := `SELECT id, status, created_at, started_at, completed_at, options, error_message, retry_count FROM jobs`
	countQuery := `SELECT COUNT(*) FROM jobs`
	args := []interface{}{}

	if status != "" {
		query += ` WHERE status = ?`
		countQuery += ` WHERE status = ?`
		args = append(args, status)
	}

	// Get total count
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to count jobs")
	}

	// Add ordering and pagination
	query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to query jobs")
	}
	defer rows.Close()

	var jobs []*StoredJob
	for rows.Next() {
		var job StoredJob
		var startedAt, completedAt sql.NullInt64
		var options, errorMsg sql.NullString

		err := rows.Scan(
			&job.ID, &job.Status, &job.CreatedAt,
			&startedAt, &completedAt, &options, &errorMsg, &job.RetryCount,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, "failed to scan job row")
		}

		// Convert nullable fields
		if startedAt.Valid {
			t := time.Unix(startedAt.Int64, 0)
			job.StartedAt = &t
		}
		if completedAt.Valid {
			t := time.Unix(completedAt.Int64, 0)
			job.CompletedAt = &t
		}
		if options.Valid {
			if err := json.Unmarshal([]byte(options.String), &job.Options); err != nil {
				log.Warnf("Failed to unmarshal job options: %v", err)
				job.Options = make(map[string]interface{})
			}
		} else {
			job.Options = make(map[string]interface{})
		}
		if errorMsg.Valid {
			job.ErrorMessage = errorMsg.String
		}

		jobs = append(jobs, &job)
	}

	return jobs, total, nil
}

// DeleteJob removes a job from the database
func (s *Store) DeleteJob(jobID string) error {
	query := `DELETE FROM jobs WHERE id = ?`
	result, err := s.db.Exec(query, jobID)
	if err != nil {
		return errors.Wrap(err, "failed to delete job")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}

	if rows == 0 {
		return errors.Errorf("job %s not found", jobID)
	}

	return nil
}

// CreateTransfer inserts a new transfer into the database
func (s *Store) CreateTransfer(transferData interface{}) error {
	var transfer *StoredTransfer

	// Handle different input types
	switch t := transferData.(type) {
	case *StoredTransfer:
		transfer = t
	case map[string]interface{}:
		// Convert map to StoredTransfer
		transfer = &StoredTransfer{}
		if id, ok := t["ID"].(string); ok {
			transfer.ID = id
		}
		if jobID, ok := t["JobID"].(string); ok {
			transfer.JobID = jobID
		}
		if op, ok := t["Operation"].(string); ok {
			transfer.Operation = op
		}
		if src, ok := t["Source"].(string); ok {
			transfer.Source = src
		}
		if dest, ok := t["Destination"].(string); ok {
			transfer.Destination = dest
		}
		if rec, ok := t["Recursive"].(bool); ok {
			transfer.Recursive = rec
		}
		if status, ok := t["Status"].(string); ok {
			transfer.Status = status
		}
		if created, ok := t["CreatedAt"].(int64); ok {
			transfer.CreatedAt = created
		}
	default:
		return errors.New("unsupported transfer data type")
	}

	query := `INSERT INTO transfers
	          (id, job_id, operation, source, destination, recursive, status, created_at)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		transfer.ID, transfer.JobID, transfer.Operation,
		transfer.Source, transfer.Destination, transfer.Recursive,
		transfer.Status, transfer.CreatedAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to insert transfer")
	}

	log.Debugf("Created transfer %s in database", transfer.ID)
	return nil
}

// UpdateTransferStatus updates the status of a transfer
func (s *Store) UpdateTransferStatus(transferID, status string) error {
	query := `UPDATE transfers SET status = ? WHERE id = ?`
	_, err := s.db.Exec(query, status, transferID)
	return errors.Wrap(err, "failed to update transfer status")
}

// UpdateTransferProgress updates the progress of a transfer
func (s *Store) UpdateTransferProgress(transferID string, bytesTransferred, totalBytes int64) error {
	query := `UPDATE transfers SET bytes_transferred = ?, total_bytes = ? WHERE id = ?`
	_, err := s.db.Exec(query, bytesTransferred, totalBytes, transferID)
	return errors.Wrap(err, "failed to update transfer progress")
}

// UpdateTransferTimes updates the started_at or completed_at timestamps
func (s *Store) UpdateTransferTimes(transferID string, startedAt, completedAt *time.Time) error {
	if startedAt != nil {
		query := `UPDATE transfers SET started_at = ? WHERE id = ?`
		if _, err := s.db.Exec(query, startedAt.Unix(), transferID); err != nil {
			return errors.Wrap(err, "failed to update transfer started_at")
		}
	}

	if completedAt != nil {
		query := `UPDATE transfers SET completed_at = ? WHERE id = ?`
		if _, err := s.db.Exec(query, completedAt.Unix(), transferID); err != nil {
			return errors.Wrap(err, "failed to update transfer completed_at")
		}
	}

	return nil
}

// UpdateTransferError updates the error message for a transfer
func (s *Store) UpdateTransferError(transferID, errorMsg string) error {
	query := `UPDATE transfers SET error_message = ? WHERE id = ?`
	_, err := s.db.Exec(query, errorMsg, transferID)
	return errors.Wrap(err, "failed to update transfer error")
}

// GetTransfer retrieves a transfer by ID
func (s *Store) GetTransfer(transferID string) (interface{}, error) {
	query := `SELECT id, job_id, operation, source, destination, recursive, status,
	          created_at, started_at, completed_at, bytes_transferred, total_bytes, error_message
	          FROM transfers WHERE id = ?`

	var transfer StoredTransfer
	var startedAt, completedAt sql.NullInt64
	var errorMsg sql.NullString

	err := s.db.QueryRow(query, transferID).Scan(
		&transfer.ID, &transfer.JobID, &transfer.Operation,
		&transfer.Source, &transfer.Destination, &transfer.Recursive, &transfer.Status,
		&transfer.CreatedAt, &startedAt, &completedAt,
		&transfer.BytesTransferred, &transfer.TotalBytes, &errorMsg,
	)

	if err == sql.ErrNoRows {
		return nil, errors.Errorf("transfer %s not found", transferID)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to query transfer")
	}

	// Convert nullable fields
	if startedAt.Valid {
		t := time.Unix(startedAt.Int64, 0)
		transfer.StartedAt = &t
	}
	if completedAt.Valid {
		t := time.Unix(completedAt.Int64, 0)
		transfer.CompletedAt = &t
	}
	if errorMsg.Valid {
		transfer.ErrorMessage = errorMsg.String
	}

	return &transfer, nil
}

// GetTransfersByJob retrieves all transfers for a job
func (s *Store) GetTransfersByJob(jobID string) (interface{}, error) {
	query := `SELECT id, job_id, operation, source, destination, recursive, status,
	          created_at, started_at, completed_at, bytes_transferred, total_bytes, error_message
	          FROM transfers WHERE job_id = ? ORDER BY created_at ASC`

	rows, err := s.db.Query(query, jobID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query transfers")
	}
	defer rows.Close()

	var transfers []*StoredTransfer
	for rows.Next() {
		var transfer StoredTransfer
		var startedAt, completedAt sql.NullInt64
		var errorMsg sql.NullString

		err := rows.Scan(
			&transfer.ID, &transfer.JobID, &transfer.Operation,
			&transfer.Source, &transfer.Destination, &transfer.Recursive, &transfer.Status,
			&transfer.CreatedAt, &startedAt, &completedAt,
			&transfer.BytesTransferred, &transfer.TotalBytes, &errorMsg,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan transfer row")
		}

		// Convert nullable fields
		if startedAt.Valid {
			t := time.Unix(startedAt.Int64, 0)
			transfer.StartedAt = &t
		}
		if completedAt.Valid {
			t := time.Unix(completedAt.Int64, 0)
			transfer.CompletedAt = &t
		}
		if errorMsg.Valid {
			transfer.ErrorMessage = errorMsg.String
		}

		transfers = append(transfers, &transfer)
	}

	return transfers, nil
}

// GetRecoverableJobs returns jobs that need recovery (pending or running status)
func (s *Store) GetRecoverableJobs() (interface{}, error) {
	query := `SELECT id, status, created_at, started_at, completed_at, options, error_message, retry_count
	          FROM jobs WHERE status IN ('pending', 'running') ORDER BY created_at ASC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query recoverable jobs")
	}
	defer rows.Close()

	var jobs []*StoredJob
	for rows.Next() {
		var job StoredJob
		var startedAt, completedAt sql.NullInt64
		var options, errorMsg sql.NullString

		err := rows.Scan(
			&job.ID, &job.Status, &job.CreatedAt,
			&startedAt, &completedAt, &options, &errorMsg, &job.RetryCount,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan job row")
		}

		// Convert nullable fields
		if startedAt.Valid {
			t := time.Unix(startedAt.Int64, 0)
			job.StartedAt = &t
		}
		if completedAt.Valid {
			t := time.Unix(completedAt.Int64, 0)
			job.CompletedAt = &t
		}
		if options.Valid {
			if err := json.Unmarshal([]byte(options.String), &job.Options); err != nil {
				log.Warnf("Failed to unmarshal job options: %v", err)
				job.Options = make(map[string]interface{})
			}
		} else {
			job.Options = make(map[string]interface{})
		}
		if errorMsg.Valid {
			job.ErrorMessage = errorMsg.String
		}

		jobs = append(jobs, &job)
	}

	return jobs, nil
}

// ArchiveJob moves a completed/failed/cancelled job to history
func (s *Store) ArchiveJob(jobID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return errors.Wrap(err, "failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Get job details
	jobData, err := s.GetJob(jobID)
	if err != nil {
		return errors.Wrap(err, "failed to get job for archival")
	}
	job, ok := jobData.(*StoredJob)
	if !ok {
		return errors.New("failed to convert job data")
	}

	// Get all transfers for this job
	transfersData, err := s.GetTransfersByJob(jobID)
	if err != nil {
		return errors.Wrap(err, "failed to get transfers for archival")
	}
	transfers, ok := transfersData.([]*StoredTransfer)
	if !ok {
		return errors.New("failed to convert transfers data")
	}

	// Calculate summary statistics
	var transfersCompleted, transfersFailed, transfersTotal int
	var bytesTransferred, totalBytes int64

	for _, t := range transfers {
		transfersTotal++
		bytesTransferred += t.BytesTransferred
		totalBytes += t.TotalBytes

		if t.Status == "completed" {
			transfersCompleted++
		} else if t.Status == "failed" {
			transfersFailed++
		}
	}

	// Insert into job_history
	historyQuery := `INSERT INTO job_history
	                 (id, status, created_at, started_at, completed_at, options, error_message,
	                  transfers_completed, transfers_failed, transfers_total,
	                  bytes_transferred, total_bytes, retry_count)
	                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var startedAt, completedAt sql.NullInt64
	if job.StartedAt != nil {
		startedAt.Valid = true
		startedAt.Int64 = job.StartedAt.Unix()
	}
	if job.CompletedAt != nil {
		completedAt.Valid = true
		completedAt.Int64 = job.CompletedAt.Unix()
	}

	optionsJSON, _ := json.Marshal(job.Options)
	if len(optionsJSON) == 0 || string(optionsJSON) == "null" {
		optionsJSON = []byte("{}")
	}

	_, err = tx.Exec(historyQuery,
		job.ID, job.Status, job.CreatedAt, startedAt, completedAt,
		string(optionsJSON), job.ErrorMessage,
		transfersCompleted, transfersFailed, transfersTotal,
		bytesTransferred, totalBytes, job.RetryCount,
	)
	if err != nil {
		return errors.Wrap(err, "failed to insert job into history")
	}

	// Insert transfers into transfer_history
	for _, t := range transfers {
		transferHistoryQuery := `INSERT INTO transfer_history
		                         (id, job_id, operation, source, destination, recursive, status,
		                          created_at, started_at, completed_at, bytes_transferred, total_bytes, error_message)
		                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

		var tStartedAt, tCompletedAt sql.NullInt64
		if t.StartedAt != nil {
			tStartedAt.Valid = true
			tStartedAt.Int64 = t.StartedAt.Unix()
		}
		if t.CompletedAt != nil {
			tCompletedAt.Valid = true
			tCompletedAt.Int64 = t.CompletedAt.Unix()
		}

		_, err = tx.Exec(transferHistoryQuery,
			t.ID, t.JobID, t.Operation, t.Source, t.Destination, t.Recursive, t.Status,
			t.CreatedAt, tStartedAt, tCompletedAt,
			t.BytesTransferred, t.TotalBytes, t.ErrorMessage,
		)
		if err != nil {
			return errors.Wrap(err, "failed to insert transfer into history")
		}
	}

	// Delete from active tables (transfers will be cascade deleted)
	deleteQuery := `DELETE FROM jobs WHERE id = ?`
	_, err = tx.Exec(deleteQuery, jobID)
	if err != nil {
		return errors.Wrap(err, "failed to delete job from active table")
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "failed to commit archive transaction")
	}

	log.Infof("Archived job %s to history", jobID)
	return nil
}

// GetJobHistory retrieves historical jobs with optional filtering
func (s *Store) GetJobHistory(status string, from, to time.Time, limit, offset int) (interface{}, int, error) {
	// Build query with filters
	query := `SELECT id, status, created_at, started_at, completed_at, error_message,
	          transfers_completed, transfers_failed, transfers_total, bytes_transferred, total_bytes, retry_count
	          FROM job_history WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM job_history WHERE 1=1`
	args := []interface{}{}

	if status != "" {
		query += ` AND status = ?`
		countQuery += ` AND status = ?`
		args = append(args, status)
	}

	if !from.IsZero() {
		query += ` AND completed_at >= ?`
		countQuery += ` AND completed_at >= ?`
		args = append(args, from.Unix())
	}

	if !to.IsZero() {
		query += ` AND completed_at <= ?`
		countQuery += ` AND completed_at <= ?`
		args = append(args, to.Unix())
	}

	// Get total count
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to count historical jobs")
	}

	// Add ordering and pagination
	query += ` ORDER BY completed_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to query job history")
	}
	defer rows.Close()

	var jobs []*HistoricalJob
	for rows.Next() {
		var job HistoricalJob
		var startedAt, completedAt sql.NullInt64
		var errorMsg sql.NullString

		err := rows.Scan(
			&job.ID, &job.Status, &job.CreatedAt,
			&startedAt, &completedAt, &errorMsg,
			&job.TransfersCompleted, &job.TransfersFailed, &job.TransfersTotal,
			&job.BytesTransferred, &job.TotalBytes, &job.RetryCount,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, "failed to scan historical job row")
		}

		// Convert nullable fields
		if startedAt.Valid {
			t := time.Unix(startedAt.Int64, 0)
			job.StartedAt = &t
		}
		if completedAt.Valid {
			t := time.Unix(completedAt.Int64, 0)
			job.CompletedAt = &t
		}
		if errorMsg.Valid {
			job.ErrorMessage = errorMsg.String
		}

		jobs = append(jobs, &job)
	}

	return jobs, total, nil
}

// PruneHistory deletes historical jobs older than the specified time
func (s *Store) PruneHistory(olderThan time.Time) (int, error) {
	// Delete from transfer_history first (will cascade via foreign key)
	// Then delete from job_history
	query := `DELETE FROM job_history WHERE completed_at < ?`
	result, err := s.db.Exec(query, olderThan.Unix())
	if err != nil {
		return 0, errors.Wrap(err, "failed to prune history")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "failed to get rows affected")
	}

	log.Infof("Pruned %d historical jobs older than %s", rows, olderThan.Format(time.RFC3339))
	return int(rows), nil
}

// DeleteJobHistory deletes a specific job from history
func (s *Store) DeleteJobHistory(jobID string) error {
	// Delete from job_history (transfers will be cascaded)
	query := `DELETE FROM job_history WHERE id = ?`
	result, err := s.db.Exec(query, jobID)
	if err != nil {
		return errors.Wrap(err, "failed to delete job history")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}

	if rows == 0 {
		return errors.New("job history not found")
	}

	log.Infof("Deleted historical job %s", jobID)
	return nil
}
