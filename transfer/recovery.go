//go:build client || server

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
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/client_agent"
)

// persistTerminalJob returns the transfer manager's job-completion callback. It
// eagerly records a job's terminal outcome (completed_at, and error on failure)
// to its transfer_jobs row the moment the job finishes — rather than lazily on a
// client status poll. That keeps the durable record poll-independent and, with
// reconcileInterruptedJobs, makes crash recovery accurate: after this runs, a
// row with a NULL completed_at genuinely means the job was still in flight.
//
// Non-terminal states are deliberately not persisted; deriveJobStatus computes
// "in flight" from a NULL completed_at, so pending/running transitions never hit
// the database. Live status for a running job is still served from the in-memory
// manager by handleGetTransferJob.
func persistTerminalJob(db *gorm.DB) func(*client_agent.TransferJob) {
	return func(job *client_agent.TransferJob) {
		completedAt := time.Now()
		if job.CompletedAt != nil {
			completedAt = *job.CompletedAt
		}
		updates := map[string]any{
			"completed_at": completedAt,
			"updated_at":   time.Now(),
		}
		// Only failures carry an error; cancellation-without-error is left to the
		// cancel handler, and a successful job must not overwrite it. This mirrors
		// what the previous lazy on-GET sync wrote.
		if job.Error != nil {
			updates["error"] = job.Error.Error()
		}
		if err := db.Model(&TransferJob{}).Where("id = ?", job.ID).Updates(updates).Error; err != nil {
			log.Errorf("Failed to persist terminal state for transfer job %s: %v", job.ID, err)
		}
	}
}

// reconcileInterruptedJobs runs once at startup. The transfer manager holds no
// jobs across a restart, so any transfer_jobs row with a NULL completed_at is a
// job that was in flight when the server last stopped (crash or shutdown). Mark
// them failed so clients stop polling a job that will never finish on its own
// and can resubmit. (Resuming from the stored request_body is a possible future
// enhancement; failing is the safe default.)
func reconcileInterruptedJobs(db *gorm.DB) error {
	now := time.Now()
	res := db.Model(&TransferJob{}).
		Where("completed_at IS NULL").
		Updates(map[string]any{
			"completed_at": now,
			"error":        "interrupted by transfer server restart",
			"updated_at":   now,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		log.Warnf("Transfer server: marked %d in-flight transfer job(s) as failed after restart", res.RowsAffected)
	}
	return nil
}
