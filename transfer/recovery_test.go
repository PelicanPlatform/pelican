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
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// newTransferTestDB stands up an isolated server database with the transfer
// tables migrated, creates an owning user (transfer_jobs.user_id is a foreign
// key into users), and returns the handle plus that user's ID.
func newTransferTestDB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	tmpDir := t.TempDir()
	require.NoError(t, param.Set(param.ConfigBase, tmpDir))
	require.NoError(t, param.Set(param.Server_DbLocation, filepath.Join(tmpDir, "transfer.sqlite")))

	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, config.InitServer(context.Background(), server_structs.TransferType))
	require.NoError(t, database.InitServerDatabase(server_structs.TransferType))
	t.Cleanup(func() {
		_ = database.ShutdownDB()
		database.ServerDatabase = nil
	})
	require.NoError(t, InitTransferDatabase())
	db := database.ServerDatabase

	user, err := database.GetOrCreateUser(db, "recovery-test-user", "recovery-test-sub", "https://test.local", database.CreatorSelf())
	require.NoError(t, err)
	return db, user.ID
}

// TestReconcileInterruptedJobs verifies the crash-recovery scan: a job left with
// no completed_at (in flight when the server stopped) is marked failed, while an
// already-terminal job is left untouched.
func TestReconcileInterruptedJobs(t *testing.T) {
	db, userID := newTransferTestDB(t)

	now := time.Now()
	inflight := TransferJob{ID: "inflight", UserID: userID, RequestBody: "{}", CreatedAt: now, UpdatedAt: now}
	done := now.Add(-time.Minute)
	completed := TransferJob{ID: "done", UserID: userID, RequestBody: "{}", CreatedAt: now, CompletedAt: &done, UpdatedAt: now}
	require.NoError(t, db.Create(&inflight).Error)
	require.NoError(t, db.Create(&completed).Error)

	require.NoError(t, reconcileInterruptedJobs(db))

	var got TransferJob
	require.NoError(t, db.Where("id = ?", "inflight").First(&got).Error)
	require.NotNil(t, got.CompletedAt, "interrupted job must be marked terminal")
	assert.Contains(t, got.Error, "interrupted", "interrupted job must carry the restart error")
	assert.Equal(t, "failed", deriveJobStatus(got))

	var stillDone TransferJob
	require.NoError(t, db.Where("id = ?", "done").First(&stillDone).Error)
	assert.Empty(t, stillDone.Error, "an already-completed job must be left untouched")
	assert.Equal(t, done.Unix(), stillDone.CompletedAt.Unix(), "its completed_at must not move")
}

// TestPersistTerminalJob verifies the eager completion callback records a
// terminal outcome to the row WITHOUT any client GET (the previous design only
// synced status on poll).
func TestPersistTerminalJob(t *testing.T) {
	db, userID := newTransferTestDB(t)

	now := time.Now()
	require.NoError(t, db.Create(&TransferJob{ID: "job1", UserID: userID, RequestBody: "{}", CreatedAt: now, UpdatedAt: now}).Error)

	// Before the callback the job is in flight (no completed_at -> "unknown").
	var before TransferJob
	require.NoError(t, db.Where("id = ?", "job1").First(&before).Error)
	require.Nil(t, before.CompletedAt)

	completedAt := now.Add(time.Second)
	persistTerminalJob(db)(&client_agent.TransferJob{
		ID:          "job1",
		Status:      client_agent.StatusFailed,
		CompletedAt: &completedAt,
		Error:       errors.New("boom"),
	})

	var after TransferJob
	require.NoError(t, db.Where("id = ?", "job1").First(&after).Error)
	require.NotNil(t, after.CompletedAt, "eager write must set completed_at without a GET")
	assert.Equal(t, "boom", after.Error)
	assert.Equal(t, "failed", deriveJobStatus(after))

	// A successful job records completed_at with no error.
	require.NoError(t, db.Create(&TransferJob{ID: "job2", UserID: userID, RequestBody: "{}", CreatedAt: now, UpdatedAt: now}).Error)
	okAt := now.Add(2 * time.Second)
	persistTerminalJob(db)(&client_agent.TransferJob{ID: "job2", Status: client_agent.StatusCompleted, CompletedAt: &okAt})
	var ok TransferJob
	require.NoError(t, db.Where("id = ?", "job2").First(&ok).Error)
	require.NotNil(t, ok.CompletedAt)
	assert.Empty(t, ok.Error)
	assert.Equal(t, "completed", deriveJobStatus(ok))
}
