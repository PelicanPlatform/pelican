//go:build unix

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

package utils

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestSQLiteConcurrentWritesNoBusy guards against the "database is locked"
// regression: many connections from the pool running read-then-write
// transactions concurrently must serialize cleanly (no SQLITE_BUSY, no lost
// updates) rather than deadlocking on the deferred read->write upgrade.
//
// Restricted to unix, the platforms Pelican's SQLite-backed servers deploy on
// and where the BEGIN IMMEDIATE + busy_timeout serialization contract this test
// asserts must hold. On Windows the pure-Go SQLite driver's file locking can
// still surface a spurious SQLITE_BUSY under this contention even with
// busy_timeout, and the Windows build is client-only (no server database), so
// exercising the contract there would only test the driver's Windows VFS.
func TestSQLiteConcurrentWritesNoBusy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent.sqlite")
	db, err := InitSQLiteDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { closeDB(t, db) })
	require.NoError(t, db.Exec("CREATE TABLE counter (id INTEGER PRIMARY KEY, n INTEGER)").Error)
	require.NoError(t, db.Exec("INSERT INTO counter (id, n) VALUES (1, 0)").Error)

	const goroutines, iters = 8, 60
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				txErr := db.Transaction(func(tx *gorm.DB) error {
					var n int
					if e := tx.Raw("SELECT n FROM counter WHERE id = 1").Scan(&n).Error; e != nil {
						return e
					}
					return tx.Exec("UPDATE counter SET n = ? WHERE id = 1", n+1).Error
				})
				if txErr != nil {
					mu.Lock()
					errs = append(errs, txErr)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("expected no errors from concurrent transactions, got %d; first: %v", len(errs), errs[0])
	}
	// Every transaction committed and serialized, so there are no lost updates.
	var final int
	require.NoError(t, db.Raw("SELECT n FROM counter WHERE id = 1").Scan(&final).Error)
	require.Equal(t, goroutines*iters, final, "serialized increments should not lose updates")
}
