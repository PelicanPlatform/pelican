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
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestSQLiteDSNSettings(t *testing.T) {
	dsn := SQLiteDSN("/var/lib/pelican/test.sqlite")
	// busy_timeout + WAL serialize writers; _txlock=immediate makes each
	// transaction take the write lock up front so busy_timeout actually applies
	// (deferred transactions deadlock on the read->write upgrade and return
	// SQLITE_BUSY immediately regardless of busy_timeout).
	require.Contains(t, dsn, "_pragma=busy_timeout(5000)")
	require.Contains(t, dsn, "_pragma=journal_mode(WAL)")
	require.Contains(t, dsn, "_txlock=immediate")
}

func TestWriteTxAndReadTx(t *testing.T) {
	db, err := InitSQLiteDB(filepath.Join(t.TempDir(), "txwrappers.sqlite"))
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE TABLE kv (k TEXT PRIMARY KEY, v INTEGER)").Error)

	// WriteTx commits on success.
	require.NoError(t, WriteTx(db, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO kv (k, v) VALUES ('a', 1)").Error
	}))

	// ReadTx sees the committed row.
	var v int
	require.NoError(t, ReadTx(db, func(tx *gorm.DB) error {
		return tx.Raw("SELECT v FROM kv WHERE k = 'a'").Scan(&v).Error
	}))
	require.Equal(t, 1, v)

	// WriteTx rolls back when fn returns an error.
	sentinel := errors.New("boom")
	require.ErrorIs(t, WriteTx(db, func(tx *gorm.DB) error {
		if e := tx.Exec("UPDATE kv SET v = 99 WHERE k = 'a'").Error; e != nil {
			return e
		}
		return sentinel
	}), sentinel)

	require.NoError(t, ReadTx(db, func(tx *gorm.DB) error {
		return tx.Raw("SELECT v FROM kv WHERE k = 'a'").Scan(&v).Error
	}))
	require.Equal(t, 1, v, "rolled-back WriteTx must not have changed the row")
}

// TestSQLiteConcurrentWritesNoBusy guards against the "database is locked"
// regression: many connections from the pool running read-then-write
// transactions concurrently must serialize cleanly (no SQLITE_BUSY, no lost
// updates) rather than deadlocking on the deferred read->write upgrade.
func TestSQLiteConcurrentWritesNoBusy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent.sqlite")
	db, err := InitSQLiteDB(dbPath)
	require.NoError(t, err)
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
