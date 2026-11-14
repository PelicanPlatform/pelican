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
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// closeDB closes the underlying SQLite connection. Tests must close before the
// t.TempDir cleanup removes the file: on Windows an open handle keeps the file
// locked and RemoveAll fails the test.
func closeDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

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
	t.Cleanup(func() { closeDB(t, db) })
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
