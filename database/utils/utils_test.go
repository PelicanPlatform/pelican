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
	"testing"

	log "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type probeRow struct {
	ID       uint `gorm:"primarykey"`
	IsActive bool
}

// "No such row" is how a great deal of this codebase asks a question -- is there
// an operator-edited AUP document? has this user signed one? -- and gorm answers
// it with an error. Logging every such miss at error level filled operators'
// logs with queries that failed in no meaningful sense.
func TestInitSQLiteDBDoesNotLogRecordNotFound(t *testing.T) {
	db, err := InitSQLiteDB(filepath.Join(t.TempDir(), "probe.sqlite"))
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&probeRow{}))

	hook := logrustest.NewLocal(log.StandardLogger())
	prevLevel := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetLevel(prevLevel)
		hook.Reset()
	})

	var row probeRow
	err = db.Where("is_active = ?", true).First(&row).Error
	// The caller still learns there was no row; only the logging changes.
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	for _, entry := range hook.AllEntries() {
		assert.NotEqual(t, log.ErrorLevel, entry.Level,
			"a missing row must not be logged as an error: %s", entry.Message)
	}

	// A query that is genuinely broken must still be reported.
	hook.Reset()
	require.Error(t, db.Raw("SELECT * FROM no_such_table").Scan(&row).Error)
	var sawError bool
	for _, entry := range hook.AllEntries() {
		if entry.Level == log.ErrorLevel {
			sawError = true
		}
	}
	assert.True(t, sawError, "a real SQL error must still be logged")
}
