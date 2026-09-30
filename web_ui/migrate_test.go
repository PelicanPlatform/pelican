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

// Deliberately NOT constrained to !windows. Most of this package's test
// files are, because they exercise unix-only behavior, but the schema
// helpers below are not unix-specific and scopes_test.go — which does
// run on Windows — needs them. Keeping them here is what lets that
// coverage stay on Windows instead of being excluded to satisfy the
// compiler.

package web_ui

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	dbutils "github.com/pelicanplatform/pelican/database/utils"
)

// migrateTestDB brings database.ServerDatabase up to the production
// schema.
func migrateTestDB(t *testing.T) {
	t.Helper()
	migrateTestDBHandle(t, database.ServerDatabase)
}

// migrateTestDBHandle brings one handle up to the production schema,
// for the setups that keep their own DB rather than using
// database.ServerDatabase.
func migrateTestDBHandle(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// Each CONNECTION to ":memory:" gets its own database, so the pool
	// is pinned to one. Without it goose could migrate a database the
	// queries never see.
	sqlDB.SetMaxOpenConns(1)
	// The production migrations, not AutoMigrate. GORM can only emit a
	// FULL unique index from struct tags, so a hand-rolled schema
	// lacks the partial indexes that let a soft-deleted account release
	// its username. Running the real thing also means the schema under test
	// is the schema that ships.
	require.NoError(t,
		dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"),
		"failed to run the production migrations against the test database")
}
