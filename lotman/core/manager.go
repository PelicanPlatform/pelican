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

package core

import (
	"embed"
	"time"

	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// migrationsDir is the path of the migrations within embeddedMigrations.
const migrationsDir = "migrations"

// gooseTableName is the lotman-private Goose version table. Using a distinct
// name lets the lot schema coexist in a shared SQLite database without
// colliding with other components' migration bookkeeping.
const gooseTableName = "lotman_goose_db_version"

// ContractionPolicy controls whether MPA reductions that would drop a parent's
// capacity below its children's reserved shares are permitted.
type ContractionPolicy string

const (
	// ContractionNone places no restrictions on MPA reductions.
	ContractionNone ContractionPolicy = "none"
	// ContractionAlways blocks reductions that violate children's reserved shares.
	ContractionAlways ContractionPolicy = "always"
)

// Options configures a Manager.
type Options struct {
	// StrictHierarchy enables the parent/child MPA axioms on mutation.
	StrictHierarchy bool
	// ContractionPolicy governs MPA reductions; defaults to ContractionAlways.
	ContractionPolicy ContractionPolicy
	// AdminOverride bypasses contraction-policy checks (axioms still apply).
	AdminOverride bool
	// Now supplies the current time; defaults to time.Now. Injectable for tests.
	Now func() time.Time
	// Logger receives debug/warn output; defaults to a no-op logger.
	Logger Logger
}

// Manager is the entry point for all lot operations. It is safe for concurrent
// use to the extent the underlying *gorm.DB / SQLite connection is (the Pelican
// DSN enables WAL + a busy timeout); individual mutations run in transactions.
type Manager struct {
	db   *gorm.DB
	opts Options
	log  Logger
	now  func() time.Time
}

// New constructs a Manager over the supplied GORM handle. It does not run
// migrations; call Migrate (or ensure the host has applied them) first.
func New(db *gorm.DB, opts Options) (*Manager, error) {
	if db == nil {
		return nil, ErrNilDB
	}
	if opts.ContractionPolicy == "" {
		opts.ContractionPolicy = ContractionAlways
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = nopLogger{}
	}
	return &Manager{db: db, opts: opts, log: opts.Logger, now: opts.Now}, nil
}

// Migrate applies the embedded lot-schema migrations against the Manager's
// database, tracked in the lotman-private Goose version table. It is idempotent
// and safe to call on every startup. Migrations run sequentially at startup;
// this is not safe to call concurrently with other Goose-based migrators
// (Goose uses process-global dialect/table state), matching Pelican's usage.
func (m *Manager) Migrate() error {
	sqlDB, err := m.db.DB()
	if err != nil {
		return wrap(err, "obtaining sql.DB handle for migrations")
	}
	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return wrap(err, "setting goose dialect")
	}
	goose.SetTableName(gooseTableName)
	if err := goose.Up(sqlDB, migrationsDir); err != nil {
		return wrap(err, "applying lot migrations")
	}
	return nil
}

// nowMs returns the manager's notion of "now" in Unix milliseconds.
func (m *Manager) nowMs() int64 {
	return m.now().UnixMilli()
}
