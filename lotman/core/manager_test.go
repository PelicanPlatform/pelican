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
	"errors"
	"path/filepath"
	"testing"

	// The sqlite driver is imported only in tests; the core package proper takes
	// an already-opened *gorm.DB and never depends on a specific driver.
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newTestDB opens a fresh temp-file SQLite database with foreign keys enabled
// (lot tables rely on ON DELETE CASCADE).
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "lotman-test.sqlite")
	dsn := dbPath + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	return db
}

// newTestManager returns a migrated Manager with strict hierarchy enabled.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(newTestDB(t), Options{StrictHierarchy: true})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := m.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return m
}

func TestNewRejectsNilDB(t *testing.T) {
	if _, err := New(nil, Options{}); !errors.Is(err, ErrNilDB) {
		t.Fatalf("expected ErrNilDB, got %v", err)
	}
}

func TestMigrateCreatesTablesAndIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	m, err := New(db, Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := m.Migrate(); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	// Idempotent: a second Up should be a no-op, not an error.
	if err := m.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	want := []string{
		"lots", "lot_parents", "lot_paths", "lot_usage",
		"lot_parent_attributions", "lot_reclamations",
	}
	for _, tbl := range want {
		var name string
		err := db.Raw(
			"SELECT name FROM sqlite_master WHERE type='table' AND name = ?", tbl,
		).Scan(&name).Error
		if err != nil {
			t.Fatalf("query for table %q: %v", tbl, err)
		}
		if name != tbl {
			t.Errorf("expected table %q to exist, not found", tbl)
		}
	}
}

func TestMigrateDefaultsApplied(t *testing.T) {
	m := newTestManager(t)
	if m.opts.ContractionPolicy != ContractionAlways {
		t.Errorf("expected default contraction policy %q, got %q", ContractionAlways, m.opts.ContractionPolicy)
	}
	if m.now == nil {
		t.Error("expected non-nil now function")
	}
	if m.log == nil {
		t.Error("expected non-nil logger")
	}
}
