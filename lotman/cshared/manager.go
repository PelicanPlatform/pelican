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

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// lotmanVersion is the API version this shared library advertises. It matches
// the C ABI the historical libLotMan published (and that the XRootD purge
// plugin version-gates against).
const lotmanVersion = "0.1.0"

// defaultBusyTimeoutMs is the SQLite busy timeout used unless the caller
// overrides it via the "db_timeout" integer context key.
const defaultBusyTimeoutMs = 5000

// Context store. The C ABI is configured imperatively via
// lotman_set_context_{str,int}; "lot_home" selects the database directory,
// "caller" identifies who is invoking mutating operations, and "db_timeout"
// (ms) tunes the SQLite busy timeout for multi-process access.
var (
	ctxMu  sync.RWMutex
	ctxStr = map[string]string{}
	ctxInt = map[string]int{}
)

func setContextStr(key, value string) {
	ctxMu.Lock()
	defer ctxMu.Unlock()
	ctxStr[key] = value
}

func getContextStr(key string) (string, bool) {
	ctxMu.RLock()
	defer ctxMu.RUnlock()
	v, ok := ctxStr[key]
	return v, ok
}

func setContextInt(key string, value int) {
	ctxMu.Lock()
	defer ctxMu.Unlock()
	ctxInt[key] = value
}

func getContextInt(key string) (int, bool) {
	ctxMu.RLock()
	defer ctxMu.RUnlock()
	v, ok := ctxInt[key]
	return v, ok
}

// caller returns the configured caller identity (empty if unset).
func caller() string {
	v, _ := getContextStr("caller")
	return v
}

// Lazily-opened manager, keyed by the lot_home it was opened against so a
// caller that re-points lot_home gets a fresh database.
var (
	mgrMu      sync.Mutex
	mgr        *core.Manager
	mgrLotHome string
)

// manager returns the process-wide lot manager, opening (and migrating) the
// database under the current "lot_home" context on first use.
func manager() (*core.Manager, error) {
	lotHome, ok := getContextStr("lot_home")
	if !ok || lotHome == "" {
		return nil, errors.New(`the "lot_home" context key must be set before calling LotMan`)
	}

	mgrMu.Lock()
	defer mgrMu.Unlock()
	if mgr != nil && mgrLotHome == lotHome {
		return mgr, nil
	}

	if err := os.MkdirAll(lotHome, 0o755); err != nil {
		return nil, fmt.Errorf("unable to create lot_home %q: %w", lotHome, err)
	}

	busy := defaultBusyTimeoutMs
	if v, ok := getContextInt("db_timeout"); ok && v > 0 {
		busy = v
	}
	dbPath := filepath.Join(lotHome, "lots.sqlite")
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dbPath, busy)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("unable to open lot database %q: %w", dbPath, err)
	}
	m, err := core.New(db, core.Options{StrictHierarchy: true, ContractionPolicy: core.ContractionAlways})
	if err != nil {
		return nil, err
	}
	if err := m.Migrate(); err != nil {
		return nil, fmt.Errorf("unable to migrate lot database: %w", err)
	}

	mgr = m
	mgrLotHome = lotHome
	return mgr, nil
}
