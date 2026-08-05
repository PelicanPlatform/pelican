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

// lotmanVersion -- the API version this shared library advertises -- is defined
// per ABI variant, in export_api_v1.go and export_api_legacy.go, so the string
// can never contradict the signatures actually exported. A consumer that
// version-gates on lotman_version() and then calls a differently-shaped entry
// point gets shifted arguments and a crash.
//
// The value carries the leading "v" the original library published
// ("v" + major.minor.patch); that prefix is also what makes it parse as a
// semver, and Pelican's own historical gate used semver.IsValid, which rejects
// an unprefixed "0.1.0".

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

	db, err := gorm.Open(sqlite.Open(lotDBDSN(dbPath, busy)), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("unable to open lot database %q: %w", dbPath, err)
	}
	// Everything below can fail, and gorm has already opened a connection pool.
	// This function is called from every C entry point, so a persistently
	// failing migration -- a lot_home on a read-only mount, or a database left
	// behind by the original C++ library, whose schema differs -- would
	// otherwise leak a pool per call inside a long-lived xrootd.
	ok = false
	defer func() {
		if !ok {
			closeGormDB(db)
		}
	}()

	m, err := core.New(db, core.Options{StrictHierarchy: true, ContractionPolicy: core.ContractionAlways})
	if err != nil {
		return nil, err
	}
	if err := m.Migrate(); err != nil {
		return nil, fmt.Errorf("unable to migrate lot database: %w", err)
	}

	// Replacing a manager built over a different lot_home: release the old
	// one's pool rather than dropping it on the floor.
	if mgr != nil {
		_ = mgr.Close()
	}
	mgr = m
	mgrLotHome = lotHome
	ok = true
	return mgr, nil
}

// lotDBDSN builds the connection string for the shared lot database.
//
// _txlock=immediate is the load-bearing part. Every core mutation is a
// read-then-write inside one transaction, and this database is shared with
// pelican-server, which opens it with the same flag. Without it SQLite takes a
// deferred read lock and tries to upgrade on the first write; when the other
// process commits in between, the upgrade fails with SQLITE_BUSY_SNAPSHOT
// *immediately* -- busy_timeout cannot retry it, because waiting cannot resolve
// the conflict. The purge plugin then reports an error and recovers no bytes
// that cycle.
//
// This mirrors database/utils.SQLiteDSN, which is the canonical definition;
// it is restated here rather than imported so the shared library does not pull
// in Pelican's config package and everything behind it. TestDSNMatchesPelican
// asserts the two cannot drift apart.
func lotDBDSN(dbPath string, busyTimeoutMs int) string {
	return fmt.Sprintf(
		"%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate",
		dbPath, busyTimeoutMs)
}

// closeGormDB releases a *gorm.DB's underlying connection pool.
func closeGormDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
