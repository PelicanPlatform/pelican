package utils

import (
	"database/sql"
	"embed"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"github.com/pkg/errors"
	"github.com/pressly/goose/v3"
	log "github.com/sirupsen/logrus"
	gormlog "github.com/thomas-tacquet/gormv2-logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/pelicanplatform/pelican/config"
)

// SQLiteDSN builds a SQLite connection string with the project's standard
// connection parameters. This centralizes DSN construction so callers don't
// duplicate query parameters as ad-hoc string literals.
func SQLiteDSN(dbPath string) string {
	// Use repeated _pragma entries, as glebarez/sqlite (modernc.org/sqlite) requires.
	// The mattn-style `_name=value` shorthand is silently ignored.
	return dbPath + "?" +
		"_pragma=busy_timeout(5000)&" +
		"_pragma=journal_mode(WAL)&" +
		"_pragma=foreign_keys(1)"
}

func InitSQLiteDB(dbPath string) (*gorm.DB, error) {
	if dbPath == "" {
		return nil, errors.New("SQLite database path is empty")
	}

	// Before attempting to create the database, the path
	// must exist or sql.Open will panic.
	err := os.MkdirAll(filepath.Dir(dbPath), 0755)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create directory for SQLite database at %s", dbPath)
	}

	if len(filepath.Ext(dbPath)) == 0 { // No fp extension, let's add .sqlite so it's obvious what the file is
		dbPath += ".sqlite"
	}

	dbName := SQLiteDSN(dbPath)

	globalLogLevel := config.GetEffectiveLogLevel()
	var ormLevel logger.LogLevel
	if globalLogLevel == log.DebugLevel || globalLogLevel == log.TraceLevel || globalLogLevel == log.InfoLevel {
		ormLevel = logger.Info
	} else if globalLogLevel == log.WarnLevel {
		ormLevel = logger.Warn
	} else if globalLogLevel == log.ErrorLevel {
		ormLevel = logger.Error
	} else {
		ormLevel = logger.Info
	}

	gormLogger := gormlog.NewGormlog(
		gormlog.WithLogrusEntry(log.WithField("component", "gorm")),
		gormlog.WithGormOptions(gormlog.GormOptions{
			LogLatency: true,
			LogLevel:   ormLevel,
		}),
	)

	log.Debugln("Opening connection to sqlite DB", dbName)

	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{Logger: gormLogger})

	if err != nil {
		return nil, errors.Wrapf(err, "failed to open the database with path: %s", dbPath)
	}

	// SQLite permits at most one writer at a time. With database/sql's default of
	// unbounded MaxOpenConns, any goroutine that leaks a transaction (leaves BEGIN
	// without COMMIT/ROLLBACK) poisons one connection; the next caller to pull that
	// connection from the pool fails with "cannot start a transaction within a
	// transaction" and, because the driver still holds the DB handle, the hot
	// rollback journal never clears -- the whole DB appears stuck.
	//
	// Pinning MaxOpenConns to 1 serializes writes through a single connection, so
	// a leaked transaction is immediately visible to its own caller instead of
	// being deferred onto an unrelated code path, and the connection is reset
	// cleanly by GORM's Transaction machinery on the next use. Readers are
	// unaffected at our scale (this DB is metadata-sized) and the five-second busy
	// timeout continues to handle any transient contention with external processes.
	sqlDB, err := db.DB()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to obtain underlying *sql.DB for %s", dbPath)
	}
	sqlDB.SetMaxOpenConns(1)

	return db, nil
}

func MigrateDB(sqldb *sql.DB, migrationFS embed.FS, migrationPath string) error {
	return MigrateServerSpecificDB(sqldb, migrationFS, migrationPath, "")
}

func MigrateServerSpecificDB(sqldb *sql.DB, migrationFS embed.FS, migrationPath string, tablePrefix string) error {
	goose.SetBaseFS(migrationFS)

	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}

	// Set table prefix if provided (for server-type-specific migrations)
	if tablePrefix != "" {
		goose.SetTableName(tablePrefix + "_goose_db_version")
	} else {
		goose.SetTableName("goose_db_version") // Default table name
	}

	if err := goose.Up(sqldb, migrationPath); err != nil {
		return err
	}
	return nil
}
