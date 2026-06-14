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
	//
	// _txlock=immediate makes every transaction BEGIN IMMEDIATE, acquiring the
	// write lock up front. Without it, GORM's default deferred transactions take
	// only a read lock and then try to upgrade to a write on their first write
	// statement; when two connections from the pool do this concurrently, SQLite
	// returns SQLITE_BUSY ("database is locked") *immediately* -- busy_timeout
	// does not help, because waiting cannot resolve the mutual upgrade. With
	// BEGIN IMMEDIATE, a second writer instead waits on busy_timeout for the
	// write lock, which is exactly the intended serialization.
	//
	// Consequently every explicit transaction is BEGIN IMMEDIATE by default. A
	// multi-statement read that must stay concurrent with writers should run via
	// ReadTx (which marks the transaction ReadOnly); lone autocommit reads are
	// unaffected and remain concurrent. Prefer WriteTx/ReadTx over calling
	// db.Transaction directly so the lock intent is explicit.
	return dbPath + "?" +
		"_pragma=busy_timeout(5000)&" +
		"_pragma=journal_mode(WAL)&" +
		"_pragma=foreign_keys(1)&" +
		"_txlock=immediate"
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

	return db, nil
}

// WriteTx runs fn inside a read-write transaction. With the standard SQLite DSN
// (see SQLiteDSN) the transaction is BEGIN IMMEDIATE: it takes the write lock up
// front and serializes cleanly against other writers via busy_timeout, instead
// of risking an immediate SQLITE_BUSY ("database is locked") on a deferred
// read->write upgrade. This is the default shape; use it for any transaction
// that writes.
func WriteTx(db *gorm.DB, fn func(tx *gorm.DB) error) error {
	return db.Transaction(fn)
}

// ReadTx runs fn inside a read-only transaction. It is marked ReadOnly so the
// driver issues a deferred read transaction that keeps running concurrently
// under WAL even while a writer holds the lock -- unlike a default transaction,
// which BEGIN IMMEDIATE would serialize. Use it only for a multi-statement read
// that needs a single consistent snapshot. (A lone query -- db.First/Find/Where
// with no transaction -- is already a concurrent autocommit read and needs no
// wrapper.)
func ReadTx(db *gorm.DB, fn func(tx *gorm.DB) error) error {
	return db.Transaction(fn, &sql.TxOptions{ReadOnly: true})
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
