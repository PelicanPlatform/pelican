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
)

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

	dbName := dbPath + "?_busy_timeout=5000&_journal_mode=WAL"

	globalLogLevel := log.GetLevel()
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

func MigrateDB(sqldb *sql.DB, migrationFS embed.FS) error {
	goose.SetBaseFS(migrationFS)

	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}

	if err := goose.Up(sqldb, "migrations"); err != nil {
		return err
	}
	return nil
}
