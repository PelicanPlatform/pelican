/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package server_utils

import (
	"database/sql"
	"embed"

	"github.com/pressly/goose/v3"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	dbutils "github.com/pelicanplatform/pelican/database/utils"
)

// InitSQLiteDB opens (creating it if need be) the SQLite database at dbPath.
//
// It is a thin alias for the implementation in database/utils, kept so the
// callers that reach for server_utils keep working.  The body used to be a
// verbatim copy of that one, which meant every fix to the shared logger or DSN
// handling had to be made -- and remembered -- twice.
func InitSQLiteDB(dbPath string) (*gorm.DB, error) {
	return dbutils.InitSQLiteDB(dbPath)
}

// Update database schema with the embedded migration files
//
// The embedded migration files need to be under "/migrations" folder
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

func ShutdownDB(db *gorm.DB) error {
	sqldb, err := db.DB()
	if err != nil {
		log.Errorln("Failure when getting database instance from gorm:", err)
		return err
	}
	err = sqldb.Close()
	if err != nil {
		log.Errorln("Failure when shutting down the database:", err)
	}
	return err
}
