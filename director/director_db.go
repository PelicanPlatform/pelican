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
package director

import (
	"embed"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

type ServerDowntime struct {
	UUID       string     `gorm:"primaryKey"`
	Name       string     `gorm:"not null;unique"`
	FilterType filterType `gorm:"type:text;not null"`
	// We don't use gorm default gorm.Model to change ID type to string
	CreatedAt time.Time
	UpdatedAt time.Time
}

var db *gorm.DB

//go:embed migrations/*.sql
var embedMigrations embed.FS

// Initialize the Director's sqlite database, which is used to persist information about server downtimes
func InitializeDB() error {
	dbPath := param.Director_DbLocation.GetString()
	tdb, err := server_utils.InitSQLiteDB(dbPath)
	if err != nil {
		return errors.Wrap(err, "failed to initialize the Director's sqlite database")
	}
	db = tdb
	sqldb, err := db.DB()
	if err != nil {
		return errors.Wrapf(err, "failed to get sql.DB from gorm DB: %s", dbPath)
	}
	// Run database migrations
	if err := server_utils.MigrateDB(sqldb, embedMigrations); err != nil {
		return errors.Wrap(err, "failed to migrate the Director's sqlite database using embedded migration files")
	}
	return nil
}

// Shut down the Director's sqlite database
func shutdownDirectorDB() error {
	return server_utils.ShutdownDB(db)
}

// Create a new db entry representing the downtime info of a server
func createServerDowntime(serverName string, filterType filterType) error {
	id, err := uuid.NewV7()
	if err != nil {
		return errors.Wrap(err, "unable to create new UUID for new entry in server status table")
	}
	serverDowntime := ServerDowntime{
		UUID:       id.String(),
		Name:       serverName,
		FilterType: filterType,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := db.Create(serverDowntime).Error; err != nil {
		return errors.Wrap(err, "unable to create server downtime table")
	}
	return nil
}

// Retrieve the downtime info of a given server (filter applied to the server)
func getServerDowntime(serverName string) (filterType, error) {
	var serverDowntime ServerDowntime
	err := db.First(&serverDowntime, "name = ?", serverName).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", errors.Wrapf(err, "%s is not found in the Director db", serverName)
		}
		return "", errors.Wrapf(err, "unable to get the downtime of %s", serverName)
	}
	return filterType(serverDowntime.FilterType), nil
}

// Retrieve the downtime info of all servers saved in the Director's sqlite database
func getAllServerDowntimes() ([]ServerDowntime, error) {
	var statuses []ServerDowntime
	result := db.Find(&statuses)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to get the downtime of all servers")
	}
	return statuses, nil
}

// Set the downtime info (filterType) of a given server
func setServerDowntime(serverName string, filterType filterType) error {
	var serverDowntime ServerDowntime
	// silence the logger for this query because there's definitely an ErrRecordNotFound when a new downtime info entry inserted
	err := db.Session(&gorm.Session{Logger: db.Logger.LogMode(logger.Silent)}).First(&serverDowntime, "name = ?", serverName).Error

	// If the server doesn't exist in director db, create a new entry for it
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return createServerDowntime(serverName, filterType)
		}

		return errors.Wrapf(err, "unable to retrieve downtime status for server %s", serverName)
	}

	serverDowntime.FilterType = filterType
	serverDowntime.UpdatedAt = time.Now()

	if err := db.Save(&serverDowntime).Error; err != nil {
		return errors.Wrap(err, "unable to update")
	}
	return nil
}

// Define a function type for setServerDowntime
type setServerDowntimeFunc func(string, filterType) error

// Make the function a variable so it can be mocked in tests
var setServerDowntimeFn setServerDowntimeFunc = setServerDowntime

// Delete the downtime info of a given server from the Director's sqlite database
func deleteServerDowntime(serverName string) error {
	if err := db.Where("name = ?", serverName).Delete(&ServerDowntime{}).Error; err != nil {
		return errors.Wrap(err, "failed to delete an entry in Server Status table")
	}
	return nil
}

// Define a function type for deleteServerDowntime
type deleteServerDowntimeFunc func(string) error

// Make the function a variable so it can be mocked in tests
var deleteServerDowntimeFn deleteServerDowntimeFunc = deleteServerDowntime
