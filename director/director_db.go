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
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type ServerStatus struct {
	UUID       string     `gorm:"primaryKey"`
	Name       string     `gorm:"not null;unique"`
	FilterType filterType `gorm:"type:text;not null"`
	// We don't use gorm default gorm.Model to change ID type to string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

var db *gorm.DB

//go:embed migrations/*.sql
var embedMigrations embed.FS

func InitializeDB() error {
	dbPath := param.Director_DbLocation.GetString()
	tdb, err := server_utils.InitSQLiteDB(dbPath)
	if err != nil {
		return err
	}
	db = tdb
	sqldb, err := db.DB()
	if err != nil {
		return errors.Wrapf(err, "Failed to get sql.DB from gorm DB: %s", dbPath)
	}
	// Run database migrations
	if err := server_utils.MigrateDB(sqldb, embedMigrations); err != nil {
		return err
	}
	return nil
}

func ShutdownDirectorDB() error {
	return server_utils.ShutdownDB(db)
}

func CreateServerStatus(name string, filterType filterType) error {
	id, err := uuid.NewV7()
	if err != nil {
		return errors.Wrap(err, "Unable to create new UUID for new entry in server status table")
	}
	serverStatus := ServerStatus{
		UUID:       id.String(),
		Name:       name,
		FilterType: filterType,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := db.Create(serverStatus).Error; err != nil {
		return err
	}
	return nil
}

func GetServerStatus(name string) (filterType, error) {
	var serverStatus ServerStatus
	err := db.First(&serverStatus, "name = ?", name).Error
	if err != nil {
		return "", err
	}
	return filterType(serverStatus.FilterType), nil
}

func GetAllServerStatuses() ([]ServerStatus, error) {
	var statuses []ServerStatus
	result := db.Find(&statuses)

	if result.Error != nil {
		return nil, result.Error
	}
	return statuses, nil
}

// Set filterType of a given server. If the server doesn't exist in director db, create a new entry for it
func SetServerStatus(name string, filterType filterType) error {
	var serverStatus ServerStatus
	err := db.First(&serverStatus, "name = ?", name).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return CreateServerStatus(name, filterType)
	} else if err != nil {
		return errors.Wrap(err, "Error retrieving Server Status")
	}

	serverStatus.FilterType = filterType
	serverStatus.UpdatedAt = time.Now()

	if err := db.Save(&serverStatus).Error; err != nil {
		return err
	}
	return nil
}

func DeleteServerStatus(name string) error {
	if err := db.Where("name = ?", name).Delete(&ServerStatus{}).Error; err != nil {
		return errors.Wrap(err, "Failed to delete an entry in Server Status table")
	}
	return nil
}
