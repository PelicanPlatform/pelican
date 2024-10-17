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
	UUID     string `gorm:"primaryKey"`
	URL      string `gorm:"not null;default:''"`
	Downtime bool   `gorm:"not null;default:false"`
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

func CreateServerStatus(url string) error {
	id, err := uuid.NewV7()
	if err != nil {
		return errors.Wrap(err, "Unable to create new UUID for new entry in server status table")
	}
	serverStatus := ServerStatus{
		UUID:      id.String(),
		URL:       url,
		Downtime:  false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := db.Create(serverStatus).Error; err != nil {
		return err
	}
	return nil
}

func GetServerDowntime(url string) (bool, error) {
	var serverStatus ServerStatus
	err := db.First(&serverStatus, "url = ?", url).Error
	if err != nil {
		return false, err
	}
	return serverStatus.Downtime, nil
}

func SetServerDowntime(downtime bool, url string) error {
	var serverStatus ServerStatus
	err := db.First(&serverStatus, "url = ?", url).Error
	if err != nil {
		return err
	}
	serverStatus.Downtime = downtime
	serverStatus.UpdatedAt = time.Now()

	if err := db.Save(&serverStatus).Error; err != nil {
		return err
	}
	return nil
}
