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

package origin

import (
	"embed"
	"time"

	"github.com/pkg/errors"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

type GlobusCollection struct {
	UUID         string `gorm:"primaryKey"`
	Name         string `gorm:"not null;default:''"`
	ServerURL    string `gorm:"not null;default:''"`
	RefreshToken string `gorm:"not null;default:''"`
	// We don't use gorm default gorm.Model to use UUID as the pk
	// and don't allow soft delete
	CreatedAt time.Time
	UpdatedAt time.Time
}

/*
Declare the DB handle as an unexported global so that all
functions in the package can access it without having to
pass it around. This simplifies the HTTP handlers, and
the handle is already thread-safe! The approach being used
is based off of 1.b from
https://www.alexedwards.net/blog/organising-database-access
*/
var db *gorm.DB

//go:embed migrations/*.sql
var embedMigrations embed.FS

func InitializeDB() error {
	dbPath := param.Origin_DbLocation.GetString()

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

func ShutdownOriginDB() error {
	return server_utils.ShutdownDB(db)
}

func collectionExistsByUUID(uuid string) (bool, error) {
	var count int64
	err := db.Model(&GlobusCollection{}).Where("uuid = ?", uuid).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func getCollectionByUUID(uuid string) (*GlobusCollection, error) {
	var collection GlobusCollection
	err := db.First(&collection, "uuid = ?", uuid).Error
	if err != nil {
		return nil, err
	}
	if collection.RefreshToken != "" {
		collection.RefreshToken, err = config.DecryptString(collection.RefreshToken)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt the refresh token")
		}
	}
	return &collection, nil
}

func createCollection(collection *GlobusCollection) error {
	var err error
	if collection.RefreshToken != "" {
		collection.RefreshToken, err = config.EncryptString(collection.RefreshToken)
		if err != nil {
			return errors.Wrap(err, "failed to encrypt the refresh token")
		}
	}
	if err = db.Create(collection).Error; err != nil {
		return err
	}
	return nil
}

func updateCollection(uuid string, updatedCollection *GlobusCollection) error {
	var err error
	if updatedCollection.RefreshToken != "" {
		updatedCollection.RefreshToken, err = config.EncryptString(updatedCollection.RefreshToken)
		if err != nil {
			return errors.Wrap(err, "failed to encrypt the refresh token")
		}
	}
	if err = db.Model(&GlobusCollection{}).Where("uuid = ?", uuid).Updates(updatedCollection).Error; err != nil {
		return err
	}

	return nil
}

// Hard-delete the collection from the DB
func deleteCollectionByUUID(uuid string) error {
	return db.Delete(&GlobusCollection{}, "uuid = ?", uuid).Error
}
