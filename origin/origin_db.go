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
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
)

type GlobusCollection struct {
	UUID                 string `gorm:"primaryKey"`
	Name                 string `gorm:"not null;default:''"`
	ServerURL            string `gorm:"not null;default:''"`
	RefreshToken         string `gorm:"not null;default:''"`
	TransferRefreshToken string `gorm:"not null;default:''"`
	// We don't use gorm default gorm.Model to use UUID as the pk
	// and don't allow soft delete
	CreatedAt time.Time
	UpdatedAt time.Time
}

func collectionExistsByUUID(uuid string) (bool, error) {
	var count int64
	err := database.ServerDatabase.Model(&GlobusCollection{}).Where("uuid = ?", uuid).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func getCollectionByUUID(uuid string) (*GlobusCollection, error) {
	var collection GlobusCollection
	err := database.ServerDatabase.First(&collection, "uuid = ?", uuid).Error
	if err != nil {
		return nil, err
	}
	if collection.RefreshToken != "" {
		var keyID string
		var decrypted string
		decrypted, keyID, err = config.DecryptString(collection.RefreshToken)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt the refresh token")
		}
		collection.RefreshToken = decrypted

		// Check if key rotation happened
		currentIssuerKey, err := config.GetIssuerPrivateJWK()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get current issuer key")
		}
		if keyID != currentIssuerKey.KeyID() {
			// Re-encrypt with the current key and update DB
			newEncrypted, err := config.EncryptString(collection.RefreshToken)
			if err == nil {
				// Only update if re-encryption succeeded
				database.ServerDatabase.Model(&GlobusCollection{}).Where("uuid = ?", uuid).Update("refresh_token", newEncrypted)
			}
		}
	}
	if collection.TransferRefreshToken != "" {
		var keyID string
		collection.TransferRefreshToken, keyID, err = config.DecryptString(collection.TransferRefreshToken)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt the transfer refresh token")
		}
		currentIssuerKey, err := config.GetIssuerPrivateJWK()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get current issuer key")
		}
		if keyID != currentIssuerKey.KeyID() {
			newEncrypted, err := config.EncryptString(collection.TransferRefreshToken)
			if err == nil {
				database.ServerDatabase.Model(&GlobusCollection{}).Where("uuid = ?", uuid).Update("transfer_refresh_token", newEncrypted)
			}
		}
	}
	return &collection, nil
}

func createCollection(collection *GlobusCollection) error {
	if collection.RefreshToken != "" {
		var err error
		collection.RefreshToken, err = config.EncryptString(collection.RefreshToken)
		if err != nil {
			return errors.Wrap(err, "failed to encrypt the refresh token")
		}
	}
	if collection.TransferRefreshToken != "" {
		var err error
		collection.TransferRefreshToken, err = config.EncryptString(collection.TransferRefreshToken)
		if err != nil {
			return errors.Wrap(err, "failed to encrypt the transfer refresh token")
		}
	}
	if err := database.ServerDatabase.Create(collection).Error; err != nil {
		return err
	}
	return nil
}

func updateCollection(uuid string, updatedCollection *GlobusCollection) error {
	if updatedCollection.RefreshToken != "" {
		var err error
		updatedCollection.RefreshToken, err = config.EncryptString(updatedCollection.RefreshToken)
		if err != nil {
			return errors.Wrap(err, "failed to encrypt the refresh token")
		}
	}
	if updatedCollection.TransferRefreshToken != "" {
		var err error
		updatedCollection.TransferRefreshToken, err = config.EncryptString(updatedCollection.TransferRefreshToken)
		if err != nil {
			return errors.Wrap(err, "failed to encrypt the transfer refresh token")
		}
	}
	if err := database.ServerDatabase.Model(&GlobusCollection{}).Where("uuid = ?", uuid).Updates(updatedCollection).Error; err != nil {
		return err
	}

	return nil
}

// Hard-delete the collection from the DB
func deleteCollectionByUUID(uuid string) error {
	return database.ServerDatabase.Delete(&GlobusCollection{}, "uuid = ?", uuid).Error
}
