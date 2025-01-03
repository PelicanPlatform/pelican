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
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

type GrafanaApiKey struct {
	ID          string `gorm:"primaryKey;column:id;type:text;not null"`
	Name        string `gorm:"column:name;type:text"`
	HashedValue string `gorm:"column:hashed_value;type:text;not null"`
	Scopes      string `gorm:"column:scopes;type:text"`
	ExpiresAt   time.Time
	CreatedAt   time.Time
	CreatedBy   string `gorm:"column:created_by;type:text"`
}

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

var verifiedKeysCache *ttlcache.Cache[string, GrafanaApiKey] = ttlcache.New[string, GrafanaApiKey]()

// Initialize the Director's sqlite database, which is used to persist information about server downtimes
func InitializeDB() error {
	go verifiedKeysCache.Start()
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

func generateSecret(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateTokenID(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])[:5]
}

func createGrafanaApiKey(name, createdBy, scopes string) (string, error) {
	expiresAt := time.Now().Add(time.Hour * 24 * 30) // 30 days
	for {
		secret, err := generateSecret(32)
		if err != nil {
			return "", errors.Wrap(err, "failed to generate a secret")
		}

		id := generateTokenID(secret)

		hashedValue, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return "", errors.Wrap(err, "failed to hash the secret")
		}

		apiKey := GrafanaApiKey{
			ID:          id,
			Name:        name,
			HashedValue: string(hashedValue),
			Scopes:      scopes,
			ExpiresAt:   expiresAt,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
		}
		result := db.Create(apiKey)
		if result.Error != nil {
			isConstraintError := result.Error.Error() == "UNIQUE constraint failed: tokens.id"
			if !isConstraintError {
				return "", errors.Wrap(result.Error, "failed to create a new Grafana API key")
			}
			// If the ID is already taken, try again
			continue
		}
		return fmt.Sprintf("%s.%s", id, secret), nil
	}
}

// REMOVE THIS
//
//nolint:golint,unused
func verifyGrafanaApiKey(apiKey string) (bool, error) {
	parts := strings.Split(apiKey, ".")
	if len(parts) != 2 {
		return false, errors.New("invalid API key format")
	}
	id := parts[0]
	secret := parts[1]

	item := verifiedKeysCache.Get(id)
	if item != nil {
		cachedToken := item.Value()
		beforeExpiration := time.Now().Before(cachedToken.ExpiresAt)
		matches := bcrypt.CompareHashAndPassword([]byte(cachedToken.HashedValue), []byte(secret)) == nil
		if beforeExpiration && matches {
			return true, nil
		}
	}

	var token GrafanaApiKey
	result := db.First(&token, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil // token not found
		}
		return false, errors.Wrap(result.Error, "failed to retrieve the Grafana API key")
	}

	if time.Now().After(token.ExpiresAt) {
		return false, nil
	}

	err := bcrypt.CompareHashAndPassword([]byte(token.HashedValue), []byte(secret))
	if err != nil {
		return false, nil
	}

	verifiedKeysCache.Set(id, token, ttlcache.DefaultTTL)
	return true, nil
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
