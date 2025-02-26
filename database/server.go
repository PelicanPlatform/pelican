package database

import (
	"embed"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var ServerDatabase *gorm.DB

//go:embed migrations/*.sql
var embedMigrations embed.FS

type Counter struct {
	Key   string `gorm:"primaryKey"`
	Value int    `gorm:"not null;default:0"`
}

func InitServerDatabase(serverType server_structs.ServerType) error {
	if serverType != server_structs.OriginType && serverType != server_structs.CacheType {
		return errors.New("invalid server type")
	}
	var dbPath string
	if serverType == server_structs.OriginType {
		dbPath = param.Origin_DbLocation.GetString()
	} else {
		dbPath = param.Cache_DbLocation.GetString()
	}

	tdb, err := utils.InitSQLiteDB(dbPath)
	if err != nil {
		return err
	}
	ServerDatabase = tdb

	sqlDB, err := ServerDatabase.DB()
	if err != nil {
		return err
	}

	// run migrations
	if err := utils.MigrateDB(sqlDB, embedMigrations); err != nil {
		return err
	}

	return nil
}

func CreateCounter(key string, value int) error {
	counter := Counter{
		Key:   key,
		Value: value,
	}
	return ServerDatabase.Create(&counter).Error
}

func CreateOrUpdateCounter(key string, value int) error {
	counter := Counter{
		Key:   key,
		Value: value,
	}
	return ServerDatabase.Save(&counter).Error
}

// CRUD operations for downtimes table
// Create a new downtime entry
func createDowntime(downtime *server_structs.Downtime) error {
	if err := ServerDatabase.Create(downtime).Error; err != nil {
		return err
	}
	return nil
}

// Update an existing downtime entry by UUID
func updateDowntime(uuid string, updatedDowntime *server_structs.Downtime) error {
	if err := ServerDatabase.Model(&server_structs.Downtime{}).Where("uuid = ?", uuid).Updates(updatedDowntime).Error; err != nil {
		return err
	}
	return nil
}

// Delete a downtime entry by UUID (hard delete)
func deleteDowntime(uuid string) error {
	return ServerDatabase.Delete(&server_structs.Downtime{}, "uuid = ?", uuid).Error
}

// Retrieve all downtime entries where EndTime is later than the current UTC time.
func GetActiveDowntimes() ([]server_structs.Downtime, error) {
	var downtimes []server_structs.Downtime
	currentTime := time.Now().UTC().UnixMilli()

	err := ServerDatabase.Where("end_time > ?", currentTime).Find(&downtimes).Error
	if err != nil {
		return nil, err
	}

	return downtimes, nil
}

// Retrieve all downtime entries
func getAllDowntimes() ([]server_structs.Downtime, error) {
	var downtimes []server_structs.Downtime

	err := ServerDatabase.Find(&downtimes).Error
	if err != nil {
		return nil, err
	}

	return downtimes, nil
}

// Retrieve a downtime entry by UUID
func getDowntimeByUUID(uuid string) (*server_structs.Downtime, error) {
	var downtime server_structs.Downtime
	err := ServerDatabase.First(&downtime, "uuid = ?", uuid).Error
	if err != nil {
		return nil, err
	}
	return &downtime, nil
}
