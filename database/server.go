package database

import (
	"embed"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var ServerDatabase *gorm.DB

//go:embed universal_migrations/*.sql
var embedMigrations embed.FS

type Counter struct {
	Key   string `gorm:"primaryKey"`
	Value int    `gorm:"not null;default:0"`
}

func InitServerDatabase() error {
	dbPath := param.Server_DbLocation.GetString()
	log.Debugln("Initializing server database: ", dbPath)

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
	if err := utils.MigrateDB(sqlDB, embedMigrations, "universal_migrations"); err != nil {
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
func CreateDowntime(downtime *server_structs.Downtime) error {
	if err := ServerDatabase.Create(downtime).Error; err != nil {
		return err
	}
	return nil
}

// Update an existing downtime entry by UUID
func UpdateDowntime(uuid string, updatedDowntime *server_structs.Downtime) error {
	if err := ServerDatabase.Model(&server_structs.Downtime{}).Where("uuid = ?", uuid).Updates(updatedDowntime).Error; err != nil {
		return err
	}
	return nil
}

// Delete a downtime entry by UUID (hard delete)
func DeleteDowntime(uuid string) error {
	return ServerDatabase.Delete(&server_structs.Downtime{}, "uuid = ?", uuid).Error
}

// Retrieve all downtime entries where EndTime is later than the current UTC time.
func GetIncompleteDowntimes(source string) ([]server_structs.Downtime, error) {
	var downtimes []server_structs.Downtime
	currentTime := time.Now().UTC().UnixMilli()

	query := ServerDatabase.Where("end_time > ? OR end_time = ?", currentTime, server_structs.IndefiniteEndTime)

	// If a source is provided, append it to the existing query.
	if source != "" {
		query = query.Where("source = ?", source)
	}

	err := query.Find(&downtimes).Error
	if err != nil {
		return nil, err
	}

	return downtimes, nil
}

// Retrieve all downtime entries
func GetAllDowntimes(source string) ([]server_structs.Downtime, error) {
	var downtimes []server_structs.Downtime

	// Begin a new query on the ServerDatabase
	query := ServerDatabase

	// If a non-empty source is provided, add the source condition
	if source != "" {
		query = query.Where("source = ?", source)
	}

	// Execute the query
	err := query.Find(&downtimes).Error
	if err != nil {
		return nil, err
	}

	return downtimes, nil
}

// Retrieve a downtime entry by UUID
func GetDowntimeByUUID(uuid string) (*server_structs.Downtime, error) {
	var downtime server_structs.Downtime
	err := ServerDatabase.First(&downtime, "uuid = ?", uuid).Error
	if err != nil {
		return nil, err
	}
	return &downtime, nil
}

func ShutdownDB() error {
	if ServerDatabase == nil {
		return nil
	}
	sqldb, err := ServerDatabase.DB()
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
