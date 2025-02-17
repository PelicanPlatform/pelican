package database

import (
	"embed"
	"errors"

	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
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

	tdb, err := server_utils.InitSQLiteDB(dbPath)
	if err != nil {
		return err
	}
	ServerDatabase = tdb

	sqlDB, err := ServerDatabase.DB()
	if err != nil {
		return err
	}

	// run migrations
	if err := server_utils.MigrateDB(sqlDB, embedMigrations); err != nil {
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
