package database

import (
	"embed"
	"fmt"

	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
)

var ServerDatabase *gorm.DB

//go:embed server_migrations/*.sql
var embedMigrations embed.FS

type Counter struct {
	Key   string `gorm:"primaryKey"`
	Value int    `gorm:"not null;default:0"`
}

func InitServerDatabase() error {
	dbPath := param.Server_DbLocation.GetString()
	fmt.Println("Initializing server database: ", dbPath)

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
	if err := utils.MigrateDB(sqlDB, embedMigrations, "server_migrations"); err != nil {
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
