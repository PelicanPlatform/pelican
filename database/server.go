package database

import (
	"embed"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

var ServerDatabase *gorm.DB

//go:embed migrations/*.sql
var embedMigrations embed.FS

type Counter struct {
	Key   string `gorm:"primaryKey"`
	Value int    `gorm:"not null;default:0"`
}

func InitServerDatabase() error {
	dbPath := param.Server_DbLocation.GetString()

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

// CreateOrIncrementCounter creates a new counter with the given key and increment value,
// or if the counter already exists, increments its value by 'inc'.
func CreateOrIncrementCounter(key string, inc int) error {
	return ServerDatabase.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "key"}}, // use key as the conflict target
		DoUpdates: clause.Assignments(map[string]interface{}{
			"value": gorm.Expr("value + ?", inc),
		}),
	}).Create(&Counter{
		Key:   key,
		Value: inc, // If the counter doesn't exist, its initial value is set to 'inc'
	}).Error
}
