package database

import (
	"embed"
	"sync"

	"github.com/pkg/errors"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

var ServerDatabase *gorm.DB

//go:embed migrations/server/*.sql
var embedMigrations embed.FS

type Counter struct {
	Key   string `gorm:"primaryKey"`
	Value int    `gorm:"not null;default:0"`
}

func init() {
	initDB := sync.OnceFunc(func() {
		dbPath := param.Server_DbLocation.GetString()
		tdb, err := server_utils.InitSQLiteDB(dbPath)
		if err != nil {
			panic(err)
		}

		ServerDatabase = tdb

		sqldb, err := ServerDatabase.DB()

		if err != nil {
			panic(errors.Wrapf(err, "Failed to get sql.DB from gorm DB: %s", dbPath))
		}

		// Run database migrations
		if err := server_utils.MigrateDB(sqldb, embedMigrations); err != nil {
			panic(err)
		}
	})
	initDB()
}

func CreateCounter(key string, value int) error {
	counter := Counter{
		Key:   key,
		Value: value,
	}
	return ServerDatabase.Create(&counter).Error
}
