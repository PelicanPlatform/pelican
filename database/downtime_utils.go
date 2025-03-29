package database

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/server_structs"
)

// Test helper functions for Downtime
func SetupMockDowntimeDB(t *testing.T) {
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock downtime DB")
	err = ServerDatabase.AutoMigrate(&server_structs.Downtime{})
	require.NoError(t, err, "Failed to migrate DB for Downtime table")
}

func TeardownMockDowntimeDB(t *testing.T) {
	err := ServerDatabase.Migrator().DropTable(&server_structs.Downtime{})
	require.NoError(t, err, "Error tearing down downtime DB")
}

func InsertMockDowntime(d server_structs.Downtime) error {
	return ServerDatabase.Create(&d).Error
}
