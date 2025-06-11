package database

import (
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestCreateDowntime(t *testing.T) {
	config.ResetConfig()
	SetupMockDowntimeDB(t)
	t.Cleanup(func() {
		TeardownMockDowntimeDB(t)
		config.ResetConfig()
	})

	t.Run("create-downtime-success", func(t *testing.T) {
		mockDowntime := server_structs.Downtime{
			UUID:        uuid.NewString(),
			CreatedBy:   "test_user",
			Class:       "SCHEDULED",
			Description: "Routine maintenance",
			Severity:    "Outage (completely inaccessible)",
			StartTime:   time.Now().UnixMilli(),
			EndTime:     time.Now().Add(1 * time.Hour).UnixMilli(),
		}
		err := CreateDowntime(&mockDowntime)
		require.NoError(t, err)

		var retrieved server_structs.Downtime
		err = ServerDatabase.First(&retrieved, "uuid = ?", mockDowntime.UUID).Error
		require.NoError(t, err)
		assert.Equal(t, mockDowntime.UUID, retrieved.UUID)
		assert.Equal(t, mockDowntime.Description, retrieved.Description)
	})
}

func TestUpdateDowntime(t *testing.T) {
	config.ResetConfig()
	SetupMockDowntimeDB(t)
	t.Cleanup(func() {
		TeardownMockDowntimeDB(t)
		config.ResetConfig()
	})

	mockDowntime := server_structs.Downtime{
		UUID:        uuid.NewString(),
		CreatedBy:   "test_user",
		Class:       "UNSCHEDULED",
		Description: "Unexpected outage",
		Severity:    "Severe (most services down)",
		StartTime:   time.Now().UnixMilli(),
		EndTime:     time.Now().Add(2 * time.Hour).UnixMilli(),
	}
	err := InsertMockDowntime(mockDowntime)
	require.NoError(t, err)

	t.Run("update-existing-downtime", func(t *testing.T) {
		updatedFields := server_structs.Downtime{
			Description: "Planned upgrade",
			Severity:    "Intermittent Outage (may be up for some of the time)",
		}
		err := UpdateDowntime(mockDowntime.UUID, &updatedFields)
		require.NoError(t, err)

		var retrieved server_structs.Downtime
		err = ServerDatabase.First(&retrieved, "uuid = ?", mockDowntime.UUID).Error
		require.NoError(t, err)
		assert.Equal(t, "Planned upgrade", retrieved.Description)
		assert.Equal(t, server_structs.IntermittentOutage, retrieved.Severity)
	})
}

func TestGetIncompleteDowntimes(t *testing.T) {
	config.ResetConfig()
	SetupMockDowntimeDB(t)
	t.Cleanup(func() {
		TeardownMockDowntimeDB(t)
		config.ResetConfig()
	})

	currentTime := time.Now().UTC().UnixMilli()
	activeDowntime := server_structs.Downtime{
		UUID:        uuid.NewString(),
		CreatedBy:   "admin",
		Class:       "SCHEDULED",
		Description: "Active issue",
		Severity:    "No Significant Outage Expected (you shouldn't notice)",
		StartTime:   currentTime - 3600000, // Started an hour ago
		EndTime:     currentTime + 3600000, // Ends in an hour
	}
	pastDowntime := server_structs.Downtime{
		UUID:        uuid.NewString(),
		CreatedBy:   "admin",
		Class:       "UNSCHEDULED",
		Description: "Resolved issue",
		Severity:    "No Significant Outage Expected (you shouldn't notice)",
		StartTime:   currentTime - 7200000, // Started two hours ago
		EndTime:     currentTime - 3600000, // Ended an hour ago
	}

	err := InsertMockDowntime(activeDowntime)
	require.NoError(t, err)
	err = InsertMockDowntime(pastDowntime)
	require.NoError(t, err)

	t.Run("fetch-active-downtimes", func(t *testing.T) {
		activeEntries, err := GetIncompleteDowntimes("")
		require.NoError(t, err)
		assert.Len(t, activeEntries, 1)
		assert.Equal(t, activeDowntime.UUID, activeEntries[0].UUID)
	})

	t.Run("fetch-specific-downtime-by-uuid", func(t *testing.T) {
		get, err := GetDowntimeByUUID(activeDowntime.UUID)
		require.NoError(t, err)
		assert.Equal(t, activeDowntime.UUID, get.UUID)
	})
}

func TestDeleteDowntime(t *testing.T) {
	config.ResetConfig()
	SetupMockDowntimeDB(t)
	t.Cleanup(func() {
		TeardownMockDowntimeDB(t)
		config.ResetConfig()
	})

	mockDowntime := server_structs.Downtime{
		UUID:        uuid.NewString(),
		CreatedBy:   "test_user",
		Class:       "SCHEDULED",
		Description: "Temporary downtime",
		Severity:    "No Significant Outage Expected (you shouldn't notice)",
		StartTime:   time.Now().UnixMilli(),
		EndTime:     time.Now().Add(30 * time.Minute).UnixMilli(),
	}
	err := InsertMockDowntime(mockDowntime)
	require.NoError(t, err)

	t.Run("delete-existing-downtime", func(t *testing.T) {
		err := DeleteDowntime(mockDowntime.UUID)
		require.NoError(t, err)

		var retrieved server_structs.Downtime
		err = ServerDatabase.First(&retrieved, "uuid = ?", mockDowntime.UUID).Error
		assert.Error(t, err) // Expect record not found
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
}

// Tests for server_name table

func SetupMockServiceNameDB(t *testing.T) {
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "opening in-memory sqlite DB")
	ServerDatabase = mockDB
	err = ServerDatabase.AutoMigrate(&server_structs.ServiceName{})
	require.NoError(t, err, "migrating ServiceName schema")
}

func TeardownMockServiceNameDB(t *testing.T) {
	err := ServerDatabase.Migrator().DropTable(&server_structs.ServiceName{})
	require.NoError(t, err, "dropping ServiceName table")
}

func TestUpsertServiceName(t *testing.T) {
	config.ResetConfig()
	SetupMockServiceNameDB(t)
	t.Cleanup(func() {
		TeardownMockServiceNameDB(t)
		config.ResetConfig()
	})

	const name1 = "server-one"
	origType := server_structs.NewServerType()
	origType.SetString("origin")
	cacheType := server_structs.NewServerType()
	cacheType.SetString("cache")

	t.Run("insert-when-empty", func(t *testing.T) {
		typ := server_structs.NewServerType()
		typ.SetString("origin")
		err := UpsertServiceName(name1, typ)
		require.NoError(t, err)

		var got server_structs.ServiceName
		err = ServerDatabase.First(&got, "name = ?", name1).Error
		require.NoError(t, err)

		assert.Equal(t, name1, got.Name)
		assert.Equal(t, strings.ToLower(typ.String()), got.Type)
		assert.WithinDuration(t, time.Now().UTC(), got.CreatedAt, time.Second)
		assert.WithinDuration(t, time.Now().UTC(), got.UpdatedAt, time.Second)
	})

	t.Run("update-existing-record", func(t *testing.T) {
		// seed initial
		err := UpsertServiceName(name1, origType)
		require.NoError(t, err)

		// capture original timestamps & ID
		var original server_structs.ServiceName
		require.NoError(t,
			ServerDatabase.First(&original, "name = ?", name1).Error,
		)

		// Upsert with same name
		err = UpsertServiceName(name1, origType)
		require.NoError(t, err)

		var updated server_structs.ServiceName
		require.NoError(t,
			ServerDatabase.First(&updated, "name = ?", name1).Error,
		)

		assert.Equal(t, original.ID, updated.ID, "ID should be unchanged")
		assert.Equal(t, original.CreatedAt.UnixNano(), updated.CreatedAt.UnixNano(),
			"CreatedAt should be unchanged")
		assert.True(t, updated.UpdatedAt.After(original.UpdatedAt),
			"UpdatedAt should be newer")
		assert.Equal(t, strings.ToLower(origType.String()), updated.Type, "Type should not be updated")
	})

	t.Run("insert-second-record-when-name-differs", func(t *testing.T) {
		err := UpsertServiceName(name1, origType)
		require.NoError(t, err)
		err = UpsertServiceName("server-two", cacheType)
		require.NoError(t, err)

		var count int64
		require.NoError(t,
			ServerDatabase.Model(&server_structs.ServiceName{}).Count(&count).Error,
		)
		assert.Equal(t, int64(2), count, "should have two distinct rows")
	})
}

func TestGetServiceName(t *testing.T) {
	config.ResetConfig()
	SetupMockServiceNameDB(t)
	t.Cleanup(func() {
		TeardownMockServiceNameDB(t)
		config.ResetConfig()
	})

	t.Run("empty-table", func(t *testing.T) {
		_, err := GetServiceName()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
	})

	t.Run("returns-latest-by-updated_at", func(t *testing.T) {
		now := time.Now().UTC()
		old := server_structs.ServiceName{
			ID:        uuid.NewString(),
			Name:      "old-server",
			Type:      "cache",
			CreatedAt: now.Add(-2 * time.Hour),
			UpdatedAt: now.Add(-2 * time.Hour),
		}
		recent := server_structs.ServiceName{
			ID:        uuid.NewString(),
			Name:      "new-server",
			Type:      "origin",
			CreatedAt: now.Add(-1 * time.Hour),
			UpdatedAt: now.Add(-1 * time.Hour),
		}
		require.NoError(t, ServerDatabase.Create(&old).Error)
		require.NoError(t, ServerDatabase.Create(&recent).Error)

		got, err := GetServiceName()
		require.NoError(t, err)
		assert.Equal(t, "new-server", got)
	})
}
