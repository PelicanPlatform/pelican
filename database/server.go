package database

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var ServerDatabase *gorm.DB

//go:embed universal_migrations/*.sql
var embedUniversalMigrations embed.FS

//go:embed registry_migrations/*.sql
var embedRegistryMigrations embed.FS

type Counter struct {
	Key   string `gorm:"primaryKey"`
	Value int    `gorm:"not null;default:0"`
}

// Initialize a centralized server database and run universal and server-type-specific migrations
func InitServerDatabase(serverType server_structs.ServerType) error {

	dbPath := param.Server_DbLocation.GetString()
	log.Debugln("Initializing server database: ", dbPath)

	tdb, err := utils.InitSQLiteDB(dbPath)
	if err != nil {
		return err
	}
	ServerDatabase = tdb

	// Enable foreign key constraints for SQLite
	if err := ServerDatabase.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		return errors.Wrap(err, "failed to enable foreign key constraints")
	}

	sqlDB, err := ServerDatabase.DB()
	if err != nil {
		return err
	}

	// Always run universal migrations first
	if err := utils.MigrateDB(sqlDB, embedUniversalMigrations, "universal_migrations"); err != nil {
		return err
	}

	// Apply server-type-specific migrations
	if err := runServerTypeMigrations(sqlDB, serverType); err != nil {
		return errors.Wrapf(err, "failed to run migrations for server type %s", serverType.String())
	}

	// Data cleanup - remove stale entries in the `servers` and `services` tables
	// They are caused by the damaged foreign key constraint in `services` table and we didn't update webUI to use server deletion API in time.
	// See https://opensciencegrid.atlassian.net/browse/OPS-438
	if serverType == server_structs.RegistryType {
		if err := cleanupStaleServerEntries(); err != nil {
			return errors.Wrapf(err, "failed to cleanup stale server entries")
		}
	}

	// Data migration - this block could be removed after the Registry upgrade is complete
	if serverType == server_structs.RegistryType {
		// Run data migration from old registry.sqlite to new pelican.sqlite
		if err := migrateFromLegacyRegistryDB(); err != nil {
			log.Warnf("Legacy registry database data migration failed: %v", err)
		}

		// Migrate existing namespace data to server tables
		if err := populateNewServerTables(); err != nil {
			log.Errorf("Failed to populate the data for the new server tables: %v", err)
			return errors.Wrap(err, "server data migration failed")
		}
	}

	return nil
}

func runServerTypeMigrations(sqlDB *sql.DB, serverType server_structs.ServerType) error {
	switch serverType {
	case server_structs.RegistryType:
		return utils.MigrateServerSpecificDB(sqlDB, embedRegistryMigrations, "registry_migrations", "registry")
	default:
		log.Debugf("No specific migrations for server type: %s", serverType.String())
	}

	return nil
}

func cleanupStaleServerEntries() error {
	// Identify stale servers via missing/invalid registrations and remove their services and server rows
	return ServerDatabase.Transaction(func(tx *gorm.DB) error {
		// Query all stale server IDs
		var staleServerIDs []string
		rawQuery := `
			SELECT DISTINCT servers.id
			FROM services
			LEFT JOIN registrations ON services.registration_id = registrations.id
			LEFT JOIN servers ON servers.id = services.server_id
			WHERE registrations.pubkey IS NULL`

		if err := tx.Raw(rawQuery).Scan(&staleServerIDs).Error; err != nil {
			return errors.Wrap(err, "failed to query stale server IDs")
		}

		if len(staleServerIDs) == 0 {
			return nil
		}

		// Delete services first to be robust even if old rows lacked proper FKs
		if err := tx.Where("server_id IN ?", staleServerIDs).Delete(&server_structs.Service{}).Error; err != nil {
			return errors.Wrap(err, "failed to delete stale services")
		}

		// Delete servers
		if err := tx.Where("id IN ?", staleServerIDs).Delete(&server_structs.Server{}).Error; err != nil {
			return errors.Wrap(err, "failed to delete stale servers")
		}

		log.WithField("count", len(staleServerIDs)).Info("Cleaned up stale server entries")
		return nil
	})
}

// The following snippet should be removed in the release after the Registry upgrade is complete
// ///////////////////////////////Start//////////////////////////////////////////////
// migrateFromLegacyRegistryDB copies data from old registry.sqlite to new pelican.sqlite
func migrateFromLegacyRegistryDB() error {
	// Get the old registry database path
	legacyDbPath := param.Registry_DbLocation.GetString()
	if legacyDbPath == "" {
		log.Debug("Registry_DbLocation parameter is not set, skipping migration")
		return nil
	}

	// Check if the legacy database file exists
	if !fileExists(legacyDbPath) {
		log.Debugf("Legacy registry database not found at %s, skipping migration", legacyDbPath)
		return nil
	}

	// Get the current server database path
	serverDbPath := param.Server_DbLocation.GetString()
	if serverDbPath == "" {
		return errors.New("Server_DbLocation parameter is not set")
	}

	// Check if we've already migrated (if registrations table has data)
	var registrationCount int64
	if err := ServerDatabase.Model(&server_structs.Registration{}).Count(&registrationCount).Error; err != nil {
		return errors.Wrap(err, "failed to check existing registration data")
	}

	if registrationCount > 0 {
		log.Info("Registration data already exists, skipping legacy database migration")
		return nil
	}

	log.Infof("Migrating data from legacy registry database: %s -> %s", legacyDbPath, serverDbPath)

	// Get the underlying SQL database connection
	sqlDB, err := ServerDatabase.DB()
	if err != nil {
		return errors.Wrap(err, "failed to get SQL database connection")
	}

	// Attach the legacy database
	attachSQL := fmt.Sprintf("ATTACH DATABASE '%s' AS legacy_registry", legacyDbPath)
	if _, err := sqlDB.Exec(attachSQL); err != nil {
		return errors.Wrapf(err, "failed to attach legacy database %s", legacyDbPath)
	}
	defer func() {
		if _, err := sqlDB.Exec("DETACH DATABASE legacy_registry"); err != nil {
			log.Errorf("Failed to detach legacy database: %v", err)
		}
	}()

	// Copy the data from the namespace table into the registrations table
	copyNamespaceSQL := `
		INSERT OR IGNORE INTO registrations (id, prefix, pubkey, identity, admin_metadata, custom_fields)
		SELECT id, prefix, pubkey, identity, admin_metadata, custom_fields
		FROM legacy_registry.namespace
	`
	result, err := sqlDB.Exec(copyNamespaceSQL)
	if err != nil {
		return errors.Wrap(err, "failed to copy namespace data")
	}
	namespaceRows, _ := result.RowsAffected()

	// Copy topology data
	copyTopologySQL := `
		INSERT OR IGNORE INTO topology (id, prefix)
		SELECT id, prefix
		FROM legacy_registry.topology
	`
	result, err = sqlDB.Exec(copyTopologySQL)
	if err != nil {
		return errors.Wrap(err, "failed to copy topology data")
	}
	topologyRows, _ := result.RowsAffected()

	log.Infof("Successfully migrated %d registration records and %d topology records from legacy database",
		namespaceRows, topologyRows)

	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}

// Populate new tables with the newly migrated data
func populateNewServerTables() error {
	// Find all server namespaces that haven't been migrated yet
	var namespaces []server_structs.Registration
	err := ServerDatabase.Where("prefix LIKE ? OR prefix LIKE ?", "/origins/%", "/caches/%").Find(&namespaces).Error
	if err != nil {
		return errors.Wrap(err, "failed to fetch server namespaces")
	}

	// Check if any of these namespaces already have server entries
	migratedCount := 0
	for _, ns := range namespaces {
		var serviceCount int64
		if err := ServerDatabase.Model(&server_structs.Service{}).Where("registration_id = ?", ns.ID).Count(&serviceCount).Error; err != nil {
			return errors.Wrapf(err, "failed to check if namespace %d is already migrated", ns.ID)
		}
		if serviceCount > 0 {
			migratedCount++
		}
	}

	if migratedCount == len(namespaces) && len(namespaces) > 0 {
		log.Info("All server namespaces have already been migrated")
		return nil
	}

	if len(namespaces) == 0 {
		log.Debug("No server namespaces found to migrate")
		return nil
	}

	log.Infof("Found %d server namespaces, %d already migrated, migrating %d",
		len(namespaces), migratedCount, len(namespaces)-migratedCount)

	// Migrate remaining namespaces
	return ServerDatabase.Transaction(func(tx *gorm.DB) error {
		for _, ns := range namespaces {
			// Skip if already migrated
			var serviceCount int64
			if err := tx.Model(&server_structs.Service{}).Where("registration_id = ?", ns.ID).Count(&serviceCount).Error; err != nil {
				return err
			}
			if serviceCount > 0 {
				continue // Already migrated
			}

			if ns.AdminMetadata.Status != server_structs.RegApproved {
				continue // Skip if not approved
			}

			// Check if site name exists. If not, auto create it based on the prefix.
			if ns.AdminMetadata.SiteName == "" {
				// Strip the leading "/origins/" or "/caches/" from ns.Prefix
				remaining := ""
				if strings.HasPrefix(ns.Prefix, server_structs.OriginPrefix.String()) {
					remaining = strings.TrimPrefix(ns.Prefix, server_structs.OriginPrefix.String())
				} else if strings.HasPrefix(ns.Prefix, server_structs.CachePrefix.String()) {
					remaining = strings.TrimPrefix(ns.Prefix, server_structs.CachePrefix.String())
				}

				// Check if the remaining string contains ".", if so, it is a URL
				if strings.Contains(remaining, ".") {
					// It's a URL, keep only the hostname (split by ":" and keep the first part)
					colonIndex := strings.Index(remaining, ":")
					if colonIndex != -1 {
						ns.AdminMetadata.SiteName = remaining[:colonIndex]
					} else {
						ns.AdminMetadata.SiteName = remaining
					}
				} else {
					// Not a URL, assign the remaining string to name
					ns.AdminMetadata.SiteName = remaining
				}

				log.Warnf("Namespace %s has no site name, falling back to name %s", ns.Prefix, ns.AdminMetadata.SiteName)
			}

			// Determine server type
			isOrigin := strings.HasPrefix(ns.Prefix, server_structs.OriginPrefix.String())
			isCache := strings.HasPrefix(ns.Prefix, server_structs.CachePrefix.String())

			// Check if a server with this name already exists
			var server server_structs.Server
			err := tx.Where("name = ?", ns.AdminMetadata.SiteName).First(&server).Error
			if err == gorm.ErrRecordNotFound {
				// No existing server, create a new one
				server = server_structs.Server{
					Name:     ns.AdminMetadata.SiteName,
					IsOrigin: isOrigin,
					IsCache:  isCache,
				}
				if err := tx.Create(&server).Error; err != nil {
					return errors.Wrapf(err, "failed to create server for namespace %d", ns.ID)
				}
			} else if err != nil {
				return errors.Wrapf(err, "failed to check for existing server with name %s", ns.AdminMetadata.SiteName)
			} else {
				// Server exists, update its services (a server can be both an origin and a cache)
				if isOrigin {
					server.IsOrigin = true
				}
				if isCache {
					server.IsCache = true
				}

				if err := tx.Save(&server).Error; err != nil {
					return errors.Wrapf(err, "failed to update server services for %s", ns.AdminMetadata.SiteName)
				}
			}

			// Create service mapping
			service := server_structs.Service{
				ServerID:       server.ID,
				RegistrationID: ns.ID,
			}
			if err := tx.Create(&service).Error; err != nil {
				return errors.Wrapf(err, "failed to create service for registration %d", ns.ID)
			}

			log.Infof("Migrated registration %d (%s) -> server %s", ns.ID, ns.Prefix, server.ID)
		}
		return nil
	})
}

/////////////////////////////////End//////////////////////////////////////////////

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

// Create or update a record for the given serverName
// 1) If no such row exists, it inserts a new one.
// 2) If a row with that name exists, it updates updated_at (and type).
func UpsertServiceName(serverName string, typ server_structs.ServerType) error {
	now := time.Now()

	// look for existing
	var entry server_structs.ServiceName
	err := ServerDatabase.Where("name = ?", serverName).First(&entry).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// no existing row → insert
		entry = server_structs.ServiceName{
			ID:        uuid.NewString(),
			Name:      serverName,
			Type:      strings.ToLower(typ.String()),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return ServerDatabase.Create(&entry).Error
	}
	if err != nil {
		return err
	}

	// found → update timestamp
	entry.UpdatedAt = now
	entry.Type = strings.ToLower(typ.String())
	return ServerDatabase.Save(&entry).Error
}

// Retrieve the server name in use - lookup the entry whose UpdatedAt is the most recent
func GetServiceName() (string, error) {
	var entry server_structs.ServiceName
	// There is an index in the database to speed up this query
	err := ServerDatabase.
		Where("deleted_at IS NULL").
		Order("updated_at DESC").
		First(&entry).Error
	if err != nil {
		// err will be gorm.ErrRecordNotFound if there's no matching row
		return "", err
	}
	return entry.Name, nil
}

// Retrieve all service names from most recent to oldest
func GetServiceNameHistory() ([]server_structs.ServiceName, error) {
	var entries []server_structs.ServiceName

	err := ServerDatabase.
		Where("deleted_at IS NULL").
		Order("updated_at DESC").
		Find(&entries).Error

	if err != nil {
		return nil, err
	}

	return entries, nil
}

// Mark a service name as deleted without actually removing it from the database
func SoftDeleteServiceName(id string) error {
	now := time.Now()

	result := ServerDatabase.Model(&server_structs.ServiceName{}).
		Where("id = ? AND deleted_at IS NULL", id).
		Update("deleted_at", now)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
