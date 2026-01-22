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

package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

type NamespaceWOPubkey struct {
	ID            int                          `json:"id"`
	Prefix        string                       `json:"prefix"`
	Pubkey        string                       `json:"-"` // Don't include pubkey in this case
	Identity      string                       `json:"identity"`
	AdminMetadata server_structs.AdminMetadata `json:"admin_metadata"`
}

type Topology struct {
	ID     int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Prefix string `json:"prefix" gorm:"unique;not null"`
}

type prefixType string // Type of a prefix

const (
	prefixForOrigin    prefixType = "origin"    // origin servers
	prefixForCache     prefixType = "cache"     // cache servers
	prefixForNamespace prefixType = "namespace" // data namespace
)

/*
The database was declared as a global variable in the database package
*/

func (st prefixType) String() string {
	return string(st)
}

func (Topology) TableName() string {
	return "topology"
}

func GetTopoPrefixString(topoNss []Topology) (result string) {
	for i, topoNs := range topoNss {
		if i != len(topoNss)-1 {
			result += (topoNs.Prefix + ", ")
		} else {
			result += topoNs.Prefix
		}
	}
	return
}

// Check if a registration exists in the registrations table
func registrationExistsByPrefix(prefix string) (bool, error) {
	var count int64

	err := database.ServerDatabase.Model(&server_structs.Registration{}).Where("prefix = ?", prefix).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Check if a namespace exists in the Topology table
func topologyNamespaceExistsByPrefix(prefix string) (bool, error) {
	var count int64

	err := database.ServerDatabase.Model(&Topology{}).Where("prefix = ?", prefix).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func namespaceSupSubChecks(prefix string) (superspaces []string, subspaces []string, inTopo bool, topoNss []Topology, err error) {
	// The very first thing we do is check if there's a match in topo. We simply flag it's in topology if so
	if config.GetPreferredPrefix() == config.OsdfPrefix {
		topoSuperSubQuery := `
		SELECT prefix FROM topology WHERE (? || '/') LIKE (prefix || '/%')
		UNION
		SELECT prefix FROM topology WHERE (prefix || '/') LIKE (? || '/%')
		`
		err = database.ServerDatabase.Raw(topoSuperSubQuery, prefix, prefix).Scan(&topoNss).Error
		if err != nil {
			return
		}

		if len(topoNss) > 0 {
			inTopo = true
		}
	}

	// Check if any registered namespaces already superspace the incoming namespace,
	// eg if /foo is already registered, this will be true for an incoming /foo/bar because
	// /foo is logically above /foo/bar (according to my logic, anyway)
	superspaceQuery := `SELECT prefix FROM registrations WHERE (?) LIKE (prefix || '/%')`
	err = database.ServerDatabase.Raw(superspaceQuery, prefix).Scan(&superspaces).Error
	if err != nil {
		return
	}

	// Check if any registered namespaces already subspace the incoming namespace,
	// eg if /foo/bar is already registered, this will be true for an incoming /foo because
	// /foo/bar is logically below /foo
	subspaceQuery := `SELECT prefix FROM registrations WHERE (prefix) LIKE (? || '/%')`
	err = database.ServerDatabase.Raw(subspaceQuery, prefix).Scan(&subspaces).Error
	if err != nil {
		return
	}

	return
}

func registrationExistsById(id int) (bool, error) {
	var registrations []server_structs.Registration
	result := database.ServerDatabase.Limit(1).Find(&registrations, id)
	if result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected > 0, nil
	}
}

func registrationBelongsToUserId(id int, userId string) (bool, error) {
	var result server_structs.Registration
	err := database.ServerDatabase.First(&result, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, errors.Errorf("registration with id = %d does not exists", id)
	} else if err != nil {
		return false, errors.Wrap(err, "error retrieving registration")
	}
	return result.AdminMetadata.UserID == userId, nil
}

func getRegistrationJwksById(id int) (jwk.Set, error) {
	var result server_structs.Registration
	err := database.ServerDatabase.Select("pubkey").Where("id = ?", id).Last(&result).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.Errorf("registration with id %d not found in database", id)
	} else if err != nil {
		return nil, errors.Wrap(err, "error retrieving pubkey")
	}

	set, err := jwk.ParseString(result.Pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse pubkey as a jwks")
	}

	return set, nil
}

func getRegistrationJwksByPrefix(prefix string) (jwk.Set, *server_structs.AdminMetadata, error) {
	// Note that this cannot retrieve public keys from topology as the topology table
	// doesn't contain that information.
	if prefix == "" {
		return nil, nil, errors.New("Invalid prefix. Prefix must not be empty")
	}
	var result server_structs.Registration
	err := database.ServerDatabase.Select("pubkey", "admin_metadata").Where("prefix = ?", prefix).Last(&result).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, errors.Errorf("registration with prefix %q not found in database", prefix)
	} else if err != nil {
		return nil, nil, errors.Wrap(err, "error retrieving pubkey")
	}

	set, err := jwk.ParseString(result.Pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse pubkey as a jwks")
	}

	return set, &result.AdminMetadata, nil
}

func getRegistrationStatusById(id int) (server_structs.RegistrationStatus, error) {
	if id < 1 {
		return "", errors.New("Invalid id. id must be a positive integer")
	}
	var result server_structs.Registration
	query := database.ServerDatabase.Select("admin_metadata").Where("id = ?", id).Last(&result)
	err := query.Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return server_structs.RegUnknown, errors.Errorf("registration with id %d not found in database", id)
	} else if err != nil {
		return server_structs.RegUnknown, errors.Wrap(err, "error retrieving pubkey")
	}
	if result.AdminMetadata.Status == "" {
		return server_structs.RegUnknown, nil
	}
	return result.AdminMetadata.Status, nil
}

// Helper to construct a ServerRegistration from a server and its services,
// filtering out services whose preloaded Registration is missing. Returns an
// error if, after filtering, there are no valid registrations remaining.
func buildServerRegistration(server server_structs.Server, services []server_structs.Service) (*server_structs.ServerRegistration, error) {
	// If server has no services, return a "service not found" error
	// See the definitions of server and service in the realm of Pelican
	if len(services) == 0 {
		return nil, errors.Errorf("no service found")
	}

	result := &server_structs.ServerRegistration{
		ID:        server.ID,
		Name:      server.Name,
		IsOrigin:  server.IsOrigin,
		IsCache:   server.IsCache,
		Note:      server.Note,
		CreatedAt: server.CreatedAt,
		UpdatedAt: server.UpdatedAt,
	}

	for _, service := range services {
		// Exclude services whose preloaded Registration is missing
		if service.Registration.ID != 0 && service.Registration.Prefix != "" {
			result.Registration = append(result.Registration, service.Registration)
		}
	}

	// Throw an error if no valid registrations for this server
	if len(result.Registration) == 0 {
		return nil, errors.Errorf("no service found for server with ID %s. This server is associated with a non-existent registration, which may have been deleted", server.ID)
	}

	return result, nil
}

// Retrieve the details of a server by server ID
// 1. Get the server from servers table
// 2. Iterate through the services table (preload registrations table), find every service registration associated with this server
// 3. [Safety net for foreign key constraint violation] Filter out services with missing registrations, and server with no services
func getServerByID(serverID string) (*server_structs.ServerRegistration, error) {
	var server server_structs.Server
	if err := database.ServerDatabase.Where("id = ?", serverID).First(&server).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Return empty server instead of error for non-existent records
			return &server_structs.ServerRegistration{}, nil
		}
		return nil, errors.Wrapf(err, "failed to get server by ID: %s", serverID)
	}

	var services []server_structs.Service
	if err := database.ServerDatabase.Where("server_id = ?", serverID).Preload("Registration").Find(&services).Error; err != nil {
		return nil, errors.Wrapf(err, "failed to get services for server ID: %s", serverID)
	}

	return buildServerRegistration(server, services)
}

// Retrieve the details of a server by its registration's ID
func getServerByRegistrationID(registrationID int) (*server_structs.ServerRegistration, error) {
	var service server_structs.Service
	if err := database.ServerDatabase.Where("registration_id = ?", registrationID).Preload("Server").Preload("Registration").First(&service).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Return empty server instead of error for non-existent records
			return &server_structs.ServerRegistration{}, nil
		}
		return nil, errors.Wrapf(err, "failed to get service for registration ID: %d", registrationID)
	}

	// Get all services for this server to get complete registration list
	var allServices []server_structs.Service
	if err := database.ServerDatabase.Where("server_id = ?", service.ServerID).Preload("Registration").Find(&allServices).Error; err != nil {
		return nil, errors.Wrapf(err, "failed to get all services for server ID: %s", service.ServerID)
	}

	result := &server_structs.ServerRegistration{
		ID:        service.Server.ID,
		Name:      service.Server.Name,
		IsOrigin:  service.Server.IsOrigin,
		IsCache:   service.Server.IsCache,
		Note:      service.Server.Note,
		CreatedAt: service.Server.CreatedAt,
		UpdatedAt: service.Server.UpdatedAt,
	}

	for _, svc := range allServices {
		result.Registration = append(result.Registration, svc.Registration)
	}

	return result, nil
}

// Retrieve the details of a server by server name
func getServerByName(serverName string) (*server_structs.ServerRegistration, error) {
	var server server_structs.Server
	// Use a silent session to suppress "record not found" log noise for this expected lookup
	if err := database.ServerDatabase.Session(&gorm.Session{
		Logger: logger.Default.LogMode(logger.Silent),
	}).Where("name = ?", serverName).First(&server).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, errors.Wrapf(err, "failed to get server by name: %s", serverName)
	}

	var services []server_structs.Service
	if err := database.ServerDatabase.Where("server_id = ?", server.ID).Preload("Registration").Find(&services).Error; err != nil {
		return nil, errors.Wrapf(err, "failed to get services for server name: %s", serverName)
	}
	return buildServerRegistration(server, services)
}

// Retrieve the details of a server by a registration prefix
func getServerByPrefix(prefix string) (*server_structs.ServerRegistration, error) {
	if prefix == "" {
		return nil, errors.New("invalid prefix. Prefix must not be empty")
	}

	// Find the registration by prefix
	registration, err := getRegistrationByPrefix(prefix)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get registration by prefix: %s", prefix)
	}

	// Reuse existing helper to assemble the server payload
	return getServerByRegistrationID(registration.ID)
}

// Get the complete info of all servers
func listServers() ([]server_structs.ServerRegistration, error) {
	var servers []server_structs.Server
	if err := database.ServerDatabase.Order("id ASC").Find(&servers).Error; err != nil {
		return nil, errors.Wrap(err, "failed to retrieve servers from the database")
	}

	var results []server_structs.ServerRegistration
	for _, server := range servers {
		var services []server_structs.Service
		if err := database.ServerDatabase.Where("server_id = ?", server.ID).Preload("Registration").Find(&services).Error; err != nil {
			return nil, errors.Wrapf(err, "failed to get services for server ID: %s", server.ID)
		}

		serverReg, err := buildServerRegistration(server, services)
		if err != nil || serverReg == nil {
			// Skip servers with no valid service registrations
			continue
		}
		results = append(results, *serverReg)
	}

	return results, nil
}

func getRegistrationById(id int) (*server_structs.Registration, error) {
	if id < 1 {
		return nil, errors.New("Invalid id. id must be a positive number")
	}
	ns := server_structs.Registration{}
	err := database.ServerDatabase.Last(&ns, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.Errorf("registration with id %d not found in database", id)
	} else if err != nil {
		return nil, errors.Wrap(err, "error retrieving pubkey")
	}

	// By default, JSON unmarshal will convert any generic number to float
	// and we only allow integer in custom fields, so we convert them back
	for key, val := range ns.CustomFields {
		switch v := val.(type) {
		case float64:
			ns.CustomFields[key] = int(v)
		case float32:
			ns.CustomFields[key] = int(v)
		}
	}
	return &ns, nil
}

// Get an entry from the registrations table based on the prefix
func getRegistrationByPrefix(prefix string) (*server_structs.Registration, error) {
	if prefix == "" {
		return nil, errors.New("invalid prefix. Prefix must not be empty")
	}
	ns := server_structs.Registration{}
	err := database.ServerDatabase.Where("prefix = ? ", prefix).Last(&ns).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.Errorf("registration with prefix %q not found in database", prefix)
	} else if err != nil {
		return nil, errors.Wrap(err, "error retrieving registration registration by its prefix")
	}

	// By default, JSON unmarshal will convert any generic number to float
	// and we only allow integer in custom fields, so we convert them back
	for key, val := range ns.CustomFields {
		switch v := val.(type) {
		case float64:
			ns.CustomFields[key] = int(v)
		case float32:
			ns.CustomFields[key] = int(v)
		}
	}
	return &ns, nil
}

// getAllowedPrefixesForCaches queries the database to create a map of cache
// hostnames to a list of prefixes that each cache is allowed to serve.
// If a cache hostname key is not present in the resultant map, it implies the
// default behavior where the cache is allowed to serve all prefixes. However,
// if the cache hostname key is present with an empty list of prefixes, it implies
// the cache is not allowed to serve any prefixes. It is explicitly NOT treated like "*".
func getAllowedPrefixesForCaches() (map[string][]string, error) {
	var registrations []server_structs.Registration

	err := database.ServerDatabase.Where("prefix LIKE ?", "/caches/%").Find(&registrations).Error
	if err != nil {
		return nil, err
	}

	allowedPrefixesForCachesMap := make(map[string][]string)

	for _, registration := range registrations {
		// Remove "/caches/" from the beginning of the Prefix
		cacheHostname := strings.TrimPrefix(registration.Prefix, "/caches/")

		allowedPrefixesRaw, exists := registration.CustomFields["AllowedPrefixes"]
		if !exists {
			continue // Skip if "AllowedPrefixes" key does not exist
		}

		allowedPrefixesInterface, ok := allowedPrefixesRaw.([]interface{})
		if !ok {
			continue
		}

		allowedPrefixes := make([]string, 0, len(allowedPrefixesInterface))
		for _, prefix := range allowedPrefixesInterface {
			strPrefix, ok := prefix.(string)
			if ok {
				allowedPrefixes = append(allowedPrefixes, strPrefix)
			}
		}

		if len(allowedPrefixes) == 1 && allowedPrefixes[0] == "*" {
			continue // Skip if the only value is "*"
		}

		allowedPrefixesForCachesMap[cacheHostname] = allowedPrefixes
	}

	return allowedPrefixesForCachesMap, nil
}

// Get a collection of registrations by filtering against various non-default registration fields
// excluding Registration.ID, Registration.Identity, Registration.Pubkey, and various dates
//
// For filterNs.AdminMetadata.Description and filterNs.AdminMetadata.SiteName,
// the string will be matched using `strings.Contains`. This is too mimic a SQL style `like` match.
// The rest of the AdminMetadata fields is matched by `==`
func getRegistrationsByFilter(filterNs server_structs.Registration, pType prefixType, legacy bool) ([]server_structs.Registration, error) {
	query := `SELECT id, prefix, pubkey, identity, admin_metadata FROM registrations WHERE 1=1 `
	if pType == prefixForCache {
		// Refer to the cache prefix name in cmd/cache_serve
		query += ` AND prefix LIKE '/caches/%'`
	} else if pType == prefixForOrigin {
		query += ` AND prefix LIKE '/origins/%'`
	} else if pType == prefixForNamespace {
		query += ` AND NOT prefix LIKE '/caches/%' AND NOT prefix LIKE '/origins/%'`
	} else if pType != "" {
		return nil, errors.New(fmt.Sprint("Can't get registration: unsupported server type: ", pType))
	}

	if filterNs.CustomFields != nil {
		return nil, errors.New("Unsupported operation: Can't filter against Custrom Registration field.")
	}
	if filterNs.ID != 0 {
		return nil, errors.New("Unsupported operation: Can't filter against ID field.")
	}
	if filterNs.Identity != "" {
		return nil, errors.New("Unsupported operation: Can't filter against Identity field.")
	}
	if filterNs.Pubkey != "" {
		return nil, errors.New("Unsupported operation: Can't filter against Pubkey field.")
	}
	if filterNs.Prefix != "" {
		query += fmt.Sprintf(" AND prefix like '%%%s%%' ", filterNs.Prefix)
	}
	if !filterNs.AdminMetadata.ApprovedAt.Equal(time.Time{}) || !filterNs.AdminMetadata.UpdatedAt.Equal(time.Time{}) || !filterNs.AdminMetadata.CreatedAt.Equal(time.Time{}) {
		return nil, errors.New("Unsupported operation: Can't filter against date.")
	}
	// Always sort by id by default
	query += " ORDER BY id ASC"

	registrationsIn := []server_structs.Registration{}
	if err := database.ServerDatabase.Raw(query).Scan(&registrationsIn).Error; err != nil {
		return nil, err
	}

	registrationsOut := []server_structs.Registration{}
	for idx, ns := range registrationsIn {
		// If we want legacy registration and the query result doesn't have AdminMetadata, put it in the return value
		if legacy {
			if ns.AdminMetadata.Equal(server_structs.AdminMetadata{}) {
				registrationsOut = append(registrationsOut, ns)
				continue
			} else {
				continue
			}
			// If we don't want legacy namespace and the query result does not have AdminMetadata, skip it
		} else if !legacy && ns.AdminMetadata.Equal(server_structs.AdminMetadata{}) {
			continue
		}
		if filterNs.AdminMetadata.UserID != "" && filterNs.AdminMetadata.UserID != ns.AdminMetadata.UserID {
			continue
		}
		if filterNs.AdminMetadata.Description != "" && !strings.Contains(ns.AdminMetadata.Description, filterNs.AdminMetadata.Description) {
			continue
		}
		if filterNs.AdminMetadata.SiteName != "" && !strings.Contains(ns.AdminMetadata.SiteName, filterNs.AdminMetadata.SiteName) {
			continue
		}
		if filterNs.AdminMetadata.Institution != "" && filterNs.AdminMetadata.Institution != ns.AdminMetadata.Institution {
			continue
		}
		if filterNs.AdminMetadata.SecurityContactUserID != "" && filterNs.AdminMetadata.SecurityContactUserID != ns.AdminMetadata.SecurityContactUserID {
			continue
		}
		if filterNs.AdminMetadata.Status != "" {
			if filterNs.AdminMetadata.Status == server_structs.RegUnknown {
				if ns.AdminMetadata.Status != "" && ns.AdminMetadata.Status != server_structs.RegUnknown {
					continue
				}
			} else if filterNs.AdminMetadata.Status != ns.AdminMetadata.Status {
				continue
			}
		}
		if filterNs.AdminMetadata.ApproverID != "" && filterNs.AdminMetadata.ApproverID != ns.AdminMetadata.ApproverID {
			continue
		}
		// Congrats! You passed all the filter check and this registration matches what you want
		registrationsOut = append(registrationsOut, registrationsIn[idx])
	}
	return registrationsOut, nil
}

func AddRegistration(ns *server_structs.Registration) error {
	if ns.AdminMetadata.SiteName == "" {
		return errors.New("Site Name is required")
	}
	// Adding default values to the field. Note that you need to pass other fields
	// including user_id before this function
	ns.AdminMetadata.CreatedAt = time.Now()
	ns.AdminMetadata.UpdatedAt = time.Now()
	// We only set status to pending when it's empty to allow unit tests to add a registration with
	// desired status
	if ns.AdminMetadata.Status == "" {
		ns.AdminMetadata.Status = server_structs.RegPending
	}

	// Extract server ID from CustomFields before saving to database
	var serverID string
	isOrigin := strings.HasPrefix(ns.Prefix, server_structs.OriginPrefix.String())
	isCache := strings.HasPrefix(ns.Prefix, server_structs.CachePrefix.String())
	if (isOrigin || isCache) && ns.CustomFields != nil {
		if id, exists := ns.CustomFields["server_id"]; exists {
			if idStr, ok := id.(string); ok {
				serverID = idStr
				// serverID will be stored in `servers` table, not in `registrations` table.
				// Here we remove `server_id` from CustomFields to avoid storing it in `registrations` table
				delete(ns.CustomFields, "server_id")
			}
		}
	}

	// Wrap all database operations in a transaction
	// If any operation fails, all changes are reverted. No partial records left.
	return database.ServerDatabase.Transaction(func(tx *gorm.DB) error {
		// Save the registration
		if err := tx.Save(&ns).Error; err != nil {
			return errors.Wrapf(err, "failed to save registration: %s", ns.AdminMetadata.SiteName)
		}

		// If this is a server registration, we need to add it to the server tables
		if isOrigin || isCache {
			// If server ID is provided, check for conflicts first
			if serverID != "" {
				var existingServerWithID server_structs.Server
				err := tx.Where("id = ?", serverID).First(&existingServerWithID).Error
				if err == nil {
					// Server ID already exists, return conflict error
					return &duplicateServerIdError{
						Message: fmt.Sprintf("Server ID %q already exists. Please try again to generate a new ID.", serverID),
					}
				} else if !errors.Is(err, gorm.ErrRecordNotFound) {
					return errors.Wrapf(err, "failed to check for existing server ID: %s", serverID)
				}
				// Server ID doesn't exist, continue
			}

			// Check if a server with this name already exists
			var existingServer server_structs.Server
			err := tx.Where("name = ?", ns.AdminMetadata.SiteName).First(&existingServer).Error
			if err == gorm.ErrRecordNotFound {
				// No existing server, create a new one
				server := server_structs.Server{
					ID:       serverID, // Use provided server ID (may be empty for auto-generation)
					Name:     ns.AdminMetadata.SiteName,
					IsOrigin: isOrigin,
					IsCache:  isCache,
				}
				if err := tx.Create(&server).Error; err != nil {
					return errors.Wrapf(err, "failed to save server: %s", ns.AdminMetadata.SiteName)
				}

				service := server_structs.Service{
					ServerID:       server.ID,
					RegistrationID: ns.ID,
				}
				if err := tx.Create(&service).Error; err != nil {
					return errors.Wrapf(err, "failed to save service: %s", ns.AdminMetadata.SiteName)
				}
			} else if err != nil {
				return errors.Wrapf(err, "failed to check for existing server: %s", ns.AdminMetadata.SiteName)
			} else {
				// If there's an existing server with the same name owned by the same entity,
				// update its services (a server can be both an origin and a cache).
				// We consider they belong to the same entity if they have the same public key(s)

				// Get the first registration for this server to compare public keys
				// Because if multiple services registered to the same server, they all have the same public keys
				var existingService server_structs.Service
				if err := tx.Where("server_id = ?", existingServer.ID).Preload("Registration").First(&existingService).Error; err != nil {
					return errors.Wrapf(err, "failed to get existing service for server: %s", ns.AdminMetadata.SiteName)
				}

				existingPubkeySet, err := jwk.ParseString(existingService.Registration.Pubkey)
				if err != nil {
					return errors.Wrapf(err, "failed to parse existing server's pubkey as a jwks: %s", ns.AdminMetadata.SiteName)
				}
				inputPubkeySet, err := jwk.ParseString(ns.Pubkey)
				if err != nil {
					return errors.Wrapf(err, "failed to parse input registration's pubkey as a jwks: %s", ns.AdminMetadata.SiteName)
				}

				if !compareJwks(existingPubkeySet, inputPubkeySet) {
					return errors.Errorf("A server with the name %q already exists. Please choose a different server name or prove you have ownership of this server.", ns.AdminMetadata.SiteName)
				}
				if isOrigin {
					existingServer.IsOrigin = true
				}
				if isCache {
					existingServer.IsCache = true
				}
				existingServer.UpdatedAt = time.Now()

				if err := tx.Save(&existingServer).Error; err != nil {
					return errors.Wrapf(err, "failed to update server service(s): %s", ns.AdminMetadata.SiteName)
				}

				service := server_structs.Service{
					ServerID:       existingServer.ID,
					RegistrationID: ns.ID,
				}
				if err := tx.Create(&service).Error; err != nil {
					return errors.Wrapf(err, "failed to create new entry in service table: %s", ns.AdminMetadata.SiteName)
				}
			}
		}

		return nil
	})
}

func updateRegistration(ns *server_structs.Registration) error {
	existingNs, err := getRegistrationById(ns.ID)
	if err != nil || existingNs == nil {
		return errors.Wrap(err, "Failed to get registration")
	}
	if ns.Prefix == "" {
		ns.Prefix = existingNs.Prefix
	}
	if ns.Pubkey == "" {
		ns.Pubkey = existingNs.Pubkey
	}
	// We intentionally exclude updating "identity" as this should only be updated
	// when user registered through Pelican client with identity
	ns.Identity = existingNs.Identity

	existingNsAdmin := existingNs.AdminMetadata
	// We prevent the following fields from being modified by the user for now.
	// They are meant for "internal" use only.
	// We also don't allow changing Status other than explicitly
	// call updateRegistrationStatusById
	ns.AdminMetadata.CreatedAt = existingNsAdmin.CreatedAt
	ns.AdminMetadata.Status = existingNsAdmin.Status
	ns.AdminMetadata.ApprovedAt = existingNsAdmin.ApprovedAt
	ns.AdminMetadata.ApproverID = existingNsAdmin.ApproverID
	ns.AdminMetadata.UpdatedAt = time.Now()

	// Wrap all database operations in a transaction
	// If any operation fails, all changes are reverted. No partial records left.
	return database.ServerDatabase.Transaction(func(tx *gorm.DB) error {
		// Update the registration first
		if err := tx.Save(ns).Error; err != nil {
			return errors.Wrapf(err, "failed to update registration: %s", ns.AdminMetadata.SiteName)
		}

		// If this is a server registration, we need to update the server tables
		isOrigin := strings.HasPrefix(ns.Prefix, server_structs.OriginPrefix.String())
		isCache := strings.HasPrefix(ns.Prefix, server_structs.CachePrefix.String())
		if isOrigin || isCache {
			// Find the existing server via service mapping
			var service server_structs.Service
			if err := tx.Where("registration_id = ?", ns.ID).First(&service).Error; err != nil {
				return errors.Wrapf(err, "failed to find service for registration: %s", ns.AdminMetadata.SiteName)
			} else {
				// Update the existing server
				updates := map[string]interface{}{
					"name":       ns.AdminMetadata.SiteName,
					"is_origin":  isOrigin,
					"is_cache":   isCache,
					"updated_at": time.Now(),
				}
				if err := tx.Model(&server_structs.Server{}).Where("id = ?", service.ServerID).Updates(updates).Error; err != nil {
					return errors.Wrapf(err, "failed to update server: %s", ns.AdminMetadata.SiteName)
				}
			}
		}

		return nil
	})
}

func updateRegistrationStatusById(id int, status server_structs.RegistrationStatus, approverId string) error {
	ns, err := getRegistrationById(id)
	if err != nil {
		return errors.Wrap(err, "Error getting registration by id")
	}

	ns.AdminMetadata.Status = status
	ns.AdminMetadata.UpdatedAt = time.Now()
	if status == server_structs.RegApproved {
		if approverId == "" {
			return errors.New("approverId can't be empty to approve")
		}
		ns.AdminMetadata.ApproverID = approverId
		ns.AdminMetadata.ApprovedAt = time.Now()
	}

	adminMetadataByte, err := json.Marshal(ns.AdminMetadata)
	if err != nil {
		return errors.Wrap(err, "Error marshaling admin metadata")
	}

	return database.ServerDatabase.Model(ns).Where("id = ?", id).Update("admin_metadata", string(adminMetadataByte)).Error
}

func setRegistrationPubKey(prefix string, pubkeyDbString string) error {
	if prefix == "" {
		return errors.New("invalid prefix. Prefix must not be empty")
	}
	if pubkeyDbString == "" {
		return errors.New("invalid pubkeyDbString. pubkeyDbString must not be empty")
	}
	ns := server_structs.Registration{}
	return database.ServerDatabase.Model(ns).Where("prefix = ? ", prefix).Update("pubkey", pubkeyDbString).Error
}

// Note: If this is a server registration, the foreign key constraint applied on the DB will
// remove the corresponding entry in the “services” table.
// Additionally, if this server only has this single service registration (i.e., the server is only an
// origin or only a cache, not both), then delete the corresponding entry in the “servers” table.
// If services remain, update the server's is_origin and is_cache fields accordingly.
func deleteRegistrationByID(id int) error {
	// Wrap in a transaction to perform an atomic operation
	return database.ServerDatabase.Transaction(func(tx *gorm.DB) error {
		// Determine the server ID associated with this registration via the services table
		// (Server ID is not empty if this is a server registration)
		var svc server_structs.Service
		if err := tx.Where("registration_id = ?", id).First(&svc).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			// No service mapping found; proceed to delete registration only
		}

		// Delete the registration (this cascadingly deletes the related service entry)
		if err := tx.Delete(&server_structs.Registration{}, id).Error; err != nil {
			return err
		}

		if svc.ServerID != "" {
			var remainingSvcs []server_structs.Service
			if err := tx.Where("server_id = ?", svc.ServerID).Preload("Registration").Find(&remainingSvcs).Error; err != nil {
				return err
			}

			if len(remainingSvcs) == 0 {
				// Also delete the server only if no services belonging to it remain.
				//
				// The nested NOT EXISTS subquery ensures we only delete the server if
				// there are no remaining rows in `services` referencing this server. Within
				// the same transaction, this makes the check-and-delete atomic: if a new
				// service is inserted concurrently, the subquery returns a row and the
				// DELETE is skipped.
				subq := tx.Model(&server_structs.Service{}).Select("1").Where("server_id = ?", svc.ServerID).Limit(1)
				if err := tx.Where("id = ? AND NOT EXISTS (?)", svc.ServerID, subq).Delete(&server_structs.Server{}).Error; err != nil {
					return err
				}
			} else {
				// Update server flags to reflect remaining service types
				var hasOrigin, hasCache bool
				for _, remaining := range remainingSvcs {
					if remaining.Registration.ID == 0 {
						continue
					}
					prefix := remaining.Registration.Prefix
					if strings.HasPrefix(prefix, server_structs.OriginPrefix.String()) {
						hasOrigin = true
					}
					if strings.HasPrefix(prefix, server_structs.CachePrefix.String()) {
						hasCache = true
					}
				}
				updates := map[string]interface{}{
					"is_origin":  hasOrigin,
					"is_cache":   hasCache,
					"updated_at": time.Now(),
				}
				if err := tx.Model(&server_structs.Server{}).Where("id = ?", svc.ServerID).Updates(updates).Error; err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func deleteRegistrationByPrefix(prefix string) error {
	// GORM by default uses transaction for write operations
	return database.ServerDatabase.Where("prefix = ?", prefix).Delete(&server_structs.Registration{}).Error
}

func deleteServerByID(id string) error {
	// Wrap all database operations in a transaction
	// If any operation fails, all changes are reverted. No partial records left.
	return database.ServerDatabase.Transaction(func(tx *gorm.DB) error {
		serverRegistration, err := getServerByID(id)
		if err != nil {
			return errors.Wrap(err, "failed to get server by ID")
		}
		// Because of the foreign key constraints applied on the DB,
		// All entries with matching server_id in "services", "endpoints", "contacts" tables will be deleted automatically
		err = tx.Delete(&server_structs.Server{}, id).Error
		if err != nil {
			return errors.Wrap(err, "failed to delete server")
		}
		// Delete all registrations corresponding to the server separately
		for _, registration := range serverRegistration.Registration {
			err = tx.Delete(&server_structs.Registration{}, registration.ID).Error
			if err != nil {
				return errors.Wrapf(err, "failed to delete the registration corresponding to the server: %s", registration.Prefix)
			}
		}
		return nil
	})

}

func getAllRegistrations() ([]*server_structs.Registration, error) {
	var registrations []*server_structs.Registration
	if result := database.ServerDatabase.Order("id ASC").Find(&registrations); result.Error != nil {
		return nil, result.Error
	}

	for _, ns := range registrations {
		for key, val := range ns.CustomFields {
			switch v := val.(type) {
			case float64:
				ns.CustomFields[key] = int(v)
			case float32:
				ns.CustomFields[key] = int(v)
			}
		}
	}

	return registrations, nil
}

// Get all namespaces from the topology
func getTopologyNamespaces() ([]*Topology, error) {
	var topology []*Topology
	if result := database.ServerDatabase.Order("id ASC").Find(&topology); result.Error != nil {
		return nil, result.Error
	}
	return topology, nil
}

// Create a table in the registry to store namespace prefixes from topology
func PopulateTopology(ctx context.Context) error {
	// The topology table may already exist from before, it may not. Because of this
	// we need to add to the table any prefixes that are in topology, delete from the
	// table any that aren't in topology, and skip any that exist in both.

	// First get all that are in the table. At time of writing, this is ~57 entries,
	// and that number should be monotonically decreasing. We're safe to load into mem.
	var topologies []Topology
	if err := database.ServerDatabase.Model(&Topology{}).Select("prefix").Find(&topologies).Error; err != nil {
		return err
	}

	nsFromTopoTable := make(map[string]bool)
	for _, topo := range topologies {
		nsFromTopoTable[topo.Prefix] = true
	}

	// Next, get the values from topology
	namespaces, err := server_utils.GetTopologyJSON(ctx)
	if err != nil {
		return errors.Wrapf(err, "Failed to get topology JSON")
	}

	// Be careful here, the ns object we iterate over is from topology,
	// and it's not the same ns object we use elsewhere in this file.
	nsFromTopoJSON := make(map[string]bool)
	for _, ns := range namespaces.Namespaces {
		nsFromTopoJSON[ns.Path] = true
	}

	toAdd := []string{}
	toDelete := []string{}
	// If in topo and not in the table, add
	for prefix := range nsFromTopoJSON {
		if found := nsFromTopoTable[prefix]; !found {
			toAdd = append(toAdd, prefix)
		}
	}
	// If in table and not in topo, delete
	for prefix := range nsFromTopoTable {
		if found := nsFromTopoJSON[prefix]; !found {
			toDelete = append(toDelete, prefix)
		}
	}

	var toAddTopo []Topology
	for _, prefix := range toAdd {
		toAddTopo = append(toAddTopo, Topology{Prefix: prefix})
	}

	return database.ServerDatabase.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("prefix IN ?", toDelete).Delete(&Topology{}).Error; err != nil {
			return err
		}

		if len(toAddTopo) > 0 {
			if err := tx.Create(&toAddTopo).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func PeriodicTopologyReload(ctx context.Context) {
	for {
		time.Sleep(param.Federation_TopologyReloadInterval.GetDuration())
		err := PopulateTopology(ctx)
		if err != nil {
			log.Warningf("Failed to re-populate topology table: %s. Will try again later",
				err)
		}
	}
}
