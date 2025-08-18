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

// Check if a namespace exists in the Namespace table
func namespaceExistsByPrefix(prefix string) (bool, error) {
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

func namespaceExistsById(id int) (bool, error) {
	var namespaces []server_structs.Registration
	result := database.ServerDatabase.Limit(1).Find(&namespaces, id)
	if result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected > 0, nil
	}
}

func namespaceBelongsToUserId(id int, userId string) (bool, error) {
	var result server_structs.Registration
	err := database.ServerDatabase.First(&result, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, fmt.Errorf("Namespace with id = %d does not exists", id)
	} else if err != nil {
		return false, errors.Wrap(err, "error retrieving namespace")
	}
	return result.AdminMetadata.UserID == userId, nil
}

func getNamespaceJwksById(id int) (jwk.Set, error) {
	var result server_structs.Registration
	err := database.ServerDatabase.Select("pubkey").Where("id = ?", id).Last(&result).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("namespace with id %d not found in database", id)
	} else if err != nil {
		return nil, errors.Wrap(err, "error retrieving pubkey")
	}

	set, err := jwk.ParseString(result.Pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse pubkey as a jwks")
	}

	return set, nil
}

func getNamespaceJwksByPrefix(prefix string) (jwk.Set, *server_structs.AdminMetadata, error) {
	// Note that this cannot retrieve public keys from topology as the topology table
	// doesn't contain that information.
	if prefix == "" {
		return nil, nil, errors.New("Invalid prefix. Prefix must not be empty")
	}
	var result server_structs.Registration
	err := database.ServerDatabase.Select("pubkey", "admin_metadata").Where("prefix = ?", prefix).Last(&result).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("namespace with prefix %q not found in database", prefix)
	} else if err != nil {
		return nil, nil, errors.Wrap(err, "error retrieving pubkey")
	}

	set, err := jwk.ParseString(result.Pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse pubkey as a jwks")
	}

	return set, &result.AdminMetadata, nil
}

func getNamespaceStatusById(id int) (server_structs.RegistrationStatus, error) {
	if id < 1 {
		return "", errors.New("Invalid id. id must be a positive integer")
	}
	var result server_structs.Registration
	query := database.ServerDatabase.Select("admin_metadata").Where("id = ?", id).Last(&result)
	err := query.Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return server_structs.RegUnknown, fmt.Errorf("namespace with id %d not found in database", id)
	} else if err != nil {
		return server_structs.RegUnknown, errors.Wrap(err, "error retrieving pubkey")
	}
	if result.AdminMetadata.Status == "" {
		return server_structs.RegUnknown, nil
	}
	return result.AdminMetadata.Status, nil
}

// Retrieve the details of a server by server ID
func getServerByID(serverID string) (*server_structs.ServerRegistration, error) {
	var result server_structs.ServerRegistration

	query := `
		SELECT
			s.id, s.name, s.is_origin, s.is_cache, s.note, s.created_at, s.updated_at,
			n.id as ns_id, n.prefix, n.pubkey, n.identity, n.admin_metadata, n.custom_fields
		FROM services srv
		JOIN servers s ON srv.server_id = s.id
		JOIN registrations n ON srv.registration_id = n.id
		WHERE s.id = ?
	`

	if err := database.ServerDatabase.Raw(query, serverID).Scan(&result).Error; err != nil {
		return nil, errors.Wrapf(err, "failed to get server namespace for server ID: %s", serverID)
	}

	return &result, nil
}

// Retrieve the details of a server by its registration's ID
func getServerByRegistrationID(registrationID int) (*server_structs.ServerRegistration, error) {
	var result server_structs.ServerRegistration

	query := `
		SELECT
			s.id, s.name, s.is_origin, s.is_cache, s.note, s.created_at, s.updated_at,
			n.id as ns_id, n.prefix, n.pubkey, n.identity, n.admin_metadata, n.custom_fields
		FROM services srv
		JOIN servers s ON srv.server_id = s.id
		JOIN registrations n ON srv.registration_id = n.id
		WHERE n.id = ?
	`

	if err := database.ServerDatabase.Raw(query, registrationID).Scan(&result).Error; err != nil {
		return nil, errors.Wrapf(err, "failed to get server namespace for namespace ID: %d", registrationID)
	}

	return &result, nil
}

// Get the complete info of all servers
func listServers() ([]server_structs.ServerRegistration, error) {
	var results []server_structs.ServerRegistration

	query := `
		SELECT
			s.id, s.name, s.is_origin, s.is_cache, s.note, s.created_at, s.updated_at,
			n.id as ns_id, n.prefix, n.pubkey, n.identity, n.admin_metadata, n.custom_fields
		FROM services srv
		JOIN servers s ON srv.server_id = s.id
		JOIN registrations n ON srv.registration_id = n.id
		ORDER BY s.id ASC
	`

	if err := database.ServerDatabase.Raw(query).Scan(&results).Error; err != nil {
		return nil, errors.Wrap(err, "failed to retrieve all servers from the database")
	}

	return results, nil
}

func getNamespaceById(id int) (*server_structs.Registration, error) {
	if id < 1 {
		return nil, errors.New("Invalid id. id must be a positive number")
	}
	ns := server_structs.Registration{}
	err := database.ServerDatabase.Last(&ns, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("namespace with id %d not found in database", id)
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

// Get an entry from the namespace table based on the prefix
func getNamespaceByPrefix(prefix string) (*server_structs.Registration, error) {
	if prefix == "" {
		return nil, errors.New("invalid prefix. Prefix must not be empty")
	}
	ns := server_structs.Registration{}
	err := database.ServerDatabase.Where("prefix = ? ", prefix).Last(&ns).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("namespace with id %q not found in database", prefix)
	} else if err != nil {
		return nil, errors.Wrap(err, "error retrieving namespace registration by its prefix")
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
	var namespaces []server_structs.Registration

	err := database.ServerDatabase.Where("prefix LIKE ?", "/caches/%").Find(&namespaces).Error
	if err != nil {
		return nil, err
	}

	allowedPrefixesForCachesMap := make(map[string][]string)

	for _, namespace := range namespaces {
		// Remove "/caches/" from the beginning of the Prefix
		cacheHostname := strings.TrimPrefix(namespace.Prefix, "/caches/")

		allowedPrefixesRaw, exists := namespace.CustomFields["AllowedPrefixes"]
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

// Get a collection of namespaces by filtering against various non-default namespace fields
// excluding Namespace.ID, Namespace.Identity, Namespace.Pubkey, and various dates
//
// For filterNs.AdminMetadata.Description and filterNs.AdminMetadata.SiteName,
// the string will be matched using `strings.Contains`. This is too mimic a SQL style `like` match.
// The rest of the AdminMetadata fields is matched by `==`
func getNamespacesByFilter(filterNs server_structs.Registration, pType prefixType, legacy bool) ([]server_structs.Registration, error) {
	query := `SELECT id, prefix, pubkey, identity, admin_metadata FROM registrations WHERE 1=1 `
	if pType == prefixForCache {
		// Refer to the cache prefix name in cmd/cache_serve
		query += ` AND prefix LIKE '/caches/%'`
	} else if pType == prefixForOrigin {
		query += ` AND prefix LIKE '/origins/%'`
	} else if pType == prefixForNamespace {
		query += ` AND NOT prefix LIKE '/caches/%' AND NOT prefix LIKE '/origins/%'`
	} else if pType != "" {
		return nil, errors.New(fmt.Sprint("Can't get namespace: unsupported server type: ", pType))
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

	namespacesIn := []server_structs.Registration{}
	if err := database.ServerDatabase.Raw(query).Scan(&namespacesIn).Error; err != nil {
		return nil, err
	}

	namespacesOut := []server_structs.Registration{}
	for idx, ns := range namespacesIn {
		// If we want legacy registration and the query result doesn't have AdminMetadata, put it in the return value
		if legacy {
			if ns.AdminMetadata.Equal(server_structs.AdminMetadata{}) {
				namespacesOut = append(namespacesOut, ns)
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
		// Congrats! You passed all the filter check and this namespace matches what you want
		namespacesOut = append(namespacesOut, namespacesIn[idx])
	}
	return namespacesOut, nil
}

func AddNamespace(ns *server_structs.Registration) error {
	// Adding default values to the field. Note that you need to pass other fields
	// including user_id before this function
	ns.AdminMetadata.CreatedAt = time.Now()
	ns.AdminMetadata.UpdatedAt = time.Now()
	// We only set status to pending when it's empty to allow unit tests to add a namespace with
	// desired status
	if ns.AdminMetadata.Status == "" {
		ns.AdminMetadata.Status = server_structs.RegPending
	}

	// Wrap all database operations in a transaction
	// If any operation fails, all changes are reverted. No partial records left.
	return database.ServerDatabase.Transaction(func(tx *gorm.DB) error {
		// Save the namespace first
		if err := tx.Save(&ns).Error; err != nil {
			return errors.Wrapf(err, "failed to save namespace: %s", ns.AdminMetadata.SiteName)
		}

		// If this is a server registration, we need to add it to the server tables
		isOrigin := strings.HasPrefix(ns.Prefix, server_structs.OriginPrefix.String())
		isCache := strings.HasPrefix(ns.Prefix, server_structs.CachePrefix.String())
		if isOrigin || isCache {
			// Check if a server with this name already exists
			var existingServer server_structs.Server
			err := tx.Where("name = ?", ns.AdminMetadata.SiteName).First(&existingServer).Error
			if err == gorm.ErrRecordNotFound {
				// No existing server, create a new one
				server := server_structs.Server{
					// ID will be auto-generated by BeforeCreate hook
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
				// Server exists, update its services (a server can be both an origin and a cache)
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

func updateNamespace(ns *server_structs.Registration) error {
	existingNs, err := getNamespaceById(ns.ID)
	if err != nil || existingNs == nil {
		return errors.Wrap(err, "Failed to get namespace")
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
	// call updateNamespaceStatusById
	ns.AdminMetadata.CreatedAt = existingNsAdmin.CreatedAt
	ns.AdminMetadata.Status = existingNsAdmin.Status
	ns.AdminMetadata.ApprovedAt = existingNsAdmin.ApprovedAt
	ns.AdminMetadata.ApproverID = existingNsAdmin.ApproverID
	ns.AdminMetadata.UpdatedAt = time.Now()

	// Wrap all database operations in a transaction
	// If any operation fails, all changes are reverted. No partial records left.
	return database.ServerDatabase.Transaction(func(tx *gorm.DB) error {
		// Update the namespace first
		if err := tx.Save(ns).Error; err != nil {
			return errors.Wrapf(err, "failed to update namespace: %s", ns.AdminMetadata.SiteName)
		}

		// If this is a server registration, we need to update the server tables
		isOrigin := strings.HasPrefix(ns.Prefix, server_structs.OriginPrefix.String())
		isCache := strings.HasPrefix(ns.Prefix, server_structs.CachePrefix.String())
		if isOrigin || isCache {
			// Find the existing server via service mapping
			var service server_structs.Service
			if err := tx.Where("registration_id = ?", ns.ID).First(&service).Error; err != nil {
				return errors.Wrapf(err, "failed to find service for namespace: %s", ns.AdminMetadata.SiteName)
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

func updateNamespaceStatusById(id int, status server_structs.RegistrationStatus, approverId string) error {
	ns, err := getNamespaceById(id)
	if err != nil {
		return errors.Wrap(err, "Error getting namespace by id")
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

func setNamespacePubKey(prefix string, pubkeyDbString string) error {
	if prefix == "" {
		return errors.New("invalid prefix. Prefix must not be empty")
	}
	if pubkeyDbString == "" {
		return errors.New("invalid pubkeyDbString. pubkeyDbString must not be empty")
	}
	ns := server_structs.Registration{}
	return database.ServerDatabase.Model(ns).Where("prefix = ? ", prefix).Update("pubkey", pubkeyDbString).Error
}

func deleteNamespaceByID(id int) error {
	// First get the namespace to check if it's a server
	ns, err := getNamespaceById(id)
	if err != nil {
		return errors.Wrap(err, "failed to get namespace by ID")
	}

	// Wrap all database operations in a transaction
	// If any operation fails, all changes are reverted. No partial records left.
	return database.ServerDatabase.Transaction(func(tx *gorm.DB) error {
		// If this is a server registration, we need to delete from the server tables
		isOrigin := strings.HasPrefix(ns.Prefix, server_structs.OriginPrefix.String())
		isCache := strings.HasPrefix(ns.Prefix, server_structs.CachePrefix.String())
		if isOrigin || isCache {
			// Find the existing server via service mapping
			var service server_structs.Service
			if err := tx.Where("registration_id = ?", ns.ID).First(&service).Error; err != nil {
				return errors.Wrapf(err, "failed to find service for %s", ns.AdminMetadata.SiteName)
			}

			// Delete the service entry first (foreign key constraint)
			if err := tx.Delete(&service).Error; err != nil {
				return errors.Wrapf(err, "failed to delete service for %s", ns.AdminMetadata.SiteName)
			}

			// Delete the server entry
			if err := tx.Delete(&server_structs.Server{}, service.ServerID).Error; err != nil {
				return errors.Wrapf(err, "failed to delete server for %s", ns.AdminMetadata.SiteName)
			}
		}

		// Finally delete the namespace
		if err := tx.Delete(&server_structs.Registration{}, id).Error; err != nil {
			return errors.Wrapf(err, "failed to delete %s", ns.AdminMetadata.SiteName)
		}

		return nil
	})
}

func deleteNamespaceByPrefix(prefix string) error {
	// GORM by default uses transaction for write operations
	return database.ServerDatabase.Where("prefix = ?", prefix).Delete(&server_structs.Registration{}).Error
}

func getAllNamespaces() ([]*server_structs.Registration, error) {
	var namespaces []*server_structs.Registration
	if result := database.ServerDatabase.Order("id ASC").Find(&namespaces); result.Error != nil {
		return nil, result.Error
	}

	for _, ns := range namespaces {
		for key, val := range ns.CustomFields {
			switch v := val.(type) {
			case float64:
				ns.CustomFields[key] = int(v)
			case float32:
				ns.CustomFields[key] = int(v)
			}
		}
	}

	return namespaces, nil
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
