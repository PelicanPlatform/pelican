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
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
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
Declare the DB handle as an unexported global so that all
functions in the package can access it without having to
pass it around. This simplifies the HTTP handlers, and
the handle is already thread-safe! The approach being used
is based off of 1.b from
https://www.alexedwards.net/blog/organising-database-access
*/
var db *gorm.DB

//go:embed migrations/*.sql
var embedMigrations embed.FS

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

	err := db.Model(&server_structs.Namespace{}).Where("prefix = ?", prefix).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Check if a namespace exists in the Topology table
func topologyNamespaceExistsByPrefix(prefix string) (bool, error) {
	var count int64

	err := db.Model(&Topology{}).Where("prefix = ?", prefix).Count(&count).Error
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
		err = db.Raw(topoSuperSubQuery, prefix, prefix).Scan(&topoNss).Error
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
	superspaceQuery := `SELECT prefix FROM namespace WHERE (? || '/') LIKE (prefix || '/%')`
	err = db.Raw(superspaceQuery, prefix).Scan(&superspaces).Error
	if err != nil {
		return
	}

	// Check if any registered namespaces already subspace the incoming namespace,
	// eg if /foo/bar is already registered, this will be true for an incoming /foo because
	// /foo/bar is logically below /foo
	subspaceQuery := `SELECT prefix FROM namespace WHERE (prefix || '/') LIKE (? || '/%')`
	err = db.Raw(subspaceQuery, prefix).Scan(&subspaces).Error
	if err != nil {
		return
	}

	return
}

func namespaceExistsById(id int) (bool, error) {
	var namespaces []server_structs.Namespace
	result := db.Limit(1).Find(&namespaces, id)
	if result.Error != nil {
		return false, result.Error
	} else {
		return result.RowsAffected > 0, nil
	}
}

func namespaceBelongsToUserId(id int, userId string) (bool, error) {
	var result server_structs.Namespace
	err := db.First(&result, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, fmt.Errorf("Namespace with id = %d does not exists", id)
	} else if err != nil {
		return false, errors.Wrap(err, "error retrieving namespace")
	}
	return result.AdminMetadata.UserID == userId, nil
}

func getNamespaceJwksById(id int) (jwk.Set, error) {
	var result server_structs.Namespace
	err := db.Select("pubkey").Where("id = ?", id).Last(&result).Error
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
	var result server_structs.Namespace
	err := db.Select("pubkey", "admin_metadata").Where("prefix = ?", prefix).Last(&result).Error
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
	var result server_structs.Namespace
	query := db.Select("admin_metadata").Where("id = ?", id).Last(&result)
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

func getNamespaceById(id int) (*server_structs.Namespace, error) {
	if id < 1 {
		return nil, errors.New("Invalid id. id must be a positive number")
	}
	ns := server_structs.Namespace{}
	err := db.Last(&ns, id).Error
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
func getNamespaceByPrefix(prefix string) (*server_structs.Namespace, error) {
	if prefix == "" {
		return nil, errors.New("invalid prefix. Prefix must not be empty")
	}
	ns := server_structs.Namespace{}
	err := db.Where("prefix = ? ", prefix).Last(&ns).Error
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

// Get a collection of namespaces by filtering against various non-default namespace fields
// excluding Namespace.ID, Namespace.Identity, Namespace.Pubkey, and various dates
//
// For filterNs.AdminMetadata.Description and filterNs.AdminMetadata.SiteName,
// the string will be matched using `strings.Contains`. This is too mimic a SQL style `like` match.
// The rest of the AdminMetadata fields is matched by `==`
func getNamespacesByFilter(filterNs server_structs.Namespace, pType prefixType, legacy bool) ([]server_structs.Namespace, error) {
	query := `SELECT id, prefix, pubkey, identity, admin_metadata FROM namespace WHERE 1=1 `
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

	namespacesIn := []server_structs.Namespace{}
	if err := db.Raw(query).Scan(&namespacesIn).Error; err != nil {
		return nil, err
	}

	namespacesOut := []server_structs.Namespace{}
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

func AddNamespace(ns *server_structs.Namespace) error {
	// Adding default values to the field. Note that you need to pass other fields
	// including user_id before this function
	ns.AdminMetadata.CreatedAt = time.Now()
	ns.AdminMetadata.UpdatedAt = time.Now()
	// We only set status to pending when it's empty to allow unit tests to add a namespace with
	// desired status
	if ns.AdminMetadata.Status == "" {
		ns.AdminMetadata.Status = server_structs.RegPending
	}

	return db.Save(&ns).Error
}

func updateNamespace(ns *server_structs.Namespace) error {
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

	return db.Save(ns).Error
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

	return db.Model(ns).Where("id = ?", id).Update("admin_metadata", string(adminMetadataByte)).Error
}

func deleteNamespaceByID(id int) error {
	return db.Delete(&server_structs.Namespace{}, id).Error
}

func deleteNamespaceByPrefix(prefix string) error {
	// GORM by default uses transaction for write operations
	return db.Where("prefix = ?", prefix).Delete(&server_structs.Namespace{}).Error
}

func getAllNamespaces() ([]*server_structs.Namespace, error) {
	var namespaces []*server_structs.Namespace
	if result := db.Order("id ASC").Find(&namespaces); result.Error != nil {
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
	if result := db.Order("id ASC").Find(&topology); result.Error != nil {
		return nil, result.Error
	}
	return topology, nil
}

func InitializeDB() error {
	dbPath := param.Registry_DbLocation.GetString()

	tdb, err := server_utils.InitSQLiteDB(dbPath)
	if err != nil {
		return err
	}

	db = tdb

	sqldb, err := db.DB()

	if err != nil {
		return errors.Wrapf(err, "Failed to get sql.DB from gorm DB: %s", dbPath)
	}

	// Run database migrations
	if err := server_utils.MigrateDB(sqldb, embedMigrations); err != nil {
		return err
	}

	return nil
}

// Create a table in the registry to store namespace prefixes from topology
func PopulateTopology(ctx context.Context) error {
	// The topology table may already exist from before, it may not. Because of this
	// we need to add to the table any prefixes that are in topology, delete from the
	// table any that aren't in topology, and skip any that exist in both.

	// First get all that are in the table. At time of writing, this is ~57 entries,
	// and that number should be monotonically decreasing. We're safe to load into mem.
	var topologies []Topology
	if err := db.Model(&Topology{}).Select("prefix").Find(&topologies).Error; err != nil {
		return err
	}

	nsFromTopoTable := make(map[string]bool)
	for _, topo := range topologies {
		nsFromTopoTable[topo.Prefix] = true
	}

	// Next, get the values from topology
	namespaces, err := utils.GetTopologyJSON(ctx, false)
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

	return db.Transaction(func(tx *gorm.DB) error {
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

func ShutdownRegistryDB() error {
	return server_utils.ShutdownDB(db)
}
