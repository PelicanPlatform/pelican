/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	// commented sqlite driver requires CGO
	// _ "github.com/mattn/go-sqlite3" // SQLite driver
	_ "modernc.org/sqlite"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

type RegistrationStatus string

// The AdminMetadata is used in [Namespace] as a marshalled JSON string
// to be stored in registry DB.
//
// The *UserID are meant to correspond to the "sub" claim of the user token that
// the OAuth client issues if the user is logged in using OAuth, or it should be
// "admin" from local password-based authentication.
//
// To prevent users from writing to certain fields (readonly), you may use "post" tag
// with value "exclude". This will exclude the field from user's create/update requests
// and the field will also be excluded from field discovery endpoint (OPTION method).
//
// We use validator package to validate struct fields from user requests. If a field is
// required, add `validate:"required"` to that field. This tag will also be used by fields discovery
// endpoint to tell the UI if a field is required. For other validator tags,
// visit: https://pkg.go.dev/github.com/go-playground/validator/v10
type AdminMetadata struct {
	UserID                string             `json:"user_id" post:"exclude"` // "sub" claim of user JWT who requested registration
	Description           string             `json:"description"`
	SiteName              string             `json:"site_name"`
	Institution           string             `json:"institution" validate:"required"` // the unique identifier of the institution
	SecurityContactUserID string             `json:"security_contact_user_id"`        // "sub" claim of user who is responsible for taking security concern
	Status                RegistrationStatus `json:"status" post:"exclude"`
	ApproverID            string             `json:"approver_id" post:"exclude"` // "sub" claim of user JWT who approved registration
	ApprovedAt            time.Time          `json:"approved_at" post:"exclude"`
	CreatedAt             time.Time          `json:"created_at" post:"exclude"`
	UpdatedAt             time.Time          `json:"updated_at" post:"exclude"`
}

type Namespace struct {
	ID            int           `json:"id" post:"exclude"`
	Prefix        string        `json:"prefix" validate:"required"`
	Pubkey        string        `json:"pubkey" validate:"required"`
	Identity      string        `json:"identity" post:"exclude"`
	AdminMetadata AdminMetadata `json:"admin_metadata"`
}

type NamespaceWOPubkey struct {
	ID            int           `json:"id"`
	Prefix        string        `json:"prefix"`
	Pubkey        string        `json:"-"` // Don't include pubkey in this case
	Identity      string        `json:"identity"`
	AdminMetadata AdminMetadata `json:"admin_metadata"`
}

type ServerType string

const (
	OriginType ServerType = "origin"
	CacheType  ServerType = "cache"
)

const (
	Pending  RegistrationStatus = "Pending"
	Approved RegistrationStatus = "Approved"
	Denied   RegistrationStatus = "Denied"
	Unknown  RegistrationStatus = "Unknown"
)

/*
Declare the DB handle as an unexported global so that all
functions in the package can access it without having to
pass it around. This simplifies the HTTP handlers, and
the handle is already thread-safe! The approach being used
is based off of 1.b from
https://www.alexedwards.net/blog/organising-database-access
*/
var db *sql.DB

func (st ServerType) String() string {
	return string(st)
}

func (rs RegistrationStatus) String() string {
	return string(rs)
}

func (a AdminMetadata) Equal(b AdminMetadata) bool {
	return a.UserID == b.UserID &&
		a.Description == b.Description &&
		a.SiteName == b.SiteName &&
		a.Institution == b.Institution &&
		a.SecurityContactUserID == b.SecurityContactUserID &&
		a.Status == b.Status &&
		a.ApproverID == b.ApproverID &&
		a.ApprovedAt.Equal(b.ApprovedAt) &&
		a.CreatedAt.Equal(b.CreatedAt) &&
		a.UpdatedAt.Equal(b.UpdatedAt)
}

func createNamespaceTable() {
	//We put a size limit on admin_metadata to guard against potentially future
	//malicious large inserts
	query := `
    CREATE TABLE IF NOT EXISTS namespace (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prefix TEXT NOT NULL UNIQUE,
        pubkey TEXT NOT NULL,
        identity TEXT,
        admin_metadata TEXT CHECK (length("admin_metadata") <= 4000)
    );`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create namespace table: %v", err)
	}
}

func createTopologyTable() {
	query := `
    CREATE TABLE IF NOT EXISTS topology (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prefix TEXT NOT NULL UNIQUE
    );`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create topology table: %v", err)
	}
}

func namespaceExists(prefix string) (bool, error) {
	var checkQuery string
	var args []interface{}
	if config.GetPreferredPrefix() == "OSDF" {
		checkQuery = `
		SELECT prefix FROM namespace WHERE prefix = ?
		UNION
		SELECT prefix FROM topology WHERE prefix = ?
		`
		args = []interface{}{prefix, prefix}
	} else {
		checkQuery = `SELECT prefix FROM namespace WHERE prefix = ?`
		args = []interface{}{prefix}
	}

	result, err := db.Query(checkQuery, args...)
	if err != nil {
		return false, err
	}
	defer result.Close()

	found := false
	for result.Next() {
		found = true
		break
	}
	return found, nil
}

func namespaceSupSubChecks(prefix string) (superspaces []string, subspaces []string, inTopo bool, err error) {
	// The very first thing we do is check if there's a match in topo -- if there is, for now
	// we simply refuse to allow registration of a superspace or a subspace, assuming the registrant
	// has to go through topology
	if config.GetPreferredPrefix() == "OSDF" {
		topoSuperSubQuery := `
		SELECT prefix FROM topology WHERE (? || '/') LIKE (prefix || '/%')
		UNION
		SELECT prefix FROM topology WHERE (prefix || '/') LIKE (? || '/%')
		`
		args := []interface{}{prefix, prefix}
		topoSuperSubResults, tmpErr := db.Query(topoSuperSubQuery, args...)
		if tmpErr != nil {
			err = tmpErr
			return
		}
		defer topoSuperSubResults.Close()

		for topoSuperSubResults.Next() {
			// if we make it here, there was a match -- it's a trap!
			inTopo = true
			return
		}
		topoSuperSubResults.Close()
	}

	// Check if any registered namespaces already superspace the incoming namespace,
	// eg if /foo is already registered, this will be true for an incoming /foo/bar because
	// /foo is logically above /foo/bar (according to my logic, anyway)
	superspaceQuery := `SELECT prefix FROM namespace WHERE (? || '/') LIKE (prefix || '/%')`
	superspaceResults, err := db.Query(superspaceQuery, prefix)
	if err != nil {
		return
	}
	defer superspaceResults.Close()

	for superspaceResults.Next() {
		var foundSuperspace string
		if err := superspaceResults.Scan(&foundSuperspace); err == nil {
			superspaces = append(superspaces, foundSuperspace)
		}
	}

	// Check if any registered namespaces already subspace the incoming namespace,
	// eg if /foo/bar is already registered, this will be true for an incoming /foo because
	// /foo/bar is logically below /foo
	subspaceQuery := `SELECT prefix FROM namespace WHERE (prefix || '/') LIKE (? || '/%')`
	subspaceResults, err := db.Query(subspaceQuery, prefix)
	if err != nil {
		return
	}
	defer subspaceResults.Close()

	for subspaceResults.Next() {
		var foundSubspace string
		if err := subspaceResults.Scan(&foundSubspace); err == nil {
			subspaces = append(subspaces, foundSubspace)
		}
	}

	return
}

func namespaceExistsById(id int) (bool, error) {
	checkQuery := `SELECT id FROM namespace WHERE id = ?`
	result, err := db.Query(checkQuery, id)
	if err != nil {
		return false, err
	}
	defer result.Close()

	found := false
	for result.Next() {
		found = true
		break
	}
	return found, nil
}

func namespaceBelongsToUserId(id int, userId string) (bool, error) {
	query := `SELECT admin_metadata FROM namespace where id = ?`
	rows, err := db.Query(query, id)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		ns := &Namespace{}
		adminMetadataStr := ""
		if err := rows.Scan(&adminMetadataStr); err != nil {
			return false, err
		}
		// For backward compatibility, if adminMetadata is an empty string, don't unmarshall json
		if adminMetadataStr != "" {
			if err := json.Unmarshal([]byte(adminMetadataStr), &ns.AdminMetadata); err != nil {
				return false, err
			}
		} else {
			return false, nil // If adminMetadata is an empty string, no userId is present
		}
		if ns.AdminMetadata.UserID == userId {
			return true, nil
		}
	}
	return false, nil
}

func getNamespaceJwksById(id int) (jwk.Set, error) {
	jwksQuery := `SELECT pubkey FROM namespace WHERE id = ?`
	var pubkeyStr string
	err := db.QueryRow(jwksQuery, id).Scan(&pubkeyStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("prefix not found in database")
		}
		return nil, errors.Wrap(err, "error performing origin pubkey query")
	}

	set, err := jwk.ParseString(pubkeyStr)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse pubkey as a jwks")
	}

	return set, nil
}

func getNamespaceJwksByPrefix(prefix string, approvalRequired bool) (*jwk.Set, error) {
	var jwksQuery string
	var pubkeyStr string
	if strings.HasPrefix(prefix, "/caches/") && approvalRequired {
		adminMetadataStr := ""
		jwksQuery = `SELECT pubkey, admin_metadata FROM namespace WHERE prefix = ?`
		err := db.QueryRow(jwksQuery, prefix).Scan(&pubkeyStr, &adminMetadataStr)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, errors.New("prefix not found in database")
			}
			return nil, errors.Wrap(err, "error performing cache pubkey query")
		}
		if adminMetadataStr != "" { // Older version didn't have admin_metadata populated, skip checking
			adminMetadata := AdminMetadata{}
			if err = json.Unmarshal([]byte(adminMetadataStr), &adminMetadata); err != nil {
				return nil, errors.Wrap(err, "Failed to unmarshall admin_metadata")
			}
			// TODO: Move this to upper functions that handles business logic to keep db access functions simple
			if adminMetadata.Status != Approved {
				return nil, serverCredsErr
			}
		}
	} else {
		jwksQuery := `SELECT pubkey FROM namespace WHERE prefix = ?`
		err := db.QueryRow(jwksQuery, prefix).Scan(&pubkeyStr)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, errors.New("prefix not found in database")
			}
			return nil, errors.Wrap(err, "error performing origin pubkey query")
		}
	}

	set, err := jwk.ParseString(pubkeyStr)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse pubkey as a jwks")
	}

	return &set, nil
}

func getNamespaceStatusById(id int) (RegistrationStatus, error) {
	if id < 1 {
		return "", errors.New("Invalid id. id must be a positive integer")
	}
	adminMetadata := AdminMetadata{}
	adminMetadataStr := ""
	query := `SELECT admin_metadata FROM namespace WHERE id = ?`
	err := db.QueryRow(query, id).Scan(&adminMetadataStr)
	if err != nil {
		return "", err
	}
	// For backward compatibility, if adminMetadata is an empty string, don't unmarshall json
	if adminMetadataStr != "" {
		if err := json.Unmarshal([]byte(adminMetadataStr), &adminMetadata); err != nil {
			return "", err
		}
		// This should never happen in non-testing environment, but if it does, we want to
		// decode it to known enumeration for this field
		if adminMetadata.Status == "" {
			return Unknown, nil
		}
		return adminMetadata.Status, nil
	} else {
		return Unknown, nil
	}
}

func getNamespaceById(id int) (*Namespace, error) {
	if id < 1 {
		return nil, errors.New("Invalid id. id must be a positive number")
	}
	ns := &Namespace{}
	adminMetadataStr := ""
	query := `SELECT id, prefix, pubkey, identity, admin_metadata FROM namespace WHERE id = ?`
	err := db.QueryRow(query, id).Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &adminMetadataStr)
	if err != nil {
		return nil, err
	}
	// For backward compatibility, if adminMetadata is an empty string, don't unmarshall json
	if adminMetadataStr != "" {
		if err := json.Unmarshal([]byte(adminMetadataStr), &ns.AdminMetadata); err != nil {
			return nil, err
		}
	}
	return ns, nil
}

func getNamespaceByPrefix(prefix string) (*Namespace, error) {
	if prefix == "" {
		return nil, errors.New("Invalid prefix. Prefix must not be empty")
	}
	ns := &Namespace{}
	adminMetadataStr := ""
	query := `SELECT id, prefix, pubkey, identity, admin_metadata FROM namespace WHERE prefix = ?`
	err := db.QueryRow(query, prefix).Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &adminMetadataStr)
	if err != nil {
		return nil, err
	}
	// For backward compatibility, if adminMetadata is an empty string, don't unmarshall json
	if adminMetadataStr != "" {
		if err := json.Unmarshal([]byte(adminMetadataStr), &ns.AdminMetadata); err != nil {
			return nil, err
		}
	}
	return ns, nil
}

// Get a collection of namespaces by filtering against various non-default namespace fields
// excluding Namespace.ID, Namespace.Identity, Namespace.Pubkey, and various dates
//
// For filterNs.AdminMetadata.Description and filterNs.AdminMetadata.SiteName,
// the string will be matched using `strings.Contains`. This is too mimic a SQL style `like` match.
// The rest of the AdminMetadata fields is matched by `==`
func getNamespacesByFilter(filterNs Namespace, serverType ServerType) ([]*Namespace, error) {
	query := `SELECT id, prefix, pubkey, identity, admin_metadata FROM namespace WHERE 1=1 `
	if serverType == CacheType {
		// Refer to the cache prefix name in cmd/cache_serve
		query += ` AND prefix LIKE '/caches/%'`
	} else if serverType == OriginType {
		query += ` AND NOT prefix LIKE '/caches/%'`
	} else if serverType != "" {
		return nil, errors.New(fmt.Sprint("Can't get namespace: unsupported server type: ", serverType))
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
	// For now, we need to execute the query first and manually filter out fields for AdminMetadata
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	namespaces := make([]*Namespace, 0)
	for rows.Next() {
		ns := &Namespace{}
		adminMetadataStr := ""
		if err := rows.Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &adminMetadataStr); err != nil {
			return nil, err
		}
		// For backward compatibility, if adminMetadata is an empty string, don't unmarshall json
		if adminMetadataStr == "" {
			// If we apply any filter against the AdminMetadata field but the
			// entry didn't populate this field, skip it
			if !filterNs.AdminMetadata.Equal(AdminMetadata{}) {
				continue
			} else {
				// If we don't filter against AdminMetadata, just add it to result
				namespaces = append(namespaces, ns)
			}
		} else {
			if err := json.Unmarshal([]byte(adminMetadataStr), &ns.AdminMetadata); err != nil {
				return nil, err
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
				if filterNs.AdminMetadata.Status == Unknown {
					if ns.AdminMetadata.Status != "" && ns.AdminMetadata.Status != Unknown {
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
			namespaces = append(namespaces, ns)
		}
	}

	return namespaces, nil
}

/*
Some generic functions for CRUD actions on namespaces,
used BY the registry (as opposed to the parallel
functions) used by the client.
*/

func addNamespace(ns *Namespace) error {
	query := `INSERT INTO namespace (prefix, pubkey, identity, admin_metadata) VALUES (?, ?, ?, ?)`
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// Adding default values to the field. Note that you need to pass other fields
	// including user_id before this function
	ns.AdminMetadata.CreatedAt = time.Now()
	ns.AdminMetadata.UpdatedAt = time.Now()
	// We only set status to pending when it's empty to allow tests to add a namespace with
	// desired status
	if ns.AdminMetadata.Status == "" {
		ns.AdminMetadata.Status = Pending
	}

	strAdminMetadata, err := json.Marshal(ns.AdminMetadata)
	if err != nil {
		return errors.Wrap(err, "Fail to marshall AdminMetadata")
	}

	_, err = tx.Exec(query, ns.Prefix, ns.Pubkey, ns.Identity, strAdminMetadata)
	if err != nil {
		if errRoll := tx.Rollback(); errRoll != nil {
			log.Errorln("Failed to rollback transaction:", errRoll)
		}
		return err
	}
	return tx.Commit()
}

func updateNamespace(ns *Namespace) error {
	existingNs, err := getNamespaceById(ns.ID)
	if err != nil || existingNs == nil {
		return errors.Wrap(err, "Failed to get namespace")
	}
	existingNsAdmin := existingNs.AdminMetadata
	// We prevent the following fields from being modified by the user for now.
	// They are meant for "internal" use only and we don't support changing
	// UserID on the fly. We also don't allow changing Status other than explicitly
	// call updateNamespaceStatusById
	ns.AdminMetadata.UserID = existingNsAdmin.UserID
	ns.AdminMetadata.CreatedAt = existingNsAdmin.CreatedAt
	ns.AdminMetadata.Status = existingNsAdmin.Status
	ns.AdminMetadata.ApprovedAt = existingNsAdmin.ApprovedAt
	ns.AdminMetadata.ApproverID = existingNsAdmin.ApproverID
	ns.AdminMetadata.UpdatedAt = time.Now()
	strAdminMetadata, err := json.Marshal(ns.AdminMetadata)
	if err != nil {
		return errors.Wrap(err, "Fail to marshall AdminMetadata")
	}

	// We intentionally exclude updating "identity" as this should only be updated
	// when user registered through Pelican client with identity
	query := `UPDATE namespace SET pubkey = ?, admin_metadata = ? WHERE id = ?`
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(query, ns.Pubkey, strAdminMetadata, ns.ID)
	if err != nil {
		if errRoll := tx.Rollback(); errRoll != nil {
			log.Errorln("Failed to rollback transaction:", errRoll)
		}
		return errors.Wrap(err, "Failed to execute update query")
	}
	return tx.Commit()
}

func updateNamespaceStatusById(id int, status RegistrationStatus, approverId string) error {
	ns, err := getNamespaceById(id)
	if err != nil {
		return errors.Wrap(err, "Error getting namespace by id")
	}

	ns.AdminMetadata.Status = status
	ns.AdminMetadata.UpdatedAt = time.Now()
	if status == Approved {
		if approverId == "" {
			return errors.New("approverId can't be empty to approve")
		}
		ns.AdminMetadata.ApproverID = approverId
		ns.AdminMetadata.ApprovedAt = time.Now()
	}

	adminMetadataByte, err := json.Marshal(ns.AdminMetadata)
	if err != nil {
		return errors.Wrap(err, "Error marshalling admin metadata")
	}

	query := `UPDATE namespace SET admin_metadata = ? WHERE id = ?`
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(query, string(adminMetadataByte), ns.ID)
	if err != nil {
		if errRoll := tx.Rollback(); errRoll != nil {
			log.Errorln("Failed to rollback transaction:", errRoll)
		}
		return errors.Wrap(err, "Failed to execute update query")
	}
	return tx.Commit()
}

func deleteNamespace(prefix string) error {
	deleteQuery := `DELETE FROM namespace WHERE prefix = ?`
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(deleteQuery, prefix)
	if err != nil {
		if errRoll := tx.Rollback(); errRoll != nil {
			log.Errorln("Failed to rollback transaction:", errRoll)
		}
		return errors.Wrap(err, "Failed to execute deletion query")
	}
	return tx.Commit()
}

func getAllNamespaces() ([]*Namespace, error) {
	query := `SELECT id, prefix, pubkey, identity, admin_metadata FROM namespace ORDER BY id ASC`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	namespaces := make([]*Namespace, 0)
	for rows.Next() {
		ns := &Namespace{}
		adminMetadataStr := ""
		if err := rows.Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &adminMetadataStr); err != nil {
			return nil, err
		}
		// For backward compatibility, if adminMetadata is an empty string, don't unmarshall json
		if adminMetadataStr != "" {
			if err := json.Unmarshal([]byte(adminMetadataStr), &ns.AdminMetadata); err != nil {
				return nil, err
			}
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces, nil
}

func InitializeDB(ctx context.Context) error {
	dbPath := param.Registry_DbLocation.GetString()
	if dbPath == "" {
		err := errors.New("Could not get path for the namespace registry database.")
		log.Fatal(err)
		return err
	}

	// Before attempting to create the database, the path
	// must exist or sql.Open will panic.
	err := os.MkdirAll(filepath.Dir(dbPath), 0755)
	if err != nil {
		return errors.Wrap(err, "Failed to create directory for namespace registry database")
	}

	if len(filepath.Ext(dbPath)) == 0 { // No fp extension, let's add .sqlite so it's obvious what the file is
		dbPath += ".sqlite"
	}

	dbName := "file:" + dbPath + "?_busy_timeout=5000&_journal_mode=WAL"
	log.Debugln("Opening connection to sqlite DB", dbName)
	db, err = sql.Open("sqlite", dbName)
	if err != nil {
		return errors.Wrapf(err, "Failed to open the database with path: %s", dbPath)
	}

	createNamespaceTable()
	return db.Ping()
}

func modifyTopologyTable(prefixes []string, mode string) error {
	if len(prefixes) == 0 {
		return nil // nothing to do!
	}

	var query string
	switch mode {
	case "add":
		query = `INSERT INTO topology (prefix) VALUES (?)`
	case "del":
		query = `DELETE FROM topology WHERE prefix = ?`
	default:
		return errors.New("invalid mode, use 'add' or 'del'")
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, prefix := range prefixes {
		_, err := stmt.Exec(prefix)
		if err != nil {
			if errRoll := tx.Rollback(); errRoll != nil {
				log.Errorln("Failed to rollback transaction:", errRoll)
			}
			return err
		}
	}

	// One nice batch commit
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

// Create a table in the registry to store namespace prefixes from topology
func PopulateTopology() error {
	// Create the toplogy table
	createTopologyTable()

	// The topology table may already exist from before, it may not. Because of this
	// we need to add to the table any prefixes that are in topology, delete from the
	// table any that aren't in topology, and skip any that exist in both.

	// First get all that are in the table. At time of writing, this is ~57 entries,
	// and that number should be monotonically decreasing. We're safe to load into mem.
	retrieveQuery := "SELECT prefix FROM topology"
	rows, err := db.Query(retrieveQuery)
	if err != nil {
		return errors.Wrap(err, "Could not construct topology database query")
	}
	defer rows.Close()

	nsFromTopoTable := make(map[string]bool)
	for rows.Next() {
		var existingPrefix string
		if err := rows.Scan(&existingPrefix); err != nil {
			return errors.Wrap(err, "Error while scanning rows from topology table")
		}
		nsFromTopoTable[existingPrefix] = true
	}
	rows.Close()

	// Next, get the values from topology
	namespaces, err := utils.GetTopologyJSON()
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

	if err := modifyTopologyTable(toAdd, "add"); err != nil {
		return errors.Wrap(err, "Failed to update topology table with new values")
	}
	if err := modifyTopologyTable(toDelete, "del"); err != nil {
		return errors.Wrap(err, "Failed to clean old values from topology table")
	}

	return nil
}

func PeriodicTopologyReload() {
	for {
		time.Sleep(time.Minute * param.Federation_TopologyReloadInterval.GetDuration())
		err := PopulateTopology()
		if err != nil {
			log.Warningf("Failed to re-populate topology table: %s. Will try again later",
				err)
		}
	}
}

func ShutdownDB() error {
	err := db.Close()
	if err != nil {
		log.Errorln("Failure when shutting down the database:", err)
	}
	return err
}
