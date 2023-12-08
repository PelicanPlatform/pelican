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

type Namespace struct {
	ID            int    `json:"id"`
	Prefix        string `json:"prefix"`
	Pubkey        string `json:"pubkey"`
	Identity      string `json:"identity"`
	AdminMetadata string `json:"admin_metadata"`
}

type NamespaceWOPubkey struct {
	ID            int    `json:"id"`
	Prefix        string `json:"prefix"`
	Pubkey        string `json:"-"` // Don't include pubkey in this case
	Identity      string `json:"identity"`
	AdminMetadata string `json:"admin_metadata"`
}

type ServerType string

const (
	OriginType ServerType = "origin"
	CacheType  ServerType = "cache"
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

func createNamespaceTable() {
	query := `
    CREATE TABLE IF NOT EXISTS namespace (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prefix TEXT NOT NULL UNIQUE,
        pubkey TEXT NOT NULL,
        identity TEXT,
        admin_metadata TEXT
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

func getPrefixJwksById(id int) (jwk.Set, error) {
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

func dbGetPrefixJwks(prefix string, adminApproval bool) (*jwk.Set, error) {
	var jwksQuery string
	var pubkeyStr string
	if strings.HasPrefix(prefix, "/caches/") && adminApproval {
		var admin_metadata string
		jwksQuery = `SELECT pubkey, admin_metadata FROM namespace WHERE prefix = ?`
		err := db.QueryRow(jwksQuery, prefix).Scan(&pubkeyStr, &admin_metadata)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, errors.New("prefix not found in database")
			}
			return nil, errors.Wrap(err, "error performing cache pubkey query")
		}

		var adminData AdminJSON
		err = json.Unmarshal([]byte(admin_metadata), &adminData)

		if !adminData.AdminApproved || err != nil {
			return nil, serverCredsErr
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
	_, err = tx.Exec(query, ns.Prefix, ns.Pubkey, ns.Identity, ns.AdminMetadata)
	if err != nil {
		if errRoll := tx.Rollback(); errRoll != nil {
			log.Errorln("Failed to rollback transaction:", errRoll)
		}
		return err
	}
	return tx.Commit()
}

/**
 * Commenting this out until we are ready to use it.  -BB
func updateNamespace(ns *Namespace) error {
	query := `UPDATE namespace SET pubkey = ?, identity = ?, admin_metadata = ? WHERE prefix = ?`
	_, err := db.Exec(query, ns.Pubkey, ns.Identity, ns.AdminMetadata, ns.Prefix)
	return err
}
*/

func deleteNamespace(prefix string) error {
	deleteQuery := `DELETE FROM namespace WHERE prefix = ?`
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	_, err = db.Exec(deleteQuery, prefix)
	if err != nil {
		if errRoll := tx.Rollback(); errRoll != nil {
			log.Errorln("Failed to rollback transaction:", errRoll)
		}
		return errors.Wrap(err, "Failed to execute deletion query")
	}
	return tx.Commit()
}

/**
 * Commenting this out until we are ready to use it.  -BB
func getNamespace(prefix string) (*Namespace, error) {
	ns := &Namespace{}
	query := `SELECT * FROM namespace WHERE prefix = ?`
	err := db.QueryRow(query, prefix).Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &ns.AdminMetadata)
	if err != nil {
		return nil, err
	}
	return ns, nil
}
*/

func getAllNamespaces() ([]*Namespace, error) {
	query := `SELECT * FROM namespace`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	namespaces := make([]*Namespace, 0)
	for rows.Next() {
		ns := &Namespace{}
		if err := rows.Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &ns.AdminMetadata); err != nil {
			return nil, err
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces, nil
}

func getNamespacesByServerType(serverType ServerType) ([]*Namespace, error) {
	query := ""
	if serverType == CacheType {
		// Refer to the cache prefix name in cmd/cache_serve
		query = `SELECT * FROM NAMESPACE WHERE PREFIX LIKE '/caches/%'`
	} else if serverType == OriginType {
		query = `SELECT * FROM NAMESPACE WHERE NOT PREFIX LIKE '/caches/%'`
	} else {
		return nil, errors.New(fmt.Sprint("Can't get namespace: unsupported server type: ", serverType))
	}

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	namespaces := make([]*Namespace, 0)
	for rows.Next() {
		ns := &Namespace{}
		if err := rows.Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &ns.AdminMetadata); err != nil {
			return nil, err
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces, nil
}

func InitializeDB() error {
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

func ShutdownDB() {
	err := db.Close()
	if err != nil {
		log.Errorln("Failure when shutting down the database:", err)
	}
}
