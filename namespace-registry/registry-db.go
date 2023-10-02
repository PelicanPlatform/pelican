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

package nsregistry

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"

	// commented sqlite driver requires CGO
	// _ "github.com/mattn/go-sqlite3" // SQLite driver
	_ "modernc.org/sqlite"
)

type Namespace struct {
	ID            int
	Prefix        string
	Pubkey        string
	Identity      string
	AdminMetadata string
}

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
		log.Fatalf("Failed to create table: %v", err)
	}
}

func namespaceExists(prefix string) (bool, error) {
	checkQuery := `SELECT prefix FROM namespace WHERE prefix = ?`
	result, err := db.Query(checkQuery, prefix)
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

func dbGetPrefixJwks(prefix string) (*jwk.Set, error) {
	jwksQuery := `SELECT pubkey FROM namespace WHERE prefix = ?`
	var pubkeyStr string
	err := db.QueryRow(jwksQuery, prefix).Scan(&pubkeyStr)
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

	return &set, nil
}

/*
Some generic functions for CRUD actions on namespaces,
used BY the registry (as opposed to the parallel
functions) used by the client.
*/
func addNamespace(ns *Namespace) error {
	query := `INSERT INTO namespace (prefix, pubkey, identity, admin_metadata) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(query, ns.Prefix, ns.Pubkey, ns.Identity, ns.AdminMetadata)
	return err
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
	_, err := db.Exec(deleteQuery, prefix)
	if err != nil {
		return errors.Wrap(err, "Failed to execute deletion query")
	}

	return nil
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

func InitializeDB() error {
	dbPath := param.NSRegistryLocation.GetString()
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

	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return errors.Wrapf(err, "Failed to open the database with path: %s", dbPath)
	}

	createNamespaceTable()
	return db.Ping()
}
