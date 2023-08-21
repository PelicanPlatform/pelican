package nsregistry

import (
	"database/sql"
	"path/filepath"
	"log"
	"os"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
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
	query := `DELETE FROM namespace WHERE prefix = ?`
	_, err := db.Exec(query, prefix)
	return err
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
	dbPath := viper.GetString("NSRegistryLocation")
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
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("Failed to open the database: %s", err)
		// log.Fatalf("Failed to open database: %v", err)
	}

	createNamespaceTable()
	return db.Ping()
}

