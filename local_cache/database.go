/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package local_cache

// Multi-Storage Architecture — Status
//
// The following items are already implemented in the current codebase:
//   - Usage keys are composite: PrefixUsage + storageID + namespaceID (see UsageKey)
//   - Inline data is tracked as a separate storage resource (StorageIDInline = 0)
//   - CacheMetadata includes StorageID to distinguish storage backends
//   - Block-state and usage updates are atomic (MergeBlockStateWithUsage)
//
// Future work for true multi-storage (multiple disk directories):
//   - Allow multiple storage directories with independent size limits
//   - Support device balancing (e.g., fast SSD vs large HDD)
//   - Make ConsistencyChecker and EvictionManager operate per-directory
//   - Add configurable InlineStorageMaxBytes limit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/sync/errgroup"
)

const (
	dbSubDir = "db"
)

// CacheDB wraps BadgerDB with cache-specific operations
type CacheDB struct {
	db      *badger.DB
	encMgr  *EncryptionManager
	baseDir string
	// salt is the random salt for hashing object/instance names.  Reads are
	// on the hot path (every ObjectHash and InstanceHash call, from arbitrary
	// goroutines) while writes happen twice at most -- at open, and again if
	// a catalog restore replaces the database underneath us -- so it is held
	// as an atomic pointer rather than under a lock.  A write publishes a
	// whole new slice; the slice a reader already loaded is never mutated,
	// which is what lets Salt hand it out directly.
	salt      atomic.Pointer[[]byte]
	closeOnce sync.Once

	// usageMu protects usageMergeOps for lazy creation of merge operators
	usageMu       sync.RWMutex
	usageMergeOps map[StorageUsageKey]*badger.MergeOperator

	// skipBudget overrides evictionSkipBudget when non-zero.  Set only by
	// tests, so that budget exhaustion can be exercised without building a
	// thousand protected objects.
	skipBudget int

	// readOnly marks a handle opened for offline introspection.  The
	// underlying BadgerDB is writable -- see OpenCacheDBReadOnly for why --
	// so this flag is what actually keeps an inspection tool from modifying
	// the database: every mutating entry point checks it first.
	readOnly bool

	// presignHold is how long after a pre-signed URL was handed out an
	// object is protected from eviction (0 = no protection).  Set during
	// single-threaded init via setPresignHold; read-only afterwards.
	presignHold time.Duration
}

// ErrReadOnly is returned by every mutating CacheDB method when the handle was
// opened for introspection.  Callers can test for it with errors.Is.
var ErrReadOnly = errors.New("the cache database is open read-only")

// checkWritable reports an error when this handle may not write.
func (cdb *CacheDB) checkWritable() error {
	if cdb.readOnly {
		return errors.Wrapf(ErrReadOnly, "refusing to modify the cache database at %s", cdb.baseDir)
	}
	return nil
}

// ReadOnly reports whether this handle refuses mutations.
func (cdb *CacheDB) ReadOnly() bool { return cdb.readOnly }

// setPresignHold configures the eviction protection window for objects with
// a recently issued pre-signed URL.  Must be called during single-threaded
// initialization.  It only sets an in-memory field (it is not a database
// write), so it is unexported and needs no read-only guard.
func (cdb *CacheDB) setPresignHold(d time.Duration) {
	cdb.presignHold = d
}

// cacheDBOptions builds the BadgerDB options shared by every way of opening a
// cache database.  Both the writable open and the introspection open must use
// identical settings: they differ in what Pelican allows, not in how the
// on-disk database is interpreted.
func cacheDBOptions(dbPath string, dbKey []byte) badger.Options {
	opts := badger.DefaultOptions(dbPath)

	// Performance: Disable synchronous writes for cache data
	// Risk: Power loss may lose last few seconds of 'access history' or 'download state'
	// Mitigation: Cache is self-healing; missing blocks will simply be re-downloaded
	opts.SyncWrites = false

	// Storage: Force small values into LSM tree
	// Bitmaps and usage counters need fast merge speeds
	opts.ValueThreshold = 4096

	// Reduce logging noise
	opts.Logger = newBadgerLogger()

	// Encrypt BadgerDB at rest so that metadata (ETags, URLs, timestamps)
	// stored in LSM tree and WAL files is not readable without the key.
	// We derive a separate key from the master key using HKDF for proper
	// key separation (the master key itself encrypts data blocks).
	opts.EncryptionKey = dbKey
	opts.EncryptionKeyRotationDuration = 0 // Disable rotation; we manage keys ourselves
	// BadgerDB requires IndexCacheSize > 0 when encryption is enabled
	opts.IndexCacheSize = 64 << 20 // 64 MB

	return opts
}

// NewCacheDB creates and initializes a new cache database.
//
// Requires issuer keys to be initialized via config.GetIssuerPublicJWKS() or
// InitIssuerKeyForTests() before calling this function.
func NewCacheDB(ctx context.Context, baseDir string) (*CacheDB, error) {
	dbPath := filepath.Join(baseDir, dbSubDir)

	// Ensure directory exists
	if err := os.MkdirAll(dbPath, 0750); err != nil {
		return nil, errors.Wrap(err, "failed to create database directory")
	}

	// Initialize encryption manager first
	encMgr, err := NewEncryptionManager(baseDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize encryption manager")
	}

	// Derive the database encryption key
	dbKey, err := encMgr.DeriveDBKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive database encryption key")
	}

	// Open the database
	db, err := badger.Open(cacheDBOptions(dbPath, dbKey))
	if err != nil {
		return nil, errors.Wrap(err, "failed to open BadgerDB")
	}

	cdb := &CacheDB{
		db:            db,
		encMgr:        encMgr,
		baseDir:       baseDir,
		usageMergeOps: make(map[StorageUsageKey]*badger.MergeOperator),
	}

	// Settle the schema version before writing anything else: a database
	// written by a newer binary must be refused untouched, not amended with a
	// salt or a store-mode marker on the way to failing.
	if err := cdb.ensureSchemaVersion(); err != nil {
		db.Close()
		return nil, err
	}

	// Load or generate the hash salt.  The salt is persisted in the DB
	// so that object/instance hashes are stable across restarts.
	salt, err := cdb.loadOrCreateSalt()
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to initialize hash salt")
	}
	cdb.setSalt(salt)

	log.Infof("Cache database initialized at %s", dbPath)
	return cdb, nil
}

// Close closes the database.  All usage MergeOperators are stopped first
// (blocking until their background goroutines exit) so that accumulated
// deltas are flushed before the DB is closed.
func (cdb *CacheDB) Close() error {
	var closeErr error
	cdb.closeOnce.Do(func() {
		cdb.usageMu.Lock()
		for key, op := range cdb.usageMergeOps {
			op.Stop()
			delete(cdb.usageMergeOps, key)
		}
		cdb.usageMu.Unlock()

		closeErr = cdb.db.Close()
	})
	return closeErr
}

// OpenCacheDBReadOnly opens an existing cache database for introspection.
// This is suitable for CLI tools that need to inspect cache contents without
// modifying anything.
//
// Like NewCacheDB, this requires issuer keys to be available for decrypting
// the database encryption key.
//
// "Read-only" is enforced by Pelican, not by BadgerDB.  BadgerDB's own
// ReadOnly mode cannot be used here:
//
//   - On Linux and macOS it aborts the process.  Opening an *encrypted*
//     database that has flushed at least one SST file read-only drives
//     Table.fetchIndex into y.Check(err) -> log.Fatalf, which prints
//     "err: invalid argument" and exits without returning an error or running
//     a single defer.  Every database NewCacheDB creates is encrypted and
//     every cache that has served an object has an SST, so this fired on
//     every real cache.
//   - On Windows it is refused outright ("Read-only mode is not supported on
//     Windows").
//
// So the database is opened the ordinary way and mutation is refused in Go
// instead, via the readOnly flag that checkWritable guards every writing entry
// point with.  This is the same trade pstore.OpenMaintenance makes.
//
// What that costs is BadgerDB's exclusive directory lock, which an ordinary
// open takes: introspection now fails while a cache is running rather than
// opening alongside it.  That is acceptable -- offline introspection is only
// reached when the cache is not running, since the CLI routes to the live
// service otherwise -- and it is arguably better, because holding the lock
// stops a cache from starting up underneath an introspection in progress.
// A lock failure is translated into an explanation of exactly that, since
// "another process is using this Badger database" is not something an operator
// should have to decode.
//
// What it does not cost is the guarantee the read-only path exists for: this
// open still never stamps a schema version (VerifySchemaVersion only checks)
// and never claims a store mode (EnsureStoreMode is not called), so
// inspecting a database leaves its header exactly as it was found.
func OpenCacheDBReadOnly(baseDir string) (*CacheDB, error) {
	dbPath := filepath.Join(baseDir, dbSubDir)

	// An introspection open must not bring a database into existence.
	// badger.Open would happily create the directory and an empty database in
	// it, leaving the operator to wonder why their cache looks empty; a
	// mistyped path should say so instead.
	if info, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("no cache database at %s; check that this is a cache "+
				"storage location (Cache.StorageLocation)", dbPath)
		}
		return nil, errors.Wrapf(err, "failed to inspect the cache database at %s", dbPath)
	} else if !info.IsDir() {
		return nil, errors.Errorf("%s is not a directory, so it does not hold a cache database", dbPath)
	}

	// Initialize encryption manager to get the database key
	encMgr, err := NewEncryptionManager(baseDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize encryption manager")
	}

	// Derive the database encryption key
	dbKey, err := encMgr.DeriveDBKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive database encryption key")
	}

	db, err := badger.Open(cacheDBOptions(dbPath, dbKey))
	if err != nil {
		if locked := explainDirectoryLock(baseDir, err); locked != nil {
			return nil, locked
		}
		return nil, errors.Wrap(err, "failed to open BadgerDB for introspection")
	}

	cdb := &CacheDB{
		db:            db,
		encMgr:        encMgr,
		baseDir:       baseDir,
		readOnly:      true,
		usageMergeOps: make(map[StorageUsageKey]*badger.MergeOperator),
	}

	// Refuse a database whose layout this binary does not understand before
	// reading a single record out of it.  Unlike NewCacheDB this only
	// verifies: an introspection tool must leave no fingerprints on a database
	// it is merely looking at, so it neither stamps a version nor claims a
	// store mode.  That is the same reasoning that keeps EnsureStoreMode out
	// of this path.
	if err := cdb.VerifySchemaVersion(); err != nil {
		db.Close()
		return nil, err
	}

	// Load the hash salt.  Unlike loadOrCreateSalt this refuses to generate
	// one: without the original salt no stored hash can be recomputed, so a
	// fresh salt would make every object in the database unfindable while
	// looking like success -- and writing it would be a modification besides.
	err = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(KeySalt))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			salt := make([]byte, len(val))
			copy(salt, val)
			cdb.setSalt(salt)
			return nil
		})
	})
	if err != nil {
		db.Close()
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.Errorf("the database at %s carries no hash salt, so it holds no "+
				"cache contents to inspect", dbPath)
		}
		return nil, errors.Wrap(err, "failed to load hash salt")
	}

	log.Debugf("Cache database opened for introspection at %s", dbPath)
	return cdb, nil
}

// explainDirectoryLock recognizes BadgerDB's directory-lock failure and
// restates it in terms an operator can act on.  It returns nil when err is
// some other failure.
//
// BadgerDB reports this as "Cannot acquire directory lock on %q.  Another
// process is using this Badger database." (dir_unix.go) or "Cannot create lock
// file %q.  Another process is using this Badger database" (dir_windows.go),
// wrapping the underlying EWOULDBLOCK or sharing violation.  Neither says the
// one thing the operator needs to know: the cache server is running, and the
// same information is available from it.
func explainDirectoryLock(baseDir string, err error) error {
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "Another process is using this Badger database") {
		return nil
	}
	return errors.Wrapf(err,
		"the cache database at %s is locked by another process, which almost always means "+
			"the cache server is running; offline introspection requires the cache to be "+
			"stopped, so either stop it or let the command query the running cache instead "+
			"-- drop --offline if you passed it, and otherwise the running cache could not "+
			"be found automatically, which usually means its address file is unreadable",
		baseDir)
}

// StartGC starts the background garbage collection goroutine.
//
// Value-log GC rewrites the value log, so a read-only handle starts nothing.
func (cdb *CacheDB) StartGC(ctx context.Context, egrp *errgroup.Group) {
	if cdb.readOnly {
		return
	}
	egrp.Go(func() error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				err := cdb.db.RunValueLogGC(0.5)
				if err != nil && !errors.Is(err, badger.ErrNoRewrite) {
					log.Warnf("BadgerDB GC error: %v", err)
				}
			}
		}
	})
}

// GetEncryptionManager returns the encryption manager
func (cdb *CacheDB) GetEncryptionManager() *EncryptionManager {
	return cdb.encMgr
}

// loadOrCreateSalt reads the hash salt from the DB, or generates a new
// random salt and persists it if none exists yet.
func (cdb *CacheDB) loadOrCreateSalt() ([]byte, error) {
	var salt []byte
	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(KeySalt))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			salt = make([]byte, len(val))
			copy(salt, val)
			return nil
		})
	})
	if err == nil {
		return salt, nil
	}
	if !errors.Is(err, badger.ErrKeyNotFound) {
		return nil, err
	}

	// No salt yet — generate one.
	salt = make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.Wrap(err, "failed to generate random salt")
	}
	if err := cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(KeySalt), salt)
	}); err != nil {
		return nil, errors.Wrap(err, "failed to persist hash salt")
	}
	return salt, nil
}

// Salt returns the per-database random salt used for hashing.
//
// The returned slice is shared with every other caller and with the database
// itself; callers must treat it as read-only.  Nothing in the tree writes
// through it -- both consumers hand it straight to hmac.New, which copies --
// and a caller that did would corrupt every hash computed concurrently.
func (cdb *CacheDB) Salt() []byte {
	if p := cdb.salt.Load(); p != nil {
		return *p
	}
	return nil
}

// setSalt publishes a new salt.
func (cdb *CacheDB) setSalt(salt []byte) {
	cdb.salt.Store(&salt)
}

// ReloadSalt re-reads the hash salt from the database.
//
// The salt is cached at open because it is on the hot path, which is fine
// until something replaces the database's contents underneath it.  Restoring
// a backup does exactly that: the restored salt is the one every instance
// hash in that catalog was derived from, so a consumer still holding the salt
// generated at open computes different hashes and finds none of its objects.
func (cdb *CacheDB) ReloadSalt() error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	salt, err := cdb.loadOrCreateSalt()
	if err != nil {
		return errors.Wrap(err, "failed to reload the hash salt")
	}
	cdb.setSalt(salt)
	return nil
}

// DB exposes the underlying BadgerDB handle.
//
// This exists for sibling subsystems that store their own records in this
// key space and need transactional semantics the typed helpers above do not
// provide — read-your-writes transactions spanning several keys, and prefix
// iteration with seeks.  The pstore origin backend
// (see docs/pstore-design.md) is the only such consumer today.
//
// Callers must confine themselves to prefixes they own, and must call
// EnsureStoreMode first so that a cache and a pstore can never operate on the
// same database.
//
// This is the one way past the read-only guard: the handle it returns is a
// writable BadgerDB even when ReadOnly reports true (see OpenCacheDBReadOnly
// for why the underlying database is not opened read-only).  A consumer that
// honors read-only opens must consult ReadOnly before writing through it --
// pstore does, in Store.checkWritable.
func (cdb *CacheDB) DB() *badger.DB { return cdb.db }

// EnsureStoreMode records which subsystem owns this database, or verifies that
// a previously recorded owner matches.
//
// Caches and pstore origins share one key space (see the prefix constants in
// schema.go), so opening one as the other would silently corrupt it.  Every
// consumer must call this immediately after opening.
//
// A database with no marker is adopted when it is empty.  A non-empty database
// with no marker is necessarily a legacy cache — pstore always writes the
// marker — so adopting it is allowed only for StoreModeCache.
//
// The other half of the database header, the schema version, is settled by
// NewCacheDB before this runs: a layout this binary cannot read is refused
// before anyone asks who owns it, because the ownership marker is itself just
// another record written under that layout.
func (cdb *CacheDB) EnsureStoreMode(mode StoreMode) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(KeyStoreMode))
		if err == nil {
			var found StoreMode
			if vErr := item.Value(func(val []byte) error {
				found = StoreMode(val)
				return nil
			}); vErr != nil {
				return errors.Wrap(vErr, "failed to read store mode marker")
			}
			if found != mode {
				return errors.Errorf(
					"database at %s belongs to a %q store but was opened as a %q store; "+
						"refusing to continue because the two share a key space",
					cdb.baseDir, string(found), string(mode))
			}
			return nil
		}
		if !errors.Is(err, badger.ErrKeyNotFound) {
			return errors.Wrap(err, "failed to read store mode marker")
		}

		// No marker.  Adopt it only if that cannot mislabel existing data.
		if mode != StoreModeCache {
			empty, cErr := txnIsEmptyApartFromHeader(txn)
			if cErr != nil {
				return cErr
			}
			if !empty {
				return errors.Errorf(
					"database at %s holds data but no store mode marker, so it is a "+
						"pre-existing cache; refusing to open it as a %q store",
					cdb.baseDir, string(mode))
			}
		}
		return txn.Set([]byte(KeyStoreMode), []byte(mode))
	})
}

// ensureSchemaVersion records the schema version of this database, or verifies
// that a previously recorded version is one this binary can work with.
//
// Called from NewCacheDB, so it covers every writable consumer of the block
// store — the cache and the pstore origin backend alike — before either of
// them interprets a record.
//
// Four cases:
//
//   - No version key.  Every database created before versioning existed is in
//     this state, as is a brand new one.  Both are stamped with
//     CurrentSchemaVersion: the layout an unversioned database holds is, by
//     definition, the one the last unversioned binary wrote, which is the
//     layout this binary reads.  Adopting rather than refusing is deliberate;
//     the alternative would break every deployed cache on upgrade.  This
//     mirrors how EnsureStoreMode adopts an unmarked database as a cache.
//   - Version equals CurrentSchemaVersion.  Nothing to do.
//   - Version is older.  Handed to migrateSchema, and re-stamped once that
//     succeeds.  No release has ever written a version below the current one,
//     so today this only happens to a hand-edited or damaged marker, and
//     migrateSchema — having no migration to offer — refuses it.
//   - Version is newer.  Refused: this binary would read the records with the
//     wrong rules, which is precisely the corruption versioning exists to
//     prevent.
func (cdb *CacheDB) ensureSchemaVersion() error {
	return cdb.db.Update(func(txn *badger.Txn) error {
		found, ok, err := readSchemaVersion(txn)
		if err != nil {
			return err
		}
		switch {
		case !ok:
			empty, cErr := txnIsEmptyApartFromHeader(txn)
			if cErr != nil {
				return cErr
			}
			if !empty {
				log.Infof("Block store database at %s predates schema versioning; "+
					"adopting it as schema version %d", cdb.baseDir, CurrentSchemaVersion)
			}
		case found == CurrentSchemaVersion:
			return nil
		case found > CurrentSchemaVersion:
			return cdb.errSchemaTooNew(found)
		default:
			if err := migrateSchema(txn, found); err != nil {
				return errors.Wrapf(err, "failed to migrate the block store database at %s "+
					"from schema version %d to %d", cdb.baseDir, found, CurrentSchemaVersion)
			}
			log.Infof("Migrated the block store database at %s from schema version %d to %d",
				cdb.baseDir, found, CurrentSchemaVersion)
		}
		return txn.Set([]byte(KeySchemaVersion), formatSchemaVersion(CurrentSchemaVersion))
	})
}

// VerifySchemaVersion is the read-only counterpart of ensureSchemaVersion: it
// refuses a database written under a newer schema but never writes, so it can
// run inside a read-only BadgerDB handle (see OpenCacheDBReadOnly).
//
// A database with no version key is accepted as CurrentSchemaVersion for the
// same reason ensureSchemaVersion adopts one, minus the stamp — introspecting
// a cache must not require write access to it.  An older version is likewise
// accepted: the writable open is where migration happens, and refusing to
// *look* at a database that a normal start would quietly upgrade helps nobody.
//
// It is exported for the same reason EnsureStoreMode is: a consumer that
// replaces this database's contents wholesale — restoring a backup catalog
// into it — has a database whose header keys came from wherever the backup did
// and no longer describe what was checked at open, and should re-verify.
func (cdb *CacheDB) VerifySchemaVersion() error {
	return cdb.db.View(func(txn *badger.Txn) error {
		found, ok, err := readSchemaVersion(txn)
		if err != nil {
			return err
		}
		if ok && found > CurrentSchemaVersion {
			return cdb.errSchemaTooNew(found)
		}
		return nil
	})
}

// errSchemaTooNew builds the error returned when the database was written by a
// binary that understands a later layout than this one does.
func (cdb *CacheDB) errSchemaTooNew(found SchemaVersion) error {
	return errors.Errorf(
		"database at %s uses block store schema version %d, but this build of Pelican "+
			"supports up to version %d; refusing to open it because reading a newer "+
			"layout with older rules would corrupt it -- upgrade Pelican to a release "+
			"that supports schema version %d",
		cdb.baseDir, found, CurrentSchemaVersion, found)
}

// readSchemaVersion reads the schema version marker.  ok is false when the
// database carries no marker at all.
func readSchemaVersion(txn *badger.Txn) (version SchemaVersion, ok bool, err error) {
	item, err := txn.Get([]byte(KeySchemaVersion))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return 0, false, nil
		}
		return 0, false, errors.Wrap(err, "failed to read the schema version marker")
	}
	if err = item.Value(func(val []byte) error {
		parsed, pErr := strconv.ParseUint(string(val), 10, 32)
		if pErr != nil {
			return errors.Errorf("schema version marker holds %q, which is not a version number", string(val))
		}
		version = SchemaVersion(parsed)
		return nil
	}); err != nil {
		return 0, false, errors.Wrap(err, "failed to read the schema version marker")
	}
	return version, true, nil
}

// formatSchemaVersion renders a version for storage, matching the plain-text
// style of the other header keys.
func formatSchemaVersion(v SchemaVersion) []byte {
	return []byte(strconv.FormatUint(uint64(v), 10))
}

// migrateSchema brings a database written under schema version `from` up to
// CurrentSchemaVersion.  Its caller re-stamps the marker once it returns.
//
// There is exactly one schema version today, so no database Pelican ever wrote
// reaches this function and it has nothing to do but refuse; it is the seam a
// future version hooks into.  Refusing rather than shrugging is the point of
// the default: whoever bumps CurrentSchemaVersion without teaching this
// function about the step gets a loud, specific failure instead of a binary
// that reads old records under new rules.
//
// A migration to version N is expected to rewrite, in place, every record
// whose layout changed between N-1 and N — and to be idempotent, since a crash
// part-way through leaves the old stamp in place and the migration runs again
// on the next open.  Handle each version step separately (`for v := from; v <
// CurrentSchemaVersion; v++`) so that a database several versions behind is
// carried forward one step at a time rather than needing a bespoke path per
// starting point.
//
// A migration too large for one BadgerDB transaction should not be forced into
// this txn: give it a method on CacheDB that batches its own writes, call that
// from ensureSchemaVersion before the stamping transaction, and leave this
// function for the cheap in-place cases.
func migrateSchema(txn *badger.Txn, from SchemaVersion) error {
	if from == 1 {
		// 1 -> 2 rewrites nothing: the S3 layout only adds key prefixes (up:,
		// ps:) that a version-1 database simply has none of, and the new
		// DiskMapping.Backend field decodes as BackendPosix when absent, which
		// is what every mapping written under version 1 is.  Stamping the new
		// version is the whole migration; see CurrentSchemaVersion for why the
		// stamp matters even so.
		return nil
	}
	return errors.Errorf("no migration is available from schema version %d", from)
}

// txnIsEmptyApartFromHeader reports whether the database holds no records
// other than the header keys that describe the database itself (the hash salt,
// which NewCacheDB writes before any consumer runs, the schema version stamped
// alongside it, and the store mode marker).  None of those says anything about
// which subsystem's records the database holds, so a database carrying only
// them is still up for adoption.
func txnIsEmptyApartFromHeader(txn *badger.Txn) (bool, error) {
	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = false
	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		switch string(it.Item().Key()) {
		case KeySalt, KeySchemaVersion, KeyStoreMode:
			continue
		default:
			return false, nil
		}
	}
	return true, nil
}

// ObjectHash computes the salted SHA-256 hash for a pelican URL.
func (cdb *CacheDB) ObjectHash(pelicanURL string) ObjectHash {
	return ComputeObjectHash(cdb.Salt(), pelicanURL)
}

// InstanceHash computes the salted SHA-256 hash for (etag, objectHash).
func (cdb *CacheDB) InstanceHash(etag string, objectHash ObjectHash) InstanceHash {
	return ComputeInstanceHash(cdb.Salt(), etag, objectHash)
}

// --- Metadata Operations ---

// GetMetadata retrieves cache metadata for a file
func (cdb *CacheDB) GetMetadata(instanceHash InstanceHash) (*CacheMetadata, error) {
	var meta CacheMetadata

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(MetaKey(instanceHash))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return msgpack.Unmarshal(val, &meta)
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get metadata")
	}

	return &meta, nil
}

// SetMetadata stores cache metadata for a file, unconditionally replacing
// any previously stored metadata.  Use this only for initial creation of a
// metadata entry (e.g. InitDiskStorage, StoreInline); for subsequent updates
// prefer MergeMetadata which applies field-level merge semantics.
func (cdb *CacheDB) SetMetadata(instanceHash InstanceHash, meta *CacheMetadata) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	data, err := msgpack.Marshal(meta)
	if err != nil {
		return errors.Wrap(err, "failed to marshal metadata")
	}

	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(MetaKey(instanceHash), data)
	})
}

// MergeMetadata performs an atomic read-modify-update of the metadata for
// instanceHash.  If no metadata exists yet, incoming is written as-is (initial
// creation).
//
// Field-level merge rules:
//
//   - Max-time (LastModified, LastValidated, LastAccessTime, Expires,
//     Completed): keep the later of existing vs incoming.
//   - Additive (Checksums): union by ChecksumType; if both sides provide the
//     same Type, prefer the OriginVerified entry.
//   - Last-writer-wins (ContentType, ContentLength, VaryHeaders, CCFlags,
//     CCMaxAge): incoming replaces existing when the incoming value is non-zero /
//     non-empty.
//   - Set-once (ETag, SourceURL, DataKey, StorageID, NamespaceID): may transition
//     from zero-value to a value, but changing a non-zero value to a different
//     non-zero value returns an error.  ETag is set-once because it is part of
//     the instance hash; a changed ETag produces a different instance.
//
// The method retries on BadgerDB transaction conflicts, which can occur when
// multiple concurrent callers merge metadata for the same instance (e.g.
// concurrent range-on-miss initialization via initObjectFromStat).
func (cdb *CacheDB) MergeMetadata(instanceHash InstanceHash, incoming *CacheMetadata) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	const maxRetries = 20
	backoff := 100 * time.Microsecond
	for attempt := 0; ; attempt++ {
		err := cdb.db.Update(func(txn *badger.Txn) error {
			existing, err := getMetadataInTxn(txn, instanceHash)
			if err != nil {
				return errors.Wrap(err, "failed to read existing metadata for merge")
			}

			merged := incoming
			if existing != nil {
				if err := mergeMetadataFields(existing, incoming); err != nil {
					return err
				}
				merged = existing // existing was mutated in place
			}

			data, err := msgpack.Marshal(merged)
			if err != nil {
				return errors.Wrap(err, "failed to marshal merged metadata")
			}
			return txn.Set(MetaKey(instanceHash), data)
		})
		if err == nil {
			return nil
		}
		if errors.Is(err, badger.ErrConflict) && attempt < maxRetries-1 {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(backoff)))
			jitter := time.Duration(n.Int64())
			time.Sleep(backoff + jitter)
			backoff *= 2
			if backoff > 50*time.Millisecond {
				backoff = 50 * time.Millisecond
			}
			continue
		}
		return err
	}
}

// mergeMetadataFields applies incoming field values into existing according to
// the merge semantics documented on CacheMetadata.  It mutates existing in place.
func mergeMetadataFields(existing, incoming *CacheMetadata) error {
	// --- Max-time fields ---
	if incoming.LastModified.After(existing.LastModified) {
		existing.LastModified = incoming.LastModified
	}
	if incoming.LastValidated.After(existing.LastValidated) {
		existing.LastValidated = incoming.LastValidated
	}
	if incoming.LastAccessTime.After(existing.LastAccessTime) {
		existing.LastAccessTime = incoming.LastAccessTime
	}
	if incoming.Expires.After(existing.Expires) {
		existing.Expires = incoming.Expires
	}
	if incoming.Completed.After(existing.Completed) {
		existing.Completed = incoming.Completed
	}
	if incoming.DataVerified.After(existing.DataVerified) {
		existing.DataVerified = incoming.DataVerified
	}

	// --- Additive: Checksums ---
	existing.Checksums = mergeChecksums(existing.Checksums, incoming.Checksums)

	// --- Last-writer-wins (non-zero incoming replaces existing) ---
	if incoming.ContentType != "" {
		existing.ContentType = incoming.ContentType
	}
	if incoming.ContentLength != 0 {
		existing.ContentLength = incoming.ContentLength
	}
	if len(incoming.VaryHeaders) > 0 {
		existing.VaryHeaders = incoming.VaryHeaders
	}
	if incoming.CCFlags != 0 {
		existing.CCFlags = incoming.CCFlags
	}
	if incoming.CCMaxAge != 0 {
		existing.CCMaxAge = incoming.CCMaxAge
	}

	// --- Set-once fields ---
	if err := mergeSetOnce("ETag", &existing.ETag, incoming.ETag); err != nil {
		return err
	}
	if err := mergeSetOnce("SourceURL", &existing.SourceURL, incoming.SourceURL); err != nil {
		return err
	}
	if err := mergeSetOnceBytes("DataKey", &existing.DataKey, incoming.DataKey); err != nil {
		return err
	}
	if err := mergeSetOnceComparable("StorageID", &existing.StorageID, incoming.StorageID); err != nil {
		return err
	}
	if err := mergeSetOnceComparable("NamespaceID", &existing.NamespaceID, incoming.NamespaceID); err != nil {
		return err
	}

	return nil
}

// mergeChecksums returns the union of two checksum slices.  If both sides
// contain the same ChecksumType, the OriginVerified entry wins; ties go to
// incoming.
func mergeChecksums(existing, incoming []Checksum) []Checksum {
	if len(incoming) == 0 {
		return existing
	}
	if len(existing) == 0 {
		return incoming
	}

	// Build map keyed by ChecksumType.
	byType := make(map[ChecksumType]Checksum, len(existing)+len(incoming))
	for _, c := range existing {
		byType[c.Type] = c
	}
	for _, c := range incoming {
		prev, ok := byType[c.Type]
		if !ok || c.OriginVerified || !prev.OriginVerified {
			byType[c.Type] = c
		}
	}

	result := make([]Checksum, 0, len(byType))
	for _, c := range byType {
		result = append(result, c)
	}
	return result
}

// mergeSetOnce enforces set-once semantics for a string field.
func mergeSetOnce(name string, existing *string, incoming string) error {
	if incoming == "" {
		return nil // incoming is zero-value, no change
	}
	if *existing == "" {
		*existing = incoming
		return nil
	}
	if *existing != incoming {
		return errors.Errorf("set-once field %s: cannot change %q to %q", name, *existing, incoming)
	}
	return nil
}

// mergeSetOnceBytes enforces set-once semantics for a []byte field.
func mergeSetOnceBytes(name string, existing *[]byte, incoming []byte) error {
	if len(incoming) == 0 {
		return nil
	}
	if len(*existing) == 0 {
		*existing = incoming
		return nil
	}
	if !bytes.Equal(*existing, incoming) {
		return errors.Errorf("set-once field %s: cannot change non-zero value", name)
	}
	return nil
}

// mergeSetOnceComparable enforces set-once semantics for a comparable field.
func mergeSetOnceComparable[T comparable](name string, existing *T, incoming T) error {
	var zero T
	if incoming == zero {
		return nil
	}
	if *existing == zero {
		*existing = incoming
		return nil
	}
	if *existing != incoming {
		return errors.Errorf("set-once field %s: cannot change value", name)
	}
	return nil
}

// DeleteMetadata removes metadata for a file
func (cdb *CacheDB) DeleteMetadata(instanceHash InstanceHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(MetaKey(instanceHash))
	})
}

// --- ETag Operations ---

// GetLatestETag retrieves the latest ETag for an object.
// Returns (etag, found, err).  An object cached without an ETag will
// return ("", true, nil); an object not in the cache returns ("", false, nil).
func (cdb *CacheDB) GetLatestETag(objectHash ObjectHash) (string, bool, error) {
	var etag string

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(ETagKey(objectHash))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			etag, _ = decodeETagEntry(val)
			return nil
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return "", false, nil
		}
		return "", false, errors.Wrap(err, "failed to get latest ETag")
	}

	return etag, true, nil
}

// SetLatestETag stores the latest ETag for an object, but only if
// observedAt is more recent than the already-stored timestamp.  This
// prevents a slow download that finishes late from clobbering a newer
// ETag written by a more recent request.
func (cdb *CacheDB) SetLatestETag(objectHash ObjectHash, etag string, observedAt time.Time) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	key := ETagKey(objectHash)
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Read-modify-write: only update if newer.
		item, err := txn.Get(key)
		if err == nil {
			var existing time.Time
			_ = item.Value(func(val []byte) error {
				_, existing = decodeETagEntry(val)
				return nil
			})
			if !existing.IsZero() && !observedAt.After(existing) {
				return nil // existing entry is at least as recent
			}
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return txn.Set(key, encodeETagEntry(etag, observedAt))
	})
}

// DeleteLatestETag removes the ETag entry for an object
func (cdb *CacheDB) DeleteLatestETag(objectHash ObjectHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(ETagKey(objectHash))
	})
}

// encodeETagEntry packs an ETag and observation timestamp into a single
// byte slice: [8-byte big-endian Unix-nano timestamp][etag bytes].
func encodeETagEntry(etag string, observedAt time.Time) []byte {
	buf := make([]byte, 8+len(etag))
	binary.BigEndian.PutUint64(buf[:8], uint64(observedAt.UnixNano()))
	copy(buf[8:], etag)
	return buf
}

// decodeETagEntry unpacks an encoded ETag entry.  For legacy entries
// (no timestamp prefix), the returned time is zero.
func decodeETagEntry(val []byte) (string, time.Time) {
	if len(val) < 8 {
		return string(val), time.Time{}
	}
	nanos := int64(binary.BigEndian.Uint64(val[:8]))
	return string(val[8:]), time.Unix(0, nanos)
}

// --- Namespace Mapping Operations ---

// SetNamespaceMapping persists the mapping from a namespace prefix string
// to a numeric ID.  This ensures the IDs survive restarts so that LRU
// keys and usage counters remain valid.
func (cdb *CacheDB) SetNamespaceMapping(prefix string, id NamespaceID) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, uint32(id))
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(NamespaceKey(prefix), val)
	})
}

// LoadNamespaceMappings loads all persisted namespace mappings and returns
// them as a map[prefix]->id, along with the highest ID seen (so the
// caller can resume the counter).
func (cdb *CacheDB) LoadNamespaceMappings() (map[string]NamespaceID, NamespaceID, error) {
	result := make(map[string]NamespaceID)
	var maxID NamespaceID

	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixNamespace)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := string(item.Key()[len(prefix):])

			err := item.Value(func(val []byte) error {
				if len(val) != 4 {
					return errors.Errorf("invalid namespace ID value for %s", key)
				}
				id := NamespaceID(binary.LittleEndian.Uint32(val))
				result[key] = id
				if id > maxID {
					maxID = id
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to load namespace mappings")
	}
	return result, maxID, nil
}

// --- Disk Mapping Operations ---

// DiskMappingKey returns the BadgerDB key for a disk mapping entry.
func DiskMappingKey(storageID StorageID) []byte {
	return []byte(fmt.Sprintf("%s%d", PrefixDiskMap, storageID))
}

// SaveDiskMapping persists a single storageID → (UUID, directory) mapping.
func (cdb *CacheDB) SaveDiskMapping(dm DiskMapping) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	data, err := msgpack.Marshal(&dm)
	if err != nil {
		return errors.Wrap(err, "failed to marshal disk mapping")
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(DiskMappingKey(dm.ID), data)
	})
}

// LoadDiskMappings loads all persisted disk mappings.
func (cdb *CacheDB) LoadDiskMappings() ([]DiskMapping, error) {
	var mappings []DiskMapping
	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixDiskMap)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			err := it.Item().Value(func(val []byte) error {
				var dm DiskMapping
				if err := msgpack.Unmarshal(val, &dm); err != nil {
					return err
				}
				mappings = append(mappings, dm)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to load disk mappings")
	}
	return mappings, nil
}

// --- Block State Operations ---

// GetBlockState retrieves the bitmap of downloaded blocks for a file.
//
// If the block-state key is absent but the object's metadata indicates a
// completed download, a fully-populated bitmap is returned.  This allows
// callers to treat completed objects uniformly without requiring a
// separate completion check.  The block-state key is removed on
// completion to save database space (see BlockWriter.Close).
func (cdb *CacheDB) GetBlockState(instanceHash InstanceHash) (*roaring.Bitmap, error) {
	bitmap := roaring.New()

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(StateKey(instanceHash))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				// No block state key.  If the metadata says the
				// download is complete, synthesize a full bitmap.
				meta, metaErr := getMetadataInTxn(txn, instanceHash)
				if metaErr != nil || meta == nil {
					return nil // truly empty — no metadata either
				}
				if !meta.Completed.IsZero() && meta.ContentLength > 0 {
					totalBlocks := CalculateBlockCount(meta.ContentLength)
					bitmap.AddRange(0, uint64(totalBlocks))
				}
				return nil
			}
			return err
		}

		return item.Value(func(val []byte) error {
			_, err := bitmap.FromBuffer(val)
			return err
		})
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to get block state")
	}

	return bitmap, nil
}

// SetBlockState stores the bitmap of downloaded blocks
func (cdb *CacheDB) SetBlockState(instanceHash InstanceHash, bitmap *roaring.Bitmap) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	data, err := bitmap.ToBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize bitmap")
	}

	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(StateKey(instanceHash), data)
	})
}

// MergeBlockStateWithUsage atomically merges new blocks into the existing bitmap
// AND updates usage statistics based on the number of newly-enabled bits.
//
// contentLength controls how the usage delta is calculated:
//   - If >= 0, the supplied contentLength, storageID, and namespaceID are used
//     directly, avoiding a metadata DB read.
//   - If < 0 (typically -1), the metadata is read within the transaction
//     to obtain the content length, storage ID, and namespace ID.
//
// The method retries on BadgerDB transaction conflicts, which can occur when
// multiple concurrent block fetchers write to the same object's bitmap.
func (cdb *CacheDB) MergeBlockStateWithUsage(instanceHash InstanceHash, newBlocks *roaring.Bitmap, storageID StorageID, namespaceID NamespaceID, contentLength int64) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	newData, err := newBlocks.ToBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize new blocks bitmap")
	}

	const maxRetries = 20
	backoff := 100 * time.Microsecond
	for attempt := 0; ; attempt++ {
		err := cdb.db.Update(func(txn *badger.Txn) error {
			return cdb.mergeBlockStateWithUsageTxn(txn, instanceHash, newData, newBlocks, storageID, namespaceID, contentLength)
		})
		if err == nil {
			return nil
		}
		if errors.Is(err, badger.ErrConflict) && attempt < maxRetries-1 {
			// Exponential backoff with jitter to avoid thundering herd
			// when many concurrent writers conflict on the same bitmap.
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(backoff)))
			jitter := time.Duration(n.Int64())
			time.Sleep(backoff + jitter)
			backoff *= 2
			if backoff > 50*time.Millisecond {
				backoff = 50 * time.Millisecond
			}
			continue
		}
		return err
	}
}

func (cdb *CacheDB) mergeBlockStateWithUsageTxn(txn *badger.Txn, instanceHash InstanceHash, newData []byte, newBlocks *roaring.Bitmap, storageID StorageID, namespaceID NamespaceID, contentLength int64) error {
	// Only merge the block bitmap.  Usage is now charged upfront at
	// file-creation time (InitDiskStorage / AllocateChunk / StoreInline)
	// to match the filesystem's pre-allocation.
	//
	// The function is kept separate from mergeBlocKStateInTxn in case we
	// ever want to do some interesting usage accounting.
	_, err := mergeBlockStateInTxn(txn, instanceHash, newData)
	return err
}

// mergeBlockStateInTxn performs the bitmap merge within an existing transaction.
// Returns the number of newly-enabled bits (blocks that were not previously set).
func mergeBlockStateInTxn(txn *badger.Txn, instanceHash InstanceHash, newData []byte) (uint64, error) {
	key := StateKey(instanceHash)

	// Get existing bitmap
	existing := roaring.New()
	item, err := txn.Get(key)
	if err == nil {
		err = item.Value(func(val []byte) error {
			_, err := existing.FromBuffer(val)
			return err
		})
		if err != nil {
			return 0, errors.Wrap(err, "failed to deserialize existing bitmap")
		}
	} else if !errors.Is(err, badger.ErrKeyNotFound) {
		return 0, err
	}

	previousCardinality := existing.GetCardinality()

	// Merge bitmaps using OR operation
	newBitmap := roaring.New()
	if _, err := newBitmap.FromBuffer(newData); err != nil {
		return 0, errors.Wrap(err, "failed to deserialize new bitmap")
	}
	existing.Or(newBitmap)

	newCardinality := existing.GetCardinality()

	// Save merged result
	mergedData, err := existing.ToBytes()
	if err != nil {
		return 0, errors.Wrap(err, "failed to serialize merged bitmap")
	}

	if err := txn.Set(key, mergedData); err != nil {
		return 0, err
	}

	return newCardinality - previousCardinality, nil
}

// getMetadataInTxn reads CacheMetadata within an existing transaction.
// Returns nil (not an error) if the key does not exist.
func getMetadataInTxn(txn *badger.Txn, instanceHash InstanceHash) (*CacheMetadata, error) {
	item, err := txn.Get(MetaKey(instanceHash))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, err
	}

	var meta CacheMetadata
	err = item.Value(func(val []byte) error {
		return msgpack.Unmarshal(val, &meta)
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal metadata in txn")
	}
	return &meta, nil
}

// encodeUsage serializes an int64 usage value into 8 little-endian bytes.
func encodeUsage(v int64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(v))
	return buf
}

// decodeUsage deserializes 8 little-endian bytes into an int64 usage value,
// clamping negative values to zero.  Returns 0 if the slice is too short.
func decodeUsage(b []byte) int64 {
	if len(b) < 8 {
		return 0
	}
	v := int64(binary.LittleEndian.Uint64(b))
	if v < 0 {
		return 0
	}
	return v
}

// decodeUsageRaw is like decodeUsage but does not clamp negative values.
// It is used by usageMergeFunc where intermediate negative totals must
// be preserved so that out-of-order deltas eventually converge.
func decodeUsageRaw(b []byte) int64 {
	if len(b) < 8 {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(b))
}

// usageMergeFunc is the merge function for BadgerDB MergeOperators.
// Both existingVal and newVal are 8-byte little-endian int64 values.
// The result is their sum.  Intermediate negative totals are allowed
// (e.g. when deletion deltas arrive before the corresponding charge)
// and are clamped to zero at read time.
func usageMergeFunc(existingVal, newVal []byte) []byte {
	return encodeUsage(decodeUsageRaw(existingVal) + decodeUsageRaw(newVal))
}

// usageCompactionInterval controls how often the MergeOperator background
// goroutine compacts accumulated delta versions into a single value.
const usageCompactionInterval = 1 * time.Second

// getUsageMergeOp returns the MergeOperator for the given usage key,
// creating one lazily if it does not yet exist.
func (cdb *CacheDB) getUsageMergeOp(storageID StorageID, namespaceID NamespaceID) *badger.MergeOperator {
	key := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}

	cdb.usageMu.RLock()
	op, ok := cdb.usageMergeOps[key]
	cdb.usageMu.RUnlock()
	if ok {
		return op
	}

	cdb.usageMu.Lock()
	defer cdb.usageMu.Unlock()
	// Double-check after acquiring write lock
	if op, ok = cdb.usageMergeOps[key]; ok {
		return op
	}
	op = cdb.db.GetMergeOperator(UsageKey(storageID, namespaceID), usageMergeFunc, usageCompactionInterval)
	cdb.usageMergeOps[key] = op
	return op
}

// AddUsage atomically adjusts the namespace-scoped usage counter by delta
// bytes.  Internally this uses BadgerDB's MergeOperator so that the write
// is append-only (no read-modify-write cycle) and cannot conflict with
// concurrent transactions.
func (cdb *CacheDB) AddUsage(storageID StorageID, namespaceID NamespaceID, delta int64) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	if delta == 0 {
		return nil
	}
	return cdb.getUsageMergeOp(storageID, namespaceID).Add(encodeUsage(delta))
}

// ChargeUsage is an alias for AddUsage for backward compatibility.
func (cdb *CacheDB) ChargeUsage(storageID StorageID, namespaceID NamespaceID, delta int64) error {
	return cdb.AddUsage(storageID, namespaceID, delta)
}

// StorageUsageKey combines storage ID and namespace ID for usage tracking
type StorageUsageKey struct {
	StorageID   StorageID
	NamespaceID NamespaceID
}

// MarkBlocksDownloaded marks specific blocks as downloaded and atomically
// updates usage statistics based on the number of newly-added blocks.
// Usage tracking requires metadata to be set for the instanceHash;
// if metadata is not yet available, the bitmap is still updated but
// usage tracking is skipped.
func (cdb *CacheDB) MarkBlocksDownloaded(instanceHash InstanceHash, startBlock, endBlock uint32, storageID StorageID, namespaceID NamespaceID, contentLength int64) error {
	newBlocks := roaring.New()
	newBlocks.AddRange(uint64(startBlock), uint64(endBlock)+1)
	return cdb.MergeBlockStateWithUsage(instanceHash, newBlocks, storageID, namespaceID, contentLength)
}

// ClearBlocks removes the specified blocks from the downloaded bitmap so they
// will be re-fetched on the next read.  This is used during auto-repair when
// corruption is detected.
func (cdb *CacheDB) ClearBlocks(instanceHash InstanceHash, blocks []uint32) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	if len(blocks) == 0 {
		return nil
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		key := StateKey(instanceHash)
		bitmap := roaring.New()

		item, err := txn.Get(key)
		if err == nil {
			err = item.Value(func(val []byte) error {
				_, err := bitmap.FromBuffer(val)
				return err
			})
			if err != nil {
				return errors.Wrap(err, "failed to deserialize bitmap")
			}
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}

		for _, b := range blocks {
			bitmap.Remove(b)
		}

		data, err := bitmap.ToBytes()
		if err != nil {
			return errors.Wrap(err, "failed to serialize bitmap")
		}
		return txn.Set(key, data)
	})
}

// IsBlockDownloaded checks if a specific block has been downloaded
func (cdb *CacheDB) IsBlockDownloaded(instanceHash InstanceHash, blockNum uint32) (bool, error) {
	bitmap, err := cdb.GetBlockState(instanceHash)
	if err != nil {
		return false, err
	}
	return bitmap.Contains(blockNum), nil
}

// GetDownloadedBlockCount returns the number of downloaded blocks
func (cdb *CacheDB) GetDownloadedBlockCount(instanceHash InstanceHash) (uint64, error) {
	bitmap, err := cdb.GetBlockState(instanceHash)
	if err != nil {
		return 0, err
	}
	return bitmap.GetCardinality(), nil
}

// DeleteBlockState removes block state for a file
func (cdb *CacheDB) DeleteBlockState(instanceHash InstanceHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(StateKey(instanceHash))
	})
}

// --- Inline Data Operations ---

// GetInlineData retrieves encrypted inline data for a small file
func (cdb *CacheDB) GetInlineData(instanceHash InstanceHash) ([]byte, error) {
	var data []byte

	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(InlineKey(instanceHash))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			data = make([]byte, len(val))
			copy(data, val)
			return nil
		})
	})

	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get inline data")
	}

	return data, nil
}

// SetInlineData stores encrypted inline data for a small file.
// The caller (StoreInline) is responsible for usage accounting via
// ChargeUsage; this function does NOT adjust usage counters.
func (cdb *CacheDB) SetInlineData(instanceHash InstanceHash, encryptedData []byte) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(InlineKey(instanceHash), encryptedData)
	})
}

// --- Append intent operations ---

// SetAppendIntent records that a streaming append is in flight for the given
// object version.  See PrefixAppendIntent for why the record exists.
func (cdb *CacheDB) SetAppendIntent(instanceHash InstanceHash, intent AppendIntent) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	encoded, err := msgpack.Marshal(&intent)
	if err != nil {
		return errors.Wrap(err, "failed to encode append intent")
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(AppendIntentKey(instanceHash), encoded)
	})
}

// DeleteAppendIntent removes an append-in-flight record.
func (cdb *CacheDB) DeleteAppendIntent(instanceHash InstanceHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(AppendIntentKey(instanceHash))
	})
}

// GetAppendIntent returns the append-in-flight record for an object version,
// or nil when there is none.
func (cdb *CacheDB) GetAppendIntent(instanceHash InstanceHash) (*AppendIntent, error) {
	var intent AppendIntent
	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(AppendIntentKey(instanceHash))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return msgpack.Unmarshal(val, &intent)
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to read append intent")
	}
	return &intent, nil
}

// ScanAppendIntents calls fn for every append-in-flight record.  Returning an
// error from fn stops the scan and is returned to the caller.
func (cdb *CacheDB) ScanAppendIntents(fn func(InstanceHash, AppendIntent) error) error {
	return cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixAppendIntent)
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			hash := InstanceHash(string(item.Key())[len(PrefixAppendIntent):])
			if hash == "" {
				continue
			}
			var intent AppendIntent
			if err := item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &intent)
			}); err != nil {
				log.Warnf("Skipping unreadable append intent for %s: %v", hash, err)
				continue
			}
			if err := fn(hash, intent); err != nil {
				return err
			}
		}
		return nil
	})
}

// --- LRU Operations ---

// UpdateLRU updates the LRU access time for a file
// Uses debouncing: only updates if last access was more than debounceTime ago
// This is optimized to avoid iteration by storing the last access time in metadata
func (cdb *CacheDB) UpdateLRU(instanceHash InstanceHash, debounceTime time.Duration) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Get metadata to find prefixID and last access time
		item, err := txn.Get(MetaKey(instanceHash))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil // No metadata, nothing to update
			}
			return errors.Wrap(err, "failed to get metadata for LRU update")
		}

		var meta CacheMetadata
		err = item.Value(func(val []byte) error {
			return msgpack.Unmarshal(val, &meta)
		})
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal metadata")
		}

		now := time.Now()

		// Check debounce using metadata's last access time
		if !meta.LastAccessTime.IsZero() && now.Sub(meta.LastAccessTime) < debounceTime {
			return nil // Too recent, skip update
		}

		// Delete old LRU key if we have a previous access time
		if !meta.LastAccessTime.IsZero() {
			oldKey := LRUKey(meta.StorageID, meta.NamespaceID, meta.LastAccessTime, instanceHash)
			if err := txn.Delete(oldKey); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
				return errors.Wrap(err, "failed to delete old LRU key")
			}
		}

		// Set new LRU key
		newKey := LRUKey(meta.StorageID, meta.NamespaceID, now, instanceHash)
		if err := txn.Set(newKey, nil); err != nil {
			return errors.Wrap(err, "failed to set new LRU key")
		}

		// Update metadata with new access time
		meta.LastAccessTime = now
		metaData, err := msgpack.Marshal(&meta)
		if err != nil {
			return errors.Wrap(err, "failed to marshal updated metadata")
		}
		return txn.Set(MetaKey(instanceHash), metaData)
	})
}

// --- Usage Counter Operations ---

// GetUsage retrieves the total bytes used by a storage+namespace combination.
// If a MergeOperator is active for the key, its Get() method is used to
// replay all accumulated deltas; otherwise a raw read is performed.
func (cdb *CacheDB) GetUsage(storageID StorageID, namespaceID NamespaceID) (int64, error) {
	key := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}

	cdb.usageMu.RLock()
	op, hasOp := cdb.usageMergeOps[key]
	cdb.usageMu.RUnlock()

	if hasOp {
		val, err := op.Get()
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return 0, nil
			}
			return 0, errors.Wrap(err, "failed to get usage")
		}
		return decodeUsage(val), nil
	}

	// No active merge operator — raw read (dormant key from prior run).
	var usage int64
	err := cdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(UsageKey(storageID, namespaceID))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) < 8 {
				return errors.New("invalid usage value")
			}
			usage = decodeUsage(val)
			return nil
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return 0, nil
		}
		return 0, errors.Wrap(err, "failed to get usage")
	}
	return usage, nil
}

// GetAllUsage returns usage for all storage+namespace combinations
func (cdb *CacheDB) GetAllUsage() (map[StorageUsageKey]int64, error) {
	return cdb.getUsageByPrefix([]byte(PrefixUsage))
}

// ComputeInlineDataSize scans all inline data entries (d: prefix) and sums
// the stored value sizes.  This gives the actual bytes consumed in BadgerDB
// for inline object data (excluding metadata overhead).
func (cdb *CacheDB) ComputeInlineDataSize() (int64, error) {
	var total int64
	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixInline)
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			total += int64(it.Item().ValueSize())
		}
		return nil
	})
	return total, err
}

// GetDirUsage returns usage for all namespaces within a single storage directory.
func (cdb *CacheDB) GetDirUsage(storageID StorageID) (map[NamespaceID]int64, error) {
	prefix := []byte(fmt.Sprintf("%s%d:", PrefixUsage, storageID))
	full, err := cdb.getUsageByPrefix(prefix)
	if err != nil {
		return nil, err
	}
	result := make(map[NamespaceID]int64, len(full))
	for key, usage := range full {
		result[key.NamespaceID] = usage
	}
	return result, nil
}

// getUsageByPrefix returns usage for all keys matching the given prefix.
// Active MergeOperators are consulted first; dormant keys (no operator)
// are read via a normal prefix scan.
func (cdb *CacheDB) getUsageByPrefix(prefix []byte) (map[StorageUsageKey]int64, error) {
	usage := make(map[StorageUsageKey]int64)

	// Phase 1: read from active merge operators whose keys match prefix.
	activeKeys := make(map[string]bool)
	cdb.usageMu.RLock()
	for suk, op := range cdb.usageMergeOps {
		dbKey := UsageKey(suk.StorageID, suk.NamespaceID)
		if !bytes.HasPrefix(dbKey, prefix) {
			continue
		}
		val, err := op.Get()
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				continue
			}
			cdb.usageMu.RUnlock()
			return nil, errors.Wrap(err, "failed to get usage from merge operator")
		}
		if len(val) >= 8 {
			usage[suk] = decodeUsage(val)
		}
		activeKeys[string(dbKey)] = true
	}
	cdb.usageMu.RUnlock()

	// Phase 2: scan the DB for keys without active operators.
	err := cdb.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()

			if activeKeys[string(key)] {
				continue
			}

			storageID, namespaceID, err := ParseUsageKey(key)
			if err != nil {
				continue
			}

			err = item.Value(func(val []byte) error {
				if len(val) >= 8 {
					usageKey := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}
					usage[usageKey] = decodeUsage(val)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return usage, err
}

// SetUsage sets the absolute usage counter for a (storageID, namespaceID)
// pair.  Any active MergeOperator for the key is stopped first (flushing
// pending deltas) and then the value is overwritten.
//
// The entry is written with WithDiscard() so that BadgerDB marks all
// earlier versions of the key as eligible for garbage collection.
// Without this flag, the MergeOperator's iterateAndMerge would still
// see the old compacted entry (which carries bitDiscardEarlierVersions)
// and sum it into the total, causing the counter to include both the
// new baseline and the old accumulated value — a compounding overcount
// that grows with every reconciliation cycle.
//
// The next AddUsage call will lazily create a fresh MergeOperator.
func (cdb *CacheDB) SetUsage(storageID StorageID, namespaceID NamespaceID, value int64) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	suk := StorageUsageKey{StorageID: storageID, NamespaceID: namespaceID}

	cdb.usageMu.Lock()
	if op, ok := cdb.usageMergeOps[suk]; ok {
		op.Stop()
		delete(cdb.usageMergeOps, suk)
	}
	cdb.usageMu.Unlock()

	if value < 0 {
		value = 0
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(badger.NewEntry(UsageKey(storageID, namespaceID), encodeUsage(value)).WithDiscard())
	})
}

// ComputeActualUsage performs a full scan of the metadata table to compute
// the real byte-level usage per (StorageID, NamespaceID).
//
// Completed objects contribute their full ContentLength.  In-progress
// objects contribute the bytes implied by their block bitmap.
//
// This is an expensive read-only operation.  The consistency checker
// accumulates usage during its metadata scan instead of calling this;
// it is retained for ad-hoc diagnostics and tests.
func (cdb *CacheDB) ComputeActualUsage() (map[StorageUsageKey]int64, error) {
	actual := make(map[StorageUsageKey]int64)

	err := cdb.db.View(func(txn *badger.Txn) error {
		metaPrefix := []byte(PrefixMeta)
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(metaPrefix); it.ValidForPrefix(metaPrefix); it.Next() {
			item := it.Item()
			metaKey := item.Key()
			instanceHash := InstanceHash(metaKey[len(PrefixMeta):])

			// Decode metadata to get StorageID, NamespaceID, ContentLength.
			var meta CacheMetadata
			err := item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &meta)
			})
			if err != nil {
				log.Warnf("ComputeActualUsage: failed to unmarshal metadata for %s: %v", instanceHash, err)
				continue
			}

			key := StorageUsageKey{StorageID: meta.StorageID, NamespaceID: meta.NamespaceID}

			// Both completed and in-progress objects are charged at their
			// full ContentLength, matching the upfront-charge model where
			// usage is reserved at file-creation time.
			if meta.ContentLength > 0 {
				actual[key] += meta.ContentLength
			}
		}
		return nil
	})

	return actual, err
}

// --- S3 Tiering Operations ---

// SetS3UploadIntent records an in-progress upload to an S3 target.  Written
// before the first byte reaches the bucket so that a crash never leaves an
// untracked object in S3.
//
// This and DeleteS3UploadIntent perform a single blind Set/Delete with no
// prior read, so their transaction read-set is empty and BadgerDB's
// serializable-snapshot conflict detection can never flag them — no retry
// loop is required (unlike RecordPresignIssued or RelocateObject, which read
// before writing).
func (cdb *CacheDB) SetS3UploadIntent(instanceHash InstanceHash, intent *S3UploadIntent) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	data, err := msgpack.Marshal(intent)
	if err != nil {
		return errors.Wrap(err, "failed to marshal upload intent")
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(S3UploadIntentKey(instanceHash), data)
	})
}

// DeleteS3UploadIntent removes an upload intent record.
func (cdb *CacheDB) DeleteS3UploadIntent(instanceHash InstanceHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(S3UploadIntentKey(instanceHash))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	})
}

// ListS3UploadIntents returns all recorded upload intents, used by crash
// recovery to reconcile the bucket with the metadata store.
func (cdb *CacheDB) ListS3UploadIntents() (map[InstanceHash]*S3UploadIntent, error) {
	intents := make(map[InstanceHash]*S3UploadIntent)
	err := cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixS3Upload)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			hash := InstanceHash(item.Key()[len(PrefixS3Upload):])
			var intent S3UploadIntent
			err := item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &intent)
			})
			if err != nil {
				log.Warnf("Failed to unmarshal S3 upload intent for %s: %v", hash, err)
				continue
			}
			intents[hash] = &intent
		}
		return nil
	})
	return intents, err
}

// presignRecordRetries bounds retries of RecordPresignIssued on BadgerDB
// write conflicts (the debounce read makes it a read-modify-write, so two
// presigns racing on the same object can conflict).
const presignRecordRetries = 5

// RecordPresignIssued stamps the current time on an object's presign key.
// Objects with a stamp newer than the configured presign hold window are
// skipped by eviction, so a client holding a fresh pre-signed URL never has
// the object deleted out from under it.
//
// The write is debounced so that a hot object being redirected repeatedly does
// not stamp the same key on every request.  The debounce window is bounded by
// how much slack the hold has over a URL's lifetime: skipping a write leaves
// the stamp up to one window old, so the protection a caller can still count
// on is hold-minus-window, which must remain at least as long as the URL it
// just handed out.  presignHoldHeadroom is the slack the cache guarantees when
// it resolves the hold, and a quarter of the hold is the cheaper bound, so the
// debounce is the smaller of the two.
func (cdb *CacheDB) RecordPresignIssued(instanceHash InstanceHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	now := time.Now()
	debounce := cdb.presignHold / 4
	if slack := cdb.presignHold - s3PresignExpiry(); slack < debounce {
		debounce = slack
	}
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, uint64(now.UnixNano()))

	for attempt := 0; ; attempt++ {
		err := cdb.db.Update(func(txn *badger.Txn) error {
			if debounce > 0 {
				if item, gErr := txn.Get(PresignKey(instanceHash)); gErr == nil {
					var prev int64
					_ = item.Value(func(v []byte) error {
						if len(v) >= 8 {
							prev = int64(binary.BigEndian.Uint64(v))
						}
						return nil
					})
					if prev > 0 && now.Sub(time.Unix(0, prev)) < debounce {
						return nil // recent enough; skip the write
					}
				}
			}
			return txn.Set(PresignKey(instanceHash), val)
		})
		if err == nil {
			return nil
		}
		if errors.Is(err, badger.ErrConflict) && attempt < presignRecordRetries {
			continue
		}
		return err
	}
}

// presignHeldInTxn reports whether the object's presign stamp is within the
// eviction protection window.
func (cdb *CacheDB) presignHeldInTxn(txn *badger.Txn, instanceHash InstanceHash) bool {
	if cdb.presignHold <= 0 {
		return false
	}
	item, err := txn.Get(PresignKey(instanceHash))
	if err != nil {
		return false
	}
	var issuedAt int64
	_ = item.Value(func(val []byte) error {
		if len(val) >= 8 {
			issuedAt = int64(binary.BigEndian.Uint64(val))
		}
		return nil
	})
	return issuedAt > 0 && time.Since(time.Unix(0, issuedAt)) < cdb.presignHold
}

// RelocateObject atomically moves a completed object's metadata onto the
// given S3 storage target.  The StorageID is rewritten (bypassing the
// set-once merge rule — this is the one sanctioned transition) and the LRU
// index entry is moved from the object's base storage ID to the new one.
//
// Chunked objects are supported: because an S3 target holds the object as a
// single contiguous blob, relocation flattens the chunk layout
// (ChunkSizeCode / ChunkLocations are cleared).  The returned pre-relocation
// metadata still carries the original chunk layout so the caller can delete
// every local chunk file and refund each contributing directory's usage.
//
// The caller is responsible for moving the object *data* and for adjusting
// usage counters after the transaction commits (AddUsage cannot run inside
// a transaction).  Returns the pre-relocation metadata.
func (cdb *CacheDB) RelocateObject(instanceHash InstanceHash, newStorageID StorageID) (*CacheMetadata, error) {
	if err := cdb.checkWritable(); err != nil {
		return nil, err
	}
	var prev CacheMetadata
	err := cdb.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(MetaKey(instanceHash))
		if err != nil {
			return errors.Wrap(err, "object metadata not found")
		}
		if err := item.Value(func(val []byte) error {
			return msgpack.Unmarshal(val, &prev)
		}); err != nil {
			return errors.Wrap(err, "failed to unmarshal metadata")
		}

		if prev.Completed.IsZero() {
			return errors.New("cannot relocate an incomplete object")
		}
		if prev.StorageID == StorageIDInline && !prev.IsChunked() {
			return errors.New("cannot relocate an inline object")
		}
		if prev.StorageID == newStorageID {
			return errors.New("object already resides on the target storage")
		}

		// Move the LRU index entry, preserving the access timestamp.  The
		// LRU is keyed by the object's base StorageID (chunk 0's directory
		// for chunked objects), which is what deleteObjectInTxn also uses.
		if !prev.LastAccessTime.IsZero() {
			oldKey := LRUKey(prev.StorageID, prev.NamespaceID, prev.LastAccessTime, instanceHash)
			if err := txn.Delete(oldKey); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
				return errors.Wrap(err, "failed to delete old LRU key")
			}
			newKey := LRUKey(newStorageID, prev.NamespaceID, prev.LastAccessTime, instanceHash)
			if err := txn.Set(newKey, nil); err != nil {
				return errors.Wrap(err, "failed to set new LRU key")
			}
		}

		updated := prev
		updated.StorageID = newStorageID
		// The bucket holds one contiguous blob; drop the chunk layout so the
		// object is a plain single-storage object on the S3 target.
		updated.ChunkSizeCode = ChunkingDisabled
		updated.ChunkLocations = nil
		data, err := msgpack.Marshal(&updated)
		if err != nil {
			return errors.Wrap(err, "failed to marshal relocated metadata")
		}
		return txn.Set(MetaKey(instanceHash), data)
	})
	if err != nil {
		return nil, err
	}
	return &prev, nil
}

// --- Bulk Operations ---

// deleteObjectInTxn removes all DB keys for a cached object within an
// existing transaction.  It returns the decoded metadata (if present) so
// the caller can decide what to do with filesystem files and usage
// counters.  The caller is responsible for usage adjustments — this
// function does NOT modify usage counters.
//
// salt is required to recompute the ObjectHash from SourceURL for
// ETag-table cleanup.
func deleteObjectInTxn(txn *badger.Txn, salt []byte, instanceHash InstanceHash) (*CacheMetadata, error) {
	meta, err := readMetadataInTxn(txn, instanceHash)
	if err != nil {
		return nil, err
	}
	return deleteObjectWithMetaInTxn(txn, salt, instanceHash, meta)
}

// readMetadataInTxn decodes an object's metadata record inside an existing
// transaction.  A missing or undecodable record yields (nil, nil): the object
// still has keys and files worth reclaiming, and the deletion path is written
// to proceed without metadata.  Only a genuine read failure is an error.
func readMetadataInTxn(txn *badger.Txn, instanceHash InstanceHash) (*CacheMetadata, error) {
	item, err := txn.Get(MetaKey(instanceHash))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get metadata for deletion")
	}
	var meta CacheMetadata
	if err := item.Value(func(val []byte) error {
		return msgpack.Unmarshal(val, &meta)
	}); err != nil {
		log.Warnf("Failed to unmarshal metadata during object deletion: %v", err)
		return nil, nil
	}
	return &meta, nil
}

// deleteObjectWithMetaInTxn is deleteObjectInTxn for a caller that has already
// decoded the object's metadata.
//
// Every phase of EvictByLRU but the plain LRU walk reads that record first, to
// decide whether the object touches the storage directory being freed.  Passing
// it in spares a second Get and a second msgpack decode of the same key inside
// the same transaction -- BadgerDB does not memoize reads, so it really is a
// repeat of both.
//
// known may be nil, meaning there is no usable metadata for the object; the
// keys that do not depend on it are still removed.
func deleteObjectWithMetaInTxn(txn *badger.Txn, salt []byte, instanceHash InstanceHash, known *CacheMetadata) (*CacheMetadata, error) {
	var meta CacheMetadata
	hasMetadata := known != nil
	if hasMetadata {
		meta = *known
	}

	// Delete LRU entry using metadata (before deleting metadata)
	if hasMetadata && !meta.LastAccessTime.IsZero() {
		lruKey := LRUKey(meta.StorageID, meta.NamespaceID, meta.LastAccessTime, instanceHash)
		if err := txn.Delete(lruKey); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.Wrap(err, "failed to delete LRU key")
		}
	}

	// Clean up ETag table if this was the latest version.
	//
	// ObjectHash is derived from SourceURL + salt rather than stored
	// redundantly in metadata.  The record is needed anyway -- for the LRU key
	// above and for the caller's usage accounting -- so this costs one HMAC
	// and one read of the e: key, not a metadata lookup of its own.
	//
	// The e: entry is deleted only when it names the version being removed;
	// an older version going away must leave the pointer to the current one
	// alone.  That comparison has to decode the entry (see decodeETagEntry) --
	// the raw value carries an 8-byte timestamp prefix, so comparing it to
	// meta.ETag byte-for-byte matches nothing and would leave a dangling e:
	// key behind for every object the cache ever evicts.
	if hasMetadata && meta.SourceURL != "" {
		objectHash := ComputeObjectHash(salt, meta.SourceURL)
		etagItem, err := txn.Get(ETagKey(objectHash))
		if err == nil {
			var currentETag string
			err = etagItem.Value(func(val []byte) error {
				currentETag, _ = decodeETagEntry(val)
				return nil
			})
			if err == nil && currentETag == meta.ETag {
				if err := txn.Delete(ETagKey(objectHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
					log.Warnf("Failed to delete ETag entry for %s: %v", objectHash, err)
				}
			}
		}
	}

	// Delete metadata
	if err := txn.Delete(MetaKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return nil, err
	}

	// Delete block state
	if err := txn.Delete(StateKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return nil, err
	}

	// Delete inline data if stored inline
	if hasMetadata && meta.IsInline() {
		if err := txn.Delete(InlineKey(instanceHash)); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return nil, err
		}
	}

	// Delete purge-first marker, presign stamp, and any S3 upload intent if
	// present (best-effort, ignore not-found).
	//
	// Dropping the intent here is safe and necessary: an intent outliving its
	// object would make the S3 consistency sweep skip that hash in both
	// directions forever, on the assumption that the uploader owns it.  Any
	// bucket bytes are handled by the same deletion -- StorageManager.Delete
	// and EvictByLRU remove the bucket object for an S3-resident version --
	// and an intent for an upload still in flight belongs to an object whose
	// metadata is being deleted underneath it, which the uploader detects when
	// its relocation fails and cleans up the bucket copy itself.
	_ = txn.Delete(PurgeFirstKey(instanceHash))
	_ = txn.Delete(PresignKey(instanceHash))
	_ = txn.Delete(S3UploadIntentKey(instanceHash))

	// Likewise the append-in-flight marker: whatever removed the object also
	// removed the thing the marker exists to let us reclaim.
	_ = txn.Delete(AppendIntentKey(instanceHash))

	if hasMetadata {
		return &meta, nil
	}
	return nil, nil
}

// DeleteObject removes all data for a cached object.
// Uses metadata to compute exact LRU key for efficient deletion.
// Also cleans up ETag table, purge-first marker, and adjusts usage
// counters.  Usage is decremented via AddUsage after the transaction
// commits so that the write cannot conflict.
func (cdb *CacheDB) DeleteObject(instanceHash InstanceHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	var meta *CacheMetadata
	err := cdb.db.Update(func(txn *badger.Txn) error {
		var txnErr error
		meta, txnErr = deleteObjectInTxn(txn, cdb.Salt(), instanceHash)
		return txnErr
	})
	if err != nil {
		return err
	}
	if meta != nil {
		// Deduct the on-disk size (content + per-block MAC overhead)
		// to match what was charged in InitDiskStorage / AllocateChunk.
		// Inline objects have no MAC overhead.
		for sid, bytes := range meta.PerDirectoryBytes() {
			if err := cdb.AddUsage(sid, meta.NamespaceID, -bytes); err != nil {
				log.Warnf("Failed to decrease usage for storage %d namespace %d: %v",
					sid, meta.NamespaceID, err)
			}
		}
	}
	return nil
}

// evictedObject holds the information needed to clean up the filesystem
// after the DB transaction commits.
type evictedObject struct {
	instanceHash   InstanceHash
	storageID      StorageID
	contentLen     int64
	namespaceID    NamespaceID
	chunkSizeCode  ChunkSizeCode   // For chunked objects
	chunkLocations []ChunkLocation // Locations of chunks 1, 2, ...
}

// evictionSkipBudget bounds how many protected objects the LRU walk (phases 2
// and 3) will step over before giving up.
//
// A skipped object frees nothing, so without a bound a long run of protected
// objects at the head of the LRU index would turn a bounded eviction into a
// full index scan.  Reaching this budget means something pathological is
// happening -- readers do not normally accumulate on the least-recently-used
// objects -- so the right response is to stop and let the next pass retry,
// not to keep scanning.
//
// The budget deliberately does NOT gate the purge-first drain.  That phase
// walks the pf: index, which is not the LRU order but an explicit list an
// operator (or the emergency low-space purge) asked to be removed; its length
// is bounded by that request, and stopping it because unrelated LRU candidates
// were pinned would silently ignore the admin evict API.
const evictionSkipBudget = 1024

// EvictByLRU evicts objects from a storage+namespace combination, draining
// purge-first items before walking the regular LRU index — all within a
// single BadgerDB transaction.
//
// Eviction stops when either maxObjects have been removed or maxBytes of
// content has been freed — whichever comes first.  A value of 0 for
// either limit means "no limit on that dimension".  The method is allowed
// to go one object over the byte threshold so that progress is always
// made even when only large objects remain.
//
// skip, when non-nil, is consulted for every candidate; returning true leaves
// the object in place.  It is how a caller protects objects that must not
// disappear right now -- see StorageManager.EvictByLRU, which uses it to spare
// objects under a live reader.  A skipped object is not counted against
// maxObjects, because skipping frees nothing and counting it would let
// eviction report a full batch while returning under target.
//
// Returns the evicted objects and the number that were skipped.
func (cdb *CacheDB) EvictByLRU(storageID StorageID, namespaceID NamespaceID, maxObjects int, maxBytes int64, skip func(InstanceHash) bool) ([]evictedObject, int, error) {
	if err := cdb.checkWritable(); err != nil {
		return nil, 0, err
	}

	var evicted []evictedObject
	// lruSkipped counts skips charged against evictionSkipBudget; pfSkipped
	// counts purge-first skips, which are reported but never end a pass.
	var lruSkipped, pfSkipped int
	usageDeltas := make(map[StorageUsageKey]int64)

	skipBudget := evictionSkipBudget
	if cdb.skipBudget > 0 {
		skipBudget = cdb.skipBudget
	}

	err := cdb.db.Update(func(txn *badger.Txn) error {
		var freedBytes int64

		// --- helper: returns true when the caller's targets are met ---
		quotaReached := func() bool {
			if maxObjects > 0 && len(evicted) >= maxObjects {
				return true
			}
			if maxBytes > 0 && freedBytes >= maxBytes {
				return true
			}
			return false
		}

		// --- helper: returns true when the LRU walk should stop ---
		limitReached := func() bool {
			return lruSkipped >= skipBudget || quotaReached()
		}

		// --- helper: delete one object by hash, record results ---
		//
		// known is the object's metadata when the caller has already read it,
		// and nil when it has not — in which case the record is read here.
		evictOne := func(hash InstanceHash, known *CacheMetadata, skipCounter *int) {
			// Checked before the metadata read: a protected object is not
			// going anywhere this pass, so there is nothing to learn about it.
			if skip != nil && skip(hash) {
				*skipCounter++
				return
			}
			// Objects with a recently issued pre-signed URL are protected the
			// same way: a client may still be downloading directly from the
			// bucket.  Counts against the skip budget so a namespace full of
			// held objects cannot spin the LRU walk.
			if cdb.presignHeldInTxn(txn, hash) {
				log.Debugf("Skipping eviction of %s: pre-signed URL issued within hold window", hash)
				*skipCounter++
				return
			}
			var meta *CacheMetadata
			var err error
			if known != nil {
				meta, err = deleteObjectWithMetaInTxn(txn, cdb.Salt(), hash, known)
			} else {
				meta, err = deleteObjectInTxn(txn, cdb.Salt(), hash)
			}
			if err != nil {
				log.Warnf("Failed to delete object %s during eviction: %v", hash, err)
				return
			}
			if meta == nil {
				return
			}
			evicted = append(evicted, evictedObject{
				instanceHash:   hash,
				storageID:      meta.StorageID,
				contentLen:     meta.ContentLength,
				namespaceID:    meta.NamespaceID,
				chunkSizeCode:  meta.ChunkSizeCode,
				chunkLocations: meta.ChunkLocations,
			})
			// For chunked objects, decrement usage from each storage
			// based on the on-disk bytes it holds.  For
			// non-chunked objects this returns a single entry for the
			// base StorageID with CalculateFileSize(ContentLength).
			for sid, bytes := range meta.PerDirectoryBytes() {
				key := StorageUsageKey{StorageID: sid, NamespaceID: meta.NamespaceID}
				usageDeltas[key] -= bytes
			}
			if meta.StorageID == StorageIDInline {
				freedBytes += meta.ContentLength
			} else {
				freedBytes += CalculateFileSize(meta.ContentLength)
			}
		}

		// objectUsesDir reports whether an object touches the given
		// storage directory — either as its base or via any chunk.
		objectUsesDir := func(meta *CacheMetadata, sid StorageID) bool {
			if meta.StorageID == sid {
				return true
			}
			for _, loc := range meta.ChunkLocations {
				if loc.StorageID == sid {
					return true
				}
			}
			return false
		}

		// Phase 1: drain purge-first items for this storageID.
		// Walk the pf: prefix; for each item whose metadata matches
		// the requested storageID (base or chunk), evict it immediately.
		{
			pfPrefix := []byte(PrefixPurgeFirst)
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false

			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(pfPrefix); it.ValidForPrefix(pfPrefix); it.Next() {
				// Only the caller's own targets end this phase; the skip
				// budget is reserved for the LRU walk below.
				if quotaReached() {
					break
				}
				keyStr := string(it.Item().Key())
				hash := InstanceHash(keyStr[len(PrefixPurgeFirst):])
				if hash == "" {
					continue
				}

				// Peek at metadata to check storageID.  The same record
				// decides what has to be deleted, so it is handed to
				// evictOne rather than read again.
				meta, err := readMetadataInTxn(txn, hash)
				if err != nil {
					return err
				}
				if meta == nil {
					// Nothing this marker can act on -- the object is gone,
					// or its record does not decode and the consistency
					// checker owns it.  Either way the marker is stale.
					_ = txn.Delete(it.Item().KeyCopy(nil))
					continue
				}
				if !objectUsesDir(meta, storageID) {
					continue
				}

				evictOne(hash, meta, &pfSkipped)
			}
		}

		// Phase 2: walk the LRU index for the requested storage+namespace.
		// This finds objects whose base (chunk 0) is in storageID.
		if !limitReached() {
			lruPrefix := []byte(fmt.Sprintf("%s%d:%d:", PrefixLRU, storageID, namespaceID))
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false

			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(lruPrefix); it.ValidForPrefix(lruPrefix); it.Next() {
				_, _, _, hash, err := ParseLRUKey(it.Item().Key())
				if err != nil {
					continue
				}
				// This phase has no reason of its own to read the record:
				// the LRU key already says the object's base chunk is in
				// this storage+namespace.
				evictOne(hash, nil, &lruSkipped)
				if limitReached() {
					break
				}
			}
		}

		// Phase 3: cross-directory scan for chunked objects.
		// If Phase 2 was not sufficient, scan ALL LRU entries for
		// the requested namespace.  For each candidate whose base
		// lives in another directory, check whether any of its chunk
		// locations reference storageID.  Skip entries that were
		// already evicted in Phase 2 (their metadata will be gone).
		if !limitReached() {
			nsLRUPrefix := fmt.Appendf(nil, "%s", PrefixLRU)
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false

			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(nsLRUPrefix); it.ValidForPrefix(nsLRUPrefix); it.Next() {
				if limitReached() {
					break
				}
				lruSID, lruNS, _, hash, err := ParseLRUKey(it.Item().Key())
				if err != nil {
					continue
				}
				// Skip the namespace we already scanned in Phase 2,
				// or different namespaces.
				if lruNS != namespaceID {
					continue
				}
				if lruSID == storageID {
					continue // already covered by Phase 2
				}

				// Peek at metadata to check chunk locations.  As in phase 1,
				// the record read here is the one the deletion needs.
				meta, err := readMetadataInTxn(txn, hash)
				if err != nil {
					return err
				}
				if meta == nil {
					continue
				}
				if !meta.IsChunked() {
					continue
				}
				if !objectUsesDir(meta, storageID) {
					continue
				}
				evictOne(hash, meta, &lruSkipped)
			}
		}

		return nil
	})

	// Apply accumulated usage decrements via MergeOperator (outside
	// the eviction transaction so they cannot cause conflicts).
	for key, delta := range usageDeltas {
		if err := cdb.AddUsage(key.StorageID, key.NamespaceID, delta); err != nil {
			log.Warnf("Failed to decrease usage for storage %d namespace %d: %v",
				key.StorageID, key.NamespaceID, err)
		}
	}

	return evicted, lruSkipped + pfSkipped, err
}

// badgerLogger adapts Pelican's logrus to BadgerDB's logger interface
type badgerLogger struct {
	log *log.Entry
}

func newBadgerLogger() *badgerLogger {
	return &badgerLogger{log: log.WithField("component", "BadgerDB")}
}

func (l *badgerLogger) Errorf(format string, args ...interface{}) {
	l.log.Errorf(format, args...)
}

func (l *badgerLogger) Warningf(format string, args ...interface{}) {
	l.log.Warnf(format, args...)
}

func (l *badgerLogger) Infof(format string, args ...interface{}) {
	l.log.Debugf(format, args...)
}

func (l *badgerLogger) Debugf(format string, args ...interface{}) {
	l.log.Tracef(format, args...)
}

// Verify badgerLogger satisfies the interface
var _ badger.Logger = (*badgerLogger)(nil)

// ScanMetadata iterates over all metadata entries
func (cdb *CacheDB) ScanMetadata(fn func(instanceHash InstanceHash, meta *CacheMetadata) error) error {
	return cdb.ScanMetadataFrom("", fn)
}

// ScanMetadataFrom scans metadata starting from the given instanceHash (empty string = start from beginning)
func (cdb *CacheDB) ScanMetadataFrom(startKey InstanceHash, fn func(instanceHash InstanceHash, meta *CacheMetadata) error) error {
	return cdb.db.View(func(txn *badger.Txn) error {
		prefix := []byte(PrefixMeta)
		opts := badger.DefaultIteratorOptions

		it := txn.NewIterator(opts)
		defer it.Close()

		// Seek to the starting position
		seekKey := prefix
		if startKey != "" {
			seekKey = MetaKey(startKey)
		}

		for it.Seek(seekKey); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := string(item.Key())
			instanceHash := InstanceHash(key[len(PrefixMeta):])

			// Skip the start key itself if resuming (we already processed it)
			if startKey != "" && instanceHash == startKey {
				continue
			}

			var meta CacheMetadata
			err := item.Value(func(val []byte) error {
				return msgpack.Unmarshal(val, &meta)
			})
			if err != nil {
				log.Warnf("Failed to unmarshal metadata for %s: %v", instanceHash, err)
				continue
			}

			if err := fn(instanceHash, &meta); err != nil {
				return err
			}
		}
		return nil
	})
}

// HasMetadata checks if metadata exists for a file
func (cdb *CacheDB) HasMetadata(instanceHash InstanceHash) (bool, error) {
	var exists bool
	err := cdb.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(MetaKey(instanceHash))
		if err == nil {
			exists = true
		} else if errors.Is(err, badger.ErrKeyNotFound) {
			exists = false
		} else {
			return err
		}
		return nil
	})
	return exists, err
}

// Batch allows batching multiple writes for efficiency
type Batch struct {
	wb *badger.WriteBatch
	// cdb is retained so the batch inherits the handle's read-only status;
	// NewBatch cannot report the refusal itself, having no error to return.
	cdb *CacheDB
}

// NewBatch creates a new write batch.
//
// A batch taken from a read-only handle refuses at Set, Delete, and Flush
// rather than here, because there is no error to return from this call.
func (cdb *CacheDB) NewBatch() *Batch {
	return &Batch{wb: cdb.db.NewWriteBatch(), cdb: cdb}
}

// Set adds a key-value pair to the batch
func (b *Batch) Set(key, value []byte) error {
	if err := b.cdb.checkWritable(); err != nil {
		return err
	}
	return b.wb.Set(key, value)
}

// Delete adds a delete operation to the batch
func (b *Batch) Delete(key []byte) error {
	if err := b.cdb.checkWritable(); err != nil {
		return err
	}
	return b.wb.Delete(key)
}

// Flush commits the batch
func (b *Batch) Flush() error {
	if err := b.cdb.checkWritable(); err != nil {
		return err
	}
	return b.wb.Flush()
}

// Cancel discards the batch
func (b *Batch) Cancel() {
	b.wb.Cancel()
}

// --- Purge First Operations ---

// MarkPurgeFirst marks a file hash for priority eviction
func (cdb *CacheDB) MarkPurgeFirst(instanceHash InstanceHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		// Check if metadata exists first
		_, err := txn.Get(MetaKey(instanceHash))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return errors.New("object not found in cache")
			}
			return err
		}
		// Set the purge first marker
		return txn.Set(PurgeFirstKey(instanceHash), []byte{1})
	})
}

// UnmarkPurgeFirst removes the purge first marker for a file hash
func (cdb *CacheDB) UnmarkPurgeFirst(instanceHash InstanceHash) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	return cdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(PurgeFirstKey(instanceHash))
	})
}

// IsPurgeFirst checks if a file hash is marked for priority eviction
func (cdb *CacheDB) IsPurgeFirst(instanceHash InstanceHash) (bool, error) {
	var isPurgeFirst bool
	err := cdb.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(PurgeFirstKey(instanceHash))
		if err == nil {
			isPurgeFirst = true
		} else if errors.Is(err, badger.ErrKeyNotFound) {
			isPurgeFirst = false
		} else {
			return err
		}
		return nil
	})
	return isPurgeFirst, err
}

// FindRecyclableStorageID searches persisted disk mappings for the
// unmounted storageID with the least usage.  mountedDirs maps storageID
// to directory path for IDs currently assigned to live directories —
// those are excluded.  Returns the storageID and nil on success, or an
// error if no recyclable ID exists.
func (cdb *CacheDB) FindRecyclableStorageID(mountedDirs map[StorageID]string) (StorageID, error) {
	mappings, err := cdb.LoadDiskMappings()
	if err != nil {
		return 0, errors.Wrap(err, "failed to load disk mappings")
	}

	bestID := StorageID(0)
	bestUsage := int64(-1)
	found := false

	for _, dm := range mappings {
		if _, mounted := mountedDirs[dm.ID]; mounted {
			continue // still in use
		}
		if dm.Backend != BackendPosix {
			// S3 targets are never in mountedDirs; they must not be
			// recycled out from under a configured bucket.
			continue
		}

		// Sum usage across all namespaces for this storageID.
		dirUsage, err := cdb.GetDirUsage(dm.ID)
		if err != nil {
			log.Warnf("Failed to read usage for storage %d during recycle scan: %v", dm.ID, err)
			continue
		}
		var total int64
		for _, u := range dirUsage {
			total += u
		}

		if !found || total < bestUsage || (total == bestUsage && dm.ID < bestID) {
			bestID = dm.ID
			bestUsage = total
			found = true
		}
	}

	if !found {
		return 0, errors.New("no recyclable storage IDs available")
	}

	log.Infof("Selected storage ID %d (usage %d bytes) for recycling", bestID, bestUsage)
	return bestID, nil
}

// PurgeStorageID removes all database entries associated with a storageID:
// object metadata, block state, inline data, LRU entries, purge-first
// markers, ETag entries, usage counters, and the disk mapping itself.
//
// This is used during storage ID recycling to reclaim an ID that was
// previously assigned to a directory that is no longer mounted.
//
// Objects are deleted in batches to avoid exceeding BadgerDB's
// transaction size limit.
func (cdb *CacheDB) PurgeStorageID(storageID StorageID) error {
	if err := cdb.checkWritable(); err != nil {
		return err
	}
	const batchSize = 500

	lruPrefix := []byte(fmt.Sprintf("%s%d:", PrefixLRU, storageID))
	totalDeleted := 0

	// Iterate the LRU in batch-sized chunks.  After deleting a batch the
	// iterator is invalidated, so we re-seek from the prefix on each pass.
	// The loop terminates when a scan finds no more keys.
	for {
		var hashes []InstanceHash
		err := cdb.db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(lruPrefix); it.ValidForPrefix(lruPrefix); it.Next() {
				_, _, _, hash, err := ParseLRUKey(it.Item().Key())
				if err != nil {
					continue
				}
				hashes = append(hashes, hash)
				if len(hashes) >= batchSize {
					break
				}
			}
			return nil
		})
		if err != nil {
			return errors.Wrap(err, "failed to scan LRU entries for purge")
		}
		if len(hashes) == 0 {
			break
		}

		err = cdb.db.Update(func(txn *badger.Txn) error {
			for _, hash := range hashes {
				if _, err := deleteObjectInTxn(txn, cdb.Salt(), hash); err != nil {
					log.Warnf("Failed to delete object %s during storage purge: %v", hash, err)
				}
			}
			return nil
		})
		if err != nil {
			return errors.Wrapf(err, "failed to delete object batch during purge of storage %d", storageID)
		}
		totalDeleted += len(hashes)
	}

	// Clean up usage counters, any straggler LRU keys, and the disk mapping.
	err := cdb.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		// Delete all usage keys for this storageID.
		usagePrefix := []byte(fmt.Sprintf("%s%d:", PrefixUsage, storageID))
		it := txn.NewIterator(opts)
		defer it.Close()

		var usageKeys [][]byte
		for it.Seek(usagePrefix); it.ValidForPrefix(usagePrefix); it.Next() {
			usageKeys = append(usageKeys, it.Item().KeyCopy(nil))
		}
		for _, key := range usageKeys {
			if err := txn.Delete(key); err != nil {
				log.Warnf("Failed to delete usage key during purge: %v", err)
			}
		}

		// Delete any remaining LRU keys (should already be gone from
		// object deletions, but clean up in case of inconsistency).
		lruIt := txn.NewIterator(opts)
		defer lruIt.Close()

		var lruKeys [][]byte
		for lruIt.Seek(lruPrefix); lruIt.ValidForPrefix(lruPrefix); lruIt.Next() {
			lruKeys = append(lruKeys, lruIt.Item().KeyCopy(nil))
		}
		for _, key := range lruKeys {
			if err := txn.Delete(key); err != nil {
				log.Warnf("Failed to delete LRU key during purge: %v", err)
			}
		}

		// Delete the disk mapping entry.
		return txn.Delete(DiskMappingKey(storageID))
	})
	if err != nil {
		return errors.Wrapf(err, "failed to clean up usage/mapping for storage %d", storageID)
	}

	log.Infof("Purged storage ID %d: deleted %d objects", storageID, totalDeleted)
	return nil
}
