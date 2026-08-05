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

// Offline maintenance access, for the CLI.
//
// A pstore keeps its namespace in an encrypted database and its objects in
// encrypted block files, so an operator cannot inspect it with ls or du.
// OpenMaintenance is how the CLI gets in.
//
// The origin must be stopped either way: BadgerDB takes a directory lock on
// open, and a consistency check racing a live origin's writes would not mean
// anything.
//
// This deliberately does not use BadgerDB's ReadOnly mode. That mode takes a
// shared flock rather than an exclusive one, but a running origin holds the
// exclusive lock regardless, so read-only buys no concurrency -- and it fails
// outright on some platforms. Instead the database is opened normally and
// writes are refused in Go, which additionally lets `fsck --repair` work.
//
// The directory lock is a consequence of how the store is opened, not a
// safety property anything is allowed to lean on. Destructive passes assert
// their own preconditions -- `Store.repair` calls checkWritable before it
// touches anything -- because a future path that repairs a live store would
// otherwise turn "the lock happened to stop us" into silent data loss. fsck
// carries the same defense at the level below: an unreferenced object version
// is only reclaimable once it has been complete for longer than a grace
// period and is not tombstoned as a write in flight.

package pstore

import (
	"context"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
)

// OpenMaintenance opens a stopped store for inspection or repair.
//
// When allowWrites is false every mutating entry point refuses, so an
// inspection command cannot modify the store even by mistake.
//
// Requires issuer keys, since the catalog is encrypted under a key derived
// from them.  The caller must Close the result.
func OpenMaintenance(ctx context.Context, baseDir string, allowWrites bool) (*Store, error) {
	if baseDir == "" {
		return nil, errors.New("pstore requires a base directory")
	}

	// Background workers still start, so give them a group to live in and
	// stop them on Close.
	egrp, egrpCtx := errgroup.WithContext(ctx)

	db, err := local_cache.NewCacheDB(egrpCtx, baseDir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open the pstore catalog at %s", baseDir)
	}

	// Confirm this is a pstore before interpreting any key as a pstore
	// record.
	//
	// When writes are allowed the ordinary adoption rule applies, because
	// `restore` has to be able to populate a fresh directory: an empty
	// database is claimed, a non-empty unmarked one is refused since it can
	// only be a cache predating the marker.  Inspection commands take the
	// read-only check, which never writes and so never adopts -- a CLI
	// pointed at the wrong directory should say so rather than claim it.
	if allowWrites {
		if err := db.EnsureStoreMode(local_cache.StoreModePStore); err != nil {
			db.Close()
			return nil, err
		}
	} else if err := verifyStoreMode(db); err != nil {
		db.Close()
		return nil, err
	}

	storage, err := local_cache.NewStorageManagerReadOnly(baseDir, db)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to open pstore block storage")
	}

	capacity, err := newCapacityTracker(db, storage, nil)
	if err != nil {
		storage.Close()
		db.Close()
		return nil, err
	}

	store := &Store{
		db:        db,
		storage:   storage,
		bdb:       db.DB(),
		capacity:  capacity,
		dirLabels: storageDirLabels(storage),
		detached:  newDetachedSet(),
		readOnly:  !allowWrites,
		egrp:      egrp,
	}
	if err := store.reloadDetached(); err != nil {
		storage.Close()
		db.Close()
		return nil, err
	}
	return store, nil
}

// ReadOnly reports whether the store refuses mutations.
func (s *Store) ReadOnly() bool { return s.readOnly }

// verifyStoreMode checks the mode marker without writing one.
func verifyStoreMode(db *local_cache.CacheDB) error {
	var found local_cache.StoreMode
	err := db.DB().View(func(txn *badger.Txn) error {
		item, gErr := txn.Get([]byte(local_cache.KeyStoreMode))
		if gErr != nil {
			return gErr
		}
		return item.Value(func(val []byte) error {
			found = local_cache.StoreMode(val)
			return nil
		})
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return errors.New("this database has no store mode marker, so it is not a pstore " +
			"(a cache predating the marker has none; use the cache introspection commands)")
	}
	if err != nil {
		return errors.Wrap(err, "failed to read the store mode marker")
	}
	if found != local_cache.StoreModePStore {
		return errors.Errorf("this database belongs to a %q store, not a pstore", string(found))
	}
	return nil
}
