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

// Package pstore ("pelican store") uses the cache V2 block store as an
// origin's primary data store rather than as a cache.
//
// The block store underneath local_cache — encrypted 4080-byte blocks,
// multi-directory spreading, chunking for large objects, and a BadgerDB
// catalog that is itself encrypted at rest — is a general-purpose object store
// that happens to be used by a cache.  pstore drives it directly, adds the one
// thing a cache never needed (a directory index), and exposes the result as an
// afero.Fs so it drops into the origin's existing serving stack.
//
// Objects are immutable: Pelican has no mid-file edits, so a write always
// creates a complete new version and atomically swaps it in.  There is no
// eviction; when the store fills, writes fail with ErrNoSpace until something
// is deleted.
//
// See docs/pstore-design.md for the full design.
package pstore

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
)

const (
	// defaultDirMode is the mode reported for directories.  pstore does not
	// implement per-entry ownership or permissions; access control is the
	// origin's authorization layer, not the store's.
	defaultDirMode os.FileMode = os.ModeDir | 0755
	// defaultFileMode is the mode reported for objects.
	defaultFileMode os.FileMode = 0644

	// atimeDebounce bounds how often a read refreshes an object's access
	// time.  Below this interval a read is a single metadata get and skips
	// the index update entirely.
	atimeDebounce = 15 * time.Minute
)

// Config describes a store to open.
type Config struct {
	// BaseDir holds the BadgerDB catalog.  It is also the first storage
	// directory when StorageDirs is empty.
	BaseDir string

	// StorageDirs are the directories object data is spread across.  When
	// empty, BaseDir is used as the sole storage directory.
	StorageDirs []local_cache.StorageDirConfig

	// InlineMaxBytes is the largest object stored directly in the catalog
	// rather than on disk.  Zero selects local_cache.InlineThreshold.
	InlineMaxBytes int

	// NamespaceLabel names the store in the catalog's usage counters.
	//
	// A store is one accounting unit spanning however many exports are mapped
	// onto subtrees of it, because capacity is enforced store-wide (§7).
	// Per-export accounting arrives with path-based quotas, where the lot
	// tree is the natural place for it.  Empty selects the store root.
	NamespaceLabel string
}

// Store is the object store backing a pstore origin.
//
// It owns the catalog and the block store, and is safe for concurrent use.  A
// store has exclusive ownership of its directories for its lifetime, exactly
// as the cache does.
type Store struct {
	db      *local_cache.CacheDB
	storage *local_cache.StorageManager
	bdb     *badger.DB

	capacity *capacityTracker

	// dirLabels names each storage directory for the capacity gauges.  Built
	// once at open, because resolving a storage ID to its configured path
	// means walking the block store's directory map and every publish would
	// otherwise redo it.
	dirLabels map[local_cache.StorageID]string

	// namespaceID scopes this store's usage counters.  A store backs one
	// export, so a single ID covers everything in it.
	namespaceID local_cache.NamespaceID

	// detached holds subtree roots that RemoveAll has unlinked but the
	// janitor has not finished draining.  Their descendants remain in the
	// index, so lookups must treat them as already gone.
	detached *detachedSet

	// readOnly marks a store opened for offline inspection; every mutating
	// entry point refuses rather than failing deeper down in BadgerDB.
	readOnly bool

	// egrp is set only for maintenance opens, which own the group their
	// background workers run in and must drain it on Close.
	egrp *errgroup.Group

	closeOnce sync.Once
}

// checkWritable reports an error when the store was opened read-only.
func (s *Store) checkWritable() error {
	if s.readOnly {
		return errors.Wrap(ErrNotSupported, "the store is open read-only")
	}
	return nil
}

// Open initializes a store, creating it if the directory is empty.
//
// Requires issuer keys to be available (config.GetIssuerPublicJWKS or the test
// helper), because the catalog and every object's data key are encrypted under
// a master key derived from them.
func Open(ctx context.Context, egrp *errgroup.Group, cfg Config) (*Store, error) {
	if cfg.BaseDir == "" {
		return nil, errors.New("pstore requires a base directory")
	}

	dirs := cfg.StorageDirs
	if len(dirs) == 0 {
		dirs = []local_cache.StorageDirConfig{{Path: cfg.BaseDir}}
	}
	dirPaths := make([]string, len(dirs))
	for i, d := range dirs {
		if d.Path == "" {
			return nil, errors.Errorf("pstore storage directory %d has an empty path", i)
		}
		dirPaths[i] = d.Path
	}

	db, err := local_cache.NewCacheDB(ctx, cfg.BaseDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open the pstore catalog")
	}

	// Claim the database before touching it: a cache and a pstore share this
	// key space, so opening one as the other would silently corrupt it.
	if err := db.EnsureStoreMode(local_cache.StoreModePStore); err != nil {
		db.Close()
		return nil, err
	}

	storage, err := local_cache.NewStorageManager(db, dirPaths, cfg.InlineMaxBytes, egrp)
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "failed to open pstore block storage")
	}

	capacity, err := newCapacityTracker(db, storage, dirs)
	if err != nil {
		storage.Close()
		db.Close()
		return nil, err
	}

	namespaceID, err := resolveNamespaceID(db, cfg.NamespaceLabel)
	if err != nil {
		storage.Close()
		db.Close()
		return nil, err
	}

	store := &Store{
		db:          db,
		storage:     storage,
		bdb:         db.DB(),
		capacity:    capacity,
		dirLabels:   storageDirLabels(storage),
		namespaceID: namespaceID,
		detached:    newDetachedSet(),
	}

	// The block store's default chooser is round-robin, which ignores how
	// full each directory is; hand it one driven by the capacity limits.
	storage.SetChooseDir(capacity.chooseDir)

	// A crash mid-drain leaves queue entries behind; reload them so the
	// half-deleted trees stay invisible.
	if err := store.reloadDetached(); err != nil {
		storage.Close()
		db.Close()
		return nil, err
	}

	// Publish capacity before serving starts.  The tracker has just recovered
	// the store's real usage from the catalog, and a gauge that only becomes
	// correct after the first write would tell an operator that a restarted
	// origin holding terabytes was empty -- for however long it took the next
	// PUT to arrive.
	store.publishCapacityMetrics()
	store.publishReclamationMetrics()

	return store, nil
}

// resolveNamespaceID assigns a stable usage-accounting ID to the store's
// export, reusing the catalog's existing namespace index.
func resolveNamespaceID(db *local_cache.CacheDB, prefix string) (local_cache.NamespaceID, error) {
	if prefix == "" {
		prefix = "/"
	}
	existing, next, err := db.LoadNamespaceMappings()
	if err != nil {
		return 0, errors.Wrap(err, "failed to load namespace mappings")
	}
	if id, ok := existing[prefix]; ok {
		return id, nil
	}
	if next == 0 {
		next = 1
	}
	if err := db.SetNamespaceMapping(prefix, next); err != nil {
		return 0, errors.Wrapf(err, "failed to register namespace %s", prefix)
	}
	return next, nil
}

// Close releases the store's resources.
//
// Safe to call more than once: the origin closes a store both explicitly and
// from the shutdown goroutine watching the server context, and the block
// store's TTL caches do not tolerate being stopped twice.
func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.storage.Close()
		err = s.db.Close()
		// A maintenance open owns its error group; wait for the block
		// store's workers so the process can exit.
		if s.egrp != nil {
			if wErr := s.egrp.Wait(); wErr != nil && err == nil {
				err = wErr
			}
		}
	})
	return err
}

// DB exposes the catalog, for introspection and tests.
func (s *Store) DB() *local_cache.CacheDB { return s.db }

// Storage exposes the block store, for introspection and tests.
func (s *Store) Storage() *local_cache.StorageManager { return s.storage }

// ---------------------------------------------------------------------------
// Namespace operations
// ---------------------------------------------------------------------------

// Stat returns the entry at the given path.
func (s *Store) Stat(name string) (*Dirent, error) {
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return nil, err
	}
	var d *Dirent
	err = s.bdb.View(func(txn *badger.Txn) error {
		var gErr error
		d, gErr = s.resolve(txn, cleanPath)
		return gErr
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// List returns the direct children of a directory in name order.
//
// after resumes a previous listing at the first name strictly greater than it;
// limit bounds the result (0 means unbounded).  The bool reports whether more
// entries remain.
func (s *Store) List(name string, after string, limit int) ([]ListEntry, bool, error) {
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return nil, false, err
	}
	var (
		entries []ListEntry
		more    bool
	)
	err = s.bdb.View(func(txn *badger.Txn) error {
		if dErr := s.requireDirResolved(txn, cleanPath); dErr != nil {
			return dErr
		}
		var lErr error
		entries, more, lErr = listDir(txn, cleanPath, after, limit)
		return lErr
	})
	if err != nil {
		return nil, false, err
	}
	return entries, more, nil
}

// Mkdir creates a single directory.  The parent must already exist.
func (s *Store) Mkdir(name string) error {
	if err := s.checkWritable(); err != nil {
		return err
	}
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return err
	}
	if isRootPath(cleanPath) {
		return ErrExist
	}
	parent, _ := splitPath(cleanPath)

	if err := s.checkNotDraining(cleanPath); err != nil {
		return err
	}

	return s.bdb.Update(func(txn *badger.Txn) error {
		if pErr := s.requireDirResolved(txn, parent); pErr != nil {
			if errors.Is(pErr, ErrNotExist) {
				return errors.Wrapf(ErrNotExist, "parent directory %s does not exist", parent)
			}
			return pErr
		}
		if _, gErr := s.resolve(txn, cleanPath); gErr == nil {
			return ErrExist
		} else if !errors.Is(gErr, ErrNotExist) {
			return gErr
		}
		return putDirent(txn, cleanPath, &Dirent{
			Type:       EntryDir,
			MTimeNanos: time.Now().UnixNano(),
			Mode:       uint32(defaultDirMode.Perm()),
		})
	})
}

// MkdirAll creates a directory and any missing ancestors.  It succeeds when
// the directory already exists.
func (s *Store) MkdirAll(name string) error {
	if err := s.checkWritable(); err != nil {
		return err
	}
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return err
	}
	if isRootPath(cleanPath) {
		return nil
	}

	if err := s.checkNotDraining(cleanPath); err != nil {
		return err
	}

	// Collect the chain root-ward so ancestors are created outermost first.
	var missing []string
	for cur := cleanPath; !isRootPath(cur); {
		missing = append(missing, cur)
		cur, _ = splitPath(cur)
	}

	return s.bdb.Update(func(txn *badger.Txn) error {
		now := time.Now().UnixNano()
		for i := len(missing) - 1; i >= 0; i-- {
			p := missing[i]
			d, gErr := s.resolve(txn, p)
			if gErr == nil {
				if !d.IsDir() {
					return errors.Wrapf(ErrNotDir, "%s exists and is not a directory", p)
				}
				continue
			}
			if !errors.Is(gErr, ErrNotExist) {
				return gErr
			}
			if pErr := putDirent(txn, p, &Dirent{
				Type:       EntryDir,
				MTimeNanos: now,
				Mode:       uint32(defaultDirMode.Perm()),
			}); pErr != nil {
				return pErr
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Removal and rename
// ---------------------------------------------------------------------------

// Remove deletes a file, or an empty directory.
//
// The entry and its reclamation record are written together, so the object's
// bytes can never become unreachable without also being queued for the
// janitor.
func (s *Store) Remove(name string) error {
	if err := s.checkWritable(); err != nil {
		return err
	}
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return err
	}
	if isRootPath(cleanPath) {
		return errors.Wrap(ErrInvalidPath, "cannot remove the store root")
	}

	return s.bdb.Update(func(txn *badger.Txn) error {
		d, gErr := s.resolve(txn, cleanPath)
		if gErr != nil {
			return gErr
		}
		if d.IsDir() {
			hasChildren, cErr := dirHasChildren(txn, cleanPath)
			if cErr != nil {
				return cErr
			}
			if hasChildren {
				return ErrNotEmpty
			}
			return deleteDirent(txn, cleanPath)
		}
		if dErr := deleteDirent(txn, cleanPath); dErr != nil {
			return dErr
		}
		if d.Generation == "" {
			return nil
		}
		return enqueueInstance(txn, instanceHashFor(s.db, d.Generation))
	})
}

// RemoveAll deletes a path and everything beneath it.
//
// A large subtree cannot be removed in one transaction, so the entry is
// unlinked from its parent — making the subtree unreachable at once — and its
// root handed to the janitor to drain.  Deletion need not be atomic: a
// partially drained subtree is invisible either way.
func (s *Store) RemoveAll(name string) error {
	if err := s.checkWritable(); err != nil {
		return err
	}
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return err
	}
	if isRootPath(cleanPath) {
		return errors.Wrap(ErrInvalidPath, "cannot remove the store root")
	}

	// The transaction is driven by hand rather than through bdb.Update so the
	// detached mark can be raised between the last write and the commit.
	// Raising it afterwards leaves a window in which the subtree is already
	// unlinked but still resolves: Stat, OpenRead and List on a descendant
	// succeed on data that is gone, and a Create that slips past
	// checkNotDraining materializes an instance whose commit then fails.
	txn := s.bdb.NewTransaction(true)
	defer txn.Discard()

	detached := false
	err = func() error {
		d, gErr := s.resolve(txn, cleanPath)
		if gErr != nil {
			return gErr
		}
		if dErr := deleteDirent(txn, cleanPath); dErr != nil {
			return dErr
		}
		if !d.IsDir() {
			if d.Generation == "" {
				return nil
			}
			return enqueueInstance(txn, instanceHashFor(s.db, d.Generation))
		}

		// Remove the whole subtree now when it is small enough to fit in this
		// transaction, which covers nearly every real removal.
		//
		// This matters for more than latency.  A detached subtree leaves its
		// descendants in the index under keys the same paths would reuse, so
		// recreating the tree before the janitor drains it would put new
		// entries where the drain is about to delete.  Finishing inline
		// removes that window entirely; only a subtree too large for one
		// transaction is deferred, and re-creating one of those is refused
		// until the drain completes rather than silently losing data.
		done, dErr := deleteSubtreeInline(txn, s.db, cleanPath)
		if dErr != nil {
			return dErr
		}
		if done {
			return nil
		}
		detached = true
		return enqueueSubtree(txn, cleanPath)
	}()
	// Matching os.RemoveAll, removing something that is not there is not an
	// error.
	if errors.Is(err, ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	if detached {
		// Descendants keep their index keys until the janitor drains them,
		// and a path-derived lookup does not consult ancestors, so they must
		// be masked explicitly until then.  See detached.go.
		s.detached.add(cleanPath)
	}
	if cErr := txn.Commit(); cErr != nil {
		if detached {
			// Nothing was unlinked after all, so the mask must come back down
			// or the subtree stays invisible for the life of the process.
			s.detached.remove(cleanPath)
		}
		return errors.Wrapf(cErr, "failed to remove %s", cleanPath)
	}
	return nil
}

// Rename moves an entry, replacing any existing file at the destination.
//
// Renaming a file rewrites one key.  Renaming a directory rewrites every
// descendant's key, which is why it is O(descendants) — but object identity
// does not depend on the path, so no data file is touched and no bytes move.
func (s *Store) Rename(oldName, newName string) error {
	if err := s.checkWritable(); err != nil {
		return err
	}
	oldPath, err := cleanRelative(oldName)
	if err != nil {
		return err
	}
	newPath, err := cleanRelative(newName)
	if err != nil {
		return err
	}
	if isRootPath(oldPath) || isRootPath(newPath) {
		return errors.Wrap(ErrInvalidPath, "cannot rename the store root")
	}
	if oldPath == newPath {
		return nil
	}
	// Moving a directory into itself would detach the subtree from the tree.
	if strings.HasPrefix(newPath, oldPath+"/") {
		return errors.Wrapf(ErrInvalidPath, "cannot move %s beneath itself", oldPath)
	}

	// Both ends have to be checked against the drain queue, and neither check
	// can be left to the resolves below: resolve *masks* a detached path as
	// ErrNotExist, so a destination that is a subtree still being reclaimed
	// looks like free space.  The rename would then succeed, rebase the source
	// onto keys the drain is about to walk, and the janitor would delete both
	// subtrees without anything reporting an error.
	if err := s.checkNotDraining(oldPath); err != nil {
		return err
	}
	if err := s.checkNotDraining(newPath); err != nil {
		return err
	}

	return s.bdb.Update(func(txn *badger.Txn) error {
		src, gErr := s.resolve(txn, oldPath)
		if gErr != nil {
			return gErr
		}
		newParent, _ := splitPath(newPath)
		if pErr := s.requireDirResolved(txn, newParent); pErr != nil {
			return pErr
		}

		// A destination file is replaced; its version still needs reclaiming.
		if dst, dErr := s.resolve(txn, newPath); dErr == nil {
			switch {
			case dst.IsDir():
				return ErrIsDir
			case src.IsDir():
				return ErrNotDir
			}
			if dst.Generation != "" {
				if eErr := enqueueInstance(txn, instanceHashFor(s.db, dst.Generation)); eErr != nil {
					return eErr
				}
			}
		} else if !errors.Is(dErr, ErrNotExist) {
			return dErr
		}

		if src.IsDir() {
			if mErr := moveSubtree(txn, oldPath, newPath); mErr != nil {
				return mErr
			}
		}
		if dErr := deleteDirent(txn, oldPath); dErr != nil {
			return dErr
		}
		return putDirent(txn, newPath, src)
	})
}

// renameSubtreeLimit bounds how many descendants a single directory rename may
// rewrite.
//
// A rename is atomic by construction — every key moves in one transaction, or
// none does — and BadgerDB caps how much one transaction may hold.  Past that
// cap the commit fails with "Txn is too big to fit into one request", which is
// not something a WebDAV client can act on.  Batching the rewrite across
// several transactions would lift the ceiling but would also mean a crash
// mid-rename could leave a tree half under each name, which is a far worse
// failure than a refusal: rename is the one namespace operation callers rely
// on being all-or-nothing.  So the limit is enforced explicitly, before
// anything is written, and reported as ErrNotSupported with an actionable
// message.
//
// The value is well under the point where BadgerDB actually refuses (~150k
// entries with dirents this size), so the typed error always wins the race
// against the raw one.
const renameSubtreeLimit = 50_000

// moveSubtree rewrites every descendant key so it hangs off newRoot.
//
// Only index keys change: an object's identity comes from its generation, not
// its path, so metadata, block state, and data files all stay put.
func moveSubtree(txn *badger.Txn, oldRoot, newRoot string) error {
	type move struct {
		path   string
		dirent *Dirent
	}
	var moves []move
	oversize := false

	if err := walkSubtree(txn, oldRoot, func(entryPath string, d *Dirent) error {
		if len(moves) >= renameSubtreeLimit {
			oversize = true
			return errStopWalk
		}
		moves = append(moves, move{path: entryPath, dirent: d})
		return nil
	}); err != nil && !errors.Is(err, errStopWalk) {
		return err
	}
	if oversize {
		return errors.Wrapf(ErrNotSupported,
			"cannot rename %s: it holds more than %d entries, which does not fit in "+
				"one atomic transaction; move its children in smaller groups",
			oldRoot, renameSubtreeLimit)
	}

	for _, m := range moves {
		if err := deleteDirent(txn, m.path); err != nil {
			return err
		}
		rebased := newRoot + strings.TrimPrefix(m.path, oldRoot)
		if err := putDirent(txn, rebased, m.dirent); err != nil {
			return err
		}
	}
	return nil
}
