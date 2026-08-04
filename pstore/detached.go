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

// Detached subtrees.
//
// RemoveAll on a large directory cannot delete every descendant in one
// transaction, so it unlinks the directory from its parent and hands the root
// to the janitor.  With an inode-style index that would be enough: the
// descendants would be unreachable the moment the parent's entry went away.
//
// Keys here are path-derived, though, and a lookup is a single point get that
// never consults ancestors — that is exactly why listing a directory is cheap.
// The consequence is that a descendant of a detached directory stays directly
// addressable until the janitor reaches it.
//
// Rather than pay O(depth) ancestor checks on every lookup, the store keeps
// the set of detached roots in memory and tests a path against it.  The set is
// empty except while a drain is in progress, and holds one entry per RemoveAll
// still draining, so the check costs a handful of string comparisons on paths
// nobody should be reading anyway.  It is rebuilt from the pg: queue at open,
// so a crash mid-drain does not resurrect a deleted tree.

package pstore

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dgraph-io/badger/v4"
)

// badgerTxn aliases the transaction type so the resolver signature stays
// readable alongside the index helpers.
type badgerTxn = badger.Txn

// detachedSet tracks subtree roots that have been unlinked but not yet
// drained.
//
// contains is called on every path resolution, and the set is empty in all but
// the moments after a RemoveAll, so the empty case must cost as little as
// possible.  An atomic population count is consulted first and the lock is
// taken only when there is actually something to compare against; the count is
// advisory, and the authoritative check happens under the read lock.
type detachedSet struct {
	// nonEmpty mirrors len(roots) for the lock-free fast path.  It may lag by
	// the width of a single add or remove, which is harmless: a stale false
	// can only occur before the transaction that detaches a subtree has been
	// observed, and a stale true costs one wasted lock acquisition.
	nonEmpty atomic.Bool

	mu    sync.RWMutex
	roots map[string]struct{}
}

func newDetachedSet() *detachedSet {
	return &detachedSet{roots: make(map[string]struct{})}
}

// add marks a subtree as detached.
func (d *detachedSet) add(root string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.roots[root] = struct{}{}
	d.nonEmpty.Store(true)
}

// remove clears a subtree once it has been fully drained.
func (d *detachedSet) remove(root string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.roots, root)
	d.nonEmpty.Store(len(d.roots) > 0)
}

// contains reports whether cleanPath is a detached root or lies beneath one,
// in which case it must be treated as already gone.
func (d *detachedSet) contains(cleanPath string) bool {
	// The overwhelmingly common case: nothing is draining, so no lock.
	if !d.nonEmpty.Load() {
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	for root := range d.roots {
		if cleanPath == root || strings.HasPrefix(cleanPath, root+"/") {
			return true
		}
	}
	return false
}

// len reports how many subtrees are awaiting drain.
func (d *detachedSet) len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.roots)
}

// reloadDetached rebuilds the detached-subtree set from the garbage queue,
// so a store that crashed mid-drain does not expose a half-deleted tree.
func (s *Store) reloadDetached() error {
	subtrees, err := s.collectAllSubtrees()
	if err != nil {
		return err
	}
	for _, root := range subtrees {
		s.detached.add(root)
	}
	return nil
}

// resolve reads the entry at cleanPath, reporting ErrNotExist for anything
// inside a subtree that has been unlinked but not yet drained.
func (s *Store) resolve(txn *badgerTxn, cleanPath string) (*Dirent, error) {
	if s.detached.contains(cleanPath) {
		return nil, ErrNotExist
	}
	return getDirent(txn, cleanPath)
}
