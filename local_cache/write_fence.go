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

import (
	"sync"
	"sync/atomic"
)

// instanceFences orders the writes of an instance's writers against the
// instance's deletion.
//
// A writer -- the BlockWriter of a download, a fill, a reader's own fetch or
// an auto-repair, a fetcher recording a transfer's checksums, the
// consistency scan recording what it verified -- can still be running when
// its instance is deleted, by an explicit evict, LRU eviction, the
// consistency scan, or the drop of a condemned object.  What it writes to
// the database afterwards outlives the deletion: block rows
// (MarkBlocksDownloaded) and metadata (MergeMetadata creates a record where
// none exists).  If the same version is fetched again it gets the same
// instance hash, and those rows become phantom blocks, or a phantom
// completion, of the new instance.  A check of some flag before writing
// cannot close that, since the deletion can land between the check and
// the write.
//
// So each writer joins its instance's fence when it is created, recording
// the instance's generation, and makes each of its database writes through
// it (writeFence.write), under the fence's lock held shared; a deletion
// holds the lock exclusively while it deletes the instance's records and
// caches, and advances the generation once they are gone.  A write is
// therefore wholly before a deletion, which then removes it, or wholly
// after, when the writer finds the generation moved and writes nothing.
// A writer created after the deletion joins at the new generation and
// writes for whatever instance exists by then.
//
// A deletion also removes the instance's local files inside its exclusive
// section, and every creation of an instance -- its record and its files --
// holds the fence shared (create), so that a fetch of the same version
// after a deletion cannot have its new files removed by the deletion that
// came before it.  A creation that a deletion races in the other order,
// after the creator read that no record exists and before it wrote one,
// simply makes the instance again, record and files together: a
// consistent object, as if it had been fetched once more.
//
// A writer that finds what it wrote condemned -- a fill, a reader's own
// fetch, a download -- drops the instance through its own membership
// (excludeAs): only if the instance is still the one it joined.  Once that
// has been deleted the hash may name a new instance, the same version
// fetched again, which owes nothing to the writer's verdict.  For the same
// reason a writer's verdict, and a download's end, reach only the block
// state of its own instance, never one looked up by hash afterwards.  A
// verdict on an instance by something that is not its writer -- a proxied
// read that finds the instance's tiered copy changed, an auto-repair that
// finds blocks corrupt -- holds no membership, so it names the life it saw
// by the record's data key, which every new instance gets afresh, and acts
// only if the record still carries it, checked under the fence
// (StorageManager.deleteIf, clearCorruptBlocks).
//
// A fence lives only while a writer has joined it or a deletion holds it,
// so the registry holds an entry per instance being written or deleted
// now, not one per instance ever written.  Generations are compared only
// within one entry's life: a writer holds the entry for its whole life, so
// no writer can see an entry that was dropped and made again.
type instanceFences struct {
	mu sync.Mutex
	m  map[InstanceHash]*instanceFence

	// beforeWrite, set only by tests, runs at the start of every fenced
	// write, before the fence's lock is taken.
	beforeWrite func(InstanceHash)
	// beforeCreate, set only by tests, runs at the start of every
	// creation (see create), before the fence's lock is taken.
	beforeCreate func(InstanceHash)
}

// instanceFence is one instance's fence.
type instanceFence struct {
	// mu is held shared by a writer for each write, and exclusively by a
	// deletion of the instance.
	mu sync.RWMutex
	// gen counts the deletions of the instance while the fence has lived;
	// written with mu held exclusively.
	gen uint64
	// refs counts the writers that have joined the fence and the deletions
	// and creations holding it; guarded by instanceFences.mu.
	refs int
	// waiting counts the creations and deletions waiting for mu, for tests.
	waiting atomic.Int32
}

// writeFence is one writer's membership of its instance's fence.
type writeFence struct {
	fences *instanceFences
	hash   InstanceHash
	f      *instanceFence
	gen    uint64
	leave  func()
	// dead marks a clone made too late to be fenced (see clone).
	dead bool
}

func newInstanceFences() *instanceFences {
	return &instanceFences{m: make(map[InstanceHash]*instanceFence)}
}

// hold returns the hash's fence, made if need be, counting the caller in.
func (fs *instanceFences) hold(hash InstanceHash) *instanceFence {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f := fs.m[hash]
	if f == nil {
		f = &instanceFence{}
		fs.m[hash] = f
	}
	f.refs++
	return f
}

// drop counts a holder of the hash's fence out, and forgets the fence with
// its last holder.
func (fs *instanceFences) drop(hash InstanceHash, f *instanceFence) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f.refs--
	if f.refs == 0 {
		delete(fs.m, hash)
	}
}

// join makes the caller a writer of the instance as it is now.  Join before
// reading anything of the instance the writes will depend on -- its
// metadata, its data key -- so that a deletion after the read also fences
// the writer.  The writer must call leave when it has finished writing.
func (fs *instanceFences) join(hash InstanceHash) *writeFence {
	f := fs.hold(hash)
	f.mu.RLock()
	gen := f.gen
	f.mu.RUnlock()
	return &writeFence{
		fences: fs,
		hash:   hash,
		f:      f,
		gen:    gen,
		leave:  sync.OnceFunc(func() { fs.drop(hash, f) }),
	}
}

// write runs fn, which makes the writer's database writes, unless the
// instance has been deleted since the writer joined; it reports whether fn
// ran.  fn must not delete the instance, nor make a fenced write of its own.
func (w *writeFence) write(fn func()) bool {
	if w.fences.beforeWrite != nil {
		w.fences.beforeWrite(w.hash)
	}
	if w.dead {
		return false
	}
	w.f.mu.RLock()
	defer w.f.mu.RUnlock()
	if w.f.gen != w.gen {
		return false
	}
	fn()
	return true
}

// stale reports whether the instance has been deleted since the writer
// joined, so that the hash may now name another instance.
func (w *writeFence) stale() bool {
	if w.dead {
		return true
	}
	w.f.mu.RLock()
	defer w.f.mu.RUnlock()
	return w.f.gen != w.gen
}

// clone makes another member of the fence at the writer's generation, for
// writes that belong to the writer but may come after it leaves: they are
// fenced off if the instance was deleted since the writer joined.  The
// clone must leave too.  Cloned after the writer has left, when its fence
// may have been forgotten and nothing can tell whether the instance has
// been deleted since, the clone writes nothing.
func (w *writeFence) clone() *writeFence {
	fs := w.fences
	fs.mu.Lock()
	defer fs.mu.Unlock()
	c := &writeFence{fences: fs, hash: w.hash, f: w.f, gen: w.gen}
	if fs.m[w.hash] != w.f {
		c.dead = true
		c.leave = func() {}
		return c
	}
	w.f.refs++
	c.leave = sync.OnceFunc(func() { fs.drop(w.hash, w.f) })
	return c
}

// exclude shuts every writer of the instance out until the returned
// function is called: it waits for writes in progress to finish, and holds
// off new ones and new writers.  The caller deletes the instance's records
// and in-memory state in between, and passes the release whether it did,
// which fences off every writer that joined before.
func (fs *instanceFences) exclude(hash InstanceHash) (release func(deleted bool)) {
	f := fs.hold(hash)
	f.waiting.Add(1)
	f.mu.Lock()
	f.waiting.Add(-1)
	return func(deleted bool) {
		if deleted {
			f.gen++
		}
		f.mu.Unlock()
		fs.drop(hash, f)
	}
}

// excludeAs is exclude for a deletion made on behalf of writer w, which
// still holds its membership: it shuts the instance's writers out only if
// the instance is still the one w joined, and otherwise returns nil.  Once
// the instance has been deleted since w joined, the hash may name a new
// instance, which is not w's to delete.
func (fs *instanceFences) excludeAs(w *writeFence) (release func(deleted bool)) {
	if w.dead {
		return nil
	}
	release = fs.exclude(w.hash)
	// w holds w.f, so exclude took w.f; gen is written only under its lock,
	// which exclude now holds.
	if w.f.gen != w.gen {
		release(false)
		return nil
	}
	return release
}

// create runs fn, which creates an instance -- its record, its files --
// under the instance's fence held shared, so that the creation is wholly
// before a deletion of the instance or wholly after it.  A deletion that
// removed the old instance's record therefore cannot go on to remove the
// files of a new instance created under the same hash, nor a creation land
// between a deletion's record and its files.  Unlike a writer's write, a
// creation is not refused for a deletion before it: it creates the
// instance there is to be.  fn must not take the fence again.
func (fs *instanceFences) create(hash InstanceHash, fn func()) {
	f := fs.hold(hash)
	defer fs.drop(hash, f)
	if fs.beforeCreate != nil {
		fs.beforeCreate(hash)
	}
	f.waiting.Add(1)
	f.mu.RLock()
	f.waiting.Add(-1)
	defer f.mu.RUnlock()
	fn()
}

// shared runs fn under the instance's fence held shared, ordering it against
// a deletion of the instance as a creation is (see create): wholly before
// the deletion or wholly after it.  A reader that opens one of the
// instance's files and caches the descriptor does so through it, so that a
// deletion cannot remove the file between the open and the caching, leaving
// a descriptor of the deleted file cached where a new instance under the
// same hash would find it.  fn must not take the fence again, so a caller
// already inside a fenced write must not use it.
func (fs *instanceFences) shared(hash InstanceHash, fn func()) {
	f := fs.hold(hash)
	defer fs.drop(hash, f)
	f.mu.RLock()
	defer f.mu.RUnlock()
	fn()
}

// waiters reports how many callers are waiting for the hash's fence, for
// tests that need to know a creation or a deletion is held off.
func (fs *instanceFences) waiters(hash InstanceHash) int32 {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if f := fs.m[hash]; f != nil {
		return f.waiting.Load()
	}
	return 0
}

// size reports how many fences are alive, for tests.
func (fs *instanceFences) size() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return len(fs.m)
}
