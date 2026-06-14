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

// File object_metadata_access.go implements the in-memory atime
// debouncer for the object-metadata tracking layer.
//
// Why a debouncer at all: every GET / HEAD on an object triggers a
// Stat through the aferoFileSystem wrapper. Writing
// last_accessed=now on every such call would produce an UPDATE per
// read — kills throughput on read-heavy hot data. The debouncer
// keeps the latest observed access time per object in a small
// in-memory map and flushes them in batches at a configurable
// cadence (default 5 minutes). Worst case on origin crash: a few
// minutes of last_accessed updates are lost; commit / delete /
// rename records are flushed durably and are not affected.

package origin_serve

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// accessKey is the map key — same shape as the observation cache,
// kept separate to avoid coupling the two layers.
type accessKey struct {
	Namespace string
	Path      string
}

// accessDebouncer maintains a per-key "latest observed access time"
// in memory and periodically flushes it to the DAO via
// RecordAccess (best-effort).
type accessDebouncer struct {
	dao      *objectMetadataDAO
	interval time.Duration

	mu      sync.Mutex
	pending map[accessKey]time.Time

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// newAccessDebouncer constructs the debouncer. Caller must invoke
// Start(ctx); Stop drains a final flush.
func newAccessDebouncer(dao *objectMetadataDAO, interval time.Duration) *accessDebouncer {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &accessDebouncer{
		dao:      dao,
		interval: interval,
		pending:  make(map[accessKey]time.Time),
	}
}

// Depth reports the current number of (namespace, path) entries
// buffered in memory awaiting flush. Nil-tolerant. Read under the
// mutex so a concurrent Flush doesn't race the gauge sample.
func (d *accessDebouncer) Depth() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	n := len(d.pending)
	d.mu.Unlock()
	return n
}

// Note records a new "observed at" timestamp for (namespace, path).
// Last-write-wins: a later Note overrides any earlier one for the
// same key in the pending buffer. Non-blocking, no allocations on
// the hot path beyond a single map insert.
func (d *accessDebouncer) Note(namespace, path string, when time.Time) {
	if d == nil || d.dao == nil {
		return
	}
	d.mu.Lock()
	d.pending[accessKey{Namespace: namespace, Path: path}] = when.UTC()
	d.mu.Unlock()
}

// Start launches the periodic flush goroutine.
func (d *accessDebouncer) Start(ctx context.Context) {
	if d == nil || d.dao == nil {
		return
	}
	childCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	d.wg.Add(1)
	go d.runLoop(childCtx)
}

// Stop cancels the goroutine, does a final flush of whatever's
// buffered, and waits for the goroutine to exit. Safe to call more
// than once or before Start.
func (d *accessDebouncer) Stop() {
	if d == nil {
		return
	}
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
	// Final flush after the goroutine has stopped — covers anything
	// added between the last tick and shutdown.
	d.Flush(context.Background())
}

// runLoop is the goroutine body.
func (d *accessDebouncer) runLoop(ctx context.Context) {
	defer d.wg.Done()
	t := time.NewTicker(d.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.Flush(ctx)
		}
	}
}

// Flush drains the pending map and enqueues one best-effort
// RecordAccess per entry. Exposed for tests + the shutdown path.
func (d *accessDebouncer) Flush(ctx context.Context) {
	if d == nil || d.dao == nil {
		return
	}
	d.mu.Lock()
	if len(d.pending) == 0 {
		d.mu.Unlock()
		return
	}
	// Swap the map under the lock so the hot Note() path keeps
	// running while we issue the writes.
	snapshot := d.pending
	d.pending = make(map[accessKey]time.Time, len(snapshot))
	d.mu.Unlock()

	for k, t := range snapshot {
		if err := d.dao.RecordAccess(ctx, k.Namespace, k.Path, t); err != nil {
			log.Debugf("access debouncer: RecordAccess(%s,%s) failed: %v", k.Namespace, k.Path, err)
		}
	}
}
