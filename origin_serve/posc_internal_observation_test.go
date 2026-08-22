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

package origin_serve

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/afero"
)

// TestPoscInternal_RemoveAllSkipsObservation is the regression guard for the
// spurious-object.deleted bug: POSC's own plumbing — the reaper removing a
// stale staging file, and the transactional rollback removing a `final`
// whose commit was refused — flags its context withPoscInternal. The
// observation layer must then NOT publish object.deleted for those removals
// (no object.committed was ever published for them), while an ordinary
// delete still does.
func TestPoscInternal_RemoveAllSkipsObservation(t *testing.T) {
	afs, dao, mem, cleanup := buildTrackingFS(t, "/exp")
	defer cleanup()
	ctx := context.Background()

	var deletes int32
	afs.obs.onDelete = func(context.Context, string) { atomic.AddInt32(&deletes, 1) }

	commitHook := RecordCommitCloseHook(dao, "/exp", false)
	seedCommitted := func(path string) {
		t.Helper()
		if err := afero.WriteFile(mem, path, []byte("payload"), 0644); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		info, _ := mem.Stat(path)
		if err := commitHook(ctx, path, withBackendETag(info)); err != nil {
			t.Fatalf("commit %s: %v", path, err)
		}
		flushBatcher(t, dao)
	}

	// A POSC-internal removal (rollback / reaper) must not publish a delete.
	seedCommitted("/data/rolled-back.bin")
	if err := afs.RemoveAll(withPoscInternal(ctx), "/data/rolled-back.bin"); err != nil {
		t.Fatalf("internal RemoveAll: %v", err)
	}
	flushBatcher(t, dao)
	if n := atomic.LoadInt32(&deletes); n != 0 {
		t.Fatalf("POSC-internal RemoveAll fired onDelete %d times, want 0", n)
	}

	// Control: an ordinary delete of a real object still publishes.
	seedCommitted("/data/real.bin")
	if err := afs.RemoveAll(ctx, "/data/real.bin"); err != nil {
		t.Fatalf("ordinary RemoveAll: %v", err)
	}
	flushBatcher(t, dao)
	if n := atomic.LoadInt32(&deletes); n != 1 {
		t.Fatalf("ordinary RemoveAll fired onDelete %d times, want 1", n)
	}
}

// TestPoscInternal_StatSkipsObservation confirms a Stat flagged
// withPoscInternal (e.g. POSC's keepalive/size check on a staging file)
// does not drive the change-detection ladder, so it never publishes a
// spurious object.updated for an out-of-band-looking etag difference.
func TestPoscInternal_StatSkipsObservation(t *testing.T) {
	afs, dao, mem, cleanup := buildTrackingFS(t, "/exp")
	defer cleanup()
	ctx := context.Background()

	var updates int32
	afs.obs.onUpdate = func(context.Context, string, int64, string, time.Time) {
		atomic.AddInt32(&updates, 1)
	}

	if err := afero.WriteFile(mem, "/data/x.bin", []byte("v1"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	info, _ := mem.Stat("/data/x.bin")
	commitHook := RecordCommitCloseHook(dao, "/exp", false)
	if err := commitHook(ctx, "/data/x.bin", withBackendETag(info)); err != nil {
		t.Fatalf("commit: %v", err)
	}
	flushBatcher(t, dao)

	// Simulate an out-of-band change so a normal Stat would fire onUpdate.
	later := time.Now().Add(time.Hour)
	if err := mem.Chtimes("/data/x.bin", later, later); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// A POSC-internal Stat must ignore the change.
	if _, err := afs.Stat(withPoscInternal(ctx), "/data/x.bin"); err != nil {
		t.Fatalf("internal Stat: %v", err)
	}
	flushBatcher(t, dao)
	if n := atomic.LoadInt32(&updates); n != 0 {
		t.Fatalf("POSC-internal Stat fired onUpdate %d times, want 0", n)
	}

	// Control: an ordinary Stat detects the out-of-band change and publishes.
	if _, err := afs.Stat(ctx, "/data/x.bin"); err != nil {
		t.Fatalf("ordinary Stat: %v", err)
	}
	flushBatcher(t, dao)
	if n := atomic.LoadInt32(&updates); n != 1 {
		t.Fatalf("ordinary Stat fired onUpdate %d times, want 1", n)
	}
}
