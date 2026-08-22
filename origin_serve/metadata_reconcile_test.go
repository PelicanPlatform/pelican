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
	"testing"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
)

// reconcileFixture builds a tracked controller whose FilesystemForExists is
// backed by an in-memory afero FS, plants one object on disk, and returns the
// controller, DAO, memfs, and the on-disk backend ETag of the object.
func reconcileFixture(t *testing.T, settle time.Duration) (*metadataController, *objectMetadataDAO, afero.Fs, string) {
	t.Helper()
	mem := afero.NewMemMapFs()
	if err := afero.WriteFile(mem, "/data/orphan.dat", []byte("orphan-bytes"), 0o644); err != nil {
		t.Fatalf("seed object: %v", err)
	}
	afs := newAferoFileSystem(mem, "", nil)

	ctl, dao, _ := newTrackedTestController(t, ModeEventual, func(o *metadataControllerOptions) {
		o.Exports = []server_utils.OriginExport{{FederationPrefix: "/exp"}}
		o.ReconcileEnabled = true
		o.ReconcileSettleWindow = settle
		o.FilesystemForExists = func(string) webdav.FileSystem { return afs }
	})

	info, err := afs.Stat(context.Background(), "/data/orphan.dat")
	if err != nil {
		t.Fatalf("stat seeded object: %v", err)
	}
	return ctl, dao, mem, BackendETag(info)
}

// plantCommit records a commit row for the orphan and backdates its
// last_modified so it is (or isn't) past the settle window.
func plantCommit(t *testing.T, dao *objectMetadataDAO, etag string, ageBack time.Duration) {
	t.Helper()
	ctx := context.Background()
	if err := dao.RecordCommit(ctx, ObjectMetadataEventInput{
		Namespace:    "/exp",
		ObjectPath:   "/exp/data/orphan.dat",
		Size:         12,
		ETag:         etag,
		EtagSource:   EtagSourceBackend,
		BackendMtime: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordCommit: %v", err)
	}
	// Backdate last_modified to control settle-window eligibility.
	if err := dao.db.Exec(
		"UPDATE object_metadata SET last_modified = ? WHERE namespace = ? AND object_path = ?",
		time.Now().UTC().Add(-ageBack), "/exp", "/exp/data/orphan.dat").Error; err != nil {
		t.Fatalf("backdate last_modified: %v", err)
	}
}

func pendingCount(t *testing.T, ctl *metadataController) int64 {
	t.Helper()
	n, _, err := ctl.queue.NamespaceBacklog("/exp")
	if err != nil {
		t.Fatalf("NamespaceBacklog: %v", err)
	}
	return n
}

// TestReconcile_ReenqueuesSettledUnpublishedCommit is the happy path: a
// committed object with no publish watermark, at rest past the settle window,
// whose on-disk ETag still matches, is re-enqueued.
func TestReconcile_ReenqueuesSettledUnpublishedCommit(t *testing.T) {
	ctl, dao, _, etag := reconcileFixture(t, time.Hour)
	plantCommit(t, dao, etag, 2*time.Hour) // settled

	ctl.reconcileOnce(context.Background())

	if n := pendingCount(t, ctl); n != 1 {
		t.Fatalf("reconcile enqueued %d rows, want 1", n)
	}
}

// TestReconcile_SkipsRecentlyModified: an unpublished commit that is still
// within the settle window is left alone (it may be an in-flight publish, or a
// peer may still be writing).
func TestReconcile_SkipsRecentlyModified(t *testing.T) {
	ctl, dao, _, etag := reconcileFixture(t, time.Hour)
	plantCommit(t, dao, etag, 5*time.Minute) // NOT settled

	ctl.reconcileOnce(context.Background())

	if n := pendingCount(t, ctl); n != 0 {
		t.Fatalf("reconcile enqueued %d rows for a non-settled object, want 0", n)
	}
}

// TestReconcile_SkipsWhenOnDiskEtagChanged: the object was overwritten (by a
// peer or out-of-band) since our commit, so the on-disk ETag no longer matches
// the recorded commit — that change owns its own publish path.
func TestReconcile_SkipsWhenOnDiskEtagChanged(t *testing.T) {
	ctl, dao, _, _ := reconcileFixture(t, time.Hour)
	plantCommit(t, dao, "\"stale-etag-from-a-prior-version\"", 2*time.Hour) // settled but etag mismatches disk

	ctl.reconcileOnce(context.Background())

	if n := pendingCount(t, ctl); n != 0 {
		t.Fatalf("reconcile enqueued %d rows for a changed object, want 0", n)
	}
}

// TestReconcile_SkipsAlreadyPublished: once the publish watermark matches the
// live etag, the object is not reconsidered.
func TestReconcile_SkipsAlreadyPublished(t *testing.T) {
	ctl, dao, _, etag := reconcileFixture(t, time.Hour)
	plantCommit(t, dao, etag, 2*time.Hour)
	// Stamp the watermark at the current etag (as a successful publish would).
	if err := dao.MarkPublished(context.Background(), "/exp", "/exp/data/orphan.dat", etag); err != nil {
		t.Fatalf("MarkPublished: %v", err)
	}
	// MarkPublished is best-effort via the batcher; force it to land.
	flushBatcher(t, dao)

	ctl.reconcileOnce(context.Background())

	if n := pendingCount(t, ctl); n != 0 {
		t.Fatalf("reconcile enqueued %d rows for an already-published object, want 0", n)
	}
}

// TestPublish_StampsWatermarkOnSuccess locks the counterpart wiring: a
// successful tracked commit publish stamps the live row's publish watermark,
// so a later reconcile sweep leaves it alone.
func TestPublish_StampsWatermarkOnSuccess(t *testing.T) {
	ctl, dao, requests := newTrackedTestController(t, ModeEventual)
	ctx := context.Background()

	hook := ctl.CommitEventFromCloseHookTracked("/exp", dao, false)
	info := fakeFileInfo{name: "run.dat", size: 9, mod: time.Now().UTC()}
	if err := hook(ctx, "/data/run.dat", info); err != nil {
		t.Fatalf("commit hook: %v", err)
	}
	// Drain the (synchronous) first-attempt webhook.
	if typ, _ := readPublishedType(t, requests); typ != ObjectCommitEventType {
		t.Fatalf("first publish type = %q, want object.committed", typ)
	}
	// markPublished is best-effort via the batcher; force it to land.
	flushBatcher(t, dao)

	live, err := dao.LookupLive(ctx, "/exp", "/exp/data/run.dat")
	if err != nil || live == nil {
		t.Fatalf("LookupLive: row=%v err=%v", live, err)
	}
	if live.PublishedAt == nil {
		t.Fatal("successful publish did not stamp published_at watermark")
	}
}

// TestReconcile_SkipsDeletedObject: the tracked object no longer exists on
// disk, so the reconcile must not republish it.
func TestReconcile_SkipsDeletedObject(t *testing.T) {
	ctl, dao, mem, etag := reconcileFixture(t, time.Hour)
	plantCommit(t, dao, etag, 2*time.Hour)
	if err := mem.Remove("/data/orphan.dat"); err != nil {
		t.Fatalf("remove object: %v", err)
	}

	ctl.reconcileOnce(context.Background())

	if n := pendingCount(t, ctl); n != 0 {
		t.Fatalf("reconcile enqueued %d rows for a deleted object, want 0", n)
	}
}
