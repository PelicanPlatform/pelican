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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// applyObjectMetadataSchemaForTest runs the same DDL as the Goose
// migration in `database/origin_migrations/20260430120000_create_object_metadata_tables.sql`.
// Keep this string in sync with the migration; it's deliberately
// duplicated (rather than read from the embed.FS) so the test file
// has no I/O dependency at compile time.
func applyObjectMetadataSchemaForTest(t *testing.T, db *gorm.DB) {
	t.Helper()
	const ddl = `
		CREATE TABLE object_metadata (
		    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
		    namespace       TEXT     NOT NULL,
		    object_path     TEXT     NOT NULL,
		    size            INTEGER  NOT NULL,
		    etag            TEXT     NOT NULL,
		    etag_source     TEXT     NOT NULL DEFAULT 'backend',
		    backend_mtime   DATETIME NOT NULL,
		    created_at      DATETIME NOT NULL,
		    last_modified   DATETIME NOT NULL,
		    last_accessed   DATETIME,
		    actor           TEXT     NOT NULL DEFAULT '',
		    deleted_at      DATETIME,
		    source_etag     TEXT
		);
		CREATE UNIQUE INDEX idx_object_metadata_live ON object_metadata(namespace, object_path)
		    WHERE deleted_at IS NULL;
		CREATE INDEX idx_object_metadata_ns_modified ON object_metadata(namespace, last_modified);
		CREATE INDEX idx_object_metadata_deleted     ON object_metadata(deleted_at)
		    WHERE deleted_at IS NOT NULL;

		CREATE TABLE object_checksums (
		    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
		    object_id         INTEGER  NOT NULL REFERENCES object_metadata(id) ON DELETE CASCADE,
		    algorithm         TEXT     NOT NULL,
		    value             TEXT     NOT NULL,
		    computed_at       DATETIME NOT NULL,
		    etag_at_compute   TEXT     NOT NULL
		);
		CREATE UNIQUE INDEX idx_object_checksums_object_alg ON object_checksums(object_id, algorithm);

		CREATE TABLE object_metadata_history (
		    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
		    event_id        TEXT     NOT NULL UNIQUE,
		    namespace       TEXT     NOT NULL,
		    object_path     TEXT     NOT NULL,
		    event_type      TEXT     NOT NULL,
		    event_ts        DATETIME NOT NULL,
		    size            INTEGER,
		    etag            TEXT,
		    etag_source     TEXT,
		    backend_mtime   DATETIME,
		    checksums_json  TEXT     NOT NULL DEFAULT '{}',
		    actor           TEXT     NOT NULL DEFAULT '',
		    extra           TEXT     NOT NULL DEFAULT '{}',
		    source_etag     TEXT
		);
		CREATE INDEX idx_object_history_path  ON object_metadata_history(namespace, object_path, event_ts);
		CREATE INDEX idx_object_history_event ON object_metadata_history(event_type, event_ts);
		CREATE INDEX idx_object_history_ts    ON object_metadata_history(event_ts);
	`
	// glebarez's sqlite driver Exec does not handle multi-stmt
	// scripts via gorm.Exec; split and run one at a time.
	for _, stmt := range splitSQLForTest(ddl) {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("schema setup failed on stmt %q: %v", stmt, err)
		}
	}
}

// splitSQLForTest is a very small splitter — it assumes ";" never
// appears inside a string literal (true for our DDL).
func splitSQLForTest(s string) []string {
	var out []string
	cur := ""
	for _, ch := range s {
		if ch == ';' {
			t := strings.TrimSpace(cur)
			if t != "" {
				out = append(out, t)
			}
			cur = ""
			continue
		}
		cur += string(ch)
	}
	if t := strings.TrimSpace(cur); t != "" {
		out = append(out, t)
	}
	return out
}

// newObjectMetadataTestDB returns a per-test in-memory SQLite GORM
// handle with the three object-metadata tables created.
func newObjectMetadataTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:om_%s_%d?mode=memory&cache=shared", t.Name(), time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sqlDB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	applyObjectMetadataSchemaForTest(t, db)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// newTestDAO bundles a batcher + DAO for tests.
func newTestDAO(t *testing.T) (*objectMetadataDAO, *gorm.DB, func()) {
	t.Helper()
	db := newObjectMetadataTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	b := newSQLiteBatcher(ctx, db, 64, 30*time.Millisecond)
	d := newObjectMetadataDAO(db, b)
	return d, db, func() {
		cancel()
		b.Stop()
	}
}

// TestDAO_RecordCommit_UpsertsLiveAndInsertsHistory exercises the
// hot path: a commit lands both as a fresh live row and a history
// snapshot.
func TestDAO_RecordCommit_UpsertsLiveAndInsertsHistory(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	mtime := time.Now().UTC().Round(time.Millisecond)
	in := ObjectMetadataEventInput{
		Namespace:    "/exp",
		ObjectPath:   "/exp/data/x.bin",
		Size:         12345,
		ETag:         `"abc"`,
		EtagSource:   EtagSourceBackend,
		BackendMtime: mtime,
		Actor:        "alice",
		Extra:        map[string]any{"experiment": "atlas"},
		TrackExtra:   true,
	}
	if err := d.RecordCommit(ctx, in); err != nil {
		t.Fatalf("RecordCommit: %v", err)
	}

	live, err := d.LookupLive(ctx, "/exp", "/exp/data/x.bin")
	if err != nil {
		t.Fatalf("LookupLive: %v", err)
	}
	if live == nil {
		t.Fatal("expected live row after RecordCommit")
	}
	if live.Size != 12345 || live.ETag != `"abc"` || live.EtagSource != string(EtagSourceBackend) {
		t.Fatalf("live row mismatch: %#v", live)
	}
	if live.Actor != "alice" {
		t.Fatalf("actor = %q, want alice", live.Actor)
	}

	var hCount int64
	db.Model(&ObjectMetadataHistoryRow{}).
		Where("namespace = ? AND object_path = ? AND event_type = ?", "/exp", "/exp/data/x.bin", "commit").
		Count(&hCount)
	if hCount != 1 {
		t.Fatalf("history count = %d, want 1", hCount)
	}

	var hRow ObjectMetadataHistoryRow
	db.Where("event_type = ?", "commit").First(&hRow)
	if hRow.Extra != `{"experiment":"atlas"}` {
		t.Fatalf("history.extra = %q (want experiment snapshot)", hRow.Extra)
	}
}

// TestDAO_TrackExtraFalse_OmitsUploaderFields confirms that
// uploader-supplied fields are excluded from the history snapshot
// when TrackExtra is off for the namespace.
func TestDAO_TrackExtraFalse_OmitsUploaderFields(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	in := ObjectMetadataEventInput{
		Namespace:    "/exp",
		ObjectPath:   "/exp/x.bin",
		Size:         1,
		ETag:         `"a"`,
		EtagSource:   EtagSourceBackend,
		BackendMtime: time.Now().UTC(),
		Actor:        "alice",
		Extra:        map[string]any{"secret": "shouldnotleak"},
		TrackExtra:   false,
	}
	if err := d.RecordCommit(ctx, in); err != nil {
		t.Fatalf("RecordCommit: %v", err)
	}
	var hRow ObjectMetadataHistoryRow
	db.Where("event_type = ?", "commit").First(&hRow)
	if hRow.Extra != "{}" {
		t.Fatalf("history.extra = %q; expected {} when TrackExtra=false", hRow.Extra)
	}
}

// TestDAO_RecordCommit_ReplaceUpdatesInPlace — a second commit to
// the same path updates the live row's fields, preserves created_at,
// and writes a second history row.
func TestDAO_RecordCommit_ReplaceUpdatesInPlace(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	earlier := time.Now().Add(-time.Hour).UTC().Round(time.Millisecond)
	v1 := ObjectMetadataEventInput{
		Namespace: "/exp", ObjectPath: "/exp/x.bin", Size: 10,
		ETag: `"v1"`, EtagSource: EtagSourceBackend, BackendMtime: earlier,
		Actor: "alice",
	}
	if err := d.RecordCommit(ctx, v1); err != nil {
		t.Fatalf("v1: %v", err)
	}
	live1, _ := d.LookupLive(ctx, "/exp", "/exp/x.bin")
	createdAt1 := live1.CreatedAt

	v2 := v1
	v2.Size = 20
	v2.ETag = `"v2"`
	v2.BackendMtime = time.Now().UTC().Round(time.Millisecond)
	if err := d.RecordCommit(ctx, v2); err != nil {
		t.Fatalf("v2: %v", err)
	}
	live2, _ := d.LookupLive(ctx, "/exp", "/exp/x.bin")
	if live2.Size != 20 || live2.ETag != `"v2"` {
		t.Fatalf("post-replace live = %#v", live2)
	}
	if !live2.CreatedAt.Equal(createdAt1) {
		t.Fatalf("created_at changed across replace: %v vs %v", createdAt1, live2.CreatedAt)
	}

	var hCount int64
	db.Model(&ObjectMetadataHistoryRow{}).Where("event_type = ?", "commit").Count(&hCount)
	if hCount != 2 {
		t.Fatalf("commit-history count = %d, want 2", hCount)
	}
}

// TestDAO_RecordDelete_SoftDeletesAndSnapshots —
//  1. soft-delete clears the live row from LookupLive,
//  2. the previous live state is preserved in history (size, etag),
//  3. a subsequent re-upload to the same path succeeds (partial
//     unique index logic).
func TestDAO_RecordDelete_SoftDeletesAndSnapshots(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	commit := ObjectMetadataEventInput{
		Namespace: "/exp", ObjectPath: "/exp/x.bin", Size: 99,
		ETag: `"abc"`, EtagSource: EtagSourceBackend, BackendMtime: time.Now().UTC(),
		Actor: "alice",
	}
	if err := d.RecordCommit(ctx, commit); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := d.RecordDelete(ctx, ObjectMetadataEventInput{
		Namespace: "/exp", ObjectPath: "/exp/x.bin", Actor: "bob",
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	live, _ := d.LookupLive(ctx, "/exp", "/exp/x.bin")
	if live != nil {
		t.Fatalf("live still present after delete: %#v", live)
	}

	var hRow ObjectMetadataHistoryRow
	if err := db.Where("event_type = ?", "delete").First(&hRow).Error; err != nil {
		t.Fatalf("history: %v", err)
	}
	if hRow.Size == nil || *hRow.Size != 99 {
		t.Fatalf("history size snapshot = %v; want 99", hRow.Size)
	}
	if hRow.ETag == nil || *hRow.ETag != `"abc"` {
		t.Fatalf("history etag snapshot = %v; want \"abc\"", hRow.ETag)
	}
	if hRow.Actor != "bob" {
		t.Fatalf("history actor = %q; want bob (the deleter)", hRow.Actor)
	}

	// Re-upload after delete must succeed (partial unique excludes
	// the soft-deleted row).
	v2 := commit
	v2.Size = 1
	v2.ETag = `"reborn"`
	if err := d.RecordCommit(ctx, v2); err != nil {
		t.Fatalf("re-upload after delete: %v", err)
	}
	live, _ = d.LookupLive(ctx, "/exp", "/exp/x.bin")
	if live == nil || live.Size != 1 || live.ETag != `"reborn"` {
		t.Fatalf("re-upload live = %#v", live)
	}
}

// TestDAO_RecordExternalObserve_FirstSightingCreatesRow — a Stat on
// a previously-unknown path inserts both the live row and a history
// row of type external_observe.
func TestDAO_RecordExternalObserve_FirstSightingCreatesRow(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	in := ObjectMetadataEventInput{
		Namespace: "/exp", ObjectPath: "/exp/pre-existing.dat", Size: 7,
		ETag: `"orig"`, EtagSource: EtagSourceBackend, BackendMtime: time.Now().UTC(),
	}
	if err := d.RecordExternalObserve(ctx, in); err != nil {
		t.Fatalf("RecordExternalObserve: %v", err)
	}
	// Best-effort: force a flush by issuing a durable no-op.
	_ = d.batcher.FlushNow(ctx)
	live, _ := d.LookupLive(ctx, "/exp", "/exp/pre-existing.dat")
	if live == nil {
		t.Fatalf("expected live row after first sighting")
	}
	var hCount int64
	db.Model(&ObjectMetadataHistoryRow{}).Where("event_type = ?", "external_observe").Count(&hCount)
	if hCount != 1 {
		t.Fatalf("external_observe history count = %d, want 1", hCount)
	}
}

// TestDAO_RecordExternalChange_UpdatesLiveAndSnapshots —
// out-of-band modify path: original commit, then external change to
// a different etag, then LookupLive reflects the new etag.
func TestDAO_RecordExternalChange_UpdatesLiveAndSnapshots(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	commit := ObjectMetadataEventInput{
		Namespace: "/exp", ObjectPath: "/exp/x.bin", Size: 5,
		ETag: `"v1"`, EtagSource: EtagSourceBackend, BackendMtime: time.Now().UTC(),
	}
	if err := d.RecordCommit(ctx, commit); err != nil {
		t.Fatalf("commit: %v", err)
	}

	ext := commit
	ext.Size = 6
	ext.ETag = `"v2-external"`
	if err := d.RecordExternalChange(ctx, ext); err != nil {
		t.Fatalf("ext: %v", err)
	}
	// Force flush of best-effort op.
	_ = d.batcher.FlushNow(ctx)

	live, _ := d.LookupLive(ctx, "/exp", "/exp/x.bin")
	if live == nil || live.ETag != `"v2-external"` || live.Size != 6 {
		t.Fatalf("live after external_modify = %#v", live)
	}
	var hCount int64
	db.Model(&ObjectMetadataHistoryRow{}).Where("event_type = ?", "external_modify").Count(&hCount)
	if hCount != 1 {
		t.Fatalf("external_modify history count = %d, want 1", hCount)
	}
}

// TestDAO_RecordChecksum_Upserts — first call inserts, second call
// to the same (object, algo) updates the value + etag_at_compute in
// place rather than creating a duplicate row.
func TestDAO_RecordChecksum_Upserts(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	if err := d.RecordCommit(ctx, ObjectMetadataEventInput{
		Namespace: "/exp", ObjectPath: "/exp/x.bin", Size: 1,
		ETag: `"e1"`, EtagSource: EtagSourceBackend, BackendMtime: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if err := d.RecordChecksum(ctx, "/exp", "/exp/x.bin", "sha-256", "aaa", `"e1"`, time.Now().UTC()); err != nil {
		t.Fatalf("checksum v1: %v", err)
	}
	// Force flush
	_ = d.batcher.FlushNow(ctx)
	var n int64
	db.Model(&ObjectChecksumRow{}).Where("algorithm = ?", "sha-256").Count(&n)
	if n != 1 {
		t.Fatalf("after v1: count = %d, want 1", n)
	}

	if err := d.RecordChecksum(ctx, "/exp", "/exp/x.bin", "sha-256", "bbb", `"e2"`, time.Now().UTC()); err != nil {
		t.Fatalf("checksum v2: %v", err)
	}
	_ = d.batcher.FlushNow(ctx)
	var row ObjectChecksumRow
	db.Where("algorithm = ?", "sha-256").First(&row)
	if row.Value != "bbb" || row.EtagAtCompute != `"e2"` {
		t.Fatalf("post-upsert row = %#v", row)
	}
	db.Model(&ObjectChecksumRow{}).Where("algorithm = ?", "sha-256").Count(&n)
	if n != 1 {
		t.Fatalf("after v2: count = %d, want 1 (upsert)", n)
	}
}

// TestDAO_PruneHistory_RespectsAgeAndLimit confirms the pruner only
// touches rows older than the cutoff and stays under the per-pass
// budget.
func TestDAO_PruneHistory_RespectsAgeAndLimit(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	// Plant 5 fresh + 10 old history rows directly via gorm.
	old := time.Now().Add(-30 * 24 * time.Hour).UTC()
	newer := time.Now().UTC()
	for i := 0; i < 5; i++ {
		row := &ObjectMetadataHistoryRow{
			EventID: fmt.Sprintf("new-%d", i), Namespace: "/exp",
			ObjectPath: fmt.Sprintf("/exp/x-%d", i), EventType: "commit", EventTS: newer,
		}
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("create new: %v", err)
		}
	}
	for i := 0; i < 10; i++ {
		row := &ObjectMetadataHistoryRow{
			EventID: fmt.Sprintf("old-%d", i), Namespace: "/exp",
			ObjectPath: fmt.Sprintf("/exp/old-%d", i), EventType: "commit", EventTS: old,
		}
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("create old: %v", err)
		}
	}

	cutoff := time.Now().Add(-7 * 24 * time.Hour)

	// limit=3: only 3 of the 10 old rows go this pass.
	deleted, err := d.PruneHistory(ctx, "/exp", cutoff, 3)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 3 {
		t.Fatalf("prune deleted = %d, want 3 (limit)", deleted)
	}

	// Run to drain the rest.
	for {
		n, err := d.PruneHistory(ctx, "/exp", cutoff, 100)
		if err != nil {
			t.Fatalf("prune loop: %v", err)
		}
		if n == 0 {
			break
		}
	}
	var remain int64
	db.Model(&ObjectMetadataHistoryRow{}).Count(&remain)
	if remain != 5 {
		t.Fatalf("after full prune: %d rows remain, want 5 (the fresh ones)", remain)
	}
}
