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

// File object_metadata.go is the DAO for the origin's local object-
// metadata tracking subsystem. Three tables back it (see migration
// 20260430120000_create_object_metadata_tables.sql):
//
//   object_metadata         — live state, one row per non-deleted path
//   object_checksums        — one row per (object, algorithm)
//   object_metadata_history — append-only log of every observed change
//
// Every write goes through the sqliteBatcher so the request hot path
// never blocks on a sync fsync per row. The DAO classifies writes by
// origin:
//
//   * **Durable** (force a flush): caller-driven events that the
//     operator considers "real" — RecordCommit (POSC close hook),
//     RecordDelete, RecordRename. Losing one to a crash would mean
//     forgetting that the operator did the thing.
//
//   * **Best-effort** (piggyback on the next flush): observational
//     writes that are re-derivable next time we touch the path —
//     RecordExternalObserve, RecordExternalChange,
//     RecordExternalDelete, RecordAccess, RecordChecksum.
//
// The lookup helpers (LookupLive, ListHistory, PruneHistory) read
// directly from the GORM handle; reads don't go through the batcher.

package origin_serve

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// EtagSource is the discriminator persisted on every row that tells
// the operator where the ETag came from. Lets a reader distinguish
// "this is the backend's canonical answer" from "the origin filled
// in because the backend declined."
type EtagSource string

const (
	EtagSourceBackend EtagSource = "backend"
	EtagSourceOrigin  EtagSource = "origin"
)

// ObjectMetadataEvent is the high-level discriminator written to
// object_metadata_history.event_type.
type ObjectMetadataEvent string

const (
	ObjectEventCommit          ObjectMetadataEvent = "commit"
	ObjectEventDelete          ObjectMetadataEvent = "delete"
	ObjectEventRename          ObjectMetadataEvent = "rename"
	ObjectEventExternalObserve ObjectMetadataEvent = "external_observe"
	ObjectEventExternalModify  ObjectMetadataEvent = "external_modify"
	ObjectEventExternalDelete  ObjectMetadataEvent = "external_delete"
)

// ObjectMetadataRow is the GORM-mapped projection of object_metadata.
// The schema (including the partial unique index that distinguishes
// live from soft-deleted rows) is defined by the Goose migration,
// not by GORM's auto-migrate.
type ObjectMetadataRow struct {
	ID           int64      `gorm:"primaryKey;autoIncrement"`
	Namespace    string     `gorm:"column:namespace;not null;index"`
	ObjectPath   string     `gorm:"column:object_path;not null"`
	Size         int64      `gorm:"column:size;not null"`
	ETag         string     `gorm:"column:etag;not null"`
	EtagSource   string     `gorm:"column:etag_source;not null;default:'backend'"`
	BackendMtime time.Time  `gorm:"column:backend_mtime;not null"`
	CreatedAt    time.Time  `gorm:"column:created_at;not null"`
	LastModified time.Time  `gorm:"column:last_modified;not null"`
	LastAccessed *time.Time `gorm:"column:last_accessed"`
	Actor        string     `gorm:"column:actor;not null;default:''"`
	DeletedAt    *time.Time `gorm:"column:deleted_at"`
}

func (ObjectMetadataRow) TableName() string { return "object_metadata" }

// ObjectChecksumRow is the GORM-mapped projection of object_checksums.
type ObjectChecksumRow struct {
	ID            int64     `gorm:"primaryKey;autoIncrement"`
	ObjectID      int64     `gorm:"column:object_id;not null"`
	Algorithm     string    `gorm:"column:algorithm;not null"`
	Value         string    `gorm:"column:value;not null"`
	ComputedAt    time.Time `gorm:"column:computed_at;not null"`
	EtagAtCompute string    `gorm:"column:etag_at_compute;not null"`
}

func (ObjectChecksumRow) TableName() string { return "object_checksums" }

// ObjectMetadataHistoryRow is the GORM-mapped projection of
// object_metadata_history.
type ObjectMetadataHistoryRow struct {
	ID             int64     `gorm:"primaryKey;autoIncrement"`
	EventID        string    `gorm:"column:event_id;uniqueIndex;not null"`
	Namespace      string    `gorm:"column:namespace;not null"`
	ObjectPath     string    `gorm:"column:object_path;not null"`
	EventType      string    `gorm:"column:event_type;not null"`
	EventTS        time.Time `gorm:"column:event_ts;not null"`
	Size           *int64    `gorm:"column:size"`
	ETag           *string   `gorm:"column:etag"`
	EtagSource     *string   `gorm:"column:etag_source"`
	BackendMtime   *time.Time `gorm:"column:backend_mtime"`
	ChecksumsJSON  string    `gorm:"column:checksums_json;not null;default:'{}'"`
	Actor          string    `gorm:"column:actor;not null;default:''"`
	Extra          string    `gorm:"column:extra;not null;default:'{}'"`
}

func (ObjectMetadataHistoryRow) TableName() string { return "object_metadata_history" }

// ObjectMetadataEventInput is the call-site struct for every Record*
// method. Centralizing the field-set keeps the DAO API stable across
// the four event types we record.
type ObjectMetadataEventInput struct {
	Namespace    string
	ObjectPath   string             // federation-rooted, eg "/exp/data/run99.dat"
	Size         int64
	ETag         string
	EtagSource   EtagSource
	BackendMtime time.Time
	Actor        string             // token sub at request time; "" if unknown
	Extra        map[string]any     // X-Pelican-Object-Metadata; ignored if TrackExtra=false for the ns
	TrackExtra   bool               // resolved at call time from per-export overrides
}

// objectMetadataDAO is the storage layer. Stateless beyond its
// references; safe to share across goroutines.
type objectMetadataDAO struct {
	db      *gorm.DB
	batcher *sqliteBatcher
}

func newObjectMetadataDAO(db *gorm.DB, batcher *sqliteBatcher) *objectMetadataDAO {
	return &objectMetadataDAO{db: db, batcher: batcher}
}

// ============================================================
// Durable writes — caller-driven events
// ============================================================

// RecordCommit registers an upload-on-close event. Persists a history
// snapshot of the new state and UPSERTs the live row. This is on the
// request hot path (called from the POSC close hook) so the batcher's
// coalescing across concurrent commits is what keeps it cheap.
func (d *objectMetadataDAO) RecordCommit(ctx context.Context, in ObjectMetadataEventInput) error {
	now := time.Now().UTC()
	extraJSON := encodeExtra(in.TrackExtra, in.Extra)
	eventID := uuid.NewString()

	// Two statements, fate-shared in one tx:
	//   1. INSERT into history (event_type='commit', snapshot of the new commit).
	//   2. UPSERT into object_metadata (created_at preserved on conflict;
	//      last_modified, size, etag, etc. overwritten).
	stmts := []BatchedStmt{
		{
			SQL: `INSERT INTO object_metadata_history
				(event_id, namespace, object_path, event_type, event_ts,
				 size, etag, etag_source, backend_mtime, actor, extra)
				VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			Args: []any{
				eventID, in.Namespace, in.ObjectPath, string(ObjectEventCommit), now,
				in.Size, in.ETag, string(in.EtagSource), in.BackendMtime, in.Actor, extraJSON,
			},
		},
		{
			// Conflict scope is the partial unique index on live
			// rows: (namespace, object_path) WHERE deleted_at IS NULL.
			SQL: `INSERT INTO object_metadata
				(namespace, object_path, size, etag, etag_source,
				 backend_mtime, created_at, last_modified, actor)
				VALUES (?,?,?,?,?,?,?,?,?)
				ON CONFLICT(namespace, object_path) WHERE deleted_at IS NULL DO UPDATE SET
					size          = excluded.size,
					etag          = excluded.etag,
					etag_source   = excluded.etag_source,
					backend_mtime = excluded.backend_mtime,
					last_modified = excluded.last_modified,
					actor         = excluded.actor`,
			Args: []any{
				in.Namespace, in.ObjectPath, in.Size, in.ETag, string(in.EtagSource),
				in.BackendMtime, now, now, in.Actor,
			},
		},
	}
	return d.batcher.EnqueueDurableBatch(ctx, stmts)
}

// RecordDelete soft-deletes the live row and snapshots its prior
// state into history. The caller must have already Stat'd the object
// (so we have its final size/etag); if `in` carries zeros / empty
// strings we fall back to the live row's values.
func (d *objectMetadataDAO) RecordDelete(ctx context.Context, in ObjectMetadataEventInput) error {
	// We need the live row's values for the history snapshot. Read
	// outside the batched tx — the race window between this read
	// and the batched UPDATE is microseconds; a concurrent delete
	// would be a real bug at a higher level.
	live, err := d.LookupLive(ctx, in.Namespace, in.ObjectPath)
	if err != nil {
		return err
	}
	if live == nil {
		// Nothing live to delete; record an external_delete-style
		// history row if the caller insists, but the typical case
		// is the caller has already noticed via a 404.
		return nil
	}
	now := time.Now().UTC()
	eventID := uuid.NewString()
	extraJSON := encodeExtra(in.TrackExtra, in.Extra)
	stmts := []BatchedStmt{
		{
			SQL: `INSERT INTO object_metadata_history
				(event_id, namespace, object_path, event_type, event_ts,
				 size, etag, etag_source, backend_mtime, actor, extra)
				VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			Args: []any{
				eventID, live.Namespace, live.ObjectPath, string(ObjectEventDelete), now,
				live.Size, live.ETag, live.EtagSource, live.BackendMtime, in.Actor, extraJSON,
			},
		},
		{
			SQL:  `UPDATE object_metadata SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`,
			Args: []any{now, live.ID},
		},
	}
	return d.batcher.EnqueueDurableBatch(ctx, stmts)
}

// RecordRename updates the live row's path and snapshots the prior
// state with event_type='rename'. The history row's object_path
// holds the OLD path (so a "history for /foo/bar" query naturally
// surfaces the rename); the new path is encoded in the extra column
// as {"renamed_to": ...} for completeness.
func (d *objectMetadataDAO) RecordRename(ctx context.Context, oldNs, oldPath, newNs, newPath, actor string) error {
	live, err := d.LookupLive(ctx, oldNs, oldPath)
	if err != nil {
		return err
	}
	if live == nil {
		return nil
	}
	now := time.Now().UTC()
	eventID := uuid.NewString()
	// Always preserve the rename target in extra — it isn't
	// uploader-supplied so TrackExtra doesn't gate it.
	extra, _ := json.Marshal(map[string]any{
		"renamed_to_namespace": newNs,
		"renamed_to_path":      newPath,
	})
	stmts := []BatchedStmt{
		{
			SQL: `INSERT INTO object_metadata_history
				(event_id, namespace, object_path, event_type, event_ts,
				 size, etag, etag_source, backend_mtime, actor, extra)
				VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			Args: []any{
				eventID, oldNs, oldPath, string(ObjectEventRename), now,
				live.Size, live.ETag, live.EtagSource, live.BackendMtime, actor, string(extra),
			},
		},
		{
			SQL: `UPDATE object_metadata
				SET namespace = ?, object_path = ?, last_modified = ?, actor = ?
				WHERE id = ? AND deleted_at IS NULL`,
			Args: []any{newNs, newPath, now, actor, live.ID},
		},
	}
	return d.batcher.EnqueueDurableBatch(ctx, stmts)
}

// ============================================================
// Best-effort writes — observation-driven events
// ============================================================

// RecordExternalObserve registers a path we Stat'd that we don't yet
// have a live row for. Inserts both the live row and the history
// snapshot. Best-effort: a crash mid-flush loses the observation,
// which is fine because the next Stat re-creates it.
func (d *objectMetadataDAO) RecordExternalObserve(ctx context.Context, in ObjectMetadataEventInput) error {
	now := time.Now().UTC()
	eventID := uuid.NewString()
	extraJSON := encodeExtra(in.TrackExtra, in.Extra)
	stmts := []BatchedStmt{
		{
			SQL: `INSERT INTO object_metadata_history
				(event_id, namespace, object_path, event_type, event_ts,
				 size, etag, etag_source, backend_mtime, actor, extra)
				VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			Args: []any{
				eventID, in.Namespace, in.ObjectPath, string(ObjectEventExternalObserve), now,
				in.Size, in.ETag, string(in.EtagSource), in.BackendMtime, in.Actor, extraJSON,
			},
		},
		{
			// INSERT OR IGNORE: if a concurrent observer raced us
			// we'd rather no-op than emit a constraint error. The
			// partial unique index is what enforces single-live-row.
			SQL: `INSERT OR IGNORE INTO object_metadata
				(namespace, object_path, size, etag, etag_source,
				 backend_mtime, created_at, last_modified, actor)
				VALUES (?,?,?,?,?,?,?,?,?)`,
			Args: []any{
				in.Namespace, in.ObjectPath, in.Size, in.ETag, string(in.EtagSource),
				in.BackendMtime, now, now, in.Actor,
			},
		},
	}
	return d.batcher.EnqueueBestEffortBatch(ctx, stmts)
}

// RecordExternalChange registers an out-of-band modification: we had
// a live row with one ETag and a Stat returned a different one.
// Updates the live row and snapshots the new state into history.
func (d *objectMetadataDAO) RecordExternalChange(ctx context.Context, in ObjectMetadataEventInput) error {
	now := time.Now().UTC()
	eventID := uuid.NewString()
	extraJSON := encodeExtra(in.TrackExtra, in.Extra)
	stmts := []BatchedStmt{
		{
			SQL: `INSERT INTO object_metadata_history
				(event_id, namespace, object_path, event_type, event_ts,
				 size, etag, etag_source, backend_mtime, actor, extra)
				VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			Args: []any{
				eventID, in.Namespace, in.ObjectPath, string(ObjectEventExternalModify), now,
				in.Size, in.ETag, string(in.EtagSource), in.BackendMtime, in.Actor, extraJSON,
			},
		},
		{
			SQL: `UPDATE object_metadata
				SET size = ?, etag = ?, etag_source = ?, backend_mtime = ?, last_modified = ?
				WHERE namespace = ? AND object_path = ? AND deleted_at IS NULL`,
			Args: []any{in.Size, in.ETag, string(in.EtagSource), in.BackendMtime, now, in.Namespace, in.ObjectPath},
		},
	}
	return d.batcher.EnqueueBestEffortBatch(ctx, stmts)
}

// RecordExternalDelete registers a Stat → ENOENT for a path we had a
// live row for. Soft-deletes the live row and snapshots prior state.
// best-effort: we'll notice again on next access if this drops.
func (d *objectMetadataDAO) RecordExternalDelete(ctx context.Context, namespace, objectPath string) error {
	live, err := d.LookupLive(ctx, namespace, objectPath)
	if err != nil {
		return err
	}
	if live == nil {
		return nil
	}
	now := time.Now().UTC()
	eventID := uuid.NewString()
	stmts := []BatchedStmt{
		{
			SQL: `INSERT INTO object_metadata_history
				(event_id, namespace, object_path, event_type, event_ts,
				 size, etag, etag_source, backend_mtime, actor, extra)
				VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			Args: []any{
				eventID, live.Namespace, live.ObjectPath, string(ObjectEventExternalDelete), now,
				live.Size, live.ETag, live.EtagSource, live.BackendMtime, "", `{}`,
			},
		},
		{
			SQL:  `UPDATE object_metadata SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`,
			Args: []any{now, live.ID},
		},
	}
	return d.batcher.EnqueueBestEffortBatch(ctx, stmts)
}

// RecordAccess updates the live row's last_accessed timestamp. Used
// by the in-memory atime debouncer's periodic flush.
func (d *objectMetadataDAO) RecordAccess(ctx context.Context, namespace, objectPath string, when time.Time) error {
	return d.batcher.EnqueueBestEffort(ctx,
		`UPDATE object_metadata SET last_accessed = ? WHERE namespace = ? AND object_path = ? AND deleted_at IS NULL`,
		when.UTC(), namespace, objectPath,
	)
}

// RecordChecksum upserts a (object, algorithm) checksum row. The
// object_id is looked up by (namespace, object_path) inline via a
// subselect so the caller doesn't have to thread it through.
func (d *objectMetadataDAO) RecordChecksum(ctx context.Context, namespace, objectPath, algorithm, value, etagAtCompute string, computedAt time.Time) error {
	return d.batcher.EnqueueBestEffort(ctx,
		`INSERT INTO object_checksums (object_id, algorithm, value, computed_at, etag_at_compute)
		 SELECT id, ?, ?, ?, ?
		   FROM object_metadata
		  WHERE namespace = ? AND object_path = ? AND deleted_at IS NULL
		 ON CONFLICT(object_id, algorithm) DO UPDATE SET
		   value           = excluded.value,
		   computed_at     = excluded.computed_at,
		   etag_at_compute = excluded.etag_at_compute`,
		algorithm, value, computedAt.UTC(), etagAtCompute, namespace, objectPath,
	)
}

// ============================================================
// Read helpers (synchronous; not batched)
// ============================================================

// LookupLive returns the live (non-deleted) row for the supplied
// namespace+path, or nil if none exists. Used by the Stat hot path
// for change detection.
func (d *objectMetadataDAO) LookupLive(ctx context.Context, namespace, objectPath string) (*ObjectMetadataRow, error) {
	var rows []ObjectMetadataRow
	err := d.db.WithContext(ctx).
		Where("namespace = ? AND object_path = ? AND deleted_at IS NULL", namespace, objectPath).
		Limit(1).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// ListHistory returns the history rows for a given (namespace, path)
// in event-time order. Used by the admin endpoint.
func (d *objectMetadataDAO) ListHistory(ctx context.Context, namespace, objectPath string, limit int) ([]*ObjectMetadataHistoryRow, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows []*ObjectMetadataHistoryRow
	err := d.db.WithContext(ctx).
		Where("namespace = ? AND object_path = ?", namespace, objectPath).
		Order("event_ts ASC").
		Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// PruneHistory deletes up to `limit` history rows in the supplied
// namespace older than `olderThan`. Returns the number of rows
// deleted; callers can use that to decide whether to loop. Used by
// the background objectMetadataPruner.
func (d *objectMetadataDAO) PruneHistory(ctx context.Context, namespace string, olderThan time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 1000
	}
	// SQLite doesn't have DELETE ... LIMIT directly without the
	// SQLITE_ENABLE_UPDATE_DELETE_LIMIT build option (which glebarez
	// does enable by default); wrap defensively as a subselect to
	// stay portable.
	res := d.db.WithContext(ctx).Exec(
		`DELETE FROM object_metadata_history
		   WHERE id IN (
		     SELECT id FROM object_metadata_history
		      WHERE namespace = ? AND event_ts < ?
		      LIMIT ?
		   )`,
		namespace, olderThan.UTC(), limit,
	)
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}

// PruneSoftDeletedLive removes object_metadata rows whose deleted_at
// is older than `olderThan`. Bounded by `limit` per call for the
// same reason PruneHistory is: keeps the WAL transaction small and
// the lock window short. Returns the number of rows deleted.
//
// Note: object_checksums has ON DELETE CASCADE on object_id, so any
// dangling checksum rows attached to a soft-deleted row are removed
// implicitly here. History rows live in a separate table keyed by
// (namespace, path) — they are NOT affected; their independent
// retention via PruneHistory still applies.
func (d *objectMetadataDAO) PruneSoftDeletedLive(ctx context.Context, namespace string, olderThan time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 1000
	}
	res := d.db.WithContext(ctx).Exec(
		`DELETE FROM object_metadata
		   WHERE id IN (
		     SELECT id FROM object_metadata
		      WHERE namespace = ?
		        AND deleted_at IS NOT NULL
		        AND deleted_at < ?
		      LIMIT ?
		   )`,
		namespace, olderThan.UTC(), limit,
	)
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}

// CountHistoryRows is a thin SELECT COUNT used by metrics.
func (d *objectMetadataDAO) CountHistoryRows(ctx context.Context, namespace string) (int64, error) {
	var n int64
	err := d.db.WithContext(ctx).
		Model(&ObjectMetadataHistoryRow{}).
		Where("namespace = ?", namespace).
		Count(&n).Error
	return n, err
}

// ============================================================
// Internal helpers
// ============================================================

// encodeExtra produces the JSON-encoded `extra` column value. When
// TrackExtra is false, the namespace has explicitly opted out of
// snapshotting uploader-supplied metadata; we still write a row but
// the extra is the literal empty object so queries don't need to
// special-case nulls.
func encodeExtra(trackExtra bool, m map[string]any) string {
	if !trackExtra || len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		// json.Marshal of a map[string]any with arbitrary values
		// can fail on un-marshallable types; fall back to "{}"
		// rather than failing the whole write.
		return "{}"
	}
	return string(b)
}

// ErrObjectMetadataNotFound is the sentinel some helpers return when
// callers prefer it over a nil row.
var ErrObjectMetadataNotFound = errors.New("object_metadata: row not found")

// resolveTrackAccess returns the effective TrackAccess for an
// export: the per-export override if set, otherwise the origin-wide
// default from Origin.Metadata.TrackAccess.
func resolveTrackAccess(e server_utils.OriginExport) bool {
	if e.Metadata != nil && e.Metadata.TrackAccess != nil {
		return *e.Metadata.TrackAccess
	}
	return param.Origin_Metadata_TrackAccess.GetBool()
}

// resolveTrackExtra returns the effective TrackExtra for an export.
// Same precedence rule as resolveTrackAccess.
func resolveTrackExtra(e server_utils.OriginExport) bool {
	if e.Metadata != nil && e.Metadata.TrackExtra != nil {
		return *e.Metadata.TrackExtra
	}
	return param.Origin_Metadata_TrackExtra.GetBool()
}

// resolveHistoryRetention returns the per-export retention in days,
// or the origin-wide default. 0 means "never prune."
func resolveHistoryRetentionDays(e server_utils.OriginExport) int {
	if e.Metadata != nil && e.Metadata.HistoryRetentionDays != nil {
		return *e.Metadata.HistoryRetentionDays
	}
	return param.Origin_Metadata_History_RetentionDays.GetInt()
}

// anyTrackAccessEnabled reports whether at least one namespace —
// or the origin-wide default — has TrackAccess on. Used by
// InitializeHandlers to decide whether to spin up the
// objectMetaBatcher + DAO at all.
func anyTrackAccessEnabled(exports []server_utils.OriginExport) bool {
	if param.Origin_Metadata_TrackAccess.GetBool() {
		return true
	}
	for _, e := range exports {
		if e.Metadata != nil && e.Metadata.TrackAccess != nil && *e.Metadata.TrackAccess {
			return true
		}
	}
	return false
}
