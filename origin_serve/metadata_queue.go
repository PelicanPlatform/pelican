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

// File metadata_queue.go is the data-access layer for the
// `metadata_publish_queue` SQLite table. Both publish modes share this
// queue: it is written to synchronously on every successful upload
// commit, then drained either by the close-time publish path
// (transactional mode) or by a background worker (eventually-consistent
// mode).

package origin_serve

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
)

// MetadataPublishRow is the GORM-mapped persistence representation of
// one queued event. The struct tag `gorm:"unique"` on event_id matches
// the migration's UNIQUE constraint.
//
// MetadataContentType and MetadataBody are populated only when the
// upload was multipart/form-data (see splitMultipartParts in
// metadata_multipart.go); both columns are empty for header-only and
// no-metadata uploads, and the worker chooses plain-JSON vs
// multipart/related outbound based on whether the blob is non-empty.
type MetadataPublishRow struct {
	ID                  int64     `gorm:"primaryKey;autoIncrement"`
	EventID             string    `gorm:"column:event_id;uniqueIndex;not null"`
	Namespace           string    `gorm:"column:namespace;not null;index"`
	ObjectPath          string    `gorm:"column:object_path;not null"`
	ObjectSize          int64     `gorm:"column:object_size;not null"`
	ETag                string    `gorm:"column:etag;not null"`
	ObjectCreated       time.Time `gorm:"column:object_created;not null"`
	CustomFields        string    `gorm:"column:custom_fields;not null;default:'{}'"`
	MetadataContentType string    `gorm:"column:metadata_content_type;not null;default:''"`
	MetadataBody        []byte    `gorm:"column:metadata_body;not null;default:''"`
	CreatedAt           time.Time `gorm:"column:created_at;not null;index"`
	NextAttemptAt       time.Time `gorm:"column:next_attempt_at;not null;index"`
	Attempts            int       `gorm:"column:attempts;not null;default:0"`
	LastError           string    `gorm:"column:last_error;not null;default:''"`

	// State is "pending" (the worker keeps retrying) or "rejected" (terminal:
	// the catalog answered 422 / permanently-bad, so the worker stops touching
	// it; the row lingers for status queries and admin/operator deletion).
	State string `gorm:"column:state;not null;default:'pending'"`

	// QueryToken / ManageToken are per-row random capability tokens embedded in
	// the status / manage URLs handed back to the uploading client in eventual
	// mode. Possession of the (unguessable) URL is the authority — no separate
	// bearer token is required. Empty for transactional-mode rows (which never
	// outlive the request).
	QueryToken  string `gorm:"column:query_token;not null;default:''"`
	ManageToken string `gorm:"column:manage_token;not null;default:''"`

	// EventType is the wire `type` (object.committed / object.updated /
	// object.deleted). Persisted so a retry rebuilds the event with its
	// original type, and so the worker knows to skip the "object still exists?"
	// check for deletes.
	EventType string `gorm:"column:event_type;not null;default:'object.committed'"`
}

// TableName overrides the default GORM pluralization rule.
func (MetadataPublishRow) TableName() string { return "metadata_publish_queue" }

// Publish-queue row states.
const (
	metadataStatePending  = "pending"
	metadataStateRejected = "rejected"
)

// managementTokens carries the random capability tokens for a queued row.
// Both are empty in transactional mode.
type managementTokens struct {
	Query  string
	Manage string
}

// ErrEventNotFound is returned by mutators when no row matches the
// supplied event_id.
var ErrEventNotFound = errors.New("metadata publish event not found")

// publishQueue is a thin DAO over the GORM ServerDatabase handle.
// Methods accept *gorm.DB so unit tests can inject a sqlite in-memory
// instance without touching package globals.
//
// If `batcher` is non-nil, EnqueueEvent routes the INSERT through
// the shared SQLite write-behind batcher so it coalesces with other
// concurrent commits + best-effort observations into one transaction.
// Without the batcher (tests, or when no metadata feature triggers
// batcher construction) it falls back to a direct synchronous INSERT.
type publishQueue struct {
	db      *gorm.DB
	batcher *sqliteBatcher
}

// newPublishQueue wraps the supplied GORM handle. Passing nil causes
// the queue to fall back to database.ServerDatabase at call time, which
// is the production path; the explicit-injection form is provided for
// tests.
func newPublishQueue(db *gorm.DB) *publishQueue { return &publishQueue{db: db} }

// setBatcher installs the shared write-behind batcher. Production
// wiring lives in InitializeHandlers; tests can call this directly.
// Nil-tolerant (setting nil reverts to direct-insert mode).
func (q *publishQueue) setBatcher(b *sqliteBatcher) { q.batcher = b }

func (q *publishQueue) handle() *gorm.DB {
	if q.db != nil {
		return q.db
	}
	return database.ServerDatabase
}

// EnqueueEvent inserts a row into the publish queue from an in-memory
// event. CustomFields is JSON-encoded once at write time so subsequent
// reads can pass it straight through to the wire.
//
// When a batcher is installed (production path), the INSERT goes
// through EnqueueDurable so a burst of concurrent commits coalesces
// into one transaction. The autoincrement ID isn't known until after
// the batched tx commits, so we then read it back via SELECT WHERE
// event_id=?. The extra read is amortized across the coalesced
// batch — typically zero round-trips of latency because the row is
// already in SQLite's page cache.
// firstAttemptDelay pushes the row's next_attempt_at into the future so the
// background worker won't claim it while the caller is still performing its
// synchronous first attempt (preventing a duplicate publish). The caller
// deletes / reschedules the row itself; the delay only governs when the worker
// would recover the row if the caller's process crashed mid-attempt. Pass 0
// for immediate claimability (queue-level tests).
func (q *publishQueue) EnqueueEvent(ctx context.Context, e *ObjectCommitEvent, tok managementTokens, firstAttemptDelay time.Duration) (*MetadataPublishRow, error) {
	return q.enqueueEventAtomic(ctx, e, tok, firstAttemptDelay, nil)
}

// enqueueEventAtomic inserts the publish-queue row, optionally folding
// `extra` statements into the SAME durable transaction. The publish path
// passes the tracking-commit statements as `extra` so the tracking-commit and
// the queue row land atomically — a crash can no longer leave a committed
// object with no queue row (see commitStatements / the reconcile sweep, which
// backstops the residual pre-record window).
func (q *publishQueue) enqueueEventAtomic(ctx context.Context, e *ObjectCommitEvent, tok managementTokens, firstAttemptDelay time.Duration, extra []BatchedStmt) (*MetadataPublishRow, error) {
	customJSON := []byte("{}")
	if len(e.CustomFields) > 0 {
		var err error
		customJSON, err = json.Marshal(e.CustomFields)
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	firstAttempt := now.Add(firstAttemptDelay)
	metadataBody := e.MetadataBody
	if metadataBody == nil {
		metadataBody = []byte{}
	}
	// The queue INSERT. Column defaults are applied explicitly — when we
	// name a NOT NULL column in the INSERT list SQLite expects a value
	// regardless of any schema DEFAULT (GORM's .Create handles this
	// implicitly; a raw INSERT does not).
	insert := BatchedStmt{
		SQL: `INSERT INTO metadata_publish_queue
			(event_id, namespace, object_path, object_size, etag, object_created,
			 custom_fields, metadata_content_type, metadata_body,
			 created_at, next_attempt_at, attempts, last_error,
			 state, query_token, manage_token, event_type)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,0,'',?,?,?,?)`,
		Args: []any{
			e.ID, e.Namespace, e.ObjectPath, e.ObjectSize, e.ETag, e.ObjectCreated.UTC(),
			string(customJSON), e.MetadataContentType, metadataBody,
			now, firstAttempt,
			metadataStatePending, tok.Query, tok.Manage, e.Type,
		},
	}

	if q.batcher == nil {
		// Direct path (tests + early-init). Run any extra statements and the
		// INSERT in one transaction so the direct path preserves the same
		// atomicity as the batched path.
		if err := q.handle().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			for _, s := range extra {
				if err := tx.Exec(s.SQL, s.Args...).Error; err != nil {
					return err
				}
			}
			return tx.Exec(insert.SQL, insert.Args...).Error
		}); err != nil {
			return nil, err
		}
		return q.FindByEventID(e.ID)
	}

	// Batched path: durable insert coalesces with other concurrent commits.
	// `extra` (the tracking-commit statements) runs first in the same tx.
	stmts := append(append([]BatchedStmt{}, extra...), insert)
	if err := q.batcher.EnqueueDurableBatch(ctx, stmts); err != nil {
		return nil, err
	}
	// Read back to recover the autoincrement ID. This SELECT is indexed
	// (event_id is UNIQUE) and the row was just written inside the batched
	// tx, so it's in cache.
	return q.FindByEventID(e.ID)
}

// EventFromRow reconstructs an in-memory event from a persisted row.
// Used by both publish paths when handing rows to the HTTP attempt.
func EventFromRow(r *MetadataPublishRow) (*ObjectCommitEvent, error) {
	var custom CustomFields
	if r.CustomFields != "" {
		if err := json.Unmarshal([]byte(r.CustomFields), &custom); err != nil {
			return nil, err
		}
	}
	eventType := r.EventType
	if eventType == "" {
		eventType = ObjectCommitEventType
	}
	return &ObjectCommitEvent{
		ID:                  r.EventID,
		Type:                eventType,
		Timestamp:           r.CreatedAt,
		Namespace:           r.Namespace,
		ObjectPath:          r.ObjectPath,
		ObjectSize:          r.ObjectSize,
		ETag:                r.ETag,
		ObjectCreated:       r.ObjectCreated,
		CustomFields:        custom,
		MetadataContentType: r.MetadataContentType,
		MetadataBody:        r.MetadataBody,
	}, nil
}

// DeleteByEventID removes a row, typically after a successful publish
// or an admin-triggered drop. Returns ErrEventNotFound when no row
// matches.
func (q *publishQueue) DeleteByEventID(eventID string) error {
	res := q.handle().Where("event_id = ?", eventID).Delete(&MetadataPublishRow{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrEventNotFound
	}
	return nil
}

// FindByEventID looks up a single row.
func (q *publishQueue) FindByEventID(eventID string) (*MetadataPublishRow, error) {
	var row MetadataPublishRow
	if err := q.handle().Where("event_id = ?", eventID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEventNotFound
		}
		return nil, err
	}
	return &row, nil
}

// claimDue returns up to `limit` rows whose `next_attempt_at` is in the
// past, in age-order. To prevent a second worker grabbing the same row,
// it pushes `next_attempt_at` ahead by `lease` *before* returning.
//
// The "claim then attempt" pattern means a worker that crashes while
// attempting will let the row come due again after the lease elapses;
// we deliberately accept the resulting duplicate publish (receivers
// dedupe via event_id).
func (q *publishQueue) claimDue(limit int, lease time.Duration) ([]*MetadataPublishRow, error) {
	var rows []*MetadataPublishRow
	now := time.Now().UTC()
	tx := q.handle().Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()
	// Only "pending" rows are claimable; "rejected" rows are terminal (the
	// catalog permanently refused them) and wait for a status query or an
	// operator delete rather than being retried.
	if err := tx.Where("next_attempt_at <= ? AND state = ?", now, metadataStatePending).
		Order("next_attempt_at ASC").
		Limit(limit).
		Find(&rows).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if len(rows) == 0 {
		tx.Rollback()
		return rows, nil
	}
	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	leaseUntil := now.Add(lease)
	if err := tx.Model(&MetadataPublishRow{}).
		Where("id IN ?", ids).
		Update("next_attempt_at", leaseUntil).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// scheduleRetry records a failed attempt: increments attempts, captures
// the error message, and pushes next_attempt_at forward.
//
// next_attempt_at is normalized to UTC before storing. SQLite has no timezone
// type, so GORM writes a time.Time as its wall-clock text in whatever location
// the value carries, and claimDue selects due rows by string-comparing that
// text against time.Now().UTC(). A caller passing a local-zone time (e.g.
// c.clock().Add(backoff) with a non-UTC clock) would store "07:53" while the
// selector compares "12:51" (UTC), making every backoff row instantly
// re-eligible and turning a failing publish into a tight retry loop. Storing
// UTC keeps the write consistent with claimDue / firstEnqueue / NextDueAt.
func (q *publishQueue) scheduleRetry(rowID int64, nextAttemptAt time.Time, errMsg string) error {
	return q.handle().Model(&MetadataPublishRow{}).
		Where("id = ?", rowID).
		Updates(map[string]any{
			"attempts":        gorm.Expr("attempts + 1"),
			"next_attempt_at": nextAttemptAt.UTC(),
			"last_error":      errMsg,
		}).Error
}

// deleteByID is the row-id sibling of DeleteByEventID, used after a
// successful publish where we already have the row in hand.
func (q *publishQueue) deleteByID(rowID int64) error {
	return q.handle().Where("id = ?", rowID).Delete(&MetadataPublishRow{}).Error
}

// markRejected moves a row to the terminal "rejected" state (the catalog
// answered 422 / permanently-bad). The worker's claimDue skips it thereafter;
// it lingers so a status query can report the rejection and an operator can
// delete it. attempts is bumped so the count reflects the final try.
func (q *publishQueue) markRejected(rowID int64, errMsg string) error {
	return q.handle().Model(&MetadataPublishRow{}).
		Where("id = ?", rowID).
		Updates(map[string]any{
			"state":      metadataStateRejected,
			"attempts":   gorm.Expr("attempts + 1"),
			"last_error": errMsg,
		}).Error
}

// FindByToken looks a row up by either capability token. isManage reports
// whether the supplied token was the (more privileged) manage token, so the
// caller can gate cancel/delete on it. An empty token never matches.
func (q *publishQueue) FindByToken(token string) (row *MetadataPublishRow, isManage bool, err error) {
	if token == "" {
		return nil, false, ErrEventNotFound
	}
	var r MetadataPublishRow
	if e := q.handle().Where("manage_token = ? OR query_token = ?", token, token).First(&r).Error; e != nil {
		if errors.Is(e, gorm.ErrRecordNotFound) {
			return nil, false, ErrEventNotFound
		}
		return nil, false, e
	}
	return &r, r.ManageToken == token, nil
}

// listOptions narrows the rows returned by ListPending. All fields are
// optional.
type listOptions struct {
	Namespace string
	Limit     int
	Offset    int
}

// ListPending returns rows for the admin endpoint, sorted oldest-first.
func (q *publishQueue) ListPending(opts listOptions) ([]*MetadataPublishRow, error) {
	tx := q.handle().Model(&MetadataPublishRow{})
	if opts.Namespace != "" {
		tx = tx.Where("namespace = ?", opts.Namespace)
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Limit > 1000 {
		opts.Limit = 1000
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}
	tx = tx.Order("created_at ASC").Limit(opts.Limit).Offset(opts.Offset)

	var rows []*MetadataPublishRow
	if err := tx.Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// queueStats is a small struct describing the current state of the
// queue. Used by the metrics scraper and the admin _health endpoint.
type queueStats struct {
	Total           int64
	OldestCreatedAt *time.Time
	PerNamespace    map[string]int64
	PerNamespaceOld map[string]time.Time
}

// NextDueAt returns the smallest next_attempt_at across all rows. The
// returned bool is false when the queue is empty. Used by the worker
// scheduler to decide how long to sleep when no work is currently
// due. Uses a single indexed SELECT, so it stays cheap regardless of
// queue size.
//
// We use ORDER BY ... LIMIT 1 rather than MIN() because GORM + the
// glebarez sqlite driver round-trip MIN(DATETIME) as TEXT, which then
// can't be scanned into a time.Time. Reading the actual row column
// preserves the typed value.
func (q *publishQueue) NextDueAt() (time.Time, bool, error) {
	// Find (vs Take) so an empty queue is a 0-row no-op rather than
	// an ErrRecordNotFound that GORM logs at warn-level.
	var rows []MetadataPublishRow
	err := q.handle().Model(&MetadataPublishRow{}).
		Select("next_attempt_at").
		Where("state = ?", metadataStatePending).
		Order("next_attempt_at ASC").
		Limit(1).
		Find(&rows).Error
	if err != nil {
		return time.Time{}, false, err
	}
	if len(rows) == 0 {
		return time.Time{}, false, nil
	}
	return rows[0].NextAttemptAt.UTC(), true, nil
}

// QueueStats walks the queue once and produces the stats above. This
// is the simple SQL form; for very large queues we'd switch to
// per-namespace MIN(created_at) and a separate COUNT, but for the
// expected scale it's fine.
func (q *publishQueue) QueueStats() (*queueStats, error) {
	var rows []*MetadataPublishRow
	// Only pending rows count toward depth / oldest-age (and thus the health
	// gauge); terminal "rejected" rows are a separate, operator-facing concern.
	if err := q.handle().Where("state = ?", metadataStatePending).Find(&rows).Error; err != nil {
		return nil, err
	}
	stats := &queueStats{
		Total:           int64(len(rows)),
		PerNamespace:    map[string]int64{},
		PerNamespaceOld: map[string]time.Time{},
	}
	for _, r := range rows {
		stats.PerNamespace[r.Namespace]++
		if existing, ok := stats.PerNamespaceOld[r.Namespace]; !ok || r.CreatedAt.Before(existing) {
			stats.PerNamespaceOld[r.Namespace] = r.CreatedAt
		}
		if stats.OldestCreatedAt == nil || r.CreatedAt.Before(*stats.OldestCreatedAt) {
			t := r.CreatedAt
			stats.OldestCreatedAt = &t
		}
	}
	return stats, nil
}

// NamespaceBacklog returns the number of pending rows and the total size in
// bytes of their inline metadata blobs for a single namespace. It powers the
// eventual-mode backpressure caps, which are checked once per commit; the
// aggregate SELECT is indexed on namespace and cheap at the expected scale.
func (q *publishQueue) NamespaceBacklog(namespace string) (count int64, blobBytes int64, err error) {
	var agg struct {
		Cnt   int64
		Bytes int64
	}
	err = q.handle().Model(&MetadataPublishRow{}).
		Where("namespace = ? AND state = ?", namespace, metadataStatePending).
		Select("COUNT(*) AS cnt, COALESCE(SUM(LENGTH(metadata_body)), 0) AS bytes").
		Scan(&agg).Error
	return agg.Cnt, agg.Bytes, err
}
