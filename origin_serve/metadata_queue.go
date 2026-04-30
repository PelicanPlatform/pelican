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
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
)

// MetadataPublishRow is the GORM-mapped persistence representation of
// one queued event. The struct tag `gorm:"unique"` on event_id matches
// the migration's UNIQUE constraint.
type MetadataPublishRow struct {
	ID            int64     `gorm:"primaryKey;autoIncrement"`
	EventID       string    `gorm:"column:event_id;uniqueIndex;not null"`
	Namespace     string    `gorm:"column:namespace;not null;index"`
	ObjectPath    string    `gorm:"column:object_path;not null"`
	ObjectSize    int64     `gorm:"column:object_size;not null"`
	ETag          string    `gorm:"column:etag;not null"`
	ObjectCreated time.Time `gorm:"column:object_created;not null"`
	CustomFields  string    `gorm:"column:custom_fields;not null;default:'{}'"`
	CreatedAt     time.Time `gorm:"column:created_at;not null;index"`
	NextAttemptAt time.Time `gorm:"column:next_attempt_at;not null;index"`
	Attempts      int       `gorm:"column:attempts;not null;default:0"`
	LastError     string    `gorm:"column:last_error;not null;default:''"`
}

// TableName overrides the default GORM pluralization rule.
func (MetadataPublishRow) TableName() string { return "metadata_publish_queue" }

// ErrEventNotFound is returned by mutators when no row matches the
// supplied event_id.
var ErrEventNotFound = errors.New("metadata publish event not found")

// publishQueue is a thin DAO over the GORM ServerDatabase handle.
// Methods accept *gorm.DB so unit tests can inject a sqlite in-memory
// instance without touching package globals.
type publishQueue struct {
	db *gorm.DB
}

// newPublishQueue wraps the supplied GORM handle. Passing nil causes
// the queue to fall back to database.ServerDatabase at call time, which
// is the production path; the explicit-injection form is provided for
// tests.
func newPublishQueue(db *gorm.DB) *publishQueue { return &publishQueue{db: db} }

func (q *publishQueue) handle() *gorm.DB {
	if q.db != nil {
		return q.db
	}
	return database.ServerDatabase
}

// EnqueueEvent inserts a row into the publish queue from an in-memory
// event. CustomFields is JSON-encoded once at write time so subsequent
// reads can pass it straight through to the wire.
func (q *publishQueue) EnqueueEvent(e *ObjectCommitEvent) (*MetadataPublishRow, error) {
	customJSON := []byte("{}")
	if len(e.CustomFields) > 0 {
		var err error
		customJSON, err = json.Marshal(e.CustomFields)
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	row := &MetadataPublishRow{
		EventID:       e.ID,
		Namespace:     e.Namespace,
		ObjectPath:    e.ObjectPath,
		ObjectSize:    e.ObjectSize,
		ETag:          e.ETag,
		ObjectCreated: e.ObjectCreated.UTC(),
		CustomFields:  string(customJSON),
		CreatedAt:     now,
		NextAttemptAt: now, // first attempt eligible immediately
	}
	if err := q.handle().Create(row).Error; err != nil {
		return nil, err
	}
	return row, nil
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
	return &ObjectCommitEvent{
		ID:            r.EventID,
		Type:          ObjectCommitEventType,
		Timestamp:     r.CreatedAt,
		Namespace:     r.Namespace,
		ObjectPath:    r.ObjectPath,
		ObjectSize:    r.ObjectSize,
		ETag:          r.ETag,
		ObjectCreated: r.ObjectCreated,
		CustomFields:  custom,
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
	if err := tx.Where("next_attempt_at <= ?", now).
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
func (q *publishQueue) scheduleRetry(rowID int64, nextAttemptAt time.Time, errMsg string) error {
	return q.handle().Model(&MetadataPublishRow{}).
		Where("id = ?", rowID).
		Updates(map[string]any{
			"attempts":        gorm.Expr("attempts + 1"),
			"next_attempt_at": nextAttemptAt,
			"last_error":      errMsg,
		}).Error
}

// deleteByID is the row-id sibling of DeleteByEventID, used after a
// successful publish where we already have the row in hand.
func (q *publishQueue) deleteByID(rowID int64) error {
	return q.handle().Where("id = ?", rowID).Delete(&MetadataPublishRow{}).Error
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
	Total            int64
	OldestCreatedAt  *time.Time
	PerNamespace     map[string]int64
	PerNamespaceOld  map[string]time.Time
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
	if err := q.handle().Find(&rows).Error; err != nil {
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
