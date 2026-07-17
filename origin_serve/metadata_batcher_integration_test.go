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
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	databaseutils "github.com/pelicanplatform/pelican/database/utils"
)

// newFileBackedTestDB opens a real file-backed SQLite handle using the SAME
// DSN/pragmas production uses (WAL, busy_timeout, _txlock=immediate). Unlike
// newTestDB it does NOT pin MaxOpenConns=1, so the batcher's flusher
// goroutine and the eventual-mode worker goroutines genuinely contend for
// the write lock — the condition the in-memory single-connection unit tests
// cannot reproduce.
func newFileBackedTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pelican.sqlite")
	db, err := databaseutils.InitSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("InitSQLiteDB: %v", err)
	}
	if err := db.AutoMigrate(&MetadataPublishRow{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// TestEventual_BatcherBackedQueue_FileDB exercises the exact production
// wiring for eventual mode that no other test covered: the publish-queue
// INSERT is routed through the shared sqliteBatcher (a separate flusher
// goroutine), while the background workers read/claim/delete rows by writing
// to the SAME file-backed WAL database directly. If those two writers
// deadlock, starve, or trip an un-retried SQLITE_BUSY, the queue never
// drains — which is what a standalone origin would exhibit.
//
// The assertion is simply: every committed event is delivered and the queue
// returns to empty.
func TestEventual_BatcherBackedQueue_FileDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: file-backed DB contention test")
	}

	var delivered int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		atomic.AddInt64(&delivered, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	db := newFileBackedTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Real batcher on the real file DB, exactly like InitializeHandlers.
	batcher := newSQLiteBatcher(ctx, db, 64, 5*time.Millisecond)
	defer batcher.Stop()

	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		Batcher:        batcher,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
		MaxInflight:    4, // multiple workers contend with the flusher
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	ctl.Start(ctx)
	defer ctl.Stop()

	const n = 50
	for i := 0; i < n; i++ {
		ev := NewObjectCommitEvent("/exp", fmt.Sprintf("/exp/obj-%03d.dat", i), 1, "", time.Now().UTC(), nil)
		if err := ctl.CommitEvent(context.Background(), ev); err != nil {
			t.Fatalf("CommitEvent %d: %v", i, err)
		}
	}

	// Wait for the queue to drain.
	deadline := time.After(15 * time.Second)
	for {
		var count int64
		if err := ctl.queue.handle().Model(&MetadataPublishRow{}).Count(&count).Error; err != nil {
			t.Fatalf("count queue: %v", err)
		}
		if count == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("queue did not drain (depth=%d, delivered=%d)", count, atomic.LoadInt64(&delivered))
		case <-time.After(25 * time.Millisecond):
		}
	}

	// Every event must have been delivered at least once (retries may push
	// this higher; receivers dedupe on event_id).
	if got := atomic.LoadInt64(&delivered); got < n {
		t.Fatalf("receiver got %d deliveries, want >= %d", got, n)
	}
}
