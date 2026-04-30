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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/server_utils"
)

// newTestDB returns a fresh in-memory sqlite GORM handle with the
// metadata_publish_queue table created. Each test gets its OWN
// SQLite cache (per-test DSN) so the cache cannot bleed between
// tests, even if they run in parallel.
//
// NB: SQLite in-memory databases are per-connection. To make the
// queue's BEGIN/COMMIT transactions see the table that was created on
// the bootstrap connection we still force MaxOpenConns=1.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	// Sanitize t.Name() — Go subtests use '/' as a separator and
	// SQLite's URI parser prefers a flat name. Use a short random
	// suffix in case t.Name() collides on a re-run within the same
	// process.
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	dsn := fmt.Sprintf("file:test_%s_%d?mode=memory&cache=shared", name, time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sqlDB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&MetadataPublishRow{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// newTestController constructs a controller wired to a fresh DB and a
// fake publisher. The returned receiver is the httptest.Server URL
// the publisher will POST to; the requests channel receives every body
// the receiver got.
func newTestController(t *testing.T, mode PublishMode, exports []server_utils.OriginExport) (*metadataController, string, chan []byte, *httptest.Server) {
	t.Helper()
	requests := make(chan []byte, 32)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     mode,
		Exports:        exports,
		DB:             db,
		MinBackoff:     50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
		MaxInflight:    1,
		RatePerSecond:  100,
	})
	// Replace token signer with a deterministic stub so tests don't
	// need a real issuer key.
	ctl.publisher.signToken = func(audience, namespace string) (string, error) {
		return "test-token-" + namespace, nil
	}
	return ctl, receiver.URL, requests, receiver
}

// ---------- queue / DAO ----------

func TestQueueEnqueueAndFetch(t *testing.T) {
	db := newTestDB(t)
	q := newPublishQueue(db)

	event := NewObjectCommitEvent("/foo", "/foo/a.bin", 42, `"etag"`, time.Now().UTC(), CustomFields{"k": int64(7)})
	row, err := q.EnqueueEvent(event)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if row.EventID != event.ID {
		t.Fatalf("EventID = %q, want %q", row.EventID, event.ID)
	}

	got, err := q.FindByEventID(event.ID)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.ObjectPath != "/foo/a.bin" {
		t.Fatalf("ObjectPath = %q", got.ObjectPath)
	}

	rt, err := EventFromRow(got)
	if err != nil {
		t.Fatalf("from row: %v", err)
	}
	if v, _ := rt.CustomFields["k"].(float64); v != 7 {
		// JSON unmarshals integers into float64; that's fine for
		// downstream consumers.
		t.Fatalf("custom field roundtrip: got %#v", rt.CustomFields["k"])
	}
}

func TestQueueEventIDUnique(t *testing.T) {
	db := newTestDB(t)
	q := newPublishQueue(db)
	event := NewObjectCommitEvent("/n", "/n/x", 1, "", time.Now().UTC(), nil)
	if _, err := q.EnqueueEvent(event); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if _, err := q.EnqueueEvent(event); err == nil {
		t.Fatal("second enqueue should fail unique-constraint")
	}
}

func TestQueueClaimDuePushesAttempt(t *testing.T) {
	db := newTestDB(t)
	q := newPublishQueue(db)
	for i := 0; i < 3; i++ {
		_, err := q.EnqueueEvent(NewObjectCommitEvent("/n", "/n/x", int64(i), "", time.Now().UTC(), nil))
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	rows, err := q.claimDue(2, 5*time.Minute)
	if err != nil {
		t.Fatalf("claimDue: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// A second worker calling claimDue immediately should see only
	// the third row, since the first two have next_attempt_at pushed
	// out by the lease.
	rows2, err := q.claimDue(10, 5*time.Minute)
	if err != nil {
		t.Fatalf("claimDue 2: %v", err)
	}
	if len(rows2) != 1 {
		t.Fatalf("second claim returned %d rows, want 1", len(rows2))
	}
}

func TestQueueScheduleRetryBumpsAttempts(t *testing.T) {
	db := newTestDB(t)
	q := newPublishQueue(db)
	row, err := q.EnqueueEvent(NewObjectCommitEvent("/n", "/n/x", 1, "", time.Now().UTC(), nil))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	next := time.Now().Add(time.Hour).UTC()
	if err := q.scheduleRetry(row.ID, next, "boom"); err != nil {
		t.Fatalf("scheduleRetry: %v", err)
	}
	got, _ := q.FindByEventID(row.EventID)
	if got.Attempts != 1 {
		t.Fatalf("Attempts = %d, want 1", got.Attempts)
	}
	if got.LastError != "boom" {
		t.Fatalf("LastError = %q", got.LastError)
	}
}

// ---------- event JSON shape ----------

func TestObjectCommitEventJSONShape(t *testing.T) {
	created := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	e := NewObjectCommitEvent("/foo", "/foo/bar.dat", 4321, `"etag1"`, created, CustomFields{
		"experiment": "atlas",
		"run_number": int64(4172),
	})
	e.Timestamp = created // make deterministic for this test

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["type"] != "object.committed" {
		t.Fatalf("type = %v", got["type"])
	}
	if got["namespace"] != "/foo" {
		t.Fatalf("namespace = %v", got["namespace"])
	}
	obj, _ := got["object"].(map[string]any)
	if obj["path"] != "/foo/bar.dat" {
		t.Fatalf("object.path = %v", obj["path"])
	}
	if obj["experiment"] != "atlas" {
		t.Fatalf("custom field experiment = %v", obj["experiment"])
	}
	// Reserved keys must be present.
	for _, k := range []string{"path", "size", "etag", "created_at"} {
		if _, ok := obj[k]; !ok {
			t.Fatalf("reserved key %q missing", k)
		}
	}
}

// ---------- transactional publishing ----------

func TestTransactionalSuccess(t *testing.T) {
	ctl, _, requests, _ := newTestController(t, ModeTransactional, nil)
	ev := NewObjectCommitEvent("/foo", "/foo/x.bin", 11, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(context.Background(), ev); err != nil {
		t.Fatalf("CommitEvent: %v", err)
	}
	select {
	case body := <-requests:
		if !strings.Contains(string(body), `"object.committed"`) {
			t.Fatalf("body missing event type: %s", body)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver did not get a request")
	}
	// Row should have been deleted on success.
	if _, err := ctl.queue.FindByEventID(ev.ID); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("row still present after transactional success: %v", err)
	}
}

func TestTransactionalReceiver500FailsClose(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer receiver.Close()

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeTransactional,
		DB:             db,
		MaxInflight:    1,
		RatePerSecond:  100,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }

	ev := NewObjectCommitEvent("/foo", "/foo/x.bin", 11, "", time.Now().UTC(), nil)
	err := ctl.CommitEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("CommitEvent should have failed in transactional mode on 5xx")
	}
	// Row must be cleaned up so we don't leak.
	if _, err := ctl.queue.FindByEventID(ev.ID); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("row still present after transactional failure: %v", err)
	}
}

// ---------- eventually-consistent worker ----------

func TestEventualWorkerDrainsQueue(t *testing.T) {
	ctl, _, requests, _ := newTestController(t, ModeEventual, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	for i := 0; i < 3; i++ {
		ev := NewObjectCommitEvent("/foo", "/foo/x.bin", int64(i), "", time.Now().UTC(), nil)
		if err := ctl.CommitEvent(ctx, ev); err != nil {
			t.Fatalf("CommitEvent: %v", err)
		}
	}
	got := 0
	deadline := time.After(3 * time.Second)
	for got < 3 {
		select {
		case <-requests:
			got++
		case <-deadline:
			t.Fatalf("only %d/3 events delivered", got)
		}
	}
}

func TestEventualWorkerSkipsDeletedObject(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("receiver should not have been called for a deleted object; got %s", r.URL.Path)
	}))
	defer receiver.Close()

	db := newTestDB(t)
	var existsCalls int32
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "t", nil }
	ctl.objectExists = func(context.Context, string, string) bool {
		atomic.AddInt32(&existsCalls, 1)
		return false
	}

	ev := NewObjectCommitEvent("/foo", "/foo/gone.bin", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(context.Background(), ev); err != nil {
		t.Fatalf("CommitEvent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	deadline := time.After(2 * time.Second)
	for {
		_, err := ctl.queue.FindByEventID(ev.ID)
		if errors.Is(err, ErrEventNotFound) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("row not dropped; existsCalls=%d", atomic.LoadInt32(&existsCalls))
		case <-time.After(20 * time.Millisecond):
		}
	}
	if atomic.LoadInt32(&existsCalls) == 0 {
		t.Fatal("objectExists never invoked")
	}
}

func TestEventualEventIDStableAcrossRetries(t *testing.T) {
	var (
		mu         sync.Mutex
		seenIDs    = []string{}
		failFirst  = true
	)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var v struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &v)
		mu.Lock()
		seenIDs = append(seenIDs, v.ID)
		shouldFail := failFirst && len(seenIDs) == 1
		mu.Unlock()
		if shouldFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "t", nil }

	ev := NewObjectCommitEvent("/foo", "/foo/x.bin", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(context.Background(), ev); err != nil {
		t.Fatalf("CommitEvent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		n := len(seenIDs)
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("did not see >=2 deliveries (got %d)", n)
		case <-time.After(20 * time.Millisecond):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range seenIDs {
		if id != ev.ID {
			t.Fatalf("event ID changed across retries: got %q want %q", id, ev.ID)
		}
	}
}

// ---------- per-export resolver ----------

func TestResolverPerExportOverrides(t *testing.T) {
	enabled := true
	disabled := false
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/A",
			Metadata: &server_utils.OriginExportMetadata{
				Enabled:  &enabled,
				Endpoint: "https://A.example.com",
				Mode:     "transactional",
			},
		},
		{
			FederationPrefix: "/B",
			Metadata: &server_utils.OriginExportMetadata{
				Enabled: &disabled,
			},
		},
		{
			FederationPrefix: "/C",
			// no overrides → inherits origin-wide
		},
	}
	r := newMetadataResolver(true, "https://default.example.com", ModeEventual, exports)

	if e, ep, m := r.Resolve("/A"); !e || ep != "https://A.example.com" || m != ModeTransactional {
		t.Fatalf("/A resolve: %v %v %v", e, ep, m)
	}
	if e, _, _ := r.Resolve("/B"); e {
		t.Fatal("/B should be disabled")
	}
	if e, ep, m := r.Resolve("/C"); !e || ep != "https://default.example.com" || m != ModeEventual {
		t.Fatalf("/C resolve: %v %v %v", e, ep, m)
	}
}

// ---------- health-state pure function ----------

func TestComputeHealthState(t *testing.T) {
	now := time.Now().UTC()
	older := now.Add(-2 * time.Hour)
	older2 := now.Add(-10 * time.Hour)
	older3 := now.Add(-48 * time.Hour)
	tests := []struct {
		name   string
		oldest *time.Time
		want   string
	}{
		{"empty", nil, "healthy"},
		{"recent", &older, "healthy"},
		{"warn", &older2, "warning"},
		{"err", &older3, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeHealthState(tt.oldest, now, 4*time.Hour, 24*time.Hour)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------- backoff with jitter monotonicity ----------

func TestComputeBackoffWithinBounds(t *testing.T) {
	c := &metadataController{
		minBackoff: 10 * time.Millisecond,
		maxBackoff: 100 * time.Millisecond,
		rng:        randSource(),
	}
	for attempts := 1; attempts < 20; attempts++ {
		d := c.computeBackoff(attempts)
		if d < c.minBackoff || d > c.maxBackoff {
			t.Fatalf("attempts=%d backoff=%v out of bounds [%v,%v]", attempts, d, c.minBackoff, c.maxBackoff)
		}
	}
}

func randSource() *mrand.Rand { return mrand.New(mrand.NewSource(0xCAFEBABE)) }

// ---------- worker scheduler ----------

// TestSchedulerTicklesOnEnqueue confirms that an enqueue while the
// worker is parked in smartSleep wakes it promptly (much faster than
// any polling cadence). This is the property that makes the scheduler
// "mostly asleep" in steady state.
func TestSchedulerTicklesOnEnqueue(t *testing.T) {
	delivered := make(chan struct{}, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     5 * time.Second,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "t", nil }
	// Force the safety-net poll to be much longer than the test
	// timeout, so a successful wake-up *must* be due to the tickle
	// (not a fallback poll).
	ctl.idleMaxSleep = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	// Give the worker a beat to enter smartSleep on the empty queue.
	time.Sleep(100 * time.Millisecond)

	enqueueAt := time.Now()
	ev := NewObjectCommitEvent("/foo", "/foo/x.bin", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(ctx, ev); err != nil {
		t.Fatalf("CommitEvent: %v", err)
	}
	select {
	case <-delivered:
		// Tickle delivery should be sub-second; if it took multiple
		// seconds we'd be relying on the safety-net poll, which is
		// the bug this test catches.
		if elapsed := time.Since(enqueueAt); elapsed > 1500*time.Millisecond {
			t.Fatalf("tickle wakeup took %v; expected < 1.5s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not deliver after enqueue+tickle")
	}
}

// TestSchedulerSmartSleepUntilNextDue checks that smartSleep waits
// for the soonest `next_attempt_at`, not a fixed polling interval.
// We schedule a row 200ms in the future, observe that the worker
// doesn't fire too early, and observe that it does fire shortly
// after the scheduled time.
func TestSchedulerSmartSleepUntilNextDue(t *testing.T) {
	delivered := make(chan time.Time, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered <- time.Now()
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     5 * time.Second,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "t", nil }
	ctl.idleMaxSleep = time.Hour

	// Insert a row directly with a future next_attempt_at so the
	// worker has nothing to do *now*.
	scheduled := time.Now().Add(200 * time.Millisecond).UTC()
	row := &MetadataPublishRow{
		EventID:       "future-1",
		Namespace:     "/foo",
		ObjectPath:    "/foo/x.bin",
		ObjectSize:    1,
		ObjectCreated: time.Now().UTC(),
		CreatedAt:     time.Now().UTC(),
		NextAttemptAt: scheduled,
	}
	if err := ctl.queue.handle().Create(row).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	select {
	case at := <-delivered:
		if at.Before(scheduled.Add(-50 * time.Millisecond)) {
			t.Fatalf("worker fired too early: at %v, scheduled %v", at, scheduled)
		}
		if elapsed := at.Sub(scheduled); elapsed > 750*time.Millisecond {
			t.Fatalf("worker fired too late: %v after scheduled time", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker never fired the future-scheduled row")
	}
}

// TestSchedulerRateLimiterCapsPublishes seeds the queue with N due
// rows and asserts the per-second publish rate is bounded by the
// configured RatePerSecond. With a burst that matches MaxInflight the
// first burst goes out immediately; the rest are spaced by 1/rate.
func TestSchedulerRateLimiterCapsPublishes(t *testing.T) {
	var seen int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&seen, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     time.Microsecond,
		MaxBackoff:     time.Millisecond,
		MaxInflight:    2,
		RatePerSecond:  10, // 10 publishes/sec across the pool
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "t", nil }
	ctl.idleMaxSleep = time.Hour
	ctl.objectExists = func(context.Context, string, string) bool { return true }

	// Seed 30 due rows.
	const N = 30
	for i := 0; i < N; i++ {
		ev := NewObjectCommitEvent("/foo", fmt.Sprintf("/foo/x%d", i), int64(i), "", time.Now().UTC(), nil)
		if _, err := ctl.queue.EnqueueEvent(ev); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	// Sleep ~1.05s and check how many publishes landed. With
	// rate=10 and burst=2 we expect roughly burst + rate*1s = 12,
	// give or take. Allow generous slack since timer scheduling on
	// CI is noisy. The hard property is the *upper* bound: we must
	// be well under N (otherwise the rate limit isn't engaging).
	time.Sleep(1100 * time.Millisecond)
	got := atomic.LoadInt32(&seen)
	if got >= N {
		t.Fatalf("rate limiter never engaged: %d/%d publishes in 1.1s", got, N)
	}
	if got < 5 {
		t.Fatalf("rate limiter looks stuck: only %d publishes in 1.1s", got)
	}
	if got > 25 {
		t.Fatalf("rate limit too loose: got %d in 1.1s with rate=10/s burst=2", got)
	}
}

// TestSchedulerNextDueAtEmptyQueue confirms the DAO's NextDueAt
// returns false on an empty queue (so smartSleep falls through to
// idleMaxSleep).
func TestSchedulerNextDueAtEmptyQueue(t *testing.T) {
	db := newTestDB(t)
	q := newPublishQueue(db)
	_, ok, err := q.NextDueAt()
	if err != nil {
		t.Fatalf("NextDueAt: %v", err)
	}
	if ok {
		t.Fatal("NextDueAt returned ok=true on an empty queue")
	}
}

// TestSchedulerNextDueAtPicksMin confirms NextDueAt returns the
// smallest next_attempt_at across all rows.
func TestSchedulerNextDueAtPicksMin(t *testing.T) {
	db := newTestDB(t)
	q := newPublishQueue(db)
	earliest := time.Now().Add(50 * time.Millisecond).UTC().Round(time.Microsecond)
	rows := []*MetadataPublishRow{
		{EventID: "later", Namespace: "/x", ObjectPath: "/x/a", ObjectCreated: time.Now().UTC(),
			CreatedAt: time.Now().UTC(), NextAttemptAt: time.Now().Add(time.Hour).UTC()},
		{EventID: "earliest", Namespace: "/x", ObjectPath: "/x/b", ObjectCreated: time.Now().UTC(),
			CreatedAt: time.Now().UTC(), NextAttemptAt: earliest},
		{EventID: "middle", Namespace: "/x", ObjectPath: "/x/c", ObjectCreated: time.Now().UTC(),
			CreatedAt: time.Now().UTC(), NextAttemptAt: time.Now().Add(10 * time.Minute).UTC()},
	}
	for _, r := range rows {
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	got, ok, err := q.NextDueAt()
	if err != nil || !ok {
		t.Fatalf("NextDueAt: got=%v ok=%v err=%v", got, ok, err)
	}
	if !got.Equal(earliest) {
		t.Fatalf("NextDueAt = %v; want %v", got, earliest)
	}
}

// ---------- request middleware ----------

func TestExtractObjectMetadataFromRequest_HeaderAndContentLength(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/x", strings.NewReader("payload"))
	req.Header.Set(ObjectMetadataHeader, `experiment="atlas", run=4172`)
	req.ContentLength = 7

	out := extractObjectMetadataFromRequest(req)
	got := objectMetadataFromContext(out.Context())
	if got["experiment"] != "atlas" {
		t.Fatalf("experiment = %v", got["experiment"])
	}
	if v, _ := got["run"].(int64); v != 4172 {
		t.Fatalf("run = %v", got["run"])
	}
	if n := expectedContentLengthFromContext(out.Context()); n != 7 {
		t.Fatalf("expected Content-Length = %d", n)
	}
}

func TestExtractObjectMetadataFromRequest_NoHeaderNoContentLength(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	out := extractObjectMetadataFromRequest(req)
	if out != req {
		t.Fatal("expected the same *Request when nothing changes")
	}
	if got := objectMetadataFromContext(out.Context()); got != nil {
		t.Fatalf("expected no custom fields; got %#v", got)
	}
	if n := expectedContentLengthFromContext(out.Context()); n != -1 {
		t.Fatalf("expected -1 for absent Content-Length; got %d", n)
	}
}

func TestExtractObjectMetadataFromRequest_MalformedHeaderStillAllowsRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/x", strings.NewReader("data"))
	req.Header.Set(ObjectMetadataHeader, "completely not = sfv")
	req.ContentLength = 4
	// Should not panic / abort. Custom fields end up nil-ish but
	// Content-Length still propagates.
	out := extractObjectMetadataFromRequest(req)
	if n := expectedContentLengthFromContext(out.Context()); n != 4 {
		t.Fatalf("expected Content-Length to survive malformed header; got %d", n)
	}
}

func TestExtractObjectMetadataFromRequest_GetIgnoresContentLength(t *testing.T) {
	// We only stash Content-Length on PUTs.
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.ContentLength = 99
	out := extractObjectMetadataFromRequest(req)
	if n := expectedContentLengthFromContext(out.Context()); n != -1 {
		t.Fatalf("GET should not stash Content-Length; got %d", n)
	}
}

// ---------- path normalization ----------

func TestJoinFederationPath(t *testing.T) {
	tests := []struct {
		ns, rel, want string
	}{
		// webdav.Handler-style: ns="/exp", strips "/exp" so OpenFile sees "/data/x.bin"
		{"/exp", "/data/x.bin", "/exp/data/x.bin"},
		// trailing slash on ns: same outcome
		{"/exp/", "/data/x.bin", "/exp/data/x.bin"},
		// leading-slash variations
		{"/exp", "data/x.bin", "/exp/data/x.bin"},
		// already-rooted (defensive)
		{"/exp", "/exp/data/x.bin", "/exp/data/x.bin"},
		// root namespace
		{"/", "/data/x.bin", "/data/x.bin"},
		{"", "/data/x.bin", "/data/x.bin"},
		// empty rel
		{"/exp", "", "/exp"},
		{"/exp", "/", "/exp"},
	}
	for _, tt := range tests {
		t.Run(tt.ns+"+"+tt.rel, func(t *testing.T) {
			got := joinFederationPath(tt.ns, tt.rel)
			if got != tt.want {
				t.Errorf("joinFederationPath(%q,%q) = %q, want %q", tt.ns, tt.rel, got, tt.want)
			}
		})
	}
}

// ---------- backend ETag plumbing ----------

type fakeETagInfo struct {
	os.FileInfo
	etag string
}

func (f *fakeETagInfo) ETag(_ context.Context) (string, error) { return f.etag, nil }

// TestBackendETag_AsksFileInfo confirms the controller-side helper
// asks the FileInfo for its ETag and uses whatever it returns.
func TestBackendETag_AsksFileInfo(t *testing.T) {
	got := BackendETag(&fakeETagInfo{etag: `"backend-supplied"`})
	if got != `"backend-supplied"` {
		t.Fatalf("BackendETag = %q; want backend-supplied", got)
	}
}

// TestBackendETag_NilOrUnimplementedReturnsEmpty proves the helper
// holds no opinion of its own — if the backend doesn't tell it an
// ETag, it returns the empty string. The actual on-the-wire ETag for
// POSIXv2 is supplied by aferoFileSystem.Stat (see backend_etag.go),
// not by this helper.
func TestBackendETag_NilOrUnimplementedReturnsEmpty(t *testing.T) {
	if got := BackendETag(nil); got != "" {
		t.Fatalf("BackendETag(nil) = %q, want empty", got)
	}
	// A FileInfo with no ETag method.
	plain := &fakeFileInfoNoETag{name: "x", size: 5, mtime: time.Now()}
	if got := BackendETag(plain); got != "" {
		t.Fatalf("BackendETag(plain) = %q, want empty (it must come from the backend)", got)
	}
}

// fakeFileInfoNoETag implements os.FileInfo but NOT BackendETager —
// the negative case for TestBackendETag_NilOrUnimplementedReturnsEmpty.
type fakeFileInfoNoETag struct {
	name  string
	size  int64
	mtime time.Time
}

func (f *fakeFileInfoNoETag) Name() string       { return f.name }
func (f *fakeFileInfoNoETag) Size() int64        { return f.size }
func (f *fakeFileInfoNoETag) Mode() os.FileMode  { return 0644 }
func (f *fakeFileInfoNoETag) ModTime() time.Time { return f.mtime }
func (f *fakeFileInfoNoETag) IsDir() bool        { return false }
func (f *fakeFileInfoNoETag) Sys() any           { return nil }

// TestPosixv2BackendETag_HasStableValue confirms the POSIXv2 backend
// (the etagFileInfo wrapper installed by aferoFileSystem.Stat)
// supplies a stable, non-empty ETag matching the WebDAV-default shape.
func TestPosixv2BackendETag_HasStableValue(t *testing.T) {
	mtime := time.Unix(1745934855, 0).UTC()
	wrapped := withBackendETag(&fakeFileInfoNoETag{name: "x", size: 12345, mtime: mtime})
	got := BackendETag(wrapped)
	if got == "" {
		t.Fatal("expected non-empty ETag from POSIXv2 backend wrapper")
	}
	// Sanity-check the format matches the stdlib webdav default
	// (`"<hex(mtime)><hex(size)>"`) so a GET and a commit webhook
	// agree on the ETag for the same object.
	want := `"` + strconv.FormatInt(mtime.UnixNano(), 16) + strconv.FormatInt(12345, 16) + `"`
	if got != want {
		t.Fatalf("ETag = %q; want %q", got, want)
	}
}
