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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// installControllerForAdminTest swaps in a freshly-built controller for
// use by the admin handler tests. The original is restored on Cleanup.
func installControllerForAdminTest(t *testing.T) *metadataController {
	t.Helper()
	prev := metadataCtl
	t.Cleanup(func() { metadataCtl = prev })

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled: true,
		OriginEndpoint: "https://unused.example.com",
		OriginMode:     ModeEventual,
		DB:             db,
	})
	metadataCtl = ctl
	return ctl
}

// newAdminTestServer wires up the admin endpoints on a gin engine
// (with no auth middleware so tests can exercise behavior directly).
func newAdminTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/api/v1.0/origin_ui")
	RegisterMetadataAdminAPI(rg)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestAdminQueueListAndGet(t *testing.T) {
	ctl := installControllerForAdminTest(t)
	srv := newAdminTestServer(t)

	for i := 0; i < 3; i++ {
		ev := NewObjectCommitEvent("/foo", "/foo/x.bin", int64(i), "", time.Now().UTC(), nil)
		if _, err := ctl.queue.EnqueueEvent(ev); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	resp, err := http.Get(srv.URL + "/api/v1.0/origin_ui/metadata_queue")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status %d", resp.StatusCode)
	}
	var payload struct {
		Rows []adminQueueRow `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(payload.Rows))
	}

	// Get-by-event-id
	id := payload.Rows[0].EventID
	resp2, err := http.Get(srv.URL + "/api/v1.0/origin_ui/metadata_queue/" + id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("get status %d", resp2.StatusCode)
	}
	var row adminQueueRow
	if err := json.NewDecoder(resp2.Body).Decode(&row); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if row.EventID != id {
		t.Fatalf("eventID = %q, want %q", row.EventID, id)
	}
}

func TestAdminQueueDelete(t *testing.T) {
	ctl := installControllerForAdminTest(t)
	srv := newAdminTestServer(t)

	ev := NewObjectCommitEvent("/foo", "/foo/x.bin", 1, "", time.Now().UTC(), nil)
	if _, err := ctl.queue.EnqueueEvent(ev); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1.0/origin_ui/metadata_queue/"+ev.ID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
}

func TestAdminQueueRetryRow(t *testing.T) {
	ctl := installControllerForAdminTest(t)
	srv := newAdminTestServer(t)

	ev := NewObjectCommitEvent("/foo", "/foo/x.bin", 1, "", time.Now().UTC(), nil)
	row, err := ctl.queue.EnqueueEvent(ev)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Push next_attempt_at into the future.
	if err := ctl.queue.scheduleRetry(row.ID, time.Now().Add(24*time.Hour), "stuck"); err != nil {
		t.Fatalf("scheduleRetry: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1.0/origin_ui/metadata_queue/"+ev.ID+"/retry", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry status %d", resp.StatusCode)
	}

	got, _ := ctl.queue.FindByEventID(ev.ID)
	if got.NextAttemptAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("retry did not bring next_attempt_at forward: %v", got.NextAttemptAt)
	}
	if got.Attempts != 1 {
		t.Fatalf("retry should not bump attempts; got %d", got.Attempts)
	}
}

func TestAdminQueueHealth(t *testing.T) {
	ctl := installControllerForAdminTest(t)
	srv := newAdminTestServer(t)

	// Healthy when empty.
	resp, err := http.Get(srv.URL + "/api/v1.0/origin_ui/metadata_queue/_health")
	if err != nil {
		t.Fatalf("get _health: %v", err)
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode _health: %v", err)
	}
	if payload["state"] != "healthy" {
		t.Fatalf("empty queue not healthy: %v", payload)
	}

	// Insert a row whose created_at is older than warnAfter.
	old := time.Now().Add(-5 * time.Hour).UTC()
	row := &MetadataPublishRow{
		EventID:       "stale",
		Namespace:     "/foo",
		ObjectPath:    "/foo/x",
		ObjectSize:    1,
		ObjectCreated: old,
		CreatedAt:     old,
		NextAttemptAt: time.Now(),
	}
	if err := ctl.queue.handle().Create(row).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	resp2, err := http.Get(srv.URL + "/api/v1.0/origin_ui/metadata_queue/_health")
	if err != nil {
		t.Fatalf("get _health 2: %v", err)
	}
	defer resp2.Body.Close()
	var p2 map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&p2); err != nil {
		t.Fatalf("decode _health 2: %v", err)
	}
	if p2["state"] != "warning" {
		t.Fatalf("expected warning state, got: %v", p2)
	}
}

func TestAdminQueueServiceUnavailableWhenControllerNil(t *testing.T) {
	prev := metadataCtl
	metadataCtl = nil
	defer func() { metadataCtl = prev }()

	srv := newAdminTestServer(t)
	resp, err := http.Get(srv.URL + "/api/v1.0/origin_ui/metadata_queue")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}
