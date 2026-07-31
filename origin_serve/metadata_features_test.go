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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// fakeFileInfo is a minimal os.FileInfo for close-hook tests.
type fakeFileInfo struct {
	name string
	size int64
	mod  time.Time
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// readPublishedType waits for one webhook body and returns its (type, path).
func readPublishedType(t *testing.T, bodies chan []byte) (string, string) {
	t.Helper()
	select {
	case b := <-bodies:
		var got struct {
			Type   string         `json:"type"`
			Object map[string]any `json:"object"`
		}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal webhook body: %v", err)
		}
		p, _ := got.Object["path"].(string)
		return got.Type, p
	case <-time.After(3 * time.Second):
		t.Fatal("no webhook delivered")
		return "", ""
	}
}

// newFixedStatusController builds an eventual/transactional controller pointed
// at a receiver that always returns `status`, counting how many times it was
// called. objectExists is stubbed true and the token signer is a stub.
func newFixedStatusController(t *testing.T, mode PublishMode, status int, calls *int32) *metadataController {
	t.Helper()
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if calls != nil {
			atomic.AddInt32(calls, 1)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(receiver.Close)

	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     mode,
		DB:             db,
		RequestTimeout: 2 * time.Second,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "t", nil }
	ctl.objectExists = func(context.Context, string, string) bool { return true }
	t.Cleanup(ctl.Stop)
	return ctl
}

// ---------- Feature 1: 422 permanent reject ----------

func TestEventual_PermanentReject422MarksTerminal(t *testing.T) {
	var calls int32
	ctl := newFixedStatusController(t, ModeEventual, PermanentRejectStatus, &calls)

	ev := NewObjectCommitEvent("/exp", "/exp/bad.dat", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(context.Background(), ev); err != nil {
		t.Fatalf("eventual CommitEvent must not fail the upload on 422: %v", err)
	}

	// The row is kept but terminal, and the catalog was called exactly once.
	row, err := ctl.queue.FindByEventID(ev.ID)
	if err != nil {
		t.Fatalf("row should still exist (rejected): %v", err)
	}
	if row.State != metadataStateRejected {
		t.Fatalf("state = %q, want %q", row.State, metadataStateRejected)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("catalog called %d times, want 1 (no retries after 422)", n)
	}

	// A worker must not re-claim a rejected row.
	if _, ok, _ := ctl.queue.NextDueAt(); ok {
		t.Fatal("NextDueAt reported a due row; rejected rows must not be claimable")
	}
	ctl.Start(context.Background())
	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("catalog called %d times after starting worker, want 1", n)
	}
}

func TestTransactional_PermanentReject422FailsUpload(t *testing.T) {
	ctl := newFixedStatusController(t, ModeTransactional, PermanentRejectStatus, nil)

	ev := NewObjectCommitEvent("/exp", "/exp/bad.dat", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(context.Background(), ev); err == nil {
		t.Fatal("transactional CommitEvent must return an error on 422 so the PUT fails")
	}
	// Transactional rows never persist.
	if _, err := ctl.queue.FindByEventID(ev.ID); err == nil {
		t.Fatal("transactional row should have been deleted")
	}
}

// ---------- Feature 2: eventual first-attempt result headers ----------

func TestEventual_FirstAttemptReportsPublished(t *testing.T) {
	ctl := newFixedStatusController(t, ModeEventual, http.StatusOK, nil)
	hdr := http.Header{}
	ev := NewObjectCommitEvent("/exp", "/exp/ok.dat", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(withResponseHeader(context.Background(), hdr), ev); err != nil {
		t.Fatalf("CommitEvent: %v", err)
	}
	if got := hdr.Get(MetadataStatusHeader); got != metadataClientPublished {
		t.Fatalf("status header = %q, want %q", got, metadataClientPublished)
	}
	// A published upload has no queue row to manage → no URLs.
	if u := hdr.Get(MetadataManageURLHeader); u != "" {
		t.Fatalf("manage URL should be empty for a published upload, got %q", u)
	}
	if _, err := ctl.queue.FindByEventID(ev.ID); err == nil {
		t.Fatal("published row should have been deleted")
	}
}

func TestEventual_FirstAttemptReportsQueuedWithURLs(t *testing.T) {
	// Transient 500 → first attempt fails, row stays pending, client is told
	// "queued" and handed capability URLs.
	ctl := newFixedStatusController(t, ModeEventual, http.StatusInternalServerError, nil)
	hdr := http.Header{}
	ev := NewObjectCommitEvent("/exp", "/exp/slow.dat", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(withResponseHeader(context.Background(), hdr), ev); err != nil {
		t.Fatalf("eventual CommitEvent must not fail on transient error: %v", err)
	}
	if got := hdr.Get(MetadataStatusHeader); got != metadataClientQueued {
		t.Fatalf("status header = %q, want %q", got, metadataClientQueued)
	}
	if hdr.Get(MetadataQueryURLHeader) == "" || hdr.Get(MetadataManageURLHeader) == "" {
		t.Fatalf("queued upload must carry query + manage URLs; got query=%q manage=%q",
			hdr.Get(MetadataQueryURLHeader), hdr.Get(MetadataManageURLHeader))
	}
	row, err := ctl.queue.FindByEventID(ev.ID)
	if err != nil {
		t.Fatalf("queued row should persist: %v", err)
	}
	if row.State != metadataStatePending {
		t.Fatalf("state = %q, want pending", row.State)
	}
}

func TestEventual_FirstAttemptReportsRejectedWithURLs(t *testing.T) {
	ctl := newFixedStatusController(t, ModeEventual, PermanentRejectStatus, nil)
	hdr := http.Header{}
	ev := NewObjectCommitEvent("/exp", "/exp/bad.dat", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(withResponseHeader(context.Background(), hdr), ev); err != nil {
		t.Fatalf("CommitEvent: %v", err)
	}
	if got := hdr.Get(MetadataStatusHeader); got != metadataClientRejected {
		t.Fatalf("status header = %q, want %q", got, metadataClientRejected)
	}
	// The client still gets URLs so it can inspect / clean up the rejected row.
	if hdr.Get(MetadataQueryURLHeader) == "" || hdr.Get(MetadataManageURLHeader) == "" {
		t.Fatal("rejected upload must still carry query + manage URLs")
	}
}

// ---------- Feature 3: capability-URL status / manage endpoints ----------

func newStatusAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/api/v1.0/origin_ui")
	RegisterMetadataStatusAPI(rg)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestMetadataStatusEndpoints(t *testing.T) {
	ctl := installControllerForAdminTest(t) // sets the package-global metadataCtl
	srv := newStatusAPIServer(t)

	ev := NewObjectCommitEvent("/exp", "/exp/watch.dat", 3, "", time.Now().UTC(), nil)
	if _, err := ctl.queue.EnqueueEvent(context.Background(), ev,
		managementTokens{Query: "querytok", Manage: "managetok"}, time.Hour); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	base := srv.URL + "/api/v1.0/origin_ui/metadata_publish/"

	// GET with the query token → 200 + status body.
	resp, err := http.Get(base + "querytok")
	if err != nil {
		t.Fatalf("GET query: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET query token = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if body["object_path"] != "/exp/watch.dat" || body["state"] != metadataStatePending {
		t.Fatalf("status body = %v", body)
	}

	// GET with the manage token also works.
	resp, _ = http.Get(base + "managetok")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET manage token = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// GET unknown token → 404.
	resp, _ = http.Get(base + "nope")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET unknown = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// DELETE with the query (read-only) token → 403; row survives.
	if code := doDelete(t, base+"querytok"); code != http.StatusForbidden {
		t.Fatalf("DELETE with query token = %d, want 403", code)
	}
	if _, err := ctl.queue.FindByEventID(ev.ID); err != nil {
		t.Fatalf("row must survive a rejected DELETE: %v", err)
	}

	// DELETE with the manage token → 200; row gone.
	if code := doDelete(t, base+"managetok"); code != http.StatusOK {
		t.Fatalf("DELETE with manage token = %d, want 200", code)
	}
	if _, err := ctl.queue.FindByEventID(ev.ID); err == nil {
		t.Fatal("row should be deleted after manage-token DELETE")
	}
}

func doDelete(t *testing.T, url string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatalf("new DELETE: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	return resp.StatusCode
}

// ---------- object.deleted / object.updated ----------

// TestObjectDeleted_PublishedAndNotSkipped verifies that an object.deleted
// event is published even though the object no longer exists — the worker's
// skip-if-deleted check must NOT drop delete events.
func TestObjectDeleted_PublishedAndNotSkipped(t *testing.T) {
	ctl, _, requests, _ := newTestController(t, ModeEventual, nil)
	// Simulate the object being gone (it was just deleted).
	ctl.objectExists = func(context.Context, string, string) bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	ctl.PublishDeleteHook("/exp")(context.Background(), "/exp/gone.dat")

	typ, path := readPublishedType(t, requests)
	if typ != ObjectDeletedEventType {
		t.Fatalf("event type = %q, want %q", typ, ObjectDeletedEventType)
	}
	if path != "/exp/gone.dat" {
		t.Fatalf("object path = %q, want /exp/gone.dat", path)
	}
}

// TestObjectUpdated_OverwriteDetectedViaTrackingDB verifies the tracked commit
// hook emits object.committed for a first write and object.updated for a
// subsequent overwrite of the same path — decided purely from the local
// tracking DB (a live row already exists).
func TestObjectUpdated_OverwriteDetectedViaTrackingDB(t *testing.T) {
	ctl, dao, requests := newTrackedTestController(t, ModeEventual)

	hook := ctl.CommitEventFromCloseHookTracked("/exp", dao, false)
	info := fakeFileInfo{name: "x.dat", size: 5, mod: time.Now().UTC()}
	ctx := context.Background()

	// First write of the path → create.
	if err := hook(ctx, "/data/x.dat", info); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if typ, path := readPublishedType(t, requests); typ != ObjectCommitEventType || path != "/exp/data/x.dat" {
		t.Fatalf("first write: type=%q path=%q, want object.committed /exp/data/x.dat", typ, path)
	}

	// Overwrite of the same path → update (tracking DB has a live row now).
	if err := hook(ctx, "/data/x.dat", info); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if typ, _ := readPublishedType(t, requests); typ != ObjectUpdatedEventType {
		t.Fatalf("overwrite: type=%q, want %q", typ, ObjectUpdatedEventType)
	}
}

// TestObjectUpdated_OutOfBandChange verifies PublishUpdateHook emits an
// object.updated event carrying the new size/etag.
func TestObjectUpdated_OutOfBandChange(t *testing.T) {
	ctl, _, requests, _ := newTestController(t, ModeEventual, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	ctl.PublishUpdateHook("/exp")(context.Background(), "/exp/changed.dat", 99, `"new-etag"`, time.Now().UTC())

	typ, path := readPublishedType(t, requests)
	if typ != ObjectUpdatedEventType || path != "/exp/changed.dat" {
		t.Fatalf("type=%q path=%q, want object.updated /exp/changed.dat", typ, path)
	}
}
