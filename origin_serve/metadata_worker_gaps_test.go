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
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestEventual_MultipartBlobSurvivesBatchedEnqueueAndWorker closes the gap
// where a metadata blob rides an eventual-mode publish. The blob columns are
// only ever populated through the BATCHED INSERT path (metadata_content_type
// / metadata_body are named explicitly in the raw INSERT), and then have to
// round-trip out of the queue row, through EventFromRow, and into the
// publisher's multipart/related body. No prior eventual-mode test enqueued a
// blob, so that whole chain was unverified.
func TestEventual_MultipartBlobSurvivesBatchedEnqueueAndWorker(t *testing.T) {
	const (
		wantBlob = `<datasetSummary><experiment>atlas</experiment></datasetSummary>`
		wantCT   = "application/xml"
	)

	type received struct {
		outerCT  string
		blobCT   string
		blobBody string
		eventNS  string
	}
	got := make(chan received, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer w.WriteHeader(http.StatusOK)
		outerCT := r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(outerCT)
		if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
			got <- received{outerCT: outerCT}
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		var rec received
		rec.outerCT = outerCT
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(part)
			ct := part.Header.Get("Content-Type")
			if strings.Contains(ct, "application/json") {
				var ev struct {
					Namespace string `json:"namespace"`
				}
				_ = json.Unmarshal(b, &ev)
				rec.eventNS = ev.Namespace
			} else {
				rec.blobCT = ct
				rec.blobBody = string(b)
			}
			_ = part.Close()
		}
		got <- rec
	}))
	defer receiver.Close()

	db := newTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Route the enqueue through the real batcher so the blob columns travel
	// the production write path, not the direct-insert test shortcut.
	batcher := newSQLiteBatcher(ctx, db, 16, 5*time.Millisecond)
	defer batcher.Stop()

	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		Batcher:        batcher,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	ctl.Start(ctx)
	defer ctl.Stop()

	ev := NewObjectCommitEvent("/exp", "/exp/run.dat", int64(len(wantBlob)), "", time.Now().UTC(), nil)
	ev.WithMetadataBlob(wantCT, []byte(wantBlob))
	if err := ctl.CommitEvent(context.Background(), ev); err != nil {
		t.Fatalf("CommitEvent: %v", err)
	}

	select {
	case rec := <-got:
		if !strings.HasPrefix(rec.outerCT, "multipart/related") {
			t.Fatalf("outer Content-Type = %q, want multipart/related", rec.outerCT)
		}
		if rec.eventNS != "/exp" {
			t.Fatalf("event namespace = %q, want /exp", rec.eventNS)
		}
		if rec.blobBody != wantBlob {
			t.Fatalf("blob body = %q, want %q", rec.blobBody, wantBlob)
		}
		if !strings.Contains(rec.blobCT, wantCT) {
			t.Fatalf("blob Content-Type = %q, want to contain %q", rec.blobCT, wantCT)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver never got the multipart webhook")
	}
}

// TestEventual_ExactlyOnceDeliveryUnderNormalDrain asserts that, absent
// failures, the eventual worker pool delivers each event exactly once — no
// duplicate publishes from lease races. MaxBackoff is set large so a claim's
// lease never expires during the run; the only way a row leaves the queue is
// a successful publish followed by delete.
func TestEventual_ExactlyOnceDeliveryUnderNormalDrain(t *testing.T) {
	var (
		mu    sync.Mutex
		seen  = map[string]int{}
		total int64
	)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &ev)
		mu.Lock()
		seen[ev.ID]++
		mu.Unlock()
		atomic.AddInt64(&total, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	db := newTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     30 * time.Second, // lease long enough to never re-fire in-test
		MaxInflight:    4,
		RatePerSecond:  10000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	ctl.Start(ctx)
	defer ctl.Stop()

	const n = 30
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ev := NewObjectCommitEvent("/exp", fmt.Sprintf("/exp/obj-%03d.dat", i), 1, "", time.Now().UTC(), nil)
		ids = append(ids, ev.ID)
		if err := ctl.CommitEvent(context.Background(), ev); err != nil {
			t.Fatalf("CommitEvent %d: %v", i, err)
		}
	}

	deadline := time.After(10 * time.Second)
	for {
		var count int64
		ctl.queue.handle().Model(&MetadataPublishRow{}).Count(&count)
		if count == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("queue did not drain (depth=%d)", count)
		case <-time.After(20 * time.Millisecond):
		}
	}

	// Give a brief grace period to catch any stray duplicate that might be
	// in flight after the row was deleted (there should be none).
	time.Sleep(200 * time.Millisecond)

	if got := atomic.LoadInt64(&total); got != n {
		t.Fatalf("total deliveries = %d, want exactly %d (duplicate publishes?)", got, n)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		if seen[id] != 1 {
			t.Fatalf("event %s delivered %d times, want exactly 1", id, seen[id])
		}
	}
}

// TestCommitEvent_EnqueueFailureSurfaces verifies that when the durable
// publish-queue INSERT fails, CommitEvent returns an error rather than
// silently swallowing the event. In production this is what makes the POSC
// close hook fail and roll back the storage commit (the design's "DB
// unavailable → 500 to client" failure mode), so the client never gets a
// false success.
func TestCommitEvent_EnqueueFailureSurfaces(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// A batcher that is already stopped rejects every enqueue with
	// "already closed" — a stand-in for any durable-write failure.
	batcher := newSQLiteBatcher(ctx, db, 4, time.Millisecond)
	batcher.Stop()

	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: "http://metadata.invalid/hook",
		OriginMode:     ModeEventual,
		DB:             db,
		Batcher:        batcher,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }

	ev := NewObjectCommitEvent("/exp", "/exp/x.dat", 1, "", time.Now().UTC(), nil)
	if err := ctl.CommitEvent(ctx, ev); err == nil {
		t.Fatal("expected CommitEvent to surface the enqueue failure, got nil")
	}

	// And nothing should have been persisted.
	var count int64
	ctl.queue.handle().Model(&MetadataPublishRow{}).Count(&count)
	if count != 0 {
		t.Fatalf("queue should be empty after a failed enqueue, got %d rows", count)
	}
}
