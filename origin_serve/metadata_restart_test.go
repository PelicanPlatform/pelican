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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEventual_RestartResumesQueuedRows is the core reliability claim of
// eventual mode: an origin that enqueues publish rows and then exits
// (crash / restart) must, on the next start, resume and drain those rows.
// It models that directly — rows are written to the queue with no
// controller running (as a prior process would leave them), then a brand
// new controller is constructed over the SAME database and started; every
// queued row must be delivered to the webhook receiver.
//
// This exercises the start-up path that reads preMultiuserFs via the
// worker pool, so it also guards against the class of start-order race
// where workers claim due rows before the rest of wiring is in place.
func TestEventual_RestartResumesQueuedRows(t *testing.T) {
	got := make(chan string, 32)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed struct {
			Object struct {
				Path string `json:"path"`
			} `json:"object"`
		}
		_ = json.Unmarshal(body, &parsed)
		got <- parsed.Object.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	db := newTestDB(t)

	// A prior origin process enqueued rows (next_attempt_at in the past)
	// and exited before publishing any of them.
	q := newPublishQueue(db)
	const rows = 5
	want := map[string]bool{}
	for i := 0; i < rows; i++ {
		path := fmt.Sprintf("/exp/data/obj-%d.dat", i)
		want[path] = true
		ev := NewObjectCommitEvent("/exp", path, int64(i), "", time.Now().UTC(), nil)
		if _, err := q.EnqueueEvent(context.Background(), ev, managementTokens{}, 0); err != nil {
			t.Fatalf("seed enqueue %d: %v", i, err)
		}
	}

	// The restart: a brand-new controller over the same database.
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
		MaxInflight:    2,
		RatePerSecond:  100,
	})
	ctl.publisher.signToken = func(audience, namespace string) (string, error) {
		return "test-token-" + namespace, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl.Start(ctx)
	defer ctl.Stop()

	seen := map[string]bool{}
	deadline := time.After(15 * time.Second)
	for len(seen) < rows {
		select {
		case p := <-got:
			if !want[p] {
				t.Fatalf("received unexpected object path %q", p)
			}
			seen[p] = true
		case <-deadline:
			t.Fatalf("restart resumed only %d/%d queued rows", len(seen), rows)
		}
	}

	// The queue must fully drain. The row delete lands just after the
	// receiver acks the last webhook, so poll rather than sampling once.
	drainDeadline := time.After(5 * time.Second)
	for {
		stats, err := ctl.queue.QueueStats()
		if err != nil {
			t.Fatalf("queue stats: %v", err)
		}
		if stats.Total == 0 {
			break
		}
		select {
		case <-drainDeadline:
			t.Fatalf("after resume, %d pending rows remain, want 0", stats.Total)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
