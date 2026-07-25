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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newBacklogController builds an eventual-mode controller whose endpoint
// always fails (503) so first-attempt publishes stay pending and accumulate.
// Workers are NOT started, so the queue only grows — isolating the
// enqueue-time backpressure gate.
func newBacklogController(t *testing.T, rowCap, byteCap int) *metadataController {
	t.Helper()
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(receiver.Close)

	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:              true,
		OriginEndpoint:             receiver.URL,
		OriginMode:                 ModeEventual,
		DB:                         newTestDB(t),
		MinBackoff:                 time.Hour, // keep any retry far in the future
		MaxBackoff:                 time.Hour,
		MaxInflight:                1,
		RatePerSecond:              100,
		MaxQueuedPerNamespace:      rowCap,
		MaxQueuedBytesPerNamespace: byteCap,
	})
	ctl.publisher.signToken = func(audience, namespace string) (string, error) { return "t", nil }
	return ctl
}

// TestEventual_BacklogRowCapRefusesUpload asserts that once a namespace's
// pending row count reaches the cap, further eventual-mode commits are
// refused with ErrMetadataBacklogFull (which fails the upload), while commits
// below the cap succeed and a different namespace is unaffected.
func TestEventual_BacklogRowCapRefusesUpload(t *testing.T) {
	ctl := newBacklogController(t, 2 /*rows*/, 0 /*bytes: disabled*/)
	ctx := context.Background()

	commit := func(ns string, i int) error {
		ev := NewObjectCommitEvent(ns, fmt.Sprintf("%s/o-%d", ns, i), int64(i), "", time.Now().UTC(), nil)
		return ctl.CommitEvent(ctx, ev)
	}

	// Two commits fill the queue (the 503 leaves each pending; eventual mode
	// never fails the upload on a transient error, so these return nil).
	if err := commit("/exp", 0); err != nil {
		t.Fatalf("commit 0: %v", err)
	}
	if err := commit("/exp", 1); err != nil {
		t.Fatalf("commit 1: %v", err)
	}

	// Third commit is at the cap → refused.
	if err := commit("/exp", 2); !errors.Is(err, ErrMetadataBacklogFull) {
		t.Fatalf("commit 2 err = %v, want ErrMetadataBacklogFull", err)
	}

	// A different namespace has its own budget and is unaffected.
	if err := commit("/other", 0); err != nil {
		t.Fatalf("other-namespace commit should be allowed, got %v", err)
	}
}

// TestEventual_BacklogByteCapRefusesUpload asserts the pending-blob-bytes cap
// is enforced independently of row count.
func TestEventual_BacklogByteCapRefusesUpload(t *testing.T) {
	ctl := newBacklogController(t, 0 /*rows: disabled*/, 5 /*bytes*/)
	ctx := context.Background()

	commitBlob := func(i, n int) error {
		ev := NewObjectCommitEvent("/exp", fmt.Sprintf("/exp/o-%d", i), int64(i), "", time.Now().UTC(), nil)
		ev.WithMetadataBlob("application/octet-stream", make([]byte, n))
		return ctl.CommitEvent(ctx, ev)
	}

	// First commit carries a 6-byte blob; backlog was 0 (< 5) so it's accepted
	// and pushes pending bytes to 6.
	if err := commitBlob(0, 6); err != nil {
		t.Fatalf("commit 0: %v", err)
	}
	// Next commit sees 6 pending bytes >= 5 → refused.
	if err := commitBlob(1, 6); !errors.Is(err, ErrMetadataBacklogFull) {
		t.Fatalf("commit 1 err = %v, want ErrMetadataBacklogFull", err)
	}
}

// TestEventual_BacklogDisabledByDefault confirms that with both caps at 0 the
// gate is a no-op (no behavior change for existing deployments).
func TestEventual_BacklogDisabledByDefault(t *testing.T) {
	ctl := newBacklogController(t, 0, 0)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		ev := NewObjectCommitEvent("/exp", fmt.Sprintf("/exp/o-%d", i), int64(i), "", time.Now().UTC(), nil)
		if err := ctl.CommitEvent(ctx, ev); err != nil {
			t.Fatalf("commit %d with caps disabled: %v", i, err)
		}
	}
}
