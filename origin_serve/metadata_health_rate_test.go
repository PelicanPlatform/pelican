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
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestComputeHealthState_Boundaries locks down the pure age→state mapping at
// its threshold boundaries: exactly-at-threshold is inclusive (>=), one second
// under is not. (TestComputeHealthState covers the coarse states.)
func TestComputeHealthState_Boundaries(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	warn := 4 * time.Hour
	errAfter := 24 * time.Hour
	at := func(d time.Duration) *time.Time { tm := now.Add(-d); return &tm }

	cases := []struct {
		name   string
		oldest *time.Time
		want   string
	}{
		{"empty queue", nil, "healthy"},
		{"fresh", at(time.Minute), "healthy"},
		{"just under warn", at(warn - time.Second), "healthy"},
		{"exactly warn", at(warn), "warning"},
		{"between warn and error", at(10 * time.Hour), "warning"},
		{"just under error", at(errAfter - time.Second), "warning"},
		{"exactly error", at(errAfter), "error"},
		{"well past error", at(48 * time.Hour), "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := computeHealthState(tc.oldest, now, warn, errAfter); got != tc.want {
				t.Fatalf("computeHealthState = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRefreshHealthMetrics_GaugeTransitions drives the actual gauge through a
// controller with a fake clock: one pending row ages from healthy → warning →
// error, and draining the queue returns it to healthy. Reads the live
// Prometheus gauge to prove refreshHealthMetrics wires state correctly.
func TestRefreshHealthMetrics_GaugeTransitions(t *testing.T) {
	db := newTestDB(t)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: "http://metadata.invalid/hook",
		OriginMode:     ModeEventual,
		DB:             db,
		WarnAfter:      4 * time.Hour,
		ErrorAfter:     24 * time.Hour,
		MaxInflight:    1,
		RatePerSecond:  1000,
	})
	// Do NOT Start() the controller — we drive refreshHealthMetrics directly so
	// the background metricsLoop can't race our gauge reads.

	base := time.Now().UTC()
	ev := NewObjectCommitEvent("/exp", "/exp/x.dat", 1, "", base, nil)
	if _, err := ctl.queue.EnqueueEvent(context.Background(), ev); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	stateGauge := func(state string) float64 {
		return testutil.ToFloat64(metadataHealth.WithLabelValues(state))
	}
	assertState := func(want string) {
		t.Helper()
		ctl.refreshHealthMetrics()
		for _, s := range []string{"healthy", "warning", "error"} {
			exp := 0.0
			if s == want {
				exp = 1.0
			}
			if got := stateGauge(s); got != exp {
				t.Fatalf("state=%s gauge=%v, want %v (expected overall state %q)", s, got, exp, want)
			}
		}
	}

	// Row is ~0s old.
	ctl.clock = func() time.Time { return base.Add(time.Minute) }
	assertState("healthy")

	// Age past WarnAfter.
	ctl.clock = func() time.Time { return base.Add(5 * time.Hour) }
	assertState("warning")

	// Age past ErrorAfter.
	ctl.clock = func() time.Time { return base.Add(25 * time.Hour) }
	assertState("error")

	// Drain the queue → back to healthy regardless of clock.
	if err := ctl.queue.DeleteByEventID(ev.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	assertState("healthy")
}

// TestEventual_RatePerSecondThrottles proves the shared token bucket actually
// paces cross-worker publishing: with a low RatePerSecond and burst of 1, a
// batch of events cannot drain faster than the rate allows. Without the
// limiter these publishes would complete near-instantly.
func TestEventual_RatePerSecondThrottles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: timing-sensitive")
	}

	var delivered int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		atomic.AddInt64(&delivered, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	db := newTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		n    = 12
		rate = 20 // tokens/sec → 50ms between tokens
	)
	ctl := newMetadataController(metadataControllerOptions{
		OriginEnabled:  true,
		OriginEndpoint: receiver.URL,
		OriginMode:     ModeEventual,
		DB:             db,
		MinBackoff:     time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		MaxInflight:    1, // burst == MaxInflight == 1
		RatePerSecond:  rate,
	})
	ctl.publisher.signToken = func(string, string) (string, error) { return "tok", nil }
	ctl.Start(ctx)
	defer ctl.Stop()

	start := time.Now()
	for i := 0; i < n; i++ {
		ev := NewObjectCommitEvent("/exp", fmt.Sprintf("/exp/obj-%02d.dat", i), 1, "", time.Now().UTC(), nil)
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
		case <-time.After(10 * time.Millisecond):
		}
	}
	elapsed := time.Since(start)

	if got := atomic.LoadInt64(&delivered); got != n {
		t.Fatalf("delivered %d, want %d", got, n)
	}
	// With burst 1 and 50ms/token, n publishes need >= (n-1)*50ms. Assert a
	// comfortably lower bound so the test proves throttling without flaking.
	minExpected := time.Duration(n-1) * time.Second / rate // 550ms
	floor := minExpected * 3 / 4                           // ~412ms
	if elapsed < floor {
		t.Fatalf("drained in %s, expected >= %s under a %d/s rate limit (throttling not applied?)", elapsed, floor, rate)
	}
}
