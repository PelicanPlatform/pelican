package origin_serve

import (
	"context"
	"testing"
	"time"
)

// TestScheduleRetryNormalizesToUTC is a regression test for a retry storm:
// scheduleRetry stored next_attempt_at in whatever timezone the caller's clock
// used. SQLite has no timezone type, so a local-zone backoff (e.g. "07:53" at
// UTC-5) was string-compared by claimDue against time.Now().UTC() ("12:51"),
// making the just-failed row instantly re-eligible and producing a tight retry
// loop. scheduleRetry must normalize to UTC so a future backoff is genuinely in
// the future relative to the selector.
func TestScheduleRetryNormalizesToUTC(t *testing.T) {
	db := newTestDB(t)
	q := newPublishQueue(db)

	event := NewObjectCommitEvent("/foo", "/foo/a.bin", 1, `"e"`, time.Now().UTC(), nil)
	row, err := q.EnqueueEvent(context.Background(), event, managementTokens{}, 0)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Claim the (immediately-due) row, leasing it.
	claimed, err := q.claimDue(1, time.Minute)
	if err != nil {
		t.Fatalf("claimDue: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("expected 1 claimed row, got %d", len(claimed))
	}

	// Simulate the failing-attempt path with a clock in a non-UTC zone (the
	// user reported this at UTC-5). Before the fix this stored the local
	// wall-clock, which string-compares as being in the past against the
	// UTC selector.
	west := time.FixedZone("UTC-5", -5*3600)
	backoff := time.Now().In(west).Add(30 * time.Minute)
	if err := q.scheduleRetry(row.ID, backoff, "connection refused"); err != nil {
		t.Fatalf("scheduleRetry: %v", err)
	}

	// The row is now scheduled 30 minutes out. A subsequent claim must find
	// NOTHING due — the bug made it immediately re-eligible.
	again, err := q.claimDue(1, time.Minute)
	if err != nil {
		t.Fatalf("second claimDue: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("row became re-eligible immediately after a 30m backoff (retry storm); got %d due rows", len(again))
	}
}
