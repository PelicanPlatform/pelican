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
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/server_utils"
)

// plantHistoryRows seeds the object_metadata_history table directly
// (no DAO) so the pruner has predictable rows of predictable age.
func plantHistoryRows(t *testing.T, db interface{}, namespace string, ts time.Time, n int, idPrefix string) {
	t.Helper()
	// db is *gorm.DB but typed as interface{} so this helper can be
	// called from packages that don't import gorm directly.
	d := db.(interface {
		Create(any) interface{ Error() string }
		Exec(string, ...any) interface{ Error() string }
	})
	_ = d
}

// TestPruner_DeletesOnlyAgedRows seeds 5 old + 5 fresh history rows
// and asserts onePass removes only the old ones; one-pass is
// idempotent (second invocation deletes 0).
func TestPruner_DeletesOnlyAgedRows(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	// 5 old rows (40 days ago) + 5 fresh (10 minutes ago).
	old := time.Now().Add(-40 * 24 * time.Hour).UTC()
	fresh := time.Now().Add(-10 * time.Minute).UTC()
	for i := 0; i < 5; i++ {
		if err := db.Create(&ObjectMetadataHistoryRow{
			EventID: fmt.Sprintf("o-%d", i), Namespace: "/exp",
			ObjectPath: fmt.Sprintf("/exp/old-%d", i),
			EventType:  "commit", EventTS: old,
		}).Error; err != nil {
			t.Fatalf("seed old: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		if err := db.Create(&ObjectMetadataHistoryRow{
			EventID: fmt.Sprintf("f-%d", i), Namespace: "/exp",
			ObjectPath: fmt.Sprintf("/exp/fresh-%d", i),
			EventType:  "commit", EventTS: fresh,
		}).Error; err != nil {
			t.Fatalf("seed fresh: %v", err)
		}
	}

	rd := 7
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/exp",
			Metadata:         &server_utils.OriginExportMetadata{HistoryRetentionDays: &rd},
		},
	}
	pruner := newObjectMetadataPruner(d, exports, time.Hour, 100)
	// Don't Start() — onePass directly so the test is deterministic.
	pruner.onePass(ctx)

	var remain int64
	if err := db.Model(&ObjectMetadataHistoryRow{}).Count(&remain).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if remain != 5 {
		t.Fatalf("after prune: %d rows remain, want 5 (the fresh ones)", remain)
	}

	// Second pass: nothing to prune.
	pruner.onePass(ctx)
	if err := db.Model(&ObjectMetadataHistoryRow{}).Count(&remain).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if remain != 5 {
		t.Fatalf("idempotency: rows changed across no-op pass: %d", remain)
	}
}

// TestPruner_RetentionZeroSkipsNamespace — a namespace with
// retention=0 ("keep forever") is left entirely untouched, even when
// it has aged rows.
func TestPruner_RetentionZeroSkipsNamespace(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := db.Create(&ObjectMetadataHistoryRow{
			EventID: fmt.Sprintf("k-%d", i), Namespace: "/keepforever",
			ObjectPath: fmt.Sprintf("/keepforever/x-%d", i),
			EventType:  "commit",
			EventTS:    time.Now().Add(-100 * 24 * time.Hour).UTC(),
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	zero := 0
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/keepforever",
			Metadata:         &server_utils.OriginExportMetadata{HistoryRetentionDays: &zero},
		},
	}
	pruner := newObjectMetadataPruner(d, exports, time.Hour, 100)
	pruner.onePass(ctx)

	var remain int64
	if err := db.Model(&ObjectMetadataHistoryRow{}).Count(&remain).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if remain != 5 {
		t.Fatalf("retention=0 namespace was touched: %d rows remain (want 5)", remain)
	}
}

// TestPruner_HonorsBatchSize ensures the per-pass loop keeps going
// until aged rows are drained, even when batchSize is much smaller
// than the aged set.
func TestPruner_HonorsBatchSize(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	const N = 50
	old := time.Now().Add(-90 * 24 * time.Hour).UTC()
	for i := 0; i < N; i++ {
		if err := db.Create(&ObjectMetadataHistoryRow{
			EventID: fmt.Sprintf("o-%d", i), Namespace: "/exp",
			ObjectPath: fmt.Sprintf("/exp/x-%d", i),
			EventType:  "commit", EventTS: old,
		}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	rd := 30
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/exp",
			Metadata:         &server_utils.OriginExportMetadata{HistoryRetentionDays: &rd},
		},
	}
	// batchSize=7 so the inner loop needs ceil(50/7) = 8 iterations.
	pruner := newObjectMetadataPruner(d, exports, time.Hour, 7)
	pruner.onePass(ctx)

	var remain int64
	if err := db.Model(&ObjectMetadataHistoryRow{}).Count(&remain).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if remain != 0 {
		t.Fatalf("expected drained namespace; %d rows remain", remain)
	}
}

// TestPruner_HooksFire — the metric hooks are called with sensible
// values so the metrics package can observe the pruner correctly.
func TestPruner_HooksFire(t *testing.T) {
	d, db, cleanup := newTestDAO(t)
	defer cleanup()
	ctx := context.Background()

	old := time.Now().Add(-40 * 24 * time.Hour).UTC()
	for i := 0; i < 12; i++ {
		_ = db.Create(&ObjectMetadataHistoryRow{
			EventID: fmt.Sprintf("h-%d", i), Namespace: "/x",
			ObjectPath: fmt.Sprintf("/x/h-%d", i), EventType: "commit", EventTS: old,
		}).Error
	}

	rd := 7
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/x",
			Metadata:         &server_utils.OriginExportMetadata{HistoryRetentionDays: &rd},
		},
	}
	pruner := newObjectMetadataPruner(d, exports, time.Hour, 5)

	var (
		deletedCalls []int64
		passRan      bool
	)
	pruner.SetHooks(PrunerHooks{
		IncDeleted:          func(ns string, n int64) { deletedCalls = append(deletedCalls, n) },
		ObservePassDuration: func(_ time.Duration) { passRan = true },
	})

	pruner.onePass(ctx)

	if !passRan {
		t.Fatal("ObservePassDuration not called")
	}
	// 12 rows / batch 5 → batches of 5, 5, 2.
	if len(deletedCalls) != 3 {
		t.Fatalf("IncDeleted call count = %d, want 3 (batches of 5,5,2): %v", len(deletedCalls), deletedCalls)
	}
	total := int64(0)
	for _, n := range deletedCalls {
		total += n
	}
	if total != 12 {
		t.Fatalf("total deleted = %d, want 12", total)
	}
}

// silence unused warning if the helper above gets pared back later.
var _ = plantHistoryRows
