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

// File object_metadata_pruner.go is the background goroutine that
// trims object_metadata_history per the configured retention policy.
//
// Design choices:
//
//   * Per-namespace iteration. Each export carries its own retention
//     setting (HistoryRetentionDays — or, when unset, the origin-wide
//     default). Namespaces with retention=0 are skipped entirely;
//     they never even get a SELECT-COUNT(*) so a "keep forever"
//     namespace doesn't drag the pruner's wall-clock.
//
//   * Bounded per-pass deletes. PruneBatchSize caps the DELETE-per-
//     loop, keeping the WAL transaction small and the lock window
//     short. The pruner loops within a single namespace until a pass
//     returns less-than-batch rows (queue drained for now).
//
//   * Best-effort. The DELETE go directly through GORM, not through
//     the write-behind batcher — they're already coalesced (one tx
//     per LIMIT-N batch) and don't need to share the hot-path
//     batcher with publish-queue inserts.

package origin_serve

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_utils"
)

// objectMetadataPruner deletes aged-out history rows. Constructed
// once per origin process by InitializeHandlers when at least one
// namespace has a positive retention configured.
type objectMetadataPruner struct {
	dao       *objectMetadataDAO
	exports   []server_utils.OriginExport
	interval  time.Duration
	batchSize int

	clock func() time.Time

	wg     sync.WaitGroup
	cancel context.CancelFunc

	// Optional metric hooks; nil-tolerant.
	hooks PrunerHooks
}

// PrunerHooks lets the metrics package observe pruner activity.
type PrunerHooks struct {
	// IncDeleted is called once per loop iteration that deleted at
	// least one row. `namespace` is the export's federation prefix;
	// `count` is the number of rows deleted in that iteration.
	IncDeleted func(namespace string, count int64)
	// ObservePassDuration is called once per full pass (all
	// namespaces), with the total wall-clock spent.
	ObservePassDuration func(d time.Duration)
}

// newObjectMetadataPruner constructs the pruner but does not start
// it. Caller must invoke Start(ctx).
func newObjectMetadataPruner(dao *objectMetadataDAO, exports []server_utils.OriginExport, interval time.Duration, batchSize int) *objectMetadataPruner {
	if interval <= 0 {
		interval = time.Hour
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	return &objectMetadataPruner{
		dao:       dao,
		exports:   exports,
		interval:  interval,
		batchSize: batchSize,
		clock:     time.Now,
	}
}

// SetHooks wires metrics callbacks.
func (p *objectMetadataPruner) SetHooks(h PrunerHooks) { p.hooks = h }

// Start launches the background goroutine. It runs an initial pass
// shortly after start (so a long PruneInterval doesn't mean the
// first prune is hours away) and then on every PruneInterval tick.
func (p *objectMetadataPruner) Start(ctx context.Context) {
	if p.dao == nil {
		log.Debug("objectMetadataPruner.Start called with nil DAO; pruner disabled")
		return
	}
	childCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.wg.Add(1)
	go p.runLoop(childCtx)
}

// Stop cancels the goroutine and waits for it to exit. Safe to call
// more than once or when Start was never called.
func (p *objectMetadataPruner) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}

// runLoop is the goroutine body. We fire the first prune ~1 second
// after start (intentionally not immediate — let the origin finish
// booting), then on every interval tick.
func (p *objectMetadataPruner) runLoop(ctx context.Context) {
	defer p.wg.Done()

	// Small initial delay so we don't pile onto startup work.
	initial := time.NewTimer(time.Second)
	defer initial.Stop()
	select {
	case <-ctx.Done():
		return
	case <-initial.C:
		p.onePass(ctx)
	}

	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.onePass(ctx)
		}
	}
}

// onePass walks every export and prunes its history per its
// configured retention. A "pass" finishes when every namespace has
// been processed; the next pass waits the full interval before
// starting again.
func (p *objectMetadataPruner) onePass(ctx context.Context) {
	start := p.clock()
	for _, e := range p.exports {
		select {
		case <-ctx.Done():
			return
		default:
		}
		retentionDays := resolveHistoryRetentionDays(e)
		if retentionDays <= 0 {
			// 0 (or negative) = keep forever; skip entirely.
			continue
		}
		cutoff := p.clock().Add(-time.Duration(retentionDays) * 24 * time.Hour)
		p.pruneNamespaceToCompletion(ctx, e.FederationPrefix, cutoff)
	}
	if p.hooks.ObservePassDuration != nil {
		p.hooks.ObservePassDuration(p.clock().Sub(start))
	}
}

// pruneNamespaceToCompletion drains aged-out history rows AND
// aged-out soft-deleted live rows for one namespace in this pass.
// Two independent loops because they live in different tables; each
// runs until a DELETE returns less than batchSize rows.
//
// Same retention cutoff applies to both: a row that's been deleted
// for longer than RetentionDays is also a row whose original commit
// happened (presumably) at least RetentionDays ago. Operators who
// want a different cadence for the two tables can split via a
// future config knob; today they share.
func (p *objectMetadataPruner) pruneNamespaceToCompletion(ctx context.Context, namespace string, cutoff time.Time) {
	// History rows.
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		deleted, err := p.dao.PruneHistory(ctx, namespace, cutoff, p.batchSize)
		if err != nil {
			log.Warnf("object-metadata pruner: namespace=%s PruneHistory failed: %v", namespace, err)
			break
		}
		if deleted > 0 && p.hooks.IncDeleted != nil {
			p.hooks.IncDeleted(namespace, deleted)
		}
		if deleted < int64(p.batchSize) {
			break
		}
	}

	// Soft-deleted live rows. Same loop shape; same batch size.
	// We use the same IncDeleted hook so the metric counts every
	// row the pruner removes regardless of which table it came
	// from — operators tracking "how much is the pruner doing"
	// care about the aggregate, and per-table breakdown lives in
	// the row-counts (not yet exposed here).
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		deleted, err := p.dao.PruneSoftDeletedLive(ctx, namespace, cutoff, p.batchSize)
		if err != nil {
			log.Warnf("object-metadata pruner: namespace=%s PruneSoftDeletedLive failed: %v", namespace, err)
			return
		}
		if deleted > 0 && p.hooks.IncDeleted != nil {
			p.hooks.IncDeleted(namespace, deleted)
		}
		if deleted < int64(p.batchSize) {
			return
		}
	}
}
