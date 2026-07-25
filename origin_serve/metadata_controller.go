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

// File metadata_controller.go is the orchestration layer that ties
// together:
//
//   - Per-export resolution of endpoint URL + publish mode.
//   - The publish queue (write-ahead log shared by both modes).
//   - The single-attempt publisher.
//   - The eventually-consistent worker pool.
//   - Prometheus metrics + health-state reporting.
//   - The close-time hook invoked by the POSC layer.

package origin_serve

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// shouldEnableMetadataController returns true when at least one export
// (or the origin-wide setting) wants the metadata controller running.
// We start the controller as long as there's any chance an event will
// be published; per-export resolution does the rest.
func shouldEnableMetadataController(exports []server_utils.OriginExport) bool {
	if param.Origin_Metadata_Enabled.GetBool() {
		return true
	}
	for _, e := range exports {
		if e.Metadata != nil && e.Metadata.Enabled != nil && *e.Metadata.Enabled {
			return true
		}
	}
	return false
}

// PublishMode is the per-event behavior knob.
type PublishMode string

const (
	ModeTransactional PublishMode = "transactional"
	ModeEventual      PublishMode = "eventual"
)

// IsValid reports whether m is a recognized mode.
func (m PublishMode) IsValid() bool {
	return m == ModeTransactional || m == ModeEventual
}

// metadataResolver looks up per-export configuration for an event. The
// resolution rule is "per-export wins, falling back to origin-wide".
type metadataResolver struct {
	originEnabled  bool
	originEndpoint string
	originMode     PublishMode
	exportConfig   map[string]exportMetadataConfig
}

type exportMetadataConfig struct {
	enabled  *bool
	endpoint string
	mode     PublishMode
}

func newMetadataResolver(originEnabled bool, originEndpoint string, originMode PublishMode, exports []server_utils.OriginExport) *metadataResolver {
	r := &metadataResolver{
		originEnabled:  originEnabled,
		originEndpoint: strings.TrimSpace(originEndpoint),
		originMode:     originMode,
		exportConfig:   make(map[string]exportMetadataConfig, len(exports)),
	}
	for _, e := range exports {
		if e.Metadata == nil {
			continue
		}
		r.exportConfig[e.FederationPrefix] = exportMetadataConfig{
			enabled:  e.Metadata.Enabled,
			endpoint: strings.TrimSpace(e.Metadata.Endpoint),
			mode:     PublishMode(strings.TrimSpace(e.Metadata.Mode)),
		}
	}
	return r
}

// Resolve returns (enabled, endpoint, mode) for a federation prefix.
// `enabled=false` means "the controller should not even enqueue".
func (r *metadataResolver) Resolve(namespace string) (enabled bool, endpoint string, mode PublishMode) {
	enabled = r.originEnabled
	endpoint = r.originEndpoint
	mode = r.originMode
	if cfg, ok := r.exportConfig[namespace]; ok {
		if cfg.enabled != nil {
			enabled = *cfg.enabled
		}
		if cfg.endpoint != "" {
			endpoint = cfg.endpoint
		}
		if cfg.mode != "" {
			mode = cfg.mode
		}
	}
	return enabled, endpoint, mode
}

// metadataController is the single instance per origin process that
// owns the publisher, the queue DAO, and the worker pool.
type metadataController struct {
	publisher *publisher
	queue     *publishQueue
	resolver  *metadataResolver

	maxInflight   int
	ratePerSecond int
	minBackoff    time.Duration
	maxBackoff    time.Duration

	warnAfter  time.Duration
	errorAfter time.Duration

	// limiter caps the *global* publish rate across all worker
	// goroutines. Each Attempt acquires one token; when there are
	// no tokens, the worker blocks until the next refill.
	limiter *rate.Limiter

	// tickle is signalled (non-blocking) every time a row is
	// enqueued in eventual mode, so an idle worker wakes up
	// immediately rather than waiting for the next polling tick.
	// Buffered to size 1 so a flurry of enqueues collapses into a
	// single wake-up; the worker then drains everything that's due.
	tickle chan struct{}

	// objectExists is the deletion-aware retry hook: before each
	// retry the controller calls this to see if the underlying
	// object still exists. Defaulting to a func returning true keeps
	// tests that don't care about it simple.
	objectExists func(ctx context.Context, namespace, objectPath string) bool

	// rng is used for jitter; tests can swap it out for determinism.
	rngMu sync.Mutex
	rng   *rand.Rand

	// Worker bookkeeping.
	wg     sync.WaitGroup
	cancel context.CancelFunc

	clock func() time.Time

	// idleMaxSleep caps the amount of time a worker sleeps when the
	// queue is empty AND nothing has been tickled. We still want to
	// re-poll occasionally as a safety net against stuck timers /
	// missed wake-ups; defaults to 1 hour. Tests set this to a
	// small value so an empty-queue sleep doesn't dominate the
	// test runtime.
	idleMaxSleep time.Duration

	// firstAttemptGrace is how far into the future a freshly-committed row's
	// next_attempt_at is set, so the background worker does not claim it while
	// the request goroutine is still performing its synchronous first attempt
	// (which would double-publish). It must exceed a single attempt's wall time
	// (RequestTimeout); it only bounds how long the worker waits to recover a
	// row whose committing process crashed mid-attempt.
	firstAttemptGrace time.Duration
}

// metadataControllerOptions is constructor input.
type metadataControllerOptions struct {
	OriginEnabled  bool
	OriginEndpoint string
	OriginMode     PublishMode
	Exports        []server_utils.OriginExport

	RequestTimeout time.Duration
	TokenLifetime  time.Duration
	MinBackoff     time.Duration
	MaxBackoff     time.Duration
	MaxInflight    int
	RatePerSecond  int
	WarnAfter      time.Duration
	ErrorAfter     time.Duration

	// FilesystemForExists, when set, lets the controller check for a
	// committed object's existence before retrying. Optional — when
	// nil, retries unconditionally re-attempt the publish.
	FilesystemForExists func(namespace string) webdav.FileSystem

	// DB lets tests inject a sqlite handle.
	DB *gorm.DB

	// Batcher, when non-nil, routes publish-queue inserts through
	// the shared write-behind batcher so concurrent commits coalesce
	// into one transaction. nil → direct synchronous INSERT
	// (preserved as the test-friendly default).
	Batcher *sqliteBatcher
}

// newMetadataController constructs the controller but does not start
// the worker pool. Call Start(ctx) to kick the workers off.
func newMetadataController(opts metadataControllerOptions) *metadataController {
	if !opts.OriginMode.IsValid() {
		opts.OriginMode = ModeEventual
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 10 * time.Second
	}
	if opts.TokenLifetime <= 0 {
		opts.TokenLifetime = 5 * time.Minute
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = 30 * time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 30 * time.Minute
	}
	if opts.MaxInflight <= 0 {
		opts.MaxInflight = 4
	}
	if opts.RatePerSecond <= 0 {
		opts.RatePerSecond = 10
	}
	if opts.WarnAfter <= 0 {
		opts.WarnAfter = 4 * time.Hour
	}
	if opts.ErrorAfter <= 0 {
		opts.ErrorAfter = 24 * time.Hour
	}

	c := &metadataController{
		publisher: newPublisher(opts.RequestTimeout, opts.TokenLifetime),
		queue: func() *publishQueue {
			q := newPublishQueue(opts.DB)
			q.setBatcher(opts.Batcher)
			return q
		}(),
		resolver:      newMetadataResolver(opts.OriginEnabled, opts.OriginEndpoint, opts.OriginMode, opts.Exports),
		maxInflight:   opts.MaxInflight,
		ratePerSecond: opts.RatePerSecond,
		minBackoff:    opts.MinBackoff,
		maxBackoff:    opts.MaxBackoff,
		warnAfter:     opts.WarnAfter,
		errorAfter:    opts.ErrorAfter,
		// rate.NewLimiter(r, b): r tokens per second, burst b. Burst
		// equals MaxInflight so every worker can start immediately
		// when the queue is fresh, then settles to the configured
		// long-run rate. Token acquisition happens inside Attempt.
		limiter:      rate.NewLimiter(rate.Limit(opts.RatePerSecond), opts.MaxInflight),
		tickle:       make(chan struct{}, 1),
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
		clock:        time.Now,
		idleMaxSleep: time.Hour,
		// Grace comfortably exceeds one attempt's wall time so the worker never
		// races the synchronous first attempt.
		firstAttemptGrace: opts.RequestTimeout + 15*time.Second,
	}

	if opts.FilesystemForExists != nil {
		c.objectExists = func(ctx context.Context, ns, op string) bool {
			fs := opts.FilesystemForExists(ns)
			if fs == nil {
				return true
			}
			// The queue stores object paths federation-rooted (the wire
			// contract), but the per-export FileSystem operates in the
			// export-relative path space the webdav.Handler hands to
			// OpenFile after stripping its Prefix. Convert back before
			// Stat'ing, otherwise every existence check misses and the
			// worker drops every row as "object deleted".
			_, err := fs.Stat(ctx, exportRelativePath(ns, op))
			return err == nil
		}
	} else {
		c.objectExists = func(context.Context, string, string) bool { return true }
	}

	return c
}

// Start launches the worker pool + the metrics-refresher goroutine.
func (c *metadataController) Start(ctx context.Context) {
	childCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	for i := 0; i < c.maxInflight; i++ {
		c.wg.Add(1)
		go c.workerLoop(childCtx, i)
	}
	c.wg.Add(1)
	go c.metricsLoop(childCtx)
}

// Stop signals workers to exit and waits for them.
func (c *metadataController) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
}

// CommitEvent is the close-hook entry point. It is called from the
// POSC layer after a successful rename. Returns nil → the close (and
// the client's HTTP request) succeeds; non-nil → the close fails and
// the caller should best-effort roll back the storage commit.
func (c *metadataController) CommitEvent(ctx context.Context, event *ObjectCommitEvent) error {
	enabled, endpoint, mode := c.resolver.Resolve(event.Namespace)
	if !enabled {
		return nil
	}
	if endpoint == "" {
		// Misconfiguration. We refuse to silently swallow the event.
		return fmt.Errorf("metadata: namespace %q has metadata enabled but no endpoint resolved", event.Namespace)
	}

	// Eventual-mode rows carry per-row capability tokens so the uploading
	// client can query / cancel its own publish via unguessable URLs (no
	// separate token needed). Transactional rows never outlive the request, so
	// they get none.
	var tok managementTokens
	if mode == ModeEventual {
		q, m, err := newManagementTokens()
		if err != nil {
			return fmt.Errorf("metadata: generate capability tokens: %w", err)
		}
		tok = managementTokens{Query: q, Manage: m}
	}

	// Enqueue with next_attempt_at pushed out by the grace so the background
	// worker won't claim the row while we perform the synchronous first attempt
	// below (both modes attempt synchronously). On success/reject/transient the
	// synchronous path itself deletes / marks / reschedules the row.
	row, err := c.queue.EnqueueEvent(ctx, event, tok, c.firstAttemptGrace)
	if err != nil {
		return fmt.Errorf("metadata: enqueue: %w", err)
	}
	metadataEventsEnqueuedTotal.WithLabelValues(event.Namespace, string(mode)).Inc()

	if mode == ModeTransactional {
		return c.transactionalAttempt(ctx, row, event, endpoint)
	}
	return c.eventualFirstAttempt(ctx, row, event, endpoint, tok)
}

// attemptPublish acquires a rate token then performs (and records) one publish
// attempt. A rate-token failure only happens on shutdown; it is surfaced as a
// network-class result so callers treat it as a transient failure.
func (c *metadataController) attemptPublish(ctx context.Context, event *ObjectCommitEvent, endpoint string, mode PublishMode) publishResult {
	if err := c.acquireRateToken(ctx); err != nil {
		return publishResult{outcome: outcomeNetwork, err: fmt.Errorf("metadata publish cancelled: %w", err)}
	}
	startWall := c.clock()
	res := c.publisher.Attempt(ctx, endpoint, event)
	c.recordAttempt(event.Namespace, mode, res, c.clock().Sub(startWall))
	return res
}

// eventualFirstAttempt makes the initial publish attempt synchronously on the
// request goroutine so the uploading client learns the outcome on the PUT
// response — but it never fails the upload. Success deletes the row; a
// permanent 422 reject marks it terminal; any transient failure leaves the row
// pending for the background worker. Whenever the row persists (queued or
// rejected) the client is handed capability URLs to query / cancel it.
func (c *metadataController) eventualFirstAttempt(ctx context.Context, row *MetadataPublishRow, event *ObjectCommitEvent, endpoint string, tok managementTokens) error {
	// Skip-if-deleted, same as the worker: if the object vanished between the
	// POSC commit and now, don't publish it — drop the row silently.
	if !c.objectExists(ctx, event.Namespace, event.ObjectPath) {
		if err := c.queue.deleteByID(row.ID); err != nil {
			log.Errorf("metadata: delete row %d for vanished object: %v", row.ID, err)
		}
		metadataSkippedObjectDeleted.WithLabelValues(event.Namespace).Inc()
		return nil
	}
	res := c.attemptPublish(ctx, event, endpoint, ModeEventual)
	switch {
	case res.IsSuccess():
		if err := c.queue.deleteByID(row.ID); err != nil {
			log.Errorf("metadata: delete row %d after eventual first-attempt success: %v", row.ID, err)
		}
		c.reportClientResult(ctx, metadataClientResult{Status: metadataClientPublished})
	case res.IsPermanentReject():
		if err := c.queue.markRejected(row.ID, errString(res.err)); err != nil {
			log.Errorf("metadata: mark row %d rejected: %v", row.ID, err)
		}
		metadataRejectedTotal.WithLabelValues(event.Namespace, string(ModeEventual)).Inc()
		c.reportClientResult(ctx, c.clientResultWithURLs(metadataClientRejected, tok))
	default:
		// Transient failure: keep the row, push out next_attempt_at, and wake a
		// worker to retry. The upload still succeeds.
		c.scheduleRetryFromError(row, res.err)
		c.notifyTickle()
		c.reportClientResult(ctx, c.clientResultWithURLs(metadataClientQueued, tok))
	}
	return nil
}

// notifyTickle wakes one worker without blocking. The channel is
// buffered to size 1, so a flurry of enqueues collapses into a
// single wake-up; whichever worker reads the tickle then drains all
// rows that are due.
func (c *metadataController) notifyTickle() {
	if c.tickle == nil {
		return
	}
	select {
	case c.tickle <- struct{}{}:
	default:
	}
}

// acquireRateToken blocks (until ctx is cancelled) for one token from
// the global publish-rate limiter. Both modes go through this so the
// configured RatePerSecond is a real cross-worker cap rather than an
// approximation. Returns the ctx error on cancellation; nil otherwise.
func (c *metadataController) acquireRateToken(ctx context.Context) error {
	if c.limiter == nil {
		return nil
	}
	return c.limiter.Wait(ctx)
}

// transactionalAttempt makes one publish attempt synchronously. There are no
// retries: the row is removed either way. On success nil is returned (and the
// client is told "published"); on any failure — including a permanent 422
// reject — the error is returned so the caller rolls back the storage commit
// and the client sees a 5xx.
func (c *metadataController) transactionalAttempt(ctx context.Context, row *MetadataPublishRow, event *ObjectCommitEvent, endpoint string) error {
	res := c.attemptPublish(ctx, event, endpoint, ModeTransactional)
	if err := c.queue.deleteByID(row.ID); err != nil {
		log.Errorf("metadata: failed to delete queue row %d after transactional attempt: %v", row.ID, err)
	}
	if res.IsSuccess() {
		c.reportClientResult(ctx, metadataClientResult{Status: metadataClientPublished})
		return nil
	}
	if res.IsPermanentReject() {
		metadataRejectedTotal.WithLabelValues(event.Namespace, string(ModeTransactional)).Inc()
	}
	// Failure (transient or permanent): the caller rolls back the storage
	// commit so the object isn't left committed without metadata.
	if res.err != nil {
		return fmt.Errorf("metadata publish failed: %w", res.err)
	}
	return errors.New("metadata publish failed")
}

// workerLoop is one worker in the eventually-consistent pool.
//
// Scheduling model:
//   - Drain. Claim due rows in a tight loop and process them, one
//     row per claim. The shared rate.Limiter caps cross-worker
//     publish rate.
//   - Sleep smart. When no rows are due, ask the DAO for the
//     earliest scheduled next_attempt_at and sleep until then. If
//     the queue is empty entirely, sleep up to idleMaxSleep.
//   - Wake on tickle. CommitEvent (eventual mode) signals the
//     tickle channel after every successful enqueue, so a freshly-
//     queued row gets attention immediately rather than after the
//     next polling tick.
//   - Wake on cancellation. ctx.Done unblocks any sleep.
//
// In steady state with an empty queue, every worker is parked on a
// select with no CPU cost and no SQL traffic. In a loaded queue,
// workers stream through claim/process at the rate the limiter
// permits. We deliberately re-poll once an hour as a belt-and-
// suspenders safeguard against missed tickles or wall-clock skew.
func (c *metadataController) workerLoop(ctx context.Context, id int) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rows, err := c.queue.claimDue(1, c.maxBackoff)
		if err != nil {
			log.Debugf("metadata: worker %d claim error: %v", id, err)
			// On claim error, fall through to the smart-sleep
			// branch. Backing off with the same logic the empty-
			// queue path uses gives a sane recovery curve when the
			// DB is briefly unavailable.
			c.smartSleep(ctx)
			continue
		}
		if len(rows) > 0 {
			for _, r := range rows {
				c.processOneRow(ctx, r)
			}
			continue
		}

		// No rows currently due — sleep until the soonest scheduled
		// row, the next tickle, or ctx cancellation.
		c.smartSleep(ctx)
	}
}

// smartSleep parks the calling worker until either:
//   - the next pending row's next_attempt_at,
//   - a tickle from CommitEvent (a freshly-enqueued row),
//   - ctx cancellation, or
//   - the idleMaxSleep safety net fires.
//
// Returns immediately if the next-due time is in the past (e.g. a
// row aged into being-due between our claim and this query — the
// worker should retry the claim right away).
func (c *metadataController) smartSleep(ctx context.Context) {
	wait := c.idleMaxSleep
	if wait <= 0 {
		wait = time.Hour
	}
	if next, ok, err := c.queue.NextDueAt(); err == nil && ok {
		untilDue := next.Sub(c.clock())
		if untilDue <= 0 {
			// Already due; let the caller try claimDue immediately.
			return
		}
		if untilDue < wait {
			wait = untilDue
		}
	}
	// Add a tiny jitter so workers staggering their wake-ups don't
	// all hammer the DB on the same tick.
	wait = c.jitter(wait)

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-c.tickle:
	case <-t.C:
	}
}

func (c *metadataController) processOneRow(ctx context.Context, r *MetadataPublishRow) {
	enabled, endpoint, mode := c.resolver.Resolve(r.Namespace)
	if !enabled {
		// The export's metadata config flipped off after the row
		// was enqueued. Drop the row; do not silently keep it
		// around forever.
		_ = c.queue.deleteByID(r.ID)
		return
	}
	if endpoint == "" {
		_ = c.queue.scheduleRetry(r.ID, c.clock().Add(c.maxBackoff), "no endpoint resolved")
		return
	}

	// Skip-if-deleted: avoid chasing ghosts. NOT for object.deleted events —
	// there the object being gone is exactly what we're reporting.
	if r.EventType != ObjectDeletedEventType && !c.objectExists(ctx, r.Namespace, r.ObjectPath) {
		_ = c.queue.deleteByID(r.ID)
		metadataSkippedObjectDeleted.WithLabelValues(r.Namespace).Inc()
		log.Debugf("metadata: row %d dropped (object %s gone)", r.ID, r.ObjectPath)
		return
	}

	event, err := EventFromRow(r)
	if err != nil {
		log.Errorf("metadata: row %d malformed (will retry): %v", r.ID, err)
		c.scheduleRetryFromError(r, err)
		return
	}
	if err := c.acquireRateToken(ctx); err != nil {
		// Worker pool is shutting down; leave the row scheduled
		// where it is. We do NOT bump attempts because the failure
		// was on our side, not the receiver's.
		return
	}
	startWall := c.clock()
	res := c.publisher.Attempt(ctx, endpoint, event)
	c.recordAttempt(r.Namespace, mode, res, c.clock().Sub(startWall))
	switch {
	case res.IsSuccess():
		if err := c.queue.deleteByID(r.ID); err != nil {
			log.Errorf("metadata: failed to delete row %d after success: %v", r.ID, err)
		}
	case res.IsPermanentReject():
		// Catalog says this event is permanently bad: stop retrying. Mark the
		// row terminal (it lingers for status queries / operator deletion).
		if err := c.queue.markRejected(r.ID, errString(res.err)); err != nil {
			log.Errorf("metadata: failed to mark row %d rejected: %v", r.ID, err)
		}
		metadataRejectedTotal.WithLabelValues(r.Namespace, string(mode)).Inc()
		log.Warnf("metadata: row %d (%s) permanently rejected by catalog; no further retries", r.ID, r.ObjectPath)
	default:
		c.scheduleRetryFromError(r, res.err)
	}
}

// scheduleRetryFromError computes the next attempt time using
// exponential backoff with full jitter and pushes the row forward.
func (c *metadataController) scheduleRetryFromError(r *MetadataPublishRow, err error) {
	delay := c.computeBackoff(r.Attempts + 1)
	next := c.clock().Add(delay)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if updErr := c.queue.scheduleRetry(r.ID, next, msg); updErr != nil {
		log.Errorf("metadata: failed to scheduleRetry on row %d: %v", r.ID, updErr)
	}
}

func (c *metadataController) computeBackoff(attempts int) time.Duration {
	// Exponential up to MaxBackoff then full-jitter.
	d := c.minBackoff
	for i := 1; i < attempts && d < c.maxBackoff; i++ {
		d *= 2
	}
	if d > c.maxBackoff {
		d = c.maxBackoff
	}
	c.rngMu.Lock()
	jittered := time.Duration(c.rng.Int63n(int64(d) + 1))
	c.rngMu.Unlock()
	if jittered < c.minBackoff {
		jittered = c.minBackoff
	}
	return jittered
}

func (c *metadataController) jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 100 * time.Millisecond
	}
	c.rngMu.Lock()
	add := time.Duration(c.rng.Int63n(int64(base) + 1))
	c.rngMu.Unlock()
	return base + add/2
}

func (c *metadataController) recordAttempt(namespace string, mode PublishMode, res publishResult, elapsed time.Duration) {
	metadataPublishAttemptsTotal.WithLabelValues(namespace, string(mode), string(res.outcome)).Inc()
	metadataPublishLatency.WithLabelValues(namespace, string(mode)).Observe(elapsed.Seconds())
}

// metricsLoop refreshes queue-depth, oldest-pending, and health gauges
// every few seconds. We do this from a single goroutine so updates
// are atomic w.r.t. each other.
func (c *metadataController) metricsLoop(ctx context.Context) {
	defer c.wg.Done()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()

	c.refreshHealthMetrics()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.refreshHealthMetrics()
		}
	}
}

// refreshHealthMetrics recomputes per-namespace queue depth + oldest
// age, and the origin-wide health gauge.
func (c *metadataController) refreshHealthMetrics() {
	stats, err := c.queue.QueueStats()
	if err != nil {
		log.Debugf("metadata: queue-stats refresh failed: %v", err)
		return
	}
	// Reset per-namespace gauges before re-populating so namespaces
	// that drained back to zero don't keep stale values.
	metadataQueueDepth.Reset()
	metadataOldestPendingSeconds.Reset()
	for ns, count := range stats.PerNamespace {
		metadataQueueDepth.WithLabelValues(ns).Set(float64(count))
	}
	for ns, oldest := range stats.PerNamespaceOld {
		age := c.clock().Sub(oldest).Seconds()
		if age < 0 {
			age = 0
		}
		metadataOldestPendingSeconds.WithLabelValues(ns).Set(age)
	}

	state := computeHealthState(stats.OldestCreatedAt, c.clock(), c.warnAfter, c.errorAfter)
	for _, s := range []string{"healthy", "warning", "error"} {
		v := 0.0
		if s == state {
			v = 1.0
		}
		metadataHealth.WithLabelValues(s).Set(v)
	}
}

// computeHealthState maps "age of oldest pending row" to a state. Pure
// function so tests can exercise it directly.
func computeHealthState(oldest *time.Time, now time.Time, warn, errAfter time.Duration) string {
	if oldest == nil {
		return "healthy"
	}
	age := now.Sub(*oldest)
	if age >= errAfter {
		return "error"
	}
	if age >= warn {
		return "warning"
	}
	return "healthy"
}

// CommitEventFromCloseHook returns a closure suitable for use as the
// POSC layer's close hook. Each export gets its own closure (built
// with its own federation prefix); custom uploader fields are pulled
// from the request context (set by the request middleware).
//
// The `finalPath` passed in by the POSC layer is *export-relative*
// (the webdav.Handler strips its Prefix before calling OpenFile). The
// webhook contract is that `object.path` is the federation-rooted
// path, so we re-prepend the namespace here.
//
// The ETag is obtained from the FileInfo via BackendETag (see
// backend_etag.go); the controller deliberately holds no opinion
// about how an ETag is computed.
func (c *metadataController) CommitEventFromCloseHook(namespace string) func(ctx context.Context, finalPath string, info os.FileInfo) error {
	return func(ctx context.Context, finalPath string, info os.FileInfo) error {
		// Publish-only path (no local tracking DB to consult), so we can't
		// tell a create from an overwrite: always object.committed.
		return c.CommitEvent(ctx, c.buildCommitEvent(ctx, namespace, finalPath, info, ObjectCommitEventType))
	}
}

// CommitEventFromCloseHookTracked is the close hook to use when the local
// object-metadata tracking DB is also enabled. It probes that DB *before* the
// track hook records the commit to decide create vs overwrite (object.committed
// vs object.updated), runs the track hook (best-effort), then publishes. The
// publish error is what gates the close (transactional rollback), so it runs
// last.
func (c *metadataController) CommitEventFromCloseHookTracked(namespace string, dao *objectMetadataDAO, trackHook closeHookFn) func(ctx context.Context, finalPath string, info os.FileInfo) error {
	return func(ctx context.Context, finalPath string, info os.FileInfo) error {
		fedPath := joinFederationPath(namespace, finalPath)
		// Overwrite iff the tracking DB already has a live row for this path.
		// Per design we consult only the DB, not the object store.
		eventType := ObjectCommitEventType
		if dao != nil {
			if live, err := dao.LookupLive(ctx, namespace, fedPath); err == nil && live != nil {
				eventType = ObjectUpdatedEventType
			}
		}
		event := c.buildCommitEvent(ctx, namespace, finalPath, info, eventType)
		// Record the commit (best-effort) AFTER the overwrite probe so the
		// probe saw pre-commit state; its error is intentionally ignored.
		if trackHook != nil {
			_ = trackHook(ctx, finalPath, info)
		}
		return c.CommitEvent(ctx, event)
	}
}

// buildCommitEvent assembles an ObjectCommitEvent of the given type from the
// close-hook inputs (federation-rooted path, size/mtime/etag from FileInfo,
// custom fields + optional multipart blob from the request context).
func (c *metadataController) buildCommitEvent(ctx context.Context, namespace, finalPath string, info os.FileInfo, eventType string) *ObjectCommitEvent {
	var size int64
	var mtime time.Time
	if info != nil {
		size = info.Size()
		mtime = info.ModTime()
	}
	etag := BackendETag(info)
	custom := objectMetadataFromContext(ctx)
	if custom == nil {
		custom = CustomFields{}
	}
	fullPath := joinFederationPath(namespace, finalPath)
	event := NewObjectCommitEvent(namespace, fullPath, size, etag, mtime, custom)
	event.Type = eventType
	// If the upload was multipart-shaped, the inbound splitter stashed the
	// blob on ctx; pull it through so the publisher switches to
	// multipart/related.
	if blob := multipartBlobFromContext(ctx); blob != nil {
		event.WithMetadataBlob(blob.ContentType, blob.Body)
	}
	return event
}

// PublishStandalone queues an event for asynchronous, best-effort delivery
// (used for object.deleted and out-of-band object.updated). Unlike the commit
// path it never blocks the triggering operation or gates it on the catalog:
// the data change already happened and cannot be rolled back. A background
// worker performs the attempt(s), honoring 422 permanent-reject. No-op when
// publishing is disabled for the namespace.
func (c *metadataController) PublishStandalone(ctx context.Context, event *ObjectCommitEvent) {
	enabled, endpoint, mode := c.resolver.Resolve(event.Namespace)
	if !enabled || endpoint == "" {
		return
	}
	if _, err := c.queue.EnqueueEvent(ctx, event, managementTokens{}, 0); err != nil {
		log.Errorf("metadata: enqueue %s for %s: %v", event.Type, event.ObjectPath, err)
		return
	}
	metadataEventsEnqueuedTotal.WithLabelValues(event.Namespace, string(mode)).Inc()
	c.notifyTickle()
}

// PublishDeleteHook returns a callback the filesystem / observation layer fires
// after an object is removed, to publish an object.deleted event.
func (c *metadataController) PublishDeleteHook(namespace string) func(ctx context.Context, fedPath string) {
	return func(ctx context.Context, fedPath string) {
		c.PublishStandalone(ctx, NewObjectDeletedEvent(namespace, fedPath))
	}
}

// PublishUpdateHook returns a callback the observation layer fires when it
// detects an out-of-band modification, to publish an object.updated event.
func (c *metadataController) PublishUpdateHook(namespace string) func(ctx context.Context, fedPath string, size int64, etag string, mtime time.Time) {
	return func(ctx context.Context, fedPath string, size int64, etag string, mtime time.Time) {
		c.PublishStandalone(ctx, NewObjectUpdatedEvent(namespace, fedPath, size, etag, mtime, nil))
	}
}

// joinFederationPath produces a federation-rooted path from a namespace
// (eg "/exp") and an export-relative path (eg "/data/x.bin") yielded by
// the webdav.Handler after Prefix-stripping. It's an exposed helper so
// tests can lock down the contract.
//
// The close-hook contract guarantees an *export-relative* input (the webdav
// handler always strips its Prefix before OpenFile), so we unconditionally
// join namespace + exportRelative. We deliberately do NOT try to detect an
// "already federation-rooted" input: a legitimate object whose first path
// component happens to match the namespace's trailing segment (e.g. a
// client-created subdir named "exp" under namespace "/exp", giving
// export-relative "/exp/data/x.bin") must map to "/exp/exp/data/x.bin", not
// be misclassified and collapsed to "/exp/data/x.bin".
func joinFederationPath(namespace, exportRelative string) string {
	ns := strings.TrimRight(namespace, "/")
	rel := strings.TrimLeft(exportRelative, "/")
	if ns == "" || ns == "/" {
		return path.Clean("/" + rel)
	}
	if rel == "" {
		return ns
	}
	return path.Clean(ns + "/" + rel)
}

// exportRelativePath is the inverse of joinFederationPath: it converts a
// federation-rooted object path (as stored in the publish queue and sent
// on the wire) back into the export-relative path space the origin's
// per-export FileSystem uses. The webdav.Handler strips its federation
// Prefix before calling OpenFile, so the FileSystem — and the
// skip-if-deleted Stat that reuses it — never sees the namespace segment.
func exportRelativePath(namespace, fedPath string) string {
	ns := strings.TrimRight(namespace, "/")
	if ns == "" || ns == "/" {
		return path.Clean("/" + strings.TrimLeft(fedPath, "/"))
	}
	rooted := "/" + strings.TrimLeft(fedPath, "/")
	if rooted == ns {
		return "/"
	}
	if rel := strings.TrimPrefix(rooted, ns+"/"); rel != rooted {
		return path.Clean("/" + rel)
	}
	// fedPath wasn't actually under the namespace; treat it as already
	// export-relative rather than silently corrupting it.
	return path.Clean(rooted)
}

// http.Header carries the X-Pelican-Object-Metadata header from the
// original PUT request through to OpenFile via the request context.
// We use a private context key.
type pelicanObjectMetadataKey struct{}

// expectedContentLengthKey carries the request's Content-Length (when
// the client supplied one) through to the POSC close path so it can
// verify the staged file size before renaming. -1 / absent ⇒ no check.
type expectedContentLengthKey struct{}

// withExpectedContentLength stashes a positive content length on the
// context. Negative or zero values are ignored.
func withExpectedContentLength(ctx context.Context, n int64) context.Context {
	if n <= 0 {
		return ctx
	}
	return context.WithValue(ctx, expectedContentLengthKey{}, n)
}

// expectedContentLengthFromContext returns the stashed length or -1.
func expectedContentLengthFromContext(ctx context.Context) int64 {
	if v, ok := ctx.Value(expectedContentLengthKey{}).(int64); ok {
		return v
	}
	return -1
}

// clearExpectedContentLength overrides any previously-stashed expected size
// with a sentinel that disables the POSC size check. The upload middleware
// stashes the request's Content-Length before it knows the body is
// multipart/form-data; once the multipart rewrite runs, that length covers
// the whole multipart envelope, not the object part, so the check must be
// dropped (per the design: "the per-part length is not known from the request
// header alone").
func clearExpectedContentLength(ctx context.Context) context.Context {
	return context.WithValue(ctx, expectedContentLengthKey{}, int64(-1))
}

// withObjectMetadata stores parsed custom fields on the context.
func withObjectMetadata(ctx context.Context, custom CustomFields) context.Context {
	return context.WithValue(ctx, pelicanObjectMetadataKey{}, custom)
}

// objectMetadataFromContext retrieves parsed custom fields, or nil if
// the header was absent / malformed.
func objectMetadataFromContext(ctx context.Context) CustomFields {
	v, _ := ctx.Value(pelicanObjectMetadataKey{}).(CustomFields)
	return v
}

// sourceEtagKey carries a remote source's ETag through OpenFile so
// the close hook can persist it alongside the commit row. Populated
// by the TPC handler after the source GET returns its ETag.
type sourceEtagKey struct{}

// withSourceEtag stashes a non-empty source ETag on the context.
// Empty values are ignored so a caller can pipe getResp.Header.Get()
// through unconditionally.
func withSourceEtag(ctx context.Context, etag string) context.Context {
	if etag == "" {
		return ctx
	}
	return context.WithValue(ctx, sourceEtagKey{}, etag)
}

// sourceEtagFromContext returns the stashed source ETag, or "".
func sourceEtagFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sourceEtagKey{}).(string); ok {
		return v
	}
	return ""
}

// --- client result reporting (eventual mode) ---

// Response headers the origin sets on a PUT so the uploading client learns the
// initial publish outcome and (when the row persists) its capability URLs.
const (
	MetadataStatusHeader    = "X-Pelican-Metadata-Status"
	MetadataQueryURLHeader  = "X-Pelican-Metadata-Query-Url"
	MetadataManageURLHeader = "X-Pelican-Metadata-Manage-Url"
)

// Values for the X-Pelican-Metadata-Status header.
const (
	metadataClientPublished = "published" // delivered and accepted on the first attempt
	metadataClientQueued    = "queued"    // first attempt failed transiently; a worker will retry
	metadataClientRejected  = "rejected"  // catalog permanently refused (422); no retries
)

// metadataClientResult is what the origin reports back to the uploading client.
type metadataClientResult struct {
	Status    string
	QueryURL  string
	ManageURL string
}

// responseHeaderKey carries the PUT response's header map so the close hook can
// stamp the X-Pelican-Metadata-* result headers on it (the deferred-header
// writer flushes them after the webdav handler returns).
type responseHeaderKey struct{}

// withResponseHeader stashes the response header map on the context.
func withResponseHeader(ctx context.Context, h http.Header) context.Context {
	if h == nil {
		return ctx
	}
	return context.WithValue(ctx, responseHeaderKey{}, h)
}

// responseHeaderFromContext returns the stashed response header map, or nil
// (e.g. TPC / non-PUT paths that never plumbed one through).
func responseHeaderFromContext(ctx context.Context) http.Header {
	if v, ok := ctx.Value(responseHeaderKey{}).(http.Header); ok {
		return v
	}
	return nil
}

// reportClientResult writes the result headers onto the request's response
// header map, if one was plumbed through. No-op otherwise.
func (c *metadataController) reportClientResult(ctx context.Context, r metadataClientResult) {
	h := responseHeaderFromContext(ctx)
	if h == nil {
		return
	}
	h.Set(MetadataStatusHeader, r.Status)
	if r.QueryURL != "" {
		h.Set(MetadataQueryURLHeader, r.QueryURL)
	}
	if r.ManageURL != "" {
		h.Set(MetadataManageURLHeader, r.ManageURL)
	}
}

// clientResultWithURLs builds a result carrying the capability URLs derived
// from the row's tokens.
func (c *metadataController) clientResultWithURLs(status string, tok managementTokens) metadataClientResult {
	return metadataClientResult{
		Status:    status,
		QueryURL:  metadataStatusURL(tok.Query),
		ManageURL: metadataStatusURL(tok.Manage),
	}
}

// errString is err.Error() or "" for a nil error.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// extractObjectMetadataFromRequest parses the X-Pelican-Object-Metadata
// header off `r` and stores the resulting map on the returned request's
// context. Also stashes the request's declared Content-Length (for PUTs)
// so the POSC close path can verify the staged file's size before
// renaming. Used by the upload middleware.
func extractObjectMetadataFromRequest(r *http.Request) *http.Request {
	ctx := r.Context()
	if hdr := r.Header.Get(ObjectMetadataHeader); hdr != "" {
		parsed, err := ParseObjectMetadataHeader(hdr)
		if err != nil {
			// Accept the request but log; reserved-key collisions
			// or malformed values should not block uploads.
			log.Debugf("metadata: header parse warning: %v", err)
		}
		ctx = withObjectMetadata(ctx, parsed)
	}
	if r.Method == http.MethodPut && r.ContentLength > 0 {
		ctx = withExpectedContentLength(ctx, r.ContentLength)
	}
	if ctx == r.Context() {
		return r
	}
	return r.WithContext(ctx)
}
