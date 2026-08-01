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

package client

import (
	"container/list"
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// ErrTooManyRequests is returned by TagScheduler.Submit when the scheduler
// refuses admission because the tag (typically an upstream origin) is
// already at its share of the transfer engine's worker pool. It mirrors
// HTTP 429.
//
// Every rejection wraps this sentinel (see SchedulerRejection), so callers can
// continue to use errors.Is(err, ErrTooManyRequests) to detect a shed while
// errors.As(err, &SchedulerRejection{}) recovers the specific reason.
var ErrTooManyRequests = errors.New("too many requests: origin is over its share of the transfer pool")

// ShedReason categorizes why the scheduler refused admission. The reason is
// derived at the moment of shedding from the tag's in-flight composition and
// the global pending buffer state, and is carried out to the cache's HTTP
// layer so the client can be told whether the upstream origin is unresponsive,
// merely slow, or the cache as a whole is saturated.
type ShedReason string

const (
	// ShedOriginUnresponsive: the tag's held worker slots are dominated by
	// "starving" fetches (accepted the connection but produced no first byte).
	// The origin looks unresponsive.
	ShedOriginUnresponsive ShedReason = "origin_unresponsive"
	// ShedOriginSlow: the tag is at its active-transfer cap — the origin is
	// delivering data but already holds its fair share of the pool.
	ShedOriginSlow ShedReason = "origin_slow"
	// ShedCacheOverloaded: the global pending buffer is full — the cache is
	// saturated across all origins, not just this one.
	ShedCacheOverloaded ShedReason = "cache_overloaded"
)

// SchedulerRejection is the error returned when the scheduler sheds a
// submission. It wraps ErrTooManyRequests (so errors.Is still matches) and
// carries the categorized reason plus the tag (upstream origin host) so the
// downstream HTTP layer can build a structured 429.
type SchedulerRejection struct {
	Reason ShedReason
	Tag    string
	msg    string
}

func (e *SchedulerRejection) Error() string {
	if e.msg != "" {
		return e.msg
	}
	if e.Tag != "" {
		return fmt.Sprintf("%s: %s (%s)", ErrTooManyRequests.Error(), e.Tag, e.Reason)
	}
	return ErrTooManyRequests.Error()
}

// Unwrap returns the typed, retryable Pelican error for this rejection's
// reason, which in turn wraps ErrTooManyRequests. Going through the typed
// error rather than straight to the sentinel is what makes a locally-shed
// transfer retryable under IsRetryable, matching how the same shed is
// classified when it is observed remotely as a 429 (CacheThrottleError).
// errors.Is(err, ErrTooManyRequests) still holds, one link further down.
func (e *SchedulerRejection) Unwrap() error {
	return throttleErrorForReason(string(e.Reason), ErrTooManyRequests)
}

// PerTagStats is a per-origin snapshot of scheduler state, intended for
// monitoring / debugging. Values are consistent (all taken under one
// lock) but stale as soon as they're read.
type PerTagStats struct {
	// Pending, Active, Starving are the current counts at snapshot time.
	Pending  int
	Active   int
	Starving int
	// EMA is the exponentially-weighted moving average of Active over
	// the configured EMAWindow. Used as the weight input for the
	// per-tag round-robin dispatch decision.
	EMA float64
	// Admits and Rejects count admissions/rejections for this tag since
	// the tag was first seen — or since it was last evicted: a tag idle
	// long enough is dropped entirely (see evictIdleTags), and starts
	// from zero if it returns. Lifetime totals live in GlobalStats.
	Admits  uint64
	Rejects uint64
}

// GlobalStats is the pool-wide scheduler snapshot. The Total* counters
// are monotonic for the scheduler's lifetime (unlike PerTagStats, whose
// counters reset when an idle tag is evicted).
type GlobalStats struct {
	WorkerCount        int
	StarvingCap        int
	ActiveCap          int
	TotalPending       int
	TotalTags          int
	TotalAdmits        uint64
	TotalRejects       uint64
	TotalRejectsGlobal uint64 // subset of TotalRejects: rejected because global pending was full
	TotalRejectsPerTag uint64 // subset of TotalRejects: rejected because per-tag pending was full
}

// SchedulerSnapshot is a full snapshot of scheduler state.
type SchedulerSnapshot struct {
	Global GlobalStats
	Tags   map[string]PerTagStats
}

// SchedulerConfig configures a TagScheduler. Zero-values disable the
// corresponding limit.
type SchedulerConfig struct {
	// PerTagStarvingPercent — upper bound (percentage of worker pool) on
	// how many workers a single tag may hold while its transfers have
	// not yet produced a first byte of data. 0 or ≥100 disables.
	PerTagStarvingPercent int
	// PerTagActivePercent — upper bound (percentage of worker pool) on
	// how many workers a single tag may hold in total (starving +
	// actively-transferring). 0 or ≥100 disables.
	PerTagActivePercent int
	// PendingBufferSize — total number of pending transfers the
	// scheduler will queue across all tags before shedding new admits
	// with ErrTooManyRequests. 0 disables the cap (unbounded queue).
	//
	// Note that the cache-level knob of the same name,
	// Cache.Throttle.PendingBufferSize, reads 0 as "do not build a
	// scheduler at all" -- it never reaches this field. The two zeroes
	// mean opposite things because they act at different layers: here
	// there is a scheduler and its queue is unbounded; there, there is no
	// scheduler.
	PendingBufferSize int
	// PerTagPendingSize — number of pending transfers the scheduler
	// will queue for any single tag before rejecting new admits with
	// ErrTooManyRequests. 0 disables the per-tag cap.
	PerTagPendingSize int
	// EMAWindow — time constant of the per-tag active-worker EMA used
	// to weight the round-robin. Shorter = more reactive, longer =
	// smoother. 0 disables EMA updates (all eligible tags get equal
	// weight).
	EMAWindow time.Duration
}

const (
	// emaFloor is the value below which a decaying EMA is treated as zero.
	// The decay is asymptotic, so without a floor an idle tag would never
	// satisfy the "no residual EMA" precondition for eviction.
	emaFloor = 1e-6
	// minEvictionGrace is the lower bound on how long a tag must be idle
	// before its state is dropped (see evictIdleTags).
	minEvictionGrace = 10 * time.Second
)

// tagState is the complete scheduler state for one tag. Holding it in a
// single struct rather than a set of parallel maps keeps a tag's queue,
// counters, and bookkeeping created, updated, and evicted together, and
// lets a snapshot be built with one map iteration.
//
// Owned by the scheduler goroutine; no field may be touched from outside.
type tagState struct {
	fifo     *list.List // FIFO of *clientTransferFile awaiting dispatch; never nil
	active   int        // in-flight transfers (any state)
	starving int        // in-flight transfers without a first byte yet
	ema      float64    // EMA of active over the configured EMAWindow
	weight   float64    // dispatch weight, 1/(1+ema); refreshed once per tick
	admits   uint64     // admissions since the tag was last evicted
	rejects  uint64     // rejections since the tag was last evicted
	lastSeen time.Time  // last admit/reject/dispatch/event, for idle eviction
}

// dispatchCandidate is one entry in the weighted draw performed by
// pickForDispatch. The backing slice is reused across dispatches.
type dispatchCandidate struct {
	st *tagState
	w  float64
}

// TagScheduler admits transfers into a bounded per-tag FIFO and dispatches
// them to workers with a weighted random draw across tags. It exists to
// keep one misbehaving origin from monopolising the transfer engine's
// worker pool.
type TagScheduler struct {
	cfg         SchedulerConfig
	workerCount int

	// onDrop, when set, is invoked (on the scheduler goroutine, during
	// shutdown) for every admitted-but-never-dispatched transfer so the
	// owner can synthesize a failure result instead of silently losing
	// the file. Must be set before Start.
	onDrop func(*clientTransferFile)

	// Communication channels. Every field below the channels is owned
	// by the scheduler goroutine and MUST NOT be touched from outside.
	admit    chan *admitReq
	events   chan schedulerEvent
	snapReqs chan chan<- SchedulerSnapshot
	stop     chan struct{}
	stopOnce sync.Once
	started  atomic.Bool
	stopped  chan struct{}
	out      chan<- *clientTransferFile
	rng      *rand.Rand

	// tags holds all per-tag state. Entries are created on first contact
	// and removed only by evictIdleTags, so the map cannot grow without
	// bound as origins come and go.
	tags     map[string]*tagState
	cands    []dispatchCandidate // scratch space for pickForDispatch
	lastTick time.Time
	pending  int

	// Global monotonic counters. Unlike the per-tag state these are never
	// reset: idle tags are evicted from the map (see evictIdleTags) so
	// per-tag totals cannot serve as lifetime counters.
	totalAdmits        uint64
	totalRejectsGlobal uint64 // rejected because global pending was full
	totalRejectsPerTag uint64 // rejected because per-tag pending was full
}

// Sentinel event kinds for use over the events channel.
type schedulerEventKind int

const (
	evFirstByte schedulerEventKind = iota
	evDone
)

type schedulerEvent struct {
	kind          schedulerEventKind
	tag           string
	stillStarving bool // used by evDone
}

type admitReq struct {
	tag   string
	file  *clientTransferFile
	reply chan error
}

// NewTagScheduler builds a scheduler for a pool of `workerCount` workers.
// Call Start to run its goroutine.
func NewTagScheduler(workerCount int, cfg SchedulerConfig) *TagScheduler {
	if workerCount < 1 {
		workerCount = 1
	}
	// Each in-flight transfer produces at most two events (first-byte and
	// done), so sizing the buffer to 2× the worker pool (with a floor)
	// guarantees the hooks fired from transfer workers never block on a
	// busy scheduler goroutine.
	eventBuf := 2 * workerCount
	if eventBuf < 256 {
		eventBuf = 256
	}
	return &TagScheduler{
		cfg:         cfg,
		workerCount: workerCount,
		admit:       make(chan *admitReq),
		events:      make(chan schedulerEvent, eventBuf),
		snapReqs:    make(chan chan<- SchedulerSnapshot),
		stop:        make(chan struct{}),
		stopped:     make(chan struct{}),
		// The math/rand/v2 top-level generator is automatically seeded, so
		// it can seed this scheduler's private generator. Kept private (and
		// as a field) so dispatch draws neither contend on the global
		// generator nor resist deterministic seeding in tests.
		rng:  rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
		tags: make(map[string]*tagState),
	}
}

// tagFor returns the state for `tag`, creating it on first contact. Must
// be called on the scheduler goroutine.
func (s *TagScheduler) tagFor(tag string) *tagState {
	if st, ok := s.tags[tag]; ok {
		return st
	}
	// A new tag has an EMA of zero, whose dispatch weight is 1/(1+0); seed
	// it so a tag admitted between two ticks competes on equal footing
	// before its first weight refresh.
	st := &tagState{fifo: list.New(), weight: 1.0}
	s.tags[tag] = st
	return st
}

// Start begins the scheduler goroutine under `egrp`, dispatching admitted
// transfers on the out channel. Stop() blocks until the goroutine exits.
// Start may be called at most once per scheduler; a second call panics
// (programming error, not a runtime condition).
//
// The goroutine never returns an error: a scheduler shutdown is not a
// failure of the group it runs in.
func (s *TagScheduler) Start(ctx context.Context, egrp *errgroup.Group, out chan<- *clientTransferFile) {
	if !s.started.CompareAndSwap(false, true) {
		panic("TagScheduler.Start called more than once")
	}
	s.out = out
	egrp.Go(func() error {
		s.run(ctx)
		return nil
	})
}

// Stop signals the scheduler to exit and waits for the goroutine. It is
// safe to call multiple times, including concurrently, and safe to call
// on a scheduler that was never started.
func (s *TagScheduler) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
	if s.started.Load() {
		<-s.stopped
	}
}

// Submit asks the scheduler to admit `file`, tagged with `tag`. Returns
// nil on accept (the transfer will be dispatched when a worker is free
// and the tag is under its caps), ErrTooManyRequests on rejection.
//
// Submit attaches hooks to file.file so the workers can signal
// first-byte and completion back to the scheduler.
func (s *TagScheduler) Submit(ctx context.Context, tag string, file *clientTransferFile) error {
	s.attachHooks(tag, file)

	reply := make(chan error, 1)
	req := &admitReq{tag: tag, file: file, reply: reply}
	select {
	case s.admit <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stop:
		// Shutting down: shed with a SchedulerRejection so the caller takes
		// the same synthesize-a-result path as any other shed and the
		// remote client gets a retryable 429 rather than a silent drop.
		return &SchedulerRejection{
			Reason: ShedCacheOverloaded,
			Tag:    tag,
			msg:    fmt.Sprintf("%s: transfer scheduler is shutting down", ErrTooManyRequests.Error()),
		}
	}
	// Once the admit request has been received, handleAdmit always writes
	// the (buffered) reply before the scheduler goroutine does anything
	// else, so this receive cannot block for long and must not be raced
	// against ctx: abandoning the reply would leave an admitted file in
	// the FIFO while telling the caller it was never submitted.
	return <-reply
}

func (s *TagScheduler) attachHooks(tag string, file *clientTransferFile) {
	var firstByteFired atomic.Bool
	file.file.schedFirstByte = func() {
		if firstByteFired.CompareAndSwap(false, true) {
			s.sendEvent(schedulerEvent{kind: evFirstByte, tag: tag})
		}
	}
	file.file.schedDone = func() {
		// CompareAndSwap, not Load: completion and the first-byte signal are
		// not mutually exclusive. An upload can abandon the transfer (stopped-
		// transfer timeout, error on the side channel) while the transport is
		// still running, and the transport may then report 100-continue, a
		// first response byte, or having drained enough request body. Claiming
		// the flag here means that later signal is a no-op instead of a second
		// starving decrement, which would release some other in-flight
		// transfer's slot.
		stillStarving := firstByteFired.CompareAndSwap(false, true)
		s.sendEvent(schedulerEvent{kind: evDone, tag: tag, stillStarving: stillStarving})
	}
}

func (s *TagScheduler) sendEvent(ev schedulerEvent) {
	select {
	case s.events <- ev:
	case <-s.stop:
	}
}

// starvingCap and activeCap convert the configured percentages into absolute
// slot counts. Both round up, so a small pool cannot produce a cap of zero
// and wedge the tag entirely: workerCount is at least 1 (the constructor
// clamps it) and pct is at least 1 here, so the result is at least 1.
func (s *TagScheduler) starvingCap() int {
	pct := s.cfg.PerTagStarvingPercent
	if pct <= 0 || pct >= 100 {
		return s.workerCount
	}
	return (s.workerCount*pct + 99) / 100
}

func (s *TagScheduler) activeCap() int {
	pct := s.cfg.PerTagActivePercent
	if pct <= 0 || pct >= 100 {
		return s.workerCount
	}
	return (s.workerCount*pct + 99) / 100
}

// run is the scheduler goroutine. It multiplexes admissions, first-byte
// / done events, and dispatch attempts, and periodically ticks the EMA.
func (s *TagScheduler) run(ctx context.Context) {
	defer close(s.stopped)
	// Everything that waits on the scheduler — Submit, Snapshot, sendEvent —
	// uses s.stop as its escape hatch, so it has to be closed however run()
	// exits, not just when Stop() is the thing that ended it. Without this a
	// ctx-driven exit would leave those waiters relying on a later Stop() call
	// to release them.
	defer s.stopOnce.Do(func() { close(s.stop) })
	// On exit, hand every admitted-but-undispatched transfer to onDrop so
	// its job still observes a completion (otherwise the owning job's
	// active-transfer count never drains and its results channel never
	// closes). Registered after the close(s.stopped) defer so it runs
	// first, i.e. Stop() does not return until the drain is complete.
	defer func() {
		for _, st := range s.tags {
			for e := st.fifo.Front(); e != nil; e = e.Next() {
				if s.onDrop != nil {
					s.onDrop(e.Value.(*clientTransferFile))
				}
			}
			st.fifo.Init()
		}
		s.pending = 0
	}()

	tickInterval := s.cfg.EMAWindow / 8
	if tickInterval < 250*time.Millisecond {
		tickInterval = 250 * time.Millisecond
	}
	tick := time.NewTicker(tickInterval)
	defer tick.Stop()
	s.lastTick = time.Now()

	for {
		// If we have a candidate to dispatch AND caps allow, try to
		// hand it off to a worker while still servicing other events.
		if st, ok := s.pickForDispatch(); ok {
			head := st.fifo.Front().Value.(*clientTransferFile)
			select {
			case s.out <- head:
				s.onDispatched(st)
			case req := <-s.admit:
				s.handleAdmit(req)
			case ev := <-s.events:
				s.handleEvent(ev)
			case reply := <-s.snapReqs:
				reply <- s.buildSnapshot()
			case <-tick.C:
				s.onTick()
			case <-s.stop:
				return
			case <-ctx.Done():
				return
			}
		} else {
			select {
			case req := <-s.admit:
				s.handleAdmit(req)
			case ev := <-s.events:
				s.handleEvent(ev)
			case reply := <-s.snapReqs:
				reply <- s.buildSnapshot()
			case <-tick.C:
				s.onTick()
			case <-s.stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

// onTick advances the EMA and evicts fully-idle tags. Runs on the
// scheduler goroutine at the tick cadence.
func (s *TagScheduler) onTick() {
	s.tickEMA()
	s.evictIdleTags(time.Now())
}

// classifyShed inspects a tag's own in-flight composition to decide why a
// submission for it is being shed. If the tag itself is holding a
// starving-cap worth of first-byte-less fetches, the origin looks
// unresponsive; if it is at its active cap, it is delivering data but
// already holds its fair share (merely slow). If the tag's own counters
// are under both caps, the shed is due to pool-wide contention — blaming
// the origin would be wrong, so report the cache as overloaded.
func (s *TagScheduler) classifyShed(tag string) ShedReason {
	st, ok := s.tags[tag]
	if !ok {
		return ShedCacheOverloaded
	}
	if st.starving >= s.starvingCap() {
		return ShedOriginUnresponsive
	}
	if st.active >= s.activeCap() {
		return ShedOriginSlow
	}
	return ShedCacheOverloaded
}

func (s *TagScheduler) handleAdmit(req *admitReq) {
	st := s.tagFor(req.tag)
	st.lastSeen = time.Now()
	qLen := st.fifo.Len()
	// Per-tag cap is checked before the global one so a rejection is
	// attributed to the tag's own state whenever its own queue is the
	// limit.
	if s.cfg.PerTagPendingSize > 0 && qLen >= s.cfg.PerTagPendingSize {
		st.rejects++
		s.totalRejectsPerTag++
		reason := s.classifyShed(req.tag)
		req.reply <- &SchedulerRejection{
			Reason: reason,
			Tag:    req.tag,
			msg:    fmt.Sprintf("%s: origin %q pending queue is full (%s)", ErrTooManyRequests.Error(), req.tag, reason),
		}
		return
	}
	// Global buffer full. A tag with nothing queued may still enqueue one
	// entry past the global cap: without that reservation, a handful of
	// saturated origins could pin the global buffer and starve every
	// healthy origin out of admission entirely. The overshoot is bounded
	// by one entry per distinct tag.
	if s.cfg.PendingBufferSize > 0 && s.pending >= s.cfg.PendingBufferSize && qLen > 0 {
		st.rejects++
		s.totalRejectsGlobal++
		reason := s.classifyShed(req.tag)
		req.reply <- &SchedulerRejection{
			Reason: reason,
			Tag:    req.tag,
			msg:    fmt.Sprintf("%s: cache pending queue is full (%s)", ErrTooManyRequests.Error(), reason),
		}
		return
	}
	st.fifo.PushBack(req.file)
	s.pending++
	st.admits++
	s.totalAdmits++
	req.reply <- nil
}

func (s *TagScheduler) handleEvent(ev schedulerEvent) {
	st := s.tagFor(ev.tag)
	st.lastSeen = time.Now()
	switch ev.kind {
	case evFirstByte:
		if st.starving > 0 {
			st.starving--
		}
	case evDone:
		if st.active > 0 {
			st.active--
		}
		if ev.stillStarving && st.starving > 0 {
			st.starving--
		}
	}
}

// pickForDispatch selects the next tag whose queue head we'd like to
// hand off to a worker, using a weighted random draw across eligible
// tags (those under both the starving and active caps). Weight is
// 1/(1+EMA) so tags that have used less of the pool recently are more
// likely to be picked; it is refreshed once per tick (see tickEMA)
// because dispatch decisions are far more frequent than ticks. Cap
// eligibility, by contrast, must be evaluated live: the counters move
// with every transfer event. Returns nil, false if nothing is
// dispatchable.
func (s *TagScheduler) pickForDispatch() (*tagState, bool) {
	starvingCap := s.starvingCap()
	activeCap := s.activeCap()

	cands := s.cands[:0]
	totalW := 0.0
	for _, st := range s.tags {
		if st.fifo.Len() == 0 {
			continue
		}
		if st.starving >= starvingCap {
			continue
		}
		if st.active >= activeCap {
			continue
		}
		cands = append(cands, dispatchCandidate{st: st, w: st.weight})
		totalW += st.weight
	}
	// Retain the grown backing array; the scheduler goroutine is the sole
	// user, so it can be reused on the next dispatch decision.
	s.cands = cands
	if len(cands) == 0 {
		return nil, false
	}
	r := s.rng.Float64() * totalW
	for i := range cands {
		r -= cands[i].w
		if r <= 0 {
			return cands[i].st, true
		}
	}
	return cands[len(cands)-1].st, true
}

func (s *TagScheduler) onDispatched(st *tagState) {
	st.fifo.Remove(st.fifo.Front())
	s.pending--
	st.active++
	st.starving++
	st.lastSeen = time.Now()
}

// tickEMA advances the per-tag exponentially-weighted moving average of
// active workers and refreshes the cached dispatch weight derived from
// it. Called at a fixed cadence (roughly EMAWindow/8).
//
// A tag first seen since the last tick starts from an EMA of zero, so the
// same update rule bootstraps it correctly.
func (s *TagScheduler) tickEMA() {
	now := time.Now()
	dt := now.Sub(s.lastTick)
	s.lastTick = now
	if s.cfg.EMAWindow <= 0 || dt <= 0 {
		return
	}
	alpha := 1.0 - math.Exp(-float64(dt)/float64(s.cfg.EMAWindow))
	for _, st := range s.tags {
		next := (1-alpha)*st.ema + alpha*float64(st.active)
		if next < emaFloor && st.active == 0 {
			// Snap the tail of the decay to zero: an exponential never
			// reaches it, and an idle tag must be able to become evictable.
			next = 0
		}
		st.ema = next
		st.weight = 1.0 / (1.0 + st.ema)
	}
}

// evictIdleTags drops all state for tags with no queued or in-flight
// work, no still-decaying EMA, and no activity for at least a grace
// period. This periodic sweep is the only place tag state is removed:
// counters reaching zero are left alone, because a tag that just finished
// a transfer is very likely to start another one. Without eviction,
// though, every origin ever contacted would stay in the map (and thus in
// every monitoring snapshot) for the process lifetime — unbounded memory
// and Prometheus label cardinality, plus an ever-growing O(tags) snapshot
// cost paid on this goroutine.
//
// The grace period is at least the EMA window so the metrics publisher
// (which samples every few seconds) reliably observes a tag's final
// admit/reject totals before the tag disappears, and then observes the
// tag's absence and forgets its last-published totals. Evicted tags that
// return start their per-tag counters from zero.
//
// That ordering is what keeps the published counters honest, not the
// metrics layer's reset handling on its own: it detects a reset by the
// totals going *down*, so a tag that were to vanish and climb back past
// its old total between two samples would have the difference counted as
// if it were continuous activity. Keeping the grace period comfortably
// longer than the publish interval is what makes that unreachable.
func (s *TagScheduler) evictIdleTags(now time.Time) {
	grace := s.cfg.EMAWindow
	if grace < minEvictionGrace {
		grace = minEvictionGrace
	}
	for tag, st := range s.tags {
		if now.Sub(st.lastSeen) < grace {
			continue
		}
		if st.fifo.Len() > 0 {
			continue
		}
		if st.active > 0 || st.starving > 0 {
			continue
		}
		if st.ema >= emaFloor {
			continue
		}
		delete(s.tags, tag)
	}
}

// Snapshot returns a consistent snapshot of scheduler state suitable
// for driving monitoring metrics. Runs on the scheduler goroutine so
// counters, gauges, and per-tag maps agree with one another.
//
// Returns the zero snapshot if the scheduler has already stopped.
func (s *TagScheduler) Snapshot(ctx context.Context) SchedulerSnapshot {
	reply := make(chan SchedulerSnapshot, 1)
	select {
	case s.snapReqs <- reply:
	case <-ctx.Done():
		return SchedulerSnapshot{}
	case <-s.stop:
		return SchedulerSnapshot{}
	}
	select {
	case snap := <-reply:
		return snap
	case <-ctx.Done():
		return SchedulerSnapshot{}
	}
}

// buildSnapshot must be called on the scheduler goroutine (all state
// reads are lock-free because we're the sole writer). Every per-tag
// value is copied out; the returned SchedulerSnapshot never aliases
// scheduler state.
func (s *TagScheduler) buildSnapshot() SchedulerSnapshot {
	snap := SchedulerSnapshot{
		Global: GlobalStats{
			WorkerCount:        s.workerCount,
			StarvingCap:        s.starvingCap(),
			ActiveCap:          s.activeCap(),
			TotalPending:       s.pending,
			TotalAdmits:        s.totalAdmits,
			TotalRejects:       s.totalRejectsGlobal + s.totalRejectsPerTag,
			TotalRejectsGlobal: s.totalRejectsGlobal,
			TotalRejectsPerTag: s.totalRejectsPerTag,
		},
	}
	// Every tag the scheduler knows about is reported, including ones whose
	// queue has drained and whose transfers have finished: their
	// admit/reject totals stay visible until the tag is evicted.
	snap.Tags = make(map[string]PerTagStats, len(s.tags))
	for tag, st := range s.tags {
		snap.Tags[tag] = PerTagStats{
			Pending:  st.fifo.Len(),
			Active:   st.active,
			Starving: st.starving,
			EMA:      st.ema,
			Admits:   st.admits,
			Rejects:  st.rejects,
		}
	}
	snap.Global.TotalTags = len(snap.Tags)
	return snap
}

// synthesizeRejectionResult builds a TransferResults that surfaces a
// scheduler rejection to callers. Exposed so wire code can push it to
// te.results without special-casing.
func synthesizeRejectionResult(file *clientTransferFile, err error) *clientTransferResults {
	res := TransferResults{
		JobId: file.jobId,
		Error: err,
	}
	if file.file != nil && file.file.job != nil {
		// Populate the same base fields newTransferResults would: the
		// results are consumed by job status displays and the client
		// agent API, which expect Source to be set and Attempts to be
		// non-nil. runMux also unconditionally dereferences
		// TransferResults.job to decrement activeXfer and check
		// completion, so a scheduler-rejected transfer must carry it.
		res = newTransferResults(file.file.job)
		res.JobId = file.jobId
		res.Error = err
		if file.file.remoteURL != nil {
			res.Scheme = file.file.remoteURL.Scheme
		}
		if file.file.job.dirResp.RedirectInfo != nil {
			res.DirectorDecision = file.file.job.dirResp.RedirectInfo
		}
	}
	log.Debugf("Scheduler rejected transfer for %v: %v", file.uuid, err)
	return &clientTransferResults{id: file.uuid, results: res}
}
