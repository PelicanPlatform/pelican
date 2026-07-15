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
	"math"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// ErrTooManyRequests is returned by TagScheduler.Submit when the scheduler
// refuses admission because the tag (typically an upstream origin) is
// already at its share of the transfer engine's worker pool. It mirrors
// HTTP 429.
var ErrTooManyRequests = errors.New("too many requests: origin is over its share of the transfer pool")

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
	// Admits and Rejects are monotonic totals since scheduler start.
	Admits  uint64
	Rejects uint64
}

// GlobalStats is the pool-wide scheduler snapshot.
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

// TagScheduler admits transfers into a bounded per-tag FIFO and dispatches
// them to workers with a weighted random draw across tags. It exists to
// keep one misbehaving origin from monopolising the transfer engine's
// worker pool.
type TagScheduler struct {
	cfg         SchedulerConfig
	workerCount int

	// Communication channels. Every field below the channels is owned
	// by the scheduler goroutine and MUST NOT be touched from outside.
	admit    chan *admitReq
	events   chan schedulerEvent
	snapReqs chan chan<- SchedulerSnapshot
	stop     chan struct{}
	stopped  chan struct{}
	out      chan<- *clientTransferFile
	rng      *rand.Rand

	fifos    map[string]*list.List // tag → FIFO of *clientTransferFile
	active   map[string]int        // tag → in-flight (any state)
	starving map[string]int        // tag → in-flight without first byte
	ema      map[string]float64    // tag → EMA of active
	admits   map[string]uint64     // tag → monotonic admit count
	rejects  map[string]uint64     // tag → monotonic rejection count
	lastTick time.Time
	pending  int

	// Global monotonic counters, broken down by why we rejected.
	// TotalAdmits = sum(admits values); TotalRejects = same for rejects.
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
	return &TagScheduler{
		cfg:         cfg,
		workerCount: workerCount,
		admit:       make(chan *admitReq),
		events:      make(chan schedulerEvent, 256),
		snapReqs:    make(chan chan<- SchedulerSnapshot),
		stop:        make(chan struct{}),
		stopped:     make(chan struct{}),
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
		fifos:       make(map[string]*list.List),
		active:      make(map[string]int),
		starving:    make(map[string]int),
		ema:         make(map[string]float64),
		admits:      make(map[string]uint64),
		rejects:     make(map[string]uint64),
	}
}

// Start begins the scheduler goroutine, dispatching admitted transfers on
// the out channel. Stop() blocks until the goroutine exits.
func (s *TagScheduler) Start(ctx context.Context, out chan<- *clientTransferFile) {
	s.out = out
	go s.run(ctx)
}

// Stop signals the scheduler to exit and waits for the goroutine.
func (s *TagScheduler) Stop() {
	select {
	case <-s.stop:
		// Already stopped
	default:
		close(s.stop)
	}
	<-s.stopped
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
		return errors.New("transfer scheduler is shut down")
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *TagScheduler) attachHooks(tag string, file *clientTransferFile) {
	var firstByteFired atomic.Bool
	file.file.schedFirstByte = func() {
		if firstByteFired.CompareAndSwap(false, true) {
			s.sendEvent(schedulerEvent{kind: evFirstByte, tag: tag})
		}
	}
	file.file.schedDone = func() {
		stillStarving := !firstByteFired.Load()
		s.sendEvent(schedulerEvent{kind: evDone, tag: tag, stillStarving: stillStarving})
	}
}

func (s *TagScheduler) sendEvent(ev schedulerEvent) {
	select {
	case s.events <- ev:
	case <-s.stop:
	}
}

func (s *TagScheduler) starvingCap() int {
	pct := s.cfg.PerTagStarvingPercent
	if pct <= 0 || pct >= 100 {
		return s.workerCount
	}
	// Ceiling division so small pools (say 4 workers, 25%) always allow at least 1.
	cap := (s.workerCount*pct + 99) / 100
	if cap < 1 {
		cap = 1
	}
	return cap
}

func (s *TagScheduler) activeCap() int {
	pct := s.cfg.PerTagActivePercent
	if pct <= 0 || pct >= 100 {
		return s.workerCount
	}
	cap := (s.workerCount*pct + 99) / 100
	if cap < 1 {
		cap = 1
	}
	return cap
}

// run is the scheduler goroutine. It multiplexes admissions, first-byte
// / done events, and dispatch attempts, and periodically ticks the EMA.
func (s *TagScheduler) run(ctx context.Context) {
	defer close(s.stopped)

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
		if tag, ok := s.pickForDispatch(); ok {
			head := s.fifos[tag].Front().Value.(*clientTransferFile)
			select {
			case s.out <- head:
				s.onDispatched(tag)
			case req := <-s.admit:
				s.handleAdmit(req)
			case ev := <-s.events:
				s.handleEvent(ev)
			case reply := <-s.snapReqs:
				reply <- s.buildSnapshot()
			case <-tick.C:
				s.tickEMA()
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
				s.tickEMA()
			case <-s.stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *TagScheduler) handleAdmit(req *admitReq) {
	if s.cfg.PendingBufferSize > 0 && s.pending >= s.cfg.PendingBufferSize {
		s.rejects[req.tag]++
		s.totalRejectsGlobal++
		req.reply <- errors.Wrap(ErrTooManyRequests, "pending queue is full")
		return
	}
	q, ok := s.fifos[req.tag]
	if !ok {
		q = list.New()
		s.fifos[req.tag] = q
	}
	if s.cfg.PerTagPendingSize > 0 && q.Len() >= s.cfg.PerTagPendingSize {
		s.rejects[req.tag]++
		s.totalRejectsPerTag++
		req.reply <- errors.Wrapf(ErrTooManyRequests, "origin %q pending queue is full", req.tag)
		return
	}
	q.PushBack(req.file)
	s.pending++
	s.admits[req.tag]++
	req.reply <- nil
}

func (s *TagScheduler) handleEvent(ev schedulerEvent) {
	switch ev.kind {
	case evFirstByte:
		if s.starving[ev.tag] > 0 {
			s.starving[ev.tag]--
		}
	case evDone:
		if s.active[ev.tag] > 0 {
			s.active[ev.tag]--
		}
		if ev.stillStarving && s.starving[ev.tag] > 0 {
			s.starving[ev.tag]--
		}
	}
}

// pickForDispatch selects the next tag whose queue head we'd like to
// hand off to a worker, using a weighted random draw across eligible
// tags (those under both the starving and active caps). Weight is
// 1/(1+EMA) so tags that have used less of the pool recently are more
// likely to be picked. Returns "", false if nothing is dispatchable.
func (s *TagScheduler) pickForDispatch() (string, bool) {
	starvingCap := s.starvingCap()
	activeCap := s.activeCap()

	type cand struct {
		tag string
		w   float64
	}
	var cands []cand
	totalW := 0.0
	for tag, q := range s.fifos {
		if q.Len() == 0 {
			continue
		}
		if s.starving[tag] >= starvingCap {
			continue
		}
		if s.active[tag] >= activeCap {
			continue
		}
		w := 1.0 / (1.0 + s.ema[tag])
		cands = append(cands, cand{tag, w})
		totalW += w
	}
	if len(cands) == 0 {
		return "", false
	}
	r := s.rng.Float64() * totalW
	for _, c := range cands {
		r -= c.w
		if r <= 0 {
			return c.tag, true
		}
	}
	return cands[len(cands)-1].tag, true
}

func (s *TagScheduler) onDispatched(tag string) {
	q := s.fifos[tag]
	q.Remove(q.Front())
	if q.Len() == 0 {
		delete(s.fifos, tag)
	}
	s.pending--
	s.active[tag]++
	s.starving[tag]++
}

// tickEMA advances the per-tag exponentially-weighted moving average of
// active workers. Called at a fixed cadence (roughly EMAWindow/8).
func (s *TagScheduler) tickEMA() {
	now := time.Now()
	dt := now.Sub(s.lastTick)
	s.lastTick = now
	if s.cfg.EMAWindow <= 0 || dt <= 0 {
		return
	}
	alpha := 1.0 - math.Exp(-float64(dt)/float64(s.cfg.EMAWindow))
	seen := make(map[string]struct{}, len(s.ema))
	for tag, e := range s.ema {
		next := (1-alpha)*e + alpha*float64(s.active[tag])
		if next < 1e-6 && s.active[tag] == 0 {
			delete(s.ema, tag)
		} else {
			s.ema[tag] = next
		}
		seen[tag] = struct{}{}
	}
	// Bootstrap EMA for tags that appeared since the last tick.
	for tag := range s.active {
		if _, ok := seen[tag]; ok {
			continue
		}
		if s.active[tag] > 0 {
			s.ema[tag] = alpha * float64(s.active[tag])
		}
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
// reads are lock-free because we're the sole writer). Copies every
// map value; the returned SchedulerSnapshot never aliases scheduler
// state.
func (s *TagScheduler) buildSnapshot() SchedulerSnapshot {
	snap := SchedulerSnapshot{
		Global: GlobalStats{
			WorkerCount:        s.workerCount,
			StarvingCap:        s.starvingCap(),
			ActiveCap:          s.activeCap(),
			TotalPending:       s.pending,
			TotalRejectsGlobal: s.totalRejectsGlobal,
			TotalRejectsPerTag: s.totalRejectsPerTag,
		},
	}
	// Collect the union of every tag we know about — a tag may have
	// pending entries in `fifos`, active/starving counters even after
	// its FIFO drained, an EMA that's still decaying, or lifetime
	// admit/reject totals long after all its in-flight work is done.
	seen := make(map[string]struct{})
	add := func(m map[string]struct{}, k string) { m[k] = struct{}{} }
	for tag := range s.fifos {
		add(seen, tag)
	}
	for tag := range s.active {
		add(seen, tag)
	}
	for tag := range s.starving {
		add(seen, tag)
	}
	for tag := range s.ema {
		add(seen, tag)
	}
	for tag := range s.admits {
		add(seen, tag)
	}
	for tag := range s.rejects {
		add(seen, tag)
	}

	snap.Tags = make(map[string]PerTagStats, len(seen))
	var totalAdmits, totalRejects uint64
	for tag := range seen {
		var pending int
		if q, ok := s.fifos[tag]; ok {
			pending = q.Len()
		}
		p := PerTagStats{
			Pending:  pending,
			Active:   s.active[tag],
			Starving: s.starving[tag],
			EMA:      s.ema[tag],
			Admits:   s.admits[tag],
			Rejects:  s.rejects[tag],
		}
		snap.Tags[tag] = p
		totalAdmits += p.Admits
		totalRejects += p.Rejects
	}
	snap.Global.TotalTags = len(snap.Tags)
	snap.Global.TotalAdmits = totalAdmits
	snap.Global.TotalRejects = totalRejects
	return snap
}

// synthesizeRejectionResult builds a TransferResults that surfaces a 429
// rejection to callers. Exposed so wire code can push it to te.results
// without special-casing.
func synthesizeRejectionResult(file *clientTransferFile, err error) *clientTransferResults {
	res := TransferResults{
		JobId: file.jobId,
		Error: err,
	}
	if file.file != nil && file.file.remoteURL != nil {
		res.Scheme = file.file.remoteURL.Scheme
	}
	if file.file != nil && file.file.job != nil && file.file.job.dirResp.RedirectInfo != nil {
		res.DirectorDecision = file.file.job.dirResp.RedirectInfo
	}
	log.Debugf("Scheduler rejected transfer for %v: %v", file.uuid, err)
	return &clientTransferResults{id: file.uuid, results: res}
}
