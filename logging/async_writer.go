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

package logging

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// This file deliberately does not import logrus. Everything here runs
// underneath logrus -- it is the writer logrus hands lines to -- so calling
// back into it would re-enter the writer, at best recursing and at worst
// deadlocking against a mutex the calling path already holds. Problems are
// reported with reportProblem, which writes to stderr.

// asyncWriter is an io.Writer that decouples the (synchronous) logging call
// sites from disk I/O. Log lines handed to Write are copied into an in-memory
// batch; a dedicated goroutine (managed by the process errgroup when available)
// drains the batch to the log file every flushInterval, or sooner once enough
// bytes accumulate. This keeps wakeups/syscalls low while bounding the window in
// which a buffered line could be lost. The buffer is bounded (maxBufBytes): once
// it fills, Write blocks (backpressure) so callers cannot outrun a slow or
// stalled log device instead of growing memory without bound.
//
// When the target is a regular file, the writer also manages log rotation on
// calendar boundaries (daily or hourly) so administrators can find logs by date.
// At each boundary the active file is renamed with a suffix naming the period it
// covers (e.g. "pelican.log.2026-06-08" for daily, "pelican.log.2026-06-08T15"
// for hourly), optionally gzip-compressed, and old files pruned per the size and
// age retention budgets.
// Rotation is disabled automatically when the target is not a regular file
// (e.g. a terminal, pipe, or device such as /dev/stdout).
//
// On shutdown the writer is flipped to "synchronous mode" (see enterSyncMode):
// the background goroutine drains any remaining batch, fsyncs, and exits, after
// which any late-arriving log line is written straight to the file descriptor by
// the calling goroutine. This avoids losing logs that are emitted while the
// process is tearing down (e.g. during signal handling or a panic).
//
// A failure to write the log file is treated as fatal: the writer surfaces the
// error so the owning errgroup cancels the shutdown context (and, when the
// writer is self-managed, panics). Pelican should not keep operating if it can
// no longer record what it is doing.
type asyncWriter struct {
	// flushBytes is the buffered-byte threshold that triggers an early flush
	// (before the flushInterval timer); flushInterval bounds flush latency.
	flushBytes    int
	flushInterval time.Duration
	// maxBufBytes is the backpressure high-water mark: once this many bytes are
	// buffered, Write blocks until the drain goroutine makes room, so callers
	// cannot outrun a slow or stalled log device.
	maxBufBytes int

	// mu guards buf and synchronous; roomCond (on mu) wakes Write calls that are
	// blocked on backpressure once the buffer drains or sync mode is entered.
	mu          sync.Mutex
	roomCond    *sync.Cond
	buf         []byte
	synchronous bool

	// thresholdCrossed mirrors "batch is full" for lock-free checks in the
	// drain loop; thresholdCh/wakeCh wake the drain goroutine.
	thresholdCrossed atomic.Bool
	wakeCh           chan struct{}
	thresholdCh      chan struct{}

	// fileMu guards all access to the file descriptor and rotation state. It is
	// held during batch writes, direct (synchronous-mode) writes, and rotation.
	fileMu sync.Mutex
	file   *os.File
	// written is the number of bytes written to the active file since it was
	// opened/last rotated; drives size-based rotation.
	written int64
	// periodStart is the calendar period (truncated to the rotation interval)
	// during which the active file began accumulating lines. When the current
	// period advances past it, the file is rotated and named for periodStart.
	// Only meaningful when time-based rotation is active.
	periodStart time.Time
	// rotateRetryAfter suppresses rotation attempts until this instant. Set after
	// a failed rotation so a persistent failure neither spins on syscalls nor
	// floods stderr on every flush; zero when rotation is healthy.
	rotateRetryAfter time.Time
	// mode is the permission mode the active log file is (re)opened with, and the
	// mode given to a compressed rotated copy. It tracks the mode of the file
	// rotation replaces, so an operator's chmod on the log survives a rotation
	// instead of reverting to the default.
	mode os.FileMode
	// rotateSeqBase is the rotated name (without any collision counter) that
	// rotateSeqNext counts within, and rotateSeqNext is the next counter to
	// try for it. Together they keep repeated rotations inside one period
	// from rescanning the names already taken.
	rotateSeqBase string
	rotateSeqNext int

	// dir is the directory containing the log file. root, when non-nil, is an
	// os.Root handle to that directory: it holds an open directory descriptor and
	// performs rotation operations relative to it (open/rename/remove/stat), so
	// rotation keeps working after a privilege drop changes path traversability.
	path string
	dir  string
	base string
	root *os.Root
	// rename and openFile are the two filesystem operations a rotation can fail
	// on. They are reached through the struct rather than through root directly so
	// those failure paths -- a rename losing to a handle held elsewhere, a
	// directory that has become unwritable -- can be driven deterministically;
	// both default to the corresponding os.Root method.
	rename   func(oldName, newName string) error
	openFile func(name string, flag int, perm os.FileMode) (*os.File, error)

	// rotation configuration; rotateOK reports whether the target is eligible
	// (a regular file with rotation enabled). regularFile records only the
	// first half of that test, because a regular file whose rotation is left
	// to an external tool still needs the replacement check below.
	rot         rotateConfig
	rotateOK    bool
	regularFile bool
	// lastReplaceCheck is when the active file was last compared against the
	// path it was opened from, throttling that stat off the flush path.
	lastReplaceCheck time.Time

	// now returns the current time; overridable in tests for deterministic
	// boundary crossing. Defaults to time.Now.
	now func() time.Time

	// lifecycle
	started  atomic.Bool // true once the drain goroutine has been launched
	stopCh   chan struct{}
	stopOnce sync.Once
	doneCh   chan struct{}
	doneOnce sync.Once
	selfMgd  bool           // true when not registered with an errgroup
	wg       sync.WaitGroup // tracks self-managed goroutines

	// Compression worker: one permanent goroutine (started alongside the drain
	// goroutine when rotation+compression is enabled) compresses rotated files
	// handed to it on compressCh. The drain goroutine is the sole sender and
	// closes the channel when it stops; the worker then drains the queue and
	// exits, closing compressDone. In synchronous mode the worker is drained and
	// compression is performed inline instead.
	compressCh       chan string
	compressDone     chan struct{}
	compressStarted  atomic.Bool
	compressChClosed atomic.Bool
	compressChOnce   sync.Once
}

// rotationFrequency is the calendar cadence at which logs are rotated. freqNone
// disables time-based rotation (size-based rotation may still apply).
type rotationFrequency int

const (
	freqDaily rotationFrequency = iota
	freqHourly
	freqNone
)

// parseRotationFrequency maps an admin-facing string to a rotationFrequency. An
// unrecognized value is an error rather than a fallback: silently rotating on a
// cadence the administrator did not ask for is worse than refusing to start.
func parseRotationFrequency(s string) (rotationFrequency, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "daily":
		return freqDaily, nil
	case "hourly":
		return freqHourly, nil
	case "none", "":
		return freqNone, nil
	default:
		return freqDaily, fmt.Errorf("unrecognized rotation frequency %q (expected \"daily\", \"hourly\", or \"none\")", s)
	}
}

// timeBased reports whether this interval triggers calendar-boundary rotation.
func (ri rotationFrequency) timeBased() bool {
	return ri == freqDaily || ri == freqHourly
}

// truncate returns t rounded down to the start of its period (local time), so
// boundaries align with the calendar rather than with an arbitrary epoch offset.
func (ri rotationFrequency) truncate(t time.Time) time.Time {
	switch ri {
	case freqHourly:
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
	default:
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	}
}

// format renders the suffix used to name a rotated file. For time-based
// intervals t is the period start; when time-based rotation is disabled, a
// size-triggered rotation names the file with a full timestamp instead.
func (ri rotationFrequency) format(t time.Time) string {
	switch ri {
	case freqHourly:
		return t.Format("2006-01-02T15")
	case freqNone:
		return t.Format("2006-01-02T15-04-05")
	default:
		return t.Format("2006-01-02")
	}
}

// rotatedSuffixRe matches everything rotate() appends to the log file's name:
// the period/instant stamp produced by rotationFrequency.format, the optional
// collision counter added by uniqueRotatedBase, and the optional compression
// extension -- "<stamp>[-N][.gz]". The three stamp formats are distinguished by
// length, and the greedy inner group resolves the one ambiguity, "T15-04-05"
// (a size-only stamp) versus "T15" followed by a counter.
var rotatedSuffixRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}(?:T\d{2}(?:-\d{2}-\d{2})?)?)(?:-(\d+))?(?:\.gz)?$`)

// rotatedStampLayouts are the time layouts rotationFrequency.format emits, one
// per frequency; they are mutually distinguishable by length.
var rotatedStampLayouts = []string{"2006-01-02T15-04-05", "2006-01-02T15", "2006-01-02"}

// rotatedStamp locates a rotated file in the rotation order: the period it
// covers, plus the collision counter that separates rotations sharing a period.
type rotatedStamp struct {
	period time.Time
	seq    int
}

// before reports whether s covers an earlier rotation than other.
func (s rotatedStamp) before(other rotatedStamp) bool {
	if !s.period.Equal(other.period) {
		return s.period.Before(other.period)
	}
	return s.seq < other.seq
}

// parseRotatedName reports whether name is a file this writer produced by
// rotating the log file named base and, if so, where it falls in the rotation
// order. Two properties depend on going through this parse rather than comparing
// names directly: only names matching the rotated grammar may be deleted by
// retention (a sibling such as "pelican.log.incident-4471" belongs to whoever
// made it), and rotated names are not lexically ordered -- the stamp formats
// differ in granularity between frequencies and the collision counter is
// unpadded decimal, so "-9" sorts after "-12".
func parseRotatedName(base, name string) (rotatedStamp, bool) {
	suffix, ok := strings.CutPrefix(name, base+".")
	if !ok {
		return rotatedStamp{}, false
	}
	m := rotatedSuffixRe.FindStringSubmatch(suffix)
	if m == nil {
		return rotatedStamp{}, false
	}
	var period time.Time
	parsed := false
	for _, layout := range rotatedStampLayouts {
		if len(m[1]) != len(layout) {
			continue
		}
		if t, err := time.ParseInLocation(layout, m[1], time.Local); err == nil {
			period, parsed = t, true
		}
		break
	}
	if !parsed {
		return rotatedStamp{}, false
	}
	seq := 0
	if m[2] != "" {
		var err error
		// A counter too large to be one of ours means the name is not ours.
		if seq, err = strconv.Atoi(m[2]); err != nil {
			return rotatedStamp{}, false
		}
	}
	return rotatedStamp{period: period, seq: seq}, true
}

// rotateConfig captures the admin-facing rotation knobs in already-parsed form.
type rotateConfig struct {
	enable    bool
	frequency rotationFrequency
	maxSize   int64 // active-file size that triggers rotation; 0 disables size-based rotation
	// Retention budgets, applied independently to the set of rotated files:
	maxRetentionSize   int64         // total bytes of rotated files to keep; 0 = unlimited
	maxRetentionPeriod time.Duration // max age of rotated files to keep; 0 = unlimited
	compress           bool
}

const (
	defaultFlushBytes = 64 * 1024
	// defaultMaxBufBytes bounds how much log data may buffer before Write applies
	// backpressure. Generous enough to absorb normal bursts, small enough to cap
	// memory if the log device stalls.
	defaultMaxBufBytes = 1 * 1024 * 1024
	// logFileFlags is how the active log file is (re)opened: write-only, created
	// if absent, appending to preserve any existing content.
	logFileFlags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	// defaultLogFileMode is the mode a log file is created with when there is
	// no existing file whose permissions should be carried forward. Readable
	// by the owning group so a log-shipping account can be given access
	// without granting it write.
	defaultLogFileMode os.FileMode = 0640
	// compressTempSuffix is appended to a rotated file's name while its gzip
	// archive is being written; it is renamed to ".gz" once complete.
	compressTempSuffix = ".gz.tmp"
	// compressQueueDepth bounds how many rotated files may await compression
	// before the drain goroutine blocks on rotation (which in turn applies
	// backpressure to writers). Rotations are infrequent, so this is generous.
	compressQueueDepth = 8
)

// newAsyncWriter opens (creating if necessary, appending if present) the log
// file at path and returns a writer ready to be started. Rotation is enabled
// only when the target is a regular file and cfg.enable is true.
func newAsyncWriter(path string, cfg rotateConfig, flushInterval time.Duration) (*asyncWriter, error) {
	dir := filepath.Dir(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to access/create log directory %q: %w", dir, err)
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, defaultLogFileMode)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %q: %w", path, err)
	}

	if flushInterval <= 0 {
		flushInterval = 50 * time.Millisecond
	}

	w := &asyncWriter{
		flushBytes:    defaultFlushBytes,
		flushInterval: flushInterval,
		maxBufBytes:   defaultMaxBufBytes,
		wakeCh:        make(chan struct{}, 1),
		thresholdCh:   make(chan struct{}, 1),
		file:          f,
		path:          path,
		dir:           dir,
		base:          filepath.Base(path),
		rot:           cfg,
		now:           time.Now,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		compressCh:    make(chan string, compressQueueDepth),
		compressDone:  make(chan struct{}),
	}
	w.roomCond = sync.NewCond(&w.mu)

	// Determine whether the target is a regular file. Only regular files are
	// eligible for rotation; special files (devices, pipes, terminals) are
	// written through untouched.
	periodAnchor := time.Now()
	w.mode = defaultLogFileMode
	if fi, statErr := f.Stat(); statErr == nil && fi.Mode().IsRegular() {
		w.regularFile = true
		w.rotateOK = cfg.enable
		// Carry the existing file's permissions forward so a hardened log
		// (an operator's chmod 0600 after an incident) keeps its mode when
		// rotation replaces it.
		w.mode = fi.Mode().Perm()
		// If the file already holds content, account for its current size
		// (size-based rotation) and anchor the current period on its
		// last-modified time so a restart after a boundary rotates the existing
		// data under the period it was actually written in.
		if fi.Size() > 0 {
			w.written = fi.Size()
			periodAnchor = fi.ModTime()
		}
	}
	w.periodStart = cfg.frequency.truncate(periodAnchor)

	// When rotation is possible, keep an os.Root handle to the log directory so
	// rotation operates relative to a held directory descriptor, surviving a
	// later privilege drop. The directory was just created/opened above, so a
	// failure here is unexpected and surfaced loudly rather than silently
	// disabling the configured rotation.
	if w.rotateOK {
		root, rerr := os.OpenRoot(dir)
		if rerr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to open log directory %q for rotation: %w", dir, rerr)
		}
		w.root = root
		w.rename = root.Rename
		w.openFile = root.OpenFile
		// Remove any leftover compression temp files from a previous run that was
		// killed mid-compression. No compression is running yet, so this is safe.
		w.cleanupStaleTempFiles()
		// Enforce the retention budgets against what is already on disk.
		// Retention is otherwise only applied as a side effect of rotating, so
		// a process that never reaches a rotation -- size-based only on a quiet
		// server, or one that restarts often -- would let old logs accumulate
		// past the budget indefinitely.
		w.pruneRetention()
	}

	return w, nil
}

// Write implements io.Writer. It is safe for concurrent use and must not call
// into logrus (to avoid reentrancy).
func (w *asyncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	// Backpressure: once the buffer reaches the high-water mark, block until the
	// drain goroutine makes room (or the writer flips to synchronous mode on
	// shutdown). This is what slows callers down when the log device cannot keep
	// up, rather than letting the buffer grow without bound. roomCond.Wait
	// releases mu while parked and reacquires it on wake.
	for !w.synchronous && len(w.buf) >= w.maxBufBytes {
		w.roomCond.Wait()
	}
	if w.synchronous {
		w.mu.Unlock()
		return w.writeDirect(p)
	}
	wasEmpty := len(w.buf) == 0
	// p may be reused by the caller after Write returns, so copy it.
	w.buf = append(w.buf, p...)
	crossed := len(w.buf) >= w.flushBytes
	if crossed {
		w.thresholdCrossed.Store(true)
	}
	w.mu.Unlock()

	// Wake the drain goroutine to start the batch timer on the first line, and
	// again (separately) the moment the batch is full so it can flush early.
	if wasEmpty {
		nonBlockingSignal(w.wakeCh)
	}
	if crossed {
		nonBlockingSignal(w.thresholdCh)
	}
	return len(p), nil
}

// nonBlockingSignal pokes a capacity-1 channel without blocking; a pending
// signal is sufficient, so a full channel is fine to drop.
func nonBlockingSignal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// start launches the drain goroutine (and, when rotation+compression is enabled,
// the permanent compression worker). When egrp is non-nil the goroutines are
// registered with it (so a fatal write error cancels the shutdown context, and
// egrp.Wait covers the worker); otherwise the writer self-manages them and the
// drain goroutine panics on a fatal error.
func (w *asyncWriter) start(ctx context.Context, egrp errGroup) {
	w.started.Store(true)
	if w.rotateOK && w.rot.compress {
		w.compressStarted.Store(true)
	}

	if egrp != nil {
		egrp.Go(func() error { return w.run(ctx) })
		if w.compressStarted.Load() {
			egrp.Go(w.compressLoop)
		}
		return
	}

	w.selfMgd = true
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		if err := w.run(ctx); err != nil {
			panic(fmt.Sprintf("pelican logging: fatal error writing to log file %q: %v", w.path, err))
		}
	}()
	if w.compressStarted.Load() {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			_ = w.compressLoop()
		}()
	}
}

// compressLoop is the permanent compression worker. It compresses each rotated
// file handed to it until the drain goroutine closes compressCh, then drains any
// remaining queued files and exits.
func (w *asyncWriter) compressLoop() error {
	defer close(w.compressDone)
	for base := range w.compressCh {
		w.compressAndPrune(base)
	}
	return nil
}

// stopCompression closes compressCh so the worker drains its queue and exits.
// The drain goroutine is the sole sender, so it is the only caller (from
// finalDrain or fail); idempotent.
func (w *asyncWriter) stopCompression() {
	if !w.compressStarted.Load() {
		return
	}
	w.compressChOnce.Do(func() {
		w.compressChClosed.Store(true)
		close(w.compressCh)
	})
}

// reportProblem reports a log-maintenance failure straight to stderr.
//
// Nothing on the writer's own maintenance paths may report through logrus.
// Those paths run while fileMu is held, and a logrus call would come back
// round through Write into writeDirect, which wants that same mutex; in
// synchronous mode, where the compression worker's caller is waiting on the
// worker to finish, that is a deadlock rather than a delay. Compression and
// removal failures are exactly the kind that happen when the disk is full,
// which is when this path matters most.
func reportProblem(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pelican logging: "+format+"\n", args...)
}

// compressAndPrune compresses rotatedBase to "<base>.gz", removes the source on
// success, and applies the retention budgets.
func (w *asyncWriter) compressAndPrune(rotatedBase string) {
	if err := w.compressBackup(rotatedBase); err != nil {
		reportProblem("failed to compress rotated log %q: %v", filepath.Join(w.dir, rotatedBase), err)
	} else if err := w.root.Remove(rotatedBase); err != nil {
		reportProblem("failed to remove %q after compression (leaving an uncompressed copy): %v",
			filepath.Join(w.dir, rotatedBase), err)
	}
	w.pruneRetention()
}

// afterRotate schedules the post-rotation work for a freshly rotated file.
// Callers must hold fileMu. In asynchronous mode the compression is handed to
// the permanent worker; once the worker has been stopped (synchronous mode) or
// was never started, compression is performed inline -- after waiting for the
// worker to finish so the two never touch the directory concurrently.
func (w *asyncWriter) afterRotate(rotatedBase string) {
	if !w.rot.compress {
		w.pruneRetention()
		return
	}
	if w.compressStarted.Load() && !w.compressChClosed.Load() {
		w.compressCh <- rotatedBase
		return
	}
	if w.compressStarted.Load() {
		// The worker was told to stop; let it fully drain before we compress
		// inline so we do not operate on the directory concurrently.
		<-w.compressDone
	}
	w.compressAndPrune(rotatedBase)
}

// errGroup is the minimal subset of *errgroup.Group the writer needs; using an
// interface keeps this file free of an errgroup import and eases testing.
type errGroup interface {
	Go(func() error)
}

// run is the drain loop. It returns nil on a clean stop and a non-nil error if
// writing to the log file fails (which is fatal). It stops when the context is
// cancelled (process shutdown) or when explicitly stopped via stopCh.
func (w *asyncWriter) run(ctx context.Context) error {
	defer w.markDone()
	for {
		select {
		case <-w.stopCh:
			return w.finalDrain()
		case <-ctx.Done():
			return w.finalDrain()
		case <-w.wakeCh:
		}

		// A line is buffered. Batch for up to flushInterval unless the batch is
		// already full, in which case flush immediately.
		if !w.thresholdCrossed.Load() {
			t := time.NewTimer(w.flushInterval)
			select {
			case <-t.C:
			case <-w.thresholdCh:
				t.Stop()
			case <-w.stopCh:
				t.Stop()
				return w.finalDrain()
			case <-ctx.Done():
				t.Stop()
				return w.finalDrain()
			}
		}

		if err := w.flushOnce(); err != nil {
			return w.fail(err)
		}
	}
}

// flushOnce swaps out the current batch and writes it to the file. The rotation
// check happens before the write so the batch is attributed to the file for the
// current calendar period.
func (w *asyncWriter) flushOnce() error {
	w.mu.Lock()
	if len(w.buf) == 0 {
		w.mu.Unlock()
		return nil
	}
	batch := w.buf
	w.buf = nil
	w.thresholdCrossed.Store(false)
	// The buffer is now empty; wake any callers blocked on backpressure.
	w.roomCond.Broadcast()
	w.mu.Unlock()

	w.fileMu.Lock()
	defer w.fileMu.Unlock()
	return w.writeRotatingLocked(batch)
}

// finalDrain writes any remaining batch, stops the compression worker, and
// flips the writer to synchronous mode so subsequent Write calls go straight to
// the file. Everything is done under fileMu so a producer that later observes
// synchronous==true (and calls writeDirect) cannot race ahead of this final
// batch -- and, by the time it can, the worker has been told to stop and
// compressChClosed is visible, so its rotations compress inline rather than
// sending on a channel the drain goroutine is closing.
func (w *asyncWriter) finalDrain() error {
	w.fileMu.Lock()
	w.mu.Lock()
	batch := w.buf
	w.buf = nil
	w.mu.Unlock()

	// Flush the last batch while still asynchronous, so any rotation it triggers
	// hands compression to the worker.
	var err error
	if len(batch) > 0 {
		err = w.writeRotatingLocked(batch)
	}
	// Best-effort durability at shutdown.
	_ = w.file.Sync()

	// The drain goroutine is the sole sender and is done sending; stop the worker
	// so it drains its queue and exits, then flip to synchronous mode.
	w.stopCompression()
	w.mu.Lock()
	w.synchronous = true
	w.roomCond.Broadcast()
	w.mu.Unlock()
	w.fileMu.Unlock()
	return err
}

// writeDirect writes straight to the file descriptor under fileMu, used in
// synchronous mode for lines written by their calling goroutine.
func (w *asyncWriter) writeDirect(p []byte) (int, error) {
	w.fileMu.Lock()
	defer w.fileMu.Unlock()
	if err := w.writeRotatingLocked(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// fail records a fatal write error: it emits to stderr and flips to synchronous
// mode (so any further lines at least attempt a direct write) before the error
// is propagated to the owning errgroup.
func (w *asyncWriter) fail(err error) error {
	fmt.Fprintf(os.Stderr, "pelican logging: fatal error writing to log file %q: %v\n", w.path, err)
	// The drain goroutine is exiting; stop the worker so it drains and exits too.
	w.stopCompression()
	w.mu.Lock()
	w.synchronous = true
	// Release any callers blocked on backpressure so they don't hang now that the
	// drain goroutine is exiting; they'll re-check synchronous and write directly.
	w.roomCond.Broadcast()
	w.mu.Unlock()
	return err
}

func (w *asyncWriter) markDone() {
	w.doneOnce.Do(func() { close(w.doneCh) })
}

// enterSyncMode is the shutdown handler. It stops the drain goroutine, waits for
// it to flush and flip the writer to synchronous mode, after which late log
// lines are written directly by their calling goroutine. Safe to call multiple
// times and from any goroutine.
func (w *asyncWriter) enterSyncMode() {
	w.stopOnce.Do(func() { close(w.stopCh) })
	if w.started.Load() {
		// The drain goroutine will flush, stop the worker, flip to sync mode, and
		// close doneCh.
		<-w.doneCh
	} else {
		// No drain goroutine was ever launched (e.g. file logging that opened the
		// writer but never started it). Perform the final flush/flip inline so the
		// writer is left in a consistent synchronous state.
		w.doneOnce.Do(func() {
			_ = w.finalDrain()
			close(w.doneCh)
		})
	}
	// Wait for the compression worker to finish draining its queue and exit, so a
	// graceful shutdown never abandons an in-flight compression.
	if w.compressStarted.Load() {
		<-w.compressDone
	}
}

// close stops the writer (if not already) and closes the file and directory
// handles. Intended for tests and ResetConfig. enterSyncMode has already drained
// the compression worker.
func (w *asyncWriter) close() {
	w.enterSyncMode()
	if w.selfMgd {
		w.wg.Wait()
	}
	w.fileMu.Lock()
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	if w.root != nil {
		_ = w.root.Close()
		w.root = nil
	}
	w.fileMu.Unlock()
}

// shouldRotateTime reports whether the calendar period has advanced past the one
// the active file belongs to. Callers must hold fileMu.
func (w *asyncWriter) shouldRotateTime(now time.Time) bool {
	return w.rot.frequency.timeBased() && w.rot.frequency.truncate(now).After(w.periodStart)
}

// writeRotatingLocked writes batch to the active log file, rotating as needed:
// once before the write if the calendar period has advanced (time-based), and
// during the write whenever the active file reaches MaxSize (size-based). Size
// rotation never splits a log line: the file is cut at the last newline that
// fits, and the next line starts a fresh file. A single line larger than MaxSize
// is written whole into its own file (the only case a file may exceed MaxSize).
// Callers must hold fileMu.
func (w *asyncWriter) writeRotatingLocked(batch []byte) error {
	// A previous rotation may have left the writer without a file.
	if err := w.ensureFileLocked(); err != nil {
		return err
	}
	// Something outside this process may have moved the log aside.
	w.reopenIfReplaced()

	// A rotation that failed recently is left alone for a while, during
	// which the active file keeps growing with nothing to cap it. That is
	// tolerable only while it stays inside the operator's disk budget.
	if w.rotateOK && w.rotationSuppressed() {
		if err := w.checkUnrotatedGrowth(); err != nil {
			return err
		}
	}

	rotationOK := w.rotateOK && !w.rotationSuppressed()

	// Time-based rotation happens before the write so the batch lands in the new
	// period's file.
	if rotationOK && w.shouldRotateTime(w.now()) {
		if err := w.tryRotate(); err != nil {
			return err
		}
	}

	// No size cap (or rotation disabled): a single write.
	if !rotationOK || w.rot.maxSize <= 0 {
		n, err := w.file.Write(batch)
		w.written += int64(n)
		return err
	}

	for len(batch) > 0 {
		capacity := w.rot.maxSize - w.written
		if capacity <= 0 {
			// Active file is full; start a fresh one.
			if err := w.tryRotate(); err != nil {
				return err
			}
			capacity = w.rot.maxSize - w.written
		}
		if w.rotationSuppressed() {
			// Rotation just failed and is being left alone. Overshooting
			// MaxSize is the lesser evil: the alternative is to loop asking
			// for capacity that nothing is going to reclaim. Growth is only
			// tolerated up to the total the operator budgeted for logs.
			if err := w.checkUnrotatedGrowth(); err != nil {
				return err
			}
			n, werr := w.file.Write(batch)
			w.written += int64(n)
			return werr
		}

		cut := lineCutWithin(batch, capacity)
		if cut == 0 {
			// The next line does not fit in the remaining capacity.
			if w.written > 0 {
				// Give the line a fresh file rather than overshoot the current one.
				if err := w.tryRotate(); err != nil {
					return err
				}
				continue
			}
			// Fresh file but a single line is larger than MaxSize: it cannot be
			// split, so write it whole (this file will exceed MaxSize).
			cut = firstLineEnd(batch)
		}

		n, err := w.file.Write(batch[:cut])
		w.written += int64(n)
		if err != nil {
			return err
		}
		batch = batch[cut:]
	}
	return nil
}

// lineCutWithin returns the end offset (just past a '\n') of the longest run of
// complete lines in b whose total length is <= capacity. It returns len(b) when
// the whole buffer fits, or 0 when not even the first line fits.
func lineCutWithin(b []byte, capacity int64) int {
	if int64(len(b)) <= capacity {
		return len(b)
	}
	// capacity < len(b) here, so it fits in an int index.
	if i := bytes.LastIndexByte(b[:capacity], '\n'); i >= 0 {
		return i + 1
	}
	return 0
}

// firstLineEnd returns the offset just past the first '\n' in b, or len(b) if b
// has no newline.
func firstLineEnd(b []byte) int {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return i + 1
	}
	return len(b)
}

// rotate renames the active log file aside (named for the period it covered),
// opens a fresh one for the current period, and kicks off (optional) compression
// and retention pruning. Callers must hold fileMu.
func (w *asyncWriter) rotate() error {
	// Re-read the mode from the file about to be rotated so a chmod applied to
	// a running server is carried onto its successor, not just one applied
	// before startup.
	if fi, serr := w.file.Stat(); serr == nil && fi.Mode().IsRegular() {
		w.mode = fi.Mode().Perm()
	}

	// fsync is best-effort: a failure must not abort rotation.
	_ = w.file.Sync()
	closeErr := w.file.Close()
	// The descriptor is gone whether or not Close reported a problem, so drop
	// it: a closed *os.File left in place would silently swallow every
	// subsequent write, and w.file == nil is the signal to reopen.
	w.file = nil
	if closeErr != nil {
		return fmt.Errorf("failed to close log file before rotation: %w", closeErr)
	}

	// Name the rotated file for the period it covered (time-based), or with a
	// full timestamp when only size-based rotation is configured.
	suffixTime := w.periodStart
	if !w.rot.frequency.timeBased() {
		suffixTime = w.now()
	}
	rotatedBase := w.uniqueRotatedBase(w.base + "." + w.rot.frequency.format(suffixTime))
	if err := w.rename(w.base, rotatedBase); err != nil {
		return fmt.Errorf("failed to rotate log file %q: %w", w.path, err)
	}

	// Past the rename the old file is gone, so the byte counter no longer
	// describes anything and must not survive into a retry.
	w.written = 0
	w.periodStart = w.rot.frequency.truncate(w.now())

	f, err := w.openFile(w.base, logFileFlags, w.mode)
	if err != nil {
		return fmt.Errorf("failed to open new log file after rotation: %w", err)
	}
	w.file = f

	// Hand the (slow) compression to the permanent worker, or do it inline in
	// synchronous mode; afterRotate also applies retention.
	w.afterRotate(rotatedBase)
	return nil
}

// rotateRetryInterval is how long rotation is left alone after it fails.
// Rotation failures are usually transient but not brief -- a handle held open
// by another process on Windows, a directory that has gone read-only -- so
// retrying on the very next flush would burn syscalls and fill stderr to no
// purpose.
const rotateRetryInterval = time.Minute

// tryRotate rotates the log file, treating a rotation failure as a degraded
// condition rather than a fatal one: the process keeps logging to whatever
// file it can open, and rotation is retried later. Losing the ability to
// start a new file is not a reason to stop a data server, and rotation
// failures are dominated by transient causes.
//
// An error is returned only when the writer is left with no usable file at
// all, which is a genuine inability to record what the process is doing.
// Callers must hold fileMu.
func (w *asyncWriter) tryRotate() error {
	err := w.rotate()
	if err == nil {
		w.rotateRetryAfter = time.Time{}
		return nil
	}
	w.rotateRetryAfter = w.now().Add(rotateRetryInterval)
	reportProblem("%v; continuing without rotating, will retry in %s", err, rotateRetryInterval)
	return w.ensureFileLocked()
}

// ensureFileLocked reopens the active log file when rotation left the writer
// without one. Callers must hold fileMu.
func (w *asyncWriter) ensureFileLocked() error {
	if w.file != nil {
		return nil
	}
	f, err := w.openFile(w.base, logFileFlags, w.mode)
	if err != nil {
		return fmt.Errorf("failed to reopen log file %q: %w", w.path, err)
	}
	w.file = f
	// The reopened file may be the pre-rotation one (rename failed) or a fresh
	// one (rename succeeded, the open did not); either way its real size is
	// what size-based rotation must count from.
	if fi, serr := f.Stat(); serr == nil {
		w.written = fi.Size()
	}
	return nil
}

// replaceCheckInterval is how often the active file is compared against the
// path it was opened from. External rotation runs on the order of hours, so
// noticing within this window is prompt enough to be worth only one stat.
const replaceCheckInterval = 10 * time.Second

// reopenIfReplaced reopens the log when the path no longer refers to the file
// currently held open.
//
// An external rotator -- the logrotate configuration Logging.Rotation.Disable
// exists to defer to -- renames the log aside and creates a new one. Nothing
// about that invalidates the descriptor already open, so a writer that never
// looks keeps appending to the renamed inode: the file the administrator now
// sees stays empty, and the bytes go somewhere only this process can reach,
// until they vanish when the rotator eventually deletes the old file. The
// same applies to copytruncate, which leaves the descriptor's offset past the
// new end of file.
//
// Callers must hold fileMu.
func (w *asyncWriter) reopenIfReplaced() {
	if !w.regularFile || w.file == nil {
		return
	}
	now := w.now()
	if !w.lastReplaceCheck.IsZero() && now.Sub(w.lastReplaceCheck) < replaceCheckInterval {
		return
	}
	w.lastReplaceCheck = now

	onDisk, statErr := os.Stat(w.path)
	held, heldErr := w.file.Stat()
	if heldErr != nil {
		return
	}
	// A missing path is the rename-and-not-yet-recreated case; opening it
	// below recreates it.
	if statErr == nil && os.SameFile(onDisk, held) {
		return
	}

	f, err := os.OpenFile(w.path, logFileFlags, w.mode)
	if err != nil {
		// Keep writing to the descriptor we have: it is the only one that
		// works, and losing lines is worse than writing them somewhere
		// inconvenient.
		reportProblem("failed to reopen %q after it was replaced: %v", w.path, err)
		return
	}
	_ = w.file.Sync()
	_ = w.file.Close()
	w.file = f
	w.written = 0
	if fi, ferr := f.Stat(); ferr == nil {
		w.written = fi.Size()
	}
}

// rotationSuppressed reports whether a recent rotation failure means rotation
// should be left alone for now. Callers must hold fileMu.
func (w *asyncWriter) rotationSuppressed() bool {
	return !w.rotateRetryAfter.IsZero() && w.now().Before(w.rotateRetryAfter)
}

// checkUnrotatedGrowth decides how long a broken rotation may be tolerated.
//
// Failing to rotate is survivable: the process can keep recording into the
// file it already has, and the cause is usually transient. Failing to respect
// the disk the operator set aside for logs is not, because the next thing to
// fill the filesystem takes the rest of the service down with it -- and an
// unrotatable log grows without any bound of its own.
//
// MaxRetentionSize is that budget: it is what the administrator said all
// logs may occupy, and with rotation broken the active file is all the logs
// there are. Leaving it unset asks for unlimited retention, which is equally
// an answer for this case.
//
// Callers must hold fileMu.
func (w *asyncWriter) checkUnrotatedGrowth() error {
	budget := w.rot.maxRetentionSize
	if budget <= 0 || w.written <= budget {
		return nil
	}
	return fmt.Errorf(
		"log file %q has grown to %d bytes, past the %s budget of %d, and cannot be rotated",
		w.path, w.written, "Logging.Rotation.MaxRetentionSize", budget)
}

// uniqueRotatedBase returns base unchanged if no rotated file with that name
// (or its compressed form) already exists, otherwise it appends an incrementing
// "-N" suffix. This guards against name collisions when a process restarts and
// rotates more than once within the same period.
func (w *asyncWriter) uniqueRotatedBase(base string) string {
	exists := func(name string) bool {
		if _, err := w.root.Stat(name); err == nil {
			return true
		}
		if _, err := w.root.Stat(name + ".gz"); err == nil {
			return true
		}
		return false
	}

	// Probing upward from 1 on every rotation costs two stats per name
	// already taken, so a small MaxSize -- which produces many rotations
	// inside one period -- makes each rotation more expensive than the last.
	// Resume from the counter this period reached instead, and pay the scan
	// only when the period changes or the process has just started.
	if base != w.rotateSeqBase {
		w.rotateSeqBase = base
		w.rotateSeqNext = w.highestRotatedSeq(base) + 1
	}
	if w.rotateSeqNext == 0 && !exists(base) {
		w.rotateSeqNext = 1
		return base
	}
	for {
		candidate := fmt.Sprintf("%s-%d", base, w.rotateSeqNext)
		w.rotateSeqNext++
		// The counter is a hint, not an authority: a file could have been
		// put there by something other than this writer.
		if !exists(candidate) {
			return candidate
		}
	}
}

// highestRotatedSeq returns the largest collision counter already used for
// base, or 0 when only the unsuffixed name exists and -1 when nothing does.
// Reads the directory once rather than probing name by name.
func (w *asyncWriter) highestRotatedSeq(base string) int {
	entries, err := fs.ReadDir(w.root.FS(), ".")
	if err != nil {
		// Fall back to probing; a directory we cannot read is a problem
		// rotation itself will report soon enough.
		return 0
	}
	highest := -1
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".gz")
		if name == base {
			if highest < 0 {
				highest = 0
			}
			continue
		}
		suffix, ok := strings.CutPrefix(name, base+"-")
		if !ok {
			continue
		}
		n, cerr := strconv.Atoi(suffix)
		if cerr == nil && n > highest {
			highest = n
		}
	}
	return highest
}

// pruneRetention enforces the retention budgets on the set of rotated files.
// The two budgets are applied independently: a rotated file is deleted if it is
// older than maxRetentionPeriod, or if keeping it would push the total size of
// retained rotated files past maxRetentionSize (most-recent files are kept
// first; the single most recent rotated file is always retained). A budget of 0
// disables that dimension.
func (w *asyncWriter) pruneRetention() {
	maxSize := w.rot.maxRetentionSize
	maxAge := w.rot.maxRetentionPeriod
	if maxSize <= 0 && maxAge <= 0 {
		return
	}

	entries, err := fs.ReadDir(w.root.FS(), ".")
	if err != nil {
		return
	}
	type backup struct {
		name  string
		size  int64
		mod   time.Time
		stamp rotatedStamp
	}
	backups := make([]backup, 0)
	for _, e := range entries {
		name := e.Name()
		// Only files this writer produced are subject to retention. A name
		// that merely starts with the log's name -- an operator's saved copy,
		// or another role's log in a shared directory -- belongs to whoever
		// created it.
		stamp, ok := parseRotatedName(w.base, name)
		if !ok {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		backups = append(backups, backup{name: name, size: info.Size(), mod: info.ModTime(), stamp: stamp})
	}

	// Sort newest first by rotation order. Rotated names are not lexically
	// ordered: stamp granularity differs between frequencies and the collision
	// counter is unpadded, so "-9" would sort after "-12".
	sort.Slice(backups, func(i, j int) bool { return backups[j].stamp.before(backups[i].stamp) })

	now := w.now()
	var kept int64
	for i, b := range backups {
		if maxAge > 0 && now.Sub(b.mod) > maxAge {
			_ = w.root.Remove(b.name)
			continue
		}
		// Always keep the most recent rotated file (i == 0) regardless of size,
		// so a too-small budget can't delete a just-rotated log.
		if maxSize > 0 && i > 0 && kept+b.size > maxSize {
			_ = w.root.Remove(b.name)
			continue
		}
		kept += b.size
	}
}

// cleanupStaleTempFiles removes leftover compression temp files (named
// "<base>.*<compressTempSuffix>") in the log directory. These are left behind
// only when a process is killed while a compression is in progress; on startup
// none can be legitimately in use.
func (w *asyncWriter) cleanupStaleTempFiles() {
	entries, err := fs.ReadDir(w.root.FS(), ".")
	if err != nil {
		return
	}
	prefix := w.base + "."
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, compressTempSuffix) {
			continue
		}
		if rerr := w.root.Remove(name); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			reportProblem("failed to remove stale compression temp file %q: %v", filepath.Join(w.dir, name), rerr)
		}
	}
}

// compressBackup gzips the rotated file named base (relative to the log
// directory) to base+".gz", leaving the uncompressed source for the caller to
// remove.
//
// Compression is atomic: the gzip is written to a temporary file and renamed
// into place, so a crash never leaves a partial ".gz". fsync is best-effort: a
// complete gzip already holds the data, so a sync failure must not fail the
// operation, which would otherwise leave the caller to skip removing the source
// and strand a valid ".gz" next to its identical uncompressed copy.
func (w *asyncWriter) compressBackup(base string) error {
	in, err := w.root.Open(base)
	if err != nil {
		return err
	}
	defer in.Close()

	// Take the archive's permissions from the file being compressed rather
	// than from the writer, both because it is the mode being preserved and
	// because this runs on the compression worker, which shares no mutex with
	// the rotation path that maintains the writer's copy.
	mode := defaultLogFileMode
	if fi, serr := in.Stat(); serr == nil && fi.Mode().IsRegular() {
		mode = fi.Mode().Perm()
	}

	tmp := base + compressTempSuffix
	out, err := w.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}

	gz := gzip.NewWriter(out)
	if _, cerr := io.Copy(gz, in); cerr != nil {
		_ = gz.Close()
		_ = out.Close()
		_ = w.root.Remove(tmp)
		return cerr
	}
	if cerr := gz.Close(); cerr != nil {
		_ = out.Close()
		_ = w.root.Remove(tmp)
		return cerr
	}
	// Best-effort durability; do not let a sync failure strand the source.
	_ = out.Sync()
	if cerr := out.Close(); cerr != nil {
		_ = w.root.Remove(tmp)
		return cerr
	}
	// Put the finished archive in place atomically. The caller removes the
	// (still-present) uncompressed source.
	if cerr := w.root.Rename(tmp, base+".gz"); cerr != nil {
		_ = w.root.Remove(tmp)
		return cerr
	}
	return nil
}
