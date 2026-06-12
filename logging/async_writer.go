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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

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

	// dir is the directory containing the log file. root, when non-nil, is an
	// os.Root handle to that directory: it holds an open directory descriptor and
	// performs rotation operations relative to it (open/rename/remove/stat), so
	// rotation keeps working after a privilege drop changes path traversability.
	path string
	dir  string
	base string
	root *os.Root

	// rotation configuration; rotateOK reports whether the target is eligible
	// (a regular file with rotation enabled).
	rot      rotateConfig
	rotateOK bool

	// now returns the current time; overridable in tests for deterministic
	// boundary crossing. Defaults to time.Now.
	now func() time.Time

	// lifecycle
	started    atomic.Bool // true once the drain goroutine has been launched
	stopCh     chan struct{}
	stopOnce   sync.Once
	doneCh     chan struct{}
	doneOnce   sync.Once
	selfMgd    bool           // true when not registered with an errgroup
	wg         sync.WaitGroup // tracks the self-managed drain goroutine
	compressWg sync.WaitGroup
}

// rotationFrequency is the calendar cadence at which logs are rotated. freqNone
// disables time-based rotation (size-based rotation may still apply).
type rotationFrequency int

const (
	freqDaily rotationFrequency = iota
	freqHourly
	freqNone
)

// parseRotationFrequency maps an admin-facing string to a rotationFrequency; any
// unrecognized value falls back to daily.
func parseRotationFrequency(s string) rotationFrequency {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "hourly":
		return freqHourly
	case "none", "":
		return freqNone
	default:
		return freqDaily
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
	// compressTempSuffix is appended to a rotated file's name while its gzip
	// archive is being written; it is renamed to ".gz" once complete.
	compressTempSuffix = ".gz.tmp"
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

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
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
	}
	w.roomCond = sync.NewCond(&w.mu)

	// Determine whether the target is a regular file. Only regular files are
	// eligible for rotation; special files (devices, pipes, terminals) are
	// written through untouched.
	periodAnchor := time.Now()
	if fi, statErr := f.Stat(); statErr == nil && fi.Mode().IsRegular() {
		w.rotateOK = cfg.enable
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
		// Remove any leftover compression temp files from a previous run that was
		// killed mid-compression. No compression is running yet, so this is safe.
		w.cleanupStaleTempFiles()
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

// start launches the drain goroutine. When egrp is non-nil the goroutine is
// registered with it (so a fatal write error cancels the shutdown context);
// otherwise the writer self-manages the goroutine and panics on a fatal error.
func (w *asyncWriter) start(ctx context.Context, egrp errGroup) {
	w.started.Store(true)
	if egrp != nil {
		egrp.Go(func() error { return w.run(ctx) })
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

// finalDrain writes any remaining batch and atomically flips the writer to
// synchronous mode so that subsequent Write calls go straight to the file. It is
// only ever called from the drain goroutine.
func (w *asyncWriter) finalDrain() error {
	// Hold fileMu across the flip so a producer that observes synchronous==true
	// and calls writeDirect cannot race ahead of this final batch.
	w.fileMu.Lock()
	w.mu.Lock()
	batch := w.buf
	w.buf = nil
	w.synchronous = true
	// Wake any callers blocked on backpressure; they will re-check synchronous
	// and fall through to a direct write.
	w.roomCond.Broadcast()
	w.mu.Unlock()

	var err error
	if len(batch) > 0 {
		err = w.writeRotatingLocked(batch)
	}
	// Best-effort durability at shutdown.
	_ = w.file.Sync()
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
		// The drain goroutine will flush, flip to sync mode, and close doneCh.
		<-w.doneCh
		return
	}
	// No drain goroutine was ever launched (e.g. file logging that opened the
	// writer but never started it). Perform the final flush/flip inline so the
	// writer is left in a consistent synchronous state.
	w.doneOnce.Do(func() {
		_ = w.finalDrain()
		close(w.doneCh)
	})
}

// close stops the writer (if not already), waits for any compression workers,
// and closes the file and directory handles. Intended for tests and ResetConfig.
func (w *asyncWriter) close() {
	w.enterSyncMode()
	if w.selfMgd {
		w.wg.Wait()
	}
	w.compressWg.Wait()
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
	// Time-based rotation happens before the write so the batch lands in the new
	// period's file.
	if w.rotateOK && w.shouldRotateTime(w.now()) {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	// No size cap (or rotation disabled): a single write.
	if !w.rotateOK || w.rot.maxSize <= 0 {
		n, err := w.file.Write(batch)
		w.written += int64(n)
		return err
	}

	for len(batch) > 0 {
		capacity := w.rot.maxSize - w.written
		if capacity <= 0 {
			// Active file is full; start a fresh one.
			if err := w.rotate(); err != nil {
				return err
			}
			capacity = w.rot.maxSize
		}

		cut := lineCutWithin(batch, capacity)
		if cut == 0 {
			// The next line does not fit in the remaining capacity.
			if w.written > 0 {
				// Give the line a fresh file rather than overshoot the current one.
				if err := w.rotate(); err != nil {
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
	// fsync is best-effort: a failure must not abort rotation.
	_ = w.file.Sync()
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("failed to close log file before rotation: %w", err)
	}

	// Name the rotated file for the period it covered (time-based), or with a
	// full timestamp when only size-based rotation is configured.
	suffixTime := w.periodStart
	if !w.rot.frequency.timeBased() {
		suffixTime = w.now()
	}
	rotatedBase := w.uniqueRotatedBase(w.base + "." + w.rot.frequency.format(suffixTime))
	if err := w.root.Rename(w.base, rotatedBase); err != nil {
		// Try to reopen the original so logging can continue even if the rename
		// failed; report the rename error regardless.
		if f, oerr := w.root.OpenFile(w.base, logFileFlags, 0640); oerr == nil {
			w.file = f
		}
		return fmt.Errorf("failed to rotate log file %q: %w", w.path, err)
	}

	f, err := w.root.OpenFile(w.base, logFileFlags, 0640)
	if err != nil {
		return fmt.Errorf("failed to open new log file after rotation: %w", err)
	}
	w.file = f
	w.written = 0
	w.periodStart = w.rot.frequency.truncate(w.now())

	if w.rot.compress {
		w.compressWg.Add(1)
		go func() {
			defer w.compressWg.Done()
			// compressBackup produces "<base>.gz"; on success the uncompressed
			// source is removed. Both failure modes leave the (readable)
			// uncompressed source in place.
			if cerr := w.compressBackup(rotatedBase); cerr != nil {
				log.Warnf("Failed to compress rotated log %q: %v", filepath.Join(w.dir, rotatedBase), cerr)
			} else if rerr := w.root.Remove(rotatedBase); rerr != nil {
				log.Warnf("Failed to remove %q after compression (leaving an uncompressed copy): %v",
					filepath.Join(w.dir, rotatedBase), rerr)
			}
			w.pruneRetention()
		}()
	} else {
		w.pruneRetention()
	}

	return nil
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
	if !exists(base) {
		return base
	}
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !exists(candidate) {
			return candidate
		}
	}
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
	prefix := w.base + "."
	type backup struct {
		name string
		size int64
		mod  time.Time
	}
	backups := make([]backup, 0)
	for _, e := range entries {
		name := e.Name()
		if name == w.base || !strings.HasPrefix(name, prefix) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		backups = append(backups, backup{name: name, size: info.Size(), mod: info.ModTime()})
	}

	// Sort newest first. Rotated names embed a sortable period/timestamp suffix,
	// so reverse-lexical order is reverse-chronological.
	sort.Slice(backups, func(i, j int) bool { return backups[i].name > backups[j].name })

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
			log.Warnf("Failed to remove stale compression temp file %q: %v", filepath.Join(w.dir, name), rerr)
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

	tmp := base + compressTempSuffix
	out, err := w.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
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
