//go:build !windows

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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// fakeEgrp is a minimal errGroup that records the first non-nil error returned
// by a goroutine, so tests can assert the writer surfaces fatal write errors.
type fakeEgrp struct {
	wg  sync.WaitGroup
	mu  sync.Mutex
	err error
}

func (f *fakeEgrp) Go(fn func() error) {
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		if e := fn(); e != nil {
			f.mu.Lock()
			if f.err == nil {
				f.err = e
			}
			f.mu.Unlock()
		}
	}()
}

func (f *fakeEgrp) firstErr() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func noRotate() rotateConfig { return rotateConfig{enable: false} }

// fakeClock is a controllable time source for deterministic rotation tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestAsyncWriterBasicFlush verifies that lines written through the writer are
// batched and end up in the file once the writer is drained.
func TestAsyncWriterBasicFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := newAsyncWriter(path, noRotate(), 5*time.Millisecond)
	require.NoError(t, err)

	egrp := &fakeEgrp{}
	w.start(context.Background(), egrp)

	for i := 0; i < 10; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("line %d\n", i)))
		require.NoError(t, err)
	}

	// Draining (enterSyncMode) must flush everything buffered.
	w.enterSyncMode()
	egrp.wg.Wait()
	require.NoError(t, egrp.firstErr())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		assert.Contains(t, string(content), fmt.Sprintf("line %d\n", i))
	}
	w.close()
}

// TestAsyncWriterAppends confirms an existing log file is appended to (not
// truncated) and the initial size is accounted for.
func TestAsyncWriterAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(path, []byte("preexisting\n"), 0640))

	w, err := newAsyncWriter(path, noRotate(), time.Millisecond)
	require.NoError(t, err)

	w.start(context.Background(), &fakeEgrp{})
	_, _ = w.Write([]byte("new line\n"))
	w.close()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preexisting\nnew line\n", string(content))
}

// TestAsyncWriterSyncModeDirectWrite verifies that after enterSyncMode, a
// late-arriving line is written directly (by the calling goroutine) and still
// lands in the file, in order.
func TestAsyncWriterSyncModeDirectWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := newAsyncWriter(path, noRotate(), 5*time.Millisecond)
	require.NoError(t, err)
	w.start(context.Background(), &fakeEgrp{})

	_, _ = w.Write([]byte("before-shutdown\n"))
	w.enterSyncMode()

	// In sync mode synchronous must be set and Write goes straight to disk.
	w.mu.Lock()
	require.True(t, w.synchronous)
	w.mu.Unlock()

	_, err = w.Write([]byte("after-shutdown\n"))
	require.NoError(t, err)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "before-shutdown\nafter-shutdown\n", string(content))
	w.close()
}

// TestAsyncWriterBackpressure verifies that Write blocks once the buffer reaches
// the high-water mark (no drain making room) and is released when the writer
// enters synchronous mode, after which the blocked line is written directly.
func TestAsyncWriterBackpressure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	// Long flush interval and no started drain goroutine, so nothing relieves the
	// buffer until we force it.
	w, err := newAsyncWriter(path, noRotate(), time.Hour)
	require.NoError(t, err)
	w.maxBufBytes = 16 // tiny high-water mark for the test

	// Fill the buffer to/over the high-water mark (does not block: buffer started empty).
	_, err = w.Write([]byte("0123456789ABCDEF\n")) // 17 bytes >= 16
	require.NoError(t, err)

	// The next Write must block because the buffer is full and nothing drains it.
	done := make(chan struct{})
	go func() {
		_, _ = w.Write([]byte("blocked\n"))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Write should block while the buffer is at the high-water mark")
	case <-time.After(100 * time.Millisecond):
		// Expected: still blocked.
	}

	// Entering synchronous mode (shutdown) must release the blocked writer, which
	// then falls through to a direct write.
	w.enterSyncMode()
	select {
	case <-done:
		// Released as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Write was not released after entering synchronous mode")
	}

	w.close()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "blocked", "the previously-blocked line should reach the file")
}

// TestAsyncWriterCompressionWorkerGracefulShutdown verifies the permanent
// compression worker model: rotations hand compression to a worker registered
// in the errgroup, and a graceful shutdown (enterSyncMode followed by
// egrp.Wait) finishes all in-flight compression with no separate "await" call --
// leaving no stale ".gz.tmp" and no uncompressed rotated sources behind.
func TestAsyncWriterCompressionWorkerGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	cfg := rotateConfig{enable: true, frequency: freqNone, maxSize: 100, compress: true}
	w, err := newAsyncWriter(path, cfg, time.Millisecond)
	require.NoError(t, err)

	egrp, ctx := errgroup.WithContext(context.Background())
	w.start(ctx, egrp) // launches the drain goroutine and the compression worker

	for i := 0; i < 200; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("line-%04d-padding-xxxx\n", i)))
		require.NoError(t, err)
		if i%20 == 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}

	// Graceful shutdown: the worker runs in the errgroup, so enterSyncMode
	// drains it and egrp.Wait joins it. No further wait is needed to know
	// compression has finished.
	w.enterSyncMode()
	require.NoError(t, egrp.Wait())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		name := e.Name()
		assert.Falsef(t, strings.HasSuffix(name, compressTempSuffix),
			"a graceful shutdown must not leave a stale temp file: %s", name)
		if strings.HasPrefix(name, "test.log.") && !strings.HasSuffix(name, ".gz") {
			t.Errorf("uncompressed rotated source lingered after compression: %s", name)
		}
	}
	w.close()
}

// TestAsyncWriterContinuousRotation drives the drain goroutine with a steady stream
// of writes and asserts rotation keeps working past the first few.
func TestAsyncWriterContinuousRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	cfg := rotateConfig{enable: true, frequency: freqNone, maxSize: 200, compress: true}
	w, err := newAsyncWriter(path, cfg, 2*time.Millisecond)
	require.NoError(t, err)
	w.start(context.Background(), &fakeEgrp{}) // real drain goroutine

	// ~20 bytes/line; 500 lines -> 10KB -> ~50 rotations at MaxSize=200.
	for i := 0; i < 500; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("line-%05d-xxxx\n", i)))
		require.NoError(t, err)
		if i%25 == 0 {
			time.Sleep(3 * time.Millisecond) // let the drain goroutine flush + rotate
		}
	}
	w.enterSyncMode()

	// If rotation kept working, the active file is bounded near MaxSize.
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.LessOrEqualf(t, fi.Size(), int64(400),
		"active file grew to %d bytes -- rotation appears to have stopped", fi.Size())

	w.close()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var backups int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "test.log.") {
			backups++
		}
	}
	assert.Greaterf(t, backups, 5, "expected many rotated files, got %d", backups)
}

// newRotatingTestWriter builds a writer with rotation enabled and an injected
// clock anchored at start, so calendar-boundary rotation can be driven
// deterministically.
// newAsyncWriterForTest builds a writer on the fake clock without requiring
// that rotation be eligible, for the cases where rotation is deliberately
// left to something outside the process.
func newAsyncWriterForTest(t *testing.T, path string, cfg rotateConfig, clk *fakeClock) *asyncWriter {
	t.Helper()
	w, err := newAsyncWriter(path, cfg, time.Millisecond)
	require.NoError(t, err)
	w.now = clk.now
	w.periodStart = cfg.frequency.truncate(clk.now())
	return w
}

func newRotatingTestWriter(t *testing.T, path string, cfg rotateConfig, clk *fakeClock) *asyncWriter {
	t.Helper()
	w, err := newAsyncWriter(path, cfg, time.Millisecond)
	require.NoError(t, err)
	require.True(t, w.rotateOK, "regular file with rotation enabled should be eligible")
	w.now = clk.now
	// Re-anchor the period to the fake clock (newAsyncWriter used the real one).
	w.periodStart = cfg.frequency.truncate(clk.now())
	return w
}

// TestAsyncWriterDailyRotation verifies a daily rotation at the midnight
// boundary names the rotated file for the day it covered, and that no rotation
// happens within the same day.
func TestAsyncWriterDailyRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 10, 0, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqDaily, compress: false}
	w := newRotatingTestWriter(t, path, cfg, clk)

	// Two writes the same day: no rotation.
	_, _ = w.Write([]byte("day8-morning\n"))
	require.NoError(t, w.flushOnce())
	clk.advance(3 * time.Hour) // still 2026-06-08
	_, _ = w.Write([]byte("day8-afternoon\n"))
	require.NoError(t, w.flushOnce())

	_, err := os.Stat(filepath.Join(dir, "test.log.2026-06-08"))
	assert.True(t, os.IsNotExist(err), "no rotation should occur within the same day")

	// Cross midnight into 2026-06-09: the next flush rotates.
	clk.advance(14 * time.Hour) // now 2026-06-09 03:00
	_, _ = w.Write([]byte("day9-line\n"))
	require.NoError(t, w.flushOnce())
	w.close()

	// The rotated file is named for the day it covered and holds that day's logs.
	rotated, err := os.ReadFile(filepath.Join(dir, "test.log.2026-06-08"))
	require.NoError(t, err, "rotated file should be named for the period it covered")
	assert.Contains(t, string(rotated), "day8-morning")
	assert.Contains(t, string(rotated), "day8-afternoon")
	assert.NotContains(t, string(rotated), "day9-line")

	// The active file holds the new day's logs.
	active, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(active), "day9-line")
	assert.NotContains(t, string(active), "day8")
}

// TestAsyncWriterHourlyRotation verifies the hourly cadence and naming.
func TestAsyncWriterHourlyRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 9, 30, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqHourly, compress: false}
	w := newRotatingTestWriter(t, path, cfg, clk)

	_, _ = w.Write([]byte("hour9-line\n"))
	require.NoError(t, w.flushOnce())

	clk.advance(45 * time.Minute) // now 10:15, a new hour
	_, _ = w.Write([]byte("hour10-line\n"))
	require.NoError(t, w.flushOnce())
	w.close()

	rotated, err := os.ReadFile(filepath.Join(dir, "test.log.2026-06-08T09"))
	require.NoError(t, err, "rotated file should carry the hourly period suffix")
	assert.Contains(t, string(rotated), "hour9-line")

	active, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(active), "hour10-line")
}

// TestAsyncWriterSizeRotation verifies size-based rotation combined with a daily
// interval: within a single day the file rotates each time it reaches MaxSize,
// and the backups are named for that day (with -N uniqueness).
func TestAsyncWriterSizeRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 10, 0, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqDaily, maxSize: 50, compress: false}
	w := newRotatingTestWriter(t, path, cfg, clk)

	// 11 bytes per line, flushed individually; the clock never crosses midnight,
	// so only the size trigger fires.
	for i := 0; i < 20; i++ {
		_, _ = w.Write([]byte("0123456789\n"))
		require.NoError(t, w.flushOnce())
	}
	w.close()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var active, backups int
	for _, e := range entries {
		if e.Name() == "test.log" {
			active++
		} else if strings.HasPrefix(e.Name(), "test.log.") {
			backups++
		}
	}
	assert.Equal(t, 1, active, "active log file should exist")
	assert.GreaterOrEqual(t, backups, 3, "size-based rotation should produce multiple same-day backups")

	// Backups are named for the day; the first keeps the bare date.
	_, err = os.Stat(filepath.Join(dir, "test.log.2026-06-08"))
	assert.NoError(t, err, "first same-day backup should use the bare date suffix")
}

// TestAsyncWriterSizeRotationLineBoundary verifies that when a single drained
// batch crosses the size threshold, the file is split at line boundaries (never
// mid-line), each rotated file stays within MaxSize, and the reassembled content
// matches what was written.
func TestAsyncWriterSizeRotationLineBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 9, 12, 0, 0, 0, time.Local)}
	// Size-only rotation, no compression so files are easy to read.
	cfg := rotateConfig{enable: true, frequency: freqNone, maxSize: 20, compress: false}
	w := newRotatingTestWriter(t, path, cfg, clk)

	// One batch of fixed-width 4-char lines (5 bytes each with '\n') that crosses
	// the 20-byte limit several times.
	const lineWidth = 4
	want := ""
	var batch []byte
	for _, s := range []string{"aaaa", "bbbb", "cccc", "dddd", "eeee", "ffff", "gggg"} {
		want += s + "\n"
		batch = append(batch, []byte(s+"\n")...)
	}
	_, err := w.Write(batch)
	require.NoError(t, err)
	require.NoError(t, w.flushOnce())
	w.close()

	// Gather every log file: rotated backups (chronological) then the active file.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var backups []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "test.log.") {
			backups = append(backups, e.Name())
		}
	}
	sort.Strings(backups)
	ordered := append(append([]string{}, backups...), "test.log")

	reassembled := ""
	for _, name := range ordered {
		content, rerr := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, rerr)
		if len(content) == 0 {
			continue
		}
		// Every file must stay within MaxSize (no line here exceeds it).
		assert.LessOrEqualf(t, len(content), 20, "file %s exceeds MaxSize", name)
		// Every line must be a whole 4-char line — proof nothing was split mid-line.
		require.Equal(t, byte('\n'), content[len(content)-1], "file %s must end on a line boundary", name)
		for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
			assert.Lenf(t, line, lineWidth, "file %s contains a split/partial line %q", name, line)
		}
		reassembled += string(content)
	}
	assert.Equal(t, want, reassembled, "reassembled rotated content should match what was written")
}

// TestAsyncWriterSizeOnlyRotation verifies size-based rotation with time-based
// rotation disabled (interval "none"); rotated files get a timestamp suffix.
func TestAsyncWriterSizeOnlyRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 10, 0, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqNone, maxSize: 50, compress: false}
	w := newRotatingTestWriter(t, path, cfg, clk)

	// Advance the clock a second per flush so timestamp-named backups are unique.
	for i := 0; i < 18; i++ {
		_, _ = w.Write([]byte("0123456789\n"))
		require.NoError(t, w.flushOnce())
		clk.advance(time.Second)
	}
	w.close()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var backups, timestamped int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "test.log.") {
			backups++
			if strings.HasPrefix(e.Name(), "test.log.2026-06-08T10-00-") {
				timestamped++
			}
		}
	}
	assert.GreaterOrEqual(t, backups, 2, "size-only rotation should produce backups")
	assert.Equal(t, backups, timestamped, "size-only backups should use the timestamp suffix")
}

// TestAsyncWriterRetentionBySize verifies the total-size retention budget keeps
// the newest rotated files within the budget and deletes older ones.
func TestAsyncWriterRetentionBySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)}
	// 10 bytes/day; keep at most 25 bytes of rotated files (age budget off).
	cfg := rotateConfig{enable: true, frequency: freqDaily, maxRetentionSize: 25, compress: false}
	w := newRotatingTestWriter(t, path, cfg, clk)

	// Advance one day per iteration so each write rotates the previous day,
	// producing several 10-byte backups (2026-01-01 .. 2026-01-04).
	for i := 0; i < 5; i++ {
		_, _ = w.Write([]byte("012345678\n")) // 10 bytes
		require.NoError(t, w.flushOnce())
		clk.advance(24 * time.Hour)
	}
	w.close()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var backups int
	var total int64
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "test.log.") {
			backups++
			info, ierr := e.Info()
			require.NoError(t, ierr)
			total += info.Size()
		}
	}
	assert.Equal(t, 2, backups, "size budget of 25 bytes should retain the 2 newest 10-byte backups")
	assert.LessOrEqual(t, total, int64(25), "retained rotated files must fit the size budget")
	// The two most recent days are the ones kept.
	_, err = os.Stat(filepath.Join(dir, "test.log.2026-01-04"))
	assert.NoError(t, err, "newest backup should be retained")
	_, err = os.Stat(filepath.Join(dir, "test.log.2026-01-01"))
	assert.True(t, os.IsNotExist(err), "oldest backup should be pruned by the size budget")
}

// TestAsyncWriterRetentionByAge verifies the age retention budget deletes rotated
// files older than MaxRetentionPeriod and keeps newer ones. Backup mtimes are set
// explicitly so the policy can be checked deterministically.
func TestAsyncWriterRetentionByAge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.Local)
	clk := &fakeClock{t: now}
	cfg := rotateConfig{enable: true, frequency: freqDaily, maxRetentionPeriod: 48 * time.Hour}
	w := newRotatingTestWriter(t, path, cfg, clk)

	mk := func(name string, age time.Duration) {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("x"), 0640))
		mt := now.Add(-age)
		require.NoError(t, os.Chtimes(p, mt, mt))
	}
	mk("test.log.2026-06-07", 24*time.Hour)    // within 48h -> keep
	mk("test.log.2026-06-05", 72*time.Hour)    // older than 48h -> delete
	mk("test.log.2026-06-04.gz", 96*time.Hour) // older than 48h -> delete

	w.pruneRetention()

	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	assert.True(t, exists("test.log.2026-06-07"), "backup within the age budget should be kept")
	assert.False(t, exists("test.log.2026-06-05"), "backup older than the age budget should be deleted")
	assert.False(t, exists("test.log.2026-06-04.gz"), "old compressed backup should be deleted too")
	w.close()
}

// TestAsyncWriterCompression verifies rotated files are gzipped and the
// uncompressed original removed.
func TestAsyncWriterCompression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 3, 1, 8, 0, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqDaily, compress: true}
	w := newRotatingTestWriter(t, path, cfg, clk)

	_, _ = w.Write([]byte("hello-rotation\n"))
	require.NoError(t, w.flushOnce())
	clk.advance(24 * time.Hour) // next day -> rotate on next flush
	_, _ = w.Write([]byte("next-day\n"))
	require.NoError(t, w.flushOnce())

	// close() waits for compression workers.
	w.close()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var gzCount, plainBackups int
	var gzName string
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".gz"):
			gzCount++
			gzName = e.Name()
		case strings.HasPrefix(e.Name(), "test.log."):
			plainBackups++
		}
	}
	require.GreaterOrEqual(t, gzCount, 1, "expected at least one compressed backup")
	assert.Equal(t, 0, plainBackups, "uncompressed rotated files should be removed after compression")
	assert.Equal(t, "test.log.2026-03-01.gz", gzName, "compressed backup keeps the period-named suffix")

	// The gzip content should decompress to the original payload.
	f, err := os.Open(filepath.Join(dir, gzName))
	require.NoError(t, err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	decompressed, err := io.ReadAll(gz)
	require.NoError(t, err)
	assert.Contains(t, string(decompressed), "hello-rotation")
}

// TestAsyncWriterCompressionNoDuplicate stress-tests rapid same-day size
// rotations with concurrent compression and asserts that no uncompressed rotated
// file is left behind alongside its .gz (and that no two rotations collide on a
// name).
func TestAsyncWriterCompressionNoDuplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 9, 12, 0, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqDaily, maxSize: 50, compress: true}
	w := newRotatingTestWriter(t, path, cfg, clk)

	// Many small writes, each flushed, so the file rotates repeatedly within the
	// same day while compression goroutines run concurrently.
	for i := 0; i < 300; i++ {
		_, _ = w.Write([]byte("0123456789\n")) // 11 bytes
		require.NoError(t, w.flushOnce())
	}
	w.close() // waits for compression workers

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	present := make(map[string]bool)
	for _, e := range entries {
		present[e.Name()] = true
	}
	var lingering []string
	for name := range present {
		if !strings.HasPrefix(name, "test.log.") || strings.HasSuffix(name, ".gz") {
			continue
		}
		if name == "test.log" {
			continue
		}
		// An uncompressed rotated file remained after close().
		lingering = append(lingering, name)
	}
	assert.Emptyf(t, lingering, "uncompressed rotated files lingered after compression: %v", lingering)
}

// TestAsyncWriterSyncModeStillRotates verifies that once the writer is in
// synchronous mode (drain goroutine stopped, e.g. shutdown context cancelled
// mid-run), writes still rotate by size -- otherwise the log would grow without
// bound during the shutdown routines (which can still be chatty).
func TestAsyncWriterSyncModeStillRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 9, 12, 0, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqNone, maxSize: 50, compress: false}
	w := newRotatingTestWriter(t, path, cfg, clk)

	// Flip to synchronous mode without ever starting the drain goroutine, so
	// every Write goes through the direct (synchronous) path.
	w.mu.Lock()
	w.synchronous = true
	w.mu.Unlock()

	for i := 0; i < 30; i++ {
		clk.advance(time.Second)                  // unique timestamp suffixes for size-only naming
		_, err := w.Write([]byte("0123456789\n")) // 11 bytes
		require.NoError(t, err)
	}
	w.close()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var backups int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "test.log.") {
			backups++
		}
	}
	assert.GreaterOrEqual(t, backups, 3, "synchronous-mode writes must still rotate by size")
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.LessOrEqualf(t, fi.Size(), int64(50), "active file must stay within MaxSize in synchronous mode")
}

// TestAsyncWriterCleansStaleTempFiles verifies that a leftover compression temp
// file (from a process killed mid-compression) is removed on startup, while real
// rotated files are left alone.
func TestAsyncWriterCleansStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	stale := filepath.Join(dir, "test.log.2026-06-09-1.gz.tmp")
	require.NoError(t, os.WriteFile(stale, []byte("\x1f\x8b"), 0640)) // partial gzip
	keep := filepath.Join(dir, "test.log.2026-06-09-1")
	require.NoError(t, os.WriteFile(keep, []byte("data\n"), 0640))
	keepGz := filepath.Join(dir, "test.log.2026-06-09.gz")
	require.NoError(t, os.WriteFile(keepGz, []byte("\x1f\x8bcompressed"), 0640))

	cfg := rotateConfig{enable: true, frequency: freqDaily, maxSize: 1000}
	w, err := newAsyncWriter(path, cfg, time.Millisecond)
	require.NoError(t, err)
	defer w.close()

	_, err = os.Stat(stale)
	assert.Truef(t, os.IsNotExist(err), "stale %s should be removed on startup", filepath.Base(stale))
	_, err = os.Stat(keep)
	assert.NoErrorf(t, err, "rotated source %s must not be removed", filepath.Base(keep))
	_, err = os.Stat(keepGz)
	assert.NoErrorf(t, err, "compressed backup %s must not be removed", filepath.Base(keepGz))
}

// TestAsyncWriterNonRegularNoRotation verifies that a non-regular target
// (a device file) is never marked rotation-eligible, yet still accepts writes.
func TestAsyncWriterNonRegularNoRotation(t *testing.T) {
	cfg := rotateConfig{enable: true, frequency: freqHourly}
	w, err := newAsyncWriter("/dev/null", cfg, 5*time.Millisecond)
	require.NoError(t, err)
	assert.False(t, w.rotateOK, "/dev/null is not a regular file and must not be rotated")
	assert.Nil(t, w.root, "no directory handle should be opened when rotation is disabled")

	w.start(context.Background(), &fakeEgrp{})
	_, err = w.Write([]byte("to the void\n"))
	require.NoError(t, err)
	w.close()
}

// TestAsyncWriterWriteErrorIsFatal verifies that a write failure is surfaced
// through the errgroup (so the process can shut down).
// TestAsyncWriterTolveratesRotationFailureWithinBudget pins the first half of
// the rotation-failure policy: a process that cannot rotate keeps recording.
// Losing the ability to start a new file is not a reason to stop serving data,
// and the usual causes (a handle held open elsewhere, a briefly unwritable
// directory) clear on their own.
func TestAsyncWriterToleratesRotationFailureWithinBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 10, 0, 0, 0, time.Local)}
	cfg := rotateConfig{
		enable:           true,
		frequency:        freqNone,
		maxSize:          64,
		maxRetentionSize: 1 << 20,
	}
	w := newRotatingTestWriter(t, path, cfg, clk)
	defer w.close()

	// Every rotation attempt fails from here on.
	w.rename = func(string, string) error { return errors.New("rename refused") }

	for i := 0; i < 20; i++ {
		_, err := w.Write([]byte(strings.Repeat("x", 40) + "\n"))
		require.NoError(t, err)
		require.NoError(t, w.flushOnce(), "a failed rotation must not fail the write")
	}

	// The lines are still on disk: the file simply grew past MaxSize.
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, 20, bytes.Count(content, []byte("\n")),
		"no log line may be lost because rotation is broken")
	assert.Greater(t, int64(len(content)), cfg.maxSize,
		"the file is expected to overshoot MaxSize while rotation is unavailable")
}

// TestAsyncWriterRotationFailureBecomesFatalPastBudget pins the second half:
// tolerance ends at the disk the operator set aside. An unrotatable log has no
// bound of its own, and filling the filesystem takes down more than logging.
func TestAsyncWriterRotationFailureBecomesFatalPastBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 10, 0, 0, 0, time.Local)}
	cfg := rotateConfig{
		enable:           true,
		frequency:        freqNone,
		maxSize:          64,
		maxRetentionSize: 512,
	}
	w := newRotatingTestWriter(t, path, cfg, clk)
	defer w.close()

	w.rename = func(string, string) error { return errors.New("rename refused") }

	var flushErr error
	for i := 0; i < 100 && flushErr == nil; i++ {
		_, err := w.Write([]byte(strings.Repeat("y", 40) + "\n"))
		require.NoError(t, err)
		flushErr = w.flushOnce()
	}

	require.Error(t, flushErr,
		"growth past MaxRetentionSize with rotation broken must be surfaced as fatal")
	assert.Contains(t, flushErr.Error(), "cannot be rotated")
}

func TestAsyncWriterWriteErrorIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := newAsyncWriter(path, noRotate(), 5*time.Millisecond)
	require.NoError(t, err)

	egrp := &fakeEgrp{}
	w.start(context.Background(), egrp)

	// Close the underlying descriptor so the next flush fails with EBADF.
	w.fileMu.Lock()
	_ = w.file.Close()
	w.fileMu.Unlock()

	// Trigger writes; the drain goroutine will flush (on its timer) and fail.
	for i := 0; i < 5; i++ {
		_, _ = w.Write([]byte("doomed\n"))
	}

	require.Eventually(t, func() bool {
		return egrp.firstErr() != nil
	}, 2*time.Second, 10*time.Millisecond, "a fatal write error should be surfaced via the errgroup")

	// The writer should have flipped to synchronous mode after the failure.
	w.mu.Lock()
	synchronous := w.synchronous
	w.mu.Unlock()
	assert.True(t, synchronous, "writer should enter synchronous mode after a fatal error")
}

// TestAsyncWriterFlushOnceReturnsErrorOnClosedFile is a direct check of the
// flush error path used by the drain loop.
func TestAsyncWriterFlushOnceReturnsErrorOnClosedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := newAsyncWriter(path, noRotate(), time.Millisecond)
	require.NoError(t, err)

	_, _ = w.Write([]byte("data\n"))
	w.fileMu.Lock()
	_ = w.file.Close()
	w.fileMu.Unlock()

	assert.Error(t, w.flushOnce(), "flushOnce should report the underlying write error")
}

// mkBackup writes a rotated-log stand-in of the given size with an explicit
// mtime, so retention policy can be checked without driving real rotations.
func mkBackup(t *testing.T, dir, name string, size int, mod time.Time) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, make([]byte, size), 0640))
	require.NoError(t, os.Chtimes(p, mod, mod))
	return p
}

// TestAsyncWriterRetentionKeepsNewestCollisions verifies the size budget retains
// the most recent rotated files when more than nine rotations share a period.
// The collision counter is unpadded decimal, so the names are not lexically
// ordered ("-9" sorts after "-12") and the retained set must be chosen by the
// period/counter the name encodes.
// TestAsyncWriterCollisionCounterResumes verifies repeated rotations inside
// one period keep allocating distinct names without re-probing the ones
// already taken. A small MaxSize produces many rotations per period, so a
// scan that restarted at 1 each time would make every rotation dearer than
// the one before it.
// TestAsyncWriterReopensAfterExternalRotation covers the deployment
// Logging.Rotation.Disable is meant for: an external logrotate renames the
// log aside and creates a fresh one. Holding the old descriptor open would
// send every subsequent line to an inode nobody can read and the rotator
// will eventually delete.
func TestAsyncWriterReopensAfterExternalRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 10, 0, 0, 0, time.Local)}
	// Rotation disabled: this writer must not rotate, only notice.
	w := newAsyncWriterForTest(t, path, rotateConfig{}, clk)

	_, _ = w.Write([]byte("before\n"))
	require.NoError(t, w.flushOnce())

	// What logrotate does: rename the live file, leave the path free.
	require.NoError(t, os.Rename(path, filepath.Join(dir, "test.log.1")))

	// Move past the throttle so the next flush re-examines the path.
	clk.advance(2 * replaceCheckInterval)
	_, _ = w.Write([]byte("after\n"))
	require.NoError(t, w.flushOnce())
	w.close()

	current, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(current), "after",
		"lines written after an external rotation must land in the recreated file")
	assert.NotContains(t, string(current), "before")

	rotated, err := os.ReadFile(filepath.Join(dir, "test.log.1"))
	require.NoError(t, err)
	assert.Contains(t, string(rotated), "before",
		"lines written before the rename stay with the renamed file")
	assert.NotContains(t, string(rotated), "after",
		"the renamed file must stop receiving writes")
}

// The check must not fire when nothing has happened: reopening on every
// flush would reset the size counter that drives size-based rotation.
func TestAsyncWriterDoesNotReopenAnUntouchedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 10, 0, 0, 0, time.Local)}
	w := newAsyncWriterForTest(t, path, rotateConfig{}, clk)
	defer w.close()

	_, _ = w.Write([]byte("one\n"))
	require.NoError(t, w.flushOnce())

	w.fileMu.Lock()
	before, err := w.file.Stat()
	w.fileMu.Unlock()
	require.NoError(t, err)

	clk.advance(2 * replaceCheckInterval)
	_, _ = w.Write([]byte("two\n"))
	require.NoError(t, w.flushOnce())

	w.fileMu.Lock()
	after, serr := w.file.Stat()
	written := w.written
	w.fileMu.Unlock()
	require.NoError(t, serr)
	assert.True(t, os.SameFile(before, after), "an untouched log must keep its descriptor")
	assert.Equal(t, int64(len("one\ntwo\n")), written,
		"the byte counter must keep accumulating rather than restart")
}

func TestAsyncWriterCollisionCounterResumes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	now := time.Date(2026, 1, 1, 9, 0, 0, 0, time.Local)
	clk := &fakeClock{t: now}
	cfg := rotateConfig{enable: true, frequency: freqDaily}
	w := newRotatingTestWriter(t, path, cfg, clk)
	defer w.close()

	// Names already on disk from an earlier run must not be handed out again.
	mkBackup(t, dir, "test.log.2026-01-01", 10, now)
	mkBackup(t, dir, "test.log.2026-01-01-1", 10, now)
	mkBackup(t, dir, "test.log.2026-01-01-2", 10, now)

	base := "test.log.2026-01-01"
	assert.Equal(t, "test.log.2026-01-01-3", w.uniqueRotatedBase(base),
		"allocation must resume past the highest counter already present")
	assert.Equal(t, "test.log.2026-01-01-4", w.uniqueRotatedBase(base))
	assert.Equal(t, "test.log.2026-01-01-5", w.uniqueRotatedBase(base))

	// A new period starts its own counter, and the unsuffixed name is free.
	nextDay := "test.log.2026-01-02"
	assert.Equal(t, nextDay, w.uniqueRotatedBase(nextDay))
	assert.Equal(t, "test.log.2026-01-02-1", w.uniqueRotatedBase(nextDay))
}

// A name the writer did not create must still be stepped over: the counter
// is a hint about where to resume, not a promise the name is free.
func TestAsyncWriterCollisionCounterYieldsToForeignFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	now := time.Date(2026, 1, 1, 9, 0, 0, 0, time.Local)
	clk := &fakeClock{t: now}
	w := newRotatingTestWriter(t, path, rotateConfig{enable: true, frequency: freqDaily}, clk)
	defer w.close()

	base := "test.log.2026-01-01"
	require.Equal(t, base, w.uniqueRotatedBase(base))

	// Something else claims the name the counter was about to use.
	mkBackup(t, dir, base+"-1", 10, now)
	assert.Equal(t, base+"-2", w.uniqueRotatedBase(base))
}

func TestAsyncWriterRetentionKeepsNewestCollisions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	now := time.Date(2026, 1, 1, 23, 0, 0, 0, time.Local)
	clk := &fakeClock{t: now}
	// 10 bytes per backup, budget of 25 -> the two newest are retained.
	cfg := rotateConfig{enable: true, frequency: freqDaily, maxRetentionSize: 25}
	w := newRotatingTestWriter(t, path, cfg, clk)
	defer w.close()

	mkBackup(t, dir, "test.log.2026-01-01", 10, now)
	for i := 1; i <= 12; i++ {
		mkBackup(t, dir, fmt.Sprintf("test.log.2026-01-01-%d", i), 10, now)
	}

	w.pruneRetention()

	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	assert.True(t, exists("test.log.2026-01-01-12"), "the newest rotated file must be retained")
	assert.True(t, exists("test.log.2026-01-01-11"), "the second-newest rotated file must be retained")
	assert.False(t, exists("test.log.2026-01-01-9"), "an older rotated file must not outlive newer ones")
	assert.False(t, exists("test.log.2026-01-01"), "the oldest rotated file must be pruned first")
}

// TestAsyncWriterRetentionOrdersAcrossFormats verifies retention orders rotated
// files by the period they encode even when the directory mixes the daily,
// hourly and size-only suffix formats (a frequency change leaves both behind).
func TestAsyncWriterRetentionOrdersAcrossFormats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.Local)
	clk := &fakeClock{t: now}
	cfg := rotateConfig{enable: true, frequency: freqHourly, maxRetentionSize: 25}
	w := newRotatingTestWriter(t, path, cfg, clk)
	defer w.close()

	mkBackup(t, dir, "test.log.2026-06-08", 10, now)             // oldest (daily)
	mkBackup(t, dir, "test.log.2026-06-09T23", 10, now)          // hourly
	mkBackup(t, dir, "test.log.2026-06-10T11-30-00.gz", 10, now) // newest (size-only)

	w.pruneRetention()

	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	assert.True(t, exists("test.log.2026-06-10T11-30-00.gz"), "newest rotated file must be retained")
	assert.True(t, exists("test.log.2026-06-09T23"), "second-newest rotated file must be retained")
	assert.False(t, exists("test.log.2026-06-08"), "oldest rotated file must be pruned first")
}

// TestAsyncWriterRetentionIgnoresForeignFiles verifies retention only deletes
// files matching the rotated-name grammar. Anything else sharing the log's name
// prefix -- an operator's incident copy, a note, an unrelated log -- belongs to
// somebody else and must be left alone by both budgets.
func TestAsyncWriterRetentionIgnoresForeignFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.Local)
	clk := &fakeClock{t: now}
	cfg := rotateConfig{enable: true, frequency: freqDaily, maxRetentionSize: 1, maxRetentionPeriod: time.Hour}
	w := newRotatingTestWriter(t, path, cfg, clk)
	defer w.close()

	foreign := []string{
		"test.log.incident-4471",
		"test.log.bak",
		"test.log.2026-13-45", // prefix-shaped but not a real date
		"test.log.old.gz",
	}
	for _, name := range foreign {
		mkBackup(t, dir, name, 4096, now.Add(-72*time.Hour))
	}
	mkBackup(t, dir, "test.log.2026-06-07", 4096, now.Add(-72*time.Hour))

	w.pruneRetention()

	for _, name := range foreign {
		_, err := os.Stat(filepath.Join(dir, name))
		assert.NoErrorf(t, err, "retention must not delete %q: it is not a rotated log file", name)
	}
	_, err := os.Stat(filepath.Join(dir, "test.log.2026-06-07"))
	assert.True(t, os.IsNotExist(err), "a genuine rotated file outside both budgets should be pruned")
}

// TestAsyncWriterPrunesAtStartup verifies retention is enforced when the writer
// is constructed. Rotation is the only other trigger, so a process configured
// with Frequency "none" (or one that restarts often) would otherwise never
// enforce the budgets.
func TestAsyncWriterPrunesAtStartup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	now := time.Now()

	mkBackup(t, dir, "test.log.2026-06-07", 10, now.Add(-72*time.Hour))
	mkBackup(t, dir, "test.log.2026-06-09", 10, now.Add(-time.Hour))

	cfg := rotateConfig{enable: true, frequency: freqNone, maxRetentionPeriod: 48 * time.Hour}
	w, err := newAsyncWriter(path, cfg, time.Millisecond)
	require.NoError(t, err)
	defer w.close()

	_, err = os.Stat(filepath.Join(dir, "test.log.2026-06-07"))
	assert.True(t, os.IsNotExist(err), "a rotated file past the age budget should be pruned at startup")
	_, err = os.Stat(filepath.Join(dir, "test.log.2026-06-09"))
	assert.NoError(t, err, "a rotated file within the age budget must survive startup pruning")
}

// TestAsyncWriterRotationPreservesFileMode verifies rotation does not widen the
// permission bits of the log: an operator who tightens the active file must find
// the same mode on its successor, and on the compressed rotated copy.
func TestAsyncWriterRotationPreservesFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 8, 10, 0, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqDaily, compress: true}
	w := newRotatingTestWriter(t, path, cfg, clk)

	require.NoError(t, os.Chmod(path, 0600))

	_, _ = w.Write([]byte("day8\n"))
	require.NoError(t, w.flushOnce())
	clk.advance(24 * time.Hour)
	_, _ = w.Write([]byte("day9\n"))
	require.NoError(t, w.flushOnce())
	w.close()

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(),
		"the log file opened after rotation must keep the mode of the one it replaces")

	gz, err := os.Stat(filepath.Join(dir, "test.log.2026-06-08.gz"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), gz.Mode().Perm(),
		"a compressed rotated file must keep the mode of its source")
}

// reentrantLogHook routes every logrus entry back into the writer under test.
// In production the writer *is* logrus's output, so anything the writer logs
// re-enters it; logrus fires hooks without holding its own mutex, so a hook that
// blocks reproduces that reentrancy without wedging the standard logger for the
// rest of the suite.
type reentrantLogHook struct{ w *asyncWriter }

func (h *reentrantLogHook) Levels() []log.Level { return log.AllLevels }

func (h *reentrantLogHook) Fire(*log.Entry) error {
	_, _ = h.w.Write([]byte("reentrant\n"))
	return nil
}

// removeHook drops a specific hook from the standard logger, leaving any others
// (notably the test hook) in place.
func removeHook(target log.Hook) {
	old := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	filtered := make(log.LevelHooks)
	for lvl, hooks := range old {
		for _, h := range hooks {
			if h == target {
				continue
			}
			filtered[lvl] = append(filtered[lvl], h)
		}
	}
	log.StandardLogger().ReplaceHooks(filtered)
}

// TestAsyncWriterCompressionFailureDuringShutdownDoesNotDeadlock verifies that a
// compression failure on the synchronous-mode path (the ENOSPC-at-shutdown case)
// is reported without re-entering the writer. Post-rotation work runs under
// fileMu, so anything it emits through logrus would come straight back to
// writeDirect and self-deadlock the rotating goroutine.
func TestAsyncWriterCompressionFailureDuringShutdownDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	clk := &fakeClock{t: time.Date(2026, 6, 9, 12, 0, 0, 0, time.Local)}
	cfg := rotateConfig{enable: true, frequency: freqNone, maxSize: 10, compress: true}
	w := newRotatingTestWriter(t, path, cfg, clk)

	egrp, ctx := errgroup.WithContext(context.Background())
	w.start(ctx, egrp)
	// Drain and flip to synchronous mode, so the next rotation compresses inline
	// on the writing goroutine while it holds fileMu.
	w.enterSyncMode()
	require.NoError(t, egrp.Wait())

	// One oversized line fills the active file without rotating it.
	_, err := w.Write([]byte("aaaaaaaaaa\n"))
	require.NoError(t, err)

	// A directory where the compression temp file belongs makes the next
	// rotation's compression fail.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "test.log.2026-06-09T12-00-00"+compressTempSuffix), 0750))

	hook := &reentrantLogHook{w: w}
	log.AddHook(hook)
	defer removeHook(hook)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.Write([]byte("bbbbbbbbbb\n"))
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("a rotation whose compression fails must not block: post-rotation work must never re-enter the writer")
	}

	// The failure left the uncompressed rotated file in place rather than losing it.
	_, err = os.Stat(filepath.Join(dir, "test.log.2026-06-09T12-00-00"))
	assert.NoError(t, err, "a failed compression must leave the rotated source behind")

	_, err = w.Write([]byte("cccccccccc\n"))
	assert.NoError(t, err, "the writer must keep serving after a compression failure")
	w.close()
}

// TestAsyncWriterConcurrentWriters drives the writer from many goroutines at once
// while rotation is active, so the race detector actually exercises fileMu and
// the backpressure condition variable. Every line must survive somewhere in the
// rotated set, intact and unsplit.
func TestAsyncWriterConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	cfg := rotateConfig{enable: true, frequency: freqNone, maxSize: 4096, compress: false}
	w, err := newAsyncWriter(path, cfg, time.Millisecond)
	require.NoError(t, err)

	egrp, ctx := errgroup.WithContext(context.Background())
	w.start(ctx, egrp)
	w.maxBufBytes = 8 * 1024 // small enough that writers actually hit backpressure

	const writers, perWriter = 16, 200
	var wg sync.WaitGroup
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				_, werr := w.Write([]byte(fmt.Sprintf("writer-%02d-line-%04d-padding\n", g, i)))
				assert.NoError(t, werr)
			}
		}(g)
	}
	wg.Wait()

	w.enterSyncMode()
	require.NoError(t, egrp.Wait())
	w.close()

	// Reassemble every log file in the directory and confirm nothing was lost or
	// interleaved mid-line.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	seen := make(map[string]bool, writers*perWriter)
	for _, e := range entries {
		content, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, rerr)
		for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
			if line == "" {
				continue
			}
			assert.Falsef(t, seen[line], "line written once appeared twice: %q", line)
			seen[line] = true
		}
	}
	for g := 0; g < writers; g++ {
		for i := 0; i < perWriter; i++ {
			line := fmt.Sprintf("writer-%02d-line-%04d-padding", g, i)
			assert.Truef(t, seen[line], "line lost by concurrent writers: %q", line)
		}
	}
}
