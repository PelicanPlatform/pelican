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

package log_exports

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedClock returns a now() that never moves, so the settle margin and the
// cache-directive rules can be asserted exactly.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// logLine renders one entry the way logrus' TextFormatter writes it to the log
// file: `time` first and quoted, since an RFC3339 timestamp contains colons.
func logLine(ts time.Time, level, msg string) string {
	return fmt.Sprintf("time=%q level=%s msg=%q\n", ts.Format(time.RFC3339), level, msg)
}

// writeLog puts content in a temp file and returns a source reading it.
func writeLog(t *testing.T, content string) *activeFileSource {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pelican.log")
	require.NoError(t, os.WriteFile(p, []byte(content), 0600))
	return &activeFileSource{path: p}
}

// readWindow runs a selector over a source and returns what was streamed.
func readWindow(t *testing.T, src logSource, sel logSelector) string {
	t.Helper()
	reader, err := src.Open(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	var sb strings.Builder
	require.NoError(t, reader.Read(context.Background(), sel, &sb))
	return sb.String()
}

// coverageOf opens a source and reports its coverage.
func coverageOf(t *testing.T, src logSource) (time.Time, bool) {
	t.Helper()
	reader, err := src.Open(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	oldest, ok, err := reader.Coverage(context.Background())
	require.NoError(t, err)
	return oldest, ok
}

func TestTimeWindowSelectorCacheable(t *testing.T) {
	now := time.Date(2026, 8, 20, 18, 30, 0, 0, time.UTC)

	closed := &timeWindowSelector{
		start: time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC),
		end:   time.Date(2026, 8, 20, 16, 0, 0, 0, time.UTC),
		now:   fixedClock(now),
	}
	assert.True(t, closed.Cacheable(), "a finished hour never changes again")

	// The subtle case: an absolute path is not automatically immutable.  The
	// 18:00 bucket fetched at 18:30 is a prefix of an hour still being
	// written, and caching it would pin a truncated hour.
	inProgress := &timeWindowSelector{
		start: time.Date(2026, 8, 20, 18, 0, 0, 0, time.UTC),
		end:   time.Date(2026, 8, 20, 19, 0, 0, 0, time.UTC),
		now:   fixedClock(now),
	}
	assert.False(t, inProgress.Cacheable(),
		"the current hour is still being appended to and must not be cached")
}

func TestActiveFileSourceWindowFiltering(t *testing.T) {
	base := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)

	src := writeLog(t, strings.Join([]string{
		logLine(base.Add(-90*time.Minute), "info", "long before"),
		logLine(base.Add(-time.Minute), "info", "just before"),
		logLine(base.Add(time.Minute), "info", "inside one"),
		logLine(base.Add(30*time.Minute), "warning", "inside two"),
		logLine(base.Add(90*time.Minute), "info", "after"),
	}, ""))

	sel := &timeWindowSelector{
		start: base,
		end:   base.Add(time.Hour),
		now:   fixedClock(base.Add(3 * time.Hour)),
	}
	got := readWindow(t, src, sel)

	assert.Contains(t, got, "inside one")
	assert.Contains(t, got, "inside two")
	assert.NotContains(t, got, "just before")
	assert.NotContains(t, got, "long before")
	assert.NotContains(t, got, "after", "the window is half-open: [start, end)")
}

func TestActiveFileSourceContinuationLines(t *testing.T) {
	base := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)

	// A panic's stack trace arrives as lines with no time= field.  They belong
	// to the entry above and have to share its fate, or a caller gets a
	// message with its traceback silently removed.
	src := writeLog(t, strings.Join([]string{
		logLine(base.Add(-time.Hour), "error", "excluded parent"),
		"\tgoroutine 1 [running]: excluded frame\n",
		logLine(base.Add(time.Minute), "error", "included parent"),
		"\tgoroutine 2 [running]: included frame\n",
		"\tmain.main() included frame two\n",
	}, ""))

	got := readWindow(t, src, &timeWindowSelector{
		start: base,
		end:   base.Add(time.Hour),
		now:   fixedClock(base.Add(3 * time.Hour)),
	})

	assert.Contains(t, got, "included parent")
	assert.Contains(t, got, "included frame")
	assert.Contains(t, got, "included frame two")
	assert.NotContains(t, got, "excluded parent")
	assert.NotContains(t, got, "excluded frame",
		"a continuation line must be excluded along with the entry it belongs to")
}

func TestActiveFileSourcePartialTrailingLine(t *testing.T) {
	base := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)

	// The async writer flushes on byte thresholds, so a reader can catch the
	// tail mid-line.  A fragment is not yet a record; treating it as one would
	// hand the caller a truncated entry.
	content := logLine(base.Add(time.Minute), "info", "complete entry") +
		`time="2026-08-20T15:30:00Z" level=info msg="truncated mid`

	src := writeLog(t, content)
	got := readWindow(t, src, &timeWindowSelector{
		start: base,
		end:   base.Add(time.Hour),
		now:   fixedClock(base.Add(3 * time.Hour)),
	})

	assert.Contains(t, got, "complete entry")
	assert.NotContains(t, got, "truncated mid",
		"a line still being written must be dropped, not served half-formed")
}

func TestActiveFileSourceOutOfOrderTimestamps(t *testing.T) {
	base := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)

	// Concurrent goroutines and clock steps can transpose neighbouring
	// entries.  A scan that stopped at the first entry past the window would
	// silently drop everything after the transposition.
	src := writeLog(t, strings.Join([]string{
		logLine(base.Add(10*time.Minute), "info", "first"),
		logLine(base.Add(61*time.Minute), "info", "briefly past the end"),
		logLine(base.Add(20*time.Minute), "info", "back inside the window"),
		logLine(base.Add(30*time.Minute), "info", "still inside"),
	}, ""))

	got := readWindow(t, src, &timeWindowSelector{
		start: base,
		end:   base.Add(time.Hour),
		now:   fixedClock(base.Add(3 * time.Hour)),
	})

	assert.Contains(t, got, "first")
	assert.Contains(t, got, "back inside the window",
		"an out-of-order entry must not truncate the scan")
	assert.Contains(t, got, "still inside")
	assert.NotContains(t, got, "briefly past the end")
}

func TestActiveFileSourceMissingFile(t *testing.T) {
	base := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)

	// Logs only reach a file once FlushLogs pushes them there, so a server
	// can be serving before the file exists.  That is an empty answer, not an
	// error.
	src := &activeFileSource{path: filepath.Join(t.TempDir(), "absent.log")}

	sel := &timeWindowSelector{start: base, end: base.Add(time.Hour), now: fixedClock(base)}
	assert.Empty(t, readWindow(t, src, sel))

	_, ok := coverageOf(t, src)
	assert.False(t, ok, "a missing file covers nothing")
}

func TestActiveFileSourceCoverage(t *testing.T) {
	base := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)

	t.Run("reports the oldest entry", func(t *testing.T) {
		src := writeLog(t, logLine(base, "info", "first")+logLine(base.Add(time.Hour), "info", "second"))
		oldest, ok := coverageOf(t, src)
		require.True(t, ok)
		assert.Equal(t, base, oldest.UTC())
	})

	t.Run("skips leading unparseable lines", func(t *testing.T) {
		src := writeLog(t, "not a log line at all\n"+logLine(base, "info", "first"))
		oldest, ok := coverageOf(t, src)
		require.True(t, ok)
		assert.Equal(t, base, oldest.UTC())
	})

	t.Run("an empty file covers nothing", func(t *testing.T) {
		src := writeLog(t, "")
		_, ok := coverageOf(t, src)
		assert.False(t, ok)
	})

	t.Run("a garbage head larger than the scan bound covers nothing", func(t *testing.T) {
		// Coverage is bounded so a pathological file cannot make every request
		// walk it end to end.  Giving up must land on the safe side: covers
		// nothing, so responses are no-store rather than immutable.
		src := writeLog(t, strings.Repeat("x", maxEntrySize+1)+"\n"+logLine(base, "info", "buried"))
		_, ok := coverageOf(t, src)
		assert.False(t, ok)
	})
}

func TestActiveFileReaderSurvivesRotation(t *testing.T) {
	base := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)
	src := writeLog(t, logLine(base.Add(time.Minute), "info", "pinned entry"))

	// The reason Open exists: coverage and the streamed body must describe the
	// same bytes even if rotation renames the file mid-request.  The open
	// descriptor keeps the original contents readable after the rename.
	reader, err := src.Open(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()

	require.NoError(t, os.Rename(src.path, src.path+".rotated"))

	oldest, ok, err := reader.Coverage(context.Background())
	require.NoError(t, err)
	require.True(t, ok, "the pinned view must still cover what it covered at open time")
	assert.Equal(t, base.Add(time.Minute), oldest.UTC())

	var sb strings.Builder
	require.NoError(t, reader.Read(context.Background(), &timeWindowSelector{
		start: base,
		end:   base.Add(time.Hour),
		now:   fixedClock(base.Add(3 * time.Hour)),
	}, &sb))
	assert.Contains(t, sb.String(), "pinned entry")
}

func TestActiveFileSourceSeeksRatherThanScanning(t *testing.T) {
	// The point of the search: a window at the end of a large file must not
	// cost a full read.  The most recent servable hour is the likeliest query
	// and would otherwise be the most expensive one.
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	var sb strings.Builder
	const entries = 40000
	for i := 0; i < entries; i++ {
		sb.WriteString(logLine(base.Add(time.Duration(i)*time.Second), "info",
			fmt.Sprintf("padding entry %06d to give the file some size", i)))
	}
	src := writeLog(t, sb.String())

	info, err := os.Stat(src.path)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(4*seekSlack),
		"the fixture must be large enough for the search to have somewhere to go")

	f, err := os.Open(src.path)
	require.NoError(t, err)
	defer f.Close()
	fileReader := &activeFileReader{f: f, path: src.path}

	// Ask for a window near the end of the file.
	target := base.Add(time.Duration(entries-100) * time.Second)
	offset, err := fileReader.findOffset(context.Background(), target)
	require.NoError(t, err)

	assert.Greater(t, offset, int64(0), "a late window must not be read from the start of the file")
	assert.Less(t, offset, info.Size(), "the offset must stay inside the file")

	// And the seek must not have overshot: reading from it still finds the
	// window.  This is the half that matters -- a fast answer that misses
	// entries is worse than a slow one.
	got := readWindow(t, src, &timeWindowSelector{
		start: target,
		end:   target.Add(time.Hour),
		now:   fixedClock(base.Add(24 * time.Hour)),
	})
	assert.Contains(t, got, fmt.Sprintf("padding entry %06d", entries-100))
	assert.Contains(t, got, fmt.Sprintf("padding entry %06d", entries-1))
	assert.NotContains(t, got, fmt.Sprintf("padding entry %06d", entries-101),
		"the entry just before the window must still be excluded")
}

func TestActiveFileSourceEarlyWindowInLargeFile(t *testing.T) {
	// The mirror of the previous test: an early window must not require
	// reading backward from the end.  Correctness is what is asserted here;
	// the search direction is an implementation detail.
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	var sb strings.Builder
	for i := 0; i < 40000; i++ {
		sb.WriteString(logLine(base.Add(time.Duration(i)*time.Second), "info",
			fmt.Sprintf("padding entry %06d to give the file some size", i)))
	}
	src := writeLog(t, sb.String())

	got := readWindow(t, src, &timeWindowSelector{
		start: base,
		end:   base.Add(time.Hour),
		now:   fixedClock(base.Add(24 * time.Hour)),
	})
	assert.Contains(t, got, "padding entry 000000")
	assert.Contains(t, got, "padding entry 003599")
	assert.NotContains(t, got, "padding entry 003600", "3600s in is the exclusive end of the window")
}

func TestLogEntryFieldsAreLazy(t *testing.T) {
	ts := time.Date(2026, 8, 20, 15, 0, 0, 0, time.UTC)
	e := &logEntry{
		Timestamp: ts,
		Raw:       []byte(logLine(ts, "info", "hello world") + "\tcontinuation\n"),
	}

	// Nothing has asked for a field, so nothing has been tokenised.  A time
	// window query never needs the fields, and paying to split every
	// key=value pair on every line of a large file would be work spent for
	// a question nobody asked.
	assert.False(t, e.parsed, "fields must not be parsed until they are requested")

	level, ok := e.Field("level")
	require.True(t, ok)
	assert.Equal(t, "info", level)
	assert.True(t, e.parsed)

	msg, ok := e.Field("msg")
	require.True(t, ok)
	assert.Equal(t, "hello world", msg, "a quoted value must come back unquoted")

	_, ok = e.Field("no_such_field")
	assert.False(t, ok)
}

func TestParseEntryTime(t *testing.T) {
	ts := time.Date(2026, 8, 20, 15, 4, 5, 0, time.UTC)

	t.Run("quoted, as logrus writes it", func(t *testing.T) {
		got, ok := parseEntryTime([]byte(`time="2026-08-20T15:04:05Z" level=info msg="x"`))
		require.True(t, ok)
		assert.Equal(t, ts, got.UTC())
	})

	t.Run("unquoted is accepted too", func(t *testing.T) {
		got, ok := parseEntryTime([]byte(`time=2026-08-20T15:04:05Z level=info`))
		require.True(t, ok)
		assert.Equal(t, ts, got.UTC())
	})

	t.Run("an offset other than UTC is honoured", func(t *testing.T) {
		got, ok := parseEntryTime([]byte(`time="2026-08-20T17:04:05+02:00" level=info`))
		require.True(t, ok)
		assert.True(t, got.Equal(ts), "entries carry their own offset; matching compares instants")
	})

	for _, line := range []string{
		`\tgoroutine 1 [running]:`,
		`level=info msg="no time field"`,
		`time="not a timestamp" level=info`,
		``,
	} {
		t.Run("rejects "+line, func(t *testing.T) {
			_, ok := parseEntryTime([]byte(line))
			assert.False(t, ok)
		})
	}
}
