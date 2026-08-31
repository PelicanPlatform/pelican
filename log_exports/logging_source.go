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

// Selection and reading for the logging namespace.
//
// A request names a set of log entries.  Today the only way to name them is a
// time window, but the eventual goal is for selecting by job UUID, so the
// query is modelled as a *predicate* (logSelector) rather than as a pair of
// timestamps.

package log_exports

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// logSelector decides which log entries belong in a response.
//
// Implementations must be safe for concurrent use: one selector is built per
// request, but the source may consult it from a read loop.
type logSelector interface {
	// Matches reports whether an entry belongs in the response.
	Matches(e *logEntry) bool

	// Bounds is an optional time range the source may use to avoid reading
	// the whole file.  Zero values mean unbounded, which obliges the source
	// to consider every entry.  Bounds is an optimisation hint only --
	// correctness comes from Matches.
	Bounds() (start, end time.Time)

	// Cacheable reports whether this selector names a stable set of entries,
	// i.e. whether the same URL will keep meaning the same bytes.  A closed
	// hour bucket does; an in-progress one does not, and neither would a
	// future selector whose answer grows as the log does.
	//
	// This is only half the question -- the source must also still be able to
	// serve the window (see logSource.Coverage).  The handler combines both.
	Cacheable() bool
}

// logSource opens the log for one request.
type logSource interface {
	// Open pins the log so that everything one request learns and serves
	// comes from the same underlying bytes.
	//
	// Coverage and Read used to be separate opens, which left a gap: rotation
	// could rename the file between them, so the coverage check would vouch
	// for an hour and Read would then stream the fresh, nearly-empty
	// replacement -- an empty answer served under an immutable header, which a
	// cache keeps for good.  One open handled to both methods closes that gap:
	// a renamed file stays readable through an already-open descriptor.
	//
	// A source with nothing to serve (no log file yet) returns a reader that
	// covers nothing and streams nothing; that is a normal state, not an
	// error.  The caller owns the returned reader and must Close it.
	Open(ctx context.Context) (logReader, error)
}

// logReader answers one request's questions about the log, all from the same
// pinned view of it.
type logReader interface {
	// Coverage reports the timestamp of the oldest entry this reader can
	// serve.  ok is false when it holds nothing, which is a normal state
	// rather than an error.
	//
	// It exists so the handler can tell "this hour is empty" from "this hour
	// was rotated away and we can no longer see it".  Both stream zero bytes,
	// but only the first may be cached: labelling a rotated-away hour
	// immutable would let a cache pin an empty answer for a real hour.
	Coverage(ctx context.Context) (oldest time.Time, ok bool, err error)

	// Read writes every matching entry to w in file order.
	Read(ctx context.Context, sel logSelector, w io.Writer) error

	io.Closer
}

// timeWindowSelector accepts entries in [start, end).
type timeWindowSelector struct {
	start time.Time
	end   time.Time

	// now lets Cacheable ask whether the window has closed without reaching
	// for the wall clock, which keeps it testable.
	now func() time.Time
}

func (s *timeWindowSelector) Matches(e *logEntry) bool {
	return !e.Timestamp.Before(s.start) && e.Timestamp.Before(s.end)
}

func (s *timeWindowSelector) Bounds() (time.Time, time.Time) {
	return s.start, s.end
}

func (s *timeWindowSelector) Cacheable() bool {
	// An in-progress hour is still being appended to, so the response would
	// be a truncated prefix of what the hour eventually holds.  Only a closed
	// window is a stable answer.
	//
	// The handler refuses an unsettled window outright, so in practice
	// anything reaching here has already passed a stricter test.  Keeping the
	// check is cheap insurance on the one mistake that cannot be undone: a
	// cache that stored a truncated hour keeps it, because Cache-Control
	// decides whether a response is stored and not whether a stored one is
	// dropped.
	return !s.end.After(s.now())
}

// logEntry is one log record: a leading timestamped line plus any continuation
// lines that followed it.
//
// Non-timestamp fields are tokenised on demand.  Only a future UUID selector
// needs them, and splitting every key=value pair on every line of a 100MB file
// to answer a question about timestamps would be work spent for nothing.
type logEntry struct {
	Timestamp time.Time

	// Raw is the entry exactly as it appeared, continuation lines included,
	// with its trailing newline.  Responses stream this verbatim so a caller
	// gets the same bytes the log holds.
	Raw []byte

	fields map[string]string
	parsed bool
}

// Field returns a logrus field from the entry's first line.
func (e *logEntry) Field(name string) (string, bool) {
	if !e.parsed {
		e.fields = parseEntryFields(e.Raw)
		e.parsed = true
	}
	v, ok := e.fields[name]
	return v, ok
}

// parseEntryFields tokenises the `key=value` and `key="quoted value"` pairs on
// an entry's first line.  It is intentionally forgiving: a malformed pair is
// skipped rather than failing the entry, because a log line we cannot fully
// understand is still a log line the caller asked for.
func parseEntryFields(raw []byte) map[string]string {
	fields := make(map[string]string)

	line := raw
	if idx := bytes.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	s := string(line)

	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			break
		}
		key := s[:eq]
		s = s[eq+1:]

		var value string
		if strings.HasPrefix(s, `"`) {
			s = s[1:]
			// Find the closing quote, honouring backslash escapes.
			var b strings.Builder
			i := 0
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '"' {
					break
				}
				b.WriteByte(s[i])
				i++
			}
			value = b.String()
			if i < len(s) {
				s = s[i+1:]
			} else {
				s = ""
			}
		} else {
			sp := strings.IndexByte(s, ' ')
			if sp < 0 {
				value, s = s, ""
			} else {
				value, s = s[:sp], s[sp:]
			}
		}
		fields[key] = value
	}

	return fields
}

// timeFieldPrefix is how every log line written to the file begins.
const timeFieldPrefix = `time=`

// parseEntryTime pulls the timestamp off a log line, reporting whether the
// line begins an entry at all.  A line that does not is a continuation --
// wrapped panic output, a stack trace -- and belongs to the entry above it.
//
// The unquoted form is accepted too.  Nothing writes it today, but a parser
// that only understands one spelling of its input is a parser that breaks the
// day a formatter option changes.
func parseEntryTime(line []byte) (time.Time, bool) {
	if !bytes.HasPrefix(line, []byte(timeFieldPrefix)) {
		return time.Time{}, false
	}
	rest := line[len(timeFieldPrefix):]

	var raw []byte
	if len(rest) > 0 && rest[0] == '"' {
		rest = rest[1:]
		end := bytes.IndexByte(rest, '"')
		if end < 0 {
			return time.Time{}, false
		}
		raw = rest[:end]
	} else {
		end := bytes.IndexByte(rest, ' ')
		if end < 0 {
			raw = rest
		} else {
			raw = rest[:end]
		}
	}

	ts, err := time.Parse(time.RFC3339, string(raw))
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// activeFileSource reads the log file Pelican is currently writing.
type activeFileSource struct {
	path string
}

// Tuning for the search that locates a window inside the file.
const (
	// seekSlack is how far to rewind from a binary-search hit before scanning
	// forward.  The search assumes timestamps increase down the file, which is
	// very nearly true but not exactly: concurrent goroutines and clock steps
	// can transpose neighbouring entries.  Rewinding means the search only has
	// to land close, and Matches does the deciding.
	seekSlack = 128 << 10

	// scanTolerance is how far past the window's end to keep reading before
	// concluding the remainder of the file is beyond it.  Stopping at the very
	// first out-of-window entry would silently truncate a response whenever
	// two entries were written out of order across the boundary.
	scanTolerance = 5 * time.Minute

	// readBufSize bounds the memory used per request.  Entries stream out as
	// they are matched, so this only has to hold one line.
	readBufSize = 64 << 10

	// maxEntrySize caps how large a single entry may grow before it is passed
	// along as-is.  A runaway line should not become a runaway allocation.
	maxEntrySize = 1 << 20
)

func (s *activeFileSource) Open(ctx context.Context) (logReader, error) {
	f, err := os.Open(s.path)
	if err != nil {
		// A missing log file is expected rather than exceptional: logs are
		// only pushed to a file once FlushLogs does so, and a server can be
		// serving before that happens.
		if os.IsNotExist(err) {
			return emptyLogReader{}, nil
		}
		return nil, errors.Wrapf(err, "unable to open log file %s", s.path)
	}
	return &activeFileReader{f: f, path: s.path}, nil
}

// emptyLogReader is what opening an absent log yields: it covers nothing and
// streams nothing, and both of those are answers rather than errors.
type emptyLogReader struct{}

func (emptyLogReader) Coverage(context.Context) (time.Time, bool, error) {
	return time.Time{}, false, nil
}
func (emptyLogReader) Read(context.Context, logSelector, io.Writer) error {
	return nil
}
func (emptyLogReader) Close() error { return nil }

// activeFileReader serves one request from one open descriptor.  Rotation may
// rename the file at any moment; the descriptor keeps the renamed file's
// contents visible, so Coverage and Read cannot disagree about which file they
// are describing.
type activeFileReader struct {
	f    *os.File
	path string
}

func (r *activeFileReader) Close() error { return r.f.Close() }

func (r *activeFileReader) Coverage(ctx context.Context) (time.Time, bool, error) {
	if _, err := r.f.Seek(0, io.SeekStart); err != nil {
		return time.Time{}, false, errors.Wrapf(err, "unable to seek log file %s", r.path)
	}

	// The scan is bounded: normally the very first line is an entry, but a
	// file whose head is unparsable garbage must not make every request walk
	// it end to end looking for one.  Giving up reports "covers nothing",
	// which errs in the safe direction -- the response becomes no-store rather
	// than immutable.
	scanner := bufio.NewScanner(io.LimitReader(r.f, maxEntrySize))
	scanner.Buffer(make([]byte, 0, readBufSize), maxEntrySize)
	for scanner.Scan() {
		if ts, ok := parseEntryTime(scanner.Bytes()); ok {
			return ts, true, nil
		}
		if err := ctx.Err(); err != nil {
			return time.Time{}, false, err
		}
	}
	if err := scanner.Err(); err != nil {
		// A head with no line break inside the bound overflows the scanner
		// before it can see EOF.  That is the bound doing its job, not a read
		// failure: nothing parseable was found, so nothing is provably
		// covered.
		if errors.Is(err, bufio.ErrTooLong) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, errors.Wrapf(err, "unable to read log file %s", r.path)
	}
	// Empty, all garbage, or garbage past the bound: nothing provably covered.
	return time.Time{}, false, nil
}

func (r *activeFileReader) Read(ctx context.Context, sel logSelector, w io.Writer) error {
	start, end := sel.Bounds()

	offset := int64(0)
	if !start.IsZero() {
		var err error
		if offset, err = r.findOffset(ctx, start); err != nil {
			return err
		}
	}
	if _, err := r.f.Seek(offset, io.SeekStart); err != nil {
		return errors.Wrapf(err, "unable to seek log file %s", r.path)
	}

	return r.scan(ctx, offset, sel, end, w)
}

// findOffset returns a byte offset at or before the first entry not older than
// target, so a forward scan from there sees the whole window.
//
// This is a binary search rather than a scan from either end because the two
// obvious alternatives are each wrong for a common case: scanning forward from
// the start reads the entire file to answer a query for the most recent
// servable hour, which sits at the end of the file and is the likeliest
// request, while scanning backward from the end reads the entire file to
// answer a question about this morning.  A search costs a handful of seeks
// either way.
func (r *activeFileReader) findOffset(ctx context.Context, target time.Time) (int64, error) {
	info, err := r.f.Stat()
	if err != nil {
		return 0, errors.Wrapf(err, "unable to stat log file %s", r.path)
	}
	size := info.Size()
	if size <= seekSlack {
		return 0, nil
	}

	lo, hi := int64(0), size
	for hi-lo > seekSlack {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		mid := lo + (hi-lo)/2
		ts, found, err := r.firstEntryAt(mid, hi)
		if err != nil {
			return 0, err
		}
		if !found {
			// No parseable entry between mid and hi; the answer, if any, is
			// below mid.
			hi = mid
			continue
		}
		if ts.Before(target) {
			lo = mid
		} else {
			hi = mid
		}
	}

	// Rewind past the resolution of the search so slightly out-of-order
	// entries just before the boundary are still seen.
	if lo < seekSlack {
		return 0, nil
	}
	return lo - seekSlack, nil
}

// firstEntryAt returns the timestamp of the first entry beginning at or after
// off, without consuming the partial line off may land in the middle of.
func (r *activeFileReader) firstEntryAt(off, limit int64) (time.Time, bool, error) {
	if _, err := r.f.Seek(off, io.SeekStart); err != nil {
		return time.Time{}, false, errors.Wrapf(err, "unable to seek log file %s", r.path)
	}
	reader := bufio.NewReaderSize(io.LimitReader(r.f, limit-off), readBufSize)

	// Unless we happen to be at the very beginning, the first line is almost
	// certainly a fragment of the line that straddles off.  Drop it.
	if off > 0 {
		if _, err := reader.ReadBytes('\n'); err != nil {
			return time.Time{}, false, nil
		}
	}

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if ts, ok := parseEntryTime(bytes.TrimRight(line, "\r\n")); ok {
				return ts, true, nil
			}
		}
		if err != nil {
			// io.EOF here just means we ran out of window, not out of file.
			return time.Time{}, false, nil
		}
	}
}

// scan walks entries forward from offset, writing the ones the selector
// accepts, and stops once the file has clearly moved past end.
func (r *activeFileReader) scan(ctx context.Context, offset int64, sel logSelector, end time.Time, w io.Writer) error {
	reader := bufio.NewReaderSize(r.f, readBufSize)

	// Unless we began at the very start of the file, the first line is a
	// fragment of whichever line straddles offset.  Drop it.
	if offset > 0 {
		if _, err := reader.ReadBytes('\n'); err != nil {
			return nil
		}
	}

	var (
		current  *logEntry
		stopTime time.Time
	)
	if !end.IsZero() {
		stopTime = end.Add(scanTolerance)
	}

	// flush emits the entry just completed, if the selector wants it.
	flush := func() error {
		if current == nil {
			return nil
		}
		e := current
		current = nil
		if !sel.Matches(e) {
			return nil
		}
		_, err := w.Write(e.Raw)
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		line, readErr := reader.ReadBytes('\n')

		// ReadBytes only returns an error when it did not find the delimiter,
		// so a non-nil error with bytes in hand means the writer was caught
		// mid-flush.  A fragment is not yet a record, so it is not ours to
		// interpret: drop it and finish with what we already have.
		partial := readErr != nil && len(line) > 0

		if len(line) > 0 && !partial {
			if ts, ok := parseEntryTime(bytes.TrimRight(line, "\r\n")); ok {
				if err := flush(); err != nil {
					return err
				}
				if !stopTime.IsZero() && ts.After(stopTime) {
					// Far enough past the window that the rest of the file
					// cannot plausibly belong to it.
					return nil
				}
				current = &logEntry{Timestamp: ts, Raw: line}
			} else if current != nil && len(current.Raw)+len(line) <= maxEntrySize {
				// Continuation of the entry above -- a stack trace, or a
				// message containing a newline.  It shares that entry's fate.
				current.Raw = append(current.Raw, line...)
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				return flush()
			}
			return errors.Wrapf(readErr, "unable to read log file %s", r.path)
		}
	}
}
