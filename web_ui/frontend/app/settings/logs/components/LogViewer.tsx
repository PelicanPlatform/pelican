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

'use client';

import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  FormControlLabel,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import React, {
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import useSWR from 'swr';

import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '@/helpers/api/constants';

// -----------------------------------------------------------------------------
// Server payload shape -- one endpoint, two directions.
//
// The tail endpoint takes either ?since=<cursor> (forward polling / live
// tail) or ?before=<cursor>&count=<n> (scroll-up into older history).
// Cursors are opaque URL-safe base64 tokens: the client stores them as
// strings, echoes them back, and never interprets or does arithmetic on
// them. Reached is true when scroll-up has hit the wall.
// -----------------------------------------------------------------------------

interface LogTailResponse {
  enabled: boolean;
  content: string;
  firstCursor: string;
  lastCursor: string;
  reached: boolean;
  // Count of lines missing between our cursor and the start of `content`,
  // evicted or trimmed before we asked for them. Non-zero means the
  // content is not contiguous with what we already hold.
  dropped: number;
  // instanceId identifies the server's buffer. It changes on restart;
  // the viewer resets local state when it changes so cursors from a
  // previous instance don't leak into requests against the new one.
  instanceId: string;
  // RFC3339 stamps bracketing everything the server's buffer holds -- what a
  // download would contain, which is more than this viewer has necessarily
  // paged in. Absent when the buffer holds nothing datable.
  bufferOldest?: string;
  bufferNewest?: string;
}

// -----------------------------------------------------------------------------
// Level filter -- keep in the fixed logrus order (panic..trace) so the chip
// row reads left-to-right the way an operator expects.
// -----------------------------------------------------------------------------

const LOG_LEVELS = [
  'panic',
  'fatal',
  'error',
  'warning',
  'info',
  'debug',
  'trace',
];

const LEVEL_COLORS: Record<string, string> = {
  panic: '#ff5252',
  fatal: '#ff5252',
  error: '#ff8a80',
  warning: '#ffb74d',
  info: '#82b1ff',
  // Debug and trace read as off-white on the dark panel so they stay
  // legible without stealing focus from warning/error rows above.
  debug: '#e0e0e0',
  trace: '#bdbdbd',
};

// Regex that pulls the level token out of a formatted line. Logrus's
// TextFormatter emits `level=<name>`; DisableColors on the server side
// means no ANSI escapes to strip. A line with no level=... is treated as
// "info" so continuation lines from stack traces don't get hidden by a
// level filter.
const LEVEL_REGEX = /\blevel=([a-z]+)\b/;

function extractLevel(line: string): string {
  const m = LEVEL_REGEX.exec(line);
  if (!m) return 'info';
  const raw = m[1];
  // Logrus emits "warning" but many tools shorten to "warn"; normalize.
  return raw === 'warn' ? 'warning' : raw;
}

// Logrus's TextFormatter leads every formatted line with the timestamp:
// `time="2026-07-25T10:00:04Z" level=info msg="..."`. The value is quoted
// whenever it contains characters logrus escapes (an RFC3339 stamp always
// does), but the unquoted form is accepted too so a differently-configured
// formatter still lines up.
const TIME_PREFIX_REGEX = /^time=(?:"([^"]*)"|(\S+))\s*/;

// extractStamp returns the leading timestamp as the server wrote it, or ''
// for a line that has none (a stack trace's continuation lines, for
// instance). It is kept only to date the buffer in the summary line; the row
// itself renders the formatted line unchanged, timestamp included.
function extractStamp(line: string): string {
  const m = TIME_PREFIX_REGEX.exec(line);
  if (!m) return '';
  return m[1] ?? m[2] ?? '';
}

// formatStamp renders a stamp as a local "YYYY-MM-DD HH:MM", or '' if it
// isn't a date this browser can parse -- an unparsable stamp should leave the
// range blank rather than put "Invalid Date" in the summary.
function formatStamp(stamp: string): string {
  if (stamp === '') return '';
  const d = new Date(stamp);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => n.toString().padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    ` ${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

// -----------------------------------------------------------------------------
// LogViewer -- single-endpoint polling with an opaque cursor. State is
// deliberately simple: a flat list of accumulated Lines plus the current
// cursor/oldestSeq pair.
// -----------------------------------------------------------------------------

interface Line {
  text: string;
  level: string;
  // The line's own timestamp, exactly as the server wrote it, or '' when the
  // line carries none. Used to date the buffer in the summary line; see
  // extractStamp.
  stamp: string;
  // Client-local monotonic id (assigned in arrival order) used for
  // React keys and for eviction ordering. Unrelated to any server
  // seq; the cursor is opaque to the client.
  id: number;
  // Marks a placeholder standing in for lines the server dropped before
  // this client could read them, rather than a line the server sent. It
  // occupies a row so the break is visible where it happened; without it
  // the lines on either side read as consecutive.
  gap?: boolean;
}

// gapLine builds the placeholder shown where the server reported missing
// lines.
function gapLine(dropped: number, id: number): Line {
  const plural = dropped === 1 ? 'line' : 'lines';
  const text = `--- ${dropped.toLocaleString()} ${plural} dropped: the server's buffer filled faster than this view could read it ---`;
  return {
    text,
    level: 'gap',
    // A gap is not a record and has no time of its own, so it never dates
    // the buffer.
    stamp: '',
    id,
    gap: true,
  };
}

const POLL_INTERVAL_MS = 2000;
// Client-side memory cap on the accumulated log text. A very long-running
// viewer session can otherwise keep growing local state indefinitely --
// the server-side buffer is a small window, but the client has no such
// cap unless we impose one. When we're over, we drop lines from the oldest
// end until we're back under. The list is virtualized (see ROW_HEIGHT
// below), so the DOM is bounded regardless of how many lines are retained;
// this cap bounds only the JS-side memory held for scroll-back.
const MAX_CLIENT_BYTES = 64 * 1024 * 1024;

// Virtualization: only the rows visible in the viewport (plus a small
// overscan) are mounted in the DOM. Rows are a fixed height so the total
// scroll height is exactly rowCount * ROW_HEIGHT and off-screen rows are
// replaced by top/bottom spacer divs. Without this, a busy server drives
// the accumulated-line count into the hundreds of thousands and mounting
// one DOM node per line freezes or OOMs the tab. ROW_HEIGHT must match the
// per-row lineHeight set in the render below.
const ROW_HEIGHT = 18;
const OVERSCAN_ROWS = 30;

// Floor for the width of the row area, in pixels; see the width calculation
// in the render for why the row area is sized explicitly at all.
const CONTENT_MIN_WIDTH = 1600;

// Fixed width of each level chip, in pixels, and the abbreviation that keeps
// its label inside that width.
//
// This is load-bearing for the pane's width, not just for the toolbar's
// tidiness. The chip label is `nowrap` (MUI clips and ellipsizes it rather
// than wrapping), so a chip's min-content width is its whole label -- and the
// settings shell puts this component in a MUI Grid item, whose `min-width` is
// `auto`, so the item cannot be narrower than the min-content width of what
// is inside it. A chip that grows from "info (2)" to "info (237,394)" therefore
// widens the toolbar, overrides the Grid item's size percentage, and takes the
// log pane's width with it. A fixed width plus a bounded label breaks that
// chain: nothing in the toolbar changes size as the counts climb.
const LEVEL_CHIP_WIDTH = 128;

// formatCount abbreviates a level count so the chip label has a bounded
// length: exact below a thousand, then "12k" / "1.2M". The precise figure is
// in the chip's tooltip, and the summary line under the toolbar always
// carries exact numbers.
function formatCount(n: number): string {
  if (n < 1000) return n.toString();
  if (n < 1_000_000) return `${Math.round(n / 1000)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

// Slack, in characters, added to the widest line when sizing the row area.
// Covers the occasional glyph that is not exactly one character advance wide
// (a non-ASCII byte in a log message, say) so a line still cannot overrun the
// width computed for it.
const CONTENT_WIDTH_SLACK_CH = 4;

// TAIL_LIMIT bounds each forward-poll response. The initial load (empty
// cursor) is the primary reason: on a server configured with a large
// buffer, an unbounded initial fetch could send tens of MB in one go.
// With TAIL_LIMIT the viewer shows the newest N lines immediately;
// older content is available on scroll-up. Steady-state polls are far
// under this cap and remain full-fidelity deltas.
const TAIL_LIMIT = 10000;

async function fetchSince(cursor: string): Promise<LogTailResponse> {
  const resp = await secureFetch(
    `${API_V1_BASE_URL}/logs/tail?since=${encodeURIComponent(
      cursor
    )}&limit=${TAIL_LIMIT}`
  );
  if (!resp.ok) {
    throw new Error(`log tail fetch failed: ${resp.status}`);
  }
  return await resp.json();
}

async function fetchBefore(
  cursor: string,
  count: number
): Promise<LogTailResponse> {
  const resp = await secureFetch(
    `${API_V1_BASE_URL}/logs/tail?before=${encodeURIComponent(
      cursor
    )}&count=${encodeURIComponent(count.toString())}`
  );
  if (!resp.ok) {
    throw new Error(`log tail fetch failed: ${resp.status}`);
  }
  return await resp.json();
}

// splitLines splits the server's raw content into per-line records,
// assigning a client-local id from an increasing counter. The counter is
// caller-owned so appends and prepends can share it without collision --
// prepend uses IDs strictly below the smallest live id; append uses IDs
// strictly above the largest.
function splitLines(text: string, ids: () => number): Line[] {
  const raw = text.split('\n').filter((l) => l.length > 0);
  return raw.map((t) => ({
    text: t,
    level: extractLevel(t),
    stamp: extractStamp(t),
    id: ids(),
  }));
}

// Requested backlog per "load older" click. The server rounds up to whole
// batches, so the client's count is only a lower bound -- keeping it small
// means each scroll-up gesture consumes just one batch's worth of history.
const OLDER_FETCH_COUNT = 100;

// pruneToByteCap drops entries from the head of lines[] until the running
// character total (a proxy for bytes -- accurate for ASCII log output)
// fits within MAX_CLIENT_BYTES. Returns the input unchanged when already
// under cap. Called after both appends (live tail) and prepends (scroll-up).
function pruneToByteCap(lines: Line[]): Line[] {
  let total = 0;
  for (const line of lines) total += line.text.length + 1;
  if (total <= MAX_CLIENT_BYTES) return lines;
  let dropUntil = 0;
  while (dropUntil < lines.length && total > MAX_CLIENT_BYTES) {
    total -= lines[dropUntil].text.length + 1;
    dropUntil++;
  }
  return lines.slice(dropUntil);
}

export default function LogViewer() {
  const [lines, setLines] = useState<Line[]>([]);
  // null means "no level filter" -- every level is shown. It is a distinct
  // state from an explicit selection that happens to list all seven levels,
  // and the distinction is what lets the first click on a chip narrow to that
  // level while a later click on an already-selected chip removes it. See
  // onLevelClick.
  const [selectedLevels, setSelectedLevels] = useState<string[] | null>(null);
  const [textFilter, setTextFilter] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [reachedOldest, setReachedOldest] = useState(false);
  // Running total of lines the server reported dropped before this view
  // could read them. Each one is marked in place by a gap row; the total is
  // also summarized above the pane, because that is where an operator looks
  // to find out whether the numbers they are reading are the whole story.
  const [droppedTotal, setDroppedTotal] = useState(0);
  // What the server's whole buffer spans, straight from the last poll -- the
  // extent of a download, which is not something this viewer can work out from
  // the lines it happens to hold. Reported under the download control.
  const [bufferSpan, setBufferSpan] = useState<{
    oldest: string;
    newest: string;
  } | null>(null);
  // Virtualization viewport: the current scroll offset and the pane's pixel
  // height drive which slice of lines is mounted. Updated on scroll and on
  // resize.
  const [viewport, setViewport] = useState({ scrollTop: 0, height: 0 });

  // Cursors: opaque strings the server echoes back. sinceRef advances on
  // every live-tail poll; beforeRef is anchored on first content and
  // walks backwards each "load older" click.
  const sinceRef = useRef<string>('');
  const beforeRef = useRef<string>('');
  // Client-local id counters: appendIdRef increments as new lines arrive
  // via live tail; prependIdRef decrements as older lines arrive via
  // scroll-up. The two never collide because they start on opposite
  // sides of the same number line.
  const appendIdRef = useRef<number>(0);
  const prependIdRef = useRef<number>(0);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  // instanceIdRef tracks the server buffer we're talking to. A change
  // indicates a restart -- our cursors are meaningless against the new
  // buffer, so we clear local state before applying the response.
  const instanceIdRef = useRef<string>('');

  useSWR(
    'log-viewer-tail',
    async () => {
      let resp: LogTailResponse;
      try {
        resp = await fetchSince(sinceRef.current);
      } catch (e) {
        setError((e as Error).message);
        return null;
      }
      setError(null);
      setEnabled(resp.enabled);
      if (!resp.enabled) return resp;

      // Applies whatever the server just said its buffer spans, including
      // across a restart: it describes the buffer that answered this poll, not
      // the local state being reset below.
      setBufferSpan(
        resp.bufferOldest && resp.bufferNewest
          ? { oldest: resp.bufferOldest, newest: resp.bufferNewest }
          : null
      );

      // Restart detection: the buffer answering us is not the one we were
      // reading. Everything held describes a server that is gone, so it is
      // discarded here rather than by reloading the page -- the viewer
      // picks the new server's log up on the following poll.
      if (
        instanceIdRef.current !== '' &&
        resp.instanceId !== instanceIdRef.current
      ) {
        setLines([]);
        beforeRef.current = '';
        appendIdRef.current = 0;
        prependIdRef.current = 0;
        setReachedOldest(false);
        // The drop total described the previous instance's buffer.
        setDroppedTotal(0);
        // The cursor must go too. The server does not know a cursor
        // belongs to a previous instance -- it only compares sequence
        // numbers, and a restarted buffer numbers from the beginning
        // again. A cursor carried across a restart is therefore ahead of
        // everything the new buffer holds, so the server keeps returning
        // nothing and echoing the cursor back, and the viewer stays empty
        // for as long as it takes the new server to out-count the old
        // one. Start from an empty cursor instead.
        sinceRef.current = '';
        instanceIdRef.current = resp.instanceId;
        // This response was computed against a cursor that meant nothing
        // to the server that answered; discard it and let the next poll
        // load the new buffer from the start.
        return resp;
      }
      instanceIdRef.current = resp.instanceId;

      // A reported gap is only meaningful once something is already on
      // screen: on the very first load, and on the reset that follows a
      // server restart, there is no earlier content for the missing lines
      // to be missing from. Claim the marker's id before splitting the new
      // content so ids stay in list order.
      const gap =
        resp.dropped > 0 && sinceRef.current !== ''
          ? gapLine(resp.dropped, ++appendIdRef.current)
          : null;
      const fresh = splitLines(resp.content, () => ++appendIdRef.current);

      if (gap) {
        setLines((prev) =>
          prev.length > 0 ? pruneToByteCap(prev.concat(gap)) : prev
        );
        setDroppedTotal((prev) => prev + resp.dropped);
      }
      if (fresh.length > 0) {
        setLines((prev) => pruneToByteCap(prev.concat(fresh)));
      }
      sinceRef.current = resp.lastCursor;
      // Anchor the "before" cursor to the earliest content the server
      // gave us on the first response. Subsequent live-tail responses
      // don't move it -- scroll-up walks it further back independently.
      if (beforeRef.current === '' && fresh.length > 0) {
        beforeRef.current = resp.firstCursor;
      }
      return resp;
    },
    { refreshInterval: POLL_INTERVAL_MS, revalidateOnFocus: true }
  );

  // Load-older: fetch a batch of lines before `beforeRef` and prepend
  // them. Turns off auto-scroll for the duration of the scroll-up
  // session so the incoming live-tail poll doesn't yank the viewport
  // back to the bottom while the user is reading older content.
  const loadOlder = useCallback(async () => {
    if (loadingOlder || reachedOldest) return;
    const before = beforeRef.current;
    if (!before) return;
    // Pin the instance we're paging within. If the server restarts (or a
    // concurrent live-tail poll resets our state) while this fetch is in
    // flight, the response belongs to a previous buffer instance and must be
    // discarded rather than spliced into the freshly reset list.
    const requestInstanceId = instanceIdRef.current;
    setAutoScroll(false);
    setLoadingOlder(true);
    try {
      const resp = await fetchBefore(before, OLDER_FETCH_COUNT);
      if (!resp.enabled) {
        setEnabled(false);
        return;
      }
      if (
        requestInstanceId !== '' &&
        (resp.instanceId !== requestInstanceId ||
          instanceIdRef.current !== requestInstanceId)
      ) {
        return;
      }
      const fresh = splitLines(resp.content, () => --prependIdRef.current);
      if (fresh.length > 0) {
        // Preserve scroll offset: remember the current geometry, then
        // restore the scroll delta so the user's viewport doesn't jump.
        const el = scrollRef.current;
        const priorScrollHeight = el ? el.scrollHeight : 0;
        const priorScrollTop = el ? el.scrollTop : 0;
        setLines((prev) => pruneToByteCap(fresh.concat(prev)));
        beforeRef.current = resp.firstCursor;
        requestAnimationFrame(() => {
          if (!el) return;
          el.scrollTop = priorScrollTop + (el.scrollHeight - priorScrollHeight);
        });
      }
      // Off-the-wall detection: server reports no history left.
      if (resp.reached) {
        setReachedOldest(true);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoadingOlder(false);
    }
  }, [loadingOlder, reachedOldest]);

  // Level counts across the accumulated buffer (not filtered) so chip
  // labels can render "info (12,345)" alongside each option.
  const levelCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const lvl of LOG_LEVELS) counts[lvl] = 0;
    for (const line of lines) {
      if (line.gap) continue;
      counts[line.level] = (counts[line.level] || 0) + 1;
    }
    return counts;
  }, [lines]);

  // Filtering runs over every accumulated line, and the accumulated set
  // reaches the hundreds of thousands on a busy server -- enough for one
  // re-filter to cost long enough to feel. Deferring the filter inputs lets
  // React paint the keystroke (and the "Filtering…" indicator) against the
  // previous result first, then re-render with the new one at lower
  // priority, so the controls never feel stuck. `filtering` is true exactly
  // while the displayed rows are still the pre-change ones.
  const deferredLevels = useDeferredValue(selectedLevels);
  const deferredTextFilter = useDeferredValue(textFilter);
  const filtering =
    deferredLevels !== selectedLevels || deferredTextFilter !== textFilter;

  const visibleLines = useMemo(() => {
    // No selection means no level test at all, rather than a test against the
    // seven levels in LOG_LEVELS. The difference matters for a line whose
    // level is none of them -- `level=notice`, or whatever a library logging
    // through Pelican emits -- which a whitelist would hide by default, with
    // no chip on screen to turn it back on. The default view shows everything
    // the server sent.
    const levelSet = deferredLevels === null ? null : new Set(deferredLevels);
    const filter = deferredTextFilter.toLowerCase();
    return lines.filter((line) => {
      // Gap markers are not log lines and carry no level; hiding one
      // behind a level or text filter would restore the very illusion of
      // contiguity it exists to break.
      if (line.gap) return true;
      if (levelSet && !levelSet.has(line.level)) return false;
      // Matched against the line as the server formatted it, which is a
      // superset of what the row displays: the timestamp moves to the
      // gutter but is still on screen, so a match there is still a match
      // the operator can see.
      if (filter && !line.text.toLowerCase().includes(filter)) return false;
      return true;
    });
  }, [lines, deferredLevels, deferredTextFilter]);

  // Gap markers occupy a row but are not log lines, so they are excluded
  // from the counts an operator reads as "how much am I looking at".
  const visibleLineCount = useMemo(
    () => visibleLines.reduce((n, line) => n + (line.gap ? 0 : 1), 0),
    [visibleLines]
  );
  const totalLineCount = useMemo(
    () => lines.reduce((n, line) => n + (line.gap ? 0 : 1), 0),
    [lines]
  );

  // The dates the buffer spans, for the right-hand end of the summary line:
  // "which days am I looking at" is the other half of "how many lines am I
  // looking at", and it is not otherwise answerable without scrolling to both
  // ends of the pane.
  //
  // Just the two ends of lines[]: the list is in arrival order, so the first
  // and last entry date the whole of it -- no scan. The only reason this is
  // not literally lines[0] and lines[at(-1)] is that not every entry carries a
  // timestamp: a stack trace's continuation lines don't, and neither do gap
  // markers, so an end that has no date falls inward to the next line that
  // does. In practice that stops on the first or second try.
  //
  // Both ends are always shown, to the minute: at this buffer size they are
  // usually the same day, and the times are what distinguish them.
  const dateRange = useMemo(() => {
    let first = '';
    for (const line of lines) {
      first = formatStamp(line.stamp);
      if (first !== '') break;
    }
    let last = '';
    for (let i = lines.length - 1; i >= 0; i--) {
      last = formatStamp(lines[i].stamp);
      if (last !== '') break;
    }
    if (first === '' || last === '') return '';
    return `${first} - ${last}`;
  }, [lines]);

  // Levels that get a chip: the ones actually present in what the viewer
  // holds. A "panic (0)" chip is a control that can only ever empty the pane,
  // and on a healthy server most of the row is those -- the levels that do
  // have lines are what an operator is scanning for. A level still in the
  // selection keeps its chip even at zero, so a selection is always
  // explainable by the chips on screen (and can always be undone), which
  // matters when a level's last line ages out of the buffer while it is
  // selected.
  // Levels outside LOG_LEVELS get a chip too, after the known ones: they are
  // in the buffer and therefore on screen by default, so they need to be
  // filterable like anything else.
  const chipLevels = useMemo(() => {
    const worthShowing = (lvl: string) =>
      (levelCounts[lvl] ?? 0) > 0 || (selectedLevels?.includes(lvl) ?? false);
    const known = LOG_LEVELS.filter(worthShowing);
    const unknown = Object.keys(levelCounts)
      .filter((lvl) => !LOG_LEVELS.includes(lvl) && worthShowing(lvl))
      .sort();
    return [...known, ...unknown];
  }, [levelCounts, selectedLevels]);

  // Character count of the longest line held, which is what the row area is
  // sized from. Measured over everything accumulated rather than over the
  // filtered or mounted subset on purpose: a width that depends on which
  // rows are on screen is exactly the width that moves while you scroll.
  const maxLineChars = useMemo(() => {
    let max = 0;
    for (const line of lines) {
      const len = line.text.length;
      if (len > max) max = len;
    }
    return max;
  }, [lines]);

  // Measure the scroll pane so virtualization knows the viewport height.
  // Runs on mount and on window resize.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const measure = () =>
      setViewport((v) => ({ ...v, height: el.clientHeight }));
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  // Auto-scroll: pin to bottom whenever new content arrives, unless the
  // user has scrolled up. Setting scrollTop fires onScroll, which refreshes
  // the virtualization viewport so the bottom slice mounts.
  useEffect(() => {
    if (!autoScroll || !scrollRef.current) return;
    const el = scrollRef.current;
    el.scrollTop = el.scrollHeight;
  }, [visibleLines, autoScroll]);

  // Re-sync the stored scroll offset with the pane's real one whenever the
  // number of rows changes. A filter that shortens the content makes the
  // browser clamp scrollTop without firing a scroll event we listen for, so
  // the state would otherwise stay stale until the user scrolled -- with
  // auto-scroll off, that means an empty pane that never recovers on its
  // own. Only writes when something actually moved, so this cannot loop.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    setViewport((v) =>
      v.scrollTop === el.scrollTop && v.height === el.clientHeight
        ? v
        : { scrollTop: el.scrollTop, height: el.clientHeight }
    );
  }, [visibleLines.length]);

  // Virtualization window: the contiguous slice of visibleLines currently
  // mounted, with pixel spacers standing in for the rows above and below.
  const rowCount = visibleLines.length;
  const viewportHeight = viewport.height || 600;
  // The offset is clamped to what the filtered content can actually scroll
  // to. Applying a filter shrinks the content, and the browser silently
  // clamps the pane's real scrollTop to the new maximum -- but the offset
  // this render works from is React state, still holding the pre-filter
  // value. Left unclamped it puts the window past the end of the filtered
  // list, so the pane renders no rows at all while the summary above it
  // reports matches: the filter looks broken when it worked. The effect
  // below re-syncs the state; this keeps the render in between correct.
  const maxScrollTop = Math.max(0, rowCount * ROW_HEIGHT - viewportHeight);
  const scrollTop = Math.min(viewport.scrollTop, maxScrollTop);
  const startIdx = Math.max(
    0,
    Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN_ROWS
  );
  const endIdx = Math.min(
    rowCount,
    Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN_ROWS
  );
  const topPad = startIdx * ROW_HEIGHT;
  const bottomPad = Math.max(0, (rowCount - endIdx) * ROW_HEIGHT);
  const windowLines = visibleLines.slice(startIdx, endIdx);

  const onDownload = useCallback(() => {
    window.location.assign(`${API_V1_BASE_URL}/logs/download`);
  }, []);

  // Chip click semantics. A plain click isolates: you get only the level you
  // clicked, which is what clicking one item out of a row of them reads as.
  // Clicking the level you are already isolated on is the way back to all
  // levels. Holding a modifier keeps the old additive behaviour, for building
  // up a combination like error+warning; that is the only way to reach a
  // multi-level selection, and the only way to end up with none selected.
  const onLevelClick = useCallback(
    (lvl: string, additive: boolean) => {
      setSelectedLevels((prev) => {
        // Nothing filtered yet: narrow to the level clicked. Clicking one item
        // out of a row of them reads as "show me this one".
        if (prev === null) {
          return additive ? chipLevels.filter((v) => v !== lvl) : [lvl];
        }
        // A filter is already active, so a level not in it is being added:
        // error then warning gives error+warning, no modifier needed. The
        // selection is rebuilt in chip order -- not LOG_LEVELS order, which
        // would drop any level outside the seven known ones from a selection
        // that already held it -- so it never depends on click order either.
        if (!prev.includes(lvl)) {
          const next = new Set(prev);
          next.add(lvl);
          return chipLevels.filter((v) => next.has(v));
        }
        // Clicking the last level still selected clears the filter -- the way
        // back to everything. Under a modifier it deselects instead, which is
        // the only route to a selection of nothing.
        if (prev.length === 1 && !additive) return null;
        return prev.filter((v) => v !== lvl);
      });
    },
    [chipLevels]
  );

  const scrollToBottom = useCallback(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
    setAutoScroll(true);
  }, []);

  if (!enabled) {
    return (
      <Alert severity='info' sx={{ mt: 1 }}>
        In-memory log capture is not yet available on this server. This is
        normally a transient condition during startup; if it persists, confirm
        the server finished initializing.
      </Alert>
    );
  }

  // The root carries minWidth: 0 so this component can never be the reason
  // its container is wider than the container's own layout says it should be:
  // everything inside is either wrappable, shrinkable, or a scroll container.
  return (
    <Box
      display='flex'
      flexDirection='column'
      gap={2}
      width='100%'
      minWidth={0}
      id={'log-viewer'}
    >
      {error && (
        <Alert severity='warning' onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/*
        Top row: everything that narrows what the pane shows -- the level chips
        and the text filter.

        flexWrap and the minWidth: 0 here and on the children below are the
        other half of the fix described on LEVEL_CHIP_WIDTH: a row of controls
        that refuses to wrap or shrink reports a large min-content width, and
        the Grid item this component sits in (min-width: auto) then sizes
        itself to that instead of to its own size percentage -- so the toolbar
        would set the log pane's width. Allowed to wrap, it grows downwards
        instead, which changes nothing horizontally.
      */}
      <Stack
        direction={{ xs: 'column', md: 'row' }}
        spacing={2}
        alignItems={{ md: 'center' }}
        flexWrap='wrap'
        useFlexGap
        sx={{ minWidth: 0 }}
      >
        {/*
          One chip per level present in the buffer, in the fixed LOG_LEVELS
          order. See onLevelClick for what a click does, which the tooltip
          advertises; and chipLevels for why a level with no lines has no chip.
        */}
        <Box display='flex' flexWrap='wrap' gap={0.75} minWidth={0}>
          {chipLevels.map((lvl) => {
            // A null selection means no level filter, so every chip reads as
            // included.
            const active =
              selectedLevels === null || selectedLevels.includes(lvl);
            const count = levelCounts[lvl] ?? 0;
            return (
              <Chip
                key={lvl}
                size='small'
                clickable
                title={`${count.toLocaleString()} ${lvl} lines held. Click to show only ${lvl}; click again for all levels; hold Ctrl/⌘ or Shift to add or remove one level at a time.`}
                onClick={(e) =>
                  onLevelClick(lvl, e.ctrlKey || e.metaKey || e.shiftKey)
                }
                label={`${lvl} (${formatCount(count)})`}
                sx={{
                  backgroundColor: active
                    ? LEVEL_COLORS[lvl] || '#616161'
                    : 'transparent',
                  color: active ? '#000' : 'text.secondary',
                  border: `1px solid ${LEVEL_COLORS[lvl] || '#616161'}`,
                  fontWeight: active ? 600 : 400,
                  // Fixed, not a floor: see LEVEL_CHIP_WIDTH. Tabular figures
                  // keep the digits from jittering inside it.
                  width: LEVEL_CHIP_WIDTH,
                  flex: '0 0 auto',
                  fontVariantNumeric: 'tabular-nums',
                }}
              />
            );
          })}
        </Box>

        <TextField
          size='small'
          label='Text filter'
          value={textFilter}
          onChange={(e) => setTextFilter(e.target.value)}
          // minWidth: 0 rather than a 220px floor: the floor is a min-content
          // width the Grid item would have to honour, and this field is the
          // widest thing in the row. flexBasis gives it the same comfortable
          // size when there is room, without insisting on it when there
          // isn't.
          sx={{ flexGrow: 1, flexBasis: 220, minWidth: 0 }}
        />
      </Stack>

      {/*
        Bottom row: the controls that act on the view rather than filter it.
        Same wrap-and-shrink rules as the row above.
      */}
      <Stack
        direction='row'
        spacing={2}
        alignItems='center'
        flexWrap='wrap'
        useFlexGap
        sx={{ minWidth: 0 }}
      >
        <FormControlLabel
          control={
            <Checkbox
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
          }
          label='Auto-scroll'
        />

        <Button
          variant='outlined'
          size='small'
          startIcon={<ArrowDownwardIcon />}
          onClick={scrollToBottom}
        >
          Scroll to bottom
        </Button>

        {/*
          The download covers the server's whole buffer, which is typically
          more than this viewer has paged in, so its extent is reported from
          what the server said rather than from the lines on screen -- an admin
          deciding whether to download wants to know what is in the file, not
          what happens to be in this tab. Absent until a poll has reported a
          span, so the button never claims a range it doesn't have.
        */}
        <Stack spacing={0.25} minWidth={0}>
          <Button
            variant='outlined'
            size='small'
            startIcon={<DownloadIcon />}
            onClick={onDownload}
          >
            Download Logs In Buffer
          </Button>
          {bufferSpan && (
            <Typography
              variant='caption'
              color='text.secondary'
              data-testid='log-download-span'
              sx={{ fontVariantNumeric: 'tabular-nums' }}
            >
              Available: {formatStamp(bufferSpan.oldest)} -{' '}
              {formatStamp(bufferSpan.newest)}
            </Typography>
          )}
        </Stack>
      </Stack>

      {/*
        The denominator names its own set. "of 237,394 lines" alone invites
        the reading that the server has 237,394 lines to look at, when what
        it counts is the lines this page has fetched and is still holding --
        a window that starts when the page opens, grows as polls arrive and
        as scroll-up pulls history in, and is trimmed from the oldest end at
        MAX_CLIENT_BYTES. Lines the server dropped before this view could
        read them were never part of it, so they are reported separately
        rather than folded into a count of what is here to read.
      */}
      <Stack
        direction='row'
        spacing={1}
        alignItems='center'
        flexWrap='wrap'
        useFlexGap
        sx={{ minWidth: 0 }}
      >
        <Typography
          variant='body2'
          color='text.secondary'
          data-testid='log-summary'
          sx={{ fontVariantNumeric: 'tabular-nums' }}
        >
          Showing {visibleLineCount.toLocaleString()} of{' '}
          {totalLineCount.toLocaleString()} lines held in this browser.
          {droppedTotal > 0 &&
            ` ${droppedTotal.toLocaleString()} dropped before this view could read them.`}
          {loadingOlder && ' Loading older…'}
          {reachedOldest && ' No more history.'}
        </Typography>
        {filtering && (
          <Stack
            direction='row'
            spacing={0.75}
            alignItems='center'
            data-testid='log-filtering'
          >
            <CircularProgress size={12} thickness={6} />
            <Typography variant='body2' color='text.secondary'>
              Filtering…
            </Typography>
          </Stack>
        )}

        {/*
          The span the buffer covers, right-justified on the same line: ml:auto
          takes up all the free space to its left. Absent until something
          dateable has arrived, so the label never appears with nothing after
          it. nowrap keeps a range from breaking mid-timestamp -- the parent
          wraps this whole span to its own line instead when the row is tight.
        */}
        {dateRange !== '' && (
          <Typography
            variant='body2'
            color='text.secondary'
            data-testid='log-range'
            sx={{
              ml: 'auto',
              pl: 2,
              textAlign: 'right',
              whiteSpace: 'nowrap',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            Logs in time range: {dateRange}
          </Typography>
        )}
      </Stack>

      <Box
        ref={scrollRef}
        // Stable hooks for the end-to-end suite. Scoping row assertions to
        // the pane is what lets a test tell "filtered out" apart from
        // "virtualized off-screen" -- a page-wide text query cannot.
        data-testid='log-pane'
        sx={{
          fontFamily: 'monospace',
          fontSize: '0.8rem',
          backgroundColor: '#101418',
          color: '#e0e0e0',
          padding: 1,
          borderRadius: 1,
          height: '60vh',
          // Explicit width plus minWidth: 0: the pane takes the width its
          // container gives it and reports no opinion of its own upward. Being
          // a scroll container, the rows inside it cannot reach past it
          // either, however long they are.
          width: '100%',
          minWidth: 0,
          overflow: 'auto',
          // Reserve the vertical scrollbar's width at all times. Without it
          // the row area's usable width changes the moment the content
          // becomes taller than the pane, re-wrapping nothing but shifting
          // everything.
          scrollbarGutter: 'stable',
        }}
        onScroll={(e) => {
          const el = e.currentTarget;
          setViewport({ scrollTop: el.scrollTop, height: el.clientHeight });
          const bottomGap = el.scrollHeight - el.scrollTop - el.clientHeight;
          if (bottomGap > 20 && autoScroll) setAutoScroll(false);
          if (bottomGap <= 20 && !autoScroll) setAutoScroll(true);
          // Infinite scroll: when the user gets close to the top of the
          // pane, fetch a chunk of older history. Concurrent fetches
          // are blocked by the loadingOlder guard inside loadOlder, and
          // the fetch is a no-op once reachedOldest is set. The 200 px
          // threshold gives us headroom to load and restore scroll
          // before the user actually hits scrollTop === 0.
          if (el.scrollTop < 200) {
            loadOlder();
          }
        }}
      >
        {/*
          Virtualized rows: only windowLines are mounted; topPad/bottomPad
          reserve the scroll height of the rows outside the viewport so the
          scrollbar and scroll-offset math stay exact. Each row is fixed at
          ROW_HEIGHT and keeps whiteSpace: 'pre' so long lines scroll
          horizontally within the pane.
        */}
        {/*
          The row area is given an explicit width, wide enough for the longest
          line held, so the pane's scrollable extent stops depending on which
          rows happen to be mounted.

          Neither `width: 100%` nor a `min-width` floor achieves that: rows are
          `white-space: pre` and overrun their parent freely, so whichever long
          line is on screen sets the extent and gives it back when it scrolls
          out -- the horizontal scrollbar grows, shifts and disappears under
          the content as the virtualization window moves.

          Sizing in `ch` works here because the pane is monospace: one ch is
          one character advance, so maxLineChars ch is the width of the longest
          line. The floor keeps a nearly-empty buffer from rendering a narrow
          pane; the `100%` term keeps a wider pane filled.
        */}
        <Box
          sx={{
            width: `max(100%, ${CONTENT_MIN_WIDTH}px, ${
              maxLineChars + CONTENT_WIDTH_SLACK_CH
            }ch)`,
          }}
        >
          <Box sx={{ height: topPad }} />
          {windowLines.map((line) => (
            <Box
              key={line.id}
              component='div'
              data-testid={line.gap ? 'log-gap' : 'log-row'}
              sx={{
                height: ROW_HEIGHT,
                lineHeight: `${ROW_HEIGHT}px`,
                whiteSpace: 'pre',
                wordBreak: 'keep-all',
                // A gap is a statement about the record rather than part of
                // it, so it is styled to stand apart from every level colour.
                ...(line.gap
                  ? { color: '#ffd54f', fontStyle: 'italic' }
                  : { color: LEVEL_COLORS[line.level] || undefined }),
              }}
            >
              {line.text}
            </Box>
          ))}
          <Box sx={{ height: bottomPad }} />
        </Box>
      </Box>
    </Box>
  );
}
