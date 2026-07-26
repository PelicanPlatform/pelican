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
  FormControlLabel,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import React, {
  useCallback,
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

// -----------------------------------------------------------------------------
// LogViewer -- single-endpoint polling with an opaque cursor. State is
// deliberately simple: a flat list of accumulated Lines plus the current
// cursor/oldestSeq pair.
// -----------------------------------------------------------------------------

interface Line {
  text: string;
  level: string;
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
  return {
    text: `--- ${dropped.toLocaleString()} ${plural} dropped: the server's buffer filled faster than this view could read it ---`,
    level: 'gap',
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
  const [selectedLevels, setSelectedLevels] = useState<string[]>(LOG_LEVELS);
  const [textFilter, setTextFilter] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [reachedOldest, setReachedOldest] = useState(false);
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

  const visibleLines = useMemo(() => {
    const levelSet = new Set(selectedLevels);
    const filter = textFilter.toLowerCase();
    return lines.filter((line) => {
      // Gap markers are not log lines and carry no level; hiding one
      // behind a level or text filter would restore the very illusion of
      // contiguity it exists to break.
      if (line.gap) return true;
      if (!levelSet.has(line.level)) return false;
      if (filter && !line.text.toLowerCase().includes(filter)) return false;
      return true;
    });
  }, [lines, selectedLevels, textFilter]);

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

  // Virtualization window: the contiguous slice of visibleLines currently
  // mounted, with pixel spacers standing in for the rows above and below.
  const rowCount = visibleLines.length;
  const viewportHeight = viewport.height || 600;
  const startIdx = Math.max(
    0,
    Math.floor(viewport.scrollTop / ROW_HEIGHT) - OVERSCAN_ROWS
  );
  const endIdx = Math.min(
    rowCount,
    Math.ceil((viewport.scrollTop + viewportHeight) / ROW_HEIGHT) +
      OVERSCAN_ROWS
  );
  const topPad = startIdx * ROW_HEIGHT;
  const bottomPad = Math.max(0, (rowCount - endIdx) * ROW_HEIGHT);
  const windowLines = visibleLines.slice(startIdx, endIdx);

  const onDownload = useCallback(() => {
    window.location.assign(`${API_V1_BASE_URL}/logs/download`);
  }, []);

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

  return (
    <Box display='flex' flexDirection='column' gap={2} width='100%'>
      {error && (
        <Alert severity='warning' onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Stack
        direction={{ xs: 'column', md: 'row' }}
        spacing={2}
        alignItems={{ md: 'center' }}
      >
        {/*
          One chip per level, always in the fixed LOG_LEVELS order. Clicking
          toggles that level in / out of the selected set.
        */}
        <Box display='flex' flexWrap='wrap' gap={0.75}>
          {LOG_LEVELS.map((lvl) => {
            const active = selectedLevels.includes(lvl);
            const count = levelCounts[lvl] ?? 0;
            return (
              <Chip
                key={lvl}
                size='small'
                clickable
                onClick={() =>
                  setSelectedLevels((prev) =>
                    prev.includes(lvl)
                      ? prev.filter((v) => v !== lvl)
                      : [...prev, lvl]
                  )
                }
                label={`${lvl} (${count.toLocaleString()})`}
                sx={{
                  backgroundColor: active
                    ? LEVEL_COLORS[lvl] || '#616161'
                    : 'transparent',
                  color: active ? '#000' : 'text.secondary',
                  border: `1px solid ${LEVEL_COLORS[lvl] || '#616161'}`,
                  fontWeight: active ? 600 : 400,
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
          sx={{ flexGrow: 1, minWidth: 220 }}
        />

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

        <Button
          variant='outlined'
          startIcon={<DownloadIcon />}
          onClick={onDownload}
        >
          Download .log.gz
        </Button>
      </Stack>

      <Typography variant='body2' color='text.secondary'>
        Showing {visibleLineCount.toLocaleString()} of{' '}
        {totalLineCount.toLocaleString()} lines.
        {loadingOlder && ' Loading older…'}
        {reachedOldest && ' No more history.'}
      </Typography>

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
          overflow: 'auto',
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
  );
}
