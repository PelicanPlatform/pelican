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
}

const POLL_INTERVAL_MS = 2000;
// Client-side memory cap on the accumulated log text. A very long-running
// viewer session can otherwise keep growing local state indefinitely --
// the server-side buffer is a small window, but the client has no such
// cap unless we impose one. 500 MB of text is a hard upper bound; when
// we're over, we drop lines from the oldest end until we're back under.
const MAX_CLIENT_BYTES = 500 * 1024 * 1024;

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

      // Restart detection: server buffer changed. Reset every cursor
      // and local accumulator BEFORE we split resp.content so the
      // fresh lines start at id=1 rather than continuing an old
      // counter. Doing it here (rather than reloading the page)
      // means the viewer heals itself on the next poll after a
      // server bounce.
      if (
        instanceIdRef.current !== '' &&
        resp.instanceId !== instanceIdRef.current
      ) {
        setLines([]);
        beforeRef.current = '';
        appendIdRef.current = 0;
        prependIdRef.current = 0;
        setReachedOldest(false);
        // sinceRef was already used for this request; the fact that
        // the server returned an instance mismatch means it treated
        // our cursor as unknown and gave us whatever it currently
        // holds -- consistent with a fresh-client fetch.
      }
      instanceIdRef.current = resp.instanceId;

      const fresh = splitLines(resp.content, () => ++appendIdRef.current);

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
    setAutoScroll(false);
    setLoadingOlder(true);
    try {
      const resp = await fetchBefore(before, OLDER_FETCH_COUNT);
      if (!resp.enabled) {
        setEnabled(false);
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
    for (const line of lines)
      counts[line.level] = (counts[line.level] || 0) + 1;
    return counts;
  }, [lines]);

  const visibleLines = useMemo(() => {
    const levelSet = new Set(selectedLevels);
    const filter = textFilter.toLowerCase();
    return lines.filter((line) => {
      if (!levelSet.has(line.level)) return false;
      if (filter && !line.text.toLowerCase().includes(filter)) return false;
      return true;
    });
  }, [lines, selectedLevels, textFilter]);

  // Auto-scroll: pin to bottom whenever new content arrives, unless the
  // user has scrolled up.
  useEffect(() => {
    if (!autoScroll || !scrollRef.current) return;
    const el = scrollRef.current;
    el.scrollTop = el.scrollHeight;
  }, [visibleLines, autoScroll]);

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
        Showing {visibleLines.length.toLocaleString()} of{' '}
        {lines.length.toLocaleString()} lines.
        {loadingOlder && ' Loading older…'}
        {reachedOldest && ' No more history.'}
      </Typography>

      <Box
        ref={scrollRef}
        sx={{
          fontFamily: 'monospace',
          fontSize: '0.8rem',
          backgroundColor: '#101418',
          color: '#e0e0e0',
          padding: 1,
          borderRadius: 1,
          height: '60vh',
          overflow: 'auto',
          whiteSpace: 'pre',
          wordBreak: 'keep-all',
        }}
        onScroll={(e) => {
          const el = e.currentTarget;
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
        {visibleLines.map((line) => (
          <Box
            key={line.id}
            component='div'
            sx={{
              color: LEVEL_COLORS[line.level] || undefined,
            }}
          >
            {line.text}
          </Box>
        ))}
      </Box>
    </Box>
  );
}
