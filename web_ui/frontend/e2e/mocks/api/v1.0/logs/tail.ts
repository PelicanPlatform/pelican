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

import { Page, Route } from '@playwright/test';

// Mirrors web_ui.LogTailResponse (the JSON returned by GET
// /api/v1.0/logs/tail). Kept local to the e2e suite so the tests don't
// depend on the app's internal types.
export interface LogTailResponse {
  enabled: boolean;
  content: string;
  firstCursor: string;
  lastCursor: string;
  reached: boolean;
  dropped: number;
  instanceId: string;
  bufferOldest?: string;
  bufferNewest?: string;
}

const TAIL_URL_PATTERN = '**/api/v1.0/logs/tail**';

// Opaque instance marker. Its exact value doesn't matter to the client (it
// only compares it against the previous response); it just needs to be
// stable within a run so restart-detection in the viewer doesn't trip.
const INSTANCE_ID = 'e2e-log-instance';

// The `limit=` the viewer sends on every forward poll (LogViewer's
// TAIL_LIMIT). Fixtures larger than this get their initial load truncated
// by the server-side limit rule, which is the only way real scroll-up
// history exists.
export const CLIENT_TAIL_LIMIT = 10000;

// What the server substitutes when a before= request omits count=. The
// viewer always sends one, so this only covers hand-built requests.
const DEFAULT_BEFORE_COUNT = 100;

/**
 * Encodes a seq the way web_ui.logTailCursor does: seq 0 is the empty
 * string ("give me everything"), every other seq is the RawURLEncoding
 * base64 of its 8-byte big-endian representation. Tests never need to read
 * a cursor, but producing the real wire shape means a client that started
 * parsing (rather than echoing) cursors would fail here the same way it
 * fails against a real server.
 */
export function logCursor(seq: number): string {
  if (seq <= 0) return '';
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(seq));
  return buf.toString('base64url');
}

/** Inverse of logCursor; mirrors web_ui.parseLogTailCursor. */
export function parseLogCursor(raw: string | null): number {
  if (!raw) return 0;
  const buf = Buffer.from(raw, 'base64url');
  if (buf.length !== 8) return 0;
  return Number(buf.readBigUInt64BE());
}

/**
 * An in-memory stand-in for config.LogRingBuffer that reproduces the
 * TailSince / TailBefore semantics the Go implementation actually has:
 *
 *   - Every held line carries a monotonic seq; `lines[i]` is seq
 *     `firstSeq + i`.
 *   - TailSince returns lines with seq > since, then drops the OLDEST
 *     lines when the delta exceeds `limit`. With nothing new to send it
 *     still reports firstCursor == lastCursor == the caller's cursor,
 *     which is NOT the empty string once the client has polled once.
 *   - TailBefore returns lines with seq < before and can report content
 *     and `reached` in the same response -- that is the response shape a
 *     viewer sees on the last scroll-up before history runs out.
 *
 * The one deliberate simplification: the real server rounds `count` up to
 * whole compressed batches, so it may return more than asked. The client
 * treats count as a lower bound either way.
 */
class MockLogBuffer {
  private lines: string[];
  private firstSeq: number;
  private readonly instanceId: string;

  constructor(lines: string[], firstSeq = 1, instanceId = INSTANCE_ID) {
    this.lines = [...lines];
    this.firstSeq = firstSeq;
    this.instanceId = instanceId;
  }

  append(lines: string[]) {
    this.lines.push(...lines);
  }

  /**
   * Drops the oldest `n` lines, advancing firstSeq past them, the way the
   * real buffer's eviction does. Seqs are never reused, which is what lets
   * a caller's stale cursor be recognized as pointing below the wall.
   */
  evictOldest(n: number) {
    const removed = this.lines.splice(0, n);
    this.firstSeq += removed.length;
  }

  private get oldestSeq(): number {
    return this.lines.length > 0 ? this.firstSeq : 0;
  }

  private get newestSeq(): number {
    return this.lines.length > 0 ? this.firstSeq + this.lines.length - 1 : 0;
  }

  tailSince(since: number, limit: number): LogTailResponse {
    const newest = this.newestSeq;
    const startIdx = Math.max(
      0,
      Math.min(this.lines.length, since - this.firstSeq + 1)
    );
    let selected = this.lines.slice(startIdx);
    let firstSeqInContent = selected.length > 0 ? this.firstSeq + startIdx : -1;

    // Lines the caller's cursor covered that are no longer held: they were
    // evicted before the caller came back for them.
    let dropped = 0;
    if (since > 0 && this.oldestSeq > since + 1) {
      dropped = this.oldestSeq - since - 1;
    }

    // limit keeps only the newest `limit` lines of the delta, advancing the
    // first cursor past the lines it dropped. Those are still reachable
    // through TailBefore, but they are a gap in this response all the same.
    if (limit > 0 && firstSeqInContent >= 0) {
      const totalLines = newest - firstSeqInContent + 1;
      if (totalLines > limit) {
        const drop = totalLines - limit;
        selected = selected.slice(drop);
        firstSeqInContent += drop;
        dropped += drop;
      }
    }

    return {
      enabled: true,
      content: joinLines(selected),
      firstCursor: logCursor(
        firstSeqInContent >= 0 ? firstSeqInContent : since
      ),
      lastCursor: logCursor(newest > since ? newest : since),
      // The forward tail never runs off the end of history.
      reached: false,
      dropped,
      instanceId: this.instanceId,
      ...this.span,
    };
  }

  /**
   * The stamps bracketing everything held, mirroring the real buffer's Span():
   * the extent of a download, which is independent of what any one response
   * returns. The server reads these off the logrus entries; a fixture only has
   * the formatted lines, so they come from the first and last line's own
   * `time=` token.
   */
  private get span(): Pick<LogTailResponse, 'bufferOldest' | 'bufferNewest'> {
    const stamp = (line: string | undefined) =>
      line?.match(/^time="([^"]*)"/)?.[1] ?? '';
    const oldest = stamp(this.lines[0]);
    const newest = stamp(this.lines[this.lines.length - 1]);
    if (oldest === '' || newest === '') return {};
    return { bufferOldest: oldest, bufferNewest: newest };
  }

  tailBefore(before: number, count: number): LogTailResponse {
    const effectiveCount = count > 0 ? count : DEFAULT_BEFORE_COUNT;
    const oldestHeld = this.oldestSeq;
    const endIdx = Math.max(
      0,
      Math.min(this.lines.length, before - this.firstSeq)
    );
    const startIdx = Math.max(0, endIdx - effectiveCount);
    const selected = this.lines.slice(startIdx, endIdx);

    let firstSeqOut = before;
    let lastSeqOut = before;
    // A cursor already at (or below) the wall means history is exhausted
    // even before we return anything.
    let reached = before <= oldestHeld;
    if (selected.length > 0) {
      firstSeqOut = this.firstSeq + startIdx;
      lastSeqOut = this.firstSeq + endIdx - 1;
      reached = firstSeqOut <= oldestHeld;
    }

    return {
      enabled: true,
      content: joinLines(selected),
      firstCursor: logCursor(firstSeqOut),
      lastCursor: logCursor(lastSeqOut),
      reached,
      // `dropped` describes the forward tail only; scroll-up reports the
      // wall through `reached`.
      dropped: 0,
      instanceId: this.instanceId,
      ...this.span,
    };
  }
}

// Log content on the wire is newline-TERMINATED, not newline-separated:
// logrus writes a trailing newline on every entry and the buffer stores
// the bytes verbatim.
function joinLines(lines: string[]): string {
  return lines.length > 0 ? lines.join('\n') + '\n' : '';
}

// A small, deterministic fixture spanning several log levels so the viewer's
// level chips get non-trivial counts and text filtering has something to
// match. Formatted the way logrus's TextFormatter emits (DisableColors on
// the server), so the client's `level=<name>` extraction works unchanged.
export const DEFAULT_LOG_LINES = [
  'time="2026-07-25T10:00:00Z" level=info msg="Pelican origin started"',
  'time="2026-07-25T10:00:01Z" level=warning msg="Disk space is running low"',
  'time="2026-07-25T10:00:02Z" level=error msg="Failed to connect to backend storage"',
  'time="2026-07-25T10:00:03Z" level=info msg="Recovered connection to backend storage"',
];

/**
 * Builds `count` distinct info-level lines in the server's wire format.
 * Used by the fixtures that have to be larger than the viewer's own
 * TAIL_LIMIT (virtualization, scroll-up history).
 */
export function makeLogLines(count: number, startIndex = 1): string[] {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    const n = startIndex + i;
    lines.push(
      `time="2026-07-25T11:00:00Z" level=info msg="e2e generated log line ${n}"`
    );
  }
  return lines;
}

/**
 * Registers a GET handler on the tail endpoint, replacing any handler a
 * previous call left behind so re-mocking inside a test is deterministic
 * rather than dependent on route-stacking order.
 */
async function routeTail(
  page: Page,
  handler: (route: Route, url: URL) => void
) {
  await page.unroute(TAIL_URL_PATTERN);
  await page.route(TAIL_URL_PATTERN, (route) => {
    const req = route.request();
    if (req.method() !== 'GET') {
      route.continue();
      return;
    }
    handler(route, new URL(req.url()));
  });
}

function fulfillJson(route: Route, status: number, body: unknown) {
  route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

// Dispatches one request against the buffer exactly as HandleLogTail does:
// before= wins over since=, and each direction reads its own count/limit.
function serveTail(route: Route, url: URL, buffer: MockLogBuffer) {
  const before = url.searchParams.get('before');
  if (before !== null) {
    const count = Number(url.searchParams.get('count') ?? '0');
    fulfillJson(
      route,
      200,
      buffer.tailBefore(
        parseLogCursor(before),
        Number.isFinite(count) ? count : 0
      )
    );
    return;
  }
  const limit = Number(url.searchParams.get('limit') ?? '0');
  fulfillJson(
    route,
    200,
    buffer.tailSince(
      parseLogCursor(url.searchParams.get('since')),
      Number.isFinite(limit) ? limit : 0
    )
  );
}

/**
 * Intercepts GET /api/v1.0/logs/tail and serves a fixed set of lines from a
 * faithful buffer: the initial (empty-cursor) load returns the newest
 * `limit` lines, forward polls return only what arrived since the caller's
 * cursor (nothing, here), and scroll-up walks backwards through whatever
 * the initial load's limit truncated away.
 *
 * Pass an empty `lines` array to exercise a buffer that is enabled but empty.
 */
export async function mockLogTail(
  page: Page,
  lines: string[] = DEFAULT_LOG_LINES
) {
  const buffer = new MockLogBuffer(lines);
  await routeTail(page, (route, url) => serveTail(route, url, buffer));
}

export interface LogTailStreamOptions {
  /** Lines already in the buffer when the viewer first loads. */
  initial?: string[];
  /**
   * One batch of new lines per forward poll, in order. Once exhausted,
   * further polls report nothing new.
   */
  batches?: string[][];
}

/**
 * Intercepts GET /api/v1.0/logs/tail and grows the buffer as the viewer
 * polls: the Nth forward poll after the initial load publishes
 * `batches[N-1]`. This is what makes the live-tail accumulate-and-advance
 * loop observable -- a mock that only answers the initial load cannot tell
 * a working cursor handoff from a broken one.
 */
export async function mockLogTailStreaming(
  page: Page,
  { initial = DEFAULT_LOG_LINES, batches = [] }: LogTailStreamOptions = {}
) {
  const buffer = new MockLogBuffer(initial);
  let requests = 0;
  let delivered = 0;
  await routeTail(page, (route, url) => {
    requests++;
    const isForwardPoll = url.searchParams.get('before') === null;
    if (isForwardPoll && requests > 1 && delivered < batches.length) {
      buffer.append(batches[delivered++]);
    }
    serveTail(route, url, buffer);
  });
}

export interface LogTailEvictionOptions {
  /** Buffer contents served on the initial load. */
  initial?: string[];
  /** Lines appended on the poll that also evicts. */
  arriving?: string[];
  /** How many of the oldest lines the buffer drops on that poll. */
  evict?: number;
}

/**
 * Intercepts GET /api/v1.0/logs/tail and, on the first forward poll,
 * appends new lines while evicting older ones out from under the client's
 * cursor -- what a real buffer does when the server logs faster than the
 * viewer polls. The response then reports a non-zero `dropped`, which is
 * the only signal the client has that its view is no longer contiguous.
 */
export async function mockLogTailEvicting(
  page: Page,
  {
    initial = DEFAULT_LOG_LINES,
    arriving = [],
    evict = 0,
  }: LogTailEvictionOptions = {}
) {
  const buffer = new MockLogBuffer(initial);
  let requests = 0;
  let evicted = false;
  await routeTail(page, (route, url) => {
    requests++;
    const isForwardPoll = url.searchParams.get('before') === null;
    if (isForwardPoll && requests > 1 && !evicted) {
      evicted = true;
      buffer.append(arriving);
      buffer.evictOldest(evict);
    }
    serveTail(route, url, buffer);
  });
}

export interface LogTailFailureOptions {
  /** Buffer contents served by the requests that do succeed. */
  lines?: string[];
  /** Number of leading requests served normally before failures start. */
  failAfter?: number;
  /** How many consecutive requests fail; omit for "never recovers". */
  failCount?: number;
  /** HTTP status served while failing. */
  status?: number;
}

/**
 * Intercepts GET /api/v1.0/logs/tail and injects a window of failing
 * responses, so a test can watch the viewer surface the error, hold on to
 * the lines it already has, and recover when polling succeeds again.
 */
export async function mockLogTailFailing(
  page: Page,
  {
    lines = DEFAULT_LOG_LINES,
    failAfter = 1,
    failCount = Number.MAX_SAFE_INTEGER,
    status = 500,
  }: LogTailFailureOptions = {}
) {
  const buffer = new MockLogBuffer(lines);
  let requests = 0;
  await routeTail(page, (route, url) => {
    requests++;
    if (requests > failAfter && requests <= failAfter + failCount) {
      fulfillJson(route, status, {
        status: 'error',
        msg: 'log buffer temporarily unavailable',
      });
      return;
    }
    serveTail(route, url, buffer);
  });
}

/**
 * Intercepts GET /api/v1.0/logs/tail and answers the way
 * LogReadAuthHandler does for a caller without server.admin or
 * pelican.log_read.
 */
export async function mockLogTailForbidden(page: Page) {
  await routeTail(page, (route) => {
    fulfillJson(route, 403, {
      status: 'error',
      msg: 'You do not have permission to read server logs',
    });
  });
}

/**
 * Intercepts GET /api/v1.0/logs/tail and reports the buffer as disabled,
 * so the viewer renders its "not available" notice instead of a log pane.
 */
export async function mockLogTailDisabled(page: Page) {
  await routeTail(page, (route) => {
    fulfillJson(route, 200, {
      enabled: false,
      content: '',
      firstCursor: '',
      lastCursor: '',
      reached: false,
      dropped: 0,
      instanceId: '',
    } satisfies LogTailResponse);
  });
}

export interface LogTailRestartOptions {
  /** Buffer contents before the restart. */
  initial?: string[];
  /** Buffer contents the restarted server reports. */
  afterRestart?: string[];
}

/**
 * Intercepts GET /api/v1.0/logs/tail and swaps in a different buffer, with a
 * different instanceId, on the first forward poll -- what a client sees when
 * the server it is tailing restarts. The cursors it holds refer to a buffer
 * that no longer exists, so it has to discard them along with the lines they
 * describe rather than stitch the two servers' output together.
 */
export async function mockLogTailRestarting(
  page: Page,
  { initial = DEFAULT_LOG_LINES, afterRestart = [] }: LogTailRestartOptions = {}
) {
  const before = new MockLogBuffer(initial);
  const after = new MockLogBuffer(afterRestart, 1, INSTANCE_ID + '-restarted');
  let requests = 0;
  await routeTail(page, (route, url) => {
    requests++;
    const isForwardPoll = url.searchParams.get('before') === null;
    serveTail(route, url, isForwardPoll && requests > 1 ? after : before);
  });
}
