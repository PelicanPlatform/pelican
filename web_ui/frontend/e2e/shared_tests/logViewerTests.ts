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

import { test, expect, Page } from '@playwright/test';
import { LogViewerPage } from '../shared_pages/LogViewerPage';
import {
  CLIENT_TAIL_LIMIT,
  DEFAULT_LOG_LINES,
  makeLogLines,
  mockLogTail,
  mockLogTailDisabled,
  mockLogTailEvicting,
  mockLogTailFailing,
  mockLogTailForbidden,
  mockLogTailRestarting,
  mockLogTailStreaming,
} from '../mocks/api/v1.0/logs/tail';
import { mockLogDownload } from '../mocks/api/v1.0/logs/download';

// Distinctive substrings of the fixture lines (see DEFAULT_LOG_LINES). Chosen
// so each matches exactly one seeded line -- note both a warning/error and an
// info line mention "backend storage", so we always assert on the fuller
// phrase.
const INFO_LINE = 'Pelican origin started';
const WARNING_LINE = 'Disk space is running low';
const ERROR_LINE = 'Failed to connect to backend storage';
const INFO_LINE_2 = 'Recovered connection to backend storage';

// Lines the streaming fixture publishes on later polls -- i.e. content the
// viewer can only be holding if it advanced its cursor and appended.
const STREAMED_LINE_1 =
  'time="2026-07-25T10:00:04Z" level=info msg="Origin export refreshed"';
const STREAMED_LINE_2 =
  'time="2026-07-25T10:00:05Z" level=warning msg="Cache miss rate is elevated"';
const STREAMED_TEXT_1 = 'Origin export refreshed';
const STREAMED_TEXT_2 = 'Cache miss rate is elevated';

// Drives the eviction case, where the server discards lines the viewer has
// not read yet. The arithmetic is worth spelling out, because the expected
// gap size follows from it and not from `evict` directly:
//
//   the 4 fixture lines are seqs 1-4, so after the initial load the viewer's
//   cursor sits at seq 4; `arriving` adds seqs 5-10; evicting the oldest 7
//   leaves seqs 8-10 held. Seqs 5-7 therefore existed but are gone before
//   the viewer ever asked for them -- a gap of 3. Seqs 1-4 are evicted too,
//   but the viewer already holds those, so they are not part of the gap.
//
// Only the last arriving line is an error, so a level filter can hide the
// post-gap content while leaving the marker to be asserted on.
const EVICTION_FIXTURE = {
  arriving: [
    'time="2026-07-25T10:05:00Z" level=info msg="Missed line one"',
    'time="2026-07-25T10:05:01Z" level=info msg="Missed line two"',
    'time="2026-07-25T10:05:02Z" level=info msg="Missed line three"',
    'time="2026-07-25T10:05:03Z" level=info msg="Survivor one"',
    'time="2026-07-25T10:05:04Z" level=info msg="Survivor two"',
    'time="2026-07-25T10:05:05Z" level=error msg="After the gap"',
  ],
  evict: 7,
};
const EXPECTED_DROPPED = 3;

// The viewer polls every POLL_INTERVAL_MS (2 s), so anything that depends on
// a later poll needs several intervals of headroom.
const POLL_TIMEOUT = 10000;
// Fixtures at or above the viewer's TAIL_LIMIT take noticeably longer to
// serialize, transfer and mount.
const LARGE_FIXTURE_TIMEOUT = 30000;

/**
 * Resolves on the next forward (`since=<cursor>`) poll, i.e. a poll the
 * viewer issued with a cursor it learned from an earlier response. Used to
 * advance a deterministic number of poll cycles instead of sleeping.
 */
function waitForForwardPoll(page: Page) {
  return page.waitForResponse(
    (response) => {
      try {
        const url = new URL(response.url());
        return (
          url.pathname.endsWith('/logs/tail') && !!url.searchParams.get('since')
        );
      } catch {
        return false;
      }
    },
    { timeout: POLL_TIMEOUT }
  );
}

/**
 * Registers the shared log-viewer tests for a given service URL. Call this
 * inside a `test.describe` block in each service's spec file.
 *
 * @param serviceUrl  The relative URL for the log viewer page
 *                    (e.g. './view/settings/logs/').
 */
export function registerLogViewerTests(serviceUrl: string) {
  // The settings shell that hosts the viewer; used to prove the sidebar
  // entry actually reaches the page.
  const settingsRootUrl = serviceUrl.replace(/logs\/?$/, '');
  let logs: LogViewerPage;

  test.beforeEach(async ({ page }) => {
    logs = new LogViewerPage(page, serviceUrl);
    // Seed a stable fixture before navigating so the initial fetch (and every
    // poll thereafter) is served from the mock and never the real server.
    await mockLogTail(page);
    await logs.goto();
  });

  test('shows the Server Logs heading @smoke', async () => {
    await expect(logs.heading).toBeVisible();
  });

  test('renders the log lines returned by the API @smoke @mocked', async () => {
    await expect(logs.logLine(INFO_LINE)).toBeVisible();
    await expect(logs.logLine(WARNING_LINE)).toBeVisible();
    await expect(logs.logLine(ERROR_LINE)).toBeVisible();
    await expect(logs.logLine(INFO_LINE_2)).toBeVisible();
    // Two info lines, one warning, one error.
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );
  });

  test('shows every line it holds until a filter is applied @mocked', async ({
    page,
  }) => {
    // No level filter is not the same thing as "all seven known levels
    // selected": a line whose level is outside that list must still be on
    // screen by default, and must get a chip of its own so it can be filtered
    // like any other. A whitelisted default hides such lines with no visible
    // cause and no control to bring them back.
    await mockLogTail(page, [
      ...DEFAULT_LOG_LINES,
      'time="2026-07-25T10:00:06Z" level=notice msg="Unusual level here"',
    ]);
    await logs.goto();

    await expect(logs.logLine('Unusual level here')).toBeVisible();
    await expect(logs.summary).toContainText(
      'Showing 5 of 5 lines held in this browser.'
    );
    await expect(logs.levelChip('notice')).toContainText('notice (1)');

    // And it filters like any other level.
    await logs.clickLevel('notice');
    await expect(logs.logLine('Unusual level here')).toBeVisible();
    await expect(logs.logLine(INFO_LINE)).toHaveCount(0);
    await expect(logs.summary).toContainText(
      'Showing 1 of 5 lines held in this browser.'
    );
  });

  test('shows per-level counts in the filter chips @mocked', async () => {
    await expect(logs.levelChip('info')).toContainText('info (2)');
    await expect(logs.levelChip('warning')).toContainText('warning (1)');
    await expect(logs.levelChip('error')).toContainText('error (1)');
  });

  test('filters visible lines by the text filter @mocked', async () => {
    // "backend storage" appears in the error line and the second info line.
    await logs.textFilter.fill('backend storage');
    await expect(logs.logLine(ERROR_LINE)).toBeVisible();
    await expect(logs.logLine(INFO_LINE_2)).toBeVisible();
    await expect(logs.logLine(INFO_LINE)).not.toBeVisible();
    await expect(logs.logLine(WARNING_LINE)).not.toBeVisible();
    await expect(logs.summary).toContainText(
      'Showing 2 of 4 lines held in this browser.'
    );
  });

  test('shows only the clicked level, and restores it on a second click @mocked', async () => {
    // A row of level buttons reads as "pick the one you want to look at", so
    // the first click narrows to that level rather than subtracting it.
    await logs.clickLevel('error');
    await expect(logs.logLine(ERROR_LINE)).toBeVisible();
    await expect(logs.logLine(INFO_LINE)).toHaveCount(0);
    await expect(logs.logLine(WARNING_LINE)).toHaveCount(0);
    await expect(logs.summary).toContainText(
      'Showing 1 of 4 lines held in this browser.'
    );

    // Clicking the last level still selected is the way back to all of them.
    await logs.clickLevel('error');
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );
    await expect(logs.logLine(INFO_LINE)).toBeVisible();
  });

  test('adds each further level clicked to the selection @mocked', async () => {
    // Once a filter is active, a plain click on another level combines rather
    // than replaces: error, then warning, shows both.
    await logs.clickLevel('error');
    await logs.clickLevel('warning');
    await expect(logs.logLine(ERROR_LINE)).toBeVisible();
    await expect(logs.logLine(WARNING_LINE)).toBeVisible();
    await expect(logs.logLine(INFO_LINE)).toHaveCount(0);
    await expect(logs.summary).toContainText(
      'Showing 2 of 4 lines held in this browser.'
    );

    // And a click on a level that is already in the selection takes it out
    // again.
    await logs.clickLevel('error');
    await expect(logs.logLine(ERROR_LINE)).toHaveCount(0);
    await expect(logs.logLine(WARNING_LINE)).toBeVisible();
    await expect(logs.summary).toContainText(
      'Showing 1 of 4 lines held in this browser.'
    );
  });

  test('combines levels with a modifier-click @mocked', async () => {
    // The modifier is a plain toggle, so it reaches the same combination.
    await logs.clickLevel('error');
    await logs.toggleLevel('warning');
    await expect(logs.logLine(ERROR_LINE)).toBeVisible();
    await expect(logs.logLine(WARNING_LINE)).toBeVisible();
    await expect(logs.logLine(INFO_LINE)).toHaveCount(0);
    await expect(logs.summary).toContainText(
      'Showing 2 of 4 lines held in this browser.'
    );
  });

  test('dates the rows on screen next to the line count @mocked', async ({
    page,
  }) => {
    // The rows themselves are the server's formatted lines, timestamp
    // included; the range beside the count is what says which days they
    // cover without scrolling to both ends of the pane.
    await expect(logs.logLine('time="2026-07-25T10:00:00Z"')).toBeVisible();
    // Rendered in the viewer's local zone, so assert the shape rather than the
    // value.
    const rangePattern =
      /^Logs in time range: \d{4}-\d{2}-\d{2} \d{2}:\d{2} - \d{4}-\d{2}-\d{2} \d{2}:\d{2}$/;
    await expect(logs.dateRange()).toHaveText(rangePattern);

    // A buffer spanning two days reports two different dates, whatever zone
    // the viewer renders them in -- these fixture stamps are 25 hours apart.
    await mockLogTail(page, [
      'time="2026-07-25T23:30:00Z" level=info msg="Late on the first day"',
      'time="2026-07-27T00:30:00Z" level=info msg="Early on the third"',
    ]);
    await logs.goto();
    await expect(logs.dateRange()).toHaveText(rangePattern);
    const [from, to] = (await logs.dateRange().innerText())
      .replace('Logs in time range: ', '')
      .split(' - ');
    expect(from.split(' ')[0]).not.toEqual(to.split(' ')[0]);
  });

  test('hides a level when its chip is toggled off @mocked', async () => {
    await expect(logs.logLine(ERROR_LINE)).toBeVisible();
    await logs.toggleLevel('error');
    await expect(logs.logLine(ERROR_LINE)).not.toBeVisible();
    // The non-error lines remain.
    await expect(logs.logLine(INFO_LINE)).toBeVisible();
    await expect(logs.summary).toContainText(
      'Showing 3 of 4 lines held in this browser.'
    );
  });

  test('offers a log download control @smoke', async () => {
    await expect(logs.downloadButton).toBeVisible();
  });

  test('reports what a download would cover, not what is on screen @mocked @slow', async ({
    page,
  }) => {
    test.slow();
    // The buffer holds more than the viewer's initial load takes, so the two
    // spans genuinely differ: the download subtext must describe the server's
    // whole buffer, which is the question an admin is asking before they click
    // it. Deriving it from the lines on screen would understate the history
    // available by everything the initial limit truncated away.
    const older = makeLogLines(CLIENT_TAIL_LIMIT, 1).map((line) =>
      line.replace('2026-07-25T11:00:00Z', '2026-07-20T08:00:00Z')
    );
    await mockLogTail(page, [
      ...older,
      'time="2026-07-25T11:30:00Z" level=info msg="Newest line held"',
    ]);
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 10,000 of 10,000 lines held in this browser.',
      { timeout: LARGE_FIXTURE_TIMEOUT }
    );

    // The oldest line the viewer holds is from the 20th, but the buffer's own
    // extent starts there too -- what matters is that the subtext reports the
    // buffer's ends rather than the response's.
    const spanPattern =
      /^Available: \d{4}-\d{2}-\d{2} \d{2}:\d{2} - \d{4}-\d{2}-\d{2} \d{2}:\d{2}$/;
    await expect(logs.downloadSpan()).toHaveText(spanPattern);
    const [from, to] = (await logs.downloadSpan().innerText())
      .replace('Available: ', '')
      .split(' - ');
    expect(from.split(' ')[0]).not.toEqual(to.split(' ')[0]);
  });

  test('omits the download span when the buffer reports none @mocked', async ({
    page,
  }) => {
    // A line with no timestamp of its own leaves the server unable to date its
    // buffer; the control must then say nothing rather than show a half-range.
    await mockLogTail(page, ['a line with no timestamp at all']);
    await logs.goto();
    await expect(logs.downloadButton).toBeVisible();
    await expect(logs.downloadSpan()).toHaveCount(0);
  });

  test('shows a notice when the buffer is disabled @mocked', async ({
    page,
  }) => {
    // Re-route to report the buffer disabled, then reload so the initial fetch
    // sees enabled=false.
    await mockLogTailDisabled(page);
    await logs.goto();
    await expect(logs.unavailableNotice).toBeVisible();
    await expect(logs.logLine(INFO_LINE)).not.toBeVisible();
  });

  test('distinguishes an empty buffer from a disabled one @mocked', async ({
    page,
  }) => {
    // Both states show no log lines, and only one of them is a problem an
    // operator can act on.
    await mockLogTail(page, []);
    await logs.goto();

    await expect(logs.summary).toContainText(
      'Showing 0 of 0 lines held in this browser.'
    );
    await expect(logs.unavailableNotice).not.toBeVisible();
    // A level with no lines has no chip: the chip row describes what is in
    // the buffer, and every chip in it can narrow the view to something.
    for (const level of ['info', 'warning', 'error']) {
      await expect(logs.levelChip(level)).toHaveCount(0);
    }
  });

  test('offers a chip only for the levels present @mocked', async ({
    page,
  }) => {
    await mockLogTail(page, [
      'time="2026-07-25T10:00:00Z" level=info msg="Only info here"',
    ]);
    await logs.goto();

    await expect(logs.levelChip('info')).toContainText('info (1)');
    for (const absent of ['panic', 'fatal', 'error', 'warning', 'debug']) {
      await expect(logs.levelChip(absent)).toHaveCount(0);
    }

    // A selected level keeps its chip whatever its count, so the selection
    // stays explainable -- and undoable -- from the chips on screen.
    await logs.clickLevel('info');
    await logs.toggleLevel('info');
    await expect(logs.levelChip('info')).toContainText('info (1)');
    await expect(logs.rows()).toHaveCount(0);
  });

  test('treats short-form and level-less lines consistently @mocked', async ({
    page,
  }) => {
    // logrus emits "warning", but plenty of tools that log through Pelican
    // write "warn"; and a stack trace's continuation lines carry no level at
    // all, so they must inherit one rather than disappear.
    await mockLogTail(page, [
      ...DEFAULT_LOG_LINES,
      'time="2026-07-25T10:00:04Z" level=warn msg="Short form warning"',
      '    /usr/lib/pelican/foo.go:42 +0x1a',
    ]);
    await logs.goto();

    await expect(logs.levelChip('warning')).toContainText('warning (2)');
    await expect(logs.levelChip('info')).toContainText('info (3)');

    // The continuation line counts as info, so hiding info hides it too.
    await logs.toggleLevel('info');
    await expect(logs.logLine('foo.go:42')).toHaveCount(0);
    await expect(logs.summary).toContainText(
      'Showing 3 of 6 lines held in this browser.'
    );
  });

  test('empties and restores the pane as levels are toggled @mocked', async () => {
    // Only the levels the fixture actually contains have chips to click; the
    // rest are already contributing nothing.
    for (const level of ['error', 'warning', 'info']) {
      await logs.toggleLevel(level);
    }
    await expect(logs.summary).toContainText(
      'Showing 0 of 4 lines held in this browser.'
    );
    await expect(logs.rows()).toHaveCount(0);

    await logs.toggleLevel('info');
    await expect(logs.summary).toContainText(
      'Showing 2 of 4 lines held in this browser.'
    );
    await expect(logs.logLine(INFO_LINE)).toBeVisible();
  });

  test('starts over when the server it is tailing restarts @mocked @slow', async ({
    page,
  }) => {
    // Cursors belong to one buffer instance. After a restart the viewer's
    // are meaningless, so it must drop what it holds rather than append the
    // new server's lines to the old server's.
    await mockLogTailRestarting(page, {
      afterRestart: [
        'time="2026-07-25T11:00:00Z" level=info msg="Pelican origin restarted"',
      ],
    });
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );

    await expect(logs.logLine('Pelican origin restarted')).toBeVisible({
      timeout: POLL_TIMEOUT,
    });
    await expect(logs.summary).toContainText(
      'Showing 1 of 1 lines held in this browser.'
    );
    await expect(logs.logLine(INFO_LINE)).toHaveCount(0);
    // A restart is not a dropped-line event; the marker would be misleading.
    await expect(logs.gaps()).toHaveCount(0);
  });

  // ---------------------------------------------------------------------
  // Live tail
  // ---------------------------------------------------------------------

  test('appends lines that arrive on later polls @mocked @slow', async ({
    page,
  }) => {
    // Guarantees the accumulate-and-advance loop: each poll's lastCursor is
    // carried into the next request, and content that arrives after the
    // initial load is appended to (not swapped for) what is already shown.
    await mockLogTailStreaming(page, {
      batches: [[STREAMED_LINE_1], [STREAMED_LINE_2]],
    });
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );

    await expect(logs.logLine(STREAMED_TEXT_1)).toBeVisible({
      timeout: POLL_TIMEOUT,
    });
    await expect(logs.summary).toContainText(
      'Showing 5 of 5 lines held in this browser.',
      {
        timeout: POLL_TIMEOUT,
      }
    );

    await expect(logs.logLine(STREAMED_TEXT_2)).toBeVisible({
      timeout: POLL_TIMEOUT,
    });
    await expect(logs.summary).toContainText(
      'Showing 6 of 6 lines held in this browser.',
      {
        timeout: POLL_TIMEOUT,
      }
    );
    // The original lines survived the appends.
    await expect(logs.logLine(INFO_LINE)).toBeVisible();
  });

  test('does not re-deliver lines it already holds @mocked @slow', async ({
    page,
  }) => {
    // Guarantees the viewer advances `since` past what it has already
    // received: a viewer that kept re-sending the empty cursor would be
    // handed the whole fixture again on every poll and duplicate it.
    await mockLogTailStreaming(page, { batches: [] });
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );

    await waitForForwardPoll(page);
    await waitForForwardPoll(page);

    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );
    await expect(logs.rows()).toHaveCount(4);
    await expect(logs.logLine(INFO_LINE)).toHaveCount(1);
  });

  // ---------------------------------------------------------------------
  // Dropped lines
  // ---------------------------------------------------------------------

  test('marks the point where the server dropped lines @mocked @slow', async ({
    page,
  }) => {
    // A server logging faster than the viewer polls evicts lines the
    // viewer never saw. Without a marker the surviving lines render as
    // consecutive, which during an incident reads as a quiet period rather
    // than as lost evidence.
    await mockLogTailEvicting(page, EVICTION_FIXTURE);
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );

    await expect(logs.gaps()).toHaveCount(1, { timeout: POLL_TIMEOUT });
    await expect(logs.gaps().first()).toContainText(
      `${EXPECTED_DROPPED} lines dropped`
    );
    await expect(logs.logLine('After the gap')).toBeVisible();
    // The marker occupies a row but is not itself a log line, so the
    // count covers only the 4 original plus the 3 that survived.
    await expect(logs.summary).toContainText(
      'Showing 7 of 7 lines held in this browser.'
    );
  });

  test('keeps the dropped-lines marker visible under a level filter @mocked @slow', async ({
    page,
  }) => {
    // The marker describes the record rather than belonging to it, so a
    // level filter must not be able to hide the fact that lines are
    // missing.
    await mockLogTailEvicting(page, EVICTION_FIXTURE);
    await logs.goto();
    await expect(logs.gaps()).toHaveCount(1, { timeout: POLL_TIMEOUT });

    await logs.toggleLevel('error');
    await expect(logs.logLine('After the gap')).toHaveCount(0);
    await expect(logs.gaps()).toHaveCount(1);
  });

  test('shows no gap marker while the viewer keeps up @mocked @slow', async ({
    page,
  }) => {
    // The counterpart to the two above: an uninterrupted stream must not
    // acquire a marker, or the signal means nothing.
    await mockLogTailStreaming(page, {
      batches: [[STREAMED_LINE_1], [STREAMED_LINE_2]],
    });
    await logs.goto();
    await expect(logs.logLine(STREAMED_TEXT_2)).toBeVisible({
      timeout: POLL_TIMEOUT,
    });
    await expect(logs.gaps()).toHaveCount(0);
  });

  // ---------------------------------------------------------------------
  // Fetch failures
  // ---------------------------------------------------------------------

  test('surfaces a failed poll and keeps the lines already shown @mocked @slow', async ({
    page,
  }) => {
    // Guarantees a transport failure is reported rather than silently
    // blanking the pane, and that the warning is dismissible.
    await mockLogTailFailing(page, { failAfter: 1 });
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );

    await expect(logs.fetchErrorAlert).toBeVisible({ timeout: POLL_TIMEOUT });
    await expect(logs.logLine(INFO_LINE)).toBeVisible();
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );

    await logs.dismissFetchError();
    await expect(logs.fetchErrorAlert).not.toBeVisible();
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );
  });

  test('clears the failure warning once polling recovers @mocked @slow', async ({
    page,
  }) => {
    // Guarantees the viewer heals itself: no reload is needed after a
    // transient server-side failure.
    await mockLogTailFailing(page, { failAfter: 1, failCount: 3 });
    await logs.goto();
    await expect(logs.fetchErrorAlert).toBeVisible({ timeout: POLL_TIMEOUT });
    await expect(logs.fetchErrorAlert).not.toBeVisible({ timeout: 15000 });
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );
  });

  test('surfaces a 403 from the log-read gate @mocked', async ({ page }) => {
    // Guarantees a caller the server refuses sees why, instead of an empty
    // pane that reads as "there are no logs".
    await mockLogTailForbidden(page);
    await logs.goto();
    await expect(logs.fetchErrorAlert).toBeVisible({ timeout: POLL_TIMEOUT });
    await expect(logs.fetchErrorAlert).toContainText('403');
    // The pane itself still renders -- this is a refusal, not the
    // buffer-disabled notice.
    await expect(logs.summary).toContainText(
      'Showing 0 of 0 lines held in this browser.'
    );
    await expect(logs.unavailableNotice).not.toBeVisible();
  });

  // ---------------------------------------------------------------------
  // Scrolling
  // ---------------------------------------------------------------------

  test('pins the pane to the bottom while auto-scroll is on @mocked', async ({
    page,
  }) => {
    // Guarantees a freshly loaded buffer shows its newest lines, not its
    // oldest.
    await mockLogTail(page, makeLogLines(200));
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 200 of 200 lines held in this browser.'
    );
    await expect(logs.autoScrollCheckbox).toBeChecked();
    // The pin runs off an effect, so poll rather than reading once.
    await expect
      .poll(() => logs.paneBottomGap(), { timeout: POLL_TIMEOUT })
      .toBeLessThanOrEqual(20);
  });

  test('releases and re-takes the scroll pin @mocked', async ({ page }) => {
    // Guarantees scrolling up stops the viewer from yanking the viewport
    // back down, and that "Scroll to bottom" restores the pin.
    await mockLogTail(page, makeLogLines(200));
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 200 of 200 lines held in this browser.'
    );
    await expect
      .poll(() => logs.paneBottomGap(), { timeout: POLL_TIMEOUT })
      .toBeLessThanOrEqual(20);

    await logs.scrollPaneUpBy(300);
    await expect(logs.autoScrollCheckbox).not.toBeChecked();
    await expect
      .poll(() => logs.paneBottomGap(), { timeout: POLL_TIMEOUT })
      .toBeGreaterThan(20);

    await logs.scrollToBottomButton.click();
    await expect(logs.autoScrollCheckbox).toBeChecked();
    await expect
      .poll(() => logs.paneBottomGap(), { timeout: POLL_TIMEOUT })
      .toBeLessThanOrEqual(20);
  });

  test('shows the matching rows when filtering from a scrolled-up position @mocked @slow', async ({
    page,
  }) => {
    // Regression: filtering shortens the content, and the browser clamps the
    // pane's scroll offset to fit -- but the viewer kept virtualizing from
    // the offset it had recorded before the filter, which now points past
    // the end of the filtered list. The pane rendered no rows at all while
    // the summary above it reported matches, so a filter that had worked
    // read as a filter that had found nothing.
    await mockLogTail(page, makeLogLines(2000).concat(DEFAULT_LOG_LINES));
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 2,004 of 2,004 lines held in this browser.',
      { timeout: LARGE_FIXTURE_TIMEOUT }
    );

    // Scroll away from the bottom: with the pin released, nothing else will
    // move the offset back into range on the viewer's behalf.
    await logs.scrollPaneUpBy(400);
    await expect(logs.autoScrollCheckbox).not.toBeChecked();

    await logs.textFilter.fill(WARNING_LINE);
    await expect(logs.summary).toContainText(
      'Showing 1 of 2,004 lines held in this browser.'
    );
    await expect(logs.rows()).toHaveCount(1);
    await expect(logs.logLine(WARNING_LINE)).toBeVisible();
  });

  test('mounts only a window of rows for a large buffer @mocked @slow', async ({
    page,
  }) => {
    test.slow();
    // Guarantees virtualization: the pane holds the whole buffer in state
    // but keeps the DOM to the rows around the viewport. Without it a busy
    // server freezes the tab.
    await mockLogTail(page, makeLogLines(CLIENT_TAIL_LIMIT));
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 10,000 of 10,000 lines held in this browser.',
      {
        timeout: LARGE_FIXTURE_TIMEOUT,
      }
    );
    const mounted = await logs.rows().count();
    expect(mounted).toBeGreaterThan(0);
    expect(mounted).toBeLessThan(200);
  });

  test('loads the remaining history and stops at the wall @mocked @slow', async ({
    page,
  }) => {
    test.slow();
    // Guarantees the scroll-up path: a buffer holding more than the
    // viewer's initial-load limit has history to fetch, the response that
    // carries the last of it also reports `reached`, and the viewer stops
    // asking once it has.
    await mockLogTail(page, makeLogLines(CLIENT_TAIL_LIMIT + 50));
    await logs.goto();
    await expect(logs.summary).toContainText(
      'Showing 10,000 of 10,000 lines held in this browser.',
      {
        timeout: LARGE_FIXTURE_TIMEOUT,
      }
    );
    await expect(logs.summary).not.toContainText('No more history.');

    await logs.scrollPaneToTop();
    await expect(logs.summary).toContainText('No more history.', {
      timeout: POLL_TIMEOUT,
    });
    await expect(logs.summary).toContainText(
      'Showing 10,050 of 10,050 lines held in this browser.'
    );

    // Re-hitting the top must not re-fetch or duplicate the history.
    await logs.scrollPaneToTop();
    await waitForForwardPoll(page);
    await logs.scrollPaneToTop();
    await waitForForwardPoll(page);
    await expect(logs.summary).toContainText(
      'Showing 10,050 of 10,050 lines held in this browser.'
    );
  });

  // ---------------------------------------------------------------------
  // Download and navigation
  // ---------------------------------------------------------------------

  test('downloads the buffered log as a gzip attachment @mocked', async ({
    page,
  }) => {
    // Guarantees the Download button performs a real download with the
    // filename the API promises -- asserting the button is visible would
    // pass even if the navigation 404'd.
    await mockLogDownload(page);
    const downloadPromise = page.waitForEvent('download');
    await logs.downloadButton.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(
      /^pelican-logs-.+-\d{8}-\d{6}Z\.log\.gz$/
    );
  });

  test('reaches the log viewer from the settings sidebar @smoke', async ({
    page,
  }) => {
    // Guarantees the Logs entry in the settings sidebar points at a page
    // that exists and renders.
    await page.goto(settingsRootUrl);
    await page.getByRole('link', { name: 'Logs', exact: true }).click();
    await expect(page).toHaveURL(/\/settings\/logs\//);
    await expect(logs.heading).toBeVisible();
    await expect(logs.summary).toContainText(
      'Showing 4 of 4 lines held in this browser.'
    );
  });
}
