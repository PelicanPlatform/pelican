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

import { Page } from '@playwright/test';

// Mirrors web_ui.LogTailResponse (the JSON returned by GET
// /api/v1.0/logs/tail). Kept local to the e2e suite so the tests don't
// depend on the app's internal types.
export interface LogTailResponse {
  enabled: boolean;
  content: string;
  firstCursor: string;
  lastCursor: string;
  reached: boolean;
  instanceId: string;
}

// Opaque cursor/instance markers. Their exact values don't matter to the
// client (it only echoes them back); they just need to be stable within a
// run so restart-detection in the viewer doesn't trip.
const INSTANCE_ID = 'e2e-log-instance';
const FIRST_CURSOR = 'e2e-first';
const LAST_CURSOR = 'e2e-last';

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
 * Intercepts GET /api/v1.0/logs/tail and serves a stable fixture.
 *
 * The viewer loads once with an empty `since` cursor and then polls forward
 * every couple of seconds. To keep the rendered content stable across polls
 * we return the full fixture only on the initial (empty-cursor) load; forward
 * polls and scroll-up (`before=`) requests return no new content, so the four
 * seeded lines stay put for the duration of the test.
 *
 * Pass an empty `lines` array to exercise a buffer that is enabled but empty.
 */
export async function mockLogTail(
  page: Page,
  lines: string[] = DEFAULT_LOG_LINES
) {
  const content = lines.length > 0 ? lines.join('\n') + '\n' : '';
  await page.route('**/api/v1.0/logs/tail**', (route) => {
    const req = route.request();
    if (req.method() !== 'GET') {
      route.continue();
      return;
    }
    const url = new URL(req.url());
    const since = url.searchParams.get('since');
    const before = url.searchParams.get('before');

    let body: LogTailResponse;
    if (before !== null) {
      // Scroll-up: the mock holds no history older than the initial load.
      body = {
        enabled: true,
        content: '',
        firstCursor: before,
        lastCursor: before,
        reached: true,
        instanceId: INSTANCE_ID,
      };
    } else if (since) {
      // Steady-state forward poll after the initial load: nothing new.
      body = {
        enabled: true,
        content: '',
        firstCursor: '',
        lastCursor: since,
        reached: false,
        instanceId: INSTANCE_ID,
      };
    } else {
      // Initial load: hand back the whole fixture.
      body = {
        enabled: true,
        content,
        firstCursor: FIRST_CURSOR,
        lastCursor: LAST_CURSOR,
        reached: false,
        instanceId: INSTANCE_ID,
      };
    }
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(body),
    });
  });
}

/**
 * Intercepts GET /api/v1.0/logs/tail and reports the buffer as disabled,
 * so the viewer renders its "not available" notice instead of a log pane.
 */
export async function mockLogTailDisabled(page: Page) {
  await page.route('**/api/v1.0/logs/tail**', (route) => {
    if (route.request().method() !== 'GET') {
      route.continue();
      return;
    }
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        enabled: false,
        content: '',
        firstCursor: '',
        lastCursor: '',
        reached: false,
        instanceId: '',
      } satisfies LogTailResponse),
    });
  });
}
