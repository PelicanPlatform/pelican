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

import { test, expect } from '@playwright/test';
import { LogViewerPage } from '../shared_pages/LogViewerPage';
import { mockLogTail, mockLogTailDisabled } from '../mocks/api/v1.0/logs/tail';

// Distinctive substrings of the fixture lines (see DEFAULT_LOG_LINES). Chosen
// so each matches exactly one seeded line -- note both a warning/error and an
// info line mention "backend storage", so we always assert on the fuller
// phrase.
const INFO_LINE = 'Pelican origin started';
const WARNING_LINE = 'Disk space is running low';
const ERROR_LINE = 'Failed to connect to backend storage';
const INFO_LINE_2 = 'Recovered connection to backend storage';

/**
 * Registers the shared log-viewer tests for a given service URL. Call this
 * inside a `test.describe` block in each service's spec file.
 *
 * @param serviceUrl  The relative URL for the log viewer page
 *                    (e.g. './view/settings/logs/').
 */
export function registerLogViewerTests(serviceUrl: string) {
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
    await expect(logs.summary).toContainText('Showing 4 of 4 lines.');
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
    await expect(logs.summary).toContainText('Showing 2 of 4 lines.');
  });

  test('hides a level when its chip is toggled off @mocked', async () => {
    await expect(logs.logLine(ERROR_LINE)).toBeVisible();
    await logs.toggleLevel('error');
    await expect(logs.logLine(ERROR_LINE)).not.toBeVisible();
    // The non-error lines remain.
    await expect(logs.logLine(INFO_LINE)).toBeVisible();
    await expect(logs.summary).toContainText('Showing 3 of 4 lines.');
  });

  test('offers a log download control @smoke', async () => {
    await expect(logs.downloadButton).toBeVisible();
  });

  test('shows a notice when the buffer is disabled @mocked', async ({
    page,
  }) => {
    // Re-route to report the buffer disabled, then reload so the initial fetch
    // sees enabled=false. The later route registration takes precedence.
    await mockLogTailDisabled(page);
    await logs.goto();
    await expect(logs.unavailableNotice).toBeVisible();
    await expect(logs.logLine(INFO_LINE)).not.toBeVisible();
  });
}
