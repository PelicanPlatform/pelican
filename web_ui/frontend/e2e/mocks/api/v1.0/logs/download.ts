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

import { gzipSync } from 'zlib';
import { Page } from '@playwright/test';

import { DEFAULT_LOG_LINES } from './tail';

const DOWNLOAD_URL_PATTERN = '**/api/v1.0/logs/download**';

/**
 * Builds the filename web_ui.HandleLogTailDownload puts in the
 * Content-Disposition header: the sanitized server hostname plus a UTC
 * timestamp, so downloads from different servers or times don't collide.
 */
export function logDownloadFilename(host = 'e2e-server'): string {
  const stamp = new Date()
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')
    .replace('T', '-');
  return `pelican-logs-${host}-${stamp}.log.gz`;
}

/**
 * Intercepts GET /api/v1.0/logs/download and serves a gzip attachment.
 *
 * Without this the Download button navigates to the real server, so the
 * only thing a test could assert was that the button exists. With it the
 * browser performs an actual download and the filename contract is
 * observable.
 */
export async function mockLogDownload(
  page: Page,
  lines: string[] = DEFAULT_LOG_LINES
) {
  await page.unroute(DOWNLOAD_URL_PATTERN);
  await page.route(DOWNLOAD_URL_PATTERN, (route) => {
    if (route.request().method() !== 'GET') {
      route.continue();
      return;
    }
    const body = gzipSync(
      Buffer.from(lines.length > 0 ? lines.join('\n') + '\n' : '')
    );
    route.fulfill({
      status: 200,
      headers: {
        'Content-Type': 'application/gzip',
        'Content-Disposition': `attachment; filename="${logDownloadFilename()}"`,
      },
      body,
    });
  });
}
