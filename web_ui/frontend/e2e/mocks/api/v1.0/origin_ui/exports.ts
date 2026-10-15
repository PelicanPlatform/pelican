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

const EXPORTS_URL_PATTERN = '**/api/v1.0/origin_ui/exports**';

export interface ExportsOptions {
  /** The Origin's storage backend; `globus` is the one the rail branches on. */
  type?: 'posix' | 'globus' | 's3' | 'https';
  /** Answer 403 instead, as the server does for a non-admin caller. */
  forbidden?: boolean;
}

/**
 * Intercepts GET /api/v1.0/origin_ui/exports.
 *
 * Only one rail entry reads it -- the Origin's Globus row, via
 * `allowedExportTypes` -- but the rail will not draw until the request has
 * settled for an admin caller, so every Origin navigation test needs it
 * answered one way or the other.
 *
 * The real endpoint is admin-gated and returns storage credentials, which is
 * why `Navigation` skips the fetch entirely for non-admins. `forbidden` is
 * here so a test can reproduce the admin-who-gets-403 case and confirm the
 * rail still resolves instead of waiting forever.
 */
export async function mockExports(
  page: Page,
  { type = 'posix', forbidden = false }: ExportsOptions = {}
) {
  await page.unroute(EXPORTS_URL_PATTERN);
  await page.route(EXPORTS_URL_PATTERN, (route) => {
    if (route.request().method() !== 'GET') {
      route.continue();
      return;
    }
    if (forbidden) {
      route.fulfill({
        status: 403,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: 'error',
          msg: 'Admin privilege required',
        }),
      });
      return;
    }
    route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, exports: [] }),
    });
  });
}
