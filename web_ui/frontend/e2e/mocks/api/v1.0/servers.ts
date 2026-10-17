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

const SERVERS_URL_PATTERN = '**/api/v1.0/servers**';

export type ServerModule =
  | 'origin'
  | 'cache'
  | 'director'
  | 'registry'
  | 'transfer';

export interface ServerInfoOptions {
  /** Which modules this process runs; drives the shared (`sharedPage`) rail. */
  servers?: ServerModule[];
  /** True when the Origin belongs to no federation; hides federationOnly items. */
  standaloneOrigin?: boolean;
}

/**
 * Intercepts GET /api/v1.0/servers, which `getServerInfo` reads.
 *
 * Worth pinning in any navigation test for two reasons. It decides which rail
 * the `sharedPage` routes (/settings/, /groups/, /users/) render, and its
 * `standaloneOrigin` flag is what prunes `federationOnly` entries -- so
 * whether the Origin's Downtime row exists at all depends on this response.
 *
 * It is also one of the three requests the rail waits on before it draws
 * anything (see `resolved` in components/layout/Navigation/Navigation.tsx).
 * Left to hit a real server, a slow or missing answer leaves the rail showing
 * its placeholder and every link assertion fails for the wrong reason.
 */
export async function mockServerInfo(
  page: Page,
  { servers = ['origin'], standaloneOrigin = false }: ServerInfoOptions = {}
) {
  await page.unroute(SERVERS_URL_PATTERN);
  await page.route(SERVERS_URL_PATTERN, (route) => {
    if (route.request().method() !== 'GET') {
      route.continue();
      return;
    }
    route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ servers, standaloneOrigin }),
    });
  });
}
