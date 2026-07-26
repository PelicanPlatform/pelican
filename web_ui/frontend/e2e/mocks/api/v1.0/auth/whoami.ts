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

const WHOAMI_URL_PATTERN = '**/api/v1.0/auth/whoami**';

export interface WhoamiOptions {
  authenticated?: boolean;
  user?: string;
  /** 'admin' takes every role gate; 'user' relies on `scopes`. */
  role?: 'admin' | 'user' | '';
  /** Effective user-grantable scopes, as EffectiveScopesForIdentity emits. */
  scopes?: string[];
  displayName?: string;
  requiresAup?: boolean;
  aupVersion?: string;
}

/**
 * Intercepts GET /api/v1.0/auth/whoami so a test can pin the caller's role
 * and effective scope set, which is the only input every client-side access
 * gate (AuthenticatedContent, SubNavigation, both NavigationItem copies)
 * reads.
 *
 * The X-CSRF-Token response header is load-bearing, not decoration:
 * helpers/login.ts stashes it in sessionStorage on the first whoami and
 * secureFetch sends it on every subsequent API call. A whoami mock that
 * omits it leaves the token null and the failures surface far from here.
 */
export async function mockWhoami(
  page: Page,
  {
    authenticated = true,
    user = 'e2e-user',
    role = 'user',
    scopes = [],
    displayName,
    requiresAup = false,
    aupVersion,
  }: WhoamiOptions = {}
) {
  await page.unroute(WHOAMI_URL_PATTERN);
  await page.route(WHOAMI_URL_PATTERN, (route) => {
    if (route.request().method() !== 'GET') {
      route.continue();
      return;
    }
    route.fulfill({
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': 'e2e-csrf-token',
      },
      body: JSON.stringify({
        authenticated,
        user: authenticated ? user : '',
        role: authenticated ? role : '',
        scopes,
        displayName,
        requires_aup: requiresAup,
        aup_version: aupVersion,
      }),
    });
  });
}
