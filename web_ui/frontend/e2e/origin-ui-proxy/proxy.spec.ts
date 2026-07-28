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

// WS5 ("reduce origin requirements"): the director proxies a FIREWALLED origin's
// web UI so an admin manages it entirely against the director. This runs against
// a real two-process federation started by the CI harness:
//   - a director+registry (the baseURL for this project), and
//   - a SEPARATE broker-mode origin the admin can never reach directly.
//
// The flow mirrors real usage (and the Go curl harness that verified it):
//   1. log into the DIRECTOR (its own session),
//   2. enter "view origin" mode (the admin-gated control endpoint the director-UI
//      "View Origin UI" button hits) — the director serves the origin pages from
//      its own bundle and proxies origin-owned APIs to the origin over the broker,
//   3. log into the ORIGIN THROUGH the proxy — the origin (not the director)
//      authenticates, and the bridged cookie carries that session.
//
// Env (set by the CI job):
//   TARGET_DIRECTOR_UI_PROXY_URL - the director base URL
//   PELICAN_VIEW_ORIGIN_ID       - the broker origin's ServerID
//   PELICAN_E2E_PASSWORD         - the admin password (default "password")

const originId = process.env.PELICAN_VIEW_ORIGIN_ID;
const password = process.env.PELICAN_E2E_PASSWORD || 'password';

// Log in via the form-POST endpoint; page.request shares the browser context's
// cookie jar, so the resulting session cookie is used by subsequent navigations.
// The Origin header must match the host being addressed or the same-origin (CSRF)
// guard rejects the POST — and for the origin login that host is the director,
// which the proxy rewrites to the origin on the way through.
async function login(page: Page, baseURL: string) {
  const resp = await page.request.post('./api/v1.0/auth/login', {
    form: { user: 'admin', password },
    headers: { Origin: baseURL, 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  expect(resp.ok(), `login failed: ${resp.status()}`).toBeTruthy();
}

test.describe('Director proxies a firewalled origin UI (WS5)', () => {
  test.skip(!originId, 'requires the two-process origin-ui-proxy harness env');

  test('the director server list offers a View Origin UI action @smoke', async ({
    page,
    baseURL,
  }) => {
    await login(page, baseURL!);
    await page.goto('./view/director/');

    // The admin-only proxy entry point links to the select control endpoint,
    // targeting this specific origin's ServerID.
    const viewLink = page.locator(`a[href*="/api/v1.0/origin-ui/select/"]`).first();
    await expect(viewLink).toBeVisible();
    expect(await viewLink.getAttribute('href')).toContain(originId!);
  });

  test('view mode serves the origin dashboard and proxies its API @smoke', async ({
    page,
    baseURL,
  }) => {
    await login(page, baseURL!);

    // Enter "view origin" mode via the admin-gated control endpoint (what the
    // director-UI button does): it sets the view cookie and redirects to the
    // origin dashboard the director serves from its own bundle.
    await page.goto(`./api/v1.0/origin-ui/select/${originId}`);
    await expect(page).toHaveURL(/\/view\/origin\//);

    // Now authenticate to the ORIGIN through the proxy. The origin mints/verifies
    // this session itself; the proxy bridges the cookie so it coexists with the
    // director's.
    await login(page, baseURL!);

    // An origin-owned API call must be answered by the (remote) origin, proxied
    // over the broker — the core WS5 behavior. Reload the dashboard and watch it.
    const proxiedApi = page.waitForResponse(
      (r) =>
        r.url().includes('/api/v1.0/origin_ui/') && r.request().method() === 'GET',
      { timeout: 30_000 }
    );
    await page.goto('./view/origin/');
    const resp = await proxiedApi;
    expect(
      resp.status(),
      'origin-owned API proxied to the origin should succeed'
    ).toBeLessThan(400);

    // The origin dashboard rendered through the director (not the not-enabled
    // 404 page), even though the director itself runs no origin module.
    await expect(page).toHaveURL(/\/view\/origin\//);
    await expect(page.locator('body')).not.toContainText('404');
  });
});
