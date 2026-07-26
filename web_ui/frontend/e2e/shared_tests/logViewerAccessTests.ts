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
import { mockLogTail } from '../mocks/api/v1.0/logs/tail';
import { mockWhoami } from '../mocks/api/v1.0/auth/whoami';

/**
 * Registers the access-control tests for the log viewer.
 *
 * The log viewer is the first surface reachable with a scope grant instead
 * of the admin role, so who may see it is a property worth pinning:
 * `pelican.log_read` must be enough to reach the page and no more than that,
 * and an account without it must not reach the page at all.
 *
 * These drive the client-side gates only — they pin who is offered the page,
 * not who the server will serve. The server's own gate is enforced by
 * LogReadAuthHandler and covered by the Go tests; the two are independent on
 * purpose, and a test here passing says nothing about that one.
 *
 * @param serviceUrl  The relative URL for the log viewer page
 *                    (e.g. './view/settings/logs/').
 */
export function registerLogViewerAccessTests(serviceUrl: string) {
  const settingsRootUrl = serviceUrl.replace(/logs\/?$/, '');

  test.describe('scope-only log reader', () => {
    test.beforeEach(async ({ page }) => {
      await mockWhoami(page, {
        user: 'triage',
        role: 'user',
        scopes: ['pelican.log_read'],
      });
      await mockLogTail(page);
    });

    test('reaches the log viewer without the admin role @mocked', async ({
      page,
    }) => {
      const logs = new LogViewerPage(page, serviceUrl);
      await logs.goto();

      await expect(logs.heading).toBeVisible();
      await expect(logs.pane).toBeVisible();
    });

    test('is offered Logs but not the admin-only settings pages @mocked', async ({
      page,
    }) => {
      await page.goto(serviceUrl);

      await expect(
        page.getByRole('link', { name: 'Logs', exact: true })
      ).toBeVisible();
      // Pages gated on the admin role alone. Asserting the Logs link is
      // present in the same breath keeps this from passing on a sidebar
      // that failed to render at all.
      await expect(
        page.getByRole('link', { name: 'AUP', exact: true })
      ).toHaveCount(0);
      await expect(
        page.getByRole('link', { name: 'API', exact: true })
      ).toHaveCount(0);
    });

    test('is moved off the admin-only settings index @mocked', async ({
      page,
    }) => {
      await page.goto(settingsRootUrl);

      // The settings index is the Restart Server surface, which this caller
      // cannot use, so it must send them somewhere they can reach rather
      // than show them a privileges error. Which page that is follows from
      // the order of the settings sidebar and is not pinned here; what
      // matters is that they are neither stranded on the index nor refused.
      await expect(page).not.toHaveURL(/settings\/?$/);
      await expect(page.getByText(/Insufficient privileges/i)).toHaveCount(0);
      await expect(
        page.getByRole('heading', { name: 'Restart Server' })
      ).toHaveCount(0);
    });
  });

  test.describe('user without the log-read scope', () => {
    test('is not shown the log viewer @mocked', async ({ page }) => {
      await mockWhoami(page, { user: 'nobody', role: 'user', scopes: [] });
      await mockLogTail(page);

      // Navigated directly rather than through LogViewerPage.goto, which
      // waits for the heading this caller must never be shown.
      const logs = new LogViewerPage(page, serviceUrl);
      await page.goto(serviceUrl);

      // AuthenticatedContent redirects an unauthorized caller away rather
      // than rendering the shell, so the pane must never appear.
      await expect(logs.pane).toHaveCount(0);
      await expect(logs.heading).toHaveCount(0);
    });

    test('is not offered a Logs link @mocked', async ({ page }) => {
      await mockWhoami(page, { user: 'nobody', role: 'user', scopes: [] });
      await mockLogTail(page);

      await page.goto(settingsRootUrl);
      await expect(
        page.getByRole('link', { name: 'Logs', exact: true })
      ).toHaveCount(0);
    });
  });

  test.describe('admin', () => {
    test('reaches the log viewer through the role gate @mocked', async ({
      page,
    }) => {
      // An admin holds no explicit pelican.log_read grant; the role alone
      // has to be sufficient, both for the sidebar entry and for the page.
      await mockWhoami(page, { user: 'admin', role: 'admin', scopes: [] });
      await mockLogTail(page);

      const logs = new LogViewerPage(page, serviceUrl);
      await logs.goto();
      await expect(logs.heading).toBeVisible();
      await expect(logs.pane).toBeVisible();
    });

    test('stays on the settings index rather than being redirected @mocked', async ({
      page,
    }) => {
      await mockWhoami(page, { user: 'admin', role: 'admin', scopes: [] });
      await mockLogTail(page);

      await page.goto(settingsRootUrl);
      await expect(page).toHaveURL(/settings\/?$/);
    });
  });
}
