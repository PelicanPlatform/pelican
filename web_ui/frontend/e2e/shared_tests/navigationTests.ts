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

import { SidebarPage } from '../shared_pages/SidebarPage';
import { mockWhoami } from '../mocks/api/v1.0/auth/whoami';
import { mockServerInfo, ServerModule } from '../mocks/api/v1.0/servers';
import { mockExports } from '../mocks/api/v1.0/origin_ui/exports';

/**
 * Shared fixtures for the navigation tests.
 *
 * These drive the client-side rail only. They pin which destinations a caller
 * is *offered* and that following the offer lands somewhere usable; they say
 * nothing about what the server would serve. The server's gates are the real
 * boundary and are covered by the Go tests. The two are independent on
 * purpose -- which is precisely why the rail could, and did, offer links to
 * pages that refuse the caller.
 */

/** The callers worth distinguishing, as /whoami would describe them. */
export const PERSONAS = {
  /** Takes every role gate in the UI. */
  admin: { user: 'e2e-admin', role: 'admin' as const, scopes: [] },
  /** Signed in, holds nothing. The caller most of these tests are about. */
  user: { user: 'e2e-user', role: 'user' as const, scopes: [] },
  /**
   * Granted monitoring.query and nothing else. The scope /prometheus/query
   * demands, so this caller can genuinely use the metrics dashboards without
   * being an admin -- the scope's own description says as much.
   */
  monitor: {
    user: 'e2e-monitor',
    role: 'user' as const,
    scopes: ['monitoring.query'],
  },
  /** Granted server.user_admin; reaches Users without the admin role. */
  userAdmin: {
    user: 'e2e-user-admin',
    role: 'user' as const,
    scopes: ['server.user_admin'],
  },
};

export type Persona = (typeof PERSONAS)[keyof typeof PERSONAS];

/**
 * Pins the caller and the two other responses the rail waits on before it
 * will draw anything (see `resolved` in Navigation.tsx). Call this before
 * every navigation, not once per file: route handlers are per-page and the
 * rail re-reads all three on a fresh load.
 */
export async function signIn(
  page: Page,
  persona: Persona,
  {
    servers = ['origin'],
    standaloneOrigin = false,
  }: { servers?: ServerModule[]; standaloneOrigin?: boolean } = {}
) {
  await mockWhoami(page, { authenticated: true, ...persona });
  await mockServerInfo(page, { servers, standaloneOrigin });
  await mockExports(page);
}

/** As above, for a caller who has not signed in at all. */
export async function signedOut(
  page: Page,
  { servers = ['origin'] }: { servers?: ServerModule[] } = {}
) {
  await mockWhoami(page, { authenticated: false, role: '', scopes: [] });
  await mockServerInfo(page, { servers });
  await mockExports(page);
}

/**
 * Asserts a destination refuses this caller when they reach it by URL rather
 * than through the rail.
 *
 * A signed-in caller who lacks the role is *not* redirected -- redirecting
 * them to /login would bounce them straight back here after a successful
 * login -- so the refusal is the "Insufficient privileges" card, and that is
 * what this looks for.
 */
export async function expectRefused(page: Page, url: string) {
  await page.goto(url);
  await expect(
    page.getByRole('heading', { name: 'Insufficient privileges' })
  ).toBeVisible();
}

/**
 * Registers the access tests every service shares: no caller short of an
 * admin may reach the Settings shell, and none of them is offered a route to
 * it from the rail.
 *
 * Settings is the one destination common to all five rails, which makes it
 * the natural place to pin the negative case once rather than five times.
 *
 * @param servers The modules this service's rail should believe are running.
 */
export function registerSettingsAccessTests(servers: ServerModule[]) {
  test.describe('Settings is withheld from non-admins', () => {
    test('a plain user is offered no route to Settings @mocked @smoke', async ({
      page,
    }) => {
      await signIn(page, PERSONAS.user, { servers });
      const sidebar = new SidebarPage(page);
      await sidebar.goto(`./view/${servers[0]}/`);

      // Groups is the control: every signed-in caller gets it, so its
      // presence proves the rail rendered and the absence below is real.
      await sidebar.expectOffers({
        offered: ['Groups'],
        withheld: ['Administration'],
      });
    });

    test('a plain user is refused the Settings shell by URL @mocked', async ({
      page,
    }) => {
      await signIn(page, PERSONAS.user, { servers });
      await expectRefused(page, './view/settings/');
    });

    test('a plain user is refused the config editor by URL @mocked', async ({
      page,
    }) => {
      await signIn(page, PERSONAS.user, { servers });
      await expectRefused(page, './view/settings/config/');
    });

    test('a signed-out caller is offered nothing behind a login @mocked', async ({
      page,
    }) => {
      await signedOut(page, { servers });
      const sidebar = new SidebarPage(page);
      await page.goto(`./view/${servers[0]}/`);

      // Anonymous callers used to be shown every entry that carried no
      // explicit role, padlocked, including links straight to a login wall.
      // Nothing that needs an account should appear at all now.
      await expect(sidebar.nav).toBeVisible();
      await sidebar.expectOffers({
        withheld: ['Administration', 'Groups', 'Users'],
      });
    });

    test('an admin is offered Settings and arrives @mocked @smoke', async ({
      page,
    }) => {
      await signIn(page, PERSONAS.admin, { servers });
      const sidebar = new SidebarPage(page);
      await sidebar.goto(`./view/${servers[0]}/`);

      await sidebar.follow('Administration', '/settings/');
    });
  });
}
