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

import { test } from '@playwright/test';

import { SidebarPage } from '../shared_pages/SidebarPage';
import { PERSONAS, signIn } from '../shared_tests/navigationTests';

/**
 * Server-wide pages (Settings, Groups, Users, Profile) on a process running
 * more than one module. They belong to no module, so they borrow the rail of
 * the module the caller came from rather than showing a list of every module.
 *
 * The two rails are told apart by Object Browser, which the origin rail
 * offers an admin and the cache rail has no equivalent of. The module names
 * themselves are the old "shared" rail's rows, so their absence pins that it
 * is gone.
 */

// Cache listed first, so the fallback (first module the process runs) is
// distinguishable from "the module you came from" when that was the origin.
const servers = ['cache' as const, 'origin' as const];

const MODULE_LINKS = ['Origin', 'Cache', 'Director', 'Registry'];

test.describe('Server-wide pages keep the rail you came from', () => {
  test('arriving from the origin shows the origin rail @mocked', async ({
    page,
  }) => {
    await signIn(page, PERSONAS.admin, { servers });
    const sidebar = new SidebarPage(page);
    await sidebar.goto('./view/origin/');

    await sidebar.follow('Administration', '/settings/');

    await sidebar.expectOffers({
      offered: ['Object Browser'],
      withheld: MODULE_LINKS,
    });
  });

  test('arriving from the cache shows the cache rail @mocked', async ({
    page,
  }) => {
    await signIn(page, PERSONAS.admin, { servers });
    const sidebar = new SidebarPage(page);
    await sidebar.goto('./view/cache/');

    await sidebar.follow('Administration', '/settings/');

    await sidebar.expectOffers({
      offered: ['Metrics'],
      withheld: ['Object Browser', ...MODULE_LINKS],
    });
  });

  test('the module survives a full page load @mocked', async ({ page }) => {
    await signIn(page, PERSONAS.admin, { servers });
    const sidebar = new SidebarPage(page);
    await sidebar.goto('./view/origin/');

    // page.goto is a full load, not a client-side transition, so this only
    // passes if the module was persisted rather than held in memory.
    await signIn(page, PERSONAS.admin, { servers });
    await sidebar.goto('./view/settings/');

    await sidebar.expectOffers({
      offered: ['Object Browser'],
      withheld: MODULE_LINKS,
    });
  });

  test('with no module to remember, the first one the server runs @mocked', async ({
    page,
  }) => {
    await signIn(page, PERSONAS.admin, { servers });
    const sidebar = new SidebarPage(page);
    await sidebar.goto('./view/settings/');

    await sidebar.expectOffers({
      offered: ['Metrics'],
      withheld: ['Object Browser', ...MODULE_LINKS],
    });
  });
});
