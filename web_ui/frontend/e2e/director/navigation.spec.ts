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
import {
  PERSONAS,
  expectRefused,
  registerSettingsAccessTests,
  signIn,
} from '../shared_tests/navigationTests';

const HOME = './view/director/';
const servers = ['director' as const];

/**
 * Director navigation.
 *
 * The Director is the module that already got this right, and these tests are
 * mostly here to keep it that way. Its Dashboard renders for any signed-in
 * caller and hides two admin-only widgets inside itself rather than refusing
 * the page, and Downtime and Map are genuinely public reads -- so a non-admin
 * has real destinations here, unlike on Transfer.
 */
test.describe('Director navigation', () => {
  test.describe('admin', () => {
    test.beforeEach(async ({ page }) => {
      await signIn(page, PERSONAS.admin, { servers });
    });

    test('reaches Metrics from the rail @mocked @smoke', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Metrics', '/director/metrics/');
    });

    test('reaches Downtime from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Downtime', '/director/downtime/');
    });

    test('reaches the server Map from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Map', '/director/map/');
    });

    test('is offered the full Director rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({
        offered: [
          'Dashboard',
          'Metrics',
          'Downtime',
          'Map',
          'Groups',
          'Users',
          'Administration',
        ],
      });
    });
  });

  test.describe('signed-in user without privileges', () => {
    test.beforeEach(async ({ page }) => {
      await signIn(page, PERSONAS.user, { servers });
    });

    test('keeps the destinations it can actually use @mocked @smoke', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({
        offered: ['Dashboard', 'Downtime', 'Map', 'Groups'],
        withheld: ['Metrics', 'Users', 'Administration'],
      });
    });

    test('reaches the Map from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      // /director_ui/servers carries no auth handler, so this page is a real
      // destination for a non-admin rather than a link to a refusal.
      await sidebar.follow('Map', '/director/map/');
    });

    test('reads Downtime from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Downtime', '/director/downtime/');
    });

    test('is refused Metrics by URL @mocked', async ({ page }) => {
      await expectRefused(page, './view/director/metrics/');
    });
  });

  registerSettingsAccessTests(servers);
});
