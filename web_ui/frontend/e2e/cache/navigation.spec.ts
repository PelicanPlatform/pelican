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
  registerSettingsAccessTests,
  signIn,
} from '../shared_tests/navigationTests';

const HOME = './view/cache/';
const servers = ['cache' as const];

/**
 * Cache navigation.
 *
 * The Cache rail is the shortest of the five, which makes the Metrics row the
 * whole story: it was admin-only here while the page behind it has no gate of
 * its own and its data endpoint gates on monitoring.query instead. That hid
 * the dashboards from a user who had been deliberately granted the scope.
 */
test.describe('Cache navigation', () => {
  test.describe('admin', () => {
    test.beforeEach(async ({ page }) => {
      await signIn(page, PERSONAS.admin, { servers });
    });

    test('reaches Metrics from the rail @mocked @smoke', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Metrics', '/cache/metrics/');
    });

    test('reaches Downtime from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Downtime', '/cache/downtime/');
    });

    test('is offered the full Cache rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({
        offered: [
          'Dashboard',
          'Metrics',
          'Downtime',
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
        offered: ['Dashboard', 'Downtime', 'Groups'],
        withheld: ['Metrics', 'Users', 'Administration'],
      });
    });

    test('reads Downtime from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Downtime', '/cache/downtime/');
    });
  });

  test.describe('user granted monitoring.query', () => {
    test('is offered Metrics and arrives @mocked @smoke', async ({ page }) => {
      await signIn(page, PERSONAS.monitor, { servers });
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({ withheld: ['Administration'] });
      await sidebar.follow('Metrics', '/cache/metrics/');
    });
  });

  registerSettingsAccessTests(servers);
});
