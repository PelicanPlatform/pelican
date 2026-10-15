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

const HOME = './view/transfer/';
const servers = ['transfer' as const];

/**
 * Transfer navigation.
 *
 * Every destination in this rail is an admin-only page, and until recently
 * not one of them said so. A signed-in non-admin was shown three rows and met
 * a privileges wall on each: unlike the other modules there was nothing left
 * for them afterwards, so the whole module was a dead end. These tests pin
 * both halves -- an admin can reach all three, and a non-admin is offered
 * none of them.
 */
test.describe('Transfer navigation', () => {
  test.describe('admin', () => {
    test.beforeEach(async ({ page }) => {
      await signIn(page, PERSONAS.admin, { servers });
    });

    test('reaches Jobs from the rail @mocked @smoke', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Jobs', '/transfer/jobs/');
    });

    test('reaches Credentials from the rail @mocked @smoke', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Credentials', '/transfer/credentials/');
    });

    test('returns to the Dashboard from a sub-page @mocked', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto('./view/transfer/jobs/');

      // The rail is the only way back: Transfer has no sub-navigation, and
      // Dashboard is an exactMatch entry, so it must not already be lit from
      // the Jobs page.
      await sidebar.follow('Dashboard', '/transfer/');
    });

    test('is offered the full Transfer rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({
        offered: [
          'Dashboard',
          'Jobs',
          'Credentials',
          'Groups',
          'Administration',
        ],
      });
    });
  });

  test.describe('signed-in user without privileges', () => {
    test.beforeEach(async ({ page }) => {
      await signIn(page, PERSONAS.user, { servers });
    });

    test('is offered none of the Transfer destinations @mocked @smoke', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      // Groups is the control: it is the one thing this caller can still
      // reach from here, and its presence proves the rail rendered at all
      // rather than the three absences below being a blank sidebar.
      await sidebar.expectOffers({
        offered: ['Groups'],
        withheld: ['Dashboard', 'Jobs', 'Credentials', 'Administration'],
      });
    });

    test('is refused Jobs by URL @mocked', async ({ page }) => {
      await expectRefused(page, './view/transfer/jobs/');
    });

    test('is refused Credentials by URL @mocked', async ({ page }) => {
      await expectRefused(page, './view/transfer/credentials/');
    });
  });

  registerSettingsAccessTests(servers);
});
