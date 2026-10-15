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

const HOME = './view/origin/';
const servers = ['origin' as const];

/**
 * Origin navigation.
 *
 * The Origin has the most destinations of any module and the widest spread of
 * who may reach them, which makes it the module where the rail agreeing with
 * the pages matters most. Two entries here are regression tests for rows that
 * were offered to every signed-in caller and then refused them: the Object
 * Browser, whose page is an admin-only wall, and Metrics, whose data endpoint
 * demands the monitoring.query scope.
 */
test.describe('Origin navigation', () => {
  test.describe('admin', () => {
    test.beforeEach(async ({ page }) => {
      await signIn(page, PERSONAS.admin, { servers });
    });

    test('reaches the Object Browser from the rail @mocked @smoke', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Object Browser', '/origin/client/');
    });

    test('reaches Metrics from the rail @mocked @smoke', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Metrics', '/origin/metrics/');
    });

    test('reaches Downtime from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Downtime', '/origin/downtime/');
    });

    test('reaches both collection views through the submenu @mocked', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      // Collections is a section, not a destination: it has to be opened
      // before either child is reachable.
      await sidebar.openSection('Collections');
      await sidebar.follow('All Collections', '/origin/collections/');

      await sidebar.openSection('Collections');
      await sidebar.follow('My Collections', '/origin/owned/');
    });

    test('reaches the Issuer from the Access group @mocked', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Issuer', '/origin/issuer/');
    });

    test('reaches the server-wide Access destinations @mocked', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      // Groups and Users sit in every module's rail rather than inside the
      // administration menu, so arriving at one must not depend on having
      // been to Settings first.
      await sidebar.follow('Users', '/users/');

      await sidebar.goto(HOME);
      await sidebar.follow('Groups', '/groups/');
    });

    test('is offered the full Origin rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({
        offered: [
          'Dashboard',
          'Object Browser',
          'Collections',
          'Metrics',
          'Downtime',
          'Groups',
          'Users',
          'Issuer',
          'Administration',
        ],
      });
    });
  });

  test.describe('signed-in user without privileges', () => {
    test.beforeEach(async ({ page }) => {
      await signIn(page, PERSONAS.user, { servers });
    });

    test('is offered only what it can open @mocked @smoke', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({
        offered: ['Dashboard', 'Collections', 'Groups'],
        // Object Browser and Issuer are admin-only pages; Metrics needs
        // monitoring.query; Users needs server.user_admin. Every one of
        // these was offered to this caller before the rail was taught the
        // page's own gate.
        withheld: [
          'Object Browser',
          'Metrics',
          'Issuer',
          'Users',
          'Administration',
        ],
      });
    });

    test('reaches its collections from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.openSection('Collections');
      await sidebar.follow('My Collections', '/origin/owned/');
    });

    test('is refused the Object Browser by URL @mocked', async ({ page }) => {
      await expectRefused(page, './view/origin/client/');
    });
  });

  test.describe('user granted monitoring.query', () => {
    test('is offered Metrics and arrives @mocked @smoke', async ({ page }) => {
      await signIn(page, PERSONAS.monitor, { servers });
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      // The scope, not the admin role, is what /prometheus/query checks, so
      // a caller holding it must be offered the dashboards. Withholding the
      // Object Browser in the same breath keeps this honest: the scope buys
      // this one destination and nothing else.
      await sidebar.expectOffers({ withheld: ['Object Browser'] });
      await sidebar.follow('Metrics', '/origin/metrics/');
    });
  });

  test.describe('user granted server.user_admin', () => {
    test('is offered Users and arrives @mocked', async ({ page }) => {
      await signIn(page, PERSONAS.userAdmin, { servers });
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({ withheld: ['Administration'] });
      await sidebar.follow('Users', '/users/');
    });
  });

  test.describe('standalone Origin', () => {
    test('withholds the federation-only Downtime row @mocked', async ({
      page,
    }) => {
      await signIn(page, PERSONAS.admin, {
        servers,
        standaloneOrigin: true,
      });
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      // Downtime exists so a Director can route around this server and a
      // Registry can persist the record. A standalone Origin has neither, so
      // the row would be a control that can never take effect.
      await sidebar.expectOffers({
        offered: ['Dashboard', 'Metrics'],
        withheld: ['Downtime'],
      });
    });
  });

  registerSettingsAccessTests(servers);
});
