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

const HOME = './view/registry/';
const servers = ['registry' as const];

/**
 * Registry navigation.
 *
 * The interesting caller here is the ordinary signed-in user. Registering a
 * namespace is open to them -- POST /registry_ui/namespaces carries
 * AuthHandler alone, and admin is required only to approve, deny or delete --
 * so the Add section must be offered to them. It was admin-gated for a while,
 * which hid the only link to the registration forms from exactly the people
 * those forms exist for.
 */
test.describe('Registry navigation', () => {
  test.describe('admin', () => {
    test.beforeEach(async ({ page }) => {
      await signIn(page, PERSONAS.admin, { servers });
    });

    test('reaches each registration form through Add @mocked @smoke', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.openSection('Add');
      await sidebar.follow('Namespace', '/registry/namespace/register/');

      await sidebar.goto(HOME);
      await sidebar.openSection('Add');
      await sidebar.follow('Origin', '/registry/origin/register/');

      await sidebar.goto(HOME);
      await sidebar.openSection('Add');
      await sidebar.follow('Cache', '/registry/cache/register/');
    });

    test('reaches Denied Namespaces from the rail @mocked', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Denied Namespaces', '/registry/denied/');
    });

    test('reaches Downtime from the rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);
      await sidebar.follow('Downtime', '/registry/downtime/');
    });

    test('is offered the full Registry rail @mocked', async ({ page }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({
        offered: [
          'Dashboard',
          'Add',
          'Denied Namespaces',
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

    test('can register a namespace from the rail @mocked @smoke', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.openSection('Add');
      await sidebar.follow('Namespace', '/registry/namespace/register/');
    });

    test('is offered registration but not the admin triage views @mocked', async ({
      page,
    }) => {
      const sidebar = new SidebarPage(page);
      await sidebar.goto(HOME);

      await sidebar.expectOffers({
        offered: ['Dashboard', 'Add', 'Groups'],
        // Approving, denying and scheduling downtime are admin actions, and
        // the pages behind these rows assume an admin is looking at them.
        withheld: ['Denied Namespaces', 'Downtime', 'Users', 'Administration'],
      });
    });
  });

  registerSettingsAccessTests(servers);
});
