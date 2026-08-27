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
import { DowntimeGet } from '@/types';

const DOWNTIME_URL_PATTERN = '**/api/v1.0/downtime**';

/**
 * Registers stateful route handlers for all downtime CRUD endpoints:
 *   GET    /api/v1.0/downtime        → returns current in-memory list
 *   POST   /api/v1.0/downtime        → creates entry, adds to list
 *   PUT    /api/v1.0/downtime/:id    → updates entry in list
 *   DELETE /api/v1.0/downtime/:id    → removes entry from list
 *
 * Call before page.goto() so the initial fetch is intercepted.
 * Call again (with a new list) inside a test to override the initial state
 * and re-navigate.
 *
 * @param page         Playwright Page instance.
 * @param initialList  Seed data for the in-memory list (default: empty).
 */
export async function mockDowntimeApi(
  page: Page,
  initialList: DowntimeGet[] = []
) {
  // Remove any previously-registered handlers so re-calls start clean.
  await page.unroute(DOWNTIME_URL_PATTERN);

  let downtimes: DowntimeGet[] = [...initialList];
  let idCounter = 1;

  await page.route(DOWNTIME_URL_PATTERN, (route) => {
    const method = route.request().method();
    const url = route.request().url();

    // Strip query-string, then grab the last path segment as the ID.
    const pathSegments = url.split('?')[0].split('/').filter(Boolean);
    const lastSegment = pathSegments[pathSegments.length - 1];
    // Only treat it as an ID if it doesn't equal "downtime".
    const id = lastSegment !== 'downtime' ? lastSegment : undefined;

    if (method === 'GET') {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(downtimes),
      });
    } else if (method === 'POST') {
      const body = JSON.parse(route.request().postData() ?? '{}');
      const now = Date.now();
      const newEntry: DowntimeGet = {
        id: `mock-id-${idCounter++}`,
        serverName: '',
        serverId: 'mock-server',
        createdBy: 'admin',
        updatedBy: 'admin',
        source: 'origin',
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
        class: body.class ?? 'UNSCHEDULED',
        description: body.description ?? '',
        severity: body.severity ?? 'No Significant Outage Expected',
        startTime: body.startTime ?? now,
        endTime: body.endTime ?? now + 24 * 60 * 60 * 1000,
      };
      downtimes.push(newEntry);
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(newEntry),
      });
    } else if (method === 'PUT' && id) {
      const body = JSON.parse(route.request().postData() ?? '{}');
      const index = downtimes.findIndex((d) => d.id === id);
      if (index !== -1) {
        downtimes[index] = {
          ...downtimes[index],
          ...body,
          updatedAt: Date.now(),
        };
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(downtimes[index]),
        });
      } else {
        route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Not found' }),
        });
      }
    } else if (method === 'DELETE' && id) {
      downtimes = downtimes.filter((d) => d.id !== id);
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: '{}',
      });
    } else {
      route.continue();
    }
  });
}
