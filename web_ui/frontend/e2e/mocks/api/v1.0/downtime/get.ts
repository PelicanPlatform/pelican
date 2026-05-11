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

const now = Date.now();
const DAY = 24 * 60 * 60 * 1000;

export const mockDowntimeList: DowntimeGet[] = [
  {
    id: 'mock-downtime-1',
    serverName: '',
    serverId: 'mock-server-1',
    createdBy: 'admin',
    updatedBy: 'admin',
    source: 'origin',
    class: 'SCHEDULED',
    description: 'Planned maintenance window',
    severity: 'Severe (most services down)',
    startTime: now - DAY,
    endTime: now + DAY,
    createdAt: now - DAY,
    updatedAt: now - DAY,
    deletedAt: null,
  },
  {
    id: 'mock-downtime-2',
    serverName: '',
    serverId: 'mock-server-1',
    createdBy: 'admin',
    updatedBy: 'admin',
    source: 'origin',
    class: 'UNSCHEDULED',
    description: 'Emergency network outage',
    severity: 'Outage (completely inaccessible)',
    startTime: now - 7 * DAY,
    endTime: -1,
    createdAt: now - 7 * DAY,
    updatedAt: now - 7 * DAY,
    deletedAt: null,
  },
  {
    id: 'mock-downtime-3',
    serverName: '',
    serverId: 'mock-server-1',
    createdBy: 'admin',
    updatedBy: 'admin',
    source: 'origin',
    class: 'SCHEDULED',
    description: 'Brief yesterday outage',
    severity: 'Intermittent Outage (may be up for some of the time)',
    startTime: now - DAY,
    endTime: now - DAY / 2,
    createdAt: now - DAY,
    updatedAt: now - DAY,
    deletedAt: null,
  },
];

/**
 * Intercepts GET /api/v1.0/downtime and returns the provided fixture.
 * Defaults to a two-entry list with one scheduled and one indefinite downtime.
 */
export async function mockGetDowntime(
  page: Page,
  response: DowntimeGet[] = mockDowntimeList
) {
  await page.route('**/api/v1.0/downtime**', (route) => {
    if (route.request().method() === 'GET') {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
    } else {
      route.continue();
    }
  });
}
