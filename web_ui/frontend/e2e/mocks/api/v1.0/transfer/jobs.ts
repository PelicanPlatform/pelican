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

export interface MockTransferJob {
  job_id: string;
  status: string;
  created_at: string;
  completed_at?: string;
  error?: string;
}

const now = Date.now();
const iso = (ms: number) => new Date(ms).toISOString();

export const mockJobList: MockTransferJob[] = [
  {
    job_id: 'aaaaaaaa-1111-2222-3333-444444444444',
    status: 'running',
    created_at: iso(now - 60_000),
  },
  {
    job_id: 'bbbbbbbb-1111-2222-3333-444444444444',
    status: 'completed',
    created_at: iso(now - 3_600_000),
    completed_at: iso(now - 3_500_000),
  },
  {
    job_id: 'cccccccc-1111-2222-3333-444444444444',
    status: 'failed',
    created_at: iso(now - 7_200_000),
    completed_at: iso(now - 7_100_000),
    error: 'source unreachable',
  },
];

/**
 * Intercepts the transfer-jobs API so the transfer pages can be tested against a
 * live web UI without a working transfer backend:
 *   - GET  /api/v1.0/transfer/jobs        -> { jobs, total, limit, offset }
 *   - DELETE /api/v1.0/transfer/jobs/{id} -> { job_id, message }
 */
export async function mockTransferJobsApi(
  page: Page,
  jobs: MockTransferJob[] = mockJobList
) {
  await page.route('**/api/v1.0/transfer/jobs**', (route) => {
    const method = route.request().method();
    if (method === 'GET') {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jobs,
          total: jobs.length,
          limit: 50,
          offset: 0,
        }),
      });
    } else if (method === 'DELETE') {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ job_id: 'cancelled', message: 'Job cancelled' }),
      });
    } else {
      route.continue();
    }
  });
}
