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

import { test, expect } from '@playwright/test';
import { TransferJobsPage } from '../shared_pages/TransferJobsPage';
import { TransferCredentialsPage } from '../shared_pages/TransferCredentialsPage';
import {
  mockTransferJobsApi,
  mockJobList,
} from '../mocks/api/v1.0/transfer/jobs';

// These tests run against a LIVE Pelican origin with the transfer API enabled.
// The credentials tests and the empty-jobs test hit the real API end to end
// (real auth, real encryption/storage) — no mocks. Only the populated-jobs and
// cancel cases are mocked, because a *running* job requires a real cross-origin
// transfer, which is out of scope for a web-UI test (it is covered by the Go
// cross-origin TPC e2e tests instead).

test.describe('Transfer Credentials (live API)', () => {
  // A real round-trip against the live transfer API: create a credential
  // through the UI (real POST + server-side encryption/storage), see it appear
  // (real GET), then delete it (real DELETE) and see it disappear. A unique
  // name keeps parallel/retried runs from colliding.
  test('creates, lists, and deletes a credential @smoke', async ({ page }) => {
    const credsPage = new TransferCredentialsPage(page);
    await credsPage.goto();

    const name = `e2e-cred-${Date.now()}`;
    await credsPage.addCredential(
      name,
      'e2e-dummy-access-token',
      'https://issuer.example/api/v1.0/issuer'
    );

    // The real GET after creation reflects the real POST.
    await expect(credsPage.rowByName(name)).toBeVisible();

    // The real DELETE removes it.
    await credsPage.deleteCredential(name);
    await expect(credsPage.rowByName(name)).not.toBeVisible();
  });
});

test.describe('Transfer Jobs (live API)', () => {
  // A real GET against the live jobs API. A freshly-started origin has no jobs,
  // so the page shows its empty state. (The transfer server's own e2e tests
  // exercise the populated/queued paths against a real federation.)
  test('shows the empty state from the live API @smoke', async ({ page }) => {
    const jobsPage = new TransferJobsPage(page);
    await jobsPage.goto();
    await expect(jobsPage.emptyState).toBeVisible();
  });
});

test.describe('Transfer Jobs (mocked — running jobs need a real transfer)', () => {
  test('renders jobs returned by the API @mocked', async ({ page }) => {
    await mockTransferJobsApi(page);
    const jobsPage = new TransferJobsPage(page);
    await jobsPage.goto();

    for (const job of mockJobList) {
      await expect(
        jobsPage.rowByIdPrefix(job.job_id.substring(0, 8))
      ).toBeVisible();
    }
    await expect(page.getByText('running', { exact: true })).toBeVisible();
    await expect(page.getByText('completed', { exact: true })).toBeVisible();
    await expect(page.getByText('failed', { exact: true })).toBeVisible();
  });

  test('cancels a running job via the API @mocked', async ({ page }) => {
    await mockTransferJobsApi(page);
    const jobsPage = new TransferJobsPage(page);
    await jobsPage.goto();

    const running = mockJobList.find((j) => j.status === 'running')!;
    const deleted = page.waitForRequest(
      (req) =>
        req.method() === 'DELETE' &&
        req.url().includes(`/api/v1.0/transfer/jobs/${running.job_id}`)
    );
    await jobsPage.cancelJob(running.job_id.substring(0, 8));
    await deleted;
  });
});
