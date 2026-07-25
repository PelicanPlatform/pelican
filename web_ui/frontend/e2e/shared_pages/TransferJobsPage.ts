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

import { Page, Locator, expect } from '@playwright/test';

/**
 * Page Object Model for the Transfer Jobs page (/view/transfer/jobs/).
 */
export class TransferJobsPage {
  readonly page: Page;
  readonly pageUrl = './view/transfer/jobs/';

  readonly heading: Locator;
  readonly refreshButton: Locator;
  readonly emptyState: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Transfer Jobs' });
    this.refreshButton = page.getByRole('button', { name: 'Refresh' });
    this.emptyState = page.getByText('No transfer jobs found.');
  }

  async goto() {
    await this.page.goto(this.pageUrl);
    await expect(this.heading).toBeVisible();
  }

  /** The table row displaying the job whose id starts with the given 8-char prefix. */
  rowByIdPrefix(idPrefix: string): Locator {
    return this.page.getByRole('row').filter({ hasText: `${idPrefix}...` });
  }

  /**
   * Clicks the Cancel action on the row for a job id. The action is the only
   * button in the row (the icon button carries no accessible text label), so it
   * is located positionally within the row.
   */
  async cancelJob(idPrefix: string) {
    await this.rowByIdPrefix(idPrefix).getByRole('button').first().click();
  }
}
