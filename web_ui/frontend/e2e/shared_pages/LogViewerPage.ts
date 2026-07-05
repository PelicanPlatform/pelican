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
 * Page Object Model for the Server Logs settings page
 * (/settings/logs -> ./view/settings/logs/).
 *
 * Encapsulates the selectors and interactions for the in-memory log viewer so
 * tests stay readable and resilient to minor UI changes.
 */
export class LogViewerPage {
  readonly page: Page;
  readonly pageUrl: string;

  readonly heading: Locator;
  readonly textFilter: Locator;
  readonly downloadButton: Locator;
  readonly autoScrollCheckbox: Locator;
  // "Showing X of Y lines." — the count summary above the log pane.
  readonly summary: Locator;
  // The "In-memory log capture is not yet available" notice shown when the
  // server reports the buffer disabled.
  readonly unavailableNotice: Locator;

  constructor(page: Page, pageUrl: string) {
    this.page = page;
    this.pageUrl = pageUrl;

    this.heading = page.getByRole('heading', { name: 'Server Logs' });
    this.textFilter = page.getByLabel('Text filter');
    this.downloadButton = page.getByRole('button', { name: /Download/ });
    this.autoScrollCheckbox = page.getByRole('checkbox', {
      name: 'Auto-scroll',
    });
    this.summary = page.getByText(/Showing .* of .* lines\./);
    this.unavailableNotice = page.getByText(
      /In-memory log capture is not yet available/
    );
  }

  async goto() {
    await this.page.goto(this.pageUrl);
    await expect(this.heading).toBeVisible();
  }

  /**
   * Returns a locator for a rendered log row that contains the given text.
   * Matches a substring of the formatted line.
   */
  logLine(text: string): Locator {
    return this.page.getByText(text);
  }

  /**
   * Returns the level-filter chip whose label starts with the given level
   * name (e.g. 'info', 'error'). Chips render as `info (2)`, so this matches
   * on the leading level token and ignores the trailing count.
   */
  levelChip(level: string): Locator {
    return this.page
      .locator('.MuiChip-root')
      .filter({ hasText: new RegExp(`^${level} \\(`) });
  }

  /** Toggles a level chip in / out of the selected set. */
  async toggleLevel(level: string) {
    await this.levelChip(level).click();
  }
}
