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
  readonly scrollToBottomButton: Locator;
  readonly autoScrollCheckbox: Locator;
  // The scrolling log pane. Every row assertion is scoped to it so a match
  // means "mounted in the pane", not "this string appears somewhere on the
  // page".
  readonly pane: Locator;
  // "Showing X of Y lines held in this browser." — the count summary above
  // the log pane. Also carries the dropped-line total and the
  // "Loading older…" / "No more history." suffixes.
  readonly summary: Locator;
  // The "Filtering…" indicator shown while the pane's rows are still the
  // pre-change ones after a filter edit.
  readonly filteringIndicator: Locator;
  // The dismissible warning the viewer raises when a tail fetch fails.
  readonly fetchErrorAlert: Locator;
  // The "In-memory log capture is not yet available" notice shown when the
  // server reports the buffer disabled.
  readonly unavailableNotice: Locator;

  constructor(page: Page, pageUrl: string) {
    this.page = page;
    this.pageUrl = pageUrl;

    this.heading = page.getByRole('heading', { name: 'Server Logs' });
    this.textFilter = page.getByLabel('Text filter');
    this.downloadButton = page.getByRole('button', { name: /Download/ });
    this.scrollToBottomButton = page.getByRole('button', {
      name: 'Scroll to bottom',
    });
    this.autoScrollCheckbox = page.getByRole('checkbox', {
      name: 'Auto-scroll',
    });
    this.pane = page.getByTestId('log-pane');
    this.summary = page.getByTestId('log-summary');
    this.filteringIndicator = page.getByTestId('log-filtering');
    this.fetchErrorAlert = page
      .locator('.MuiAlert-root')
      .filter({ hasText: /log tail fetch failed/ });
    this.unavailableNotice = page.getByText(
      /In-memory log capture is not yet available/
    );
  }

  async goto() {
    await this.page.goto(this.pageUrl);
    await expect(this.heading).toBeVisible();
  }

  /**
   * Every log row currently mounted in the pane. With virtualization this is
   * the window around the viewport, not the whole buffer — compare against
   * `summary` for the full count.
   */
  rows(): Locator {
    return this.pane.getByTestId('log-row');
  }

  /**
   * Placeholders marking lines the server dropped before this view could
   * read them. Distinct from `rows()`: a gap is a statement about the
   * record rather than part of it, and it survives the level and text
   * filters that log rows are subject to.
   */
  gaps(): Locator {
    return this.pane.getByTestId('log-gap');
  }

  /**
   * Returns a locator for a mounted log row containing the given text.
   * Matches a substring of the formatted line. A row that is filtered out
   * and a row that is merely scrolled out of the virtualization window both
   * resolve to zero elements, so pair negative assertions with a count.
   */
  logLine(text: string): Locator {
    return this.rows().filter({ hasText: text });
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

  /**
   * Plain-clicks a level chip. From no filter that narrows to the level
   * clicked; with a filter active it adds the level, or removes it if it was
   * already selected; and on the last remaining level it clears the filter.
   */
  async clickLevel(level: string) {
    await this.levelChip(level).click();
  }

  /**
   * Modifier-clicks a level chip, which adds it to or removes it from the
   * current selection rather than isolating it.
   */
  async toggleLevel(level: string) {
    await this.levelChip(level).click({ modifiers: ['ControlOrMeta'] });
  }

  /**
   * The "Available: …" subtext under the download control, reporting what the
   * server's whole buffer spans — i.e. what a download would contain, which is
   * not the same set as the lines this page holds.
   */
  downloadSpan(): Locator {
    return this.page.getByTestId('log-download-span');
  }

  /**
   * The right-justified span at the end of the summary line: "Logs in time
   * range: YYYY-MM-DD HH:MM - YYYY-MM-DD HH:MM", in the viewer's local zone.
   * Absent entirely when nothing held carries a timestamp.
   */
  dateRange(): Locator {
    return this.page.getByTestId('log-range');
  }

  /** Dismisses the tail-fetch warning via its Close button. */
  async dismissFetchError() {
    await this.fetchErrorAlert.getByRole('button', { name: 'Close' }).click();
  }

  /** Current scroll offset of the pane, in pixels from the top. */
  paneScrollTop(): Promise<number> {
    return this.pane.evaluate((el) => el.scrollTop);
  }

  /**
   * Pixels of un-scrolled content below the viewport. The viewer treats
   * anything at or under 20 px as "pinned to the bottom".
   */
  paneBottomGap(): Promise<number> {
    return this.pane.evaluate(
      (el) => el.scrollHeight - el.scrollTop - el.clientHeight
    );
  }

  /** Scrolls the pane to the very top, which is what triggers a history load. */
  async scrollPaneToTop() {
    await this.pane.evaluate((el) => {
      el.scrollTop = 0;
    });
  }

  /** Scrolls the pane up by `px`, clamped at the top. */
  async scrollPaneUpBy(px: number) {
    await this.pane.evaluate((el, delta) => {
      el.scrollTop = Math.max(0, el.scrollTop - delta);
    }, px);
  }
}
