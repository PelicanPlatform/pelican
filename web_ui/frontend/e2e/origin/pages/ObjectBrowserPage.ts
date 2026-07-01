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

import { Download, Locator, Page, expect } from '@playwright/test';

/**
 * Page Object Model for the Origin Object Browser (/view/origin/client/).
 *
 * The browser UI is provided by `@pelicanplatform/components` `OriginClient`, so
 * these locators are derived from that component's DOM:
 *   - a namespace `<Select>` labelled "Select Namespace"
 *   - a hidden `<input type="file">` used for uploads (present only once the
 *     client is authorized against the Origin's issuer)
 *   - one download `IconButton` per file, `aria-label="Download <objectPath>"`
 *   - an empty-collection message and a "Login" affordance when unauthorized
 *
 * IMPORTANT: `OriginClient` attempts to log in automatically on mount (silent,
 * then a full-page redirect). Upload/download therefore require a genuinely
 * authenticated issuer session; without one the page redirects to /view/login
 * and the upload input never renders. Use {@link isAuthorized} to gate tests.
 */
export class ObjectBrowserPage {
  readonly page: Page;
  readonly pageUrl = './view/origin/client/';

  readonly heading: Locator;
  readonly namespaceSelect: Locator;
  /** Hidden file input; rendered only when the client is authorized. */
  readonly fileInput: Locator;
  /** Shown by the client when the user is not authenticated. */
  readonly loginButton: Locator;
  /** Empty-collection placeholder text. */
  readonly emptyCollection: Locator;

  /** The "Collection" column header, present only in the CollectionView. */
  readonly collectionHeader: Locator;
  /** A file-listing (ObjectView) column header, present once inside a folder. */
  readonly nameHeader: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Object Browser' });
    // MUI's Select renders a combobox; its label isn't wired for getByLabel.
    this.namespaceSelect = page.getByRole('combobox');
    this.fileInput = page.locator('input[type="file"]');
    this.loginButton = page.getByRole('button', { name: 'Login' });
    this.emptyCollection = page.getByText('You are in an empty collection.');
    this.collectionHeader = page.getByRole('columnheader', {
      name: 'Collection',
    });
    this.nameHeader = page.getByRole('columnheader', { name: 'Name' });
  }

  async goto() {
    await this.page.goto(this.pageUrl);
  }

  /**
   * True once the client has authorized against the Origin's issuer, i.e. the
   * upload input has been rendered. Returns false if the client instead settles
   * into the unauthenticated state (Login button) or redirects to /view/login.
   *
   * Use to skip upload/download tests in environments without a logged-in
   * session, rather than letting them fail on the redirect.
   */
  async isAuthorized(timeoutMs = 20000): Promise<boolean> {
    try {
      await expect(this.fileInput.or(this.loginButton)).toBeAttached({
        timeout: timeoutMs,
      });
    } catch {
      return false;
    }
    if (this.page.url().includes('/login')) {
      return false;
    }
    return (await this.fileInput.count()) > 0;
  }

  /** Selects a namespace by its federation prefix (e.g. "/test-namespace"). */
  async selectNamespace(prefix: string) {
    await this.namespaceSelect.click();
    await this.page.getByRole('option', { name: prefix, exact: true }).click();
  }

  /**
   * When the active token grants collections, the client auto-opens the
   * CollectionView instead of the file listing. Uploads/downloads happen inside
   * a collection (a writable path), so enter the first one to land in the
   * ObjectView. No-op when already in a file listing (no collections).
   */
  async enterFileView() {
    if (await this.collectionHeader.isVisible().catch(() => false)) {
      const collectionTable = this.page
        .locator('table')
        .filter({ has: this.collectionHeader });
      // Row 0 is the header; the first data row is the first collection.
      await collectionTable.getByRole('row').nth(1).click();
    }
    // We're in the file listing once its header (or the empty placeholder) shows.
    await expect(this.nameHeader.or(this.emptyCollection)).toBeVisible({
      timeout: 15000,
    });
  }

  /**
   * Uploads a local file via the hidden file input and waits for the client to
   * report completion. `setInputFiles` drives the input directly, so there is no
   * need to click the (icon-only, unlabelled) upload button.
   */
  async uploadFile(localPath: string) {
    await this.fileInput.setInputFiles(localPath);
    // The upload overlay shows per-file progress; wait for it to clear.
    await expect(this.page.getByText('Uploading Files')).toBeHidden({
      timeout: 30000,
    });
  }

  /**
   * The listing row for a file, matched by its name.
   *
   * `ObjectView` renders the name with the namespace + current collection path
   * stripped, so inside a collection it shows with a leading slash
   * (e.g. "/e2e-file.txt"), and the name also appears in the row's Download
   * button aria-label. Matching the row by substring text is therefore more
   * robust than an exact cell-name match.
   */
  fileRow(fileName: string): Locator {
    return this.page.getByRole('row').filter({ hasText: fileName });
  }

  /**
   * Clicks the download control for a file (matched by basename) and returns the
   * resulting Playwright Download. The download button's accessible name is
   * "Download <objectPath>", so we match on the trailing basename.
   */
  async downloadFile(fileName: string): Promise<Download> {
    const button = this.page.getByRole('button', {
      name: new RegExp(`Download .*${escapeRegExp(fileName)}$`),
    });
    const [download] = await Promise.all([
      this.page.waitForEvent('download'),
      button.click(),
    ]);
    return download;
  }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
