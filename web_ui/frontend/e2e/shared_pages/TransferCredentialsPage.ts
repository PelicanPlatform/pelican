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
 * Page Object Model for the Transfer Credentials page
 * (/view/transfer/credentials/).
 */
export class TransferCredentialsPage {
  readonly page: Page;
  readonly pageUrl = './view/transfer/credentials/';

  readonly heading: Locator;
  readonly refreshButton: Locator;
  readonly addButton: Locator;
  readonly emptyState: Locator;

  // Add-credential dialog
  readonly dialog: Locator;
  readonly nameField: Locator;
  readonly tokenField: Locator;
  readonly issuerField: Locator;
  readonly submitButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Transfer Credentials' });
    this.refreshButton = page.getByRole('button', { name: 'Refresh' });
    this.addButton = page.getByRole('button', { name: 'Add Credential' });
    this.emptyState = page.getByText('No credentials found.');

    this.dialog = page.getByRole('dialog');
    this.nameField = this.dialog.getByLabel('Name');
    this.tokenField = this.dialog.getByLabel('Access Token');
    this.issuerField = this.dialog.getByLabel('Token Issuer (optional)');
    // "Add" exact so it does not also match the page's "Add Credential" button.
    this.submitButton = this.dialog.getByRole('button', {
      name: 'Add',
      exact: true,
    });
  }

  async goto() {
    await this.page.goto(this.pageUrl);
    await expect(this.heading).toBeVisible();
  }

  /**
   * Opens the Add Credential dialog, fills it, and submits. Returns once the
   * dialog has closed (the submit succeeded).
   */
  async addCredential(name: string, token: string, issuer?: string) {
    await this.addButton.click();
    await expect(this.dialog).toBeVisible();
    await this.nameField.fill(name);
    await this.tokenField.fill(token);
    if (issuer) {
      await this.issuerField.fill(issuer);
    }
    await this.submitButton.click();
    await expect(this.dialog).not.toBeVisible();
  }

  /** The table row for the credential with the given name. */
  rowByName(name: string): Locator {
    return this.page.getByRole('row').filter({ hasText: name });
  }

  /**
   * Clicks the Delete action on the row for a credential name. The delete icon
   * button carries no accessible text label, so it is located positionally as
   * the only button in the row.
   */
  async deleteCredential(name: string) {
    await this.rowByName(name).getByRole('button').first().click();
  }
}
