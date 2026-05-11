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
 * Page Object Model for the  Downtime management page (/<cache|origin>/downtime).
 *
 * Encapsulates all selectors and interactions so tests stay readable and
 * resilient to minor UI changes.
 */
export class DowntimePage {
  readonly page: Page;
  readonly pageUrl: string;

  // Page-level elements
  readonly heading: Locator;
  readonly createButton: Locator;

  // Create modal elements (only present while modal is open)
  readonly modal: Locator;
  readonly modalHeading: Locator;
  readonly descriptionField: Locator;
  readonly startTimePicker: Locator;
  readonly endTimePicker: Locator;
  readonly unknownEndTimeCheckbox: Locator;
  readonly severitySelect: Locator;
  readonly submitButton: Locator;
  readonly closeModalButton: Locator;

  // Edit modal elements (only present while edit modal is open)
  readonly editModal: Locator;
  readonly editModalHeading: Locator;
  readonly editDescriptionField: Locator;
  readonly editSubmitButton: Locator;
  readonly closeEditModalButton: Locator;

  // Filter date pickers (outside the modal, in the card list)
  readonly filterStartTimePicker: Locator;
  readonly filterEndTimePicker: Locator;

  // Downtime list
  readonly downtimeList: Locator;

  constructor(page: Page, pageUrl: string) {
    this.page = page;
    this.pageUrl = pageUrl;

    this.heading = page.getByRole('heading', { name: 'Service Downtime' });
    this.createButton = page.getByRole('button', { name: 'Create Downtime' });

    // The modal is a MUI Paper inside a MUI Modal — locate it by its heading
    this.modal = page.getByRole('presentation').filter({
      has: page.getByRole('heading', { name: 'Create Downtime' }),
    });
    this.modalHeading = this.modal.getByRole('heading', {
      name: 'Create Downtime',
    });
    this.startTimePicker = this.modal.getByRole('group', {
      name: /^Start Time/,
    });
    this.endTimePicker = this.modal.getByRole('group', { name: /^End Time/ });
    this.unknownEndTimeCheckbox = this.modal.getByRole('checkbox', {
      name: 'Unknown Endtime',
      exact: true,
    });
    this.descriptionField = this.modal.getByLabel('Description');
    this.severitySelect = this.modal.getByLabel('Severity');
    this.submitButton = this.modal.getByRole('button', { name: 'Submit' });
    this.closeModalButton = this.modal.getByRole('button').first();

    this.editModal = page.getByRole('presentation').filter({
      has: page.getByRole('heading', { name: 'Create Downtime' }),
    });
    this.editModalHeading = this.editModal.getByRole('heading', {
      name: 'Create Downtime',
    });
    this.editDescriptionField = this.editModal.getByLabel('Description');
    this.editSubmitButton = this.editModal.getByRole('button', {
      name: 'Submit',
    });
    this.closeEditModalButton = this.editModal.getByRole('button').first();

    this.downtimeList = page.locator(
      '.MuiCardContent-root, [data-testid="downtime-list"]'
    );

    // The filter pickers live outside any modal
    this.filterStartTimePicker = page
      .getByRole('group', { name: /^Start Time/ })
      .filter({ hasNot: page.locator('[role="presentation"]') })
      .first();
    this.filterEndTimePicker = page
      .getByRole('group', { name: /^End Time/ })
      .filter({ hasNot: page.locator('[role="presentation"]') })
      .first();
  }

  async goto() {
    await this.page.goto(this.pageUrl);
    await expect(this.heading).toBeVisible();
  }

  /** Opens the Create Downtime modal. */
  async openCreateModal() {
    await this.createButton.click();
    await expect(this.modalHeading).toBeVisible();
  }

  /**
   * Fills in a date field with the provided date
   *
   * @param picker
   * @param date
   */
  async fillDateTimePicker(picker: Locator, date: Date) {
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const year = String(date.getFullYear());
    const hours = String(date.getHours() % 12 || 12).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const meridiem = date.getHours() < 12 ? 'AM' : 'PM';

    await picker.getByLabel('Month').fill(month);
    await picker.getByLabel('Day', { exact: true }).fill(day);
    await picker.getByLabel('Year').fill(year);
    await picker.getByLabel('Hours').fill(hours);
    await picker.getByLabel('Minutes').fill(minutes);
    await picker.getByLabel('Meridiem').fill(meridiem);
  }

  /**
   * Fills in and submits a new downtime entry.
   *
   * @param description  Unique text to identify this entry in the list afterwards.
   * @param severity     One of the four DowntimeSeverity values. Defaults to
   *                     'Severe (most services down)'.
   */
  async createDowntime(
    description: string,
    severity = 'Severe (most services down)'
  ) {
    await this.descriptionField.fill(description);
    await this.severitySelect.click();
    await this.page
      .getByRole('option', { name: severity, exact: true })
      .click();
    await this.submitButton.click();
  }

  /**
   * Returns a locator for the downtime card in the list that contains the
   * given description text.
   */
  downtimeCardByDescription(description: string): Locator {
    return this.page.locator(
      `[data-testid="downtime-card"][data-description="${description}"]`
    );
  }

  /**
   * Clicks the Edit button on the card matching the given description,
   * then waits for the Edit Downtime modal to appear.
   */
  async openEditModalForCard(description: string) {
    const card = this.downtimeCardByDescription(description);
    await card.getByRole('button', { name: 'Edit downtime' }).click();
    await expect(this.editModalHeading).toBeVisible();
  }
}
