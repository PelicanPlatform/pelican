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
import { DowntimePage } from '../shared_pages/DowntimePage';
import { mockDowntimeApi } from '../mocks/api/v1.0/downtime/crud';
import { mockDowntimeList } from '../mocks/api/v1.0/downtime/get';

/**
 * Registers the shared downtime tests for a given service URL.
 * Call this inside a `test.describe` block in each service's spec file.
 *
 * @param serviceUrl  The relative URL for the service's downtime page
 *                    (e.g. './view/origin/downtime/').
 */
export function registerDowntimeTests(serviceUrl: string) {
  let downtimePage: DowntimePage;

  test.beforeEach(async ({ page }) => {
    downtimePage = new DowntimePage(page, serviceUrl);
    // Set up a fresh, empty in-memory mock API before each navigation so no
    // test ever reaches the real server.
    await mockDowntimeApi(page);
    await downtimePage.goto();
  });

  test('shows existing downtime entries returned by the API @smoke @mocked', async ({
    page,
  }) => {
    // Override the empty mock with the fixture list, then re-navigate so the
    // initial fetch picks up the seeded data.
    await mockDowntimeApi(page, mockDowntimeList);
    await downtimePage.goto();

    // Set the filter range to encompass all mock events:
    // earliest start is 8 days ago (last-week entry), latest end is tomorrow
    const filterStart = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    const filterEnd = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
    await downtimePage.fillDateTimePicker(
      downtimePage.filterStartTimePicker,
      filterStart
    );
    await downtimePage.fillDateTimePicker(
      downtimePage.filterEndTimePicker,
      filterEnd
    );

    for (const entry of mockDowntimeList) {
      await expect(
        downtimePage.downtimeCardByDescription(entry.description)
      ).toBeVisible();
    }
  });

  test('shows the Service Downtime heading @smoke', async () => {
    await expect(downtimePage.heading).toBeVisible();
  });

  test('shows the Create Downtime button for admins @smoke', async () => {
    await expect(downtimePage.createButton).toBeVisible();
  });

  test('opens the Create Downtime modal @smoke', async () => {
    await downtimePage.openCreateModal();
    await expect(downtimePage.modalHeading).toBeVisible();
  });

  test('creates a new downtime entry and shows it in the list @smoke @mocked', async () => {
    // Use a timestamped description so parallel runs don't collide
    const description = `E2E test downtime ${Date.now()}`;
    const severity = 'Severe (most services down)';

    await downtimePage.openCreateModal();
    await downtimePage.createDowntime(description, severity);

    // Modal should close automatically on success
    await expect(downtimePage.modalHeading).not.toBeVisible();

    // The new entry should appear in the downtime list
    const card = downtimePage.downtimeCardByDescription(description);
    await expect(card).toBeVisible();
  });

  test('closes the modal without saving when the close button is clicked @mocked', async () => {
    const description = `E2E cancelled downtime ${Date.now()}`;

    await downtimePage.openCreateModal();
    await downtimePage.descriptionField.fill(description);
    await downtimePage.closeModalButton.click();

    // Modal should be gone
    await expect(downtimePage.modalHeading).not.toBeVisible();

    // Entry should NOT appear in the list
    const card = downtimePage.downtimeCardByDescription(description);
    await expect(card).not.toBeVisible();
  });

  test('edits the description of an existing downtime entry @mocked', async () => {
    const original = `E2E edit-me downtime ${Date.now()}`;
    const updated = `${original} (edited)`;

    // Create the entry first
    await downtimePage.openCreateModal();
    await downtimePage.createDowntime(original);
    await expect(downtimePage.modalHeading).not.toBeVisible();
    await expect(
      downtimePage.downtimeCardByDescription(original)
    ).toBeVisible();

    // Open the edit modal and change the description
    await downtimePage.openEditModalForCard(original);
    await downtimePage.editDescriptionField.fill(updated);
    await downtimePage.editSubmitButton.click();

    // Edit modal should close
    await expect(downtimePage.editModalHeading).not.toBeVisible();

    // Updated description should appear; original should be gone
    await expect(downtimePage.downtimeCardByDescription(updated)).toBeVisible();
    await expect(
      downtimePage.downtimeCardByDescription(original)
    ).not.toBeVisible();
  });
}
