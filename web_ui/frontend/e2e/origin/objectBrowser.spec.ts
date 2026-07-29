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

import fs from 'fs';
import { test, expect } from '@playwright/test';
import { ObjectBrowserPage } from './pages/ObjectBrowserPage';

/**
 * End-to-end tests for the Origin Object Browser upload/download round trip.
 *
 * These exercise the real data path (the client PUTs/GETs against the Origin's
 * data endpoint using a token minted by the embedded issuer), so they require a
 * running Origin whose object browser can authenticate — either silent login is
 * working or a logged-in session/storage state is provided to the `origin`
 * project. When the client can't authorize, the page redirects to /view/login;
 * the tests detect that and skip rather than fail. See e2e/README.md.
 */
const SKIP_REASON =
  'Object browser is not authorized (no issuer session). Upload/download E2E ' +
  'requires an authenticated Origin — see e2e/README.md (Object Browser).';

test.describe('Origin Object Browser', () => {
  let browser: ObjectBrowserPage;

  test.beforeEach(async ({ page }) => {
    browser = new ObjectBrowserPage(page);
    await browser.goto();
  });

  test('renders the object browser with a namespace selector @smoke @federation', async () => {
    test.skip(!(await browser.isAuthorized()), SKIP_REASON);

    await expect(browser.heading).toBeVisible();
    await expect(browser.namespaceSelect).toBeVisible();
  });

  test('uploads a file and shows it in the listing @mutating @slow @federation', async () => {
    test.skip(!(await browser.isAuthorized()), SKIP_REASON);

    const fileName = `e2e-upload-${Date.now()}.txt`;
    const contents = `pelican object-browser upload test\n${fileName}\n`;
    const localPath = test.info().outputPath(fileName);
    fs.writeFileSync(localPath, contents);

    await browser.enterFileView();
    await browser.uploadFile(localPath);

    await expect(browser.fileRow(fileName)).toBeVisible({ timeout: 15000 });
  });

  test('downloads an uploaded file with matching contents @mutating @slow @federation', async () => {
    test.skip(!(await browser.isAuthorized()), SKIP_REASON);

    const fileName = `e2e-roundtrip-${Date.now()}.txt`;
    const contents = `pelican object-browser round-trip test\n${fileName}\n`;
    const localPath = test.info().outputPath(fileName);
    fs.writeFileSync(localPath, contents);

    // Upload, then confirm it is listed before downloading it back.
    await browser.enterFileView();
    await browser.uploadFile(localPath);
    await expect(browser.fileRow(fileName)).toBeVisible({ timeout: 15000 });

    const download = await browser.downloadFile(fileName);
    const downloadedPath = await download.path();
    expect(downloadedPath).not.toBeNull();

    const downloaded = fs.readFileSync(downloadedPath!, 'utf-8');
    expect(downloaded).toBe(contents);
  });
});
