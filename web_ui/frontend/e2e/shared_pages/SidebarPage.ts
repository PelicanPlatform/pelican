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
 * How long to let a rail click settle before calling it a failure.
 *
 * Deliberately well above Playwright's 5s default. Against `next dev` the
 * first visit to a route compiles it on demand, which regularly takes longer
 * than that and has nothing to do with whether the navigation works. The
 * assertion is still tight -- it waits for a specific pathname, not for a
 * timeout to elapse -- so a genuinely broken link fails at the same speed.
 */
const NAVIGATION_TIMEOUT = 20_000;

/**
 * Page Object Model for the primary navigation rail.
 *
 * Everything here is found by accessible role and name rather than by CSS,
 * which matters more than usual for this component: the rail renders at three
 * widths and in two states, and the DOM differs in each. Roles do not.
 *
 * Two details make the role queries work where you might not expect them to:
 *
 *  - A collapsed rail hides its labels with `display: none`, so the visible
 *    text is gone. The rows stay findable by name anyway because every row is
 *    wrapped in a MUI Tooltip, which sets `aria-label` on its child by
 *    default (Tooltip.js: `nameOrDescProps['aria-label'] = title`). The
 *    accessible name is therefore the label in both states.
 *  - The burger menu carries the same `aria-label="Primary"` as the rail, but
 *    its container is `display: none` from `md` up, so it is out of the
 *    accessibility tree at the desktop widths these tests run at. If you ever
 *    run these below `md`, this locator will match two nodes.
 */
export class SidebarPage {
  readonly page: Page;
  /** The rail's navigation landmark. Every query below is scoped to it. */
  readonly nav: Locator;

  constructor(page: Page) {
    this.page = page;
    this.nav = page.getByRole('navigation', { name: 'Primary' });
  }

  async goto(url: string) {
    await this.page.goto(url);
    // The rail holds a single placeholder until /whoami, /servers and (for an
    // admin) /origin_ui/exports have all answered. Waiting for the landmark
    // is not enough -- it is present during the placeholder too -- so wait for
    // a real row to exist before asserting anything about which rows there are.
    await expect(this.nav).toBeVisible();
    await expect(this.nav.getByRole('link').first()).toBeAttached();
  }

  /** A destination in the rail, by its label. */
  link(name: string): Locator {
    return this.nav.getByRole('link', { name, exact: true });
  }

  /**
   * A section trigger (Collections, Add). These are buttons, not links: they
   * open a submenu rather than navigating, which is the distinction the rail
   * previously failed to make visible at all.
   */
  section(name: string): Locator {
    return this.nav.getByRole('button', { name, exact: true });
  }

  /**
   * Opens a section if it is not already open. A section containing the
   * current page opens itself, so this has to be idempotent rather than a
   * blind click -- clicking an already-open section would close it.
   */
  async openSection(name: string) {
    const trigger = this.section(name);
    await expect(trigger).toBeVisible();
    if ((await trigger.getAttribute('aria-expanded')) !== 'true') {
      await trigger.click();
    }
    await expect(trigger).toHaveAttribute('aria-expanded', 'true');
  }

  /**
   * Follows a rail link and asserts the caller actually arrived: the pathname
   * is the destination, the page is not a privileges wall, and the rail now
   * marks that row as the current page.
   *
   * That last assertion is the one that earns its keep. It proves the rail's
   * own `isActive` logic agrees with where the click landed, so a row that
   * navigates somewhere real but never lights up still fails.
   *
   * `path` is matched as a pathname suffix rather than against the whole URL,
   * for two reasons: it is indifferent to the app's `/view` basePath, and it
   * ignores query strings -- the metrics dashboards append their own
   * (`?time=…&range=1d`) the moment they mount, which an end-anchored URL
   * pattern would reject.
   *
   * @param path The destination's app path, e.g. '/origin/metrics/'.
   */
  async follow(name: string, path: string) {
    const row = this.link(name);
    await expect(row).toBeVisible();
    await row.click();

    await this.page.waitForURL((url) => url.pathname.endsWith(path), {
      timeout: NAVIGATION_TIMEOUT,
    });
    await expect(this.page.getByText(/Insufficient privileges/i)).toHaveCount(
      0
    );
    await expect(this.link(name)).toHaveAttribute('aria-current', 'page');
  }

  /**
   * Asserts a set of destinations is offered and another set is not.
   *
   * Both halves are checked together on purpose. An "is not offered" assertion
   * passes trivially against a rail that failed to render, so it is only
   * meaningful next to something that must be there.
   */
  async expectOffers({
    offered = [],
    withheld = [],
  }: {
    offered?: string[];
    withheld?: string[];
  }) {
    for (const name of offered) {
      await expect(
        this.link(name).or(this.section(name)),
        `rail should offer "${name}"`
      ).toBeVisible();
    }
    for (const name of withheld) {
      await expect(
        this.link(name).or(this.section(name)),
        `rail should not offer "${name}"`
      ).toHaveCount(0);
    }
  }
}
