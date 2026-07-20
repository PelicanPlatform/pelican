import { defineConfig, devices } from '@playwright/test';

/**
 * Read environment variables from file.
 * https://github.com/motdotla/dotenv
 */
import dotenv from 'dotenv';
import path from 'path';
dotenv.config({ path: path.resolve(__dirname + '/e2e', '.env') });

type Service = 'origin' | 'cache' | 'director' | 'registry';
interface TestTarget {
  baseURL: string;
  token?: string;
}

const defaultBaseUrl: string = 'https://localhost:8444';
const defaultToken: string | undefined = undefined;

// Set E2E_EXTERNAL=1 when targeting live/production instances.
// Tests tagged @mutating (create, update, delete) will be skipped automatically.
const isExternal = !!process.env.E2E_EXTERNAL;

const targets: Record<Service, TestTarget> = {
  origin: {
    baseURL: process.env.TARGET_ORIGIN_URL || defaultBaseUrl,
    token: process.env.TARGET_ORIGIN_TOKEN || defaultToken,
  },
  cache: {
    baseURL: process.env.TARGET_CACHE_URL || defaultBaseUrl,
    token: process.env.TARGET_CACHE_TOKEN || defaultToken,
  },
  director: {
    baseURL: process.env.TARGET_DIRECTOR_URL || defaultBaseUrl,
    token: process.env.TARGET_DIRECTOR_TOKEN || defaultToken,
  },
  registry: {
    baseURL: process.env.TARGET_REGISTRY_URL || defaultBaseUrl,
    token: process.env.TARGET_REGISTRY_TOKEN || defaultToken,
  },
};

/**
 * Build a Playwright storageState that carries the service token as the web-UI
 * `login` cookie — the JWT session cookie Pelican reads in GetUserGroups
 * (web_ui/authentication.go). Using the cookie instead of an `Authorization`
 * header means in-browser flows are authenticated too: notably the Origin
 * Object Browser's issuer `/authorize` call, which authenticates via this cookie
 * (not a header). The token only needs to be signed by the server's issuer key
 * and carry a `user_id` claim (issuer/audience are not checked for the cookie).
 */
const loginCookieState = (baseURL: string, token: string) => ({
  cookies: [
    {
      name: 'login',
      value: token,
      domain: new URL(baseURL).hostname,
      path: '/',
      expires: -1, // session cookie
      httpOnly: true,
      secure: true,
      sameSite: 'Lax' as const,
    },
  ],
  origins: [],
});

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
  testDir: './e2e',
  /* Run tests in files in parallel */
  fullyParallel: true,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,
  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : undefined,
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: 'html',
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Capture screenshots only when tests fail so CI artifacts stay small. */
    screenshot: 'only-on-failure',
    /* Keep video only for failing tests to help debug flaky UI behavior. */
    video: 'retain-on-failure',
    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on',
    /* In CI the server uses a self-signed certificate, so we skip TLS verification. */
    ignoreHTTPSErrors: !!process.env.CI,
  },

  /* Configure projects for major browsers */
  projects: [
    ...Object.entries(targets).map(([service, { baseURL, token }]) => ({
      name: service,
      testMatch: `**/e2e/${service}/**/*.spec.ts`,
      use: {
        ...devices['Desktop Chrome'],
        baseURL,
        // Auth precedence:
        //  1. E2E_STORAGE_STATE — an explicitly captured session file
        //     (`npm run playwright:save-auth`), for real interactive logins.
        //  2. the service token, injected as the `login` cookie so both API
        //     requests and in-browser login flows are authenticated.
        ...(process.env.E2E_STORAGE_STATE
          ? { storageState: process.env.E2E_STORAGE_STATE }
          : token
            ? { storageState: loginCookieState(baseURL, token) }
            : {}),
      },
    })),
  ],
});
