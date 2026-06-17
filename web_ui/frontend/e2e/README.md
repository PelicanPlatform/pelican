# Playwright End-to-End Tests

Tests are organized by Pelican service: `origin`, `cache`, `director`, and `registry`. Each service has its own folder, Page Objects, and auth setup.

## Setting up

Install Playwright browsers (first-time only):

```bash
npx playwright install
```

### Example `.env`

Create a `web_ui/frontend/e2e/.env` file. This file is automatically loaded by `playwright.config.ts` and is gitignored.

```env
# ── Target URLs ───────────────────────────────────────────────────────────────
# Defaults to https://localhost:8444 for all services when not set.

TARGET_ORIGIN_URL=https://localhost:8444
TARGET_CACHE_URL=https://localhost:8444
TARGET_DIRECTOR_URL=https://localhost:8444
TARGET_REGISTRY_URL=https://localhost:8444

# ── Bearer Tokens ─────────────────────────────────────────────────────────────
# Injected as `Authorization: Bearer <token>` on every request for that service.

TARGET_ORIGIN_TOKEN=
TARGET_CACHE_TOKEN=
TARGET_DIRECTOR_TOKEN=
TARGET_REGISTRY_TOKEN=
```

## Creating new tests

**Finding input locators:**

```bash
npx playwright codegen https://localhost:8444
```

**Test Tags:**

- `@mutating`: Creates, updates, or deletes data — skipped when `E2E_EXTERNAL=1`
- `@smoke`: Fast, critical-path tests — safe to run anywhere
- `@slow`: Long-running tests — skip in fast feedback loops
- `@federation`: Tests involving multiple services (e.g. Origin + Cache), good for reverse grep when you are only testing on service

**Projects:**

- `origin`: Tests running against the Origin service
- `cache`: Tests running against the Cache service
- `director`: Tests running against the Director service
- `registry`: Tests running against the Registry service

## Running tests

**Run all services:**

```bash
cd web_ui/frontend
npm run e2e
```

**Run a single service:**

```bash
npx playwright test --project=origin
npx playwright test --project=cache
npx playwright test --project=director
npx playwright test --project=registry
```

**Run only read-only tests (no mutations):**

```bash
npx playwright test --grep-invert @mutating
```

**Run only a specific tag across all services:**

```bash
npx playwright test --grep @smoke
```

**View the HTML report after a run:**

```bash
npx playwright show-report
```

## Folder structure

```
e2e/
  .env                        # Local env vars (gitignored)
  README.md
  helpers/                    # Shared test utilities
  origin/
    pages/                    # Page Object Models for Origin pages
    *.spec.ts                 # Origin tests
  cache/
    pages/
    *.spec.ts
  director/
    pages/
    *.spec.ts
  registry/
    pages/
    *.spec.ts
  shared_pages/
    *.ts
  shared_tests/
    *.ts
```

## Auth

Authentication is handled via a Bearer token injected as an `Authorization` header on every request. Set the token for each service using the `TARGET_<SERVICE>_TOKEN` env var.

No login UI interaction or session state is required — the token is applied globally at the project level.

## Test tags

Tests use title-based tags to control which tests run in which environments.

| Tag | Meaning | |---|---| | `@mutating` | Creates, updates, or deletes data — skipped when `E2E_EXTERNAL=1` | | `@smoke` | Fast, critical-path tests — safe to run anywhere | | `@slow` | Long-running tests — skip in fast feedback loops |

Example:

```ts
test('create downtime entry @mutating @smoke', async ({ page }) => { ... });
test('view downtime list @smoke', async ({ page }) => { ... });
```

## CI

Set service URLs and tokens as CI secrets, then run:

```bash
E2E_EXTERNAL=1 \
TARGET_ORIGIN_URL=https://origin.example.org \
TARGET_ORIGIN_TOKEN=$ORIGIN_TOKEN \
npm run e2e
```

`@mutating` tests are skipped automatically when `E2E_EXTERNAL=1`.

## Generating tokens for local testing

Your issuer location will depend on the combination of origin or director running.

It could be:

- https://localhost:8444
- https://localhost:8444/api/v1.0/origin

```bash
PELICAN_BINARY=./pelican-server
PELICAN_CONFIG=/etc/pelican/local/pelican.yaml

TOKEN=$("$PELICAN_BINARY" origin token create \
  --config "$PELICAN_CONFIG/pelican.yaml" \
  --private-key "$PELICAN_CONFIG/issuer.jwk" \
  --profile wlcg \
  --scope "web_ui.access monitoring.query monitoring.scrape" \
  --issuer https://localhost:8444 \
  --subject admin \
  --audience https://localhost:8444 \
  --claim "oidc_iss=https://localhost:8444" \
  --claim "oidc_sub=admin" \
  --claim "user_id=a3bb1eff")
```

Then you can use the generated token to make authenticated requests:

```bash
curl 'https://localhost:8444/api/v1.0/auth/whoami' \
  -H 'accept: */*' \
  -H "Authorization: Bearer $TOKEN" \
  --insecure
```
