# Pelican Frontend

This ui is generated with Next.js.

## Development

### Setup

To quickly develop the Pelican frontend you can run the Pelican backend and NextJS frontend separately, as well as set up a proxy to serve them both from the same host.

**Remember to replace the volume with the binary location in the `docker-compose.yml` file to your local pelican binary.**

```shell
docker compose run pelican-builder
docker compose up pelican-server pelican-api-proxy
```

If you would like to proxy the prometheus requests to another service you can do so by filling out `./dev/env.template` and placing it as `./dev/env.local`.

`./dev/env.local`

```shell
API_URL=https://origin.test.org
API_PASSWORD=password
```

### Running the Frontend

To run the frontend install the dependencies and run the development server.

```shell
pnpm install
pnpm run dev
```

### Package manager

This project uses [pnpm](https://pnpm.io/). The required version is pinned by the `packageManager` field in `package.json`, and pnpm installs the matching version automatically, so any recent pnpm 11 is enough to get started:

```shell
npm install -g pnpm
```

Use `pnpm install --frozen-lockfile` (the equivalent of `npm ci`) when you want an install that fails rather than silently updating `pnpm-lock.yaml`. That is what CI runs.

Two things to know about the settings in `pnpm-workspace.yaml`:

- **New releases are held for a week** (`minimumReleaseAge`) so that a compromised package has time to be caught and unpublished before we would install it. A brand-new upstream release will not resolve until it is 7 days old. Our own `@pelicanplatform/*` packages are exempt.
- **Dependency build scripts do not run.** Every package that wants to run one is listed under `allowBuilds` as `false`, because we rely on the prebuilt native binaries those packages ship. If you add a dependency with an install script, `pnpm install` will fail with `ERR_PNPM_IGNORED_BUILDS` until you add it there — that failure is intentional, so a new install script gets reviewed.
