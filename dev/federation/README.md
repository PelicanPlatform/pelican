# Federation Development Docker Setup

The federation setup is intended to pull out all the pieces of the federation into their own pieces with their
own configs to enable easier development and testing on a single piece of the federation.

**Before you run you have to toss a `oidc-client-id` and `oidc-client-secret` into `./configs/shared/oidc` folder so you can run the registry**

```bash
docker compose up # Run from the `dev/federation` directory
```

## Relevant URLS

# Web UIs

- [Director Web UI (https://localhost:8400)](https://localhost:8400)
- [Registry Web UI (https://localhost:8300)](https://localhost:8300)
- [Origin Web UI (https://localhost:8200)](https://localhost:8200)
- [Cache Web UI (https://localhost:8100)](https://localhost:8100)

# XRootD

- [Origin XRootD (https://localhost:8201)](https://localhost:8201)
- [Cache XRootD (https://localhost:8101)](https://localhost:8101)

## Relevant Files

- `./configs` The config directories that are mounted to the services
- `./data` The pelican data directory mounted on the Origin by default

## Web UI Password

Hardcoded to `password` for all web UIs
