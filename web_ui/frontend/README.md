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
npm i
npm run dev
```
