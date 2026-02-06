# Pelican Frontend

This ui is generated with Next.js.

## Development

### Setup

To develop the Pelican frontend you must run the backend in a separately, as well as set up a proxy to serve your backend and frontend requests from the same host.

```shell
docker compose run pelican-builder
docker compose up pelican-server pelican-api-proxy
```

If you would like to proxy the prometheus requests to another service you can do so by filling out .env.template and placing it as .env.local.

### Running the Frontend

To run the frontend install the dependencies and run the development server.

```shell
npm i
npm run dev
```
