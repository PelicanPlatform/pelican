# Website Development Docker Setup

This dev flow defined in this directory runs the pelican apis locally and allows proxying to
other pelican apis externally.

It additionally moves interaction behind a reverse proxy to allow requests to come from the same
domain:port, removing CORS issues.

```
                          - external-pelican-api:443 (External pelican api (Optional))
                          |
localhost:8444 (Nginx) ---- docker-network:8444 (Local pelican api)
                          |
                          - localhost:3000 (Local dev web server via `npm run dev`)
```

## Relevant Files

- `pelican.yaml` The pelican config file for pelican in a box
- `./data` The pelican data directory mounted on the Origin by default
- `.env.local` The environment variables used to proxy requests to the external pelican api
- `./config` The config directory that is mounted to `/etc/pelican`

## Running the Development Environment

### Nginx and Local Pelican API

```shell
docker-compose up
```

### Local Web Development Server

```shell
cd web_ui/frontend
npm install
npm run dev
```
