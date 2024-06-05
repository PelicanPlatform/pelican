# Origin UI

This ui is generated with Next.js.

## Development

### Local

In production builds the website is compiled and included with the code. This step
takes a couple minutes and is not well suited for development. Since the website
sits on top of the api the best way to develop just the website is to run the api
and the website separately and then use nginx to make them come from the same host
as they would in production.

#### To run the api:

```shell
# From repo root
make web-build
goreleaser --clean --snapshot
docker run --rm -it -p 8444:8444 -w /app -v $PWD/dist/pelican_linux_arm64/:/app -v $PWD/local/:/etc/pelican/ hub.opensciencegrid.org/pelican_platform/pelican-dev:latest-itb /bin/bash
```

```shell
# Inside the container
cp pelican osdf
./osdf origin serve -f https://osg-htc.org -v /tmp/stash/:/test
```

##### To run all of the websites

```shell
./pelican serve --module director,registry,origin,cache
```

#### To run the website and the reverse proxy:

First make sure that the ports are correct in `dev/nginx.conf` so that they point to
the website and the api as expected. Then run the following command.

```shell
sh dev/run.sh
npm run dev
```

### Docker

```shell
docker build -t origin-ui .
```

```shell
docker run -it -p 3000:3000 -v $(pwd):/webapp origin-ui npm run dev
```

You can also run if you have node installed locally via `npm install && npm run dev`.
