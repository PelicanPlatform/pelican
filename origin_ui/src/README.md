# Origin UI

This ui is generated with Next.js. 

## Development

```shell
docker build -t origin-ui .
```

```shell
docker run -it -p 3000:3000 -v $(pwd):/webapp origin-ui npm run dev
```

You can also run if you have node installed locally via `npm install && npm run dev`.