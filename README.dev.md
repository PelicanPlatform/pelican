```shell
cd /Users/clock/GolandProjects/pelican/origin_ui/src
npm run build
cd ../../

```

```shell
cd /Users/clock/GolandProjects/pelican
goreleaser --clean --snapshot
cd ./dist/pelican_darwin_arm64
cp pelican osdf
./osdf origin serve -f https://osg-htc.org -v /tmp/stash/:/testnpm run de
```
