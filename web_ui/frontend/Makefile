pelican-serve:
    cd ../..
	make pelican-build
	docker run --rm -it -p 8444:8444 -w /app -v $(PWD)/dist/pelican_linux_arm64_v8.0/:/app -v $(PWD)/local/:/etc/pelican/ hub.opensciencegrid.org/pelican_platform/pelican-dev:latest-itb ./pelican serve --module director,registry,origin,cache
