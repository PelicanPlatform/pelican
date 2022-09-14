StashCP Client
==============

[![Version][github-release-shield]][github-release]
![Go Mod][go-mod-version]
![Builds][github-build]

StashCP downloads files from the [Open Science Data Federation](https://osdf.osg-htc.org/) through a series of caches.  StashCP is used by multiple organizations to effeciently transfer input and output data.

StashCP also includes an [HTCondor](https://htcondor.org/) file transfer [plugin](https://htcondor.readthedocs.io/en/latest/admin-manual/setting-up-special-environments.html#enabling-the-transfer-of-files-specified-by-a-url).  When configured, this plugin will allow the user to specify `transfer_input_files` with the `stash://` protocol which will be downloaded through the OSDF caches.  An example of a submit file:

    ...
    transfer_input_files = stash:///osgconnect/public/dweitzel/blast/queries/query1
    ...



Building
--------

Building is performed with the [goreleaser](https://goreleaser.com/) tool.  To build a snapshot (not release):

    $ goreleaser --rm-dist --snapshot

The binaries will be located in `./dist` directory.

Testing and Usage
-----------------

Run this simple command to download a test file

    $ ./stashcp /osgconnect/public/dweitzel/blast/queries/query1 ./


Configuration
-------------
`stashcp` is affected by the environment variables:

| Environment Variable      | Description                                                                                                                                                                                                                                                         |
| ----------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OSG_DISABLE_PROXY_FALLBACK`      | Do not disable using proxies. By default, `stashcp` will try to use an HTTP proxy when connecting to a cache. If this environment variable is set (no value necessary, only if it's set), then `stashcp` will not fallback to no proxy if the proxy download fails. |
| `STASHCP_MINIMUM_DOWNLOAD_SPEED`  | The lower limit a download will be cancelled, in bytes per second                                                                                                                                                                                                   |
| `STASH_NAMESPACE_URL`             | The URL to download the namespace and cache information.  Default: https://topology.opensciencegrid.org/stashcache/namespaces                                                                                                                                                                                                 |




<!-- MARKDOWN LINKS & IMAGES -->
[go-mod-version]: https://img.shields.io/github/go-mod/go-version/opensciencegrid/stashcp
[github-build]: https://img.shields.io/github/workflow/status/opensciencegrid/stashcp/Test
[github-release-shield]: https://img.shields.io/github/v/release/opensciencegrid/stashcp
[github-release]: https://github.com/opensciencegrid/stashcp/releases
