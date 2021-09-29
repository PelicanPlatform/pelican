Stashcp Go Client
=================


Building
--------

Download the repo and cd into the directory.  Build with the command:

    $ make

It will make two executables.  A static x86 executable, and an executable native to the building machine.

Testing
-------

Run this simple command to download a test file

    $ ./stashcp /osgconnect/public/dweitzel/blast/queries/query1 ./


Configuration
-------------
`stashcp` is affected by the environment variables:

| Environment Variable      | Description |
| ----------- | ----------- |
| `OSG_DISABLE_PROXY_FALLBACK`      | Do not disable using proxies. By default, `stashcp` will try to use an HTTP proxy when connecting to a cache. If this environment variable is set (no value necessary, only if it's set), then `stashcp` will not fallback to no proxy if the proxy download fails.         |


