
Pelican Command Line
====================

The Pelican command line tool allows one to use a Pelican
federation as a client and serve datasets through running a
Pelican origin service.

Testing and Usage
-----------------

Run the following command to download a test file (`/test/query1`) from the
configured federation:

```
$ pelican object get /test/query1 ./
```


Running an Pelican origin
-------------------------

To launch a Pelican origin, run the following:

```
pelican origin serve -f https://director.example.com -v /tmp/stash/:/test
```

Running an OSDF origin or client
--------------------------------

The Open Science Data Federation (OSDF) is a well-known Pelican federation
in support of the science and engineering communities in the US.

To launch an origin using OSDF defaults, rename the output binary from
`pelican` to `osdf`.  Then, run:

```
osdf origin serve -v /tmp/stash/:/test
```

Similarly, the `osdf` binary can be used to download from the OSDF:

```
$ osdf object get /osgconnect/public/dweitzel/blast/queries/query1 ./
```

To ease the transition of `stashcp`
[users](https://github.com/htcondor/osdf-client) to pelican, the tool can also
be renamed or symlinked to `stashcp`:

```
$ stashcp /osgconnect/public/dweitzel/blast/queries/query1 ./
```

and it shares the same defaults and behavior as stashcp.


Building
--------

Building is performed with the [goreleaser](https://goreleaser.com/) tool.  To build a snapshot (not release):

    $ goreleaser --clean --snapshot

The binaries will be located in `./dist` directory.
