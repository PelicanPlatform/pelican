
<h1 align="center">Pelican Command Line</h1>

<p align="center">
  <img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/PelicanPlatform/pelican/codeql-analysis.yml?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/github/license/PelicanPlatform/pelican?style=for-the-badge">
  <img alt="Release" src="https://img.shields.io/github/v/release/pelicanplatform/pelican?style=for-the-badge">
  <img alt="Downloads for all releases" src="https://img.shields.io/github/downloads/pelicanplatform/pelican/total?style=for-the-badge">
  <img alt="Go Report" src="https://img.shields.io/badge/go%20report-A+-brightgreen.svg?style=for-the-badge">
</p>

The Pelican command line tool allows one to use a Pelican
federation as a client and serve datasets through running a
Pelican origin service.

For more information on Pelican, see the [Pelican Platform page](https://pelicanplatform.org/).

For documentation on using the Pelican Platform, see the [Pelican Platform documentation page](https://docs.pelicanplatform.org/).

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
