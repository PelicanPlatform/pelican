
Pelican Command Line
====================

The Pelican command line tool allows one to use a Pelican
federation as a client and serve datasets through running a
Pelican origin service.

Running an Pelican origin
-------------------------

To launch a Pelican origin, run the following:

```
pelican origin serve -f https://director.example.com -v /tmp/stash/:/test
```

Running an OSDF origin
----------------------

The Open Science Data Federation (OSDF) is a well-known Pelican federation
in support of the science and engineering communities in the US.

To launch an origin using OSDF defaults, rename the output binary from
`pelican` to `osdf`.  Then, run:

```
osdf origin serve -v /tmp/stash/:/test
```
