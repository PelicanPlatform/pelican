Installing the Pelican Platform
===============================

This document explains how a user can download and install the Pelican client. 

Installation Steps:
--------------------

### Install the Pelican Platform Binary
Navigate to the [Pelican release page](https://github.com/PelicanPlatform/pelican/releases/). Download the proper binary for the system you are running on and select which version you would like to install. 

Our versions are built like so:
For example: 7.1.2
- 7 represents the latest major version release
- 1 represents feature releases
- 2 represents a bug fix/patch release

### Extract the Binary
Once the package has finished downloading, place it in your workspace and extract the binary

### Test Functionality of the Pelican Platform
Once extracted, make sure you are in the same directory as the **Pelican** executable. To test if everything works, we can do a simple **object copy** command:

```console
./pelican -f osg-htc.org object copy /osgconnect/public/osg/testfile.txt .
testfile.txt 36.00 b / 36.00 b [=============================================================================================] Done!
```

You should now notice a file **testfile.txt** now in your directory.

Congrats on making your first Pelican Object Copy!