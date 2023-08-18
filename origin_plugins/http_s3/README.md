# HTTP/S3 filesystem plugin for XRootD

These filesystem plugins allow Pelican origins to interface with HTTP and S3 storage 
backends by treating them as underlying "filesystems" for an XRootD server.

## Building and Installing
### Prerequisites
    - CMake, version >=3.13
    - GCC, version >=8

### Building
From this directory, run
```
mkdir build
cd build
cmake ..
make
```
If all goes well, this should build the plugins from the source code and produce the files
`libXrdHTTPServer-5.so` and	`libXrdS3-5.so`, corresponding to the plugins for both HTTP and
S3.

If you don't wish to install these plugins, you can still use them by pointing your XRootD
config to use them, such as:
`ofs.osslib /path/to/libXrdS3.so`
Note that XRootD will automatically handle versioning of the shared object, so there's no need
to include the `-5` that suffixes each shared object's filename. 

### Installing
To install the plugins in a system-accessible location where XRootD will be able to find them
on its own, replace the `make` command from the build step with `make install`, resulting in
the following build+install command:
```
mkdir build
cd build
cmake ..
make install
```
Once installed, the `build` directory can be safely deleted.

Configuration
-------------

To configure the plugin, add the following line to the XRootd configuration file
(adjusting for whichever plugin is desired -- only one can be run at a time):

```
ofs.osslib libXrdS3.so
```
