# POSIXv2 Origin Backend Implementation Summary

## Completed Work

### 1. Storage Backend Type
- Added `OriginStoragePosixv2` constant to `server_structs/origin.go`
- Updated `ParseOriginStorageType` to recognize "posixv2" storage type
- Created `Posixv2Origin` struct in `server_utils/origin_posixv2.go`
- Integrated into origin export configuration system

### 2. Origin Serve Module
Created new `origin_serve` package with three main files:

#### filesystem.go
- `aferoFileSystem`: Wraps afero.Fs to implement webdav.FileSystem interface
- `aferoFile`: Wraps afero.File to implement webdav.File interface
- Provides POSIX filesystem operations (Mkdir, OpenFile, RemoveAll, Rename, Stat, Readdir)
- Maps federation prefixes to storage paths

#### authz.go
- `authConfig`: Token verification and authorization caching system
- Based on existing cache_authz.go implementation
- Integrates with ttlcache for performance
- Verifies SciTokens and WLCG tokens
- Checks token scopes against export capabilities
- Supports public reads without authentication

#### handlers.go
- HTTP middleware for token-based authorization
- WebDAV handler initialization for each export
- Gin route registration for federation prefixes
- Supports GET, PUT, HEAD, PROPFIND, DELETE methods
- Extracts user/group info and adds to request context

### 3. Launcher Integration
Modified `launchers/origin_serve.go`:
- Added check for POSIXv2 storage type
- Created `OriginServePosixv2` function that:
  - Initializes origin database and APIs
  - Sets up authorization configuration
  - Initializes and registers HTTP handlers
  - Bypasses XRootD entirely

### 4. End-to-End Tests
Created `e2e_fed_tests/posixv2_test.go`:
- `TestPosixv2OriginUploadDownload`: Tests file upload and download
- `TestPosixv2OriginDirectoryListing`: Tests directory access
- Uses standard Pelican client APIs
- Verifies integration with XRootD-based cache

## Architecture

```
Client Request Flow:
1. Client queries Director for namespace
2. Director returns Origin URL
3. Client makes HTTP request to Origin
4. Origin authMiddleware validates token
5. WebDAV handler serves file from afero filesystem
```

```
Components:
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       v
┌─────────────┐
│  Director   │
└──────┬──────┘
       │
       v
┌─────────────────────┐
│  POSIXv2 Origin     │
│  ┌───────────────┐  │
│  │ Gin Router    │  │
│  └───────┬───────┘  │
│          │          │
│  ┌───────v───────┐  │
│  │ authMiddleware│  │
│  └───────┬───────┘  │
│          │          │
│  ┌───────v───────┐  │
│  │ WebDAV Handler│  │
│  └───────┬───────┘  │
│          │          │
│  ┌───────v───────┐  │
│  │ afero.Fs      │  │
│  └───────────────┘  │
└─────────────────────┘
```

## Configuration Example

```yaml
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: /path/to/storage
      Capabilities: ["PublicReads", "Writes", "Listings"]
      IssuerUrls: ["https://issuer.example.com"]
```

## What Still Needs Testing

1. **Build and Run Tests**
   - Web UI needs to be built (`make web-build`)
   - Run e2e tests: `go test -v ./e2e_fed_tests -run TestPosixv2`

2. **Manual Verification**
   - Start POSIXv2 origin: `pelican origin serve`
   - Upload file: `pelican object put /local/file pelican:///test/file`
   - Download file: `pelican object get pelican:///test/file /local/download`
   - List directory: `pelican object ls pelican:///test/`

3. **Integration Testing**
   - Verify cache can fetch from POSIXv2 origin
   - Verify token scopes are properly enforced
   - Test different capability combinations
   - Test multiuser mode (if applicable)

## Known Limitations

1. **User/Group Extraction**: Currently uses placeholder "nobody" user
   - Need to extract uid/gid from token claims
   - Should set filesystem operation user context

2. **PROPFIND Depth**: WebDAV PROPFIND may need tuning
   - Current implementation supports basic directory listing
   - May need optimization for large directories

3. **Error Handling**: Should enhance error responses
   - Map filesystem errors to appropriate HTTP status codes
   - Provide more detailed error messages

## Future Enhancements

1. **Performance**
   - Add caching for stat operations
   - Optimize directory listings
   - Consider memory-mapped I/O for large files

2. **Features**
   - Support COPY/MOVE operations
   - Add checksumming support
   - Implement range requests optimization

3. **Monitoring**
   - Add metrics for origin_serve operations
   - Track authorization cache hit rates
   - Monitor filesystem operation latencies

## Files Modified/Created

### Created:
- `origin_serve/filesystem.go`
- `origin_serve/authz.go`
- `origin_serve/handlers.go`
- `server_utils/origin_posixv2.go`
- `e2e_fed_tests/posixv2_test.go`
- `POSIXV2_IMPLEMENTATION.md` (this file)

### Modified:
- `server_structs/origin.go`
- `server_utils/origin.go`
- `launchers/origin_serve.go`

## Testing Commands

```bash
# Build the project
make pelican-build

# Run POSIXv2 tests specifically
go test -v ./e2e_fed_tests -run TestPosixv2

# Run all e2e tests
go test -v ./e2e_fed_tests

# Start a POSIXv2 origin manually
pelican origin serve -c config.yaml

# Example config.yaml:
# Origin:
#   StorageType: posixv2
#   Exports:
#     - FederationPrefix: /test
#       StoragePrefix: /tmp/pelican-storage
#       Capabilities: ["PublicReads", "Writes", "Listings"]
```
