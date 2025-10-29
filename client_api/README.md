# Pelican Client API Server

The Pelican Client API Server provides a RESTful API for interacting with Pelican client functionality over a Unix domain socket. This enables external applications to use Pelican transfer capabilities programmatically without directly invoking the CLI.

## Features

- **Job-Based Transfers**: Submit multiple file transfers as a single job
- **Asynchronous Execution**: Non-blocking transfer operations with status polling
- **Progress Tracking**: Real-time progress information for jobs and transfers
- **Cancellation Support**: Cancel entire jobs and their transfers
- **File Operations**: Stat, list, and delete remote objects
- **Unix Domain Socket**: Secure local IPC without network exposure
- **RESTful API**: Standard HTTP methods and JSON payloads
- **OpenAPI Documentation**: Auto-generated API specification

## Quick Start

### Start the Server

```bash
# Start the server (runs in foreground)
pelican client-api serve

# Start with custom socket path
pelican client-api serve --socket /tmp/pelican-api.sock

# Start with custom concurrency limit
pelican client-api serve --max-jobs 10
```

### Check Server Status

```bash
pelican client-api status
```

### Stop the Server

```bash
pelican client-api stop
```

Or press `Ctrl+C` if running in foreground.

## API Overview

Base URL: `/api/v1/xfer`

### Job Management Endpoints

#### Create Job

Creates a new transfer job with one or more transfers.

```
POST /api/v1/xfer/jobs
```

**Request Body:**

```json
{
  "transfers": [
    {
      "operation": "get",
      "source": "osdf:///osgconnect/public/example.txt",
      "destination": "/tmp/example.txt",
      "recursive": false
    },
    {
      "operation": "put",
      "source": "/local/file.txt",
      "destination": "osdf:///namespace/file.txt",
      "recursive": false
    }
  ],
  "options": {
    "token": "/path/to/token",
    "caches": ["cache1.example.com", "cache2.example.com"]
  }
}
```

**Response (201 Created):**

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "created_at": "2025-01-15T10:30:00Z",
  "transfers": [
    {
      "transfer_id": "123e4567-e89b-12d3-a456-426614174000",
      "operation": "get",
      "source": "osdf:///osgconnect/public/example.txt",
      "destination": "/tmp/example.txt",
      "status": "pending"
    }
  ]
}
```

#### Get Job Status

Retrieves detailed status of a job including all transfers and progress.

```
GET /api/v1/xfer/jobs/:job_id
```

**Response (200 OK):**

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "created_at": "2025-01-15T10:30:00Z",
  "started_at": "2025-01-15T10:30:01Z",
  "progress": {
    "bytes_transferred": 1048576,
    "total_bytes": 10485760,
    "percentage": 10.0,
    "transfer_rate_mbps": 8.5,
    "transfers_completed": 0,
    "transfers_total": 2,
    "transfers_failed": 0
  },
  "transfers": [
    {
      "transfer_id": "123e4567-e89b-12d3-a456-426614174000",
      "job_id": "550e8400-e29b-41d4-a716-446655440000",
      "operation": "get",
      "source": "osdf:///osgconnect/public/example.txt",
      "destination": "/tmp/example.txt",
      "status": "running",
      "created_at": "2025-01-15T10:30:00Z",
      "started_at": "2025-01-15T10:30:01Z",
      "bytes_transferred": 524288,
      "total_bytes": 5242880,
      "transfer_rate_mbps": 8.5
    }
  ]
}
```

#### List Jobs

Lists all jobs with optional filtering.

```
GET /api/v1/xfer/jobs?status=running&limit=10&offset=0
```

**Query Parameters:**
- `status` (optional): Filter by job status (`pending`, `running`, `completed`, `failed`, `cancelled`)
- `limit` (optional, default=10, max=100): Number of jobs to return
- `offset` (optional, default=0): Pagination offset

**Response (200 OK):**

```json
{
  "jobs": [
    {
      "job_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "running",
      "created_at": "2025-01-15T10:30:00Z",
      "transfers_completed": 1,
      "transfers_total": 2,
      "bytes_transferred": 5242880,
      "total_bytes": 10485760
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

#### Cancel Job

Cancels a job and all its incomplete transfers.

```
DELETE /api/v1/xfer/jobs/:job_id
```

**Response (200 OK):**

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "transfers_cancelled": 1,
  "transfers_completed": 1
}
```

**Error (404 Not Found):**

```json
{
  "error": "Job not found",
  "code": "NOT_FOUND"
}
```

**Error (409 Conflict):**

```json
{
  "error": "Job already completed",
  "code": "CONFLICT"
}
```

### File Operations

#### Stat Remote Object

Gets metadata about a remote file or directory.

```
POST /api/v1/xfer/stat
```

**Request Body:**

```json
{
  "url": "osdf:///osgconnect/public/example.txt",
  "options": {
    "token": "/path/to/token"
  }
}
```

**Response (200 OK):**

```json
{
  "name": "example.txt",
  "size": 1024,
  "is_collection": false,
  "mod_time": "2025-01-15T10:00:00Z",
  "checksums": {
    "md5": "098f6bcd4621d373cade4e832627b4f6"
  }
}
```

#### List Directory Contents

Lists files and subdirectories in a remote directory.

```
POST /api/v1/xfer/list
```

**Request Body:**

```json
{
  "url": "osdf:///osgconnect/public/",
  "options": {
    "token": "/path/to/token"
  }
}
```

**Response (200 OK):**

```json
{
  "items": [
    {
      "name": "example.txt",
      "size": 1024,
      "is_collection": false,
      "mod_time": "2025-01-15T10:00:00Z"
    },
    {
      "name": "subdir",
      "size": 0,
      "is_collection": true,
      "mod_time": "2025-01-14T15:30:00Z"
    }
  ]
}
```

#### Delete Remote Object

Deletes a remote file or directory.

```
POST /api/v1/xfer/delete
```

**Request Body:**

```json
{
  "url": "osdf:///namespace/file.txt",
  "recursive": false,
  "options": {
    "token": "/path/to/token"
  }
}
```

**Response (200 OK):**

```json
{
  "message": "Object deleted successfully",
  "url": "osdf:///namespace/file.txt"
}
```

### Health Check

```
GET /health
```

**Response (200 OK):**

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime_seconds": 3600
}
```

### Shutdown Server

Initiates a graceful shutdown of the server.

```
POST /shutdown
```

**Response (200 OK):**

```json
{
  "message": "Server shutdown initiated"
}
```

**Notes:**
- The server responds immediately and then begins shutdown
- All active transfers are cancelled gracefully
- The server waits for HTTP connections to complete (with timeout)
- Socket and PID files are cleaned up automatically
- This is equivalent to `pelican client-api stop` or sending `SIGTERM`

## Status Values

Jobs and transfers can have the following status values:

- `pending`: Queued but not yet started
- `running`: Currently executing
- `completed`: Successfully finished
- `failed`: Encountered an error
- `cancelled`: Manually cancelled by user

## Error Codes

The API returns standard HTTP status codes along with error codes:

- `INVALID_REQUEST`: Malformed request (400)
- `NOT_FOUND`: Resource not found (404)
- `UNAUTHORIZED`: Authentication required (401)
- `CONFLICT`: Operation conflict (409)
- `INTERNAL_ERROR`: Server error (500)
- `TIMEOUT`: Operation timed out (504)
- `TRANSFER_FAILED`: Transfer operation failed (500)
- `CANCELLED`: Operation was cancelled (409)

## Examples

### Using curl

```bash
# Create a job with multiple transfers
curl -X POST \
  --unix-socket ~/.pelican/client-api.sock \
  http://localhost/api/v1/xfer/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "transfers": [
      {
        "operation": "get",
        "source": "osdf:///osgconnect/public/example.txt",
        "destination": "/tmp/example.txt"
      }
    ]
  }'

# Get job status
curl --unix-socket ~/.pelican/client-api.sock \
  http://localhost/api/v1/xfer/jobs/550e8400-e29b-41d4-a716-446655440000

# List all running jobs
curl --unix-socket ~/.pelican/client-api.sock \
  "http://localhost/api/v1/xfer/jobs?status=running"

# Cancel a job
curl -X DELETE \
  --unix-socket ~/.pelican/client-api.sock \
  http://localhost/api/v1/xfer/jobs/550e8400-e29b-41d4-a716-446655440000

# Stat a file
curl -X POST \
  --unix-socket ~/.pelican/client-api.sock \
  http://localhost/api/v1/xfer/stat \
  -H "Content-Type: application/json" \
  -d '{"url": "osdf:///osgconnect/public/example.txt"}'

# Health check
curl --unix-socket ~/.pelican/client-api.sock \
  http://localhost/health

# Shutdown the server
curl -X POST \
  --unix-socket ~/.pelican/client-api.sock \
  http://localhost/shutdown
```

### Using Python

```python
import requests
import requests_unixsocket
import json

# Create session with Unix socket support
session = requests_unixsocket.Session()

# Base URL for Unix socket
socket_path = "/Users/username/.pelican/client-api.sock"
base_url = f"http+unix://{socket_path.replace('/', '%2F')}/api/v1/xfer"

# Create a job
job_request = {
    "transfers": [
        {
            "operation": "get",
            "source": "osdf:///osgconnect/public/example.txt",
            "destination": "/tmp/example.txt",
            "recursive": False
        }
    ]
}

response = session.post(f"{base_url}/jobs", json=job_request)
job = response.json()
job_id = job["job_id"]

print(f"Created job: {job_id}")

# Poll for status
import time

while True:
    response = session.get(f"{base_url}/jobs/{job_id}")
    status = response.json()

    print(f"Status: {status['status']}")
    print(f"Progress: {status['progress']['percentage']:.1f}%")

    if status["status"] in ["completed", "failed", "cancelled"]:
        break

    time.sleep(1)

print("Job finished!")
```

## Configuration

The server can be configured via command-line flags or environment variables:

### Command-Line Flags

- `--socket`: Path to Unix socket (default: `~/.pelican/client-api.sock`)
- `--pid-file`: Path to PID file (default: `~/.pelican/client-api.pid`)
- `--max-jobs`: Maximum concurrent jobs (default: 5)

### Socket Permissions

The Unix socket is created with mode 0600 (owner read/write only) for security. Only the user who started the server can connect to it.

## Implementation Details

### Job Execution Model

1. Jobs are created with multiple transfers
2. Transfers within a job execute sequentially
3. Jobs execute concurrently (up to `max-jobs` limit)
4. Cancelling a job stops all incomplete transfers
5. Job completes when all transfers finish

### Concurrency

- Maximum concurrent jobs controlled by `--max-jobs` flag
- Transfers within a job execute sequentially
- Server uses goroutines and channels for async execution
- Transfer progress tracked in memory (Phase 1)

### Error Handling

- Transient errors: Individual transfer fails, job continues
- Fatal errors: Job fails immediately
- Cancellation: Graceful shutdown of transfers
- Panic recovery: Middleware catches panics

## Future Enhancements (Phase 2 & 3)

### Phase 2: CLI Integration
- `pelican object get --async` returns job ID
- `pelican job status <job-id>` checks status
- `pelican job cancel <job-id>` cancels job
- `pelican job list` lists all jobs

### Phase 3: Persistent State
- SQLite database for job/transfer state
- Survives server restarts
- Historical job records
- Job cleanup policies

## Troubleshooting

### Server Won't Start

```bash
# Check if already running
pelican client-api status

# Check socket file
ls -la ~/.pelican/client-api.sock

# Remove stale socket
rm ~/.pelican/client-api.sock
pelican client-api serve
```

### Connection Refused

Ensure the server is running:

```bash
pelican client-api status
```

Check socket path matches:

```bash
# Default location
~/.pelican/client-api.sock
```

### Permission Denied

The socket has restrictive permissions (0600). Ensure you're the same user who started the server.

## Development

### Running Tests

```bash
cd client_api
go test -v
```

### Building

```bash
# Build Pelican with client API support
make build
```

### Adding New Endpoints

1. Add request/response types to `models.go`
2. Implement handler in `handlers.go`
3. Register route in `server.go` `setupRoutes()`
4. Update OpenAPI documentation
5. Add tests

## License

Copyright (C) 2025, Pelican Project, Morgridge Institute for Research

Licensed under the Apache License, Version 2.0
