# Pelican Client Agent Server

The Pelican Client Agent Server provides a RESTful API for interacting with Pelican client functionality over a Unix domain socket. This enables external applications to use Pelican transfer capabilities programmatically without directly invoking the CLI.

## Features

- **Job-Based Transfers**: Submit multiple file transfers as a single job
- **Asynchronous Execution**: Non-blocking transfer operations with status polling
- **Progress Tracking**: Real-time progress information for jobs and transfers
- **Cancellation Support**: Cancel entire jobs and their transfers
- **File Operations**: Stat, list, and delete remote objects
- **Unix Domain Socket**: Secure local IPC without network exposure
- **RESTful API**: Standard HTTP methods and JSON payloads
- **Persistent State**: SQLite database with job history and recovery
- **CLI Integration**: `--async` flags and `pelican job` commands
- **API Client Library**: Go package for programmatic access

## Quick Start

### Start the Server

```bash
# Start the server (runs in foreground)
pelican client-agent start

# Start with custom socket path
pelican client-agent start --socket /tmp/pelican-api.sock

# Start with custom concurrency limit
pelican client-agent start --max-jobs 10
```

### Check Server Status

```bash
pelican client-agent status
```

### Stop the Server

```bash
pelican client-agent stop
```

Or press `Ctrl+C` if running in foreground.

## API Overview

Base URL: `/api/v1.0/transfer-agent`

### Job Management Endpoints

#### Create Job

Creates a new transfer job with one or more transfers.

```
POST /api/v1.0/transfer-agent/jobs
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
GET /api/v1.0/transfer-agent/jobs/:job_id
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
GET /api/v1.0/transfer-agent/jobs?status=running&limit=10&offset=0
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
DELETE /api/v1.0/transfer-agent/jobs/:job_id
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
POST /api/v1.0/transfer-agent/stat
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
POST /api/v1.0/transfer-agent/list
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
POST /api/v1.0/transfer-agent/delete
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
- This is equivalent to `pelican client-agent stop` or sending `SIGTERM`

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
  --unix-socket ~/.pelican/client-agent.sock \
  http://localhost/api/v1.0/transfer-agent/jobs \
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
curl --unix-socket ~/.pelican/client-agent.sock \
  http://localhost/api/v1.0/transfer-agent/jobs/550e8400-e29b-41d4-a716-446655440000

# List all running jobs
curl --unix-socket ~/.pelican/client-agent.sock \
  "http://localhost/api/v1.0/transfer-agent/jobs?status=running"

# Cancel a job
curl -X DELETE \
  --unix-socket ~/.pelican/client-agent.sock \
  http://localhost/api/v1.0/transfer-agent/jobs/550e8400-e29b-41d4-a716-446655440000

# Stat a file
curl -X POST \
  --unix-socket ~/.pelican/client-agent.sock \
  http://localhost/api/v1.0/transfer-agent/stat \
  -H "Content-Type: application/json" \
  -d '{"url": "osdf:///osgconnect/public/example.txt"}'

# Health check
curl --unix-socket ~/.pelican/client-agent.sock \
  http://localhost/health

# Shutdown the server
curl -X POST \
  --unix-socket ~/.pelican/client-agent.sock \
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
socket_path = "/Users/username/.pelican/client-agent.sock"
base_url = f"http+unix://{socket_path.replace('/', '%2F')}/api/v1.0/transfer-agent"

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

- `--socket`: Path to Unix socket (default: `~/.pelican/client-agent.sock`)
- `--pid-file`: Path to PID file (default: `~/.pelican/client-agent.pid`)
- `--max-jobs`: Maximum concurrent jobs (default: 5)

### Socket Permissions

The Unix socket is created with mode 0600 (owner read/write only) for security. Only the user who started the server can connect to it.

## Implementation Details

### Job Execution Model

1. Jobs are created with multiple transfers
1. Transfers within a job execute sequentially
1. Jobs execute concurrently (up to `max-jobs` limit)
1. Cancelling a job stops all incomplete transfers
1. Job completes when all transfers finish

### Concurrency

- Maximum concurrent jobs controlled by `--max-jobs` flag (default: 5)
- Transfers within a job execute sequentially
- Server uses goroutines and channels for async execution
- Transfer progress tracked in memory and persisted to database

### Error Handling

- Transient errors: Individual transfer fails, job continues
- Fatal errors: Job fails immediately
- Cancellation: Graceful shutdown of transfers
- Panic recovery: Middleware catches panics

## Persistent State and Job Recovery

The server uses SQLite to persist job and transfer state:

- **Database Location**: `~/.pelican/client-agent.db` (default)
- **Job Recovery**: Incomplete jobs are automatically recovered on server restart
- **Job History**: Completed jobs are archived for historical queries
- **Retention Policy**: Historical jobs older than 30 days are automatically pruned
- **Migrations**: Schema managed with Goose migrations for easy upgrades

### Job Lifecycle

1. **Active Jobs**: Stored in `jobs` and `transfers` tables
1. **Archival**: Jobs completed >5 minutes ago are moved to history tables
1. **Recovery**: On restart, incomplete jobs are retried with incremented retry count
1. **Pruning**: Historical jobs older than 30 days are deleted (configurable)

## Troubleshooting

### Server Won't Start

```bash
# Check if already running
pelican client-agent status

# Check socket file
ls -la ~/.pelican/client-agent.sock

# Remove stale socket
rm ~/.pelican/client-agent.sock
pelican client-agent start
```

### Connection Refused

Ensure the server is running:

```bash
pelican client-agent status
```

Check socket path matches:

```bash
# Default location
~/.pelican/client-agent.sock
```

### Permission Denied

The socket has restrictive permissions (0600). Ensure you're the same user who started the server.

## CLI Integration (Phase 2)

Starting with Phase 2, Pelican's CLI commands can execute transfers asynchronously through the Client Agent Server. This enables fire-and-forget transfers and better management of long-running operations.

### Async Transfer Flags

All object transfer commands (`get`, `put`, `copy`) support async execution:

#### --async Flag

Submit the transfer as an asynchronous job and return immediately with a job ID:

```bash
# Async download - returns immediately
pelican object get --async osdf:///path/to/file /local/destination

# Output:
# Job created: 550e8400-e29b-41d4-a716-446655440000
# Check status with: pelican job status 550e8400-e29b-41d4-a716-446655440000
```

#### --async --wait Flags

Submit as async job but wait for completion before returning:

```bash
# Async download with wait - blocks until complete
pelican object get --async --wait osdf:///path/to/file /local/destination

# Output:
# Job created: 550e8400-e29b-41d4-a716-446655440000
# Waiting for job to complete...
# Job completed successfully
# Transferred: 1048576 bytes
```

#### Without --async

Executes directly using the existing client library (default behavior):

```bash
# Traditional direct execution
pelican object get osdf:///path/to/file /local/destination
```

### Job Management Commands

The `pelican job` subcommand provides tools to manage asynchronous jobs:

#### Check Job Status

Get detailed status of a job including progress and transfer details:

```bash
# One-time status check
pelican job status <job-id>

# Output:
# Job ID: 550e8400-e29b-41d4-a716-446655440000
# Status: running
# Created: 2025-10-29 10:30:00
# Started: 2025-10-29 10:30:01
# Progress: 45.2% (4.7 MB / 10.4 MB)
# Transfer Rate: 8.5 Mbps
# Transfers: 1/2 completed, 0 failed
```

Watch job status with live updates (refreshes every 2 seconds):

```bash
# Watch mode - updates automatically
pelican job status --watch <job-id>
```

#### List Jobs

View all jobs with optional filtering:

```bash
# List all jobs (default: last 10)
pelican job list

# Output (table format):
# JOB ID                                STATUS     PROGRESS  CREATED
# 550e8400-e29b-41d4-a716-446655440000  completed  100.0%    2025-10-29 10:30:00
# 661f9511-f3ac-52e5-b827-557766551111  running    45.2%     2025-10-29 10:35:00

# Filter by status
pelican job list --status running
pelican job list --status completed
pelican job list --status failed

# Pagination
pelican job list --limit 20 --offset 10
```

#### Cancel Job

Stop a running job and cancel incomplete transfers:

```bash
# Cancel a job
pelican job cancel <job-id>

# Output:
# Job 550e8400-e29b-41d4-a716-446655440000 cancelled successfully
```

### Usage Examples

#### Fire-and-Forget Upload

Start a large upload and continue working:

```bash
# Start upload in background
pelican object put --async /local/large-dataset.tar.gz osdf:///project/data/

# Save the job ID from output
export JOB_ID="550e8400-e29b-41d4-a716-446655440000"

# Continue working...
# Check progress later
pelican job status $JOB_ID
```

#### Batch Transfers

Submit multiple transfers without waiting:

```bash
#!/bin/bash
# Upload multiple files asynchronously

for file in dataset/*.txt; do
    pelican object put --async "$file" "osdf:///project/data/$(basename $file)"
done

# Check status of all jobs
pelican job list
```

#### Monitored Transfer

Track a long-running transfer:

```bash
# Start transfer with live monitoring
pelican object get --async osdf:///large/dataset.tar.gz /local/destination
# (save job ID)

# Watch progress in real-time
pelican job status --watch <job-id>

# Or check periodically
watch -n 5 pelican job status <job-id>
```

#### Conditional Workflow

Wait for transfer completion before proceeding:

```bash
#!/bin/bash
# Download and process data

pelican object get --async --wait osdf:///data/input.csv /tmp/input.csv

# Only proceeds after download completes
python process_data.py /tmp/input.csv
```

### Programmatic Access (API Client)

For Go applications, use the `apiclient` package to interact with the Client Agent Server:

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/pelicanplatform/pelican/client_agent"
    "github.com/pelicanplatform/pelican/client_agent/apiclient"
)

func main() {
    ctx := context.Background()

    // Create API client (uses default socket path)
    client, err := apiclient.NewAPIClient("")
    if err != nil {
        panic(err)
    }

    // Check if server is running
    if !client.IsServerRunning(ctx) {
        fmt.Println("Server is not running. Start with: pelican client-agent start")
        return
    }

    // Create a transfer job
    transfers := []client_agent.TransferRequest{
        {
            Operation:   "get",
            Source:      "osdf:///osgconnect/public/example.txt",
            Destination: "/tmp/example.txt",
            Recursive:   false,
        },
    }

    options := client_agent.TransferOptions{
        Token: "/path/to/token",
    }

    jobID, err := client.CreateJob(ctx, transfers, options)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Created job: %s\n", jobID)

    // Wait for completion (with timeout)
    err = client.WaitForJob(ctx, jobID, 5*time.Minute)
    if err != nil {
        panic(err)
    }

    // Get final status
    status, err := client.GetJobStatus(ctx, jobID)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Job completed: %d bytes transferred\n",
        status.Progress.BytesTransferred)
}
```

### API Client Methods

The `apiclient.APIClient` provides the following methods:

- `NewAPIClient(socketPath string) (*APIClient, error)` - Create new client
- `IsServerRunning(ctx context.Context) bool` - Check if server is accessible
- `CreateJob(ctx, transfers, options) (string, error)` - Create new job
- `GetJobStatus(ctx, jobID) (*JobStatus, error)` - Get job status
- `WaitForJob(ctx, jobID, timeout) error` - Wait for job completion
- `ListJobs(ctx, status, limit, offset) (*JobListResponse, error)` - List jobs
- `CancelJob(ctx, jobID) error` - Cancel job
- `Stat(ctx, url, options) (*StatResponse, error)` - Stat remote object
- `List(ctx, url, options) (*ListResponse, error)` - List directory contents
- `Delete(ctx, url, recursive, options) error` - Delete remote object

### Prerequisites for Async Mode

1. **Server Running**: Client Agent server must be running:

   ```bash
   pelican client-agent start
   ```

1. **Socket Path**: CLI automatically uses default socket. Override with:

   ```bash
   export PELICAN_CLIENTAGENT_SOCKET=/custom/path/socket
   ```

1. **Authentication**: Same token requirements as direct execution

### Error Handling

If the server is not running, async commands will fail with a clear error:

```bash
$ pelican object get --async osdf:///file /dest
Error: Client Agent server is not running
Start it with 'pelican serve --client-agent'
```

## Development

### Running Tests

```bash
cd client_agent
go test -v
```

### Building

```bash
# Build Pelican with client agent support
make build
```

### Adding New Endpoints

1. Add request/response types to `models.go`
1. Implement handler in `handlers.go`
1. Register route in `server.go` `setupRoutes()`
1. Update OpenAPI documentation
1. Add tests

## License

Copyright (C) 2025, Pelican Project, Morgridge Institute for Research

Licensed under the Apache License, Version 2.0
