# Design Document: Pelican Client Agent Server

**Author:** Design Proposal
**Date:** October 29, 2025
**Status:** Proposed

## Executive Summary

This document proposes the design and implementation of a RESTful server that exposes Pelican's client agent functionality over a Unix domain socket. The server will enable programmatic access to Pelican's data transfer capabilities, supporting operations like get, put, copy, delete, stat, and list through a well-defined REST API.

The implementation will proceed in three phases:
1. **Phase 1:** Basic stateless server with OpenAPI schema
2. **Phase 2:** Command-line integration with dual-mode execution (server vs. direct)
3. **Phase 3:** Persistent state management with transfer history

## Background

Currently, Pelican's client functionality is accessible only through:
- Command-line interface (`pelican object get/put/copy/delete/stat/ls`)
- Direct Go API calls (`client.DoGet()`, `client.DoPut()`, etc.)

This design adds a third access method: a RESTful agent server that can be accessed over a Unix domain socket, enabling:
- Language-agnostic client implementations
- Long-running daemon for managing transfers
- Web-based or programmatic monitoring of transfers
- Separation of transfer execution from calling process

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Applications                      │
│  (CLI, Python, curl, web UI, etc.)                          │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP over Unix Socket
┌─────────────────────▼───────────────────────────────────────┐
│              Pelican Client Agent Server                       │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  REST API Layer (Gin/Echo Framework)                   │ │
│  │  - /api/v1/transfers (POST, GET, DELETE)               │ │
│  │  - /api/v1/stat (POST)                                 │ │
│  │  - /api/v1/list (POST)                                 │ │
│  │  - /api/v1/health                                      │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Transfer Manager                                       │ │
│  │  - Job scheduling and tracking                          │ │
│  │  - Progress monitoring                                  │ │
│  │  - Concurrent transfer management                       │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  State Management (Phase 3)                            │ │
│  │  - SQLite database for persistence                      │ │
│  │  - Transfer history                                     │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│           Existing Pelican Client Library                    │
│  (client.DoGet, client.DoPut, client.DoCopy, etc.)          │
└──────────────────────────────────────────────────────────────┘
```

## Phase 1: Basic Stateless Server

### Goals
- Launch a RESTful agent server listening on Unix domain socket
- Expose core client operations through REST endpoints
- Generate OpenAPI 3.0 specification
- Implement comprehensive unit tests

### Socket Configuration

#### Default Socket Location
```
Linux/macOS: $HOME/.pelican/client-api.sock
Windows:     \\.\pipe\pelican-client-api (Named Pipe)
```

#### Configuration Parameters
```yaml
# parameters.yaml
ClientAgent:
  SocketPath: ""  # Override default socket location
  MaxConnections: 100  # Maximum concurrent connections
  RequestTimeout: 300s  # Default request timeout
```

The file `param/parameters.go` is auto-generated.  Instead, update
the command line description in `docs/parameters.yaml`.

### Command Structure

#### New Command: `pelican client-api`

```bash
pelican client-api serve [flags]

Flags:
  --socket-path string        Unix socket path (default: auto-detect)
  --foreground               Run in foreground (don't daemonize)
  --pid-file string          PID file location (default: $HOME/.pelican/client-api.pid)
  --log-file string          Log file location (default: $HOME/.pelican/client-api.log)

Examples:
  # Start server with default settings (backgrounds itself)
  pelican client-api serve

  # Start server in foreground for debugging
  pelican client-api serve --foreground

  # Use custom socket path
  pelican client-api serve --socket-path /tmp/my-pelican.sock

  # Stop the server
  pelican client-api stop

  # Check server status
  pelican client-api status
```

### REST API Specification

#### Base URL
All endpoints are relative to `/api/v1/xfer`

#### Authentication
Phase 1: No authentication (Unix socket permissions provide security)
Phase 2+: Optional token-based authentication

#### Terminology
- **Transfer Job**: A collection of one or more related transfers submitted together. Jobs can be cancelled as a unit.
- **Transfer**: An individual file transfer operation (source → destination). Multiple transfers may belong to a single job.

#### Endpoints

##### 1. Health Check
```
GET /health

Response 200:
{
  "status": "ok",
  "version": "7.0.0",
  "uptime_seconds": 3600
}
```

##### 2. Create Transfer Job
```
POST /jobs

Request Body:
{
  "transfers": [
    {
      "operation": "get|put|copy",
      "source": "pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt",
      "destination": "/tmp/test.txt",
      "recursive": false
    },
    {
      "operation": "get",
      "source": "pelican://osg-htc.org/ospool/another/file.dat",
      "destination": "/tmp/file.dat",
      "recursive": false
    }
  ],
  "options": {
    "token": "/path/to/token",  // Optional, applies to all transfers
    "caches": ["cache1.example.com", "cache2.example.com"],  // Optional
    "methods": ["http", "https"],  // Optional
    "pack_option": "auto"  // Optional: auto, tar, tar.gz, tar.xz, zip
  }
}

Note: For single-file operations, the transfers array contains one element.
      For recursive operations, the server will expand into multiple transfers.

Response 202 (Accepted):
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "created_at": "2025-10-29T10:00:00Z",
  "transfers": [
    {
      "transfer_id": "650e8400-e29b-41d4-a716-446655440001",
      "operation": "get",
      "source": "pelican://osg-htc.org/ospool/...",
      "destination": "/tmp/test.txt",
      "status": "pending"
    },
    {
      "transfer_id": "650e8400-e29b-41d4-a716-446655440002",
      "operation": "get",
      "source": "pelican://osg-htc.org/ospool/another/file.dat",
      "destination": "/tmp/file.dat",
      "status": "pending"
    }
  ]
}

Response 400 (Bad Request):
{
  "error": "Invalid source URL in transfer 0",
  "code": "INVALID_REQUEST"
}

Response 500 (Internal Error):
{
  "error": "Failed to initialize transfer engine",
  "code": "INTERNAL_ERROR"
}
```

##### 3. Get Job Status
```
GET /jobs/{job_id}

Response 200:
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running|completed|failed|cancelled|pending",
  "created_at": "2025-10-29T10:00:00Z",
  "started_at": "2025-10-29T10:00:01Z",
  "completed_at": "2025-10-29T10:00:15Z",  // null if not completed
  "progress": {
    "bytes_transferred": 1048576,
    "total_bytes": 10485760,
    "percentage": 10.0,
    "transfer_rate_mbps": 5.2,
    "transfers_completed": 1,
    "transfers_total": 5,
    "transfers_failed": 0
  },
  "transfers": [
    {
      "transfer_id": "650e8400-e29b-41d4-a716-446655440001",
      "operation": "get",
      "source": "pelican://osg-htc.org/...",
      "destination": "/tmp/test.txt",
      "status": "completed",
      "bytes_transferred": 1048576,
      "total_bytes": 1048576,
      "error": null
    },
    {
      "transfer_id": "650e8400-e29b-41d4-a716-446655440002",
      "operation": "get",
      "source": "pelican://osg-htc.org/ospool/another/file.dat",
      "destination": "/tmp/file.dat",
      "status": "running",
      "bytes_transferred": 524288,
      "total_bytes": 9437184,
      "error": null
    }
  ],
  "error": null  // Overall error message if job failed
}

Response 404:
{
  "error": "Job not found",
  "code": "NOT_FOUND"
}
```

##### 4. Get Individual Transfer Status
```
GET /jobs/{job_id}/transfers/{transfer_id}

Response 200:
{
  "transfer_id": "650e8400-e29b-41d4-a716-446655440001",
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "operation": "get",
  "source": "pelican://osg-htc.org/...",
  "destination": "/tmp/test.txt",
  "status": "running|completed|failed|cancelled|pending",
  "created_at": "2025-10-29T10:00:00Z",
  "started_at": "2025-10-29T10:00:01Z",
  "completed_at": "2025-10-29T10:00:15Z",
  "bytes_transferred": 1048576,
  "total_bytes": 10485760,
  "transfer_rate_mbps": 5.2,
  "error": null
}

Response 404:
{
  "error": "Transfer not found",
  "code": "NOT_FOUND"
}
```

##### 5. List Jobs
```
GET /jobs?status=running&limit=50&offset=0

Query Parameters:
  - status: filter by status (running|completed|failed|cancelled|pending)
  - limit: max results (default: 50, max: 500)
  - offset: pagination offset (default: 0)

Response 200:
{
  "jobs": [
    {
      "job_id": "...",
      "status": "running",
      "created_at": "...",
      "transfers_completed": 2,
      "transfers_total": 5,
      "bytes_transferred": 2097152,
      "total_bytes": 10485760
    }
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

##### 6. Cancel Job
```
DELETE /jobs/{job_id}

Cancels all transfers in the job that haven't completed yet.

Response 200:
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled",
  "message": "Job cancelled successfully",
  "transfers_cancelled": 3,
  "transfers_completed": 2
}

Response 404:
{
  "error": "Job not found",
  "code": "NOT_FOUND"
}

Response 409:
{
  "error": "Job already completed",
  "code": "CONFLICT"
}
```

##### 7. Stat Remote Object
```
POST /stat

Request Body:
{
  "url": "pelican://osg-htc.org/ospool/...",
  "options": {
    "token": "/path/to/token"  // Optional
  }
}

Response 200:
{
  "name": "test.txt",
  "size": 10485760,
  "is_collection": false,
  "mod_time": "2025-10-29T10:00:00Z",
  "checksums": {
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
  }
}

Response 404:
{
  "error": "Object not found",
  "code": "NOT_FOUND"
}
```

##### 8. List Remote Directory
```
POST /list

Request Body:
{
  "url": "pelican://osg-htc.org/ospool/path/to/dir",
  "options": {
    "token": "/path/to/token"  // Optional
  }
}

Response 200:
{
  "items": [
    {
      "name": "file1.txt",
      "size": 1024,
      "is_collection": false,
      "mod_time": "2025-10-29T10:00:00Z"
    },
    {
      "name": "subdir",
      "size": 0,
      "is_collection": true,
      "mod_time": "2025-10-29T09:00:00Z"
    }
  ]
}
```

##### 9. Delete Remote Object
```
POST /delete

Request Body:
{
  "url": "pelican://osg-htc.org/ospool/path/to/file",
  "recursive": false,
  "options": {
    "token": "/path/to/token"  // Optional
  }
}

Response 200:
{
  "message": "Object deleted successfully",
  "url": "pelican://osg-htc.org/ospool/path/to/file"
}

Response 404:
{
  "error": "Object not found",
  "code": "NOT_FOUND"
}
```

### OpenAPI Schema

Generate OpenAPI 3.0 specification using [swag](https://github.com/swaggo/swag) annotations in the code. The schema will be:
- Embedded in the server binary
- Served at `/api/v1/openapi.json` and `/api/v1/openapi.yaml`
- Used to generate Swagger UI at `/api/v1/docs`

Example annotation:
```go
// @Summary Create a transfer job
// @Description Create a new job with one or more transfer operations
// @Tags jobs
// @Accept json
// @Produce json
// @Param job body JobRequest true "Job details with transfers"
// @Success 202 {object} JobResponse
// @Failure 400 {object} ErrorResponse
// @Router /jobs [post]
func (s *APIServer) CreateJob(c *gin.Context) {
    // Implementation
}
```

### Implementation Structure

#### New Package: `client_agent`

```
client_agent/
├── server.go           # Main server setup and lifecycle
├── handlers.go         # HTTP request handlers
├── models.go           # Request/response models
├── transfer_manager.go # Transfer job management
├── middleware.go       # Common middleware (logging, recovery)
├── daemon.go           # Daemonization logic (Unix)
├── daemon_windows.go   # Daemonization logic (Windows)
└── openapi.go         # OpenAPI schema generation
```

#### Key Types

```go
// models.go
type TransferRequest struct {
    Operation   string          `json:"operation" binding:"required,oneof=get put copy"`
    Source      string          `json:"source" binding:"required"`
    Destination string          `json:"destination" binding:"required"`
    Recursive   bool            `json:"recursive"`
}

type JobRequest struct {
    Transfers []TransferRequest `json:"transfers" binding:"required,min=1,dive"`
    Options   TransferOptions   `json:"options"`
}

type TransferOptions struct {
    Token      string   `json:"token,omitempty"`
    Caches     []string `json:"caches,omitempty"`
    Methods    []string `json:"methods,omitempty"`
    PackOption string   `json:"pack_option,omitempty"`
}

type JobResponse struct {
    JobID     string             `json:"job_id"`
    Status    string             `json:"status"`
    CreatedAt time.Time          `json:"created_at"`
    Transfers []TransferResponse `json:"transfers"`
}

type TransferResponse struct {
    TransferID  string    `json:"transfer_id"`
    Operation   string    `json:"operation"`
    Source      string    `json:"source"`
    Destination string    `json:"destination"`
    Status      string    `json:"status"`
}

type JobStatus struct {
    JobID       string            `json:"job_id"`
    Status      string            `json:"status"`
    CreatedAt   time.Time         `json:"created_at"`
    StartedAt   *time.Time        `json:"started_at"`
    CompletedAt *time.Time        `json:"completed_at"`
    Progress    *JobProgress      `json:"progress,omitempty"`
    Transfers   []TransferStatus  `json:"transfers"`
    Error       string            `json:"error,omitempty"`
}

type JobProgress struct {
    BytesTransferred    int64   `json:"bytes_transferred"`
    TotalBytes          int64   `json:"total_bytes"`
    Percentage          float64 `json:"percentage"`
    TransferRateMbps    float64 `json:"transfer_rate_mbps"`
    TransfersCompleted  int     `json:"transfers_completed"`
    TransfersTotal      int     `json:"transfers_total"`
    TransfersFailed     int     `json:"transfers_failed"`
}

type TransferStatus struct {
    TransferID       string     `json:"transfer_id"`
    JobID            string     `json:"job_id"`
    Operation        string     `json:"operation"`
    Source           string     `json:"source"`
    Destination      string     `json:"destination"`
    Status           string     `json:"status"`
    CreatedAt        time.Time  `json:"created_at"`
    StartedAt        *time.Time `json:"started_at"`
    CompletedAt      *time.Time `json:"completed_at"`
    BytesTransferred int64      `json:"bytes_transferred"`
    TotalBytes       int64      `json:"total_bytes"`
    TransferRateMbps float64    `json:"transfer_rate_mbps"`
    Error            string     `json:"error,omitempty"`
}

// transfer_manager.go
type TransferJob struct {
    ID          string
    Status      string
    CreatedAt   time.Time
    StartedAt   *time.Time
    CompletedAt *time.Time
    Transfers   []*Transfer
    Options     client.TransferOption
    Error       error
    CancelFunc  context.CancelFunc
}

type Transfer struct {
    ID              string
    JobID           string
    Operation       string
    Source          string
    Destination     string
    Recursive       bool
    Status          string
    CreatedAt       time.Time
    StartedAt       *time.Time
    CompletedAt     *time.Time
    BytesTransferred int64
    TotalBytes      int64
    Error           error
    CancelFunc      context.CancelFunc
    ResultChan      chan TransferResult
}

type TransferManager struct {
    jobs      map[string]*TransferJob
    transfers map[string]*Transfer
    mu        sync.RWMutex
    maxJobs   int
    semaphore chan struct{}
}
```

#### Server Implementation

```go
// server.go
type APIServer struct {
    socketPath      string
    listener        net.Listener
    router          *gin.Engine
    transferManager *TransferManager
    ctx             context.Context
    cancel          context.CancelFunc
    wg              sync.WaitGroup
}

func NewAPIServer(socketPath string) (*APIServer, error) {
    // Initialize server
    // Set up Unix socket listener
    // Create transfer manager
    // Configure Gin router with endpoints
}

func (s *APIServer) Start() error {
    // Start HTTP server on Unix socket
    // Handle graceful shutdown
}

func (s *APIServer) Stop() error {
    // Stop accepting new requests
    // Wait for in-flight transfers (with timeout)
    // Clean up resources
}

func (s *APIServer) Daemonize() error {
    // Fork process (Unix) or create service (Windows)
    // Redirect stdout/stderr to log file
    // Write PID file
    // Detach from terminal
}
```

### Daemonization

#### Unix (Linux/macOS)
Use traditional Unix daemon approach:
1. Fork parent process
2. Create new session (setsid)
3. Fork again to prevent acquiring controlling terminal
4. Change working directory to /
5. Close stdin, stdout, stderr (redirect to log file)
6. Write PID to file

Library: Use `github.com/sevlyar/go-daemon` or custom implementation

#### Windows
Create a Windows service using `golang.org/x/sys/windows/svc`

### Testing Strategy

#### Unit Tests
```
client_agent/
├── server_test.go          # Server lifecycle tests
├── handlers_test.go        # HTTP handler tests
├── transfer_manager_test.go # Transfer job management tests
└── integration_test.go     # Full API integration tests
```

Test scenarios:
1. **Server Lifecycle**
   - Start/stop server
   - Socket creation and cleanup
   - Graceful shutdown with active transfers

2. **API Endpoints**
   - Request validation
   - Successful transfers (get/put/copy)
   - Error handling (invalid URLs, missing files)
   - Concurrent transfers
   - Transfer cancellation

3. **Transfer Manager**
   - Job queueing and execution
   - Progress tracking
   - Concurrent transfer limits
   - Resource cleanup on cancellation

4. **Mock Testing**
   - Mock HTTP clients for director/origin responses
   - Mock file system operations
   - Mock transfer engine

Example test:
```go
func TestCreateJobEndpoint(t *testing.T) {
    server := setupTestServer(t)
    defer server.Stop()

    // Create job with multiple transfers
    req := JobRequest{
        Transfers: []TransferRequest{
            {
                Operation: "get",
                Source: "pelican://test.org/file1.txt",
                Destination: "/tmp/file1.txt",
            },
            {
                Operation: "get",
                Source: "pelican://test.org/file2.txt",
                Destination: "/tmp/file2.txt",
            },
        },
    }

    // Send request
    resp := sendRequest(t, server, "POST", "/api/v1/xfer/jobs", req)

    // Validate response
    assert.Equal(t, http.StatusAccepted, resp.StatusCode)

    var jobResp JobResponse
    json.NewDecoder(resp.Body).Decode(&jobResp)
    assert.NotEmpty(t, jobResp.JobID)
    assert.Equal(t, "pending", jobResp.Status)
    assert.Len(t, jobResp.Transfers, 2)
}

func TestCancelJob(t *testing.T) {
    server := setupTestServer(t)
    defer server.Stop()

    // Create and start a job
    jobID := createTestJob(t, server)

    // Cancel the job
    resp := sendRequest(t, server, "DELETE", "/api/v1/xfer/jobs/"+jobID, nil)
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    // Verify all transfers in job are cancelled
    jobStatus := getJobStatus(t, server, jobID)
    assert.Equal(t, "cancelled", jobStatus.Status)
    for _, transfer := range jobStatus.Transfers {
        if transfer.Status != "completed" {
            assert.Equal(t, "cancelled", transfer.Status)
        }
    }
}
```

### Configuration Integration

Add to `cmd/client_agent.go`:
```go
var clientAPICmd = &cobra.Command{
    Use:   "client-api",
    Short: "Manage the Pelican client agent server",
}

var clientAPIServeCmd = &cobra.Command{
    Use:   "serve",
    Short: "Start the client agent server",
    Run:   clientAPIServeMain,
}

func init() {
    flags := clientAPIServeCmd.Flags()
    flags.String("socket-path", "", "Unix socket path")
    flags.Bool("foreground", false, "Run in foreground")
    flags.String("pid-file", "", "PID file location")
    flags.String("log-file", "", "Log file location")

    clientAPICmd.AddCommand(clientAPIServeCmd)
    clientAPICmd.AddCommand(clientAPIStopCmd)
    clientAPICmd.AddCommand(clientAPIStatusCmd)
    rootCmd.AddCommand(clientAPICmd)
}
```

### Error Handling

Define standard error codes:
```go
const (
    ErrCodeInvalidRequest  = "INVALID_REQUEST"
    ErrCodeNotFound        = "NOT_FOUND"
    ErrCodeUnauthorized    = "UNAUTHORIZED"
    ErrCodeInternal        = "INTERNAL_ERROR"
    ErrCodeTimeout         = "TIMEOUT"
    ErrCodeCancelled       = "CANCELLED"
    ErrCodeTransferFailed  = "TRANSFER_FAILED"
)
```

Map Pelican client errors to HTTP status codes:
- `client.IsRetryable(err)` → 503 Service Unavailable
- URL parse errors → 400 Bad Request
- Not found errors → 404 Not Found
- Timeout errors → 504 Gateway Timeout

### Dependencies

Add to `go.mod`:
```go
require (
    github.com/gin-gonic/gin v1.10.0  // HTTP framework
    github.com/google/uuid v1.6.0      // Transfer ID generation
    github.com/sevlyar/go-daemon v0.1.6 // Unix daemonization
    github.com/swaggo/swag v1.16.3     // OpenAPI generation
    github.com/swaggo/gin-swagger v1.6.0 // Swagger UI
    golang.org/x/sys v0.15.0           // Windows service support
)
```

---

## Phase 2: Command-Line Integration

### Goals
- Update CLI to support dual-mode execution (server vs. direct)
- Transparent server discovery and fallback
- Full integration testing with running federation

### Command Behavior

Add global flag to all `pelican object` commands:
```bash
pelican object get [flags] source dest

New Flags:
  --use-api-server         Force use of agent server
  --no-api-server          Force direct execution (skip server)
  --api-socket string      Override agent server socket path

Default Behavior:
  1. Check if agent server is running (connect to socket)
  2. If running, use agent server
  3. If not running, execute directly (current behavior)
```

### Implementation

#### New Package: `client_agent/client`

```go
// client_agent/client/client.go
type APIClient struct {
    socketPath string
    httpClient *http.Client
}

func NewAPIClient(socketPath string) (*APIClient, error) {
    // Create HTTP client with Unix socket transport
}

func (c *APIClient) IsServerRunning() bool {
    // Quick connectivity check
}

func (c *APIClient) Get(ctx context.Context, source, dest string, opts ...client.TransferOption) error {
    // Call server's POST /transfers API
    // Poll for completion
    // Return results
}

func (c *APIClient) Put(ctx context.Context, source, dest string, opts ...client.TransferOption) error {
    // Similar to Get
}

// ... other operations
```

#### Update Command Files

Modify `cmd/object_get.go`, `cmd/object_put.go`, etc.:

```go
func getMain(cmd *cobra.Command, args []string) {
    ctx := cmd.Context()

    // Check mode preference
    useServer := shouldUseAPIServer(cmd)

    if useServer {
        apiClient, err := client_agent_client.NewAPIClient("")
        if err != nil {
            log.Warningln("Failed to connect to agent server, falling back to direct execution:", err)
            executeGetDirect(ctx, cmd, args)
            return
        }

        if !apiClient.IsServerRunning() {
            log.Debugln("agent server not running, using direct execution")
            executeGetDirect(ctx, cmd, args)
            return
        }

        executeGetViaAPI(ctx, apiClient, cmd, args)
    } else {
        executeGetDirect(ctx, cmd, args)
    }
}

func shouldUseAPIServer(cmd *cobra.Command) bool {
    if cmd.Flags().Changed("no-api-server") {
        noAPI, _ := cmd.Flags().GetBool("no-api-server")
        return !noAPI
    }

    if cmd.Flags().Changed("use-api-server") {
        useAPI, _ := cmd.Flags().GetBool("use-api-server")
        return useAPI
    }

    // Check config
    return param.ClientAgent_AutoConnect.GetBool()
}
```

### Configuration

Add parameters:
```yaml
ClientAgent:
  AutoConnect: false  # Phase 2: default false; Phase 3: default true
  FallbackToDirect: true  # If server fails, execute directly
  StartServerIfMissing: false  # Auto-start server if not running
```

### Progress Reporting

When using agent server:
- Poll transfer status at regular intervals
- Display progress bar (reuse existing progress bar infrastructure)
- Stream logs if available

```go
func executeGetViaAPI(ctx context.Context, apiClient *APIClient, cmd *cobra.Command, args []string) {
    // Create job with single transfer
    jobID, err := apiClient.CreateJob(ctx, []TransferRequest{
        {
            Operation: "get",
            Source: source,
            Destination: dest,
            Recursive: recursive,
        },
    }, options)

    // Set up progress bar
    pb := newProgressBar()
    defer pb.shutdown()

    if shouldShowProgress() {
        pb.launchDisplay(ctx)
    }

    // Poll for status
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            jobStatus, err := apiClient.GetJobStatus(ctx, jobID)
            if err != nil {
                return err
            }

            // Update progress bar with job progress
            if jobStatus.Progress != nil {
                pb.updateProgress(jobStatus.Progress)
            }

            // Check completion
            if jobStatus.Status == "completed" {
                return nil
            } else if jobStatus.Status == "failed" {
                // Report which transfers failed
                var failedTransfers []string
                for _, transfer := range jobStatus.Transfers {
                    if transfer.Status == "failed" {
                        failedTransfers = append(failedTransfers,
                            fmt.Sprintf("%s: %s", transfer.Source, transfer.Error))
                    }
                }
                return errors.New("Job failed: " + strings.Join(failedTransfers, "; "))
            }
        }
    }
}
```

### Testing Strategy

#### Integration Tests with Federation

Create test file: `client_agent/fed_integration_test.go`

```go
func TestGetViaAPIServer(t *testing.T) {
    // Set up test federation (reuse fed_test_utils)
    viper.Reset()
    server_utils.ResetOriginExports()
    fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

    // Start agent server
    apiServer, err := client_agent.NewAPIServer("")
    require.NoError(t, err)

    go apiServer.Start()
    defer apiServer.Stop()

    // Wait for server ready
    waitForServerReady(t, apiServer)

    // Upload test file to origin
    testFileContent := "test content"
    tempFile := filepath.Join(t.TempDir(), "test.txt")
    err = os.WriteFile(tempFile, []byte(testFileContent), 0644)
    require.NoError(t, err)

    // Upload via direct client
    destURL := fmt.Sprintf("pelican://%s/test/test.txt", fed.DirectorURL)
    err = client.DoPut(context.Background(), tempFile, destURL, false)
    require.NoError(t, err)

    // Download via API client
    apiClient := client_agent_client.NewAPIClient(apiServer.SocketPath())

    downloadPath := filepath.Join(t.TempDir(), "downloaded.txt")
    jobID, err := apiClient.CreateJob(context.Background(), []TransferRequest{
        {
            Operation: "get",
            Source: destURL,
            Destination: downloadPath,
        },
    }, nil)
    require.NoError(t, err)

    // Wait for job completion
    err = apiClient.WaitForJob(context.Background(), jobID, 30*time.Second)
    require.NoError(t, err)

    // Verify content
    downloaded, err := os.ReadFile(downloadPath)
    require.NoError(t, err)
    assert.Equal(t, testFileContent, string(downloaded))
}

func TestMultiFileJobViaAPI(t *testing.T) {
    // Test creating a job with multiple transfers
    // Verify all transfers complete
    // Test cancelling job cancels remaining transfers
}

func TestRecursiveTransferExpansion(t *testing.T) {
    // Test that recursive flag expands into multiple transfers
    // Verify job contains all discovered files
}
```

Tests should cover:
1. All operations (get, put, copy, delete, stat, list) via API
2. Recursive transfers (expansion into multiple transfers per job)
3. Multi-file jobs with multiple explicit transfers
4. Large file transfers with progress tracking
5. Concurrent jobs
6. Job cancellation (cancels all incomplete transfers)
7. Server failure and fallback behavior
8. Authentication with tokens
9. Cache preferences
10. Error conditions (network failures, missing files, partial job failures)
11. Individual transfer tracking within jobs

---

## Phase 3: Persistent State Management

### Goals
- Persist ongoing transfers to survive crashes/restarts
- Resume interrupted transfers
- Maintain transfer history
- Provide historical transfer queries

### Database Schema

Use SQLite for embedded database storage.

Location: `$HOME/.pelican/client-api.db`

#### Tables

```sql
-- Transfer jobs
CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,  -- 'pending', 'running', 'completed', 'failed', 'cancelled'
    created_at INTEGER NOT NULL,  -- Unix timestamp
    started_at INTEGER,
    completed_at INTEGER,
    options TEXT,  -- JSON-encoded transfer options
    error_message TEXT,
    CONSTRAINT check_job_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_created_at ON jobs(created_at DESC);

-- Individual transfers within jobs
CREATE TABLE transfers (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    operation TEXT NOT NULL,  -- 'get', 'put', 'copy'
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    recursive INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,  -- 'pending', 'running', 'completed', 'failed', 'cancelled'
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    bytes_transferred INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    error_message TEXT,
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
    CONSTRAINT check_transfer_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX idx_transfers_job_id ON transfers(job_id);
CREATE INDEX idx_transfers_status ON transfers(status);
CREATE INDEX idx_transfers_created_at ON transfers(created_at DESC);

-- Historical jobs (moved from jobs table)
CREATE TABLE job_history (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    options TEXT,
    error_message TEXT,
    transfers_completed INTEGER DEFAULT 0,
    transfers_failed INTEGER DEFAULT 0,
    transfers_total INTEGER DEFAULT 0,
    bytes_transferred INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0
);

CREATE INDEX idx_job_history_completed_at ON job_history(completed_at DESC);
CREATE INDEX idx_job_history_status ON job_history(status);

-- Historical transfers
CREATE TABLE transfer_history (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    source TEXT NOT NULL,
    destination TEXT NOT NULL,
    recursive INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    bytes_transferred INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    error_message TEXT,
    FOREIGN KEY (job_id) REFERENCES job_history(id) ON DELETE CASCADE
);

CREATE INDEX idx_transfer_history_job_id ON transfer_history(job_id);
CREATE INDEX idx_transfer_history_completed_at ON transfer_history(completed_at DESC);
```

#### Migration

Use [goose](https://github.com/pressly/goose) for database migrations (already a dependency in Pelican).

```
client_agent/migrations/
├── 00001_create_jobs_table.sql
├── 00002_create_transfers_table.sql
├── 00003_create_job_history_table.sql
└── 00004_create_transfer_history_table.sql
```

### State Management

#### New Package: `client_agent/store`

```go
// store/store.go
type Store struct {
    db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
    // Open SQLite database
    // Run migrations
    // Enable WAL mode for better concurrency
}

// Job operations
func (s *Store) CreateJob(job *TransferJob) error
func (s *Store) UpdateJob(id string, updates map[string]interface{}) error
func (s *Store) GetJob(id string) (*TransferJob, error)
func (s *Store) ListJobs(filter JobFilter) ([]*TransferJob, error)
func (s *Store) DeleteJob(id string) error

// Transfer operations
func (s *Store) CreateTransfer(transfer *Transfer) error
func (s *Store) UpdateTransfer(id string, updates map[string]interface{}) error
func (s *Store) GetTransfer(id string) (*Transfer, error)
func (s *Store) GetTransfersByJob(jobID string) ([]*Transfer, error)
func (s *Store) ListTransfers(filter TransferFilter) ([]*Transfer, error)

// History operations
func (s *Store) ArchiveJob(id string) error
func (s *Store) GetJobHistory(filter JobFilter) ([]*TransferJob, error)
func (s *Store) PruneHistory(olderThan time.Time) error

// Recovery operations
func (s *Store) GetRecoverableJobs() ([]*TransferJob, error)
func (s *Store) GetRecoverableTransfers(jobID string) ([]*Transfer, error)
```

### Resume Logic

On server startup:
1. Query database for jobs with status 'pending' or 'running'
2. For each job, query its transfers
3. Attempt to resume incomplete transfers
4. Update job status based on transfer states
5. Re-initiate transfers for incomplete portions

```go
func (tm *TransferManager) RecoverJobs(store *Store) error {
    jobs, err := store.GetRecoverableJobs()
    if err != nil {
        return err
    }

    for _, job := range jobs {
        transfers, err := store.GetRecoverableTransfers(job.ID)
        if err != nil {
            log.Errorf("Failed to get transfers for job %s: %v", job.ID, err)
            continue
        }

        allComplete := true
        anyFailed := false

        for _, transfer := range transfers {
            if transfer.Status == "completed" {
                continue
            }

            allComplete = false

            // Check if destination file exists and is complete
            if tm.isTransferComplete(transfer) {
                store.UpdateTransfer(transfer.ID, map[string]interface{}{
                    "status": "completed",
                    "completed_at": time.Now().Unix(),
                })
                continue
            }

            // Attempt to resume or restart transfer
            if tm.canResumeTransfer(transfer) {
                if err := tm.resumeTransfer(transfer); err != nil {
                    log.Errorf("Failed to resume transfer %s: %v", transfer.ID, err)
                    anyFailed = true
                }
            } else {
                if err := tm.retryTransfer(transfer); err != nil {
                    log.Errorf("Failed to retry transfer %s: %v", transfer.ID, err)
                    anyFailed = true
                }
            }
        }

        // Update job status
        if allComplete {
            store.UpdateJob(job.ID, map[string]interface{}{
                "status": "completed",
                "completed_at": time.Now().Unix(),
            })
        } else if anyFailed {
            store.UpdateJob(job.ID, map[string]interface{}{
                "status": "failed",
            })
        }
    }

    return nil
}
```

### New API Endpoints

#### Get Transfer History
```
GET /history?status=completed&from=2025-10-01&to=2025-10-31&limit=100&offset=0

Query Parameters:
  - status: filter by job status
  - from: start date (ISO 8601)
  - to: end date (ISO 8601)
  - operation: filter by operation type (filters jobs containing this operation)
  - limit: max results (default: 100, max: 1000)
  - offset: pagination offset

Response 200:
{
  "jobs": [
    {
      "job_id": "...",
      "status": "completed",
      "created_at": "2025-10-29T10:00:00Z",
      "completed_at": "2025-10-29T10:05:00Z",
      "transfers_completed": 5,
      "transfers_failed": 0,
      "transfers_total": 5,
      "bytes_transferred": 52428800,
      "total_bytes": 52428800
    }
  ],
  "total": 250,
  "limit": 100,
  "offset": 0
}
```

#### Get Job History Details
```
GET /history/{job_id}

Returns detailed history for a specific job including all transfers.

Response 200:
{
  "job_id": "...",
  "status": "completed",
  "created_at": "2025-10-29T10:00:00Z",
  "completed_at": "2025-10-29T10:05:00Z",
  "transfers": [
    {
      "transfer_id": "...",
      "operation": "get",
      "source": "...",
      "destination": "...",
      "status": "completed",
      "bytes_transferred": 10485760,
      "total_bytes": 10485760
    }
  ]
}
```

#### Get Transfer Statistics
```
GET /stats?from=2025-10-01&to=2025-10-31

Response 200:
{
  "period": {
    "from": "2025-10-01T00:00:00Z",
    "to": "2025-10-31T23:59:59Z"
  },
  "total_jobs": 500,
  "completed_jobs": 485,
  "failed_jobs": 10,
  "cancelled_jobs": 5,
  "total_transfers": 1500,
  "completed_transfers": 1450,
  "failed_transfers": 40,
  "cancelled_transfers": 10,
  "total_bytes_transferred": 1099511627776,  // 1 TB
  "average_job_time_seconds": 135.6,
  "average_transfer_time_seconds": 45.2,
  "operations": {
    "get": 1000,
    "put": 300,
    "copy": 200
  }
}
```

#### Prune History
```
DELETE /history?older_than=2025-09-01

Response 200:
{
  "deleted_jobs": 125,
  "deleted_transfers": 500,
  "message": "Historical records older than 2025-09-01 deleted"
}
```

### Configuration

Add parameters:
```yaml
ClientAgent:
  Database:
    Path: ""  # Override default location ($HOME/.pelican/client-api.db)
    MaxConnections: 10

  History:
    RetentionDays: 90  # Auto-prune after 90 days
    MaxEntries: 10000  # Max history entries to keep

  Recovery:
    EnableAutoRecovery: true  # Resume transfers on startup
    MaxRecoveryAttempts: 3    # Max retry attempts for recovery
```

### Periodic Tasks

Implement background goroutines for:
1. **State Persistence**: Update database every 5 seconds with current job and transfer progress
2. **History Archival**: Move completed jobs (and their transfers) older than 24 hours to history tables
3. **History Pruning**: Delete history entries older than retention period (daily)
4. **Health Check**: Verify database integrity (weekly)

```go
func (s *APIServer) startBackgroundTasks() {
    // State persistence
    s.wg.Add(1)
    go func() {
        defer s.wg.Done()
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-s.ctx.Done():
                return
            case <-ticker.C:
                s.persistJobStates()
            }
        }
    }()

    // History archival
    s.wg.Add(1)
    go func() {
        defer s.wg.Done()
        ticker := time.NewTicker(1 * time.Hour)
        defer ticker.Stop()

        for {
            select {
            case <-s.ctx.Done():
                return
            case <-ticker.C:
                s.archiveCompletedJobs()
            }
        }
    }()

    // History pruning
    s.wg.Add(1)
    go func() {
        defer s.wg.Done()
        ticker := time.NewTicker(24 * time.Hour)
        defer ticker.Stop()

        for {
            select {
            case <-s.ctx.Done():
                return
            case <-ticker.C:
                s.pruneOldHistory()
            }
        }
    }()
}
```

### Testing

#### Crash Recovery Tests
```go
func TestJobRecovery(t *testing.T) {
    // Start server
    // Create job with multiple transfers
    // Kill server mid-execution
    // Restart server
    // Verify job and transfers resume and complete
}

func TestPartialJobRecovery(t *testing.T) {
    // Start job with multiple transfers
    // Kill server after some transfers complete
    // Restart server
    // Verify only incomplete transfers are re-executed
    // Verify job completes successfully
}
```

#### History Tests
```go
func TestJobHistory(t *testing.T) {
    // Create multiple jobs over time
    // Query history with various filters
    // Verify correct results including transfer details
}

func TestHistoryPruning(t *testing.T) {
    // Create old history entries (jobs and transfers)
    // Trigger pruning
    // Verify old entries removed, recent kept
    // Verify foreign key constraints maintained
}
```

---

## Implementation Timeline

### Phase 1: Stateless Server (4-6 weeks)
- Week 1-2: Core server infrastructure, socket handling, daemonization
- Week 2-3: REST API implementation (handlers, models)
- Week 3-4: Transfer manager and job execution
- Week 4-5: OpenAPI schema generation and documentation
- Week 5-6: Unit tests and bug fixes

### Phase 2: CLI Integration (3-4 weeks)
- Week 1-2: API client library and CLI integration
- Week 2-3: Progress reporting and error handling
- Week 3-4: Integration tests with federation

### Phase 3: Persistence (3-4 weeks)
- Week 1-2: Database schema and store implementation
- Week 2-3: Resume logic and recovery
- Week 3-4: History APIs and background tasks
- Week 4: Testing and documentation

**Total Estimated Timeline: 10-14 weeks**

---

## Security Considerations

### Phase 1
- Unix socket permissions restrict access to socket owner
- No network exposure (local-only)
- Input validation on all API endpoints
- Rate limiting on endpoints

### Phase 2
- Secure token handling (never log tokens)
- Environment variable support for tokens
- Token file permissions validation (must be readable only by owner)

### Phase 3
- Database encryption at rest (optional)
- Secure credential storage using OS keychain (future)
- Audit logging of all operations

---

## Monitoring and Observability

### Metrics
Expose Prometheus metrics at `/metrics`:
- Job counts by status
- Transfer counts by operation and status
- Job duration histograms
- Transfer duration histograms
- Bytes transferred
- Active jobs gauge
- Active transfers gauge
- API request counts and latencies

### Logging
- Structured JSON logging
- Separate log file for agent server
- Rotation and retention policies
- Debug mode for troubleshooting

### Health Checks
- `/health` endpoint for monitoring
- Include database connectivity check
- Include transfer manager status
- Include job queue status

---

## Future Enhancements

### Phase 4+ (Not in Initial Scope)
1. **Authentication and Multi-User Support**
   - JWT-based authentication
   - User isolation (separate databases per user)
   - Role-based access control

2. **Advanced Transfer Features**
   - Job priorities and scheduling
   - Bandwidth throttling per job or transfer
   - Automatic retry with exponential backoff
   - Job dependencies (start job B after job A completes)
   - Batch job submission with templating

3. **Web UI**
   - Browser-based job and transfer monitoring
   - Real-time progress updates (WebSockets)
   - Job management interface
   - Transfer history visualization

4. **Notifications**
   - Email/webhook notifications on completion/failure
   - Slack/Discord integrations

5. **Performance Optimizations**
   - Job deduplication
   - Parallel chunk transfers
   - Client-side caching
   - Transfer bundling for small files

6. **Enhanced Observability**
   - Distributed tracing (OpenTelemetry)
   - Grafana dashboards
   - Alerting rules

---

## Alternatives Considered

### Alternative 1: gRPC API
**Pros:**
- Better performance (binary protocol)
- Built-in code generation for multiple languages
- Streaming support

**Cons:**
- More complex for simple HTTP clients
- Harder to debug (binary protocol)
- RESTful API is more familiar and widely supported

**Decision:** RESTful API chosen for simplicity and accessibility

### Alternative 2: Embedded Database (BoltDB)
**Pros:**
- Pure Go implementation
- Simple key-value interface

**Cons:**
- Less SQL query flexibility
- Smaller ecosystem
- SQLite is already a dependency in Pelican

**Decision:** SQLite chosen for consistency and SQL query capabilities

### Alternative 3: Stateful Server from Phase 1
**Pros:**
- Simpler implementation path (no need for two phases)

**Cons:**
- Increased complexity for initial implementation
- Harder to test and debug
- Database adds operational overhead

**Decision:** Phased approach allows incremental value delivery and testing

---

## Open Questions

1. **Transfer Resume Granularity**: Should we support byte-level resume (like HTTP range requests) or file-level resume for multi-file transfers?
   - **Recommendation**: Start with file-level resume, add byte-level in future

2. **Maximum Concurrent Jobs**: What should be the default limit?
   - **Recommendation**: Start with 10 concurrent jobs, make configurable

3. **Maximum Transfers Per Job**: Should there be a limit?
   - **Recommendation**: Start with 1000 transfers per job, make configurable

4. **Job Timeout**: Should jobs have overall timeouts independent of individual transfers?
   - **Recommendation**: Yes, default to 24 hours, configurable per job

5. **Socket Buffer Size**: What buffer size for Unix socket?
   - **Recommendation**: Use OS defaults, tune if performance issues arise

6. **History Retention**: Should we support external archival (S3, etc.)?
   - **Recommendation**: Not in initial phases, could be future enhancement

7. **Partial Job Cancellation**: Should users be able to cancel individual transfers within a job?
   - **Recommendation**: Phase 1: cancel entire job only. Phase 4+: add selective transfer cancellation

---

## References

- [Pelican Documentation](https://docs.pelicanplatform.org/)
- [OpenAPI Specification](https://swagger.io/specification/)
- [Unix Domain Sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [Gin Web Framework](https://gin-gonic.com/docs/)
- [Go Daemon Package](https://github.com/sevlyar/go-daemon)

---

## Appendix A: Example Client Usage

### cURL Examples

```bash
# Check server health
curl --unix-socket ~/.pelican/client-api.sock \
     http://localhost/api/v1/xfer/health

# Create a job with a single transfer (download)
curl --unix-socket ~/.pelican/client-api.sock \
     -X POST http://localhost/api/v1/xfer/jobs \
     -H "Content-Type: application/json" \
     -d '{
       "transfers": [
         {
           "operation": "get",
           "source": "pelican://osg-htc.org/ospool/path/to/file",
           "destination": "/tmp/file",
           "recursive": false
         }
       ]
     }'

# Create a job with multiple transfers
curl --unix-socket ~/.pelican/client-api.sock \
     -X POST http://localhost/api/v1/xfer/jobs \
     -H "Content-Type: application/json" \
     -d '{
       "transfers": [
         {
           "operation": "get",
           "source": "pelican://osg-htc.org/ospool/file1.txt",
           "destination": "/tmp/file1.txt"
         },
         {
           "operation": "get",
           "source": "pelican://osg-htc.org/ospool/file2.txt",
           "destination": "/tmp/file2.txt"
         }
       ],
       "options": {
         "caches": ["cache1.example.com"]
       }
     }'

# Check job status
curl --unix-socket ~/.pelican/client-api.sock \
     http://localhost/api/v1/xfer/jobs/550e8400-e29b-41d4-a716-446655440000

# Check individual transfer status within a job
curl --unix-socket ~/.pelican/client-api.sock \
     http://localhost/api/v1/xfer/jobs/550e8400-e29b-41d4-a716-446655440000/transfers/650e8400-e29b-41d4-a716-446655440001

# List all active jobs
curl --unix-socket ~/.pelican/client-api.sock \
     http://localhost/api/v1/xfer/jobs?status=running

# Cancel a job (cancels all incomplete transfers)
curl --unix-socket ~/.pelican/client-api.sock \
     -X DELETE http://localhost/api/v1/xfer/jobs/550e8400-e29b-41d4-a716-446655440000

# Get job history
curl --unix-socket ~/.pelican/client-api.sock \
     http://localhost/api/v1/xfer/history?limit=10
```

### Python Client Example

```python
import requests
import time
import os
from requests_unixsocket import Session

class PelicanAPIClient:
    def __init__(self, socket_path="~/.pelican/client-api.sock"):
        self.socket_path = socket_path.replace("~", os.path.expanduser("~"))
        self.session = Session()
        self.base_url = f"http+unix://{self.socket_path.replace('/', '%2F')}/api/v1/xfer"

    def create_job(self, transfers, options=None):
        """Create a transfer job with one or more transfers"""
        response = self.session.post(
            f"{self.base_url}/jobs",
            json={
                "transfers": transfers,
                "options": options or {}
            }
        )
        response.raise_for_status()
        return response.json()

    def get_job_status(self, job_id):
        """Get status of a job"""
        response = self.session.get(f"{self.base_url}/jobs/{job_id}")
        response.raise_for_status()
        return response.json()

    def wait_for_job(self, job_id, timeout=300, poll_interval=1):
        """Wait for a job to complete"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_job_status(job_id)

            if status["status"] == "completed":
                return status
            elif status["status"] == "failed":
                # Collect failed transfer details
                failed = [t for t in status["transfers"] if t["status"] == "failed"]
                errors = [f"{t['source']}: {t['error']}" for t in failed]
                raise Exception(f"Job failed: {'; '.join(errors)}")
            elif status["status"] == "cancelled":
                raise Exception("Job was cancelled")

            time.sleep(poll_interval)

        raise TimeoutError(f"Job {job_id} did not complete within {timeout} seconds")

    def cancel_job(self, job_id):
        """Cancel a job and all its incomplete transfers"""
        response = self.session.delete(f"{self.base_url}/jobs/{job_id}")
        response.raise_for_status()
        return response.json()

    def get(self, source, destination, recursive=False, token=None, wait=True):
        """Download a file from Pelican federation"""
        job_resp = self.create_job(
            transfers=[{
                "operation": "get",
                "source": source,
                "destination": destination,
                "recursive": recursive
            }],
            options={"token": token} if token else None
        )

        job_id = job_resp["job_id"]

        if wait:
            return self.wait_for_job(job_id)
        return job_resp

    def put(self, source, destination, recursive=False, token=None, wait=True):
        """Upload a file to Pelican federation"""
        job_resp = self.create_job(
            transfers=[{
                "operation": "put",
                "source": source,
                "destination": destination,
                "recursive": recursive
            }],
            options={"token": token} if token else None
        )

        job_id = job_resp["job_id"]

        if wait:
            return self.wait_for_job(job_id)
        return job_resp

    def batch_get(self, file_pairs, token=None, wait=True):
        """Download multiple files in a single job"""
        transfers = [
            {
                "operation": "get",
                "source": src,
                "destination": dst,
                "recursive": False
            }
            for src, dst in file_pairs
        ]

        job_resp = self.create_job(
            transfers=transfers,
            options={"token": token} if token else None
        )

        job_id = job_resp["job_id"]

        if wait:
            return self.wait_for_job(job_id)
        return job_resp

    def list_history(self, limit=100, status=None):
        """Get job history"""
        params = {"limit": limit}
        if status:
            params["status"] = status

        response = self.session.get(
            f"{self.base_url}/history",
            params=params
        )
        response.raise_for_status()
        return response.json()

# Usage examples

# Single file download
client = PelicanAPIClient()
result = client.get(
    source="pelican://osg-htc.org/ospool/path/to/file",
    destination="/tmp/downloaded_file"
)
print(f"Downloaded {result['transfers'][0]['bytes_transferred']} bytes")

# Batch download
file_pairs = [
    ("pelican://osg-htc.org/ospool/file1.txt", "/tmp/file1.txt"),
    ("pelican://osg-htc.org/ospool/file2.txt", "/tmp/file2.txt"),
    ("pelican://osg-htc.org/ospool/file3.txt", "/tmp/file3.txt"),
]
result = client.batch_get(file_pairs)
print(f"Batch job completed: {result['progress']['transfers_completed']}/{result['progress']['transfers_total']} transfers")

# Async job submission
job = client.get(
    source="pelican://osg-htc.org/ospool/large/file",
    destination="/tmp/large_file",
    wait=False
)
print(f"Job {job['job_id']} started")

# Poll for progress
while True:
    status = client.get_job_status(job['job_id'])
    if status['status'] in ['completed', 'failed', 'cancelled']:
        break
    print(f"Progress: {status['progress']['percentage']:.1f}%")
    time.sleep(2)

# View history
history = client.list_history(limit=10, status="completed")
for job in history["jobs"]:
    print(f"Job {job['job_id']}: {job['transfers_completed']} transfers, {job['bytes_transferred']} bytes")
```

---

## Appendix B: OpenAPI Schema (Excerpt)

```yaml
openapi: 3.0.0
info:
  title: Pelican Client Agent
  description: RESTful API for Pelican data transfer operations
  version: 1.0.0
  contact:
    name: Pelican Platform
    url: https://pelicanplatform.org

servers:
  - url: /api/v1/xfer
    description: Unix socket server

paths:
  /health:
    get:
      summary: Health check
      tags: [system]
      responses:
        '200':
          description: Server is healthy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'

  /jobs:
    post:
      summary: Create a transfer job
      tags: [jobs]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/JobRequest'
      responses:
        '202':
          description: Job accepted
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobResponse'
        '400':
          description: Invalid request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

    get:
      summary: List jobs
      tags: [jobs]
      parameters:
        - name: status
          in: query
          schema:
            type: string
            enum: [pending, running, completed, failed, cancelled]
        - name: limit
          in: query
          schema:
            type: integer
            default: 50
            maximum: 500
        - name: offset
          in: query
          schema:
            type: integer
            default: 0
      responses:
        '200':
          description: List of jobs
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobList'

  /jobs/{job_id}:
    get:
      summary: Get job status
      tags: [jobs]
      parameters:
        - name: job_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Job status with all transfers
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JobStatus'
        '404':
          description: Job not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

    delete:
      summary: Cancel job
      tags: [jobs]
      parameters:
        - name: job_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Job cancelled
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CancelResponse'
        '404':
          description: Job not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /jobs/{job_id}/transfers/{transfer_id}:
    get:
      summary: Get individual transfer status
      tags: [transfers]
      parameters:
        - name: job_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
        - name: transfer_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Transfer status
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TransferStatus'
        '404':
          description: Transfer not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

components:
  schemas:
    JobRequest:
      type: object
      required:
        - transfers
      properties:
        transfers:
          type: array
          minItems: 1
          items:
            $ref: '#/components/schemas/TransferRequest'
        options:
          $ref: '#/components/schemas/TransferOptions'

    TransferRequest:
      type: object
      required:
        - operation
        - source
        - destination
      properties:
        operation:
          type: string
          enum: [get, put, copy]
        source:
          type: string
          description: Source URL or file path
        destination:
          type: string
          description: Destination URL or file path
        recursive:
          type: boolean
          default: false

    TransferOptions:
      type: object
      properties:
        token:
          type: string
          description: Authentication token file path
        caches:
          type: array
          items:
            type: string
          description: Preferred cache servers
        methods:
          type: array
          items:
            type: string
          description: Transfer methods (http, https)
        pack_option:
          type: string
          enum: [auto, tar, tar.gz, tar.xz, zip]

    JobResponse:
      type: object
      properties:
        job_id:
          type: string
          format: uuid
        status:
          type: string
          enum: [pending, running, completed, failed, cancelled]
        created_at:
          type: string
          format: date-time
        transfers:
          type: array
          items:
            $ref: '#/components/schemas/TransferResponse'

    TransferResponse:
      type: object
      properties:
        transfer_id:
          type: string
          format: uuid
        operation:
          type: string
        source:
          type: string
        destination:
          type: string
        status:
          type: string

    JobStatus:
      type: object
      properties:
        job_id:
          type: string
          format: uuid
        status:
          type: string
          enum: [pending, running, completed, failed, cancelled]
        created_at:
          type: string
          format: date-time
        started_at:
          type: string
          format: date-time
          nullable: true
        completed_at:
          type: string
          format: date-time
          nullable: true
        progress:
          $ref: '#/components/schemas/JobProgress'
        transfers:
          type: array
          items:
            $ref: '#/components/schemas/TransferStatus'
        error:
          type: string
          nullable: true

    JobProgress:
      type: object
      properties:
        bytes_transferred:
          type: integer
          format: int64
        total_bytes:
          type: integer
          format: int64
        percentage:
          type: number
          format: double
        transfer_rate_mbps:
          type: number
          format: double
        transfers_completed:
          type: integer
        transfers_total:
          type: integer
        transfers_failed:
          type: integer

    TransferStatus:
      type: object
      properties:
        transfer_id:
          type: string
          format: uuid
        job_id:
          type: string
          format: uuid
        operation:
          type: string
        source:
          type: string
        destination:
          type: string
        status:
          type: string
          enum: [pending, running, completed, failed, cancelled]
        created_at:
          type: string
          format: date-time
        started_at:
          type: string
          format: date-time
          nullable: true
        completed_at:
          type: string
          format: date-time
          nullable: true
        bytes_transferred:
          type: integer
          format: int64
        total_bytes:
          type: integer
          format: int64
        transfer_rate_mbps:
          type: number
          format: double
        error:
          type: string
          nullable: true

    CancelResponse:
      type: object
      properties:
        job_id:
          type: string
          format: uuid
        status:
          type: string
        message:
          type: string
        transfers_cancelled:
          type: integer
        transfers_completed:
          type: integer

    HealthResponse:
      type: object
      properties:
        status:
          type: string
        version:
          type: string
        uptime_seconds:
          type: integer

    ErrorResponse:
      type: object
      properties:
        error:
          type: string
        code:
          type: string
```

---

**End of Design Document**
