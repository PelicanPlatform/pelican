/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package client_agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	pelican_config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

const (
	DefaultShutdownTimeout = 30 * time.Second
)

// GetDefaultSocketPath returns the default socket path with home directory expanded
func GetDefaultSocketPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "failed to get home directory")
	}
	return filepath.Join(homeDir, ".pelican", "client-agent.sock"), nil
}

// GetDefaultPidFile returns the default PID file path with home directory expanded
func GetDefaultPidFile() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "failed to get home directory")
	}
	return filepath.Join(homeDir, ".pelican", "client-agent.pid"), nil
}

// Server represents the client API server
type Server struct {
	socketPath      string
	pidFile         string
	pidLockFd       *os.File // Held open for the lifetime of the server (flock on Unix)
	listener        net.Listener
	httpServer      *http.Server
	router          *gin.Engine
	transferManager *TransferManager
	ctx             context.Context
	cancel          context.CancelFunc // Cancels server's internal context to signal shutdown
	eg              *errgroup.Group
	mu              sync.Mutex
	started         bool
	lastActivity    time.Time
	idleTimeout     time.Duration
	activityMu      sync.Mutex
}

// ServerConfig holds configuration for the server
type ServerConfig struct {
	SocketPath        string
	PidFile           string
	MaxConcurrentJobs int
	DbLocation        string
	IdleTimeout       time.Duration
}

// NewServer creates a new client API server
func NewServer(ctx context.Context, config ServerConfig) (*Server, error) {
	// Extract errgroup from context
	eg, ok := ctx.Value(pelican_config.EgrpKey).(*errgroup.Group)
	if !ok || eg == nil {
		// No errgroup provided, create one
		eg, ctx = errgroup.WithContext(ctx)
		ctx = context.WithValue(ctx, pelican_config.EgrpKey, eg)
	}

	socketPath := config.SocketPath
	pidFile := config.PidFile

	// Ensure socket directory exists with secure permissions (0700)
	// This must be done before socket creation to prevent race conditions
	socketDir := filepath.Dir(socketPath)
	socketDirRoot, err := ensureSecureDirectory(socketDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ensure secure socket directory")
	}
	socketDirRoot.Close() // We don't need to keep this open for sockets

	// Initialize database store
	var storeInstance StoreInterface
	dbPath := config.DbLocation
	if dbPath == "" {
		// Default to ~/.pelican/client-api.db
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Warnf("Failed to get home directory, database will not be initialized: %v", err)
		} else {
			dbPath = filepath.Join(homeDir, ".pelican", "client-api.db")
			dbDir := filepath.Dir(dbPath)
			dbDirRoot, err := ensureSecureDirectory(dbDir)
			if err != nil {
				log.Warnf("Failed to create secure database directory, database will not be initialized: %v", err)
				dbPath = ""
			} else {
				dbDirRoot.Close() // We don't need to keep this open for database
			}
		}
	}

	if dbPath != "" {
		// Verify database directory security before initializing
		dbDir := filepath.Dir(dbPath)
		dbDirRoot, err := ensureSecureDirectory(dbDir)
		if err != nil {
			return nil, errors.Wrapf(err, "database directory %s failed security check", dbDir)
		}
		dbDirRoot.Close() // We don't need to keep this open for database

		// Import is done via interface, actual store creation happens in a separate package
		log.Infof("Initializing database at %s", dbPath)
		// Note: Store initialization will be handled by importing client_api/store
		// and calling store.NewStore(dbPath) in the caller of NewServer
		// For now, we'll pass nil and the store can be set later via a method
	}

	// Create transfer manager
	// Use config value if provided, otherwise fall back to parameter
	maxJobs := config.MaxConcurrentJobs
	if maxJobs <= 0 {
		providedValue := maxJobs
		maxJobs = param.ClientAgent_MaxConcurrentJobs.GetInt()
		if maxJobs <= 0 {
			log.Warnf("Invalid max concurrent jobs configuration (provided=%d, param=%d), using default value of 5", providedValue, maxJobs)
			maxJobs = 5 // Final fallback
		}
	}
	// Create server's own cancellable context for internal goroutines
	// This is a child of the passed-in context, allowing clean shutdown
	serverCtx, cancel := context.WithCancel(ctx)

	transferManager := NewTransferManager(serverCtx, maxJobs, storeInstance)

	// Set up Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	server := &Server{
		socketPath:      socketPath,
		pidFile:         pidFile,
		router:          router,
		transferManager: transferManager,
		ctx:             serverCtx,
		cancel:          cancel,
		eg:              eg,
		lastActivity:    time.Now(),
		idleTimeout:     config.IdleTimeout,
	}

	// Add middleware that has access to server instance
	router.Use(func(c *gin.Context) {
		c.Set("server", server)
		c.Next()
	})
	router.Use(LoggerMiddleware())
	router.Use(RecoveryMiddleware())

	// Set up routes
	server.setupRoutes()

	return server, nil
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	api := s.router.Group("/api/v1.0/transfer-agent")
	{
		// Job management
		api.POST("/jobs", s.CreateJobHandler)
		api.GET("/jobs", s.ListJobsHandler)
		api.GET("/jobs/:job_id", s.GetJobStatusHandler)
		api.DELETE("/jobs/:job_id", s.CancelJobHandler)

		// History management
		api.GET("/history", s.GetJobHistoryHandler)
		api.DELETE("/history/:job_id", s.DeleteJobHistoryHandler)
		api.DELETE("/history", s.DeleteJobHistoryHandler)

		// File operations
		api.POST("/stat", s.StatHandler)
		api.POST("/list", s.ListHandler)
		api.POST("/delete", s.DeleteHandler)
	}

	// Health check
	s.router.GET("/health", s.HealthHandler)

	// Shutdown
	s.router.POST("/shutdown", s.ShutdownHandler)
}

// SetStore sets the persistent storage interface for the server
// This allows the store to be initialized separately to avoid import cycles
func (s *Server) SetStore(store StoreInterface) {
	s.transferManager.store = store
	if store != nil {
		log.Info("Database store configured for transfer manager")
		// Start background tasks if they weren't started during initialization
		// (this happens when store is set after NewTransferManager is called)
		// The startBackgroundTasks function is protected by sync.Once so it's safe to call multiple times
		s.transferManager.startBackgroundTasks()
	}
}

// SetInheritedLock sets a lock that was inherited from a parent process
// This is used when running as a daemon spawned by another process
func (s *Server) SetInheritedLock(lock *os.File) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return errors.New("cannot set inherited lock on running server")
	}

	s.pidLockFd = lock

	// Update the PID file with our PID (child's PID, not parent's)
	if err := lock.Truncate(0); err != nil {
		log.Warnf("Failed to truncate PID file: %v", err)
	}
	if _, err := lock.Seek(0, 0); err != nil {
		log.Warnf("Failed to seek PID file: %v", err)
	}
	if _, err := lock.WriteString(fmt.Sprintf("%d", os.Getpid())); err != nil {
		log.Warnf("Failed to write PID to PID file: %v", err)
	}

	log.Infof("Inherited server lock from parent process (PID: %d)", os.Getpid())
	return nil
}

// Start starts the server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return errors.New("server already started")
	}

	// Acquire exclusive lock BEFORE creating socket to prevent race conditions
	// This also prevents starting if another instance is running
	// Skip if we already have an inherited lock
	if s.pidLockFd == nil {
		pidLockFd, err := acquireServerLock(s.pidFile, 2*time.Second)
		if err != nil {
			return err
		}
		s.pidLockFd = pidLockFd
	} else {
		log.Info("Using inherited lock, skipping lock acquisition")
	}

	// Remove existing socket if it exists
	if err := removeSocket(s.socketPath); err != nil {
		if s.pidLockFd != nil {
			s.pidLockFd.Close()
		}
		return errors.Wrap(err, "failed to remove existing socket")
	}

	// Create Unix listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		if s.pidLockFd != nil {
			s.pidLockFd.Close()
		}
		return errors.Wrap(err, "failed to create Unix listener")
	}

	// Set socket permissions
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		listener.Close()
		if s.pidLockFd != nil {
			s.pidLockFd.Close()
		}
		return errors.Wrap(err, "failed to set socket permissions")
	}

	s.listener = listener

	// Create HTTP server
	s.httpServer = &http.Server{
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start serving
	s.eg.Go(func() error {
		log.Infof("Starting client API server on %s", s.socketPath)
		if err := s.httpServer.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			log.Errorf("Server error: %v", err)
			return err
		}
		return nil
	})

	s.started = true
	log.Infof("Client API server started successfully (PID: %d, Socket: %s, IdleTimeout: %v)", os.Getpid(), s.socketPath, s.idleTimeout)

	// Start idle timeout monitor if configured
	if s.idleTimeout > 0 {
		log.Infof("Starting idle timeout monitor with timeout: %v", s.idleTimeout)
		s.eg.Go(func() error {
			return s.monitorIdleTimeout()
		})
	} else {
		log.Info("Idle timeout monitoring disabled (timeout not set)")
	}

	return nil
}

// UpdateActivity records activity on the server
func (s *Server) UpdateActivity() {
	s.activityMu.Lock()
	s.lastActivity = time.Now()
	s.activityMu.Unlock()
}

// monitorIdleTimeout monitors for idle timeout and shuts down if necessary
func (s *Server) monitorIdleTimeout() error {
	// Check frequently to ensure timely shutdown (every 1 second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Infof("Idle timeout monitor started (timeout: %v, check interval: 1s)", s.idleTimeout)

	for {
		select {
		case <-s.ctx.Done():
			log.Info("Idle timeout monitor stopping due to context cancellation")
			return nil
		case <-ticker.C:
			s.activityMu.Lock()
			lastActivity := s.lastActivity
			s.activityMu.Unlock()

			// Check if there are active jobs
			hasActiveJobs := s.transferManager.HasActiveJobs()
			if hasActiveJobs {
				// Update activity since there are active jobs
				s.UpdateActivity()
				continue
			}

			idleTime := time.Since(lastActivity)
			if idleTime > s.idleTimeout {
				log.Infof("Server idle for %v (timeout: %v), initiating shutdown...", idleTime, s.idleTimeout)
				// Trigger shutdown asynchronously to avoid deadlock - shutdown blocks
				// on all goroutines including this one.
				go func() {
					if err := s.Shutdown(); err != nil {
						log.Errorf("Auto-shutdown error: %v", err)
					} else {
						log.Info("Auto-shutdown completed successfully")
					}
				}()
				return nil
			}
		}
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	log.Info("Shutdown requested")
	s.mu.Lock()
	if !s.started {
		log.Warn("Shutdown called but server not started")
		s.mu.Unlock()
		return errors.New("server not started")
	}
	s.mu.Unlock()

	log.Info("Shutting down client API server...")

	// Signal shutdown to background goroutines (idle monitor, etc.)
	s.cancel()

	// Shutdown transfer manager
	if err := s.transferManager.Shutdown(); err != nil {
		log.Warnf("Transfer manager shutdown error: %v", err)
	}

	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), DefaultShutdownTimeout)
	defer shutdownCancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		log.Warnf("HTTP server shutdown error: %v", err)
	}

	// Wait for goroutines
	if err := s.eg.Wait(); err != nil && err != context.Canceled {
		log.Warnf("Background task error during shutdown: %v", err)
	}

	// Clean up socket and PID file
	s.cleanup()

	s.mu.Lock()
	s.started = false
	s.mu.Unlock()

	log.Info("Client API server shutdown complete")
	return nil
}

// Wait blocks until the server is shut down
func (s *Server) Wait() error {
	return s.eg.Wait()
}

// cleanup removes the socket, PID file, and releases the lock
func (s *Server) cleanup() {
	if err := removeSocket(s.socketPath); err != nil {
		log.Warnf("Failed to remove socket: %v", err)
	}

	// Release PID file lock (this automatically releases the flock on Unix)
	if s.pidLockFd != nil {
		s.pidLockFd.Close()
		s.pidLockFd = nil
	}

	// Remove PID file
	if err := os.Remove(s.pidFile); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove PID file: %v", err)
	}
}

// GetSocketPath returns the socket path
func (s *Server) GetSocketPath() string {
	return s.socketPath
}

// GetPidFile returns the PID file path
func (s *Server) GetPidFile() string {
	return s.pidFile
}

// IsRunning checks if the server is running
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// removeSocket removes a Unix socket file if it exists
func removeSocket(path string) error {
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return errors.Wrap(err, "failed to remove socket")
		}
	} else if !os.IsNotExist(err) {
		return errors.Wrap(err, "failed to stat socket")
	}
	return nil
}

// CheckServerRunning checks if a server is already running at the socket path
func CheckServerRunning(socketPath string) (bool, error) {

	// Check if socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return false, nil
	}

	// Try to connect to the socket
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		// Socket exists but can't connect - probably stale
		return false, nil
	}
	conn.Close()

	return true, nil
}

// GetServerPID returns the PID of the server holding the lock on the PID file, or 0 if no server is running
// On Unix, this queries the flock holder via fcntl F_GETLK
// On Windows, this reads the PID from the file (may be stale after reboot)
func GetServerPID(pidFile string) (int, error) {
	return getServerPIDFromLock(pidFile)
}

// ensureSecureDirectory ensures a directory exists with secure permissions (0700) and correct ownership.
// This must be called before creating sockets or database files to prevent race conditions and security vulnerabilities.
// The directory is opened as a Root first, then all checks are performed through the Root to prevent TOCTOU attacks.
func ensureSecureDirectory(path string) (*os.Root, error) {
	// First check if directory exists, create if not
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create with secure permissions
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, errors.Wrap(err, "failed to create directory")
		}
	}

	// Open the Root filesystem FIRST, before doing any checks
	// This prevents TOCTOU between checking and using
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open root directory")
	}

	// Now perform all checks through the opened Root
	// Stat "." within the Root to get info about the directory itself
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, errors.Wrap(err, "failed to stat directory")
	}

	if !info.IsDir() {
		root.Close()
		return nil, errors.New("path exists but is not a directory")
	}

	// Check ownership first - must be owned by current user
	// (We can't fix ownership without root, so check this before trying to fix permissions)
	currentUID := os.Getuid()
	if err := verifyOwnership(info, currentUID); err != nil {
		root.Close()
		return nil, err
	}

	// Check permissions - must be 0700 (owner only)
	perm := info.Mode().Perm()
	if perm != 0700 {
		log.Warningf("Directory %s has insecure permissions %o, fixing to 0700", path, perm)
		// Fix permissions through the Root to be safe
		if err := root.Chmod(".", 0700); err != nil {
			root.Close()
			return nil, errors.Wrapf(err, "failed to fix permissions (has %o, need 0700)", perm)
		}
	}

	// All checks passed, return the opened and verified Root
	return root, nil
}
