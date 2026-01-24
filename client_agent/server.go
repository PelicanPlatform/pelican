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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

const (
	DefaultSocketPath      = "~/.pelican/client-api.sock"
	DefaultPidFile         = "~/.pelican/client-api.pid"
	DefaultShutdownTimeout = 30 * time.Second
)

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
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	mu              sync.Mutex
	started         bool
}

// ServerConfig holds configuration for the server
type ServerConfig struct {
	SocketPath        string
	PidFile           string
	MaxConcurrentJobs int
	DatabasePath      string
}

// NewServer creates a new client API server
func NewServer(config ServerConfig) (*Server, error) {
	// Expand home directory in paths
	socketPath, err := ExpandPath(config.SocketPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to expand socket path")
	}

	pidFile, err := ExpandPath(config.PidFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to expand pid file path")
	}

	// Ensure socket directory exists with secure permissions (0700)
	// This must be done before socket creation to prevent race conditions
	socketDir := filepath.Dir(socketPath)
	socketDirRoot, err := ensureSecureDirectory(socketDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ensure secure socket directory")
	}
	socketDirRoot.Close() // We don't need to keep this open for sockets

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize database store
	var storeInstance StoreInterface
	dbPath := config.DatabasePath
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
			cancel()
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
	transferManager := NewTransferManager(ctx, maxJobs, storeInstance)

	// Set up Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Add middleware
	router.Use(LoggerMiddleware())
	router.Use(RecoveryMiddleware())

	server := &Server{
		socketPath:      socketPath,
		pidFile:         pidFile,
		router:          router,
		transferManager: transferManager,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Set up routes
	server.setupRoutes()

	return server, nil
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	api := s.router.Group("/api/v1/xfer")
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
	}
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
	pidLockFd, err := acquireServerLock(s.pidFile, 2*time.Second)
	if err != nil {
		return err
	}
	s.pidLockFd = pidLockFd

	// Remove existing socket if it exists
	if err := removeSocket(s.socketPath); err != nil {
		s.pidLockFd.Close()
		return errors.Wrap(err, "failed to remove existing socket")
	}

	// Create Unix listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		s.pidLockFd.Close()
		return errors.Wrap(err, "failed to create Unix listener")
	}

	// Set socket permissions
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		listener.Close()
		s.pidLockFd.Close()
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
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Infof("Starting client API server on %s", s.socketPath)
		if err := s.httpServer.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			log.Errorf("Server error: %v", err)
		}
	}()

	s.started = true
	log.Info("Client API server started successfully")

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return errors.New("server not started")
	}
	s.mu.Unlock()

	log.Info("Shutting down client API server...")

	// Cancel context
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
	s.wg.Wait()

	// Clean up socket and PID file
	s.cleanup()

	s.mu.Lock()
	s.started = false
	s.mu.Unlock()

	log.Info("Client API server shutdown complete")
	return nil
}

// Wait blocks until the server is shut down
func (s *Server) Wait() {
	s.wg.Wait()
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

// ExpandPath expands ~ to home directory
func ExpandPath(path string) (string, error) {
	if len(path) == 0 {
		return path, nil
	}

	if path[0] != '~' {
		return path, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "failed to get home directory")
	}

	if len(path) == 1 {
		return homeDir, nil
	}

	return filepath.Join(homeDir, path[1:]), nil
}

// CheckServerRunning checks if a server is already running at the socket path
func CheckServerRunning(socketPath string) (bool, error) {
	expandedPath, err := ExpandPath(socketPath)
	if err != nil {
		return false, err
	}

	// Check if socket exists
	if _, err := os.Stat(expandedPath); os.IsNotExist(err) {
		return false, nil
	}

	// Try to connect to the socket
	conn, err := net.DialTimeout("unix", expandedPath, 1*time.Second)
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
