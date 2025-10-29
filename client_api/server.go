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

package client_api

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
)

const (
	DefaultSocketPath        = "~/.pelican/client-api.sock"
	DefaultPidFile           = "~/.pelican/client-api.pid"
	DefaultMaxConcurrentJobs = 5
	DefaultShutdownTimeout   = 30 * time.Second
)

// Server represents the client API server
type Server struct {
	socketPath      string
	pidFile         string
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
}

// NewServer creates a new client API server
func NewServer(config ServerConfig) (*Server, error) {
	// Expand home directory in paths
	socketPath, err := expandPath(config.SocketPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to expand socket path")
	}

	pidFile, err := expandPath(config.PidFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to expand pid file path")
	}

	// Ensure directory exists
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return nil, errors.Wrap(err, "failed to create socket directory")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create transfer manager
	maxJobs := config.MaxConcurrentJobs
	if maxJobs <= 0 {
		maxJobs = DefaultMaxConcurrentJobs
	}
	transferManager := NewTransferManager(ctx, maxJobs)

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

// Start starts the server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return errors.New("server already started")
	}

	// Remove existing socket if it exists
	if err := removeSocket(s.socketPath); err != nil {
		return errors.Wrap(err, "failed to remove existing socket")
	}

	// Create Unix listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return errors.Wrap(err, "failed to create Unix listener")
	}

	// Set socket permissions
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		listener.Close()
		return errors.Wrap(err, "failed to set socket permissions")
	}

	s.listener = listener

	// Write PID file
	if err := s.writePidFile(); err != nil {
		listener.Close()
		return errors.Wrap(err, "failed to write PID file")
	}

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

// writePidFile writes the current process ID to the PID file
func (s *Server) writePidFile() error {
	pidDir := filepath.Dir(s.pidFile)
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		return errors.Wrap(err, "failed to create PID directory")
	}

	pid := os.Getpid()
	return os.WriteFile(s.pidFile, []byte(fmt.Sprintf("%d", pid)), 0644)
}

// cleanup removes the socket and PID file
func (s *Server) cleanup() {
	if err := removeSocket(s.socketPath); err != nil {
		log.Warnf("Failed to remove socket: %v", err)
	}

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

// expandPath expands ~ to home directory
func expandPath(path string) (string, error) {
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
	expandedPath, err := expandPath(socketPath)
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

// ReadPidFile reads the PID from the PID file
func ReadPidFile(pidFile string) (int, error) {
	expandedPath, err := expandPath(pidFile)
	if err != nil {
		return 0, err
	}

	data, err := os.ReadFile(expandedPath)
	if err != nil {
		return 0, err
	}

	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		return 0, errors.Wrap(err, "failed to parse PID")
	}

	return pid, nil
}
