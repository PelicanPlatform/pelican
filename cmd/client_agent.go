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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/client_agent/store"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

var (
	clientAgentSocketPath string
	clientAgentPidFile    string
	clientAgentMaxJobs    int
	clientAgentDbPath     string
	clientAgentDaemonMode bool
	clientAgentForeground bool
)

// initializeStore creates a new database store instance
func initializeStore(dbPath string) (client_agent.StoreInterface, error) {
	return store.NewStore(dbPath)
}

var clientAgentCmd = &cobra.Command{
	Use:   "client-agent",
	Short: "Manage the Pelican client agent server",
	Long: `The client-agent server provides a RESTful API for interacting with
the Pelican client functionality over a Unix domain socket. This enables
external applications to use Pelican transfer capabilities without directly
invoking the CLI.`,
}

var clientAgentServeCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the client agent server",
	Long: `Start the client agent server as a daemon process. The server will listen
on a Unix domain socket and handle job-based transfer requests.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize config
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "Failed to initialize Pelican client")
		}

		// Use parameter socket path if set, otherwise use flag value, otherwise use default
		if socketParam := param.ClientAgent_Socket.GetString(); socketParam != "" {
			clientAgentSocketPath = socketParam
		} else if clientAgentSocketPath == "" {
			defaultPath, err := client_agent.GetDefaultSocketPath()
			if err != nil {
				return errors.Wrap(err, "Failed to get default socket path")
			}
			clientAgentSocketPath = defaultPath
		}

		// Use parameter PID file path if set, otherwise use flag value, otherwise use default
		if pidFileParam := param.ClientAgent_PidFile.GetString(); pidFileParam != "" {
			clientAgentPidFile = pidFileParam
		} else if clientAgentPidFile == "" {
			defaultPath, err := client_agent.GetDefaultPidFile()
			if err != nil {
				return errors.Wrap(err, "Failed to get default PID file")
			}
			clientAgentPidFile = defaultPath
		}

		// Default behavior: daemonize unless --foreground is set
		if !clientAgentForeground && !client_agent.IsDaemonMode() {
			daemonConfig := client_agent.DaemonConfig{
				SocketPath:  clientAgentSocketPath,
				PidFile:     clientAgentPidFile,
				LogLocation: "", // Will default to ~/.pelican/client-agent.log in daemon mode
				MaxJobs:     clientAgentMaxJobs,
				DbLocation:  clientAgentDbPath,
				IdleTimeout: param.ClientAgent_IdleTimeout.GetDuration(),
			}

			pid, err := client_agent.StartDaemon(daemonConfig)
			if err != nil {
				return errors.Wrap(err, "Failed to start daemon")
			}

			fmt.Printf("Client agent server started as daemon (PID: %d)\n", pid)
			fmt.Printf("Socket: %s\n", clientAgentSocketPath)
			return nil
		}

		// Check if we're in daemon mode (spawned as daemon child)
		var inheritedLock *os.File
		if client_agent.IsDaemonMode() {
			log.Infof("Running in daemon mode (PID: %d)", os.Getpid())
			log.Infof("Socket path: %s, PID file: %s", clientAgentSocketPath, clientAgentPidFile)
			clientAgentDaemonMode = true

			// Inherit the lock from parent process
			log.Debugln("About to inherit daemon lock")
			lock, err := client_agent.InheritDaemonLock()
			if err != nil {
				log.Errorf("Failed to inherit daemon lock: %v", err)
				return errors.Wrap(err, "Failed to inherit daemon lock")
			}
			log.Debugln("Successfully inherited daemon lock")
			inheritedLock = lock
		} else {
			// Check if already running (only when not inheriting lock)
			running, err := client_agent.CheckServerRunning(clientAgentSocketPath)
			if err != nil {
				return errors.Wrap(err, "Failed to check server status")
			}
			if running {
				return errors.New("Server is already running")
			}
		}

		// Create server config
		serverConfig := client_agent.ServerConfig{
			SocketPath:        clientAgentSocketPath,
			PidFile:           clientAgentPidFile,
			MaxConcurrentJobs: clientAgentMaxJobs,
			DbLocation:        clientAgentDbPath,
			IdleTimeout:       param.ClientAgent_IdleTimeout.GetDuration(),
		}
		log.Infof("Server config: socket=%s, pidFile=%s, maxJobs=%d, idleTimeout=%v",
			serverConfig.SocketPath, serverConfig.PidFile, serverConfig.MaxConcurrentJobs, serverConfig.IdleTimeout)

		// Create context with errgroup for managing background tasks
		egrp, egrpCtx := errgroup.WithContext(context.Background())
		ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

		// Create server
		server, err := client_agent.NewServer(ctx, serverConfig)
		if err != nil {
			log.Errorf("Failed to create server: %v", err)
			if inheritedLock != nil {
				inheritedLock.Close()
			}
			return errors.Wrap(err, "Failed to create server")
		}
		log.Debugln("Server instance created successfully")

		// Initialize database store if database path is configured
		if clientAgentDbPath != "" {
			store, err := initializeStore(clientAgentDbPath)
			if err != nil {
				log.Warnf("Failed to initialize database store: %v. Server will run without persistence.", err)
			} else {
				server.SetStore(store)
				defer store.Close()
			}
		}

		// If we inherited a lock, set it on the server before starting
		if inheritedLock != nil {
			log.Debugln("Setting inherited lock on server")
			if err := server.SetInheritedLock(inheritedLock); err != nil {
				log.Errorf("Failed to set inherited lock: %v", err)
				return errors.Wrap(err, "Failed to set inherited lock")
			}
			log.Debugln("Inherited lock set on server successfully")
		}

		// Start server
		log.Info("Starting server")
		if err := server.Start(); err != nil {
			log.Errorf("Failed to start server: %v", err)
			return errors.Wrap(err, "Failed to start server")
		}

		log.Infof("Client agent server started on %s", server.GetSocketPath())
		log.Infof("PID file: %s", server.GetPidFile())

		// Set up signal handling
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Wait for signal
		sig := <-sigChan
		log.Infof("Received signal %v, shutting down...", sig)

		// Shutdown server
		if err := server.Shutdown(); err != nil {
			return errors.Wrap(err, "Failed to shutdown server gracefully")
		}

		log.Info("Client agent server stopped")
		return nil
	},
}

var clientAgentStopCmd = &cobra.Command{
	Use:          "stop",
	Short:        "Stop the client agent server",
	Long:         `Stop a running client agent server daemon.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize config to read parameters
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "Failed to initialize Pelican client")
		}

		// Use parameter socket path if set, otherwise use flag value, otherwise use default
		if socketParam := param.ClientAgent_Socket.GetString(); socketParam != "" {
			clientAgentSocketPath = socketParam
		} else if clientAgentSocketPath == "" {
			defaultPath, err := client_agent.GetDefaultSocketPath()
			if err != nil {
				return errors.Wrap(err, "Failed to get default socket path")
			}
			clientAgentSocketPath = defaultPath
		}

		// Use parameter PID file path if set, otherwise use flag value, otherwise use default
		if pidFileParam := param.ClientAgent_PidFile.GetString(); pidFileParam != "" {
			clientAgentPidFile = pidFileParam
		} else if clientAgentPidFile == "" {
			defaultPath, err := client_agent.GetDefaultPidFile()
			if err != nil {
				return errors.Wrap(err, "Failed to get default PID file")
			}
			clientAgentPidFile = defaultPath
		}

		// Check if server is running
		running, err := client_agent.CheckServerRunning(clientAgentSocketPath)
		if err != nil {
			return errors.Wrap(err, "Failed to check server status")
		}
		if !running {
			fmt.Println("Server is not running")
			return nil
		}

		// Read PID using GetServerPID
		pid, err := client_agent.GetServerPID(clientAgentPidFile)
		if err != nil {
			return errors.Wrapf(err, "Failed to get server PID from %s", clientAgentPidFile)
		}
		if pid <= 0 {
			// Socket exists but PID file doesn't have a valid PID
			// This can happen if the server is in the process of starting or stopping
			return errors.Errorf("Server is running but PID is not available (got PID %d from %s). The server may be starting or stopping.", pid, clientAgentPidFile)
		}

		// Find process
		process, err := os.FindProcess(pid)
		if err != nil {
			return errors.Wrapf(err, "Failed to find process %d", pid)
		}

		// Send SIGTERM
		if err := process.Signal(syscall.SIGTERM); err != nil {
			return errors.Wrapf(err, "Failed to send SIGTERM to process %d", pid)
		}

		fmt.Printf("Sent shutdown signal to server (PID: %d)\n", pid)
		return nil
	},
}

var clientAgentStatusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Check the status of the client agent server",
	Long:         `Check if the client agent server is running.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize config to read parameters
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "Failed to initialize Pelican client")
		}

		// Use parameter socket path if set, otherwise use flag value, otherwise use default
		if socketParam := param.ClientAgent_Socket.GetString(); socketParam != "" {
			clientAgentSocketPath = socketParam
		} else if clientAgentSocketPath == "" {
			defaultPath, err := client_agent.GetDefaultSocketPath()
			if err != nil {
				return errors.Wrap(err, "Failed to get default socket path")
			}
			clientAgentSocketPath = defaultPath
		}

		// Use parameter PID file path if set, otherwise use flag value, otherwise use default
		if pidFileParam := param.ClientAgent_PidFile.GetString(); pidFileParam != "" {
			clientAgentPidFile = pidFileParam
		} else if clientAgentPidFile == "" {
			defaultPath, err := client_agent.GetDefaultPidFile()
			if err != nil {
				return errors.Wrap(err, "Failed to get default PID file")
			}
			clientAgentPidFile = defaultPath
		}

		running, err := client_agent.CheckServerRunning(clientAgentSocketPath)
		if err != nil {
			return errors.Wrap(err, "Failed to check server status")
		}

		if running {
			// Try to get PID using GetServerPID
			pid, err := client_agent.GetServerPID(clientAgentPidFile)
			if err == nil && pid > 0 {
				fmt.Printf("Client agent server is running (PID: %d)\n", pid)
				fmt.Printf("Socket: %s\n", clientAgentSocketPath)
			} else {
				fmt.Println("Client agent server is running")
				fmt.Printf("Socket: %s\n", clientAgentSocketPath)
			}
		} else {
			fmt.Println("Client agent server is not running")
		}

		return nil
	},
}

func init() {
	// Add subcommands
	clientAgentCmd.AddCommand(clientAgentServeCmd)
	clientAgentCmd.AddCommand(clientAgentStopCmd)
	clientAgentCmd.AddCommand(clientAgentStatusCmd)

	// Persistent flags (available to all subcommands)
	// Note: Default values for socket and pid-file will be computed at runtime if empty
	clientAgentCmd.PersistentFlags().StringVar(&clientAgentSocketPath, "socket", "",
		"Path to the Unix domain socket (default: ~/.pelican/client-agent.sock)")
	clientAgentCmd.PersistentFlags().StringVar(&clientAgentPidFile, "pid-file", "",
		"Path to the PID file (default: ~/.pelican/client-agent.pid)")

	// Serve-specific flags
	clientAgentServeCmd.Flags().IntVar(&clientAgentMaxJobs, "max-jobs", 0,
		"Maximum number of concurrent transfer jobs (default: uses ClientAgent.MaxConcurrentJobs parameter, or 5)")
	clientAgentServeCmd.Flags().StringVar(&clientAgentDbPath, "database", "",
		"Path to the SQLite database file for persistence (default: ~/.pelican/client-agent.db)")
	clientAgentServeCmd.Flags().BoolVar(&clientAgentForeground, "foreground", false,
		"Run in foreground instead of daemonizing (default: daemonize)")
	clientAgentServeCmd.Flags().BoolVar(&clientAgentDaemonMode, "daemon-mode", false,
		"Internal flag indicating the process was spawned as a daemon")
	// Hide the daemon-mode flag as it's for internal use only
	_ = clientAgentServeCmd.Flags().MarkHidden("daemon-mode")

	// Add to root command
	rootCmd.AddCommand(clientAgentCmd)
}
