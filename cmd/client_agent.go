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
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

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
)

// initializeStore creates a new database store instance
func initializeStore(dbPath string) (client_agent.StoreInterface, error) {
	return store.NewStore(dbPath)
}

var clientAgentCmd = &cobra.Command{
	Use:   "client-api",
	Short: "Manage the Pelican client API server",
	Long: `The client-api server provides a RESTful API for interacting with
the Pelican client functionality over a Unix domain socket. This enables
external applications to use Pelican transfer capabilities without directly
invoking the CLI.`,
}

var clientAgentServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the client API server",
	Long: `Start the client API server as a daemon process. The server will listen
on a Unix domain socket and handle job-based transfer requests.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize config
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "Failed to initialize Pelican client")
		}

		// Use parameter socket path if set, otherwise use flag value
		if socketParam := param.ClientAgent_Socket.GetString(); socketParam != "" {
			clientAgentSocketPath = socketParam
		}

		// Check if already running
		running, err := client_agent.CheckServerRunning(clientAgentSocketPath)
		if err != nil {
			return errors.Wrap(err, "Failed to check server status")
		}
		if running {
			return errors.New("Server is already running")
		}

		// Create server config
		serverConfig := client_agent.ServerConfig{
			SocketPath:        clientAgentSocketPath,
			PidFile:           clientAgentPidFile,
			MaxConcurrentJobs: clientAgentMaxJobs,
			DatabasePath:      clientAgentDbPath,
		}

		// Create server
		server, err := client_agent.NewServer(serverConfig)
		if err != nil {
			return errors.Wrap(err, "Failed to create server")
		}

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

		// Start server
		if err := server.Start(); err != nil {
			return errors.Wrap(err, "Failed to start server")
		}

		log.Infof("Client API server started on %s", server.GetSocketPath())
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

		log.Info("Client API server stopped")
		return nil
	},
}

var clientAgentStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the client API server",
	Long:  `Stop a running client API server daemon.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize config to read parameters
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "Failed to initialize Pelican client")
		}

		// Use parameter socket path if set, otherwise use flag value
		if socketParam := param.ClientAgent_Socket.GetString(); socketParam != "" {
			clientAgentSocketPath = socketParam
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

		// Read PID from file
		pid, err := client_agent.ReadPidFile(clientAgentPidFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read PID file")
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
	Use:   "status",
	Short: "Check the status of the client API server",
	Long:  `Check if the client API server is running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize config to read parameters
		if err := config.InitClient(); err != nil {
			return errors.Wrap(err, "Failed to initialize Pelican client")
		}

		// Use parameter socket path if set, otherwise use flag value
		if socketParam := param.ClientAgent_Socket.GetString(); socketParam != "" {
			clientAgentSocketPath = socketParam
		}

		running, err := client_agent.CheckServerRunning(clientAgentSocketPath)
		if err != nil {
			return errors.Wrap(err, "Failed to check server status")
		}

		if running {
			// Try to read PID
			pid, err := client_agent.ReadPidFile(clientAgentPidFile)
			if err == nil {
				fmt.Printf("Client API server is running (PID: %d)\n", pid)
				fmt.Printf("Socket: %s\n", clientAgentSocketPath)
			} else {
				fmt.Println("Client API server is running")
				fmt.Printf("Socket: %s\n", clientAgentSocketPath)
			}
		} else {
			fmt.Println("Client API server is not running")
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
	clientAgentCmd.PersistentFlags().StringVar(&clientAgentSocketPath, "socket", client_agent.DefaultSocketPath,
		"Path to the Unix domain socket")
	clientAgentCmd.PersistentFlags().StringVar(&clientAgentPidFile, "pid-file", client_agent.DefaultPidFile,
		"Path to the PID file")

	// Serve-specific flags
	clientAgentServeCmd.Flags().IntVar(&clientAgentMaxJobs, "max-jobs", client_agent.DefaultMaxConcurrentJobs,
		"Maximum number of concurrent transfer jobs")
	clientAgentServeCmd.Flags().StringVar(&clientAgentDbPath, "database", "",
		"Path to the SQLite database file for persistence (default: ~/.pelican/client-api.db)")

	// Add to root command
	rootCmd.AddCommand(clientAgentCmd)
}
