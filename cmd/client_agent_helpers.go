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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/client_agent/apiclient"
	"github.com/pelicanplatform/pelican/param"
)

// ensureClientAgentRunning ensures the client API server is running, starting it if necessary
// Returns an API client connected to the server
// Retries up to maxRetries times with exponential backoff
func ensureClientAgentRunning(ctx context.Context, maxRetries int) (*apiclient.APIClient, error) {
	if maxRetries <= 0 {
		maxRetries = 5
	}

	// Get socket path from config
	socketPath := param.ClientAgent_Socket.GetString()
	if socketPath == "" {
		var err error
		socketPath, err = client_agent.GetDefaultSocketPath()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get default socket path")
		}
	}

	// Try to connect to existing server first
	client, err := apiclient.NewAPIClient(socketPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create API client")
	}

	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if client.IsServerRunning(checkCtx) {
		log.Debug("Client API server is already running")
		return client, nil
	}

	// Server not running, try to start it
	log.Info("Client API server is not running, starting daemon...")

	pidFile := param.ClientAgent_PidFile.GetString()
	if pidFile == "" {
		var err error
		pidFile, err = client_agent.GetDefaultPidFile()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get default PID file")
		}
	}

	dbLocation := param.ClientAgent_DbLocation.GetString()
	if dbLocation == "" {
		// Default to ~/.pelican/client-agent.db
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get user home directory")
		}
		dbLocation = filepath.Join(homeDir, ".pelican", "client-agent.db")
	}

	config := client_agent.DaemonConfig{
		SocketPath:  socketPath,
		PidFile:     pidFile,
		LogLocation: "", // Use default
		MaxJobs:     param.ClientAgent_MaxConcurrentJobs.GetInt(),
		DbLocation:  dbLocation,
		IdleTimeout: param.ClientAgent_IdleTimeout.GetDuration(),
	}

	pid, err := client_agent.StartDaemon(config)
	if err != nil {
		// Check if the error is due to the daemon already running
		if strings.Contains(err.Error(), "already running") {
			log.Debugf("Daemon is already running, attempting to connect...")
		} else {
			// Real error - don't proceed
			return nil, errors.Wrap(err, "failed to start daemon")
		}
	} else {
		log.Infof("Started client API daemon (PID: %d)", pid)
	}

	// Retry connecting to the server with exponential backoff
	backoff := 100 * time.Millisecond
	maxBackoff := 2 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Wait before retrying
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}

		// Try to connect
		retryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if client.IsServerRunning(retryCtx) {
			cancel()
			log.Debugf("Successfully connected to client API server (attempt %d/%d)", attempt+1, maxRetries)
			return client, nil
		}
		cancel()

		log.Debugf("Server not ready yet (attempt %d/%d), retrying...", attempt+1, maxRetries)
	}

	return nil, errors.Errorf("failed to connect to server after %d attempts", maxRetries)
}
