//go:build client

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/client_agent/apiclient"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// asyncWarmItem identifies a remote object whose credential should be ensured
// in the wallet before an asynchronous submission to the client agent.
type asyncWarmItem struct {
	url   string
	write bool
}

// warmWalletForAsync ensures the user's wallet holds usable tokens for the
// given remote objects (acquiring them interactively if needed) and then opens
// the agent's wallet so the agent can use and refresh them while the job runs.
//
// The client agent runs without a controlling terminal and cannot perform
// interactive token acquisition, so the (interactive) CLI warms the wallet on
// its behalf before submitting. Public namespaces that require no token are
// skipped; if none of the objects needs a token, the agent wallet is left
// untouched.
func warmWalletForAsync(ctx context.Context, apiClient *apiclient.APIClient, items []asyncWarmItem) error {
	warmedAny := false
	for _, it := range items {
		needed, err := warmOneCredential(ctx, it.url, it.write)
		if err != nil {
			return err
		}
		warmedAny = warmedAny || needed
	}
	if !warmedAny {
		return nil
	}

	// Forward the wallet password (cached while acquiring above) to the agent
	// so it can decrypt, use, and refresh the stored credentials.
	password, _ := config.TryGetPassword()
	if err := apiClient.OpenWallet(ctx, string(password)); err != nil {
		return errors.Wrap(err, "failed to open the agent's credential wallet")
	}
	return nil
}

// warmOneCredential ensures a usable token for a single remote object is in the
// wallet, acquiring one interactively if necessary. It reports whether the
// object's namespace required a token at all.
func warmOneCredential(ctx context.Context, rawURL string, write bool) (needed bool, err error) {
	pUrl, err := client.ParseRemoteAsPUrl(ctx, rawURL)
	if err != nil {
		return false, errors.Wrapf(err, "failed to parse %q", rawURL)
	}

	httpMethod := http.MethodGet
	var operation config.TokenOperation
	operation.Set(config.TokenRead)
	operation.Set(config.TokenList)
	if write {
		operation.Set(config.TokenWrite)
		operation.Set(config.TokenDelete)
		httpMethod = http.MethodPut
	}

	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, httpMethod, "")
	if err != nil {
		return false, errors.Wrapf(err, "director lookup failed for %q", rawURL)
	}
	if !dirResp.XPelNsHdr.RequireToken {
		return false, nil
	}

	opts := config.TokenGenerationOpts{
		Operation:    operation,
		DiscoveryURL: pUrl.FedInfo.DiscoveryEndpoint,
	}
	if _, err := client.AcquireToken(pUrl.GetRawUrl(), dirResp, opts); err != nil {
		return true, errors.Wrapf(err, "failed to acquire a credential for %q", rawURL)
	}
	return true, nil
}

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
