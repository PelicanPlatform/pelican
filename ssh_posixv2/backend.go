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

package ssh_posixv2

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	// globalBackend is the singleton backend instance
	globalBackend *SSHBackend
	backendMu     sync.Mutex
)

// init registers the reset callback with server_utils
func init() {
	server_utils.RegisterSSHBackendReset(ResetBackend)
}

// ResetBackend resets the global backend state (for testing)
func ResetBackend() {
	backendMu.Lock()
	defer backendMu.Unlock()

	if globalBackend != nil {
		globalBackend.Shutdown()
		globalBackend = nil
	}
}

// GetBackend returns the global SSH backend instance
func GetBackend() *SSHBackend {
	backendMu.Lock()
	defer backendMu.Unlock()
	return globalBackend
}

// NewSSHBackend creates a new SSH POSIXv2 backend
func NewSSHBackend(ctx context.Context) *SSHBackend {
	ctx, cancel := context.WithCancel(ctx)
	return &SSHBackend{
		connections: make(map[string]*SSHConnection),
		ctx:         ctx,
		cancelFunc:  cancel,
	}
}

// NewSSHConnection creates a new SSH connection with the given configuration
func NewSSHConnection(cfg *SSHConfig) *SSHConnection {
	return &SSHConnection{
		config:       cfg,
		keyboardChan: make(chan KeyboardInteractiveChallenge, 1),
		responseChan: make(chan KeyboardInteractiveResponse, 1),
		errChan:      make(chan error, 1),
	}
}

// AddConnection adds a connection to the backend
func (b *SSHBackend) AddConnection(host string, conn *SSHConnection) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.connections[host] = conn
}

// GetConnection returns a connection for the given host
func (b *SSHBackend) GetConnection(host string) *SSHConnection {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connections[host]
}

// RemoveConnection removes a connection from the backend
func (b *SSHBackend) RemoveConnection(host string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.connections, host)
}

// Shutdown shuts down all connections
func (b *SSHBackend) Shutdown() {
	if b.cancelFunc != nil {
		b.cancelFunc()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for host, conn := range b.connections {
		log.Infof("Shutting down SSH connection to %s", host)
		conn.Close()
	}
	b.connections = make(map[string]*SSHConnection)
}

// GetAllConnections returns all connections
func (b *SSHBackend) GetAllConnections() map[string]*SSHConnection {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[string]*SSHConnection)
	for k, v := range b.connections {
		result[k] = v
	}
	return result
}

// InitializeBackend initializes the SSH POSIXv2 backend from configuration
func InitializeBackend(ctx context.Context, egrp *errgroup.Group, exports []server_utils.OriginExport) error {
	backendMu.Lock()
	defer backendMu.Unlock()

	// Check if SSH POSIXv2 is configured
	host := param.Origin_SSH_Host.GetString()
	if host == "" {
		return errors.New("Origin.SSH.Host is required for SSH POSIXv2 backend")
	}

	// Build the SSH configuration
	sshConfig := &SSHConfig{
		Host:                     host,
		Port:                     param.Origin_SSH_Port.GetInt(),
		User:                     param.Origin_SSH_User.GetString(),
		PasswordFile:             param.Origin_SSH_PasswordFile.GetString(),
		PrivateKeyFile:           param.Origin_SSH_PrivateKeyFile.GetString(),
		PrivateKeyPassphraseFile: param.Origin_SSH_PrivateKeyPassphraseFile.GetString(),
		KnownHostsFile:           param.Origin_SSH_KnownHostsFile.GetString(),
		AutoAddHostKey:           param.Origin_SSH_AutoAddHostKey.GetBool(),
		PelicanBinaryPath:        param.Origin_SSH_PelicanBinaryPath.GetString(),
		RemotePelicanBinaryDir:   param.Origin_SSH_RemotePelicanBinaryDir.GetString(),
		MaxRetries:               param.Origin_SSH_MaxRetries.GetInt(),
		ConnectTimeout:           param.Origin_SSH_ConnectTimeout.GetDuration(),
		ChallengeTimeout:         param.Origin_SSH_ChallengeTimeout.GetDuration(),
		ProxyJump:                param.Origin_SSH_ProxyJump.GetString(),
	}

	// Parse auth methods
	authMethodStrs := param.Origin_SSH_AuthMethods.GetStringSlice()
	if len(authMethodStrs) == 0 {
		// Default to trying common methods
		authMethodStrs = []string{"publickey", "agent", "keyboard-interactive", "password"}
	}
	for _, methodStr := range authMethodStrs {
		sshConfig.AuthMethods = append(sshConfig.AuthMethods, AuthMethod(methodStr))
	}

	// Parse remote binary overrides
	overrideStrs := param.Origin_SSH_RemotePelicanBinaryOverrides.GetStringSlice()
	if len(overrideStrs) > 0 {
		sshConfig.RemotePelicanBinaryOverrides = make(map[string]string)
		for _, override := range overrideStrs {
			// Format: "os/arch=/path/to/binary"
			// e.g., "linux/amd64=/opt/pelican/pelican"
			parts := splitOnce(override, "=")
			if len(parts) == 2 {
				sshConfig.RemotePelicanBinaryOverrides[parts[0]] = parts[1]
			} else {
				log.Warnf("Invalid remote binary override format: %s (expected os/arch=/path)", override)
			}
		}
	}

	// Convert exports to our internal format
	exportConfigs := make([]ExportConfig, len(exports))
	for i, export := range exports {
		exportConfigs[i] = ExportConfig{
			FederationPrefix: export.FederationPrefix,
			StoragePrefix:    export.StoragePrefix,
			Capabilities: ExportCapabilities{
				PublicReads: export.Capabilities.PublicReads,
				Reads:       export.Capabilities.Reads,
				Writes:      export.Capabilities.Writes,
				Listings:    export.Capabilities.Listings,
				DirectReads: export.Capabilities.DirectReads,
			},
		}
	}

	// Generate auth cookie for the helper broker
	authCookie, err := generateAuthCookie()
	if err != nil {
		return errors.Wrap(err, "failed to generate auth cookie for helper broker")
	}

	// Create the backend with helper broker
	backend := NewSSHBackend(ctx)
	backend.helperBroker = NewHelperBroker(ctx, authCookie)
	globalBackend = backend

	// Set the global helper broker so HTTP handlers can find it
	SetHelperBroker(backend.helperBroker)

	// Start cleanup routine for stale requests (every 30 seconds, remove requests older than 5 minutes)
	backend.helperBroker.StartCleanupRoutine(ctx, egrp, 5*time.Minute, 30*time.Second)

	// Set initial health status - SSH backend is initializing
	metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusWarning,
		fmt.Sprintf("SSH backend initializing, connecting to %s", host))

	// Launch the connection manager
	egrp.Go(func() error {
		return runConnectionManager(ctx, backend, sshConfig, exportConfigs)
	})

	log.Infof("SSH POSIXv2 backend initialized for host %s", host)
	return nil
}

// runConnectionManager manages the SSH connection lifecycle with retries
func runConnectionManager(ctx context.Context, backend *SSHBackend, sshConfig *SSHConfig, exports []ExportConfig) error {
	retryDelay := DefaultReconnectDelay
	maxRetries := sshConfig.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}

	// Get the session establishment timeout - this bounds the entire time to establish
	// a working SSH connection (connect, detect platform, transfer binary, start helper)
	sessionEstablishTimeout := param.Origin_SSH_SessionEstablishTimeout.GetDuration()
	if sessionEstablishTimeout <= 0 {
		sessionEstablishTimeout = DefaultSessionEstablishTimeout
	}

	// Get the auth cookie from the helper broker
	authCookie := ""
	if backend.helperBroker != nil {
		authCookie = backend.helperBroker.GetAuthCookie()
	}

	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Create a new connection
		conn := NewSSHConnection(sshConfig)
		backend.AddConnection(sshConfig.Host, conn)

		// Try to establish a connection and run the helper.
		// The session establishment timeout bounds only the establishment phase
		// (connect, detect platform, transfer binary); the helper runs indefinitely
		// under the parent context.
		err := runConnection(ctx, sessionEstablishTimeout, conn, exports, authCookie)

		if err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				// Parent context was cancelled, exit gracefully
				metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusShuttingDown,
					"SSH backend shutting down")
				return nil
			}

			consecutiveFailures++
			if errors.Is(err, context.DeadlineExceeded) {
				log.Errorf("SSH session establishment timed out after %v (attempt %d/%d)", sessionEstablishTimeout, consecutiveFailures, maxRetries)
				metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusCritical,
					fmt.Sprintf("SSH session establishment timed out (attempt %d/%d)", consecutiveFailures, maxRetries))
			} else {
				log.Errorf("SSH connection failed (attempt %d/%d): %v", consecutiveFailures, maxRetries, err)
				metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusCritical,
					fmt.Sprintf("SSH connection failed (attempt %d/%d): %v", consecutiveFailures, maxRetries, err))
			}

			// Check if we've exceeded max retries
			if consecutiveFailures >= maxRetries {
				log.Errorf("Max SSH connection retries (%d) exceeded", maxRetries)
				metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusCritical,
					fmt.Sprintf("SSH connection failed after max retries (%d)", maxRetries))
				return errors.Wrap(err, "SSH connection failed after max retries")
			}

			// Exponential backoff with jitter (+/-25% of delay)
			retryDelay = time.Duration(float64(retryDelay) * 1.5)
			if retryDelay > MaxReconnectDelay {
				retryDelay = MaxReconnectDelay
			}
			jitter := time.Duration(float64(retryDelay) * (0.5*rand.Float64() - 0.25)) // -25% to +25%
			delayWithJitter := retryDelay + jitter

			log.Infof("Retrying SSH connection in %v", delayWithJitter)
			metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusWarning,
				fmt.Sprintf("SSH connection lost, retrying in %v", delayWithJitter))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delayWithJitter):
			}
		} else {
			// Connection completed normally (helper exited gracefully)
			consecutiveFailures = 0
			retryDelay = DefaultReconnectDelay
			// Note: Status will be set back to Warning when we start the reconnection loop
		}

		// Clean up the connection
		conn.Close()
		backend.RemoveConnection(sshConfig.Host)
	}
}

// runConnection establishes a connection and runs the helper process.
// The sessionEstablishTimeout bounds only the establishment phase (connect,
// detect platform, transfer binary). Once the helper is started, it runs
// under the parent ctx with no timeout.
func runConnection(ctx context.Context, sessionEstablishTimeout time.Duration, conn *SSHConnection, exports []ExportConfig, authCookie string) error {
	// Create a timeout context for the establishment phase only
	establishCtx, establishCancel := context.WithTimeout(ctx, sessionEstablishTimeout)
	defer establishCancel()

	// Connect to the remote host
	if err := conn.Connect(establishCtx); err != nil {
		return errors.Wrap(err, "failed to connect")
	}

	// Notify WebSocket clients that authentication is complete
	// This includes all ProxyJump hops - the SSH connection is fully established
	host := conn.config.Host
	if err := NotifyAuthComplete(host, "SSH connection established successfully."); err != nil {
		log.Warnf("Failed to notify auth complete: %v", err)
		// Non-fatal - continue even if WebSocket notification fails
	}

	// Detect the remote platform
	if _, err := conn.DetectRemotePlatform(establishCtx); err != nil {
		return errors.Wrap(err, "failed to detect remote platform")
	}

	// Transfer the binary if needed
	if conn.NeedsBinaryTransfer() {
		if err := conn.TransferBinary(establishCtx); err != nil {
			return errors.Wrap(err, "failed to transfer binary")
		}
	}

	// Ensure we clean up the remote binary on all exit paths
	// Use a background context for cleanup since the main context may be cancelled
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := conn.CleanupRemoteBinary(cleanupCtx); err != nil {
			log.Warnf("Failed to cleanup remote binary: %v", err)
		}
	}()

	// Get the callback URL - this is the origin's helper broker callback endpoint
	// The helper will use this URL to establish reverse connections
	callbackURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/origin/ssh/callback"

	// Get the certificate chain
	certChain, err := getCertificateChain()
	if err != nil {
		return errors.Wrap(err, "failed to get certificate chain")
	}

	// Create the helper configuration with the auth cookie from the helper broker
	helperConfig, err := conn.createHelperConfigWithCookie(exports, callbackURL, certChain, authCookie)
	if err != nil {
		return errors.Wrap(err, "failed to create helper config")
	}

	// Start the helper process.
	// Use the parent context (not the establishment timeout) so the helper's
	// errgroup goroutines are not killed by the establishment timeout expiring.
	if err := conn.StartHelper(ctx, helperConfig); err != nil {
		return errors.Wrap(err, "failed to start helper")
	}

	// Establishment is complete — cancel the timeout so it doesn't linger
	establishCancel()

	// SSH backend is now fully operational - helper is running and ready to serve requests
	metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusOK,
		fmt.Sprintf("SSH backend connected to %s, helper running", conn.config.Host))

	// Start keepalive
	var wg sync.WaitGroup
	conn.StartKeepalive(ctx, &wg)

	// Wait for the helper to exit
	select {
	case <-ctx.Done():
		if err := conn.StopHelper(ctx); err != nil {
			log.Warnf("Failed to stop helper: %v", err)
		}
		return ctx.Err()
	case err := <-conn.errChan:
		if err != nil {
			return errors.Wrap(err, "helper process failed")
		}
	}

	return nil
}

// getCertificateChain reads and returns the PEM-encoded certificate chain
func getCertificateChain() (string, error) {
	certFile := param.Server_TLSCertificateChain.GetString()
	if certFile == "" {
		return "", errors.New("TLS certificate chain not configured")
	}

	certPEM, err := config.LoadCertificateChainPEM(certFile)
	if err != nil {
		return "", errors.Wrap(err, "failed to load certificate chain")
	}

	return certPEM, nil
}

// splitOnce splits a string on the first occurrence of sep
func splitOnce(s, sep string) []string {
	before, after, found := strings.Cut(s, sep)
	if !found {
		return []string{s}
	}
	return []string{before, after}
}

// GetKeyboardChannel returns the channel for keyboard-interactive challenges
// This is used by the WebSocket handler
func (c *SSHConnection) GetKeyboardChannel() <-chan KeyboardInteractiveChallenge {
	return c.keyboardChan
}

// GetResponseChannel returns the channel for keyboard-interactive responses
// This is used by the WebSocket handler
func (c *SSHConnection) GetResponseChannel() chan<- KeyboardInteractiveResponse {
	return c.responseChan
}

// GetConnectionInfo returns information about the connection for status endpoints
func (c *SSHConnection) GetConnectionInfo() map[string]interface{} {
	info := map[string]interface{}{
		"state": c.GetState().String(),
	}

	if c.config != nil {
		info["host"] = c.config.Host
		info["port"] = c.config.Port
		info["user"] = c.config.User
	}

	if c.platformInfo != nil {
		info["remote_os"] = c.platformInfo.OS
		info["remote_arch"] = c.platformInfo.Arch
	}

	if c.remoteBinaryPath != "" {
		info["remote_binary"] = c.remoteBinaryPath
	}

	lastKeepalive := c.GetLastKeepalive()
	if !lastKeepalive.IsZero() {
		info["last_keepalive"] = lastKeepalive.Format(time.RFC3339)
		info["keepalive_age"] = fmt.Sprintf("%.1fs", time.Since(lastKeepalive).Seconds())
	}

	return info
}
