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
	"net/http"
	"os/user"
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

// NewSSHBackend creates a new SSH backend
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
	// Snapshot the connections under the lock, then release it so that
	// runConnectionManager (which also needs b.mu) does not deadlock
	// while we wait for helpers to exit.
	b.mu.Lock()
	conns := make(map[string]*SSHConnection, len(b.connections))
	for host, conn := range b.connections {
		conns[host] = conn
	}
	b.connections = make(map[string]*SSHConnection)
	b.mu.Unlock()

	for host, conn := range conns {
		sshLog.Infof("Shutting down SSH connection to %s", host)
		// StopHelper sends the "shutdown" message on stdin and waits for
		// the helper process to exit cleanly before escalating to signals.
		// This must run before Close() so the SSH session is still alive
		// when the shutdown message is written.
		if err := conn.StopHelper(context.Background()); err != nil {
			sshLog.Warnf("Failed to stop helper for %s during shutdown: %v", host, err)
		}
		conn.Close()
	}

	// Cancel the backend context after helpers are stopped. This must
	// happen last so that the errgroup's stdout/stderr reader goroutines
	// remain alive long enough to relay the helper's "goodbye" message.
	if b.cancelFunc != nil {
		b.cancelFunc()
	}
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

// InitializeBackend initializes the SSH backend from configuration.
func InitializeBackend(ctx context.Context, egrp *errgroup.Group, exports []server_utils.OriginExport) error {
	backendMu.Lock()
	defer backendMu.Unlock()

	// Check if SSH backend is configured
	host := param.Origin_SSH_Host.GetString()
	if host == "" {
		return errors.New("Origin.SSH.Host is required for SSH backend")
	}

	// Determine SSH username: use config value, fall back to current OS user
	sshUser := param.Origin_SSH_User.GetString()
	if sshUser == "" {
		currentUser, err := user.Current()
		if err != nil {
			return errors.Wrap(err, "Origin.SSH.User is not set and failed to determine current OS user")
		}
		sshUser = currentUser.Username
		sshLog.Infof("Origin.SSH.User not configured; defaulting to current OS user %q", sshUser)
	}

	// Build the SSH configuration
	sshConfig := &SSHConfig{
		Host:                     host,
		Port:                     param.Origin_SSH_Port.GetInt(),
		User:                     sshUser,
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
		TunnelCallback:           param.Origin_SSH_TunnelCallback.GetBool(),
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
				sshLog.Warnf("Invalid remote binary override format: %s (expected os/arch=/path)", override)
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

	// Set up the global helper transport.
	// In tunnel mode, use SSHTunnelTransport (origin dials helper through SSH).
	// In broker mode, use HelperTransport (helper calls back with reversed connections).
	if sshConfig.TunnelCallback {
		tunnelTransport := NewSSHTunnelTransport(authCookie)
		backend.tunnelTransport = tunnelTransport
		SetHelperTransport(tunnelTransport)
	} else {
		SetHelperTransport(NewHelperTransport(backend.helperBroker))
	}

	// Start cleanup routine for stale requests (every 30 seconds, remove requests older than 5 minutes)
	backend.helperBroker.StartCleanupRoutine(ctx, egrp, 5*time.Minute, 30*time.Second)

	// Set initial health status - SSH backend is initializing
	metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusWarning,
		fmt.Sprintf("SSH backend initializing, connecting to %s", host))

	// Launch the connection manager
	egrp.Go(func() error {
		return runConnectionManager(ctx, backend, sshConfig, exportConfigs)
	})

	sshLog.Infof("SSH backend initialized for host %s", host)
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
				sshLog.Errorf("SSH session establishment timed out after %v (attempt %d/%d)", sessionEstablishTimeout, consecutiveFailures, maxRetries)
				metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusCritical,
					fmt.Sprintf("SSH session establishment timed out (attempt %d/%d)", consecutiveFailures, maxRetries))
			} else {
				sshLog.Errorf("SSH connection failed (attempt %d/%d): %v", consecutiveFailures, maxRetries, err)
				metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusCritical,
					fmt.Sprintf("SSH connection failed (attempt %d/%d): %v", consecutiveFailures, maxRetries, err))
			}

			// Check if we've exceeded max retries
			if consecutiveFailures >= maxRetries {
				sshLog.Errorf("Max SSH connection retries (%d) exceeded", maxRetries)
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

			sshLog.Infof("Retrying SSH connection in %v", delayWithJitter)
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

	host := conn.config.Host

	// Start a background goroutine that logs connection progress every 3s
	// so that INFO-level output isn't silent during potentially long auth.
	progressCtx, progressCancel := context.WithCancel(ctx)
	var progressWg sync.WaitGroup
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		logConnectionProgress(progressCtx, conn, host)
	}()
	defer func() {
		progressCancel()
		progressWg.Wait()
	}()

	// Connect to the remote host
	sshLog.Infof("Starting SSH login to %s (methods: %v)", host, conn.config.AuthMethods)
	NotifyStatus(host, fmt.Sprintf("Establishing SSH connection to %s (methods: %v)...",
		host, conn.config.AuthMethods))
	if err := conn.Connect(establishCtx); err != nil {
		return errors.Wrap(err, "failed to connect")
	}

	// Notify WebSocket clients that authentication is complete
	// This includes all ProxyJump hops - the SSH connection is fully established
	if err := NotifyAuthComplete(host, "SSH connection established successfully."); err != nil {
		sshLog.Warnf("Failed to notify auth complete: %v", err)
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
			sshLog.Warnf("Failed to cleanup remote binary: %v", err)
		}
	}()

	// Build the helper configuration.
	// Tunnel mode (TunnelCallback):
	//   The origin dials the helper through SSH direct-tcpip channels.
	//   The helper starts a plain HTTP server on 127.0.0.1:0, reports
	//   the port via stdout, and the origin connects through ssh.Client.Dial.
	//   No TLS, no callback URL, no certificate chain needed — the SSH
	//   channel provides encryption and authentication.
	// Broker mode (default):
	//   The helper polls the origin's /retrieve endpoint and calls back
	//   to establish reverse connections.  Requires a callback URL, TLS
	//   certificate chain, and optional TLS server name override.
	var helperConfig *HelperConfig
	if conn.config.TunnelCallback {
		helperConfig = &HelperConfig{
			AuthCookie:       authCookie,
			Exports:          exports,
			DirectListenMode: true,
			LogLevel:         log.GetLevel().String(),
		}
		sshLog.Info("Tunnel mode: helper will listen on local port (origin dials via SSH)")
	} else {
		// Broker mode: helper needs callback URL and origin's certificate
		originExternalURL := param.Server_ExternalWebUrl.GetString()
		callbackURL := originExternalURL + "/api/v1.0/origin/ssh/callback"

		certChain, err := getCertificateChain()
		if err != nil {
			return errors.Wrap(err, "failed to get certificate chain")
		}

		helperConfig, err = conn.createHelperConfigWithCookie(exports, callbackURL, certChain, authCookie)
		if err != nil {
			return errors.Wrap(err, "failed to create helper config")
		}
		helperConfig.LogLevel = log.GetLevel().String()
	}

	// Start the helper process.
	// Use the parent context (not the establishment timeout) so the helper's
	// errgroup goroutines are not killed by the establishment timeout expiring.
	if err := conn.StartHelper(ctx, helperConfig); err != nil {
		return errors.Wrap(err, "failed to start helper")
	}

	// In tunnel mode, wait for the helper to report its listening socket and
	// wire the SSHTunnelTransport so origin→helper HTTP requests flow
	// through the SSH connection.
	if conn.config.TunnelCallback {
		socketPath, err := conn.WaitForHelperSocket(ctx, 30*time.Second)
		if err != nil {
			return errors.Wrap(err, "helper did not report listening socket")
		}

		if tunnelTransport := GetHelperTransport(); tunnelTransport != nil {
			if tt, ok := tunnelTransport.(*SSHTunnelTransport); ok {
				tt.SetReady(conn.client, socketPath)
				sshLog.Infof("SSH tunnel transport ready: helper at %s via SSH streamlocal", socketPath)
			}
		}
	}

	// Establishment is complete — cancel the timeout and stop progress logging.
	establishCancel()
	progressCancel()
	progressWg.Wait()

	// SSH backend is now fully operational - helper is running and ready to serve requests
	metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusOK,
		fmt.Sprintf("SSH backend connected to %s, helper running", conn.config.Host))

	// Use an errgroup to manage all steady-state goroutines.  The first
	// one to return a non-nil error cancels steadyCtx, which makes all
	// the others shut down as well.
	steadyCtx, steadyCancel := context.WithCancel(ctx)
	defer steadyCancel()
	steadyGrp, steadyCtx := errgroup.WithContext(steadyCtx)

	// SSH transport-level keepalive
	conn.StartKeepalive(steadyCtx, steadyGrp)

	// Broker watchdog (broker mode only — in tunnel mode there is no
	// retrieve polling to watch).
	if !conn.config.TunnelCallback {
		steadyGrp.Go(func() error {
			return runBrokerWatchdog(steadyCtx, conn.config.Host)
		})
	}

	// Origin→helper ping: actively probes the helper through the helper
	// transport, logging round-trip latency at debug level so operators
	// can verify the data path.  If pings fail for longer than
	// DefaultPingFailureTimeout the connection is torn down.
	steadyGrp.Go(func() error {
		return runOriginToHelperPing(steadyCtx, 15*time.Second)
	})

	// Bridge helper-process exit (conn.errChan) into the errgroup so
	// that a helper crash terminates the steady state.
	steadyGrp.Go(func() error {
		select {
		case <-steadyCtx.Done():
			return steadyCtx.Err()
		case err := <-conn.errChan:
			if err != nil {
				return errors.Wrap(err, "helper process failed")
			}
			sshLog.Info("Helper process exited; will reconnect")
			return nil
		}
	})

	// Wait for either the parent context to be cancelled or a
	// goroutine in the steady-state group to finish.
	err := steadyGrp.Wait()

	// Attempt a clean helper shutdown regardless of the exit reason.
	if stopErr := conn.StopHelper(ctx); stopErr != nil {
		sshLog.Warnf("Failed to stop helper during teardown: %v", stopErr)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		sshLog.Errorf("Steady-state goroutine failed: %v", err)
		return err
	}
	return nil
}

// logConnectionProgress logs the SSH connection establishment at INFO
// level every 3 seconds until ctx is cancelled.  When the connection is
// waiting for user input (password or keyboard-interactive) it suggests
// running `pelican origin ssh-auth login` to complete authentication.
func logConnectionProgress(ctx context.Context, conn *SSHConnection, host string) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state := conn.GetState()
			switch state {
			case StateWaitingForUserInput:
				step := conn.GetAuthStep()
				if step == "agent" {
					sshLog.Infof("SSH login to %s: waiting for agent confirmation (e.g., touch hardware key)", host)
				} else {
					sshLog.Infof("SSH login to %s: waiting for user input (%s) — run `pelican origin ssh-auth login` to complete authentication", host, step)
				}
			case StateConnecting:
				sshLog.Infof("SSH login to %s: connecting...", host)
			case StateAuthenticating:
				if step := conn.GetAuthStep(); step != "" {
					sshLog.Infof("SSH login to %s: authenticating (%s)...", host, step)
				} else {
					sshLog.Infof("SSH login to %s: authenticating...", host)
				}
			case StateConnected:
				sshLog.Infof("SSH login to %s: connected, setting up helper...", host)
			case StateRunningHelper:
				// Helper is up; progress goroutine will be cancelled soon.
				return
			default:
				sshLog.Infof("SSH login to %s: %s", host, state)
			}
		}
	}
}

// runOriginToHelperPing periodically sends an HTTP request to the helper via
// the global helper transport (broker-based or SSH-tunnel-based).  This
// validates the full data path and gives operators a debug-level heartbeat
// showing round-trip latency.  If pings fail continuously for longer than
// DefaultPingFailureTimeout the function returns an error so the connection
// manager can tear down and retry.
func runOriginToHelperPing(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	transport := GetHelperTransport()
	if transport == nil {
		sshLog.Debug("Origin→helper ping: no transport available, skipping")
		return nil
	}

	broker := GetHelperBroker()
	authCookie := ""
	if broker != nil {
		authCookie = broker.GetAuthCookie()
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	var lastSuccess time.Time
	var firstFailure time.Time
	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, "POST", "http://helper/api/v1.0/ssh-helper/keepalive", nil)
		if err != nil {
			sshLog.Debugf("Origin→helper ping: failed to create request: %v", err)
			continue
		}
		req.Header.Set("Authorization", "Bearer "+authCookie)

		resp, err := client.Do(req)
		latency := time.Since(start)
		if err != nil {
			if ctx.Err() != nil {
				return nil // context cancelled; exit quietly
			}
			consecutiveFailures++
			if firstFailure.IsZero() {
				firstFailure = time.Now()
			}
			// First failure and every 4th failure after → warning; otherwise debug
			if consecutiveFailures == 1 || consecutiveFailures%4 == 0 {
				if lastSuccess.IsZero() {
					sshLog.Warnf("Origin→helper ping failed (%v): %v", latency.Round(time.Millisecond), err)
				} else {
					sshLog.Warnf("Origin→helper ping failed (%v; last success %v ago): %v",
						latency.Round(time.Millisecond), time.Since(lastSuccess).Round(time.Second), err)
				}
			} else {
				sshLog.Debugf("Origin→helper ping failed (%v): %v", latency.Round(time.Millisecond), err)
			}
			// If failures have persisted beyond the timeout, give up.
			if failDuration := time.Since(firstFailure); failDuration > DefaultPingFailureTimeout {
				metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusCritical,
					fmt.Sprintf("Origin→helper ping has failed for %v", failDuration.Round(time.Second)))
				return fmt.Errorf("origin→helper ping has failed for %v (%d consecutive failures)",
					failDuration.Round(time.Second), consecutiveFailures)
			}
			continue
		}
		resp.Body.Close()
		if consecutiveFailures > 0 {
			sshLog.Infof("Origin→helper ping recovered after %d failures (%v)", consecutiveFailures, latency.Round(time.Millisecond))
		}
		consecutiveFailures = 0
		firstFailure = time.Time{}
		lastSuccess = time.Now()
		sshLog.Debugf("Origin→helper ping OK (%v)", latency.Round(time.Millisecond))
	}
}

// runBrokerWatchdog monitors the helper's broker-retrieve polling.
// It returns an error if the helper has not polled for an extended period,
// which signals that the origin cannot serve requests via this helper.
// It also updates the component health status as the situation changes.
func runBrokerWatchdog(ctx context.Context, host string) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	wasHealthy := true

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		broker := GetHelperBroker()
		if broker == nil {
			continue
		}

		lastRetrieve := broker.GetLastRetrieveTime()

		// Before the helper has ever polled, don't alarm — it takes time
		// for the helper to start up and begin its polling loop.
		if lastRetrieve.IsZero() {
			continue
		}

		since := time.Since(lastRetrieve)

		if since > DefaultBrokerPollTimeout {
			if wasHealthy {
				sshLog.Warnf("Helper broker check-in overdue: last poll was %v ago (threshold %v)",
					since.Round(time.Second), DefaultBrokerPollTimeout)
			}
			wasHealthy = false
			metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusCritical,
				fmt.Sprintf("Helper has not checked in via broker for %v (host %s)", since.Round(time.Second), host))
		} else {
			if !wasHealthy {
				sshLog.Infof("Helper broker check-in recovered: last poll was %v ago", since.Round(time.Second))
				metrics.SetComponentHealthStatus(metrics.Origin_SSHBackend, metrics.StatusOK,
					fmt.Sprintf("SSH backend connected to %s, helper running", host))
			}
			wasHealthy = true
		}
	}
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
