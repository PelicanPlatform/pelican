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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

// HelperState represents the state of the remote helper process
type HelperState int

const (
	HelperStateNotStarted HelperState = iota
	HelperStateStarting
	HelperStateRunning
	HelperStateStopped
	HelperStateFailed
)

// String returns a human-readable helper state
func (s HelperState) String() string {
	switch s {
	case HelperStateNotStarted:
		return "not_started"
	case HelperStateStarting:
		return "starting"
	case HelperStateRunning:
		return "running"
	case HelperStateStopped:
		return "stopped"
	case HelperStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// HelperStatus contains status information from the remote helper
type HelperStatus struct {
	State     HelperState `json:"state"`
	Message   string      `json:"message,omitempty"`
	LastError string      `json:"last_error,omitempty"`
	Uptime    string      `json:"uptime,omitempty"`
}

// helperIO manages stdin/stdout communication with the remote helper
type helperIO struct {
	stdin        io.WriteCloser
	stdoutReader *bufio.Reader
	stdinMu      sync.Mutex
	stdoutMu     sync.Mutex

	// lastPong is the time of the last pong received from the helper
	lastPong atomic.Value // time.Time

	// helperReady is true once the helper sends the "ready" message
	helperReady atomic.Bool

	// helperUptime is the last reported uptime from the helper
	helperUptime atomic.Value // string
}

// StartHelper starts the Pelican helper process on the remote host.
// All goroutines are managed by an errgroup for clean shutdown.
func (c *SSHConnection) StartHelper(ctx context.Context, helperConfig *HelperConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.GetState() != StateConnected {
		return errors.New("SSH connection not established")
	}

	// Get the remote binary path
	binaryPath, err := c.GetRemoteBinaryPath()
	if err != nil {
		return errors.Wrap(err, "failed to get remote binary path")
	}

	c.helperConfig = helperConfig
	c.setState(StateRunningHelper)

	// Create a new session for the helper process
	session, err := c.client.NewSession()
	if err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to create SSH session for helper")
	}
	c.session = session

	// Set up pipes for stdin/stdout/stderr
	stdin, err := session.StdinPipe()
	if err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to get stdin pipe")
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to get stdout pipe")
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to get stderr pipe")
	}

	// Initialize helper IO management
	c.helperIO = &helperIO{
		stdin:        stdin,
		stdoutReader: bufio.NewReader(stdout),
	}
	c.helperIO.lastPong.Store(time.Now())
	c.helperIO.helperUptime.Store("")

	// Serialize the helper configuration
	configJSON, err := json.Marshal(helperConfig)
	if err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to serialize helper config")
	}

	// Build the command
	cmd := fmt.Sprintf("%s ssh-helper", binaryPath)

	log.Infof("Starting remote helper: %s", cmd)

	// Start the command
	if err := session.Start(cmd); err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to start helper process")
	}

	// Send the configuration on stdin (not in a goroutine - must complete before continuing)
	if _, err := stdin.Write(configJSON); err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to write config to helper stdin")
	}
	if _, err := stdin.Write([]byte("\n")); err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to write newline to helper stdin")
	}

	// Create errgroup for managing helper goroutines
	egrp, egrpCtx := errgroup.WithContext(ctx)
	c.helperErrgroup = egrp
	c.helperCtx = egrpCtx
	c.helperCancel = func() {
		// Signal shutdown via stdin before cancelling context
		_ = c.sendShutdownMessage()
	}

	// Goroutine: Read helper stdout for pong responses
	egrp.Go(func() error {
		return c.readHelperStdout(egrpCtx)
	})

	// Goroutine: Read helper stderr and log it
	egrp.Go(func() error {
		c.readHelperStderr(egrpCtx, stderr)
		return nil
	})

	// Goroutine: Send ping keepalives to helper via stdin
	egrp.Go(func() error {
		return c.runStdinKeepalive(egrpCtx)
	})

	// Goroutine: Monitor pong responses and timeout if missing
	egrp.Go(func() error {
		return c.runPongMonitor(egrpCtx)
	})

	// Goroutine: Wait for the process to exit
	egrp.Go(func() error {
		err := session.Wait()
		if err != nil {
			log.Errorf("Helper process exited with error: %v", err)
			return err
		}
		log.Info("Helper process exited normally")
		return nil
	})

	log.Info("Remote helper process started")
	return nil
}

// readHelperStdout reads and processes stdout messages from the helper.
// It parses JSON messages for pong responses and ready notifications.
func (c *SSHConnection) readHelperStdout(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c.helperIO.stdoutMu.Lock()
		line, err := c.helperIO.stdoutReader.ReadBytes('\n')
		c.helperIO.stdoutMu.Unlock()

		if err != nil {
			if err == io.EOF {
				log.Debug("Helper stdout closed")
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Warnf("Error reading helper stdout: %v", err)
			return err
		}

		// Try to parse as JSON message
		var msg StdoutMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			// Not JSON, just log it
			log.Debugf("Helper stdout: %s", strings.TrimSpace(string(line)))
			continue
		}

		switch msg.Type {
		case "ready":
			log.Info("Helper process is ready")
			c.helperIO.helperReady.Store(true)
			c.helperIO.lastPong.Store(time.Now())

		case "pong":
			c.helperIO.lastPong.Store(time.Now())
			if msg.Uptime != "" {
				c.helperIO.helperUptime.Store(msg.Uptime)
			}
			log.Debugf("Received pong from helper (uptime: %s)", msg.Uptime)

		default:
			log.Debugf("Unknown helper message type: %s", msg.Type)
		}
	}
}

// readHelperStderr reads stderr from the helper and logs it
func (c *SSHConnection) readHelperStderr(ctx context.Context, r io.Reader) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := r.Read(buf)
		if n > 0 {
			lines := strings.Split(strings.TrimSpace(string(buf[:n])), "\n")
			for _, line := range lines {
				if line != "" {
					log.Debugf("Helper stderr: %s", line)
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Debugf("Error reading helper stderr: %v", err)
			}
			return
		}
	}
}

// runStdinKeepalive sends periodic ping messages to the helper via stdin.
// The helper responds with pong messages which are tracked by readHelperStdout.
func (c *SSHConnection) runStdinKeepalive(ctx context.Context) error {
	interval := DefaultKeepaliveInterval
	if c.helperConfig != nil && c.helperConfig.KeepaliveInterval > 0 {
		interval = c.helperConfig.KeepaliveInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.sendPing(); err != nil {
				log.Warnf("Failed to send ping to helper: %v", err)
				// Don't return error - let the pong monitor handle timeouts
			}
		}
	}
}

// sendPing sends a ping message to the helper via stdin
func (c *SSHConnection) sendPing() error {
	msg := StdinMessage{Type: "ping"}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	c.helperIO.stdinMu.Lock()
	defer c.helperIO.stdinMu.Unlock()

	if _, err := c.helperIO.stdin.Write(data); err != nil {
		return err
	}
	if _, err := c.helperIO.stdin.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

// sendShutdownMessage sends a shutdown message to the helper via stdin
func (c *SSHConnection) sendShutdownMessage() error {
	if c.helperIO == nil {
		return nil
	}

	msg := StdinMessage{Type: "shutdown"}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	c.helperIO.stdinMu.Lock()
	defer c.helperIO.stdinMu.Unlock()

	if _, err := c.helperIO.stdin.Write(data); err != nil {
		return err
	}
	if _, err := c.helperIO.stdin.Write([]byte("\n")); err != nil {
		return err
	}
	log.Debug("Sent shutdown message to helper")
	return nil
}

// runPongMonitor monitors pong responses and triggers shutdown if timeout is exceeded
func (c *SSHConnection) runPongMonitor(ctx context.Context) error {
	timeout := DefaultKeepaliveTimeout
	if c.helperConfig != nil && c.helperConfig.KeepaliveTimeout > 0 {
		timeout = c.helperConfig.KeepaliveTimeout
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			lastPong := c.helperIO.lastPong.Load().(time.Time)
			if time.Since(lastPong) > timeout {
				log.Warnf("Helper keepalive timeout exceeded (last pong: %v ago, timeout: %v)",
					time.Since(lastPong), timeout)
				return errors.New("helper keepalive timeout")
			}
		}
	}
}

// StopHelper stops the remote helper process.
// It first tries a clean shutdown via stdin message, then falls back to signals.
func (c *SSHConnection) StopHelper(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil {
		return nil
	}

	log.Info("Stopping remote helper process")

	// First, try clean shutdown via stdin message
	if err := c.sendShutdownMessage(); err != nil {
		log.Debugf("Failed to send shutdown message: %v", err)
	}

	// Wait for the errgroup to finish with a short timeout
	cleanShutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		if c.helperErrgroup != nil {
			done <- c.helperErrgroup.Wait()
		} else {
			done <- nil
		}
	}()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Debugf("Helper errgroup finished with: %v", err)
		}
		log.Info("Helper process stopped cleanly")
	case <-cleanShutdownCtx.Done():
		// Clean shutdown timed out, fall back to signals
		log.Warn("Clean shutdown timed out, sending SIGTERM")
		if err := c.session.Signal(ssh.SIGTERM); err != nil {
			log.Warnf("Failed to send SIGTERM to helper: %v", err)
		}

		// Wait a bit more for SIGTERM
		select {
		case <-done:
			log.Info("Helper process stopped after SIGTERM")
		case <-time.After(2 * time.Second):
			// SIGTERM didn't work, try SIGKILL
			log.Warn("SIGTERM timed out, sending SIGKILL")
			if err := c.session.Signal(ssh.SIGKILL); err != nil {
				log.Warnf("Failed to send SIGKILL to helper: %v", err)
			}
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	// Close stdin to signal EOF to helper
	if c.helperIO != nil && c.helperIO.stdin != nil {
		c.helperIO.stdin.Close()
	}

	c.session.Close()
	c.session = nil
	c.helperIO = nil
	c.helperErrgroup = nil

	if c.GetState() == StateRunningHelper {
		c.setState(StateConnected)
	}

	return nil
}

// StartKeepalive starts the SSH-level keepalive mechanism.
// This is in addition to the process-level stdin/stdout keepalive.
func (c *SSHConnection) StartKeepalive(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runSSHKeepalive(ctx)
	}()
}

// runSSHKeepalive sends periodic SSH keepalive packets at the transport level.
// This complements the stdin/stdout keepalive which operates at the application level.
func (c *SSHConnection) runSSHKeepalive(ctx context.Context) {
	interval := DefaultKeepaliveInterval
	if c.helperConfig != nil && c.helperConfig.KeepaliveInterval > 0 {
		interval = c.helperConfig.KeepaliveInterval
	}

	timeout := DefaultKeepaliveTimeout
	if c.helperConfig != nil && c.helperConfig.KeepaliveTimeout > 0 {
		timeout = c.helperConfig.KeepaliveTimeout
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.client == nil {
				continue
			}

			// Check if we've exceeded the keepalive timeout
			lastKeepalive := c.GetLastKeepalive()
			if time.Since(lastKeepalive) > timeout {
				log.Warnf("SSH keepalive timeout exceeded (last: %v ago, timeout: %v), closing connection",
					time.Since(lastKeepalive), timeout)
				c.Close()
				return
			}

			// Send a keepalive request
			// The "keepalive@openssh.com" request is a standard SSH keepalive
			_, _, err := c.client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				log.Warnf("SSH keepalive failed: %v", err)
				// Don't immediately close - let the timeout handle it
				continue
			}

			c.setLastKeepalive(time.Now())
			log.Debugf("SSH keepalive successful")
		}
	}
}

// GetHelperStatus queries the helper for its status using the stdin/stdout protocol.
// This does not require the helper to listen on any TCP port.
func (c *SSHConnection) GetHelperStatus(ctx context.Context) (*HelperStatus, error) {
	if c.session == nil || c.helperIO == nil {
		return &HelperStatus{
			State:   HelperStateNotStarted,
			Message: "Helper not started",
		}, nil
	}

	if !c.helperIO.helperReady.Load() {
		return &HelperStatus{
			State:   HelperStateStarting,
			Message: "Helper starting",
		}, nil
	}

	// Check if we've received a recent pong
	lastPong := c.helperIO.lastPong.Load().(time.Time)
	timeout := DefaultKeepaliveTimeout
	if c.helperConfig != nil && c.helperConfig.KeepaliveTimeout > 0 {
		timeout = c.helperConfig.KeepaliveTimeout
	}

	if time.Since(lastPong) > timeout {
		return &HelperStatus{
			State:     HelperStateFailed,
			LastError: fmt.Sprintf("no pong received in %v", time.Since(lastPong)),
		}, nil
	}

	uptime := c.helperIO.helperUptime.Load().(string)
	return &HelperStatus{
		State:   HelperStateRunning,
		Uptime:  uptime,
		Message: "Helper running",
	}, nil
}

// WaitForHelper waits for the helper process to become ready
func (c *SSHConnection) WaitForHelper(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check if helper errgroup has an error
		if c.helperErrgroup != nil {
			// Check non-blocking if errgroup finished
			done := make(chan struct{})
			go func() {
				// This will return quickly if errgroup is done
				select {
				case <-c.helperCtx.Done():
					close(done)
				default:
				}
			}()
			select {
			case <-done:
				// Context was cancelled, likely helper failed
				return errors.New("helper process failed during startup")
			default:
			}
		}

		// Check if helper is ready
		if c.helperIO != nil && c.helperIO.helperReady.Load() {
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return errors.Errorf("timeout waiting for helper to become ready after %v", timeout)
}

// createHelperConfigWithCookie creates the helper configuration with a provided auth cookie
// This is used when the auth cookie is shared with the helper broker on the origin
func (c *SSHConnection) createHelperConfigWithCookie(exports []ExportConfig, callbackURL, certChain, authCookie string) (*HelperConfig, error) {
	return &HelperConfig{
		OriginCallbackURL: callbackURL,
		AuthCookie:        authCookie,
		Exports:           exports,
		CertificateChain:  certChain,
		KeepaliveInterval: DefaultKeepaliveInterval,
		KeepaliveTimeout:  DefaultKeepaliveTimeout,
	}, nil
}
