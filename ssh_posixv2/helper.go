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
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
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

// StartHelper starts the Pelican helper process on the remote host
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

	// Serialize the helper configuration
	configJSON, err := json.Marshal(helperConfig)
	if err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to serialize helper config")
	}

	// Build the command
	// The helper will read its configuration from stdin
	cmd := fmt.Sprintf("%s ssh-helper", binaryPath)

	log.Infof("Starting remote helper: %s", cmd)

	// Start the command
	if err := session.Start(cmd); err != nil {
		c.setState(StateConnected)
		return errors.Wrap(err, "failed to start helper process")
	}

	// Send the configuration on stdin
	go func() {
		defer stdin.Close()
		if _, err := stdin.Write(configJSON); err != nil {
			log.Errorf("Failed to write config to helper stdin: %v", err)
		}
		// Write a newline to signal end of config
		if _, err := stdin.Write([]byte("\n")); err != nil {
			log.Warnf("Failed to write newline to helper stdin: %v", err)
		}
	}()

	// Start goroutines to read stdout/stderr
	go c.readHelperOutput(ctx, stdout, "stdout")
	go c.readHelperOutput(ctx, stderr, "stderr")

	// Start a goroutine to wait for the process to exit
	go func() {
		err := session.Wait()
		if err != nil {
			log.Errorf("Helper process exited with error: %v", err)
			c.errChan <- err
		} else {
			log.Info("Helper process exited normally")
			c.errChan <- nil
		}
	}()

	log.Info("Remote helper process started")
	return nil
}

// readHelperOutput reads output from the helper process and logs it
func (c *SSHConnection) readHelperOutput(ctx context.Context, r io.Reader, name string) {
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
					log.Debugf("Helper %s: %s", name, line)
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Debugf("Error reading helper %s: %v", name, err)
			}
			return
		}
	}
}

// StopHelper stops the remote helper process
func (c *SSHConnection) StopHelper(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil {
		return nil
	}

	log.Info("Stopping remote helper process")

	// Send SIGTERM to the helper
	if err := c.session.Signal(ssh.SIGTERM); err != nil {
		log.Warnf("Failed to send SIGTERM to helper: %v", err)
	}

	// Wait for the process to exit with timeout
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-c.errChan:
		if err != nil && !strings.Contains(err.Error(), "signal") {
			log.Warnf("Helper exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		// Force kill if it doesn't exit gracefully
		log.Warn("Helper did not exit gracefully, sending SIGKILL")
		if err := c.session.Signal(ssh.SIGKILL); err != nil {
			log.Warnf("Failed to send SIGKILL to helper: %v", err)
		}
	}

	c.session.Close()
	c.session = nil

	if c.GetState() == StateRunningHelper {
		c.setState(StateConnected)
	}

	return nil
}

// StartKeepalive starts the keepalive mechanism for both SSH and HTTP
func (c *SSHConnection) StartKeepalive(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runSSHKeepalive(ctx)
	}()
}

// runSSHKeepalive sends periodic SSH keepalive packets
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

// SendHelperCommand sends a command to the helper process via stdin
func (c *SSHConnection) SendHelperCommand(ctx context.Context, command string) (string, error) {
	if c.session == nil {
		return "", errors.New("helper not running")
	}

	// For now, we use a simple approach - run a new session with a command
	// In the future, we could implement a more sophisticated IPC mechanism
	binaryPath, err := c.GetRemoteBinaryPath()
	if err != nil {
		return "", errors.Wrap(err, "failed to get remote binary path")
	}

	cmd := fmt.Sprintf("%s ssh-helper --command %s", binaryPath, command)
	return c.runCommand(ctx, cmd)
}

// GetHelperStatus queries the helper for its status
func (c *SSHConnection) GetHelperStatus(ctx context.Context) (*HelperStatus, error) {
	if c.session == nil {
		return &HelperStatus{
			State:   HelperStateNotStarted,
			Message: "Helper not started",
		}, nil
	}

	// Query the helper's status endpoint
	output, err := c.SendHelperCommand(ctx, "status")
	if err != nil {
		return &HelperStatus{
			State:     HelperStateFailed,
			LastError: err.Error(),
		}, nil
	}

	var status HelperStatus
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		// If we can't parse the output, assume the helper is running
		return &HelperStatus{
			State:   HelperStateRunning,
			Message: output,
		}, nil
	}

	return &status, nil
}

// WaitForHelper waits for the helper process to become ready
func (c *SSHConnection) WaitForHelper(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-c.errChan:
			// Helper exited unexpectedly
			return errors.Wrapf(err, "helper process exited during startup")
		default:
		}

		// Try to get the helper status
		status, err := c.GetHelperStatus(ctx)
		if err == nil && status.State == HelperStateRunning {
			return nil
		}

		time.Sleep(500 * time.Millisecond)
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
