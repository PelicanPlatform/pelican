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

	// helperSocketPath is the Unix socket path the helper reported for direct
	// connections (tunnel/direct-listen mode only).  Empty means not yet reported.
	helperSocketPath atomic.Value // string
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

	sshLog.Infof("Starting remote helper: %s", cmd)

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

	// Create errgroup for managing helper goroutines. We layer a separate
	// cancellable context on top of the caller's so StopHelper can actively
	// wake ticker-driven goroutines (runPongMonitor / runStdinKeepalive)
	// without waiting for their next tick. Without this, the SIGKILL
	// fallback path nils helperIO while those goroutines are still ticking
	// and they panic on the stale field deref.
	cancelCtx, cancel := context.WithCancel(ctx)
	egrp, egrpCtx := errgroup.WithContext(cancelCtx)
	c.helperErrgroup = egrp
	c.helperCtx = egrpCtx
	c.helperCancel = cancel

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

	// Goroutine: Wait for the process to exit.
	// When the process exits, close the session to unblock the
	// stdout/stderr reader goroutines (whose blocking ReadBytes /
	// scanner.Scan calls won't notice context cancellation until the
	// underlying pipe returns EOF or an error).
	egrp.Go(func() error {
		err := session.Wait()
		// Closing the session tears down the SSH channel, which makes
		// the stdout and stderr pipe reads return immediately.
		session.Close()
		if err != nil {
			sshLog.Errorf("Helper process exited with error: %v", err)
			return err
		}
		sshLog.Info("Helper process exited normally")
		return nil
	})

	// Bridge the errgroup to errChan so that runConnection's select loop
	// can detect helper exit (normal or error) and trigger reconnection.
	go func() {
		err := egrp.Wait()
		if err != nil && !errors.Is(err, context.Canceled) {
			c.errChan <- err
		} else {
			c.errChan <- nil
		}
	}()

	sshLog.Info("Remote helper process started")
	return nil
}

// readHelperStdout reads and processes stdout messages from the helper.
// It parses JSON messages for pong responses and ready notifications.
func (c *SSHConnection) readHelperStdout(ctx context.Context) error {
	// Snapshot helperIO once. StopHelper nils c.helperIO during teardown;
	// holding our own pointer keeps the underlying struct reachable for
	// the rest of this goroutine's life and avoids a nil-deref race.
	helperIO := c.helperIO
	if helperIO == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		helperIO.stdoutMu.Lock()
		line, err := helperIO.stdoutReader.ReadBytes('\n')
		helperIO.stdoutMu.Unlock()

		if err != nil {
			if err == io.EOF {
				sshLog.Debug("Helper stdout closed")
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			sshLog.Warnf("Error reading helper stdout: %v", err)
			return err
		}

		// Try to parse as JSON message
		var msg StdoutMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			// Not JSON — unexpected output from the helper, log at Info
			sshLog.Infof("[helper] stdout: %s", strings.TrimSpace(string(line)))
			continue
		}

		switch msg.Type {
		case "ready":
			sshLog.Info("Helper process is ready")
			helperIO.helperReady.Store(true)
			helperIO.lastPong.Store(time.Now())

		case "listening":
			if msg.SocketPath != "" {
				sshLog.Infof("Helper listening on unix socket %s (direct-listen mode)", msg.SocketPath)
				helperIO.helperSocketPath.Store(msg.SocketPath)
			}

		case "pong":
			helperIO.lastPong.Store(time.Now())
			if msg.Uptime != "" {
				helperIO.helperUptime.Store(msg.Uptime)
			}
			sshLog.Debugf("Received pong from helper (uptime: %s)", msg.Uptime)

		case "goodbye":
			sshLog.Infof("Helper acknowledged shutdown (uptime: %s)", msg.Uptime)

		default:
			sshLog.Debugf("Unknown helper message type: %s", msg.Type)
		}
	}
}

// readHelperStderr reads stderr from the helper and logs it.
// The helper uses logrus which writes to stderr, so we parse the log level
// from each line and relay at the corresponding level on the origin side.
func (c *SSHConnection) readHelperStderr(ctx context.Context, r io.Reader) {
	sshLog.Debug("readHelperStderr: started reading helper stderr")
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	lines := 0
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			sshLog.Debugf("readHelperStderr: context done after %d lines", lines)
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}
		lines++

		// Parse the logrus level from the helper's output and relay at the
		// corresponding level. Logrus text format (non-TTY) looks like:
		//   time="..." level=info msg="..."
		helperLogAtLevel(line)
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() == nil {
			sshLog.Warnf("readHelperStderr: scanner error after %d lines: %v", lines, err)
		}
	}
	sshLog.Debugf("readHelperStderr: finished after %d lines", lines)
}

// helperLogAtLevel parses a log line from the helper and relays it on the
// origin side at the corresponding level with a structured daemon field.
// The helper uses JSON log format, so we parse the JSON to extract the
// level, message, and any extra fields.
func helperLogAtLevel(line string) {
	entry := sshLog.WithField("daemon", "ssh-helper")

	// Try to parse as JSON (helper uses JSONFormatter)
	var fields map[string]interface{}
	if err := json.Unmarshal([]byte(line), &fields); err == nil {
		msg, _ := fields["msg"].(string)
		level, _ := fields["level"].(string)

		// Forward any extra fields the helper attached to the entry
		for k, v := range fields {
			switch k {
			case "msg", "level", "time":
				// Skip standard logrus fields — we re-emit these naturally
			default:
				entry = entry.WithField(k, v)
			}
		}

		switch level {
		case "panic", "fatal":
			entry.Error(msg)
		case "error":
			entry.Error(msg)
		case "warning", "warn":
			entry.Warn(msg)
		case "info":
			entry.Info(msg)
		case "debug":
			entry.Debug(msg)
		case "trace":
			entry.Trace(msg)
		default:
			entry.Info(msg)
		}
		return
	}

	// Fallback for non-JSON lines (e.g. early startup, panics):
	// use the text-based level detection.
	switch {
	case strings.Contains(line, "level=panic") || strings.Contains(line, "level=fatal"):
		entry.Error(line)
	case strings.Contains(line, "level=error"):
		entry.Error(line)
	case strings.Contains(line, "level=warning") || strings.Contains(line, "level=warn"):
		entry.Warn(line)
	case strings.Contains(line, "level=info"):
		entry.Info(line)
	case strings.Contains(line, "level=debug") || strings.Contains(line, "level=trace"):
		entry.Debug(line)
	default:
		entry.Info(line)
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
				sshLog.Warnf("Failed to send ping to helper: %v", err)
				// Don't return error - let the pong monitor handle timeouts
			}
		}
	}
}

// sendPing sends a ping message to the helper via stdin
func (c *SSHConnection) sendPing() error {
	// Snapshot helperIO so a concurrent StopHelper that nils it (or its
	// stdin) can't turn this into a nil deref. sendShutdownMessage uses
	// the same pattern.
	helperIO := c.helperIO
	if helperIO == nil || helperIO.stdin == nil {
		return errors.New("helper IO not initialized")
	}

	msg := StdinMessage{Type: "ping"}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	helperIO.stdinMu.Lock()
	defer helperIO.stdinMu.Unlock()

	if _, err := helperIO.stdin.Write(data); err != nil {
		return err
	}
	if _, err := helperIO.stdin.Write([]byte("\n")); err != nil {
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
	sshLog.Debug("Sent shutdown message to helper")
	return nil
}

// runPongMonitor monitors pong responses and triggers shutdown if timeout is exceeded
func (c *SSHConnection) runPongMonitor(ctx context.Context) error {
	timeout := DefaultKeepaliveTimeout
	if c.helperConfig != nil && c.helperConfig.KeepaliveTimeout > 0 {
		timeout = c.helperConfig.KeepaliveTimeout
	}

	// Snapshot helperIO once: StopHelper sets c.helperIO = nil during
	// teardown, and a nil deref on c.helperIO.lastPong here is the panic
	// reported in #3363. Holding our own pointer keeps the atomic.Value
	// reachable for the rest of the goroutine's life.
	helperIO := c.helperIO
	if helperIO == nil {
		return nil
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			v := helperIO.lastPong.Load()
			lastPong, ok := v.(time.Time)
			if !ok {
				// Never Stored (shouldn't happen — StartHelper Stores
				// time.Now() before launching this goroutine — but treat
				// as "just received" rather than panic).
				continue
			}
			if time.Since(lastPong) > timeout {
				sshLog.Warnf("Helper keepalive timeout exceeded (last pong: %v ago, timeout: %v)",
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

	sshLog.Info("Stopping remote helper process")

	// First, try clean shutdown via stdin message
	if err := c.sendShutdownMessage(); err != nil {
		sshLog.Debugf("Failed to send shutdown message: %v", err)
	}

	// Close stdin so the helper also sees EOF (belt-and-suspenders with
	// the "shutdown" message above).  This also causes the origin-side
	// runStdinKeepalive to fail its next Write and return.
	if c.helperIO != nil && c.helperIO.stdin != nil {
		c.helperIO.stdin.Close()
	}

	// Start waiting for the errgroup to finish in the background.
	// We must wait for all goroutines to exit before niling helperIO,
	// otherwise goroutines like readHelperStdout will hit a nil pointer.
	done := make(chan error, 1)
	go func() {
		if c.helperErrgroup != nil {
			done <- c.helperErrgroup.Wait()
		} else {
			done <- nil
		}
	}()

	// Wait for clean shutdown with an absolute timeout.
	// Use time.After instead of context.WithTimeout because the caller's
	// context may already be expired (e.g., during shutdown), which would
	// make the derived context immediately expired and skip the grace period.
	// The 5-second budget matches the helper's internal HTTP server shutdown
	// timeout; the helper needs time to flush in-flight responses and close
	// the unix socket listener before exiting.
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			sshLog.Debugf("Helper errgroup finished with: %v", err)
		}
		sshLog.Info("Helper process stopped cleanly")
	case <-time.After(5 * time.Second):
		// Clean shutdown timed out, fall back to signals
		sshLog.Warn("Clean shutdown timed out, sending SIGTERM")
		if err := c.session.Signal(ssh.SIGTERM); err != nil {
			sshLog.Warnf("Failed to send SIGTERM to helper: %v", err)
		}

		// Wait a bit more for SIGTERM
		select {
		case <-done:
			sshLog.Info("Helper process stopped after SIGTERM")
		case <-time.After(2 * time.Second):
			// SIGTERM didn't work, try SIGKILL
			sshLog.Warn("SIGTERM timed out, sending SIGKILL")
			if err := c.session.Signal(ssh.SIGKILL); err != nil {
				sshLog.Warnf("Failed to send SIGKILL to helper: %v", err)
			}

			// Close stdin and session to force goroutines to unblock from
			// their I/O reads, then wait for the errgroup to finish.
			if c.helperIO != nil && c.helperIO.stdin != nil {
				c.helperIO.stdin.Close()
			}
			c.session.Close()

			// Cancel the helper context too, so ticker-driven goroutines
			// (runPongMonitor / runStdinKeepalive) wake up immediately
			// instead of waiting for their next tick.
			if c.helperCancel != nil {
				c.helperCancel()
			}

			select {
			case <-done:
				sshLog.Info("Helper process stopped after SIGKILL")
			case <-time.After(5 * time.Second):
				// Last-resort wait so we don't nil helperIO out from
				// under still-running goroutines and trigger nil-deref
				// panics. Goroutines now snapshot helperIO and tolerate
				// it being nil, but giving them a final chance to exit
				// cleanly avoids spurious "stdin closed" errors in logs.
				sshLog.Warn("Helper errgroup did not finish after SIGKILL; waiting briefly before forcing cleanup")
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					sshLog.Warn("Helper errgroup did not finish; goroutines may leak")
				}
			}
		}
	}

	// Close stdin and session (may already be closed after SIGKILL path; double-close is safe)
	if c.helperIO != nil && c.helperIO.stdin != nil {
		c.helperIO.stdin.Close()
	}

	if c.session != nil {
		c.session.Close()
	}
	// Cancel the helper context if it hasn't been already, so anything
	// still running notices we're shutting down.
	if c.helperCancel != nil {
		c.helperCancel()
		c.helperCancel = nil
	}
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
func (c *SSHConnection) StartKeepalive(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		c.runSSHKeepalive(ctx)
		return nil
	})
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
			// Snapshot c.client once so a concurrent Close() that nils it
			// can't turn a non-nil check into a nil-deref on SendRequest
			// below. SendRequest on an already-closed *ssh.Client returns
			// an error rather than panicking, so a stale snapshot is safe.
			client := c.client
			if client == nil {
				continue
			}

			// Check if we've exceeded the keepalive timeout
			lastKeepalive := c.GetLastKeepalive()
			if time.Since(lastKeepalive) > timeout {
				sshLog.Warnf("SSH keepalive timeout exceeded (last: %v ago, timeout: %v), closing connection",
					time.Since(lastKeepalive), timeout)
				c.Close()
				return
			}

			// Send a keepalive request
			// The "keepalive@openssh.com" request is a standard SSH keepalive
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				sshLog.Warnf("SSH keepalive failed: %v", err)
				// Don't immediately close - let the timeout handle it
				continue
			}

			c.setLastKeepalive(time.Now())
			sshLog.Debugf("SSH keepalive successful")
		}
	}
}

// GetHelperStatus queries the helper for its status using the stdin/stdout protocol.
// This does not require the helper to listen on any TCP port.
func (c *SSHConnection) GetHelperStatus(ctx context.Context) (*HelperStatus, error) {
	// Snapshot helperIO once so a concurrent StopHelper that nils it
	// can't turn the field reads below into a nil-deref or surface a
	// type-assertion panic on a nil interface from Load().
	helperIO := c.helperIO
	if c.session == nil || helperIO == nil {
		return &HelperStatus{
			State:   HelperStateNotStarted,
			Message: "Helper not started",
		}, nil
	}

	if !helperIO.helperReady.Load() {
		return &HelperStatus{
			State:   HelperStateStarting,
			Message: "Helper starting",
		}, nil
	}

	// Check if we've received a recent pong
	v := helperIO.lastPong.Load()
	lastPong, ok := v.(time.Time)
	if !ok {
		// Should not happen — StartHelper Stores time.Now() before
		// returning — but treat the absence as "starting" rather than
		// panic.
		return &HelperStatus{
			State:   HelperStateStarting,
			Message: "Helper starting",
		}, nil
	}
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

	uptime, _ := helperIO.helperUptime.Load().(string)
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

// WaitForHelperSocket waits for the helper to report the Unix socket path it is
// listening on (direct-listen mode only).  Returns the socket path once available.
func (c *SSHConnection) WaitForHelperSocket(ctx context.Context, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		if c.helperIO != nil {
			if v := c.helperIO.helperSocketPath.Load(); v != nil {
				if sp, ok := v.(string); ok && sp != "" {
					return sp, nil
				}
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	return "", errors.Errorf("timeout waiting for helper to report socket path after %v", timeout)
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
