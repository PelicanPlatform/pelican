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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// DefaultSSHHandshakeTimeout is the default timeout for SSH handshake operations
const DefaultSSHHandshakeTimeout = 60 * time.Second

// DefaultChallengeTimeout is the default timeout for individual auth challenges
const DefaultChallengeTimeout = 5 * time.Minute

// sshDialContext dials an SSH server with context support for cancellation
func sshDialContext(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	// Use a dialer that respects context
	d := net.Dialer{
		Timeout: config.Timeout,
	}

	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Perform SSH handshake with context cancellation support
	// We do this by running the handshake in a goroutine and selecting on context
	type result struct {
		client *ssh.Client
		err    error
	}
	done := make(chan result, 1)

	go func() {
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
		if err != nil {
			conn.Close()
			done <- result{nil, err}
			return
		}
		done <- result{ssh.NewClient(c, chans, reqs), nil}
	}()

	select {
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	case r := <-done:
		return r.client, r.err
	}
}

// buildSSHAuthMethods constructs the list of SSH auth methods from the configuration
func (c *SSHConnection) buildSSHAuthMethods(ctx context.Context) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	// Determine challenge timeout
	challengeTimeout := c.config.ChallengeTimeout
	if challengeTimeout == 0 {
		challengeTimeout = DefaultChallengeTimeout
	}

	for _, method := range c.config.AuthMethods {
		log.Debugf("Building auth method: %s", method)
		switch method {
		case AuthMethodPassword:
			auth, err := c.buildPasswordAuth(ctx, challengeTimeout)
			if err != nil {
				log.Warnf("Failed to build password auth: %v", err)
				continue
			}
			authMethods = append(authMethods, auth)

		case AuthMethodPublicKey:
			auth, err := c.buildPublicKeyAuth()
			if err != nil {
				log.Warnf("Failed to build public key auth: %v", err)
				continue
			}
			authMethods = append(authMethods, auth)

		case AuthMethodAgent:
			auth, err := c.buildAgentAuth(ctx)
			if err != nil {
				log.Warnf("Failed to build SSH agent auth: %v", err)
				continue
			}
			authMethods = append(authMethods, auth)

		case AuthMethodKeyboardInteractive:
			auth := c.buildKeyboardInteractiveAuth(ctx, challengeTimeout)
			authMethods = append(authMethods, auth)

		default:
			log.Warnf("Unknown SSH auth method: %s", method)
		}
	}

	if len(authMethods) == 0 {
		return nil, errors.New("no valid SSH authentication methods configured")
	}

	return authMethods, nil
}

// buildPasswordAuth reads the password from a file and creates an auth method
func (c *SSHConnection) buildPasswordAuth(ctx context.Context, challengeTimeout time.Duration) (ssh.AuthMethod, error) {
	// If a password file is configured, use it
	if c.config.PasswordFile != "" {
		password, err := os.ReadFile(c.config.PasswordFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read password file")
		}

		// Trim any trailing whitespace/newlines
		passwordStr := strings.TrimSpace(string(password))

		return ssh.Password(passwordStr), nil
	}

	// No password file - use WebSocket-based password callback
	// This will prompt the user for a password via the WebSocket connection
	return c.buildPasswordAuthCallback(ctx, challengeTimeout), nil
}

// buildPasswordAuthCallback creates a password auth method that prompts the user
// for a password via the WebSocket connection (like keyboard-interactive)
// The ctx parameter allows cancellation; challengeTimeout limits each individual challenge.
func (c *SSHConnection) buildPasswordAuthCallback(ctx context.Context, challengeTimeout time.Duration) ssh.AuthMethod {
	return ssh.PasswordCallback(func() (string, error) {
		log.Debugf("Password auth requested via callback")

		// Check if context is already cancelled
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		// Check if WebSocket channels are set up
		if c.keyboardChan == nil || c.responseChan == nil {
			log.Debugf("Password auth channels not set up, skipping this auth method")
			return "", errors.New("password auth not available (no WebSocket connection)")
		}

		// Set state to waiting for user input
		c.setState(StateWaitingForUserInput)
		defer c.setState(StateAuthenticating)

		// Generate a session ID for this challenge
		sessionID, err := generateAuthCookie()
		if err != nil {
			return "", errors.Wrap(err, "failed to generate session ID")
		}

		// Build a challenge that asks for the password
		// We use the keyboard-interactive infrastructure for this
		challenge := KeyboardInteractiveChallenge{
			SessionID:   sessionID,
			User:        c.config.User,
			Instruction: "Password authentication",
			Questions: []KeyboardInteractiveQuestion{
				{
					Prompt: "Password: ",
					Echo:   false,
				},
			},
		}

		// Send the challenge to the WebSocket handler
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case c.keyboardChan <- challenge:
		case <-time.After(challengeTimeout):
			return "", errors.New("password authentication timed out waiting to send challenge")
		}

		// Wait for the response from the WebSocket handler
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case response := <-c.responseChan:
			if response.SessionID != sessionID {
				return "", errors.New("session ID mismatch in password response")
			}
			if len(response.Answers) != 1 {
				return "", errors.Errorf("expected 1 answer, got %d", len(response.Answers))
			}
			return response.Answers[0], nil
		case <-time.After(challengeTimeout):
			return "", errors.New("password authentication timed out")
		}
	})
}

// buildPublicKeyAuth reads the private key from a file and creates an auth method
func (c *SSHConnection) buildPublicKeyAuth() (ssh.AuthMethod, error) {
	if c.config.PrivateKeyFile == "" {
		return nil, errors.New("private key file not configured")
	}

	keyData, err := os.ReadFile(c.config.PrivateKeyFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read private key file")
	}

	var signer ssh.Signer

	// Check if we have a passphrase file
	if c.config.PrivateKeyPassphraseFile != "" {
		passphrase, err := os.ReadFile(c.config.PrivateKeyPassphraseFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read passphrase file")
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, passphrase)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse private key with passphrase")
		}
	} else {
		// Try parsing without passphrase first
		signer, err = ssh.ParsePrivateKey(keyData)
		if err != nil {
			// Check if it's a passphrase-required error
			if _, ok := err.(*ssh.PassphraseMissingError); ok {
				return nil, errors.New("private key is encrypted but no passphrase file configured")
			}
			return nil, errors.Wrap(err, "failed to parse private key")
		}
	}

	return ssh.PublicKeys(signer), nil
}

// getAgentSocket returns the SSH agent socket path from the SSH_AUTH_SOCK environment variable.
// This is the only standard way OpenSSH locates the agent socket; there is no default path.
func getAgentSocket() (string, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return "", errors.New("SSH_AUTH_SOCK environment variable not set")
	}
	return socket, nil
}

// buildAgentAuth connects to the SSH agent and creates an auth method
// The ctx parameter allows context-aware dialing and cancellation
func (c *SSHConnection) buildAgentAuth(ctx context.Context) (ssh.AuthMethod, error) {
	socket, err := getAgentSocket()
	if err != nil {
		return nil, err
	}

	log.Debugf("Connecting to SSH agent at %s", socket)

	// Use context-aware dialer
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to SSH agent")
	}

	log.Debugf("Connected to SSH agent, creating agent client")
	agentClient := agent.NewClient(conn)

	// List keys to verify the agent is responsive
	keys, err := agentClient.List()
	if err != nil {
		conn.Close()
		return nil, errors.Wrap(err, "failed to list SSH agent keys")
	}
	log.Debugf("SSH agent has %d key(s) available", len(keys))
	for i, key := range keys {
		log.Debugf("  Key %d: %s %s", i+1, key.Type(), key.Comment)
	}

	log.Debugf("SSH agent auth method ready")

	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		signers, err := agentClient.Signers()
		if err != nil {
			log.Debugf("Failed to get signers from agent: %v", err)
			return nil, err
		}
		log.Debugf("Got %d signer(s) from SSH agent", len(signers))
		return signers, nil
	}), nil
}

// buildKeyboardInteractiveAuth creates a keyboard-interactive auth method
// that forwards challenges to the WebSocket handler for user interaction.
// The ctx parameter allows overall cancellation; challengeTimeout limits each individual challenge.
func (c *SSHConnection) buildKeyboardInteractiveAuth(ctx context.Context, challengeTimeout time.Duration) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		log.Debugf("Keyboard-interactive auth requested (user=%s, questions=%d)", user, len(questions))

		// Check if context is already cancelled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// If there are no questions, just return empty answers
		// Some servers send an empty challenge if they can't determine a priori keyboard interactive is unneeded.
		if len(questions) == 0 {
			log.Debugf("No questions in keyboard-interactive challenge, returning empty")
			return []string{}, nil
		}

		// Check if WebSocket channels are set up and have readers
		// In CLI mode without WebSocket, channels exist but have no readers
		if c.keyboardChan == nil || c.responseChan == nil {
			log.Debugf("Keyboard-interactive channels not set up, skipping this auth method")
			return nil, errors.New("keyboard-interactive not available (no WebSocket connection)")
		}

		// Set state to waiting for user input
		c.setState(StateWaitingForUserInput)
		defer c.setState(StateAuthenticating)

		// Generate a session ID for this challenge
		sessionID, err := generateAuthCookie()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate session ID")
		}

		// Build the challenge
		challenge := KeyboardInteractiveChallenge{
			SessionID:   sessionID,
			User:        user,
			Instruction: instruction,
			Questions:   make([]KeyboardInteractiveQuestion, len(questions)),
		}

		for i, q := range questions {
			challenge.Questions[i] = KeyboardInteractiveQuestion{
				Prompt: q,
				Echo:   echos[i],
			}
		}

		// Send the challenge to the WebSocket handler
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case c.keyboardChan <- challenge:
		case <-time.After(challengeTimeout):
			return nil, errors.New("keyboard-interactive timed out waiting to send challenge")
		}

		// Wait for the response from the WebSocket handler
		// Use both the overall context and the per-challenge timeout
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case response := <-c.responseChan:
			if response.SessionID != sessionID {
				return nil, errors.New("session ID mismatch in keyboard-interactive response")
			}
			if len(response.Answers) != len(questions) {
				return nil, errors.Errorf("expected %d answers, got %d", len(questions), len(response.Answers))
			}
			return response.Answers, nil
		case <-time.After(challengeTimeout):
			return nil, errors.New("keyboard-interactive authentication timed out")
		}
	})
}

// getKnownHostsPath returns the path to the known_hosts file
func (c *SSHConnection) getKnownHostsPath() (string, error) {
	knownHostsPath := c.config.KnownHostsFile
	if knownHostsPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", errors.Wrap(err, "failed to get home directory")
		}
		knownHostsPath = filepath.Join(homeDir, ".ssh", "known_hosts")
	}
	return knownHostsPath, nil
}

// getHostKeyAlgorithmsForHost reads the known_hosts file and returns the preferred
// host key algorithms for the given host, based on what keys are already known.
// This mimics OpenSSH's behavior of preferring algorithms that already have entries.
//
// This manual parsing is necessary because the golang.org/x/crypto/ssh/knownhosts
// package only provides a HostKeyCallback that accepts or rejects keys, but doesn't
// expose an API to query which key types are known for a host. OpenSSH's behavior
// of preferring known algorithms improves user experience by reducing host key
// verification prompts when a host offers multiple key types.
func (c *SSHConnection) getHostKeyAlgorithmsForHost(host string, port int) []string {
	knownHostsPath, err := c.getKnownHostsPath()
	if err != nil {
		return nil
	}

	file, err := os.Open(knownHostsPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Normalize the host for lookup.
	// The [host]:port format is the standard SSH known_hosts format for non-default ports.
	// From OpenSSH's sshd(8) man page: "Hostnames is a comma-separated list of patterns...;
	// a hostname or address may optionally be enclosed within '[' and ']' brackets then
	// followed by ':' and a non-standard port number."
	// Example: "[example.com]:2222 ssh-ed25519 AAAAC3..."
	addr := host
	if port != 22 {
		addr = fmt.Sprintf("[%s]:%d", host, port)
	}
	normalizedHost := knownhosts.Normalize(addr)

	// Also check the hostname without port for port 22
	var preferredAlgorithms []string
	seenAlgorithms := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip markers like @cert-authority, @revoked
		if strings.HasPrefix(line, "@") {
			continue
		}

		// Parse the line: hosts keytype key [comment]
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		hostPatterns := strings.Split(fields[0], ",")
		keyType := fields[1]

		// Check if any host pattern matches
		for _, pattern := range hostPatterns {
			pattern = strings.TrimSpace(pattern)
			// Handle hashed hostnames
			if strings.HasPrefix(pattern, "|1|") {
				// Can't easily match hashed hostnames, skip
				continue
			}

			normalizedPattern := knownhosts.Normalize(pattern)
			if normalizedPattern == normalizedHost || normalizedPattern == host {
				if !seenAlgorithms[keyType] {
					seenAlgorithms[keyType] = true
					preferredAlgorithms = append(preferredAlgorithms, keyType)
					log.Debugf("Found known host key algorithm for %s: %s", host, keyType)
				}
			}
		}
	}

	return preferredAlgorithms
}

// buildHostKeyCallback creates the SSH host key callback for verification
func (c *SSHConnection) buildHostKeyCallback() (ssh.HostKeyCallback, error) {
	knownHostsPath, err := c.getKnownHostsPath()
	if err != nil {
		return nil, err
	}

	// Check if the known_hosts file exists
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		log.Warnf("Known hosts file %s does not exist; creating empty file", knownHostsPath)
		// Create the .ssh directory if it doesn't exist
		dir := filepath.Dir(knownHostsPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, errors.Wrap(err, "failed to create .ssh directory")
		}
		// Create an empty known_hosts file
		if err := os.WriteFile(knownHostsPath, []byte{}, 0600); err != nil {
			return nil, errors.Wrap(err, "failed to create known_hosts file")
		}
	}

	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse known_hosts file")
	}

	// Wrap the callback to provide better error messages and optionally allow
	// new host key acceptance (with logging)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		log.Debugf("Verifying host key for %s (key type: %s)", hostname, key.Type())
		err := callback(hostname, remote, key)
		if err != nil {
			// Check if it's a key mismatch error vs a new host
			if keyErr, ok := err.(*knownhosts.KeyError); ok && len(keyErr.Want) > 0 {
				// Host key changed - this is a security concern
				log.Errorf("SSH host key mismatch for %s", hostname)
				log.Errorf("  Hostname passed to callback: %q", hostname)
				log.Errorf("  Remote address: %s", remote.String())
				log.Errorf("  Normalized hostname: %q", knownhosts.Normalize(hostname))
				if remote != nil {
					log.Errorf("  Normalized remote: %q", knownhosts.Normalize(remote.String()))
				}
				log.Errorf("  Server offered key type: %s", key.Type())
				log.Errorf("  Server offered fingerprint: %s", ssh.FingerprintSHA256(key))
				log.Errorf("  Known hosts file: %s", knownHostsPath)
				log.Errorf("  Found %d matching entries in known_hosts:", len(keyErr.Want))
				for i, want := range keyErr.Want {
					log.Errorf("    #%d: %s:%d type=%s fingerprint=%s",
						i+1, want.Filename, want.Line, want.Key.Type(), ssh.FingerprintSHA256(want.Key))
				}
				log.Errorf("  None of the known_hosts entries match the server's key.")
				log.Errorf("  This could mean:")
				log.Errorf("    - The host key has genuinely changed (security concern)")
				log.Errorf("    - known_hosts has entries for IP address with different keys")
				log.Errorf("    - There are stale entries that need to be removed")
				return errors.Wrapf(err, "SSH host key verification failed for %s: host key has changed", hostname)
			}
			// New host - behavior depends on configuration
			if c.config.AutoAddHostKey {
				// Allow auto-adding unknown hosts (less secure, mainly for testing)
				log.Warnf("SSH host %s (%s) is not in known_hosts file but AutoAddHostKey is enabled. Key fingerprint: %s",
					hostname, remote.String(), ssh.FingerprintSHA256(key))
				log.Warnf("Auto-accepting host key. Consider adding this host to known_hosts for better security.")
				// Append to known_hosts file
				if appendErr := c.appendToKnownHosts(hostname, remote, key); appendErr != nil {
					log.Errorf("Failed to add host key to known_hosts: %v", appendErr)
					return errors.Wrap(appendErr, "failed to add host key to known_hosts")
				}
				log.Infof("Added host key for %s to known_hosts file", hostname)
				return nil
			} else {
				// Reject unknown hosts for security (default behavior in server mode)
				log.Errorf("SSH host %s (%s) is not in known_hosts file. Key fingerprint: %s",
					hostname, remote.String(), ssh.FingerprintSHA256(key))
				log.Errorf("For security, unknown hosts are rejected by default.")
				log.Errorf("To allow this connection:")
				log.Errorf("  1. Add the host to known_hosts manually: ssh-keyscan -H %s >> %s", hostname, knownHostsPath)
				log.Errorf("  2. Or set Origin.SSH.AutoAddHostKey=true (not recommended for production)")
				return errors.Wrapf(err, "SSH host %s is not in known_hosts file", hostname)
			}
		}
		log.Debugf("Host key verification succeeded for %s", hostname)
		return nil
	}, nil
}

// appendToKnownHosts adds a host key to the known_hosts file
func (c *SSHConnection) appendToKnownHosts(hostname string, remote net.Addr, key ssh.PublicKey) error {
	knownHostsPath, err := c.getKnownHostsPath()
	if err != nil {
		return err
	}

	// Open file in append mode
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "failed to open known_hosts file")
	}
	defer f.Close()

	// Format the host key entry
	// Use knownhosts.Normalize to ensure consistent formatting
	normalizedHost := knownhosts.Normalize(hostname)
	line := knownhosts.Line([]string{normalizedHost}, key)

	// Write to file
	if _, err := f.WriteString(line + "\n"); err != nil {
		return errors.Wrap(err, "failed to write to known_hosts file")
	}

	return nil
}

// parseProxyJumpSpec parses a ProxyJump spec like [user@]host[:port]
func parseProxyJumpSpec(spec, defaultUser string) (user, host string, port int) {
	port = 22
	user = defaultUser

	// Handle user@host:port format
	if atIdx := strings.Index(spec, "@"); atIdx != -1 {
		user = spec[:atIdx]
		spec = spec[atIdx+1:]
	}

	// Handle host:port format
	if colonIdx := strings.LastIndex(spec, ":"); colonIdx != -1 {
		host = spec[:colonIdx]
		if p, err := strconv.Atoi(spec[colonIdx+1:]); err == nil {
			port = p
		}
	} else {
		host = spec
	}

	return user, host, port
}

// sshNewClientConnWithContext wraps ssh.NewClientConn with context support.
// It runs the handshake in a goroutine and cancels by closing the connection if the context is cancelled.
func sshNewClientConnWithContext(ctx context.Context, conn net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	type result struct {
		sshConn ssh.Conn
		chans   <-chan ssh.NewChannel
		reqs    <-chan *ssh.Request
		err     error
	}

	done := make(chan result, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
		done <- result{sshConn, chans, reqs, err}
	}()

	select {
	case <-ctx.Done():
		// Context cancelled - close the connection to abort the handshake
		conn.Close()
		// Wait for the goroutine to finish to avoid leaking it
		wg.Wait()
		return nil, nil, nil, ctx.Err()
	case r := <-done:
		return r.sshConn, r.chans, r.reqs, r.err
	}
}

// dialViaProxyWithContext dials through an SSH client with context cancellation support.
// It runs the dial in a goroutine and returns an error if the context is cancelled.
func dialViaProxyWithContext(ctx context.Context, client *ssh.Client, network, addr string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}

	done := make(chan result, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := client.Dial(network, addr)
		done <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		// Context cancelled - we can't cancel the dial, but we wait for it
		// and close the connection if it succeeded
		wg.Wait()
		select {
		case r := <-done:
			if r.conn != nil {
				r.conn.Close()
			}
		default:
		}
		return nil, ctx.Err()
	case r := <-done:
		return r.conn, r.err
	}
}

// dialViaProxy establishes an SSH connection through a proxy jump host
func (c *SSHConnection) dialViaProxy(ctx context.Context, targetAddr string, targetConfig *ssh.ClientConfig) (*ssh.Client, error) {
	// Parse the proxy jump specification
	// Format: [user@]host[:port] or chained: host1,host2
	proxySpecs := strings.Split(c.config.ProxyJump, ",")

	// Build chain of proxy connections
	var proxyClients []*ssh.Client
	success := false

	// Cleanup proxy clients on failure; disabled on success
	defer func() {
		if !success {
			for _, pc := range proxyClients {
				pc.Close()
			}
		}
	}()

	for i, spec := range proxySpecs {
		// Check context before each hop
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		proxyUser, proxyHost, proxyPort := parseProxyJumpSpec(spec, c.config.User)
		proxyAddr := net.JoinHostPort(proxyHost, strconv.Itoa(proxyPort))

		log.Debugf("Connecting to proxy hop %d: %s@%s:%d", i+1, proxyUser, proxyHost, proxyPort)

		// Get preferred host key algorithms for this proxy hop
		preferredAlgorithms := c.getHostKeyAlgorithmsForHost(proxyHost, proxyPort)
		if len(preferredAlgorithms) > 0 {
			log.Debugf("Using preferred host key algorithms for %s: %v", proxyHost, preferredAlgorithms)
		}

		// Build auth methods for proxy (reuse same methods as target)
		proxyConfig := &ssh.ClientConfig{
			User:              proxyUser,
			Auth:              targetConfig.Auth,
			HostKeyCallback:   targetConfig.HostKeyCallback,
			HostKeyAlgorithms: preferredAlgorithms,
			Timeout:           targetConfig.Timeout,
		}
		if proxyConfig.Timeout == 0 {
			proxyConfig.Timeout = DefaultSSHHandshakeTimeout
		}

		var proxyClient *ssh.Client
		var err error

		if len(proxyClients) == 0 {
			// First hop - direct connection with context support
			log.Debugf("Dialing proxy hop %d directly at %s", i+1, proxyAddr)
			proxyClient, err = sshDialContext(ctx, "tcp", proxyAddr, proxyConfig)
		} else {
			// Subsequent hop - tunnel through previous proxy
			prevClient := proxyClients[len(proxyClients)-1]
			conn, dialErr := dialViaProxyWithContext(ctx, prevClient, "tcp", proxyAddr)
			if dialErr != nil {
				return nil, errors.Wrapf(dialErr, "failed to dial proxy hop %d through tunnel", i+1)
			}

			// Perform SSH handshake with context support
			ncc, chans, reqs, connErr := sshNewClientConnWithContext(ctx, conn, proxyAddr, proxyConfig)
			if connErr != nil {
				conn.Close()
				return nil, errors.Wrapf(connErr, "failed to establish SSH connection to proxy hop %d", i+1)
			}
			proxyClient = ssh.NewClient(ncc, chans, reqs)
		}

		if err != nil {
			return nil, errors.Wrapf(err, "failed to connect to proxy hop %d: %s@%s:%d", i+1, proxyUser, proxyHost, proxyPort)
		}

		log.Debugf("Proxy hop %d established successfully", i+1)
		proxyClients = append(proxyClients, proxyClient)
	}

	if len(proxyClients) == 0 {
		return nil, errors.New("no valid proxy hosts in ProxyJump specification")
	}

	// Check context before final hop
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Now connect to the target through the last proxy
	lastProxy := proxyClients[len(proxyClients)-1]
	log.Debugf("Opening TCP connection to target %s through proxy chain...", targetAddr)

	conn, err := dialViaProxyWithContext(ctx, lastProxy, "tcp", targetAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to dial target %s through proxy", targetAddr)
	}
	log.Debugf("TCP connection to target established, starting SSH handshake (may require another Yubikey touch)...")

	// Final handshake with context support
	ncc, chans, reqs, err := sshNewClientConnWithContext(ctx, conn, targetAddr, targetConfig)
	if err != nil {
		conn.Close()
		return nil, errors.Wrapf(err, "failed to establish SSH connection to target %s", targetAddr)
	}

	// Store proxy clients so they can be closed when the main connection closes
	c.proxyClients = proxyClients
	success = true // Disable cleanup in defer

	return ssh.NewClient(ncc, chans, reqs), nil
}

// Connect establishes the SSH connection to the remote host
func (c *SSHConnection) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.GetState() != StateDisconnected {
		return errors.New("connection already in progress or established")
	}

	c.setState(StateConnecting)

	log.Debugf("Building SSH auth methods...")
	// Build auth methods
	authMethods, err := c.buildSSHAuthMethods(ctx)
	if err != nil {
		c.setState(StateDisconnected)
		return errors.Wrap(err, "failed to build SSH auth methods")
	}
	log.Debugf("Built %d auth methods", len(authMethods))

	log.Debugf("Building host key callback...")
	// Build host key callback
	hostKeyCallback, err := c.buildHostKeyCallback()
	if err != nil {
		c.setState(StateDisconnected)
		return errors.Wrap(err, "failed to build host key callback")
	}
	log.Debugf("Host key callback built")

	// Build SSH client config
	sshConfig := &ssh.ClientConfig{
		User:            c.config.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         c.config.ConnectTimeout,
	}

	if sshConfig.Timeout == 0 {
		sshConfig.Timeout = 30 * time.Second
	}

	// Determine the address
	port := c.config.Port
	if port == 0 {
		port = 22
	}

	log.Debugf("Getting preferred host key algorithms for %s:%d...", c.config.Host, port)
	// Get preferred host key algorithms for the target host
	preferredAlgorithms := c.getHostKeyAlgorithmsForHost(c.config.Host, port)
	if len(preferredAlgorithms) > 0 {
		log.Debugf("Using preferred host key algorithms for %s: %v", c.config.Host, preferredAlgorithms)
		sshConfig.HostKeyAlgorithms = preferredAlgorithms
	} else {
		log.Debugf("No preferred host key algorithms found for %s", c.config.Host)
	}
	addr := net.JoinHostPort(c.config.Host, strconv.Itoa(port))

	c.setState(StateAuthenticating)
	log.Debugf("Starting SSH connection to %s", addr)

	// Establish the connection (directly or through proxy)
	var client *ssh.Client
	if c.config.ProxyJump != "" {
		log.Infof("Connecting to SSH server %s@%s:%d via ProxyJump %s", c.config.User, c.config.Host, port, c.config.ProxyJump)
		client, err = c.dialViaProxy(ctx, addr, sshConfig)
	} else {
		log.Infof("Connecting to SSH server %s@%s:%d", c.config.User, c.config.Host, port)
		client, err = sshDialContext(ctx, "tcp", addr, sshConfig)
	}
	if err != nil {
		c.setState(StateDisconnected)
		return errors.Wrap(err, "failed to establish SSH connection")
	}

	c.client = client
	c.setState(StateConnected)
	c.setLastKeepalive(time.Now())

	log.Infof("SSH connection established to %s@%s:%d", c.config.User, c.config.Host, port)

	return nil
}

// Close closes the SSH connection. It is not context-aware because SSH close operations
// should complete regardless of context cancellation to ensure clean resource cleanup.
// The underlying ssh.Client.Close() will wait for in-flight operations to complete.
func (c *SSHConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.setState(StateShuttingDown)

	var errs []error

	if c.session != nil {
		if err := c.session.Close(); err != nil {
			errs = append(errs, errors.Wrap(err, "failed to close SSH session"))
		}
		c.session = nil
	}

	if c.client != nil {
		if err := c.client.Close(); err != nil {
			errs = append(errs, errors.Wrap(err, "failed to close SSH client"))
		}
		c.client = nil
	}

	// Close proxy clients in reverse order (innermost to outermost)
	for i := len(c.proxyClients) - 1; i >= 0; i-- {
		if err := c.proxyClients[i].Close(); err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to close proxy client %d", i))
		}
	}
	c.proxyClients = nil

	if c.cancelFunc != nil {
		c.cancelFunc()
	}

	c.setState(StateDisconnected)

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
