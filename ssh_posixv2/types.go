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

// Package ssh_posixv2 implements an SSH-based POSIXv2 backend for Pelican origins.
// It transfers the pelican binary over SSH to a remote host and executes it as a
// helper process that connects back to the origin via the broker mechanism.
package ssh_posixv2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultKeepaliveInterval is the interval between keepalive pings
	DefaultKeepaliveInterval = 5 * time.Second

	// DefaultKeepaliveTimeout is the timeout for a keepalive response
	DefaultKeepaliveTimeout = 20 * time.Second

	// DefaultReconnectDelay is the initial delay before attempting to reconnect
	DefaultReconnectDelay = 1 * time.Second

	// MaxReconnectDelay is the maximum delay before attempting to reconnect
	MaxReconnectDelay = 30 * time.Second

	// DefaultMaxRetries is the maximum number of connection retries
	DefaultMaxRetries = 5
)

// AuthMethod represents the type of SSH authentication to use
type AuthMethod string

const (
	// AuthMethodPassword authenticates using a password from a file
	AuthMethodPassword AuthMethod = "password"

	// AuthMethodPublicKey authenticates using SSH public key
	AuthMethodPublicKey AuthMethod = "publickey"

	// AuthMethodKeyboardInteractive authenticates via keyboard-interactive (requires user input)
	AuthMethodKeyboardInteractive AuthMethod = "keyboard-interactive"

	// AuthMethodAgent authenticates using the SSH agent
	AuthMethodAgent AuthMethod = "agent"
)

// PlatformInfo contains information about the remote platform
type PlatformInfo struct {
	// OS is the operating system (output of `uname -s`)
	OS string

	// Arch is the architecture (output of `uname -m`)
	Arch string
}

// HelperConfig is the configuration sent to the remote helper process
type HelperConfig struct {
	// OriginCallbackURL is the URL the helper should use to connect back for connection reversal
	OriginCallbackURL string `json:"origin_callback_url"`

	// AuthCookie is a randomly-generated cookie for authenticating the callback
	AuthCookie string `json:"auth_cookie"`

	// Exports contains the export configurations
	Exports []ExportConfig `json:"exports"`

	// CertificateChain is the PEM-encoded public certificate chain
	CertificateChain string `json:"certificate_chain"`

	// KeepaliveInterval is how often to send keepalive pings
	KeepaliveInterval time.Duration `json:"keepalive_interval"`

	// KeepaliveTimeout is the maximum time to wait for keepalive response
	KeepaliveTimeout time.Duration `json:"keepalive_timeout"`
}

// ExportConfig represents a single export path configuration
type ExportConfig struct {
	// FederationPrefix is the prefix in the federation namespace
	FederationPrefix string `json:"federation_prefix"`

	// StoragePrefix is the local path on the remote system
	StoragePrefix string `json:"storage_prefix"`

	// Capabilities defines what operations are allowed
	Capabilities ExportCapabilities `json:"capabilities"`
}

// ExportCapabilities defines the allowed operations for an export
type ExportCapabilities struct {
	PublicReads bool `json:"public_reads"`
	Reads       bool `json:"reads"`
	Writes      bool `json:"writes"`
	Listings    bool `json:"listings"`
	DirectReads bool `json:"direct_reads"`
}

// SSHConfig contains the SSH connection configuration
type SSHConfig struct {
	// Host is the remote SSH server hostname or IP
	Host string

	// Port is the SSH port (default: 22)
	Port int

	// User is the SSH username
	User string

	// AuthMethods is the list of authentication methods to try, in order
	AuthMethods []AuthMethod

	// PasswordFile is the path to a file containing the password
	// (used with AuthMethodPassword)
	PasswordFile string

	// PrivateKeyFile is the path to the SSH private key file
	// (used with AuthMethodPublicKey)
	PrivateKeyFile string

	// PrivateKeyPassphraseFile is the path to a file containing the key passphrase
	// (used with AuthMethodPublicKey if the key is encrypted)
	PrivateKeyPassphraseFile string

	// KnownHostsFile is the path to the known_hosts file for host verification
	// If empty, the default ~/.ssh/known_hosts is used
	KnownHostsFile string

	// AutoAddHostKey controls whether unknown host keys should be automatically accepted
	// When false (default), connections to unknown hosts will fail
	// When true, unknown hosts will be accepted (less secure, suitable for testing only)
	AutoAddHostKey bool

	// PelicanBinaryPath is the local path to the Pelican binary to transfer
	// If empty, the current executable is used
	PelicanBinaryPath string

	// RemotePelicanBinaryDir is the directory on the remote host for the Pelican binary
	// If empty, a temporary directory is used
	RemotePelicanBinaryDir string

	// RemotePelicanBinaryOverrides maps platform (os/arch) to binary path
	// Format: "linux/amd64" -> "/path/to/pelican-linux-amd64"
	// This allows using pre-deployed binaries on the remote system
	RemotePelicanBinaryOverrides map[string]string

	// MaxRetries is the maximum number of connection retries
	MaxRetries int

	// ConnectTimeout is the timeout for establishing the SSH connection
	ConnectTimeout time.Duration

	// ChallengeTimeout is the timeout for individual authentication challenges
	// (e.g., password prompts, keyboard-interactive questions)
	// Default: 5 minutes
	ChallengeTimeout time.Duration

	// ProxyJump specifies a jump host for the connection (similar to ssh -J)
	// Format: [user@]host[:port] or [user@]host[:port],[user@]host[:port] for chained jumps
	ProxyJump string
}

// Validate validates the SSH configuration
func (c *SSHConfig) Validate() error {
	if c.Host == "" {
		return errors.New("SSH host is required")
	}
	if c.User == "" {
		return errors.New("SSH user is required")
	}
	if len(c.AuthMethods) == 0 {
		return errors.New("at least one SSH auth method is required")
	}

	for _, method := range c.AuthMethods {
		switch method {
		case AuthMethodPublicKey:
			if c.PrivateKeyFile == "" {
				return errors.New("private key file is required for publickey auth")
			}
		case AuthMethodPassword:
			// Password can come from file or WebSocket - no validation needed here
		case AuthMethodKeyboardInteractive, AuthMethodAgent:
			// No additional validation needed
		default:
			return errors.Errorf("unknown auth method: %s", method)
		}
	}

	return nil
}

// ConnectionState represents the state of the SSH connection
type ConnectionState int32

const (
	// StateDisconnected means no active connection
	StateDisconnected ConnectionState = iota

	// StateConnecting means a connection attempt is in progress
	StateConnecting

	// StateAuthenticating means authentication is in progress
	StateAuthenticating

	// StateWaitingForUserInput means waiting for keyboard-interactive input
	StateWaitingForUserInput

	// StateConnected means the connection is established
	StateConnected

	// StateRunningHelper means the helper process is running
	StateRunningHelper

	// StateShuttingDown means the connection is being closed
	StateShuttingDown
)

// String returns a human-readable connection state
func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateAuthenticating:
		return "authenticating"
	case StateWaitingForUserInput:
		return "waiting_for_user_input"
	case StateConnected:
		return "connected"
	case StateRunningHelper:
		return "running_helper"
	case StateShuttingDown:
		return "shutting_down"
	default:
		return "unknown"
	}
}

// KeyboardInteractiveChallenge represents a challenge from the SSH server
type KeyboardInteractiveChallenge struct {
	// SessionID is the unique identifier for this authentication session
	SessionID string `json:"session_id"`

	// User is the username being authenticated
	User string `json:"user"`

	// Instruction is the instruction from the SSH server
	Instruction string `json:"instruction"`

	// Questions contains the challenge questions
	Questions []KeyboardInteractiveQuestion `json:"questions"`
}

// KeyboardInteractiveQuestion represents a single question in a challenge
type KeyboardInteractiveQuestion struct {
	// Prompt is the question text
	Prompt string `json:"prompt"`

	// Echo indicates whether the response should be echoed (e.g., username vs password)
	Echo bool `json:"echo"`
}

// KeyboardInteractiveResponse contains the user's responses to a challenge
type KeyboardInteractiveResponse struct {
	// SessionID is the unique identifier for this authentication session
	SessionID string `json:"session_id"`

	// Answers contains the answers to the challenge questions
	Answers []string `json:"answers"`
}

// SSHConnection represents an active SSH connection to a remote host
type SSHConnection struct {
	// config is the SSH configuration
	config *SSHConfig

	// client is the SSH client connection
	client *ssh.Client

	// proxyClients are SSH clients for proxy jump hosts (in order of connection)
	proxyClients []*ssh.Client

	// session is the current SSH session (for running the helper)
	session *ssh.Session

	// state is the current connection state
	state atomic.Int32

	// lastKeepalive is the time of the last successful keepalive
	lastKeepalive atomic.Value // time.Time

	// cancelFunc cancels the connection context
	cancelFunc context.CancelFunc

	// mu protects connection state changes
	mu sync.Mutex

	// helperConfig is the configuration to send to the helper
	helperConfig *HelperConfig

	// remoteBinaryPath is the path to the Pelican binary on the remote host
	remoteBinaryPath string

	// remoteBinaryIsCached indicates if the binary is in a persistent cache location
	// (e.g., ~/.pelican) and should NOT be cleaned up on disconnect
	remoteBinaryIsCached bool

	// remoteTempDir is the temp directory created on the remote host (if any)
	// This will be cleaned up on disconnect
	remoteTempDir string

	// platformInfo contains information about the remote platform
	platformInfo *PlatformInfo

	// keyboardChan is used to send keyboard-interactive challenges to the WebSocket handler
	keyboardChan chan KeyboardInteractiveChallenge

	// responseChan is used to receive keyboard-interactive responses from the WebSocket handler
	responseChan chan KeyboardInteractiveResponse

	// errChan is used to signal errors from the helper process
	errChan chan error
}

// GetState returns the current connection state
func (c *SSHConnection) GetState() ConnectionState {
	return ConnectionState(c.state.Load())
}

// setState sets the connection state
func (c *SSHConnection) setState(state ConnectionState) {
	c.state.Store(int32(state))
}

// GetLastKeepalive returns the time of the last successful keepalive
func (c *SSHConnection) GetLastKeepalive() time.Time {
	if v := c.lastKeepalive.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

// setLastKeepalive updates the last keepalive time
func (c *SSHConnection) setLastKeepalive(t time.Time) {
	c.lastKeepalive.Store(t)
}

// KeyboardChan returns the channel for keyboard-interactive challenges
// This is used by test code and WebSocket handlers
func (c *SSHConnection) KeyboardChan() <-chan KeyboardInteractiveChallenge {
	return c.keyboardChan
}

// ResponseChan returns the channel for keyboard-interactive responses
// This is used by test code and WebSocket handlers
func (c *SSHConnection) ResponseChan() chan<- KeyboardInteractiveResponse {
	return c.responseChan
}

// InitializeAuthChannels creates the channels for WebSocket-based authentication
// This must be called before Connect() if WebSocket auth is desired
func (c *SSHConnection) InitializeAuthChannels() {
	if c.keyboardChan == nil {
		c.keyboardChan = make(chan KeyboardInteractiveChallenge, 10)
	}
	if c.responseChan == nil {
		c.responseChan = make(chan KeyboardInteractiveResponse, 10)
	}
}

// SSHBackend manages SSH POSIXv2 connections
type SSHBackend struct {
	// connections is a map of active connections by host
	connections map[string]*SSHConnection

	// mu protects the connections map
	mu sync.RWMutex

	// ctx is the backend context
	ctx context.Context

	// cancelFunc cancels all connections
	cancelFunc context.CancelFunc

	// helperBroker manages reverse connections to helpers
	helperBroker *HelperBroker
}

// generateAuthCookie generates a cryptographically secure random cookie
func generateAuthCookie() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetLocalAddr returns the local network address of the SSH connection
func (c *SSHConnection) GetLocalAddr() net.Addr {
	if c.client != nil {
		return c.client.LocalAddr()
	}
	return nil
}

// GetRemoteAddr returns the remote network address of the SSH connection
func (c *SSHConnection) GetRemoteAddr() net.Addr {
	if c.client != nil {
		return c.client.RemoteAddr()
	}
	return nil
}
