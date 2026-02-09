//go:build !windows

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

package ssh_posixv2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testSSHServerConfig holds the configuration for a test SSH server
type testSSHServerConfig struct {
	// password is the password to accept for password auth
	password string

	// keyboardInteractivePrompts defines the prompts and expected answers
	keyboardInteractivePrompts []testKIPrompt

	// publicKey is the authorized public key for publickey auth
	publicKey ssh.PublicKey

	// hostKey is the server's host key
	hostKey ssh.Signer
}

// testKIPrompt defines a keyboard-interactive prompt
type testKIPrompt struct {
	Prompt string
	Echo   bool
	Answer string
}

// testSSHServerGo represents a Go-based SSH server for testing
type testSSHServerGo struct {
	listener    net.Listener
	config      *ssh.ServerConfig
	testConfig  *testSSHServerConfig
	port        int
	tempDir     string
	knownHosts  string
	wg          sync.WaitGroup
	stopCh      chan struct{}
	connections []net.Conn
	connMu      sync.Mutex
}

// startTestSSHServerGo starts a Go-based SSH server for authentication testing
func startTestSSHServerGo(t *testing.T, cfg *testSSHServerConfig) (*testSSHServerGo, error) {
	tempDir := t.TempDir()

	// Generate host key if not provided
	if cfg.hostKey == nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate host key: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer: %w", err)
		}
		cfg.hostKey = signer
	}

	// Create SSH server config
	serverConfig := &ssh.ServerConfig{}

	// Add password auth if password is set
	if cfg.password != "" {
		serverConfig.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "testuser" && string(pass) == cfg.password {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		}
	}

	// Add keyboard-interactive auth if prompts are defined
	if len(cfg.keyboardInteractivePrompts) > 0 {
		serverConfig.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// Build prompts and echos
			prompts := make([]string, len(cfg.keyboardInteractivePrompts))
			echos := make([]bool, len(cfg.keyboardInteractivePrompts))
			expectedAnswers := make([]string, len(cfg.keyboardInteractivePrompts))

			for i, p := range cfg.keyboardInteractivePrompts {
				prompts[i] = p.Prompt
				echos[i] = p.Echo
				expectedAnswers[i] = p.Answer
			}

			// Send the challenge
			answers, err := client(c.User(), "Test Authentication", prompts, echos)
			if err != nil {
				return nil, err
			}

			// Verify answers
			if len(answers) != len(expectedAnswers) {
				return nil, fmt.Errorf("expected %d answers, got %d", len(expectedAnswers), len(answers))
			}

			for i, expected := range expectedAnswers {
				if answers[i] != expected {
					return nil, fmt.Errorf("answer %d mismatch: expected %q, got %q", i, expected, answers[i])
				}
			}

			return &ssh.Permissions{}, nil
		}
	}

	// Add publickey auth if public key is set
	if cfg.publicKey != nil {
		serverConfig.PublicKeyCallback = func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if string(pubKey.Marshal()) == string(cfg.publicKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		}
	}

	serverConfig.AddHostKey(cfg.hostKey)

	// Start the listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	// Create known_hosts file
	// Format: [host]:port key-type base64-key
	hostPubKey := cfg.hostKey.PublicKey()
	knownHostsPath := filepath.Join(tempDir, "known_hosts")
	// MarshalAuthorizedKey already includes the key type and base64 data
	authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostPubKey)))
	knownHostsLine := fmt.Sprintf("[127.0.0.1]:%d %s\n", port, authorizedKey)
	if err := os.WriteFile(knownHostsPath, []byte(knownHostsLine), 0644); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to write known_hosts: %w", err)
	}

	server := &testSSHServerGo{
		listener:   listener,
		config:     serverConfig,
		testConfig: cfg,
		port:       port,
		tempDir:    tempDir,
		knownHosts: knownHostsPath,
		stopCh:     make(chan struct{}),
	}

	// Start accepting connections
	server.wg.Add(1)
	go server.acceptConnections()

	return server, nil
}

// acceptConnections accepts and handles SSH connections
func (s *testSSHServerGo) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		// Set a deadline so we can check stopCh periodically
		_ = s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))

		conn, err := s.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}

		s.connMu.Lock()
		s.connections = append(s.connections, conn)
		s.connMu.Unlock()

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SSH connection
func (s *testSSHServerGo) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		// Auth failed - this is expected in some tests
		return
	}
	defer sshConn.Close()

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
			defer ch.Close()
			for req := range reqs {
				switch req.Type {
				case "exec":
					// Simple command execution
					if len(req.Payload) > 4 {
						cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
						if len(req.Payload) >= 4+cmdLen {
							cmd := string(req.Payload[4 : 4+cmdLen])
							// Handle simple commands for testing
							switch {
							case cmd == "echo hello":
								_, _ = ch.Write([]byte("hello\n"))
							case strings.HasPrefix(cmd, "echo "):
								_, _ = ch.Write([]byte(cmd[5:] + "\n"))
							default:
								_, _ = ch.Write([]byte("unknown command\n"))
							}
						}
					}
					_ = req.Reply(true, nil)
					// Send exit status and close the channel to signal completion
					_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					_ = ch.CloseWrite()
					return // Exit the goroutine to close the channel
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}(channel, requests)
	}
}

// stop stops the test SSH server
func (s *testSSHServerGo) stop() {
	close(s.stopCh)
	s.listener.Close()

	s.connMu.Lock()
	for _, conn := range s.connections {
		conn.Close()
	}
	s.connMu.Unlock()

	s.wg.Wait()
}

// TestPasswordAuthentication tests SSH password authentication
func TestPasswordAuthentication(t *testing.T) {
	// Create test server with password auth
	serverCfg := &testSSHServerConfig{
		password: "secretpassword123",
	}

	server, err := startTestSSHServerGo(t, serverCfg)
	require.NoError(t, err)
	defer server.stop()

	// Create password file
	passwordFile := filepath.Join(server.tempDir, "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte("secretpassword123"), 0600))

	// Create SSH config
	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           server.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodPassword},
		PasswordFile:   passwordFile,
		KnownHostsFile: server.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}

	// Connect
	conn := NewSSHConnection(sshConfig)
	ctx := context.Background()
	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	// Verify connection
	assert.Equal(t, StateConnected, conn.GetState())

	// Run a command to verify the connection works
	session, err := conn.client.NewSession()
	require.NoError(t, err)
	output, err := session.Output("echo hello")
	session.Close()
	require.NoError(t, err)
	assert.Equal(t, "hello\n", string(output))
}

// TestPasswordAuthenticationWrongPassword tests password auth with wrong password
func TestPasswordAuthenticationWrongPassword(t *testing.T) {
	serverCfg := &testSSHServerConfig{
		password: "correctpassword",
	}

	server, err := startTestSSHServerGo(t, serverCfg)
	require.NoError(t, err)
	defer server.stop()

	// Create password file with wrong password
	passwordFile := filepath.Join(server.tempDir, "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte("wrongpassword"), 0600))

	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           server.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodPassword},
		PasswordFile:   passwordFile,
		KnownHostsFile: server.knownHosts,
		ConnectTimeout: 5 * time.Second,
	}

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to authenticate")
}

// TestKeyboardInteractiveLocal tests keyboard-interactive with local channel-based responses
func TestKeyboardInteractiveLocal(t *testing.T) {
	// Create test server with keyboard-interactive auth
	serverCfg := &testSSHServerConfig{
		keyboardInteractivePrompts: []testKIPrompt{
			{Prompt: "Password: ", Echo: false, Answer: "mypassword"},
			{Prompt: "OTP Code: ", Echo: true, Answer: "123456"},
		},
	}

	server, err := startTestSSHServerGo(t, serverCfg)
	require.NoError(t, err)
	defer server.stop()

	// Create SSH config
	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           server.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodKeyboardInteractive},
		KnownHostsFile: server.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}

	conn := NewSSHConnection(sshConfig)
	ctx := context.Background()

	// Start a goroutine to respond to keyboard-interactive challenges
	go func() {
		// Wait for the challenge
		select {
		case challenge := <-conn.GetKeyboardChannel():
			// Verify challenge structure
			assert.Len(t, challenge.Questions, 2)
			assert.Equal(t, "Password: ", challenge.Questions[0].Prompt)
			assert.False(t, challenge.Questions[0].Echo)
			assert.Equal(t, "OTP Code: ", challenge.Questions[1].Prompt)
			assert.True(t, challenge.Questions[1].Echo)

			// Send response
			response := KeyboardInteractiveResponse{
				SessionID: challenge.SessionID,
				Answers:   []string{"mypassword", "123456"},
			}
			conn.GetResponseChannel() <- response

		case <-time.After(5 * time.Second):
			t.Error("Timeout waiting for keyboard-interactive challenge")
		}
	}()

	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, StateConnected, conn.GetState())
}

// TestKeyboardInteractiveWrongAnswer tests keyboard-interactive with wrong answers
func TestKeyboardInteractiveWrongAnswer(t *testing.T) {
	serverCfg := &testSSHServerConfig{
		keyboardInteractivePrompts: []testKIPrompt{
			{Prompt: "Password: ", Echo: false, Answer: "correctanswer"},
		},
	}

	server, err := startTestSSHServerGo(t, serverCfg)
	require.NoError(t, err)
	defer server.stop()

	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           server.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodKeyboardInteractive},
		KnownHostsFile: server.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}

	conn := NewSSHConnection(sshConfig)
	ctx := context.Background()

	// Respond with wrong answer
	go func() {
		select {
		case challenge := <-conn.GetKeyboardChannel():
			response := KeyboardInteractiveResponse{
				SessionID: challenge.SessionID,
				Answers:   []string{"wronganswer"},
			}
			conn.GetResponseChannel() <- response
		case <-time.After(5 * time.Second):
			t.Error("Timeout waiting for challenge")
		}
	}()

	err = conn.Connect(ctx)
	assert.Error(t, err)
}

// TestKeyboardInteractiveWebSocket tests keyboard-interactive auth via WebSocket
func TestKeyboardInteractiveWebSocket(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create test server with keyboard-interactive auth
	serverCfg := &testSSHServerConfig{
		keyboardInteractivePrompts: []testKIPrompt{
			{Prompt: "Enter token: ", Echo: false, Answer: "token123"},
		},
	}

	sshServer, err := startTestSSHServerGo(t, serverCfg)
	require.NoError(t, err)
	defer sshServer.stop()

	// Create SSH config
	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           sshServer.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodKeyboardInteractive},
		KnownHostsFile: sshServer.knownHosts,
		ConnectTimeout: 30 * time.Second,
	}

	conn := NewSSHConnection(sshConfig)

	// Create a test Gin router with the WebSocket handler
	router := gin.New()

	// Create a test-specific WebSocket handler that works with our connection
	router.GET("/ws/auth", func(c *gin.Context) {
		ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			t.Errorf("WebSocket upgrade failed: %v", err)
			return
		}
		defer ws.Close()

		// Forward challenges from SSH connection to WebSocket
		go func() {
			for challenge := range conn.GetKeyboardChannel() {
				msg := WebSocketMessage{
					Type: WsMsgTypeChallenge,
				}
				msg.Payload, _ = json.Marshal(challenge)
				msgBytes, _ := json.Marshal(msg)
				_ = ws.WriteMessage(websocket.TextMessage, msgBytes)
			}
		}()

		// Read responses from WebSocket and forward to SSH connection
		for {
			_, message, err := ws.ReadMessage()
			if err != nil {
				break
			}

			var msg WebSocketMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				continue
			}

			if msg.Type == WsMsgTypeResponse {
				var response KeyboardInteractiveResponse
				if err := json.Unmarshal(msg.Payload, &response); err != nil {
					continue
				}
				conn.GetResponseChannel() <- response
			}
		}
	})

	// Start test HTTP server
	httpServer := httptest.NewServer(router)
	defer httpServer.Close()

	// Create WebSocket client
	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws/auth"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer wsConn.Close()

	// Start SSH connection in a goroutine
	connErr := make(chan error, 1)
	go func() {
		connErr <- conn.Connect(context.Background())
	}()

	// Wait for challenge and respond via WebSocket
	go func() {
		for {
			_, message, err := wsConn.ReadMessage()
			if err != nil {
				return
			}

			var msg WebSocketMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				continue
			}

			if msg.Type == WsMsgTypeChallenge {
				var challenge KeyboardInteractiveChallenge
				if err := json.Unmarshal(msg.Payload, &challenge); err != nil {
					continue
				}

				// Send response
				response := KeyboardInteractiveResponse{
					SessionID: challenge.SessionID,
					Answers:   []string{"token123"},
				}

				respPayload, _ := json.Marshal(response)
				respMsg := WebSocketMessage{
					Type:    WsMsgTypeResponse,
					Payload: respPayload,
				}
				respBytes, _ := json.Marshal(respMsg)
				_ = wsConn.WriteMessage(websocket.TextMessage, respBytes)
				return
			}
		}
	}()

	// Wait for connection result
	select {
	case err := <-connErr:
		require.NoError(t, err)
		assert.Equal(t, StateConnected, conn.GetState())
		conn.Close()
	case <-time.After(15 * time.Second):
		t.Fatal("Timeout waiting for SSH connection")
	}
}

// TestMultipleAuthMethods tests fallback between auth methods
func TestMultipleAuthMethods(t *testing.T) {
	// Server only accepts password auth
	serverCfg := &testSSHServerConfig{
		password: "mysecret",
	}

	server, err := startTestSSHServerGo(t, serverCfg)
	require.NoError(t, err)
	defer server.stop()

	// Create password file
	passwordFile := filepath.Join(server.tempDir, "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte("mysecret"), 0600))

	// Create a fake private key file (publickey auth will fail)
	fakeKeyFile := filepath.Join(server.tempDir, "fake_key")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	pemData := pem.EncodeToMemory(block)
	require.NoError(t, os.WriteFile(fakeKeyFile, pemData, 0600))

	// Configure to try publickey first (will fail), then password (will succeed)
	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           server.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodPublicKey, AuthMethodPassword},
		PrivateKeyFile: fakeKeyFile,
		PasswordFile:   passwordFile,
		KnownHostsFile: server.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(context.Background())
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, StateConnected, conn.GetState())
}

// TestKeyboardInteractiveMultiRound tests multi-round keyboard-interactive
func TestKeyboardInteractiveMultiRound(t *testing.T) {
	// This tests a more complex keyboard-interactive scenario
	serverCfg := &testSSHServerConfig{
		keyboardInteractivePrompts: []testKIPrompt{
			{Prompt: "Username: ", Echo: true, Answer: "admin"},
			{Prompt: "Password: ", Echo: false, Answer: "secret123"},
			{Prompt: "Security Question - Pet's name: ", Echo: true, Answer: "fluffy"},
		},
	}

	server, err := startTestSSHServerGo(t, serverCfg)
	require.NoError(t, err)
	defer server.stop()

	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           server.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodKeyboardInteractive},
		KnownHostsFile: server.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}

	conn := NewSSHConnection(sshConfig)
	ctx := context.Background()

	// Respond to challenges
	go func() {
		select {
		case challenge := <-conn.GetKeyboardChannel():
			// Verify all prompts received
			require.Len(t, challenge.Questions, 3)
			assert.Equal(t, "Username: ", challenge.Questions[0].Prompt)
			assert.Equal(t, "Password: ", challenge.Questions[1].Prompt)
			assert.Equal(t, "Security Question - Pet's name: ", challenge.Questions[2].Prompt)

			response := KeyboardInteractiveResponse{
				SessionID: challenge.SessionID,
				Answers:   []string{"admin", "secret123", "fluffy"},
			}
			conn.GetResponseChannel() <- response

		case <-time.After(5 * time.Second):
			t.Error("Timeout waiting for challenge")
		}
	}()

	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, StateConnected, conn.GetState())
}

// TestPasswordFromFileWithWhitespace tests password file with trailing whitespace
func TestPasswordFromFileWithWhitespace(t *testing.T) {
	serverCfg := &testSSHServerConfig{
		password: "cleanpassword",
	}

	server, err := startTestSSHServerGo(t, serverCfg)
	require.NoError(t, err)
	defer server.stop()

	// Create password file with trailing whitespace and newlines
	passwordFile := filepath.Join(server.tempDir, "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte("cleanpassword  \n\n"), 0600))

	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           server.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodPassword},
		PasswordFile:   passwordFile,
		KnownHostsFile: server.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(context.Background())
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, StateConnected, conn.GetState())
}

// BenchmarkPasswordAuth benchmarks password authentication
func BenchmarkPasswordAuth(b *testing.B) {
	serverCfg := &testSSHServerConfig{
		password: "benchpassword",
	}

	t := &testing.T{}
	server, err := startTestSSHServerGo(t, serverCfg)
	if err != nil {
		b.Fatal(err)
	}
	defer server.stop()

	passwordFile := filepath.Join(server.tempDir, "password")
	if err := os.WriteFile(passwordFile, []byte("benchpassword"), 0600); err != nil {
		b.Fatal(err)
	}

	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           server.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodPassword},
		PasswordFile:   passwordFile,
		KnownHostsFile: server.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := NewSSHConnection(sshConfig)
		if err := conn.Connect(context.Background()); err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

// TestParseProxyJumpSpec tests the ProxyJump specification parsing
func TestParseProxyJumpSpec(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		defaultUser string
		wantUser    string
		wantHost    string
		wantPort    int
	}{
		{
			name:        "simple host",
			spec:        "bastion.example.com",
			defaultUser: "defaultuser",
			wantUser:    "defaultuser",
			wantHost:    "bastion.example.com",
			wantPort:    22,
		},
		{
			name:        "user@host",
			spec:        "admin@bastion.example.com",
			defaultUser: "defaultuser",
			wantUser:    "admin",
			wantHost:    "bastion.example.com",
			wantPort:    22,
		},
		{
			name:        "host:port",
			spec:        "bastion.example.com:2222",
			defaultUser: "defaultuser",
			wantUser:    "defaultuser",
			wantHost:    "bastion.example.com",
			wantPort:    2222,
		},
		{
			name:        "user@host:port",
			spec:        "admin@bastion.example.com:2222",
			defaultUser: "defaultuser",
			wantUser:    "admin",
			wantHost:    "bastion.example.com",
			wantPort:    2222,
		},
		{
			name:        "IPv4 address",
			spec:        "192.168.1.100",
			defaultUser: "root",
			wantUser:    "root",
			wantHost:    "192.168.1.100",
			wantPort:    22,
		},
		{
			name:        "IPv4 with port",
			spec:        "192.168.1.100:2222",
			defaultUser: "root",
			wantUser:    "root",
			wantHost:    "192.168.1.100",
			wantPort:    2222,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, host, port := parseProxyJumpSpec(tt.spec, tt.defaultUser)
			assert.Equal(t, tt.wantUser, user, "user mismatch")
			assert.Equal(t, tt.wantHost, host, "host mismatch")
			assert.Equal(t, tt.wantPort, port, "port mismatch")
		})
	}
}

// TestGetHostKeyAlgorithmsForHost tests the host key algorithm ordering based on known_hosts
func TestGetHostKeyAlgorithmsForHost(t *testing.T) {
	tempDir := t.TempDir()
	knownHostsPath := filepath.Join(tempDir, "known_hosts")

	// Create a known_hosts file with multiple entries
	knownHostsContent := `# Example known_hosts file
bastion.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
bastion.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpo=
server1.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... comment
[server2.example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
192.168.1.100 ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCt...
`
	require.NoError(t, os.WriteFile(knownHostsPath, []byte(knownHostsContent), 0600))

	config := &SSHConfig{
		Host:           "bastion.example.com",
		Port:           22,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodAgent},
		KnownHostsFile: knownHostsPath,
	}

	conn := NewSSHConnection(config)

	tests := []struct {
		name       string
		host       string
		port       int
		wantAlgos  []string
		wantLength int
	}{
		{
			name:       "bastion with multiple key types",
			host:       "bastion.example.com",
			port:       22,
			wantAlgos:  []string{"ssh-ed25519", "ecdsa-sha2-nistp256"},
			wantLength: 2,
		},
		{
			name:       "server1 with RSA",
			host:       "server1.example.com",
			port:       22,
			wantAlgos:  []string{"ssh-rsa"},
			wantLength: 1,
		},
		{
			name:       "server2 with non-standard port",
			host:       "server2.example.com",
			port:       2222,
			wantAlgos:  []string{"ssh-ed25519"},
			wantLength: 1,
		},
		{
			name:       "IP address",
			host:       "192.168.1.100",
			port:       22,
			wantAlgos:  []string{"ecdsa-sha2-nistp384"},
			wantLength: 1,
		},
		{
			name:       "unknown host returns empty",
			host:       "unknown.example.com",
			port:       22,
			wantAlgos:  nil,
			wantLength: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Update config for this test case
			conn.config.Host = tt.host
			conn.config.Port = tt.port

			algos := conn.getHostKeyAlgorithmsForHost(tt.host, tt.port)
			assert.Equal(t, tt.wantLength, len(algos), "algorithm count mismatch")
			if tt.wantAlgos != nil {
				assert.Equal(t, tt.wantAlgos, algos, "algorithms mismatch")
			}
		})
	}
}
