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
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/ssh_posixv2"
)

var sshAuthTestCmd = &cobra.Command{
	Use:   "test [user@]host",
	Short: "Test SSH POSIXv2 connection and helper lifecycle",
	Long: `Test an SSH connection to a remote server, upload the Pelican binary,
start the helper process, verify keepalives work, and demonstrate clean shutdown.

This command allows testing the SSH POSIXv2 backend without running a full origin.
It's useful for verifying SSH connectivity and authentication before deploying.

The destination can be specified as [user@]host, similar to the ssh command.
If user is not specified, it defaults to the current OS username.
The known_hosts file defaults to ~/.ssh/known_hosts.

Example:
  # Test with default settings (uses SSH agent or default keys)
  pelican origin ssh-auth test storage.example.com

  # Test with explicit username
  pelican origin ssh-auth test pelican@storage.example.com

  # Test with specific private key
  pelican origin ssh-auth test pelican@storage.example.com --private-key ~/.ssh/id_rsa

  # Test with password authentication
  pelican origin ssh-auth test pelican@storage.example.com \
      --password-file /path/to/password.txt

  # Test with keyboard-interactive authentication only (disable agent/keys)
  pelican origin ssh-auth test pelican@storage.example.com \
      --auth-methods keyboard-interactive

  # Test with specific auth methods in order
  pelican origin ssh-auth test pelican@storage.example.com \
      --auth-methods agent,keyboard-interactive

  # Connect through a jump host (ProxyJump)
  pelican origin ssh-auth test internal-server -J bastion.example.com

  # Connect through a jump host with explicit user
  pelican origin ssh-auth test pelican@internal-server -J admin@bastion.example.com

  # Chained jump hosts
  pelican origin ssh-auth test pelican@internal-server -J jump1.example.com,jump2.example.com

  # Quick connectivity test without starting the helper
  pelican origin ssh-auth test pelican@storage.example.com --connect-only
`,
	Args:         cobra.ExactArgs(1),
	RunE:         runSSHAuthTest,
	SilenceUsage: true,
}

var (
	sshTestPort               int
	sshTestUser               string
	sshTestPrivateKey         string
	sshTestPrivateKeyPassword string
	sshTestPasswordFile       string
	sshTestKnownHosts         string
	sshTestAuthMethod         string
	sshTestAuthMethods        string
	sshTestPelicanBinary      string
	sshTestRemoteBinary       string
	sshTestRemoteDir          string
	sshTestConnectOnly        bool
	sshTestKeepaliveCount     int
	sshTestKeepaliveInterval  time.Duration
	sshTestProxyJump          string
)

func init() {
	sshAuthTestCmd.Flags().IntVarP(&sshTestPort, "port", "p", 22, "SSH port")
	sshAuthTestCmd.Flags().StringVarP(&sshTestUser, "user", "l", "", "SSH username (overrides user@host)")
	sshAuthTestCmd.Flags().StringVarP(&sshTestPrivateKey, "private-key", "i", "", "Path to SSH private key")
	sshAuthTestCmd.Flags().StringVar(&sshTestPrivateKeyPassword, "private-key-passphrase-file", "", "Path to file containing private key passphrase")
	sshAuthTestCmd.Flags().StringVar(&sshTestPasswordFile, "password-file", "", "Path to file containing SSH password")
	sshAuthTestCmd.Flags().StringVarP(&sshTestKnownHosts, "known-hosts", "o", "", "Path to known_hosts file (default: ~/.ssh/known_hosts)")
	sshAuthTestCmd.Flags().StringVar(&sshTestAuthMethod, "auth-method", "", "Single authentication method (deprecated, use --auth-methods)")
	sshAuthTestCmd.Flags().StringVar(&sshTestAuthMethods, "auth-methods", "", "Comma-separated list of auth methods to try: agent,publickey,password,keyboard-interactive")
	sshAuthTestCmd.Flags().StringVar(&sshTestPelicanBinary, "pelican-binary", "", "Path to local Pelican binary to upload (defaults to current binary)")
	sshAuthTestCmd.Flags().StringVar(&sshTestRemoteBinary, "remote-binary", "", "Path to pre-built binary for remote platform (os/arch=/path or just /path for auto-detect)")
	sshAuthTestCmd.Flags().StringVar(&sshTestRemoteDir, "remote-dir", "/tmp/pelican-test", "Remote directory for Pelican binary")
	sshAuthTestCmd.Flags().BoolVar(&sshTestConnectOnly, "connect-only", false, "Only test connectivity, don't start the helper")
	sshAuthTestCmd.Flags().IntVar(&sshTestKeepaliveCount, "keepalive-count", 3, "Number of keepalive cycles to verify before shutdown")
	sshAuthTestCmd.Flags().DurationVar(&sshTestKeepaliveInterval, "keepalive-interval", 5*time.Second, "Keepalive interval for testing")
	sshAuthTestCmd.Flags().StringVarP(&sshTestProxyJump, "jump", "J", "", "Jump host(s) for ProxyJump ([user@]host[:port], comma-separated for chaining)")

	// Add to ssh-auth command
	sshAuthCmd.AddCommand(sshAuthTestCmd)
}

// parseUserHost parses a [user@]host string into user and host components
func parseUserHost(destination string) (user, host string) {
	if idx := strings.LastIndex(destination, "@"); idx != -1 {
		return destination[:idx], destination[idx+1:]
	}
	return "", destination
}

// getDefaultKnownHosts returns the default known_hosts file path
func getDefaultKnownHosts() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".ssh", "known_hosts")
	}
	return ""
}

// getCurrentUsername returns the current OS username
func getCurrentUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// startTestWebSocketServer starts a minimal HTTP server with WebSocket support
// for keyboard-interactive and password authentication in test mode.
// Returns: shutdown function, WebSocket URL, connected channel, error
func startTestWebSocketServer(conn *ssh_posixv2.SSHConnection) (func(), string, <-chan struct{}, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	connected := make(chan struct{})
	var connectedOnce bool

	// WebSocket handler for auth challenges
	router.GET("/auth-ws", func(c *gin.Context) {
		ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to upgrade to WebSocket: %v\n", err)
			return
		}
		defer ws.Close()

		fmt.Println("✓ WebSocket connection established for authentication")

		// Signal that a client has connected
		if !connectedOnce {
			connectedOnce = true
			close(connected)
		}

		// Set read/write deadlines
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_ = ws.SetWriteDeadline(time.Now().Add(30 * time.Second))

		// Bridge between WebSocket and terminal - this handles all read/write
		handleAuthWebSocket(ws, conn)
	})

	server := &http.Server{
		Addr:    "127.0.0.1:0", // Random port
		Handler: router,
	}

	// Get the actual port
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, "", nil, err
	}
	addr := listener.Addr().String()
	wsURL := fmt.Sprintf("ws://%s/auth-ws", addr)

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "WebSocket server error: %v\n", err)
		}
	}()

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}

	return shutdown, wsURL, connected, nil
}

// startWebSocketClient connects to the WebSocket server as a client and handles terminal I/O
func startWebSocketClient(ctx context.Context, wsURL string) error {
	// Connect to the WebSocket server
	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}

	log.Debugf("WebSocket client attempting to connect to %s", wsURL)
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket server: %w", err)
	}
	defer ws.Close()

	fmt.Println("✓ WebSocket client connected")
	log.Debug("WebSocket client starting message loop")

	reader := bufio.NewReader(os.Stdin)

	// Close WebSocket when context is canceled
	go func() {
		<-ctx.Done()
		log.Debug("Context canceled, closing WebSocket client")
		ws.Close()
	}()

	// Goroutine to read messages from WebSocket (challenges from server)
	go func() {
		log.Debug("WebSocket client goroutine started, waiting for messages...")
		for {
			select {
			case <-ctx.Done():
				log.Debug("WebSocket client goroutine context canceled")
				return
			default:
			}

			log.Debug("WebSocket client waiting for next message")

			// Set read deadline to prevent indefinite hanging
			_ = ws.SetReadDeadline(time.Now().Add(2 * time.Minute))

			var msg map[string]interface{}
			err := ws.ReadJSON(&msg)
			if err != nil {
				// Suppress expected closure errors during shutdown
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Debug("WebSocket closed normally")
					return
				}
				// Suppress "use of closed network connection" errors (happens during shutdown)
				if ctx.Err() != nil || strings.Contains(err.Error(), "use of closed network connection") {
					log.Debug("WebSocket client shutting down cleanly")
					return
				}
				log.Debugf("WebSocket client ReadJSON error: %v", err)
				fmt.Fprintf(os.Stderr, "WebSocket read error: %v\n", err)
				return
			}

			log.Debugf("WebSocket client received message: %+v", msg)

			// Check for authentication complete message
			if msgType, ok := msg["type"].(string); ok && msgType == "auth_complete" {
				log.Debug("Received auth_complete signal, closing client")
				return
			}

			// Check if it's a keyboard-interactive challenge
			if sessionID, ok := msg["session_id"].(string); ok {
				log.Debugf("Got keyboard-interactive challenge, sessionID=%s", sessionID)
				// Prompt user on terminal
				fmt.Println()
				if instruction, ok := msg["instruction"].(string); ok && instruction != "" {
					fmt.Println(instruction)
				}

				questions, ok := msg["questions"].([]interface{})
				if !ok {
					continue
				}

				answers := make([]string, len(questions))
				for i, q := range questions {
					qMap, ok := q.(map[string]interface{})
					if !ok {
						continue
					}
					prompt, _ := qMap["prompt"].(string)
					echo, _ := qMap["echo"].(bool)

					fmt.Printf("%s", prompt)

					var answer string
					if !echo {
						// Use terminal.ReadPassword for non-echoed input
						passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
						if err != nil {
							fmt.Fprintf(os.Stderr, "\nError reading password: %v\n", err)
							return
						}
						answer = string(passwordBytes)
						fmt.Println() // Print newline after password entry
					} else {
						// Use regular reader for echoed input
						line, err := reader.ReadString('\n')
						if err != nil {
							fmt.Fprintf(os.Stderr, "\nError reading input: %v\n", err)
							return
						}
						answer = strings.TrimRight(line, "\n\r")
					}
					answers[i] = answer
				}

				log.Debugf("WebSocket client collected %d answers, sending response...", len(answers))
				// Send response back to server via WebSocket
				response := ssh_posixv2.KeyboardInteractiveResponse{
					SessionID: sessionID,
					Answers:   answers,
				}
				if err := ws.WriteJSON(response); err != nil {
					log.Debugf("Failed to send response: %v", err)
					return
				}
				log.Debug("Response sent to WebSocket server")
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Send close message gracefully
	_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	return nil
}

// handleAuthWebSocket handles WebSocket messages and bridges between SSH channels and WebSocket
// This runs on the server side and forwards challenges/responses bidirectionally
func handleAuthWebSocket(ws *websocket.Conn, conn *ssh_posixv2.SSHConnection) {
	log.Debug("handleAuthWebSocket started")

	done := make(chan struct{})

	// Goroutine to forward challenges from SSH to WebSocket
	go func() {
		defer close(done)
		log.Debug("Challenge forwarding goroutine started, waiting for challenges...")
		for challenge := range conn.KeyboardChan() {
			log.Debugf("Got challenge from SSH channel: sessionID=%s, %d questions", challenge.SessionID, len(challenge.Questions))
			log.Debug("Forwarding challenge to WebSocket...")
			if err := ws.WriteJSON(challenge); err != nil {
				log.Debugf("Failed to send challenge to WebSocket: %v", err)
				return
			}
			log.Debug("Challenge forwarded to WebSocket successfully")
		}
		// Channel closed - authentication completed
		log.Debug("Challenge channel closed - authentication complete")
		// Send success message to client
		successMsg := map[string]string{"type": "auth_complete"}
		_ = ws.WriteJSON(successMsg)
	}()

	// Read responses from WebSocket and forward to SSH
	log.Debug("Starting to read responses from WebSocket...")
	for {
		select {
		case <-done:
			log.Debug("Authentication complete, closing server handler")
			return
		default:
		}

		log.Debug("Waiting for response from WebSocket...")
		var response ssh_posixv2.KeyboardInteractiveResponse

		// Set a reasonable read deadline
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Minute))

		if err := ws.ReadJSON(&response); err != nil {
			log.Debugf("WebSocket ReadJSON error: %v", err)
			// Suppress expected closure errors during normal shutdown
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				return
			}
			return
		}

		log.Debugf("Received response from WebSocket: sessionID=%s, %d answers", response.SessionID, len(response.Answers))
		// Forward response to SSH connection
		log.Debug("Forwarding response to SSH channel...")
		select {
		case conn.ResponseChan() <- response:
			log.Debug("Response forwarded to SSH successfully")
		case <-time.After(30 * time.Second):
			log.Debug("Timeout forwarding response to SSH (30s)")
			return
		}
	}
}

func runSSHAuthTest(cmd *cobra.Command, args []string) error {
	// Initialize client configuration and logging
	if err := config.InitClient(); err != nil {
		return fmt.Errorf("failed to initialize client config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse the destination argument
	destUser, destHost := parseUserHost(args[0])

	// Determine the username (priority: -l flag > user@host > current user)
	username := sshTestUser
	if username == "" {
		username = destUser
	}
	if username == "" {
		username = getCurrentUsername()
	}
	if username == "" {
		return fmt.Errorf("could not determine username; specify with user@host or -l flag")
	}

	// Determine the known_hosts file
	knownHostsFile := sshTestKnownHosts
	if knownHostsFile == "" {
		knownHostsFile = getDefaultKnownHosts()
	}
	if knownHostsFile == "" {
		return fmt.Errorf("could not determine known_hosts file; specify with -o flag")
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Printf("\nReceived signal %v, initiating graceful shutdown...\n", sig)
		cancel()
	}()

	// Determine auth methods
	authMethods := []ssh_posixv2.AuthMethod{}
	if sshTestAuthMethods != "" {
		// Parse comma-separated list of auth methods
		for _, method := range strings.Split(sshTestAuthMethods, ",") {
			method = strings.TrimSpace(method)
			if method == "" {
				continue
			}
			switch method {
			case "agent":
				authMethods = append(authMethods, ssh_posixv2.AuthMethodAgent)
			case "publickey":
				authMethods = append(authMethods, ssh_posixv2.AuthMethodPublicKey)
			case "password":
				authMethods = append(authMethods, ssh_posixv2.AuthMethodPassword)
			case "keyboard-interactive", "kbd", "ki":
				authMethods = append(authMethods, ssh_posixv2.AuthMethodKeyboardInteractive)
			default:
				return fmt.Errorf("unknown auth method: %s (valid: agent, publickey, password, keyboard-interactive)", method)
			}
		}
	} else if sshTestAuthMethod != "" {
		// Legacy single method flag
		authMethods = append(authMethods, ssh_posixv2.AuthMethod(sshTestAuthMethod))
	} else {
		// Auto-detect based on provided flags and available resources
		// Always try SSH agent first (no config needed)
		authMethods = append(authMethods, ssh_posixv2.AuthMethodAgent)

		// Add publickey if a key file is specified
		if sshTestPrivateKey != "" {
			authMethods = append(authMethods, ssh_posixv2.AuthMethodPublicKey)
		}

		// Add password if a password file is specified
		if sshTestPasswordFile != "" {
			authMethods = append(authMethods, ssh_posixv2.AuthMethodPassword)
		}

		// Always try keyboard-interactive as a fallback (no config needed)
		authMethods = append(authMethods, ssh_posixv2.AuthMethodKeyboardInteractive)
	}

	// Determine pelican binary path
	pelicanBinary := sshTestPelicanBinary
	if pelicanBinary == "" {
		var err error
		pelicanBinary, err = os.Executable()
		if err != nil {
			return fmt.Errorf("failed to determine current executable path: %w", err)
		}
	}

	// Parse remote binary overrides
	// Support formats: "/path/to/binary" (applies to all platforms) or "linux/amd64=/path/to/binary"
	remoteBinaryOverrides := make(map[string]string)
	if sshTestRemoteBinary != "" {
		if strings.Contains(sshTestRemoteBinary, "=") {
			// Format: os/arch=/path/to/binary
			parts := strings.SplitN(sshTestRemoteBinary, "=", 2)
			remoteBinaryOverrides[parts[0]] = parts[1]
		} else {
			// Just a path - will be used for any platform
			// We'll set common ones
			remoteBinaryOverrides["linux/amd64"] = sshTestRemoteBinary
			remoteBinaryOverrides["linux/arm64"] = sshTestRemoteBinary
			remoteBinaryOverrides["darwin/amd64"] = sshTestRemoteBinary
			remoteBinaryOverrides["darwin/arm64"] = sshTestRemoteBinary
		}
	}

	// Build SSH config
	sshConfig := &ssh_posixv2.SSHConfig{
		Host:                         destHost,
		Port:                         sshTestPort,
		User:                         username,
		PasswordFile:                 sshTestPasswordFile,
		PrivateKeyFile:               sshTestPrivateKey,
		PrivateKeyPassphraseFile:     sshTestPrivateKeyPassword,
		KnownHostsFile:               knownHostsFile,
		AutoAddHostKey:               true, // Test mode: allow auto-adding unknown hosts
		AuthMethods:                  authMethods,
		PelicanBinaryPath:            pelicanBinary,
		RemotePelicanBinaryDir:       sshTestRemoteDir,
		RemotePelicanBinaryOverrides: remoteBinaryOverrides,
		ConnectTimeout:               30 * time.Second,
		ProxyJump:                    sshTestProxyJump,
	}

	// Validate config
	if err := sshConfig.Validate(); err != nil {
		return fmt.Errorf("invalid SSH configuration: %w", err)
	}

	fmt.Println("========================================")
	fmt.Println("SSH POSIXv2 Connection Test")
	fmt.Println("========================================")
	fmt.Printf("Host:           %s:%d\n", destHost, sshTestPort)
	fmt.Printf("User:           %s\n", username)
	fmt.Printf("Auth Methods:   %v\n", authMethods)
	fmt.Printf("Known Hosts:    %s\n", knownHostsFile)
	if sshTestPrivateKey != "" {
		fmt.Printf("Private Key:    %s\n", sshTestPrivateKey)
	}
	fmt.Printf("Pelican Binary: %s\n", pelicanBinary)
	fmt.Printf("Remote Dir:     %s\n", sshTestRemoteDir)
	fmt.Printf("Connect Only:   %v\n", sshTestConnectOnly)
	fmt.Println("----------------------------------------")

	// Create the connection
	conn := ssh_posixv2.NewSSHConnection(sshConfig)

	// Initialize WebSocket channels for authentication
	conn.InitializeAuthChannels()

	// Start internal WebSocket server for authentication
	shutdownServer, wsURL, clientConnected, err := startTestWebSocketServer(conn)
	if err != nil {
		return fmt.Errorf("failed to start WebSocket server: %w", err)
	}
	defer shutdownServer()
	fmt.Printf("WebSocket server started at %s\n", wsURL)

	// Start WebSocket client to handle auth prompts
	go func() {
		if err := startWebSocketClient(ctx, wsURL); err != nil {
			fmt.Fprintf(os.Stderr, "WebSocket client error: %v\n", err)
		}
	}()

	// Wait for client to connect with timeout
	log.Debug("Waiting for WebSocket client to connect...")
	select {
	case <-clientConnected:
		log.Debug("WebSocket client connected successfully")
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for WebSocket client to connect")
	case <-ctx.Done():
		return fmt.Errorf("context canceled while waiting for WebSocket client")
	}

	// Phase 1: Connect
	fmt.Println("\n[Phase 1] Establishing SSH connection...")
	if sshTestProxyJump != "" {
		fmt.Printf("  Jump host(s): %s\n", sshTestProxyJump)
	}
	// Show hardware key message only if using agent or publickey auth
	if len(authMethods) > 0 {
		for _, method := range authMethods {
			if method == "agent" || method == "publickey" {
				fmt.Println("  (If using a hardware key like Yubikey, you may need to touch it now)")
				break
			}
		}
	}
	startTime := time.Now()
	if err := conn.Connect(ctx); err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}
	fmt.Printf("✓ SSH connection established in %v\n", time.Since(startTime))
	fmt.Printf("  State: %s\n", conn.GetState())

	// Ensure cleanup on exit
	defer func() {
		fmt.Println("\n[Cleanup] Closing SSH connection...")
		conn.Close()
		fmt.Println("✓ Connection closed")
	}()

	if sshTestConnectOnly {
		// Phase 1.5: Run a quick command to verify
		fmt.Println("\n[Phase 1.5] Testing command execution...")
		output, err := conn.RunCommand(ctx, "echo 'SSH connection successful' && uname -a")
		if err != nil {
			return fmt.Errorf("command execution failed: %w", err)
		}
		fmt.Printf("✓ Remote command output:\n%s\n", output)
		fmt.Println("\n========================================")
		fmt.Println("Connection test completed successfully!")
		fmt.Println("========================================")
		return nil
	}

	// Phase 2: Detect remote platform
	fmt.Println("\n[Phase 2] Detecting remote platform...")
	platform, err := conn.DetectRemotePlatform(ctx)
	if err != nil {
		return fmt.Errorf("platform detection failed: %w", err)
	}
	fmt.Printf("✓ Remote platform: %s/%s\n", platform.OS, platform.Arch)

	// Phase 3: Upload Pelican binary
	fmt.Println("\n[Phase 3] Uploading Pelican binary...")
	startTime = time.Now()
	if err := conn.TransferBinary(ctx); err != nil {
		return fmt.Errorf("binary upload failed: %w", err)
	}
	remotePath, err := conn.GetRemoteBinaryPath()
	if err != nil {
		return fmt.Errorf("failed to get remote binary path: %w", err)
	}
	fmt.Printf("✓ Binary uploaded to %s in %v\n", remotePath, time.Since(startTime))

	// Phase 4: Start the helper
	fmt.Println("\n[Phase 4] Starting helper process...")

	// Create a minimal export for testing
	testExports := []ssh_posixv2.ExportConfig{
		{
			FederationPrefix: "/test",
			StoragePrefix:    "/tmp",
			Capabilities: ssh_posixv2.ExportCapabilities{
				Reads:    true,
				Listings: true,
			},
		},
	}

	helperConfig := &ssh_posixv2.HelperConfig{
		Exports:           testExports,
		KeepaliveInterval: sshTestKeepaliveInterval,
	}

	startTime = time.Now()
	if err := conn.StartHelper(ctx, helperConfig); err != nil {
		return fmt.Errorf("helper start failed: %w", err)
	}
	fmt.Printf("✓ Helper started in %v\n", time.Since(startTime))
	fmt.Printf("  State: %s\n", conn.GetState())

	// Phase 5: Verify keepalives
	fmt.Printf("\n[Phase 5] Verifying keepalives (%d cycles at %v intervals)...\n",
		sshTestKeepaliveCount, sshTestKeepaliveInterval)

	keepaliveSuccess := 0
	for i := 0; i < sshTestKeepaliveCount; i++ {
		select {
		case <-ctx.Done():
			fmt.Println("\n  Interrupted during keepalive test")
			break
		case <-time.After(sshTestKeepaliveInterval):
			// Check if connection is still alive
			state := conn.GetState()
			if state != ssh_posixv2.StateRunningHelper {
				return fmt.Errorf("helper died during keepalive test, state: %s", state)
			}
			keepaliveSuccess++
			fmt.Printf("  ✓ Keepalive %d/%d - State: %s\n", keepaliveSuccess, sshTestKeepaliveCount, state)
		}
	}
	fmt.Printf("✓ All %d keepalive cycles successful\n", keepaliveSuccess)

	// Phase 6: Graceful shutdown
	fmt.Println("\n[Phase 6] Testing graceful shutdown...")
	startTime = time.Now()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := conn.StopHelper(shutdownCtx); err != nil {
		return fmt.Errorf("helper shutdown failed: %w", err)
	}
	fmt.Printf("✓ Helper stopped gracefully in %v\n", time.Since(startTime))
	fmt.Printf("  State: %s\n", conn.GetState())

	// Verify state after shutdown
	if conn.GetState() != ssh_posixv2.StateConnected {
		fmt.Printf("  Warning: Expected state %s, got %s\n", ssh_posixv2.StateConnected, conn.GetState())
	}

	fmt.Println("\n========================================")
	fmt.Println("SSH POSIXv2 test completed successfully!")
	fmt.Println("========================================")
	fmt.Println("\nSummary:")
	fmt.Println("  ✓ SSH connection: OK")
	fmt.Println("  ✓ Platform detection: OK")
	fmt.Println("  ✓ Binary upload: OK")
	fmt.Println("  ✓ Helper startup: OK")
	fmt.Printf("  ✓ Keepalive test: OK (%d cycles)\n", keepaliveSuccess)
	fmt.Println("  ✓ Graceful shutdown: OK")

	return nil
}
