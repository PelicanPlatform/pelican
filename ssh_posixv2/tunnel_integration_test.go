//go:build !windows

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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// tunnelTestSSHServer is a minimal SSH server that supports
// direct-streamlocal@openssh.com channels. When the SSH client calls
// sshClient.Dial("unix", socketPath), the server connects to the
// requested Unix socket and proxies traffic bidirectionally through
// the SSH channel.
type tunnelTestSSHServer struct {
	listener    net.Listener
	config      *ssh.ServerConfig
	port        int
	tempDir     string
	knownHosts  string
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	connections []net.Conn
	connMu      sync.Mutex
}

// streamLocalPayload is the wire format for direct-streamlocal@openssh.com
// channel extra data.  Field names must be exported for ssh.Unmarshal.
type streamLocalPayload struct {
	SocketPath string
	Reserved0  string
	Reserved1  uint32
}

// startTunnelTestSSHServer starts a Go-based SSH server that supports
// password auth and direct-streamlocal channel forwarding.
func startTunnelTestSSHServer(t *testing.T, password string) (*tunnelTestSSHServer, error) {
	tempDir := t.TempDir()

	// Generate host key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}
	hostKey, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}
	serverConfig.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// Write known_hosts
	hostPubKey := hostKey.PublicKey()
	knownHostsPath := filepath.Join(tempDir, "known_hosts")
	authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostPubKey)))
	knownHostsLine := fmt.Sprintf("[127.0.0.1]:%d %s\n", port, authorizedKey)
	if err := os.WriteFile(knownHostsPath, []byte(knownHostsLine), 0644); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to write known_hosts: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &tunnelTestSSHServer{
		listener:   listener,
		config:     serverConfig,
		port:       port,
		tempDir:    tempDir,
		knownHosts: knownHostsPath,
		ctx:        ctx,
		cancel:     cancel,
	}

	s.wg.Add(1)
	go s.acceptLoop()

	return s, nil
}

func (s *tunnelTestSSHServer) stop() {
	s.cancel()
	_ = s.listener.Close()

	s.connMu.Lock()
	for _, conn := range s.connections {
		_ = conn.Close()
	}
	s.connMu.Unlock()

	s.wg.Wait()
}

func (s *tunnelTestSSHServer) acceptLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

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

func (s *tunnelTestSSHServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	// Reject all global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels: accept direct-streamlocal, reject everything else
	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-streamlocal@openssh.com":
			s.wg.Add(1)
			go s.handleStreamLocal(newChan)
		case "session":
			ch, _, err := newChan.Accept()
			if err == nil {
				ch.Close()
			}
		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

// handleStreamLocal handles a "direct-streamlocal@openssh.com" channel
// request by connecting to the requested Unix socket and proxying traffic.
func (s *tunnelTestSSHServer) handleStreamLocal(newChan ssh.NewChannel) {
	defer s.wg.Done()

	var payload streamLocalPayload
	if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "invalid payload")
		return
	}

	unixConn, err := net.DialTimeout("unix", payload.SocketPath, 5*time.Second)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		unixConn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	// Bidirectional copy between the SSH channel and the Unix connection
	var copyWg sync.WaitGroup
	copyWg.Add(2)
	go func() {
		defer copyWg.Done()
		_, _ = io.Copy(ch, unixConn)
		_ = ch.CloseWrite()
	}()
	go func() {
		defer copyWg.Done()
		_, _ = io.Copy(unixConn, ch)
	}()
	copyWg.Wait()
	ch.Close()
	unixConn.Close()
}

// TestSSHTunnelTransportIntegration is an integration test that:
// 1. Starts a plain HTTP server on a Unix socket (simulating the helper)
// 2. Starts a Go-based SSH server with direct-streamlocal support
// 3. Connects to the SSH server as a client
// 4. Creates an SSHTunnelTransport with the SSH client
// 5. Sends HTTP requests through the SSH tunnel transport and verifies responses
func TestSSHTunnelTransportIntegration(t *testing.T) {
	const testPassword = "tunnel-test-password"
	const authCookie = "integration-test-cookie"

	// 1. Start a plain HTTP server on a Unix socket (simulates the helper)
	handler := http.NewServeMux()
	handler.HandleFunc("/api/v1.0/ssh-helper/keepalive", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+authCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	handler.HandleFunc("/test/data", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+authCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello from helper"))
	})

	sockDir, err := os.MkdirTemp("/tmp", "pt-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	helperSocket := filepath.Join(sockDir, "h.sock")
	helperLn, err := net.Listen("unix", helperSocket)
	require.NoError(t, err)
	helperSrv := &http.Server{Handler: handler}
	go func() { _ = helperSrv.Serve(helperLn) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = helperSrv.Shutdown(ctx)
	}()
	t.Logf("Helper HTTP server on unix socket %s", helperSocket)

	// 2. Start the SSH server with direct-streamlocal support
	sshServer, err := startTunnelTestSSHServer(t, testPassword)
	require.NoError(t, err)
	defer sshServer.stop()
	t.Logf("SSH server on port %d", sshServer.port)

	// 3. Connect to the SSH server as a client
	passwordFile := filepath.Join(sshServer.tempDir, "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte(testPassword), 0600))

	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           sshServer.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodPassword},
		PasswordFile:   passwordFile,
		KnownHostsFile: sshServer.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}

	conn := NewSSHConnection(sshConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()
	t.Log("SSH client connected")

	// 4. Create SSHTunnelTransport and mark it ready with the socket path
	transport := NewSSHTunnelTransport(authCookie)
	transport.SetReady(conn.client, helperSocket)

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// 5. Send requests through the SSH tunnel via streamlocal
	t.Run("keepalive-through-tunnel", func(t *testing.T) {
		req, err := http.NewRequest("POST", "http://ssh-helper/api/v1.0/ssh-helper/keepalive", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err, "HTTP through SSH streamlocal tunnel should work")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), `"status":"ok"`)
		t.Logf("Response through tunnel: %s", string(body))
	})

	t.Run("data-endpoint-through-tunnel", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://ssh-helper/test/data", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "hello from helper", string(body))
	})

	t.Run("multiple-requests-through-tunnel", func(t *testing.T) {
		const numRequests = 10
		errCh := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func(idx int) {
				req, err := http.NewRequest("GET", fmt.Sprintf("http://ssh-helper/test/data?idx=%d", idx), nil)
				if err != nil {
					errCh <- err
					return
				}
				resp, err := httpClient.Do(req)
				if err != nil {
					errCh <- fmt.Errorf("request %d: %w", idx, err)
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					errCh <- fmt.Errorf("request %d: status %d", idx, resp.StatusCode)
					return
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					errCh <- fmt.Errorf("request %d: read body: %w", idx, err)
					return
				}
				if string(body) != "hello from helper" {
					errCh <- fmt.Errorf("request %d: unexpected body: %s", idx, body)
					return
				}
				errCh <- nil
			}(i)
		}

		for i := 0; i < numRequests; i++ {
			assert.NoError(t, <-errCh)
		}
	})

	t.Run("auth-cookie-injected", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://ssh-helper/test/data", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestSSHTunnelTransportSetReadyUnblocks verifies that RoundTrip blocks
// until SetReady is called, then succeeds.
func TestSSHTunnelTransportSetReadyUnblocks(t *testing.T) {
	const testPassword = "unblock-test-password"
	const authCookie = "unblock-cookie"

	// Start a helper HTTP server on a Unix socket
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "unblocked")
	})
	sockDir, err := os.MkdirTemp("/tmp", "pt-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	helperSocket := filepath.Join(sockDir, "h.sock")
	helperLn, err := net.Listen("unix", helperSocket)
	require.NoError(t, err)
	helperSrv := &http.Server{Handler: handler}
	go func() { _ = helperSrv.Serve(helperLn) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = helperSrv.Shutdown(ctx)
	}()

	// Start SSH server
	sshServer, err := startTunnelTestSSHServer(t, testPassword)
	require.NoError(t, err)
	defer sshServer.stop()

	// Connect SSH client
	passwordFile := filepath.Join(sshServer.tempDir, "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte(testPassword), 0600))

	sshConfig := &SSHConfig{
		Host:           "127.0.0.1",
		Port:           sshServer.port,
		User:           "testuser",
		AuthMethods:    []AuthMethod{AuthMethodPassword},
		PasswordFile:   passwordFile,
		KnownHostsFile: sshServer.knownHosts,
		ConnectTimeout: 10 * time.Second,
	}
	conn := NewSSHConnection(sshConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, conn.Connect(ctx))
	defer conn.Close()

	// Create transport in "not ready" state
	transport := NewSSHTunnelTransport(authCookie)

	// Start a request in background — it should block
	resultCh := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", "http://ssh-helper/test", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			resultCh <- err
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			resultCh <- fmt.Errorf("status %d", resp.StatusCode)
			return
		}
		resultCh <- nil
	}()

	// Verify the request hasn't completed yet (transport not ready)
	select {
	case err := <-resultCh:
		t.Fatalf("request should be blocked, got: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Expected: still blocked
	}

	// Now set the transport ready with the socket path
	transport.SetReady(conn.client, helperSocket)

	// The request should complete
	select {
	case err := <-resultCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("request should have completed after SetReady")
	}
}
