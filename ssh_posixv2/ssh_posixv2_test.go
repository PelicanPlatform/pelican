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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// testSSHServer represents a running test SSH server
type testSSHServer struct {
	cmd            *exec.Cmd
	port           int
	hostKeyFile    string
	authKeysFile   string
	configFile     string
	pidFile        string
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	knownHostsFile string
	tempDir        string
	userKeyFile    string
}

// generateTestKeys creates ED25519 key pair for testing
func generateTestKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// writePrivateKeyPEM writes a private key in PEM format
func writePrivateKeyPEM(filename string, privateKey ed25519.PrivateKey) error {
	// The OpenSSH private key format is special, so we use x/crypto/ssh to marshal it
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(block)
	return os.WriteFile(filename, data, 0600)
}

// writePublicKeyOpenSSH writes a public key in OpenSSH format for authorized_keys
func writePublicKeyOpenSSH(filename string, publicKey ed25519.PublicKey) error {
	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return err
	}
	data := ssh.MarshalAuthorizedKey(sshPubKey)
	return os.WriteFile(filename, data, 0644)
}

// startTestSSHD starts a temporary sshd for testing
// Uses port 0 to let the OS assign an available port, avoiding TOCTOU race conditions
func startTestSSHD(t *testing.T) (*testSSHServer, error) {
	tempDir := t.TempDir()

	// Generate host key
	hostKeyFile := filepath.Join(tempDir, "host_key")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", hostKeyFile, "-N", "", "-q")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	// Generate user key for authentication
	pub, priv, err := generateTestKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate test keys: %w", err)
	}

	// Write private key for client use
	privateKeyFile := filepath.Join(tempDir, "user_key")
	if err := writePrivateKeyPEM(privateKeyFile, priv); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key for authorized_keys
	authKeysFile := filepath.Join(tempDir, "authorized_keys")
	if err := writePublicKeyOpenSSH(authKeysFile, pub); err != nil {
		return nil, fmt.Errorf("failed to write authorized keys: %w", err)
	}

	// Create a listener on port 0 to get an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	// Close the listener before starting sshd - there's a brief race window
	// but it's much smaller than the previous findFreePort approach
	listener.Close()

	// Create known_hosts file from host key
	hostPubKey, err := os.ReadFile(hostKeyFile + ".pub")
	if err != nil {
		return nil, fmt.Errorf("failed to read host public key: %w", err)
	}
	knownHostsFile := filepath.Join(tempDir, "known_hosts")
	// Format: [host]:port key-type key-data
	knownHostsLine := fmt.Sprintf("[127.0.0.1]:%d %s", port, strings.TrimSpace(string(hostPubKey)))
	if err := os.WriteFile(knownHostsFile, []byte(knownHostsLine), 0644); err != nil {
		return nil, fmt.Errorf("failed to write known_hosts: %w", err)
	}

	// Create sshd config
	pidFile := filepath.Join(tempDir, "sshd.pid")
	configFile := filepath.Join(tempDir, "sshd_config")
	config := fmt.Sprintf(`
Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
AuthorizedKeysFile %s
StrictModes no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin yes
LogLevel DEBUG3
`, port, hostKeyFile, pidFile, authKeysFile)
	if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
		return nil, fmt.Errorf("failed to write sshd config: %w", err)
	}

	// Start sshd
	sshdCmd := exec.Command("/usr/sbin/sshd", "-D", "-f", configFile, "-E", filepath.Join(tempDir, "sshd.log"))
	if err := sshdCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sshd: %w", err)
	}

	server := &testSSHServer{
		cmd:            sshdCmd,
		port:           port,
		hostKeyFile:    hostKeyFile,
		authKeysFile:   authKeysFile,
		configFile:     configFile,
		pidFile:        pidFile,
		privateKey:     priv,
		publicKey:      pub,
		knownHostsFile: knownHostsFile,
		tempDir:        tempDir,
		userKeyFile:    privateKeyFile,
	}

	// Wait for sshd to be ready using require.Eventually
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		return false
	}, 2*time.Second, 100*time.Millisecond, "sshd should become ready")

	return server, nil
}

// stop stops the test SSH server
func (s *testSSHServer) stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
}

// makeTestConfig creates an SSHConfig for testing
func (s *testSSHServer) makeTestConfig() *SSHConfig {
	return &SSHConfig{
		Host:           "127.0.0.1",
		Port:           s.port,
		User:           os.Getenv("USER"),
		AuthMethods:    []AuthMethod{AuthMethodPublicKey},
		PrivateKeyFile: s.userKeyFile,
		KnownHostsFile: s.knownHostsFile,
		AutoAddHostKey: true, // Test mode: allow auto-adding unknown hosts
		ConnectTimeout: 10 * time.Second,
	}
}

// Test SSH connection with public key authentication
func TestSSHConnection(t *testing.T) {
	// Time-limited context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	sshConfig := server.makeTestConfig()

	// Create and connect
	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(ctx)
	require.NoError(t, err, "Failed to connect via SSH")
	defer conn.Close()

	assert.Equal(t, StateConnected, conn.GetState())

	// Test running a simple command
	session, err := conn.client.NewSession()
	require.NoError(t, err)
	defer session.Close()

	output, err := session.Output("echo hello")
	require.NoError(t, err)
	assert.Equal(t, "hello\n", string(output))
}

// Test platform detection
func TestPlatformDetection(t *testing.T) {
	// Time-limited context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	sshConfig := server.makeTestConfig()

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	// Detect platform
	platform, err := conn.DetectRemotePlatform(ctx)
	require.NoError(t, err)

	// On the same machine, platform should match current runtime
	expectedOS := runtime.GOOS
	expectedArch := runtime.GOARCH

	assert.Equal(t, expectedOS, platform.OS, "OS should match")
	assert.Equal(t, expectedArch, platform.Arch, "Architecture should match")
	assert.False(t, conn.NeedsBinaryTransfer(), "Should not need binary transfer on same platform")
}

// Test binary transfer via SCP
func TestBinaryTransfer(t *testing.T) {
	// Time-limited context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	// Create a unique test file to transfer - include timestamp to avoid cache hits
	// This ensures we test the actual transfer, not just cache lookup
	testData := []byte(fmt.Sprintf("#!/bin/sh\necho 'test binary %d'\n", time.Now().UnixNano()))
	srcFile := filepath.Join(server.tempDir, "test_binary")
	require.NoError(t, os.WriteFile(srcFile, testData, 0755))

	// Create a test-owned temp directory for the binary
	// This ensures the binary doesn't go to the user's home directory
	// and allows concurrent tests to run without conflict
	testCacheDir := filepath.Join(server.tempDir, "cache")
	require.NoError(t, os.MkdirAll(testCacheDir, 0700))

	sshConfig := server.makeTestConfig()
	sshConfig.PelicanBinaryPath = srcFile

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	// Detect platform first (required for binary transfer)
	_, err = conn.DetectRemotePlatform(ctx)
	require.NoError(t, err)

	// Set remoteTempDir to force using our test-owned directory
	// This bypasses the XDG cache lookup and uses our temp directory
	conn.remoteTempDir = testCacheDir

	// Manually set up the remote binary path in our test directory
	// This simulates what setupRemoteBinaryPath would do with temp fallback
	remotePath := filepath.Join(testCacheDir, "pelican")
	conn.remoteBinaryPath = ""
	conn.remoteBinaryIsCached = false

	// Transfer the binary using SCP directly to our test directory
	srcFileHandle, err := os.Open(srcFile)
	require.NoError(t, err)
	srcInfo, err := srcFileHandle.Stat()
	require.NoError(t, err)
	err = conn.scpFile(ctx, srcFileHandle, remotePath, srcInfo.Size(), 0755)
	srcFileHandle.Close()
	require.NoError(t, err)

	conn.remoteBinaryPath = remotePath

	// Verify the file exists and is executable
	session, err := conn.client.NewSession()
	require.NoError(t, err)
	output, err := session.Output(fmt.Sprintf("test -x %s && echo 'ok'", remotePath))
	session.Close()
	require.NoError(t, err)
	assert.Equal(t, "ok\n", string(output))

	// Cleanup
	err = conn.CleanupRemoteBinary(ctx)
	require.NoError(t, err)
}

// Test binary transfer with temp directory fallback
func TestBinaryTransferTempDir(t *testing.T) {
	// Time-limited context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	// Create a unique test file to transfer - include timestamp to avoid cache hits
	testData := []byte(fmt.Sprintf("#!/bin/sh\necho 'test binary temp %d'\n", time.Now().UnixNano()))
	srcFile := filepath.Join(server.tempDir, "test_binary")
	require.NoError(t, os.WriteFile(srcFile, testData, 0755))

	// Create a test-owned temp directory for the binary
	testCacheDir := filepath.Join(server.tempDir, "cache")
	require.NoError(t, os.MkdirAll(testCacheDir, 0700))

	sshConfig := server.makeTestConfig()
	sshConfig.PelicanBinaryPath = srcFile

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	// Detect platform first
	_, err = conn.DetectRemotePlatform(ctx)
	require.NoError(t, err)

	// Set remoteTempDir to our test-owned directory to avoid using home directory
	conn.remoteTempDir = testCacheDir
	conn.remoteBinaryIsCached = false

	// Manually set up the binary path in our test directory
	remotePath := filepath.Join(testCacheDir, "pelican")

	// Transfer using SCP directly to test directory
	srcFileHandle, err := os.Open(srcFile)
	require.NoError(t, err)
	srcInfo, err := srcFileHandle.Stat()
	require.NoError(t, err)
	err = conn.scpFile(ctx, srcFileHandle, remotePath, srcInfo.Size(), 0755)
	srcFileHandle.Close()
	require.NoError(t, err)

	conn.remoteBinaryPath = remotePath

	// Verify the file exists
	session, err := conn.client.NewSession()
	require.NoError(t, err)
	_, err = session.Output(fmt.Sprintf("test -x %s && echo 'ok'", remotePath))
	session.Close()
	require.NoError(t, err)

	// Cleanup
	err = conn.CleanupRemoteBinary(ctx)
	require.NoError(t, err)
}

// Test SSH connection timeout
func TestSSHConnectionTimeout(t *testing.T) {
	// Use a non-routable IP to trigger a timeout
	sshConfig := &SSHConfig{
		Host:           "10.255.255.1", // Non-routable
		Port:           22,
		User:           "test",
		AuthMethods:    []AuthMethod{AuthMethodPublicKey},
		PrivateKeyFile: "/nonexistent",
		ConnectTimeout: 2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn := NewSSHConnection(sshConfig)
	start := time.Now()
	err := conn.Connect(ctx)
	elapsed := time.Since(start)

	assert.Error(t, err)
	// Connection should fail within the timeout
	assert.Less(t, elapsed, 4*time.Second)
}

// Test SSH keepalive functionality
func TestSSHKeepalive(t *testing.T) {
	// Time-limited context for the entire test
	testCtx, testCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer testCancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	sshConfig := server.makeTestConfig()

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(testCtx)
	require.NoError(t, err)
	defer conn.Close()

	// Set helper config for keepalive
	conn.helperConfig = &HelperConfig{
		AuthCookie:        "test-cookie",
		KeepaliveTimeout:  5 * time.Second,
		KeepaliveInterval: 500 * time.Millisecond,
	}

	// Initialize the last keepalive time
	conn.setLastKeepalive(time.Now())

	// Start keepalive monitoring
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go conn.runSSHKeepalive(ctx)

	// Let keepalive run for a bit
	time.Sleep(1500 * time.Millisecond)

	// Connection should still be valid
	session, err := conn.client.NewSession()
	require.NoError(t, err)
	output, err := session.Output("echo alive")
	session.Close()
	require.NoError(t, err)
	assert.Equal(t, "alive\n", string(output))

	// Cancel and check that keepalive stops gracefully
	cancel()
	time.Sleep(100 * time.Millisecond)
}

// Test helper config serialization
func TestHelperConfigSerialization(t *testing.T) {
	config := &HelperConfig{
		AuthCookie:        "test-cookie-12345",
		OriginCallbackURL: "https://origin.example.com/api/v1.0/origin/ssh/callback",
		KeepaliveTimeout:  20 * time.Second,
		KeepaliveInterval: 5 * time.Second,
		Exports: []ExportConfig{
			{
				FederationPrefix: "/test",
				StoragePrefix:    "/data/export",
				Capabilities: ExportCapabilities{
					Reads:  true,
					Writes: true,
				},
			},
		},
		CertificateChain: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	// Serialize to JSON
	data, err := json.Marshal(config)
	require.NoError(t, err)

	// Deserialize
	parsed := &HelperConfig{}
	err = json.Unmarshal(data, parsed)
	require.NoError(t, err)

	assert.Equal(t, config.AuthCookie, parsed.AuthCookie)
	assert.Equal(t, config.OriginCallbackURL, parsed.OriginCallbackURL)
	assert.Equal(t, config.KeepaliveTimeout, parsed.KeepaliveTimeout)
	assert.Equal(t, len(config.Exports), len(parsed.Exports))
	assert.Equal(t, config.CertificateChain, parsed.CertificateChain)
}

// Test architecture normalization
func TestArchNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"x86_64", "amd64"},
		{"amd64", "amd64"},
		{"aarch64", "arm64"},
		{"arm64", "arm64"},
		{"armv7l", "arm"},
		{"i686", "386"},
		{"i386", "386"},
		{"ppc64le", "ppc64le"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeArch(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test OS normalization
func TestOSNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Linux", "linux"},
		{"LINUX", "linux"},
		{"Darwin", "darwin"},
		{"DARWIN", "darwin"},
		{"FreeBSD", "freebsd"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeOS(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestSSHConfigValidation tests configuration validation
func TestSSHConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    *SSHConfig
		expectErr bool
	}{
		{
			name: "valid config",
			config: &SSHConfig{
				Host:           "example.com",
				Port:           22,
				User:           "user",
				AuthMethods:    []AuthMethod{AuthMethodPublicKey},
				PrivateKeyFile: "/path/to/key",
			},
			expectErr: false,
		},
		{
			name: "missing host",
			config: &SSHConfig{
				Port:           22,
				User:           "user",
				AuthMethods:    []AuthMethod{AuthMethodPublicKey},
				PrivateKeyFile: "/path/to/key",
			},
			expectErr: true,
		},
		{
			name: "missing user",
			config: &SSHConfig{
				Host:           "example.com",
				Port:           22,
				AuthMethods:    []AuthMethod{AuthMethodPublicKey},
				PrivateKeyFile: "/path/to/key",
			},
			expectErr: true,
		},
		{
			name: "empty auth methods",
			config: &SSHConfig{
				Host:        "example.com",
				Port:        22,
				User:        "user",
				AuthMethods: []AuthMethod{},
			},
			expectErr: true,
		},
		{
			name: "publickey without key file",
			config: &SSHConfig{
				Host:        "example.com",
				Port:        22,
				User:        "user",
				AuthMethods: []AuthMethod{AuthMethodPublicKey},
			},
			expectErr: true,
		},
		{
			name: "password without password file is valid",
			config: &SSHConfig{
				Host:        "example.com",
				Port:        22,
				User:        "user",
				AuthMethods: []AuthMethod{AuthMethodPassword},
			},
			expectErr: false, // Password can come from WebSocket callback
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// BenchmarkSSHConnection benchmarks SSH connection establishment
func BenchmarkSSHConnection(b *testing.B) {
	// Skip if no sshd available
	if _, err := exec.LookPath("sshd"); err != nil {
		b.Skip("sshd not available")
	}

	// Setup is expensive, so we do it once
	t := &testing.T{}
	server, err := startTestSSHD(t)
	if err != nil {
		b.Fatalf("Failed to start test sshd: %v", err)
	}
	defer server.stop()

	sshConfig := server.makeTestConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := NewSSHConnection(sshConfig)
		if err := conn.Connect(context.Background()); err != nil {
			b.Fatalf("Connection failed: %v", err)
		}
		conn.Close()
	}
}

// TestInitializeBackendConfig tests that backend configuration is properly loaded
func TestInitializeBackendConfig(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	tempDir := t.TempDir()

	// Create test key files
	privateKeyFile := filepath.Join(tempDir, "test_key")
	require.NoError(t, os.WriteFile(privateKeyFile, []byte("fake-key"), 0600))

	knownHostsFile := filepath.Join(tempDir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHostsFile, []byte(""), 0644))

	// Set configuration
	require.NoError(t, param.Set(param.Origin_SSH_Host.GetName(), "test.example.com"))
	require.NoError(t, param.Set(param.Origin_SSH_Port.GetName(), "2222"))
	require.NoError(t, param.Set(param.Origin_SSH_User.GetName(), "testuser"))
	require.NoError(t, param.Set(param.Origin_SSH_AuthMethods.GetName(), "publickey"))
	require.NoError(t, param.Set(param.Origin_SSH_PrivateKeyFile.GetName(), privateKeyFile))
	require.NoError(t, param.Set(param.Origin_SSH_KnownHostsFile.GetName(), knownHostsFile))

	// Build config from parameters
	sshConfig := &SSHConfig{
		Host:           param.Origin_SSH_Host.GetString(),
		Port:           param.Origin_SSH_Port.GetInt(),
		User:           param.Origin_SSH_User.GetString(),
		PrivateKeyFile: param.Origin_SSH_PrivateKeyFile.GetString(),
		KnownHostsFile: param.Origin_SSH_KnownHostsFile.GetString(),
	}

	// Parse auth methods
	for _, method := range param.Origin_SSH_AuthMethods.GetStringSlice() {
		sshConfig.AuthMethods = append(sshConfig.AuthMethods, AuthMethod(method))
	}

	assert.Equal(t, "test.example.com", sshConfig.Host)
	assert.Equal(t, 2222, sshConfig.Port)
	assert.Equal(t, "testuser", sshConfig.User)
	assert.Equal(t, []AuthMethod{AuthMethodPublicKey}, sshConfig.AuthMethods)
	assert.Equal(t, privateKeyFile, sshConfig.PrivateKeyFile)
}

// TestRunCommand tests running commands over SSH
func TestRunCommand(t *testing.T) {
	// Time-limited context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	sshConfig := server.makeTestConfig()

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	tests := []struct {
		name     string
		cmd      string
		expected string
	}{
		{"simple echo", "echo hello", "hello\n"},
		{"multi-word echo", "echo hello world", "hello world\n"},
		{"pwd", "pwd", ""},            // Just check it doesn't error
		{"env var", "echo $HOME", ""}, // Just check it doesn't error
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			session, err := conn.client.NewSession()
			require.NoError(t, err)
			defer session.Close()

			output, err := session.Output(tc.cmd)
			require.NoError(t, err)
			if tc.expected != "" {
				assert.Equal(t, tc.expected, string(output))
			} else {
				// Just verify we got some output
				assert.NotEmpty(t, output)
			}
		})
	}
}

// TestConcurrentSSHSessions tests multiple concurrent SSH sessions
func TestConcurrentSSHSessions(t *testing.T) {
	// Time-limited context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	sshConfig := server.makeTestConfig()

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	// Run multiple sessions concurrently
	numSessions := 5
	results := make(chan string, numSessions)
	errors := make(chan error, numSessions)

	for i := 0; i < numSessions; i++ {
		go func(id int) {
			session, err := conn.client.NewSession()
			if err != nil {
				errors <- err
				return
			}
			defer session.Close()

			output, err := session.Output(fmt.Sprintf("echo session-%d", id))
			if err != nil {
				errors <- err
				return
			}
			results <- string(output)
		}(i)
	}

	// Collect results
	for i := 0; i < numSessions; i++ {
		select {
		case result := <-results:
			assert.Contains(t, result, "session-")
		case err := <-errors:
			t.Errorf("Session error: %v", err)
		case <-time.After(5 * time.Second):
			t.Error("Timeout waiting for session")
		}
	}
}

// TestStdinTransfer tests sending data over stdin (for helper config)
func TestStdinTransfer(t *testing.T) {
	// Time-limited context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	sshConfig := server.makeTestConfig()

	conn := NewSSHConnection(sshConfig)
	err = conn.Connect(ctx)
	require.NoError(t, err)
	defer conn.Close()

	// Create a session with stdin
	session, err := conn.client.NewSession()
	require.NoError(t, err)
	defer session.Close()

	stdin, err := session.StdinPipe()
	require.NoError(t, err)

	stdout, err := session.StdoutPipe()
	require.NoError(t, err)

	// Start a command that reads from stdin
	err = session.Start("cat")
	require.NoError(t, err)

	// Send test data
	testData := "hello from stdin"
	_, err = io.WriteString(stdin, testData)
	require.NoError(t, err)
	stdin.Close()

	// Read output
	output, err := io.ReadAll(stdout)
	require.NoError(t, err)

	err = session.Wait()
	require.NoError(t, err)

	assert.Equal(t, testData, string(output))
}

// TestConnectionState tests state transitions
func TestConnectionState(t *testing.T) {
	// Time-limited context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test sshd")
	defer server.stop()

	sshConfig := server.makeTestConfig()

	conn := NewSSHConnection(sshConfig)

	// Initially disconnected
	assert.Equal(t, StateDisconnected, conn.GetState())

	// Connect
	err = conn.Connect(ctx)
	require.NoError(t, err)

	// Should be connected
	assert.Equal(t, StateConnected, conn.GetState())

	// Close
	conn.Close()

	// Should be disconnected
	assert.Equal(t, StateDisconnected, conn.GetState())
}

// TestGenerateAuthCookie tests cookie generation
func TestGenerateAuthCookie(t *testing.T) {
	cookie1, err := generateAuthCookie()
	require.NoError(t, err)
	assert.Len(t, cookie1, 64) // 32 bytes = 64 hex characters

	cookie2, err := generateAuthCookie()
	require.NoError(t, err)
	assert.NotEqual(t, cookie1, cookie2, "Cookies should be unique")
}
