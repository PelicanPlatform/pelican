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

package fed_tests

import (
	"crypto/md5"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

var (
	buildOnce         sync.Once
	pelicanBinPath    string
	binaryTempDir     string
	binaryBuildErr    error
	binaryBuildOutput []byte
)

// waitForSSHBackendReady waits for the SSH backend to report healthy status
func waitForSSHBackendReady(t *testing.T, timeout time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool {
		status, err := metrics.GetComponentStatus(metrics.Origin_SSHBackend)
		if err != nil {
			return false
		}
		return status == metrics.StatusOK.String()
	}, timeout, 100*time.Millisecond, "SSH backend did not become ready (status OK)")
}

// TestMain sets up fixtures that persist across all tests
func TestMain(m *testing.M) {
	// Run all tests
	code := m.Run()

	// Cleanup binary temp directory if it was created
	if binaryTempDir != "" {
		os.RemoveAll(binaryTempDir)
	}
	os.Exit(code)
}

// testSSHDServer represents a temporary sshd server for testing
type testSSHDServer struct {
	cmd            *exec.Cmd
	port           int
	hostKeyFile    string
	authKeysFile   string
	configFile     string
	pidFile        string
	knownHostsFile string
	privateKeyFile string
	tempDir        string
	storageDir     string
}

// startTestSSHD starts a temporary sshd for E2E testing
// The sshd instance is configured for key-based authentication only
func startTestSSHD(t *testing.T) (*testSSHDServer, error) {
	tempDir := t.TempDir()

	// Create storage directory for the origin
	storageDir := filepath.Join(tempDir, "storage")
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Generate host key
	hostKeyFile := filepath.Join(tempDir, "host_key")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", hostKeyFile, "-N", "", "-q")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	// Generate user key for authentication
	userKeyFile := filepath.Join(tempDir, "user_key")
	cmd = exec.Command("ssh-keygen", "-t", "ed25519", "-f", userKeyFile, "-N", "", "-q")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to generate user key: %w", err)
	}

	// Read public key and create authorized_keys
	pubKey, err := os.ReadFile(userKeyFile + ".pub")
	if err != nil {
		return nil, fmt.Errorf("failed to read user public key: %w", err)
	}
	authKeysFile := filepath.Join(tempDir, "authorized_keys")
	if err := os.WriteFile(authKeysFile, pubKey, 0600); err != nil {
		return nil, fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	// Create a listener on port 0 to get an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	// Close the listener before starting sshd
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
	logFile := filepath.Join(tempDir, "sshd.log")
	sshdCmd := exec.Command("/usr/sbin/sshd", "-D", "-f", configFile, "-E", logFile)
	if err := sshdCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sshd: %w", err)
	}

	server := &testSSHDServer{
		cmd:            sshdCmd,
		port:           port,
		hostKeyFile:    hostKeyFile,
		authKeysFile:   authKeysFile,
		configFile:     configFile,
		pidFile:        pidFile,
		knownHostsFile: knownHostsFile,
		privateKeyFile: userKeyFile,
		tempDir:        tempDir,
		storageDir:     storageDir,
	}

	// Wait for sshd to be ready using require.Eventually to follow testing guidelines
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
func (s *testSSHDServer) stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
}

// sshOriginConfig generates the origin configuration template for SSH backend
func sshOriginConfig(sshPort int, storageDir, knownHostsFile, privateKeyFile, pelicanBinaryPath string) string {
	currentUserInfo, err := user.Current()
	currentUser := "root"
	if err == nil {
		currentUser = currentUserInfo.Username
	}

	return fmt.Sprintf(`
Origin:
  StorageType: ssh
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Reads", "Writes", "Listings"]
  SSH:
    Host: 127.0.0.1
    Port: %d
    User: %s
    AuthMethods: ["publickey"]
    PrivateKeyFile: %s
    KnownHostsFile: %s
    PelicanBinaryPath: %s
    ConnectTimeout: 30s
    SessionEstablishTimeout: 60s
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, storageDir, sshPort, currentUser, privateKeyFile, knownHostsFile, pelicanBinaryPath)
}

// buildPelicanBinary builds the pelican binary on first call and returns its path.
// The binary is built once and shared across all tests, then cleaned up in TestMain.
func buildPelicanBinary(t *testing.T) string {
	buildOnce.Do(func() {
		var err error
		binaryTempDir, err = os.MkdirTemp("", "pelican-ssh-e2e-test-*")
		if err != nil {
			binaryBuildErr = fmt.Errorf("failed to create temp directory: %w", err)
			return
		}

		pelicanBinPath = filepath.Join(binaryTempDir, "pelican")
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", pelicanBinPath, "../cmd")
		binaryBuildOutput, binaryBuildErr = cmd.CombinedOutput()
		if binaryBuildErr != nil {
			os.RemoveAll(binaryTempDir)
			binaryTempDir = ""
		}
	})

	if binaryBuildErr != nil {
		t.Fatalf("Failed to build pelican binary: %v\nOutput: %s", binaryBuildErr, binaryBuildOutput)
	}

	return pelicanBinPath
}

// TestSSHPosixv2OriginUploadDownload tests basic upload and download operations
// using the SSH POSIXv2 backend through the federation.
func TestSSHPosixv2OriginUploadDownload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Skip if sshd is not available
	if _, err := exec.LookPath("/usr/sbin/sshd"); err != nil {
		t.Skip("sshd not available, skipping SSH E2E test")
	}

	// Build the pelican binary (built once and shared across tests)
	pelicanBinary := buildPelicanBinary(t)

	// Start the test SSH server
	sshServer, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test SSH server")
	t.Cleanup(sshServer.stop)

	t.Logf("Started test SSH server on port %d with storage at %s", sshServer.port, sshServer.storageDir)

	// Configure origin with SSH storage
	originConfig := sshOriginConfig(sshServer.port, sshServer.storageDir, sshServer.knownHostsFile, sshServer.privateKeyFile, pelicanBinary)

	// Set up the federation test with the SSH origin config
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Wait for SSH backend to be ready - it needs to connect and transfer the helper binary
	waitForSSHBackendReady(t, 60*time.Second)

	// Create a test file to upload
	testContent := []byte("Hello from SSH POSIXv2 E2E test!")
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "test.txt")
	require.NoError(t, os.WriteFile(localFile, testContent, 0644))

	// Upload the file using the Pelican client
	uploadURL := fmt.Sprintf("pelican://%s:%d/test/test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)

	// Upload should succeed immediately since SSH backend is now ready
	_, err = client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err, "Upload should succeed")

	// Verify file exists in backend storage
	backendFile := filepath.Join(sshServer.storageDir, "test.txt")
	backendContent, err := os.ReadFile(backendFile)
	require.NoError(t, err, "File should exist in backend storage")
	assert.Equal(t, testContent, backendContent, "Backend file content should match")

	// Download the file
	downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
	transferResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err, "Download should succeed")
	require.NotEmpty(t, transferResults, "Should have transfer results")
	assert.Equal(t, int64(len(testContent)), transferResults[0].TransferredBytes, "Downloaded bytes should match")

	// Verify downloaded content
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, downloadedContent, "Downloaded content should match original")
}

// TestSSHPosixv2OriginStat tests stat operations with checksum verification
func TestSSHPosixv2OriginStat(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Skip if sshd is not available
	if _, err := exec.LookPath("/usr/sbin/sshd"); err != nil {
		t.Skip("sshd not available, skipping SSH E2E test")
	}

	// Build the pelican binary (built once and shared across tests)
	pelicanBinary := buildPelicanBinary(t)

	sshServer, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test SSH server")
	t.Cleanup(sshServer.stop)

	originConfig := sshOriginConfig(sshServer.port, sshServer.storageDir, sshServer.knownHostsFile, sshServer.privateKeyFile, pelicanBinary)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Wait for SSH backend to be ready
	waitForSSHBackendReady(t, 60*time.Second)

	// Create a test file with known content for checksum verification
	testContent := []byte("Content for stat test with checksum verification")
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "stat_test.txt")
	require.NoError(t, os.WriteFile(localFile, testContent, 0644))

	expectedChecksum := fmt.Sprintf("%x", md5.Sum(testContent))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/stat_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)

	// Upload file (should succeed immediately since SSH backend is ready)
	_, err = client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err, "Upload should succeed")

	// Perform stat operation
	statInfo, err := client.DoStat(ft.Ctx, uploadURL, client.WithToken(testToken))
	require.NoError(t, err, "Stat should succeed")
	require.NotNil(t, statInfo, "Should have stat info")

	assert.Equal(t, int64(len(testContent)), statInfo.Size, "Stat size should match content length")
	assert.False(t, statInfo.IsCollection, "Should not be a collection")

	// If checksums are returned, verify MD5 if present
	if md5Checksum, ok := statInfo.Checksums["md5"]; ok {
		assert.Equal(t, expectedChecksum, md5Checksum, "MD5 checksum should match expected")
	}
}

// TestSSHPosixv2OriginLargeFile tests transfer of larger files through SSH backend
func TestSSHPosixv2OriginLargeFile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Skip if sshd is not available
	if _, err := exec.LookPath("/usr/sbin/sshd"); err != nil {
		t.Skip("sshd not available, skipping SSH E2E test")
	}

	// Build the pelican binary (built once and shared across tests)
	pelicanBinary := buildPelicanBinary(t)

	sshServer, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test SSH server")
	t.Cleanup(sshServer.stop)

	originConfig := sshOriginConfig(sshServer.port, sshServer.storageDir, sshServer.knownHostsFile, sshServer.privateKeyFile, pelicanBinary)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Wait for SSH backend to be ready
	waitForSSHBackendReady(t, 60*time.Second)

	// Create a larger test file (1MB)
	largeContent := make([]byte, 1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "large_file.bin")
	require.NoError(t, os.WriteFile(localFile, largeContent, 0644))

	originalHash := fmt.Sprintf("%x", md5.Sum(largeContent))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/large_file.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)

	// Upload file (should succeed immediately since SSH backend is ready)
	_, err = client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err, "Upload should succeed")

	// Download the large file
	downloadFile := filepath.Join(localTmpDir, "downloaded_large.bin")
	transferResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err, "Download should succeed")
	require.NotEmpty(t, transferResults)
	assert.Equal(t, int64(len(largeContent)), transferResults[0].TransferredBytes)

	// Verify content integrity
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	downloadedHash := fmt.Sprintf("%x", md5.Sum(downloadedContent))
	assert.Equal(t, originalHash, downloadedHash, "Downloaded file hash should match original")
}

// TestSSHPosixv2OriginDirectoryListing tests directory listing through SSH backend
func TestSSHPosixv2OriginDirectoryListing(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Skip if sshd is not available
	if _, err := exec.LookPath("/usr/sbin/sshd"); err != nil {
		t.Skip("sshd not available, skipping SSH E2E test")
	}

	// Build the pelican binary (built once and shared across tests)
	pelicanBinary := buildPelicanBinary(t)

	sshServer, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test SSH server")
	t.Cleanup(sshServer.stop)

	originConfig := sshOriginConfig(sshServer.port, sshServer.storageDir, sshServer.knownHostsFile, sshServer.privateKeyFile, pelicanBinary)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Wait for SSH backend to be ready
	waitForSSHBackendReady(t, 60*time.Second)

	// Create directory structure in the storage backend directly
	subdir := filepath.Join(sshServer.storageDir, "subdir")
	require.NoError(t, os.Mkdir(subdir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sshServer.storageDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sshServer.storageDir, "file2.txt"), []byte("content2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "file3.txt"), []byte("content3"), 0644))

	testToken := getTempTokenForTest(t)

	// List directory (should succeed immediately since SSH backend is ready)
	listURL := fmt.Sprintf("pelican://%s:%d/test/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	entries, err := client.DoList(ft.Ctx, listURL, client.WithToken(testToken))
	require.NoError(t, err, "List should succeed")
	require.NotEmpty(t, entries, "Should have entries in root directory")

	// Verify we have both files and directory
	var hasFile1, hasFile2, hasSubdir bool
	for _, entry := range entries {
		if strings.Contains(entry.Name, "file1.txt") && !entry.IsCollection {
			hasFile1 = true
		} else if strings.Contains(entry.Name, "file2.txt") && !entry.IsCollection {
			hasFile2 = true
		} else if strings.Contains(entry.Name, "subdir") && entry.IsCollection {
			hasSubdir = true
		}
	}

	assert.True(t, hasFile1, "Should list file1.txt")
	assert.True(t, hasFile2, "Should list file2.txt")
	assert.True(t, hasSubdir, "Should list subdir directory")

	// Test subdirectory listing
	subdirURL := fmt.Sprintf("pelican://%s:%d/test/subdir/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	subEntries, err := client.DoList(ft.Ctx, subdirURL, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to list subdirectory")
	require.NotEmpty(t, subEntries, "Should have entries in subdirectory")

	var hasFile3 bool
	for _, entry := range subEntries {
		if strings.Contains(entry.Name, "file3.txt") && !entry.IsCollection {
			hasFile3 = true
		}
	}
	assert.True(t, hasFile3, "Should list file3.txt in subdirectory")
}

// TestSSHPosixv2OriginMultipleFiles tests uploading and downloading multiple files
func TestSSHPosixv2OriginMultipleFiles(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Skip if sshd is not available
	if _, err := exec.LookPath("/usr/sbin/sshd"); err != nil {
		t.Skip("sshd not available, skipping SSH E2E test")
	}

	// Build the pelican binary (built once and shared across tests)
	pelicanBinary := buildPelicanBinary(t)

	sshServer, err := startTestSSHD(t)
	require.NoError(t, err, "Failed to start test SSH server")
	t.Cleanup(sshServer.stop)

	originConfig := sshOriginConfig(sshServer.port, sshServer.storageDir, sshServer.knownHostsFile, sshServer.privateKeyFile, pelicanBinary)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Wait for SSH backend to be ready
	waitForSSHBackendReady(t, 60*time.Second)

	localTmpDir := t.TempDir()
	testToken := getTempTokenForTest(t)

	// Define multiple test files
	testFiles := map[string][]byte{
		"file1.txt": []byte("Content of file 1"),
		"file2.txt": []byte("Content of file 2"),
		"file3.txt": []byte("Content of file 3"),
	}

	// Upload all files
	for filename, content := range testFiles {
		localFile := filepath.Join(localTmpDir, filename)
		require.NoError(t, os.WriteFile(localFile, content, 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)

		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err, "Upload should succeed for %s", filename)
	}

	// Download and verify all files
	for filename, expectedContent := range testFiles {
		downloadFile := filepath.Join(localTmpDir, "downloaded_"+filename)
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)

		_, err := client.DoGet(ft.Ctx, downloadURL, downloadFile, false, client.WithToken(ft.Token))
		require.NoError(t, err, "Download should succeed for %s", filename)

		downloadedContent, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, expectedContent, downloadedContent, "Content should match for %s", filename)
	}
}
