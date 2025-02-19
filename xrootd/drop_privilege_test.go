//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package xrootd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

const (
	CmdUpdateCA = 1
)

// isValidFD checks if a file descriptor is valid.
func isValidFD(fd int) (bool, error) {
	if fd < 0 {
		return false, nil
	}
	var stat syscall.Stat_t
	err := syscall.Fstat(fd, &stat)
	if err != nil && err != syscall.EBADF {
		return false, err
	}
	return true, err
}

func mockXRootDProcess(t *testing.T, fds [2]int, ready chan<- struct{}) {
	t.Logf("Mock XRootD Process started. FDs: %v", fds)
	close(ready) // Signal that mockXRootDProcess is ready

	commandBuf := make([]byte, 1)

	// Read the command byte sent by the another process
	n, err := syscall.Read(fds[0], commandBuf)
	if err != nil {
		t.Errorf("Mock XRootD: Error receiving command: %v", err)
		return
	}
	if n != 1 {
		t.Errorf("Mock XRootD: Expected to read 1 command byte, but read: %d", n)
		return
	}

	cmd := commandBuf[0]

	switch cmd {
	case byte(CmdUpdateCA):
		t.Log("Mock XRootD: Received CmdUpdateCA")
	default:
		t.Errorf("Mock XRootD received unexpected command")
		return
	}
}

func startMockXrootdProcess(t *testing.T, isOrigin bool) (ready <-chan struct{}) {
	readyChan := make(chan struct{})
	ready = readyChan

	var targetFds *[2]int
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	if isOrigin {
		g_origin_fds = [2]int{fds[0], fds[1]}
		targetFds = &g_origin_fds
	} else {
		g_cache_fds = [2]int{fds[0], fds[1]}
		targetFds = &g_cache_fds
	}

	isValidFD, err := isValidFD(g_origin_fds[1])
	require.True(t, isValidFD, "Write file descriptor is not valid (os.Stat err)")
	require.NoError(t, err)

	go mockXRootDProcess(t, *targetFds, readyChan)

	return ready
}

// receiveFD reads the file descriptor from its global variable
func receiveFD(isOrigin bool) (int, error) {
	var readFD int

	if isOrigin {
		readFD = g_origin_fds[0]
	} else {
		readFD = g_cache_fds[0]
	}

	isValid, err := isValidFD(readFD)
	if !isValid || err != nil {
		return -1, fmt.Errorf("invalid FD: %d %w", readFD, err)
	}

	return readFD, nil
}

// generateTestCert generates a self-signed certificate and key for testing
func generateTestCert(runDir string) (certPath, keyPath string, err error) {
	// Create cert and key files
	certPath = filepath.Join(runDir, "cert.pem")
	keyPath = filepath.Join(runDir, "key.pem")

	viper.Set("IssuerKey", keyPath)
	viper.Set("Server.TLSCertificateChain", certPath)
	viper.Set("Server.TLSKey", keyPath)
	viper.Set("Server.TLSCACertificateFile", filepath.Join(runDir, "ca.pem"))
	viper.Set("Server.TLSCAKey", filepath.Join(runDir, "ca-key.pem"))
	viper.Set("Server.Hostname", "localhost")

	err = config.GenerateCert() // GenerateCert uses the viper config set above

	return certPath, keyPath, err
}

func TestDropPrivilegeSignaling(t *testing.T) {
	server_utils.ResetTestState()
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
		server_utils.ResetTestState()
	})

	runDir := t.TempDir()
	viper.Set("Origin.RunLocation", runDir)
	viper.Set("Cache.RunLocation", runDir)
	viper.Set("ConfigDir", runDir)
	config.InitConfig()

	pelicanDir := filepath.Join(runDir, "pelican")
	err := os.Mkdir(pelicanDir, 0755)
	require.NoError(t, err, "Failed to create pelican directory")

	// Set the configuration parameters before calling any xrootd functions
	certFile, keyFile, err := generateTestCert(runDir)
	require.NoError(t, err, "Failed to generate test certificate")

	require.NotEmpty(t, certFile, "Empty certificate file path")
	require.NotEmpty(t, keyFile, "Empty key file path")

	// Dummy CA bundle data
	caBundleData := []byte("Test CA Bundle Content")
	caBundleFile := filepath.Join(runDir, "ca-bundle.crt")
	require.NoError(t, os.WriteFile(caBundleFile, caBundleData, 0644))

	// Open the CA bundle file
	caBundle, err := os.Open(caBundleFile)
	require.NoError(t, err, "Failed to open CA bundle file")
	defer caBundle.Close()

	isOrigin := true
	// Start mock XRootD (sets up the IPC)
	ready := startMockXrootdProcess(t, isOrigin)
	defer func() {
		err := closeChildSocket(isOrigin)
		require.NoError(t, err, "Failed to close child socket")
	}()

	// The ready channel signals to the test function that the mock XRootD process is ready to receive data (the command byte)
	<-ready

	viper.Set("Server.DropPrivileges", true)

	// Send the command byte BEFORE calling dropPrivilegeCopy
	command := []byte{byte(CmdUpdateCA)}

	if isOrigin {
		// Verify FD is valid before writing
		isValidFD, err := isValidFD(g_origin_fds[1])
		require.True(t, isValidFD, "Write file descriptor is not valid (os.Stat err)")
		require.NoError(t, err)

		t.Log("Global origin FDs: ", g_origin_fds)
		t.Logf("Writing %x to fd %d", command, g_origin_fds[1])

		n, err := syscall.Write(g_origin_fds[1], command)
		require.NoError(t, err, "Failed to send command byte")
		require.Equal(t, 1, n, "Expected to write 1 byte")
	} else {
		_, err = syscall.Write(g_cache_fds[1], command)
		require.NoError(t, err, "Failed to send command byte")
	}

	// Call the function under test
	t.Logf("Before dropPrivilegeCopy, g_origin_fds: %v", g_origin_fds)
	err = dropPrivilegeCopy(&origin.OriginServer{})
	require.NoError(t, err, "dropPrivilegeCopy failed")
	t.Logf("After dropPrivilegeCopy, g_origin_fds: %v", g_origin_fds)

	// Get the file descriptor sent by dropPrivilegeCopy
	_, err = receiveFD(isOrigin)
	require.NoError(t, err)
}
