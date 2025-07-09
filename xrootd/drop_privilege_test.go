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
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

const (
	CmdUpdateCA = 1
)

// validateFD checks if a file descriptor is valid.
func validateFD(fd int) (bool, error) {
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

func mockXRootDProcess(t *testing.T, fds [2]int, ready chan<- struct{}, wg *sync.WaitGroup) {
	defer wg.Done() // Signal that the mockXRootDProcess has finished

	readFD := fds[0]
	t.Logf("Mock XRootD Process started. FDs: %d", readFD)
	close(ready) // Signal that mockXRootDProcess is ready

	commandBuf := make([]byte, 1)

	// Read the command byte sent by the another process
	n, err := syscall.Read(readFD, commandBuf)
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

func startMockXrootdProcess(t *testing.T, isOrigin bool, wg *sync.WaitGroup) (ready <-chan struct{}) {
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
	t.Log("Global origin FDs after Socketpair setup: ", g_origin_fds)
	t.Log("Global cache FDs after Socketpair setup: ", g_cache_fds)
	var isValidFD bool
	if isOrigin {
		isValidFD, err = validateFD(g_origin_fds[1])
	} else {
		isValidFD, err = validateFD(g_cache_fds[1])
	}
	require.True(t, isValidFD, "Write file descriptor is not valid (os.Stat err)")
	require.NoError(t, err)

	wg.Add(1)

	go mockXRootDProcess(t, *targetFds, readyChan, wg)

	return ready
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
		// Clean up global FDs state
		g_origin_fds = [2]int{-1, -1}
		g_cache_fds = [2]int{-1, -1}

		cancel()
		require.NoError(t, egrp.Wait())
		server_utils.ResetTestState()
	})

	testCases := []struct {
		name     string
		isOrigin bool
	}{
		{"Origin", true},
		{"Cache", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() {
				server_utils.ResetTestState()
				// Clean up global FDs state
				g_origin_fds = [2]int{-1, -1}
				g_cache_fds = [2]int{-1, -1}
			})
			t.Log("Global origin FDs: ", g_origin_fds)
			runDir := t.TempDir()
			viper.Set("Origin.RunLocation", runDir)
			viper.Set("Cache.RunLocation", runDir)
			viper.Set("ConfigDir", runDir)

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

			var wg sync.WaitGroup

			isOrigin := tc.isOrigin
			// Start mock XRootD (sets up the IPC)
			ready := startMockXrootdProcess(t, isOrigin, &wg)
			defer func() {
				// Wait for the mock XRootD process to finish
				wg.Wait() // Block until wg.Done() is called in the mock XRootD process
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
				isValidFD, err := validateFD(g_origin_fds[1])
				require.True(t, isValidFD, "Write file descriptor is not valid (os.Stat err)")
				require.NoError(t, err)

				t.Log("Global origin FDs: ", g_origin_fds)
				t.Logf("Writing %x to fd %d", command, g_origin_fds[1])

				n, err := syscall.Write(g_origin_fds[1], command)
				require.NoError(t, err, "Failed to send command byte")
				require.Equal(t, 1, n, "Expected to write 1 byte")
			} else {
				isValidFD, err := validateFD(g_cache_fds[1])
				require.True(t, isValidFD, "Write file descriptor is not valid (os.Stat err)")
				require.NoError(t, err)

				t.Log("Global cache FDs: ", g_cache_fds)
				t.Logf("Writing %x to fd %d", command, g_cache_fds[1])

				_, err = syscall.Write(g_cache_fds[1], command)
				require.NoError(t, err, "Failed to send command byte")
			}

			if isOrigin {
				err = dropPrivilegeCopy(&origin.OriginServer{})
			} else {
				err = dropPrivilegeCopy(&cache.CacheServer{})
			}
			require.NoError(t, err, "dropPrivilegeCopy failed")

			// Verify the caBundleFile has been transferred in dropPrivilegeCopy func
			expectedTransferredCAFileLocation := filepath.Join(runDir, "pelican", "copied-tls-creds.crt")
			_, err = os.Stat(expectedTransferredCAFileLocation)
			require.NoError(t, err, "Expected CA file does not exist")

			// Verify the contents of the transferred CA file
			transferredData, err := os.ReadFile(expectedTransferredCAFileLocation)
			require.NoError(t, err, "Failed to read transferred CA file")
			transferredContents := string(transferredData)
			require.Contains(t, transferredContents, "-----BEGIN CERTIFICATE-----", "Certificate header missing from transferred CA file")
			require.Contains(t, transferredContents, "-----BEGIN PRIVATE KEY-----", "Private key header missing from transferred CA file")

		})
	}

}
