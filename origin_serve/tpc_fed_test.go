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

package origin_serve_test

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	//go:embed resources/posixv2-auth.yml
	posixv2AuthCfg string

	//go:embed resources/posix-auth.yml
	posixAuthCfg string
)

// getTestToken generates a short-lived WLCG token with read, create, and modify
// scopes rooted at "/".  It writes the token to a temp file and returns both
// the file handle and the raw token string.
func getTestToken(t *testing.T) (tokenFile *os.File, tkn string) {
	t.Helper()
	require.NoError(t, param.IssuerKeysDirectory.Set(t.TempDir()))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope, createScope, modScope)

	tkn, err = tokenConfig.CreateToken()
	require.NoError(t, err)

	tokenFile, err = os.CreateTemp(t.TempDir(), "token")
	require.NoError(t, err)
	_, err = tokenFile.WriteString(tkn)
	require.NoError(t, err)
	tokenFile.Close()
	return
}

// getReadOnlyToken generates a short-lived WLCG token with only storage.read
// scope. This is insufficient for COPY which requires storage.create.
func getReadOnlyToken(t *testing.T) string {
	t.Helper()
	require.NoError(t, param.IssuerKeysDirectory.Set(t.TempDir()))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// dumpFileToTestLog logs the contents of a file into the test output,
// truncating from the beginning when the file is large.
func dumpFileToTestLog(t *testing.T, filePath, label string) {
	t.Helper()

	contents, err := os.ReadFile(filePath)
	if err != nil {
		t.Logf("Failed to read %s at %s: %v", label, filePath, err)
		return
	}

	const maxBytes = 128 * 1024
	if len(contents) > maxBytes {
		contents = contents[len(contents)-maxBytes:]
		t.Logf("%s is larger than %d bytes; showing the last %d bytes", label, maxBytes, maxBytes)
	}

	t.Logf("===== Begin %s (%s) =====\n%s\n===== End %s =====", label, filePath, string(contents), label)
}

// waitForURLStatusOrProcessExit polls an endpoint until it returns the expected
// status code, while also checking whether the subprocess has exited unexpectedly.
func waitForURLStatusOrProcessExit(
	t *testing.T,
	ctx context.Context,
	url string,
	expectedStatus int,
	timeout time.Duration,
	pollInterval time.Duration,
	exitCh <-chan error,
	origin2LogPath string,
	name string,
) error {
	t.Helper()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	client := &http.Client{
		Transport: config.GetTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	lastStatus := 0
	var lastErr error

	for {
		select {
		case waitErr := <-exitCh:
			dumpFileToTestLog(t, origin2LogPath, "origin2.log")
			if waitErr != nil {
				return fmt.Errorf("origin2 exited unexpectedly while waiting for %s: %w", name, waitErr)
			}
			return fmt.Errorf("origin2 exited while waiting for %s", name)
		case <-ctx.Done():
			dumpFileToTestLog(t, origin2LogPath, "origin2.log")
			return fmt.Errorf("context cancelled while waiting for %s: %w", name, ctx.Err())
		case <-ticker.C:
			if time.Now().After(deadline) {
				dumpFileToTestLog(t, origin2LogPath, "origin2.log")
				if lastErr != nil {
					return fmt.Errorf("timed out waiting for %s at %s; last error: %w", name, url, lastErr)
				}
				return fmt.Errorf("timed out waiting for %s at %s; last HTTP status: %d (expected %d)", name, url, lastStatus, expectedStatus)
			}

			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if reqErr != nil {
				lastErr = reqErr
				continue
			}

			resp, doErr := client.Do(req)
			if doErr != nil {
				lastErr = doErr
				continue
			}

			lastStatus = resp.StatusCode
			resp.Body.Close()
			lastErr = nil

			if resp.StatusCode == expectedStatus {
				return nil
			}
		}
	}
}

// TestTPCWithPOSIXv2 verifies that DoCopy (third-party copy) works end-to-end
// against a POSIXv2 origin, exercising the TPC COPY handler.
func TestTPCWithPOSIXv2(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	fed := fed_test_utils.NewFedTest(t, posixv2AuthCfg)

	// Disable SSRF protection for federation tests where the origin
	// connects to itself via a local hostname that resolves to a
	// private/link-local address.  The SSRF dialer is thoroughly
	// tested in config/ssrf_transport_test.go.
	require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()

	tokenFile, tkn := getTestToken(t)
	defer os.Remove(tokenFile.Name())

	require.NoError(t, param.Logging_DisableProgressBars.Set(true))

	host := param.Server_Hostname.GetString()
	port := strconv.Itoa(param.Server_WebPort.GetInt())

	type tpcTestCase struct {
		name string
		// content is the data written to the source file.
		content string
		// copyOpts are passed to client.DoCopy.
		copyOpts func(t *testing.T) []client.TransferOption
		// seedVia controls how the source file is created:
		// "file" writes directly to disk, "put" uploads via DoPut.
		seedVia string
		// expectErr, if true, means DoCopy should return an error.
		expectErr bool
		// verifyDest, if true, downloads the destination and compares content.
		verifyDest bool
		// verifyAbsent, if true, asserts the destination file was NOT created.
		verifyAbsent bool
	}

	tests := []tpcTestCase{
		{
			name:    "CopyWithinExport",
			content: "hello from the POSIXv2 TPC E2E test",
			copyOpts: func(_ *testing.T) []client.TransferOption {
				return []client.TransferOption{client.WithToken(tkn), client.WithSourceToken(tkn)}
			},
			seedVia:    "file",
			verifyDest: true,
		},
		{
			name:    "CopyFailsWithNoToken",
			content: "secret",
			copyOpts: func(_ *testing.T) []client.TransferOption {
				return []client.TransferOption{client.WithAcquireToken(false)}
			},
			seedVia:   "file",
			expectErr: true,
		},
		{
			name:    "CopyFailsWithReadOnlyToken",
			content: "readonly-content",
			copyOpts: func(t *testing.T) []client.TransferOption {
				readTkn := getReadOnlyToken(t)
				return []client.TransferOption{
					client.WithToken(readTkn), client.WithSourceToken(readTkn),
					client.WithAcquireToken(false),
				}
			},
			seedVia:      "file",
			expectErr:    true,
			verifyAbsent: true,
		},
		{
			name:    "CopyFromPut",
			content: "uploaded then copied via TPC",
			copyOpts: func(_ *testing.T) []client.TransferOption {
				return []client.TransferOption{client.WithToken(tkn), client.WithSourceToken(tkn)}
			},
			seedVia:    "put",
			verifyDest: true,
		},
	}

	for _, export := range fed.Exports {
		for _, tc := range tests {
			tc := tc
			t.Run(tc.name+"_"+export.FederationPrefix, func(t *testing.T) {
				subdir := fmt.Sprintf("tpc_%s", tc.name)
				sourceURL := fmt.Sprintf("pelican://%s:%s%s/%s/source.txt", host, port, export.FederationPrefix, subdir)
				destURL := fmt.Sprintf("pelican://%s:%s%s/%s/dest.txt", host, port, export.FederationPrefix, subdir)

				// Seed the source file.
				switch tc.seedVia {
				case "file":
					srcDir := filepath.Join(export.StoragePrefix, subdir)
					require.NoError(t, os.MkdirAll(srcDir, 0755))
					srcFile := filepath.Join(srcDir, "source.txt")
					require.NoError(t, os.WriteFile(srcFile, []byte(tc.content), 0644))
					test_utils.ChownToDaemon(t, srcDir, srcFile)
				case "put":
					tmpFile, err := os.CreateTemp(t.TempDir(), "upload")
					require.NoError(t, err)
					_, err = tmpFile.WriteString(tc.content)
					require.NoError(t, err)
					tmpFile.Close()
					_, err = client.DoPut(fed.Ctx, tmpFile.Name(), sourceURL, false, client.WithToken(tkn))
					require.NoError(t, err)
				default:
					t.Fatalf("unknown seedVia %q", tc.seedVia)
				}

				// Execute the third-party copy.
				opts := tc.copyOpts(t)
				transferResults, err := client.DoCopy(fed.Ctx, sourceURL, destURL, false, opts...)
				if tc.expectErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Len(t, transferResults, 1)
					assert.Equal(t, int64(len(tc.content)), transferResults[0].TransferredBytes)
				}

				// Verify the destination file contents via download.
				if tc.verifyDest {
					localDir := t.TempDir()
					downloadResults, err := client.DoGet(fed.Ctx, destURL, localDir, false, client.WithToken(tkn))
					require.NoError(t, err)
					require.Len(t, downloadResults, 1)
					assert.Equal(t, int64(len(tc.content)), downloadResults[0].TransferredBytes)

					downloaded, err := os.ReadFile(filepath.Join(localDir, "dest.txt"))
					require.NoError(t, err)
					assert.Equal(t, tc.content, string(downloaded))
				}

				// Verify the destination was NOT created (e.g. auth failure).
				if tc.verifyAbsent {
					destDir := filepath.Join(export.StoragePrefix, subdir)
					_, statErr := os.Stat(filepath.Join(destDir, "dest.txt"))
					assert.True(t, os.IsNotExist(statErr), "destination file should not exist after rejected COPY")
				}
			})
		}
	}
}

// TestTPCCrossOrigin verifies that TPC works when the source is an
// independent origin with its own authentication and issuer keys.
// A real second Pelican origin is launched as a subprocess and joins
// the federation via its discovery URL.  This proves that:
//   - The source token is correctly forwarded via TransferHeaderAuthorization
//   - The destination token is independently verified
//   - TPC works across trust boundaries (separate issuers)
func TestTPCCrossOrigin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	// Start the federation with origin #1 (the destination).
	fed := fed_test_utils.NewFedTest(t, posixv2AuthCfg)

	require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()

	// Capture the federation's IssuerKeysDirectory before doing anything else.
	// We must not call getTestToken here: it changes param.IssuerKeysDirectory
	// to a new empty temp dir, and the background key-refresh goroutine
	// (LaunchIssuerKeysDirRefresh) reads that param dynamically.  If the goroutine
	// fires after getTestToken, it generates a brand-new key in the temp dir,
	// stores it as issuerKeys.CurrentKey, and updates the registry DB with that
	// new key.  Origin2 copies the *original* key from fedIssuerKeysDir, so its
	// registration would then fail compareJwks against the updated DB entry.
	fedIssuerKeysDir := param.IssuerKeysDirectory.GetString()

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	newDestToken := func(t *testing.T) string {
		t.Helper()
		destTknCfg := token.NewWLCGToken()
		destTknCfg.Lifetime = time.Minute
		destTknCfg.Issuer = issuer
		destTknCfg.Subject = "origin"
		destTknCfg.AddAudienceAny()
		readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
		require.NoError(t, err)
		createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
		require.NoError(t, err)
		modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
		require.NoError(t, err)
		destTknCfg.AddScopes(readScope, createScope, modScope)
		destTkn, err := destTknCfg.CreateToken()
		require.NoError(t, err)
		return destTkn
	}

	require.NoError(t, param.Logging_DisableProgressBars.Set(true))

	host := param.Server_Hostname.GetString()
	port := strconv.Itoa(param.Server_WebPort.GetInt())

	// Build the pelican binary for the second origin.
	pelicanBinary := getPelicanBinary(t)

	// Prepare directories and config for the second origin (source).
	origin2Dir := t.TempDir()
	origin2StorageDir := filepath.Join(origin2Dir, "storage")
	require.NoError(t, os.MkdirAll(origin2StorageDir, 0755))
	origin2ConfigDir := filepath.Join(origin2Dir, "config")
	require.NoError(t, os.MkdirAll(origin2ConfigDir, 0755))
	origin2RuntimeDir := filepath.Join(origin2Dir, "runtime")
	require.NoError(t, os.MkdirAll(origin2RuntimeDir, 0755))

	// Find a free port for origin #2.
	ln, err := net.Listen("tcp", host+":0")
	require.NoError(t, err)
	origin2Port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	// Grab federation values from the running federation.
	discoveryURL := param.Federation_DiscoveryUrl.GetString()
	require.NotEmpty(t, discoveryURL, "Federation discovery URL should be set")
	caCertFile := param.Server_TLSCACertificateFile.GetString()
	require.NotEmpty(t, caCertFile, "TLS CA cert should be set")
	caKeyFile := param.Server_TLSCAKey.GetString()
	tlsCertFile := param.Server_TLSCertificateChain.GetString()
	tlsKeyFile := param.Server_TLSKey.GetString()

	// Copy the federation's issuer keys into origin #2's config dir so both
	// origins present the same JWKS to the registry (avoiding "unable to verify
	// you own the registered server" errors when the hostname is shared).
	origin2IssuerKeysDir := filepath.Join(origin2ConfigDir, "issuer-keys")
	require.NoError(t, os.MkdirAll(origin2IssuerKeysDir, 0700))
	entries, err := os.ReadDir(fedIssuerKeysDir)
	require.NoError(t, err, "Failed to read federation IssuerKeysDirectory %s", fedIssuerKeysDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(fedIssuerKeysDir, e.Name())
		dst := filepath.Join(origin2IssuerKeysDir, e.Name())
		data, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(dst, data, 0600))
	}

	origin2FedPrefix := "/origin2/tpc-test"
	origin2LogPath := filepath.Join(origin2Dir, "origin2.log")

	// Write the config file for origin #2.
	origin2ConfigFile := filepath.Join(origin2ConfigDir, "pelican.yaml")
	origin2ConfigContent := fmt.Sprintf(`
Federation:
  DiscoveryUrl: %s

IssuerKeysDirectory: %s

Server:
  WebPort: %d
  TLSCACertificateFile: %s
  TLSCAKey: %s
  TLSCertificateChain: %s
  TLSKey: %s
  EnableUI: false
  Hostname: %s

Origin:
  StorageType: posixv2
  EnableDirectReads: true
  EnableCmsd: false
  EnableVoms: false
  Port: 0
  DbLocation: %s
  Exports:
    - StoragePrefix: %s
      FederationPrefix: %s
      Capabilities: ["PublicReads", "Reads", "Writes", "DirectReads", "Listings", "Copies"]

Logging:
  Level: debug
  DisableProgressBars: true
  LogLocation: %s

Xrootd:
  RunLocation: %s
`, discoveryURL, origin2IssuerKeysDir, origin2Port, caCertFile, caKeyFile, tlsCertFile, tlsKeyFile, host,
		filepath.Join(origin2Dir, "origin.sqlite"),
		origin2StorageDir, origin2FedPrefix,
		origin2LogPath,
		origin2RuntimeDir,
	)
	require.NoError(t, os.WriteFile(origin2ConfigFile, []byte(origin2ConfigContent), 0644))

	// Launch origin #2 as a subprocess.
	ctx, cancel := context.WithCancel(fed.Ctx)

	cmd := exec.CommandContext(ctx, pelicanBinary, "origin", "serve", "--config", origin2ConfigFile)
	cmd.Env = append(os.Environ(),
		"PELICAN_CONFIGDIR="+origin2ConfigDir,
	)

	// Capture stdout/stderr for debugging.
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start())
	exitCh := make(chan error, 1)
	go func() {
		exitCh <- cmd.Wait()
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case <-exitCh:
		case <-time.After(5 * time.Second):
			t.Log("Timed out waiting for origin2 process to exit during cleanup")
		}
	})

	// Log stdout/stderr in background for debugging.
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			t.Logf("[origin2-stdout] %s", scanner.Text())
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			t.Logf("[origin2-stderr] %s", scanner.Text())
		}
	}()

	// Seed a source file on origin #2's storage.
	sourceContent := "Hello from the independent second origin"
	srcDir := filepath.Join(origin2StorageDir, "cross-origin")
	require.NoError(t, os.MkdirAll(srcDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "source.txt"), []byte(sourceContent), 0644))

	// Wait for origin #2 to become healthy.
	origin2URL := fmt.Sprintf("https://%s:%d", host, origin2Port)
	healthURL := origin2URL + "/api/v1.0/health"
	err = waitForURLStatusOrProcessExit(t, ctx, healthURL, http.StatusOK, 30*time.Second, 500*time.Millisecond, exitCh, origin2LogPath, "origin2 health")
	require.NoError(t, err, "Origin #2 failed to become healthy")

	// Poll the director until origin #2's namespace is resolvable.
	// This means the origin has registered and the director can redirect to it.
	directorURL := param.Server_ExternalWebUrl.GetString()
	testSourcePath := origin2FedPrefix + "/cross-origin/source.txt"
	statURL := directorURL + "/api/v1.0/director/origin" + testSourcePath
	err = waitForURLStatusOrProcessExit(t, ctx, statURL, http.StatusTemporaryRedirect, 30*time.Second, 500*time.Millisecond, exitCh, origin2LogPath, "director registration of origin2")
	require.NoError(t, err, "Origin #2 never appeared in director")

	for _, export := range fed.Exports {
		t.Run("CrossOriginTPC_"+export.FederationPrefix, func(t *testing.T) {
			destTkn := newDestToken(t)
			sourceURL := fmt.Sprintf("pelican://%s:%s%s/cross-origin/source.txt", host, port, origin2FedPrefix)
			destURL := fmt.Sprintf("pelican://%s:%s%s/cross-origin/dest.txt", host, port, export.FederationPrefix)

			// Create parent directory for the destination on origin #1.
			destDir := filepath.Join(export.StoragePrefix, "cross-origin")
			require.NoError(t, os.MkdirAll(destDir, 0755))
			test_utils.ChownToDaemon(t, destDir)

			// Execute the third-party copy across two independent origins.
			// The dest token is a real WLCG JWT signed by the federation's issuer.
			// The source token is acquired automatically from the director redirect.
			transferResults, err := client.DoCopy(fed.Ctx, sourceURL, destURL, false,
				client.WithToken(destTkn),
			)
			require.NoError(t, err)
			require.Len(t, transferResults, 1)
			assert.Equal(t, int64(len(sourceContent)), transferResults[0].TransferredBytes)

			// Verify the file was correctly written to the destination.
			localDir := t.TempDir()
			downloadResults, err := client.DoGet(fed.Ctx, destURL, localDir, false, client.WithToken(destTkn))
			require.NoError(t, err)
			require.Len(t, downloadResults, 1)

			downloaded, err := os.ReadFile(filepath.Join(localDir, "dest.txt"))
			require.NoError(t, err)
			assert.Equal(t, sourceContent, string(downloaded))
		})
	}
}

// TestTPCWithXRootD verifies that TPC works against a POSIX (XRootD-based)
// origin, exercising the XRootD TPC plugin (libXrdHttpTPC.so) rather than
// the Go-native POSIXv2 handler.
func TestTPCWithXRootD(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	fed := fed_test_utils.NewFedTest(t, posixAuthCfg)

	require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()

	tokenFile, tkn := getTestToken(t)
	defer os.Remove(tokenFile.Name())

	require.NoError(t, param.Logging_DisableProgressBars.Set(true))

	host := param.Server_Hostname.GetString()
	port := strconv.Itoa(param.Server_WebPort.GetInt())

	content := "hello from the XRootD TPC E2E test"

	for _, export := range fed.Exports {
		t.Run("XRootDTPC_"+export.FederationPrefix, func(t *testing.T) {
			subdir := "tpc_xrootd"
			sourceURL := fmt.Sprintf("pelican://%s:%s%s/%s/source.txt", host, port, export.FederationPrefix, subdir)
			destURL := fmt.Sprintf("pelican://%s:%s%s/%s/dest.txt", host, port, export.FederationPrefix, subdir)

			// Seed the source file directly on disk
			srcDir := filepath.Join(export.StoragePrefix, subdir)
			require.NoError(t, os.MkdirAll(srcDir, 0755))
			srcFile := filepath.Join(srcDir, "source.txt")
			require.NoError(t, os.WriteFile(srcFile, []byte(content), 0644))
			test_utils.ChownToDaemon(t, srcDir, srcFile)

			// Execute the third-party copy
			transferResults, err := client.DoCopy(fed.Ctx, sourceURL, destURL, false,
				client.WithToken(tkn), client.WithSourceToken(tkn),
			)
			require.NoError(t, err)
			require.Len(t, transferResults, 1)
			assert.Equal(t, int64(len(content)), transferResults[0].TransferredBytes)

			// Verify the destination file contents via download
			localDir := t.TempDir()
			downloadResults, err := client.DoGet(fed.Ctx, destURL, localDir, false, client.WithToken(tkn))
			require.NoError(t, err)
			require.Len(t, downloadResults, 1)
			assert.Equal(t, int64(len(content)), downloadResults[0].TransferredBytes)

			downloaded, err := os.ReadFile(filepath.Join(localDir, "dest.txt"))
			require.NoError(t, err)
			assert.Equal(t, content, string(downloaded))
		})
	}
}
