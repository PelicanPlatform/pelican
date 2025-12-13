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

package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

var server *httptest.Server

// Generate a context associated with the test
//
// Note: Does not utilize test_utils.TestContext to avoid an import cycle
func testConfigContext(t *testing.T) (ctx context.Context) {
	var cancel context.CancelFunc
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	t.Cleanup(cancel)
	return
}

// Set up a mock discovery endpoint that uses its own URL as the discovery URL.
// Note that this is a scaled back version of test_utils.MockFederationRoot to avoid import cycles.
func mockFederationRoot(t *testing.T) string {
	responseHandler := func(w http.ResponseWriter, r *http.Request) {
		// We only understand GET requests
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("I only understand GET requests, but you sent me " + r.Method))
			require.NoError(t, err)
			return
		}

		path := r.URL.Path
		switch path {
		// Provide base fed root metadata
		case "/.well-known/pelican-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			discoveryMetadata := pelican_url.FederationDiscovery{
				DiscoveryEndpoint: "https://fake-discovery.com",
				DirectorEndpoint:  "https://fake-director.com",
				RegistryEndpoint:  "https://fake-registry.com",
				BrokerEndpoint:    "https://fake-broker.com",
				JwksUri:           "https://fake-discovery/.well-known/issuer.jwks",
				DirectorAdvertiseEndpoints: []string{
					"https://fake-director-1.com",
					"https://fake-director-2.com",
				},
			}

			discoveryJSONBytes, err := json.Marshal(discoveryMetadata)
			require.NoError(t, err, "Failed to marshal discovery metadata")
			_, err = w.Write(discoveryJSONBytes)
			require.NoError(t, err)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte("I don't understand this path: " + path))
			require.NoError(t, err)
		}
	}

	server := httptest.NewTLSServer(http.HandlerFunc(responseHandler))

	// Cleanup, cleanup, everybody do your share!
	t.Cleanup(server.Close)

	require.NoError(t, param.Set(param.TLSSkipVerify.GetName(), true))
	require.NoError(t, param.Set(param.Federation_DiscoveryUrl.GetName(), server.URL))

	return server.URL
}

func TestMain(m *testing.M) {
	// Create a test server
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// simuilate long server response
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
		code, err := w.Write([]byte("Success"))
		if err != nil {
			fmt.Printf("Error writing out response: %d, %v", code, err)
			os.Exit(1)
		}
	}))
	// Init server to get configs initiallized
	if err := param.Set("Transport.MaxIdleConns", 30); err != nil {
		panic(err)
	}
	if err := param.Set("Transport.IdleConnTimeout", time.Second*90); err != nil {
		panic(err)
	}
	if err := param.Set("Transport.TLSHandshakeTimeout", time.Second*15); err != nil {
		panic(err)
	}
	if err := param.Set("Transport.ExpectContinueTimeout", time.Second*1); err != nil {
		panic(err)
	}
	if err := param.Set("Transport.ResponseHeaderTimeout", time.Second*10); err != nil {
		panic(err)
	}
	if err := param.Set("Transport.Dialer.Timeout", time.Second*1); err != nil {
		panic(err)
	}
	if err := param.Set("Transport.Dialer.KeepAlive", time.Second*30); err != nil {
		panic(err)
	}
	if err := param.Set("TLSSkipVerify", true); err != nil {
		panic(err)
	}
	if err := param.Set(param.Logging_Level.GetName(), "debug"); err != nil {
		panic(err)
	}
	server.StartTLS()
	defer server.Close()
	exitCode := m.Run()
	os.Exit(exitCode)
}

// Test that no deprecated config keys are present in defaultsYaml or osdfDefaultsYaml
func TestNoReplacementKeysInDefaults(t *testing.T) {
	type testCase struct {
		yamlStr     string
		fName       string
		shouldError bool
	}
	testCases := []testCase{
		{yamlStr: defaultsYaml, fName: "defaults.yaml", shouldError: false},
		{yamlStr: osdfDefaultsYaml, fName: "osdfDefaults.yaml", shouldError: false},
		// Example: Client.DisableHttpProxy is a replacement for DisableHttpProxy
		{yamlStr: `
Client:
  DisableHttpProxy: true
`, fName: "inline test case with replacement key Client.DisableHttpProxy", shouldError: true},
	}

	deprecatedMap := param.GetDeprecated()
	for _, tc := range testCases {
		var m map[string]any
		err := yaml.Unmarshal([]byte(tc.yamlStr), &m)
		require.NoError(t, err, "Failed to parse %s", tc.fName)

		// Map replacement key -> deprecated key(s)
		found := make(map[string]string)
		for deprecated, replacements := range deprecatedMap {
			for _, rep := range replacements {
				if rep == "none" {
					continue
				}
				// Check for top-level and nested keys (e.g., Logging.Level)
				parts := strings.Split(rep, ".")
				node := m
				foundKey := true
				for _, part := range parts {
					val, ok := node[part]
					if !ok {
						foundKey = false
						break
					}
					// If not at the last part, descend if possible
					if mp, ok := val.(map[string]any); ok {
						node = mp
					} else if part != parts[len(parts)-1] {
						foundKey = false
						break
					}
				}
				if foundKey {
					found[rep] = deprecated
				}
			}
		}

		if tc.shouldError {
			assert.NotEmpty(t, found, "Expected replacement key(s) in %s, but none found", tc.fName)
		} else {
			if len(found) > 0 {
				var details []string
				for rep, dep := range found {
					details = append(details, fmt.Sprintf("%q (replacement for deprecated key %q)", rep, dep))
				}
				t.Errorf("Replacement config key(s) found in %s: %v. Please remove them from the defaults yaml and set them in a SetDefaults() function in the config package.", tc.fName, details)
			}
		}
	}
}

func TestResponseHeaderTimeout(t *testing.T) {
	// Change the viper value of the timeout
	require.NoError(t, param.Set("Transport.ResponseHeaderTimeout", time.Millisecond*25))
	setupTransport()
	transport := GetTransport()
	client := &http.Client{Transport: transport}
	// make a request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Perform the request and handle the timeout
	_, err = client.Do(req)
	if err != nil {
		// Check if the error is a timeout error
		assert.True(t, strings.Contains(err.Error(), "timeout awaiting response headers"))
	} else {
		t.Fatalf("Test returned no error when there should be")
	}

	require.NoError(t, param.Set("Transport.ResponseHeaderTimeout", time.Second*10))
}

func TestDialerTimeout(t *testing.T) {
	// Change the viper value of the timeout
	require.NoError(t, param.Set("Transport.Dialer.Timeout", time.Millisecond*25))
	setupTransport()
	transport := GetTransport()
	client := &http.Client{Transport: transport}

	unreachableServerURL := "http://abc123:1000"

	// make a request
	req, err := http.NewRequest("GET", unreachableServerURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Perform the request and handle the timeout
	_, err = client.Do(req)
	if err != nil {
		// Check if the error is a timeout error
		assert.True(t, strings.Contains(err.Error(), "dial tcp"))
	} else {
		t.Fatalf("Test returned no error when there should be")
	}

	require.NoError(t, param.Set("Transport.Dialer.Timeout", time.Second*10))
}

func TestInitConfig(t *testing.T) {
	ResetConfig()
	t.Cleanup(func() {
		ResetConfig()
	})
	// Set prefix to OSDF to ensure that config is being set
	testingPreferredPrefix = "OSDF"

	// Create a temp config file to use
	tempCfgFile, err := os.CreateTemp("", "pelican-*.yaml")
	if err != nil {
		t.Fatalf("Failed to make temp file: %v", err)
	}
	require.NoError(t, param.Set("config", tempCfgFile.Name()))

	InitConfigInternal(logrus.DebugLevel) // Should set up pelican.yaml, osdf.yaml and defaults.yaml

	// Check if server address is correct by defaults.yaml
	assert.Equal(t, "0.0.0.0", param.Server_WebHost.GetString())
	// Check that Federation Discovery url is correct by osdf.yaml
	assert.Equal(t, "osg-htc.org", param.Federation_DiscoveryUrl.GetString())

	require.NoError(t, param.Set("Server.WebHost", "1.1.1.1")) // should write to temp config file
	if err := viper.WriteConfigAs(tempCfgFile.Name()); err != nil {
		t.Fatalf("Failed to write to config file: %v", err)
	}
	ResetConfig()
	require.NoError(t, param.Set("config", tempCfgFile.Name())) // Set the temp file as the new 'pelican.yaml'
	InitConfigInternal(logrus.DebugLevel)

	// Check if server address overrides the default
	assert.Equal(t, "1.1.1.1", param.Server_WebHost.GetString())
	ResetConfig()

	//Test if prefix is not set, should not be able to find osdfYaml configuration
	testingPreferredPrefix = ""
	tempCfgFile, err = os.CreateTemp("", "pelican-*.yaml")
	if err != nil {
		t.Fatalf("Failed to make temp file: %v", err)
	}
	require.NoError(t, param.Set("config", tempCfgFile.Name()))
	InitConfigInternal(logrus.DebugLevel)
	assert.Equal(t, "", param.Federation_DiscoveryUrl.GetString())
}

func TestHomeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on Windows, as it's not expected to work")
	}

	tempDir := t.TempDir()
	mockHomeDir := filepath.Join(tempDir, "test", "configDir")
	confDir := t.TempDir()
	ResetConfig()
	t.Cleanup(func() {
		ResetConfig()
	})

	// Save the original environment variables
	oldConfigRoot := isRootExec

	defer func() {
		isRootExec = oldConfigRoot
	}()

	t.Setenv("HOME", mockHomeDir)

	type testCase struct {
		name        string
		isRootExec  bool
		configDir   string
		homeEnv     bool
		expectedDir string
	}

	testCases := []testCase{
		{
			name:        "RootUserNoConfigDir",
			isRootExec:  true,
			configDir:   "",
			homeEnv:     true,
			expectedDir: "/etc/pelican",
		},
		{
			name:        "NonRootWithConfigDir",
			isRootExec:  false,
			configDir:   filepath.Join(confDir),
			homeEnv:     true,
			expectedDir: filepath.Join(confDir),
		},
		{
			name:        "NonRootNoConfigDirWithHome",
			isRootExec:  false,
			configDir:   "",
			homeEnv:     true,
			expectedDir: filepath.Join(mockHomeDir, ".config", "pelican"),
		},
		{
			name:        "NonRootNoConfigDirNoHome",
			isRootExec:  false,
			configDir:   "",
			homeEnv:     false,
			expectedDir: filepath.Join("/etc", "pelican"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isRootExec = tc.isRootExec
			require.NoError(t, param.Reset())

			if tc.configDir != "" {
				require.NoError(t, param.Set("ConfigDir", tc.configDir))
			}

			if !tc.homeEnv {
				os.Unsetenv("HOME")
			}

			InitConfigDir(viper.GetViper())

			cDir := viper.GetString("ConfigDir")
			require.Equal(t, tc.expectedDir, cDir)
		})
	}
}

// Helper func for TestExtraCfg
//
// Sets up the root config file and adds the ConfigLocations key to point to a test's tempdir
func setupConfigLocations(t *testing.T, continueDirs []string) {
	rootCfgDir := t.TempDir()

	viper.AddConfigPath(rootCfgDir)
	viper.SetConfigType("yaml")
	viper.SetConfigName("pelican")

	// Escape backslashes in the directory paths -- needed for Windows tests
	for idx, dir := range continueDirs {
		continueDirs[idx] = strings.ReplaceAll(dir, "\\", "\\\\")
	}

	// Convert the slice of directories into a YAML list
	yamlDirs := strings.Join(continueDirs, "\", \"")
	yamlDirs = fmt.Sprintf("[\"%s\"]", yamlDirs)

	err := os.WriteFile(filepath.Join(rootCfgDir, "pelican.yaml"), []byte(fmt.Sprintf("ConfigLocations: %s\nOtherVal: bar", yamlDirs)), 0644)
	require.NoError(t, err)
	err = viper.MergeInConfig()
	require.NoError(t, err)
}

// Test that the `ConfigLocations` key works as expected
func TestExtraCfg(t *testing.T) {
	ResetConfig()
	t.Cleanup(func() {
		ResetConfig()
	})

	t.Run("test-no-continue", func(t *testing.T) {
		err := handleContinuedCfg()
		assert.NoError(t, err)
	})

	t.Run("test-one-dir-no-files", func(t *testing.T) {
		ResetConfig()
		dir1 := t.TempDir()
		setupConfigLocations(t, []string{dir1})

		// If there are no files in a directory pointed to by ConfigLocations, we should not error
		// We should also do no config merging
		err := handleContinuedCfg()
		assert.NoError(t, err)
		// Check the other value in our original config to make sure we didn't simply overwrite
		assert.Equal(t, "bar", viper.GetString("OtherVal"))
	})

	t.Run("test-one-dir-one-file", func(t *testing.T) {
		ResetConfig()
		dir1 := t.TempDir()
		setupConfigLocations(t, []string{dir1})

		// Write a key: value to a file in the continue directory
		continueFile := filepath.Join(dir1, "config.yaml")
		err := os.WriteFile(continueFile, []byte("TestVal: foo"), 0644)
		require.NoError(t, err)

		err = handleContinuedCfg()
		assert.NoError(t, err)
		assert.Equal(t, "foo", viper.GetString("TestVal"))
		// Check the other value in our original config to make sure we didn't simply overwrite
		assert.Equal(t, "bar", viper.GetString("otherVal"))
	})

	t.Run("test-two-dirs-one-file-each", func(t *testing.T) {
		ResetConfig()
		dir1 := t.TempDir()
		dir2 := t.TempDir()
		setupConfigLocations(t, []string{dir1, dir2})

		for idx, dir := range []string{dir1, dir2} {
			continueFile := filepath.Join(dir, "config.yaml")
			err := os.WriteFile(continueFile, []byte(fmt.Sprintf("TestVal: foo-%d\nDirVal%d: %d", idx, idx, idx)), 0644)
			require.NoError(t, err)
		}

		// Because we've configured ConfigLocations: [dir1, dir2], we should expect the value from dir1 to be overwritten by the value from dir2
		err := handleContinuedCfg()
		assert.NoError(t, err)
		assert.Equal(t, "foo-1", viper.GetString("TestVal"))
		// Any previously-undefined keys should still be picked up (ie they're new and not a "patch")
		assert.Equal(t, "0", viper.GetString("DirVal0"))
		assert.Equal(t, "1", viper.GetString("DirVal1"))

		// Check the other value in our original config to make sure we didn't simply overwrite the entire config with our new values
		assert.Equal(t, "bar", viper.GetString("otherVal"))
	})

	t.Run("test-two-dirs-two-files-each", func(t *testing.T) {
		ResetConfig()
		dir1 := t.TempDir()
		dir2 := t.TempDir()
		setupConfigLocations(t, []string{dir1, dir2})

		counter := 1
		for dirIdx, dir := range []string{dir1, dir2} {
			for fileIdx := 0; fileIdx < 2; fileIdx++ {
				// These should be parsed in lexicographical order. That's not extensively tested here, because
				// it's a feature of the underlying library filesystem library.
				continueFile := filepath.Join(dir, fmt.Sprintf("config-%d.yaml", dirIdx))
				err := os.WriteFile(continueFile, []byte(fmt.Sprintf("TestVal: foo-%d-%d", dirIdx, fileIdx)), 0644)
				require.NoError(t, err)
			}
			counter += 1
		}

		err := handleContinuedCfg()
		assert.NoError(t, err)
		assert.Equal(t, "foo-1-1", viper.GetString("TestVal"))
		// Check the other value in our original config to make sure we didn't simply overwrite the entire config with our new values
		assert.Equal(t, "bar", viper.GetString("otherVal"))
	})

	t.Run("test-bad-directory", func(t *testing.T) {
		ResetConfig()
		continueDir := t.TempDir()
		setupConfigLocations(t, []string{continueDir + "-dne"})

		continueFile := filepath.Join(continueDir, "continue.yaml")
		err := os.WriteFile(continueFile, []byte("TestVal: foo"), 0644)
		require.NoError(t, err)

		err = handleContinuedCfg()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})
}

// TestDeprecationHandling verifies that if a deprecated configuration parameter is set,
// a warning message is displayed. Additionally, the value of the deprecated parameter
// is used as the default value for its replacement.
func TestDeprecationHandling(t *testing.T) {
	ResetConfig()
	t.Cleanup(func() {
		ResetConfig()
	})
	tmpConfigPath := "testconfigdir"
	tmpConfigDirPath, err := os.MkdirTemp("", tmpConfigPath)
	require.NoError(t, err)
	defer os.RemoveAll(tmpConfigDirPath)

	permissions := os.FileMode(0755)
	err = os.Chmod(tmpConfigDirPath, permissions)
	require.NoError(t, err)

	tlsCertPath := filepath.Join(tmpConfigDirPath, "somerandomfile.txt")

	require.NoError(t, param.Set("ConfigDir", tmpConfigDirPath))
	require.NoError(t, param.Set("Logging.Level", "Warning"))

	// Set the deprecated config parameter `Server.TLSCertificate`.
	// This parameter is replaced by the new `Server.TLSCertificateChain`.
	require.NoError(t, param.Set("Server.TLSCertificate", tlsCertPath))

	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	defer logrus.SetOutput(os.Stdout) // Restore stdout after the test

	err = InitServer(context.Background(), server_structs.DirectorType)
	require.NoError(t, err)
	err = SetServerDefaults(viper.GetViper())
	require.NoError(t, err)

	logContent := logBuffer.String()

	expectedMessage := "The configuration key \\\"Server.TLSCertificate\\\" is deprecated. Please use \\\"Server.TLSCertificateChain\\\" instead."

	require.Contains(t, logContent, expectedMessage, "Expected message not found in the logs")

	assert.Equal(t, tlsCertPath, viper.GetString("Server.TLSCertificateChain"))
}

func TestEnabledServers(t *testing.T) {
	ResetConfig()
	t.Cleanup(func() {
		ResetConfig()
	})
	allServerTypes := []server_structs.ServerType{server_structs.OriginType, server_structs.CacheType, server_structs.DirectorType, server_structs.RegistryType}
	allServerStrs := make([]string, 0)
	allServerStrsLower := make([]string, 0)
	for _, st := range allServerTypes {
		allServerStrs = append(allServerStrs, st.String())
		allServerStrsLower = append(allServerStrsLower, strings.ToLower(st.String()))
	}
	sort.Strings(allServerStrs)
	sort.Strings(allServerStrsLower)

	t.Run("no-value-set", func(t *testing.T) {
		enabledServers = 0
		for _, server := range allServerTypes {
			assert.False(t, IsServerEnabled(server))
		}
	})

	t.Run("enable-one-server", func(t *testing.T) {
		for _, server := range allServerTypes {
			enabledServers = 0
			// We didn't call setEnabledServer as it will only set once per process
			enabledServers.SetList([]server_structs.ServerType{server})
			assert.True(t, IsServerEnabled(server))
			assert.Equal(t, []string{server.String()}, GetEnabledServerString(false))
			assert.Equal(t, []string{strings.ToLower(server.String())}, GetEnabledServerString(true))
		}
	})

	t.Run("enable-multiple-servers", func(t *testing.T) {
		enabledServers = 0
		enabledServers.SetList([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType})
		serverStr := []string{server_structs.OriginType.String(), server_structs.CacheType.String()}
		serverStrLower := []string{strings.ToLower(server_structs.OriginType.String()), strings.ToLower(server_structs.CacheType.String())}
		sort.Strings(serverStr)
		sort.Strings(serverStrLower)
		assert.True(t, IsServerEnabled(server_structs.OriginType))
		assert.True(t, IsServerEnabled(server_structs.CacheType))
		assert.Equal(t, serverStr, GetEnabledServerString(false))
		assert.Equal(t, serverStrLower, GetEnabledServerString(true))
	})

	t.Run("enable-all-servers", func(t *testing.T) {
		enabledServers = 0
		enabledServers.SetList(allServerTypes)
		assert.True(t, IsServerEnabled(server_structs.OriginType))
		assert.True(t, IsServerEnabled(server_structs.CacheType))
		assert.True(t, IsServerEnabled(server_structs.RegistryType))
		assert.True(t, IsServerEnabled(server_structs.DirectorType))
		assert.Equal(t, allServerStrs, GetEnabledServerString(false))
		assert.Equal(t, allServerStrsLower, GetEnabledServerString(true))
	})

	t.Run("setEnabledServer-only-set-once", func(t *testing.T) {
		enabledServers = 0
		sType := server_structs.OriginType
		sType.Set(server_structs.CacheType)
		setEnabledServer(sType)
		assert.True(t, IsServerEnabled(server_structs.OriginType))
		assert.True(t, IsServerEnabled(server_structs.CacheType))

		sType.Clear()
		sType.Set(server_structs.DirectorType)
		sType.Set(server_structs.RegistryType)
		setEnabledServer(sType)
		assert.True(t, IsServerEnabled(server_structs.OriginType))
		assert.True(t, IsServerEnabled(server_structs.CacheType))
		assert.False(t, IsServerEnabled(server_structs.DirectorType))
		assert.False(t, IsServerEnabled(server_structs.RegistryType))
	})
}

// Tests the function setPreferredPrefix: ensures case-insensitivity and invalid values are handled correctly
func TestSetPreferredPrefix(t *testing.T) {
	t.Run("TestPelicanPreferredPrefix", func(t *testing.T) {
		oldPref, err := SetPreferredPrefix(PelicanPrefix)
		assert.NoError(t, err)
		if GetPreferredPrefix() != PelicanPrefix {
			t.Errorf("Expected preferred prefix to be 'PELICAN', got '%s'", GetPreferredPrefix())
		}
		if oldPref != "" {
			t.Errorf("Expected old preferred prefix to be empty, got '%s'", oldPref)
		}
	})

	t.Run("TestOSDFPreferredPrefix", func(t *testing.T) {
		oldPref, err := SetPreferredPrefix(OsdfPrefix)
		assert.NoError(t, err)
		if GetPreferredPrefix() != OsdfPrefix {
			t.Errorf("Expected preferred prefix to be 'OSDF', got '%s'", GetPreferredPrefix())
		}
		if oldPref != PelicanPrefix {
			t.Errorf("Expected old preferred prefix to be 'PELICAN', got '%s'", oldPref)
		}
	})

	t.Run("TestStashPreferredPrefix", func(t *testing.T) {
		oldPref, err := SetPreferredPrefix(StashPrefix)
		assert.NoError(t, err)
		if GetPreferredPrefix() != StashPrefix {
			t.Errorf("Expected preferred prefix to be 'STASH', got '%s'", GetPreferredPrefix())
		}
		if oldPref != OsdfPrefix {
			t.Errorf("Expected old preferred prefix to be 'osdf', got '%s'", oldPref)
		}
	})

	t.Run("TestInvalidPreferredPrefix", func(t *testing.T) {
		_, err := SetPreferredPrefix("invalid")
		assert.Error(t, err)
	})
}

func TestInitServerUrl(t *testing.T) {
	ctx := testConfigContext(t)

	mockHostname := "example.com"
	mockNon443Port := 8444
	mock443Port := 443

	mockWebUrlWoPort := "https://example.com"
	mockWebUrlW443Port := "https://example.com:443"
	mockWebUrlWNon443Port := "https://example.com:8444"

	t.Cleanup(func() {
		ResetConfig()
	})
	initConfig := func() {
		ResetConfig()
		mockFederationRoot(t)
		tempDir := t.TempDir()
		require.NoError(t, param.Set("ConfigDir", tempDir))
	}

	initDirectoryConfig := func() {
		initConfig()
		require.NoError(t, param.Set(param.Director_MinStatResponse.GetName(), 1))
		require.NoError(t, param.Set(param.Director_MaxStatResponse.GetName(), 4))
	}

	t.Run("web-url-defaults-to-hostname-port", func(t *testing.T) {
		initDirectoryConfig()
		require.NoError(t, param.Set(param.Server_Hostname.GetName(), mockHostname))
		require.NoError(t, param.Set(param.Server_WebPort.GetName(), mockNon443Port))
		err := InitServer(context.Background(), 0)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWNon443Port, param.Server_ExternalWebUrl.GetString())
	})

	t.Run("default-web-url-removes-443-port", func(t *testing.T) {
		initDirectoryConfig()
		require.NoError(t, param.Set(param.Server_Hostname.GetName(), mockHostname))
		require.NoError(t, param.Set(param.Server_WebPort.GetName(), mock443Port))
		err := InitServer(context.Background(), 0)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, param.Server_ExternalWebUrl.GetString())
	})

	t.Run("remove-443-port-for-set-web-url", func(t *testing.T) {
		// We respect the URL value set directly by others. Won't remove 443 port
		initDirectoryConfig()
		require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), mockWebUrlW443Port))
		err := InitServer(context.Background(), 0)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, param.Server_ExternalWebUrl.GetString())
	})

	t.Run("dir-url-default-to-web-url", func(t *testing.T) {
		// We respect the URL value set directly by others. Won't remove 443 port
		initDirectoryConfig()
		// If Server_ExternalWebUrl is not set, Federation_DirectorUrl defaults to https://<hostname>:<non-443-port>
		// In this case, the port is 443, so Federation_DirectorUrl = https://example.com
		require.NoError(t, param.Set(param.Server_Hostname.GetName(), mockHostname))
		require.NoError(t, param.Set(param.Server_WebPort.GetName(), mock443Port))
		err := InitServer(ctx, server_structs.DirectorType)
		require.NoError(t, err)
		fedInfo, err := GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.DirectorEndpoint)

		// If Server_ExternalWebUrl is explicitly set, Federation_DirectorUrl defaults to whatever it is
		// But 443 port is stripped if provided
		initDirectoryConfig()
		require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), mockWebUrlW443Port))
		err = InitServer(ctx, server_structs.DirectorType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.DirectorEndpoint)

		initDirectoryConfig()
		require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), mockWebUrlWoPort))
		require.NoError(t, param.Set("Federation.DirectorUrl", "https://example-director.com"))
		err = InitServer(ctx, server_structs.DirectorType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://example-director.com", fedInfo.DirectorEndpoint)
	})

	t.Run("reg-url-default-to-web-url", func(t *testing.T) {
		// We respect the URL value set directly by others. Won't remove 443 port
		initConfig()
		// If Server_ExternalWebUrl is not set, Federation_RegistryUrl defaults to https://<hostname>:<non-443-port>
		// In this case, the port is 443, so Federation_RegistryUrl = https://example.com
		require.NoError(t, param.Set(param.Server_Hostname.GetName(), mockHostname))
		require.NoError(t, param.Set(param.Server_WebPort.GetName(), mock443Port))
		err := InitServer(ctx, server_structs.RegistryType)
		require.NoError(t, err)
		fedInfo, err := GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.RegistryEndpoint)

		// If Server_ExternalWebUrl is explicitly set, Federation_RegistryUrl defaults to whatever it is
		// But 443 port is stripped if provided
		initConfig()
		require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), mockWebUrlW443Port))
		err = InitServer(ctx, server_structs.RegistryType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.RegistryEndpoint)

		initConfig()
		require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), mockWebUrlWoPort))
		require.NoError(t, param.Set("Federation.RegistryUrl", "https://example-registry.com"))
		err = InitServer(ctx, server_structs.RegistryType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://example-registry.com", fedInfo.RegistryEndpoint)
	})

	t.Run("broker-url-default-to-web-url", func(t *testing.T) {
		// We respect the URL value set directly by others. Won't remove 443 port
		initConfig()
		// If Server_ExternalWebUrl is not set, Federation_BrokerUrl defaults to https://<hostname>:<non-443-port>
		// In this case, the port is 443, so Federation_BrokerUrl = https://example.com
		require.NoError(t, param.Set(param.Server_Hostname.GetName(), mockHostname))
		require.NoError(t, param.Set(param.Server_WebPort.GetName(), mock443Port))
		err := InitServer(ctx, server_structs.BrokerType)
		require.NoError(t, err)
		fedInfo, err := GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.BrokerEndpoint)

		// If Server_ExternalWebUrl is explicitly set, Federation_BrokerUrl defaults to whatever it is
		// But 443 port is stripped if provided
		initConfig()
		require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), mockWebUrlW443Port))
		err = InitServer(ctx, server_structs.BrokerType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.BrokerEndpoint)

		initConfig()
		require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), mockWebUrlWoPort))
		require.NoError(t, param.Set("Federation.BrokerUrl", "https://example-registry.com"))
		err = InitServer(ctx, server_structs.BrokerType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://example-registry.com", fedInfo.BrokerEndpoint)
	})
}

// Test that the web config override can correctly set the logfile location.
func TestWebConfigSetsLogFile(t *testing.T) {
	ResetConfig()
	defer ResetConfig()
	configDir := t.TempDir()
	require.NoError(t, param.Set("ConfigDir", configDir))
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "debug"))
	webConfigFile := filepath.Join(configDir, "web-config.yaml")
	require.NoError(t, param.Set(param.Server_WebConfigFile.GetName(), webConfigFile))
	logFile := filepath.Join(configDir, "test-log.txt")

	mockFederationRoot(t)

	yamlContent := fmt.Sprintf(`
Logging:
  LogLocation: %s
`, logFile)
	require.NoError(t, os.WriteFile(webConfigFile, []byte(yamlContent), 0777))

	logging.SetupLogBuffering()
	err := InitServer(context.Background(), server_structs.OriginType)
	require.NoError(t, err)

	// Manually close the logger's file handle -- this happens automatically
	// when running Pelican proper, but the file lingers in test code and Windows
	// won't be able to close the file because it's in use.
	logging.CloseLogger()

	// Stat the file -- that it was created is sufficient evidence of success
	_, err = os.Stat(logFile)
	require.NoError(t, err)
}

func TestDiscoverFederationImpl(t *testing.T) {
	testCases := []struct {
		name                  string
		inputFed              pelican_url.FederationDiscovery
		mockMetadataIsFedRoot bool
		extWebUrl             string
		expectedFed           pelican_url.FederationDiscovery
		expectError           bool
	}{
		{
			name:                  "all values come from defined discovery URL",
			inputFed:              pelican_url.FederationDiscovery{},
			mockMetadataIsFedRoot: true,
			expectedFed: pelican_url.FederationDiscovery{
				DirectorEndpoint: "https://fake-director.com",
				RegistryEndpoint: "https://fake-registry.com",
				BrokerEndpoint:   "https://fake-broker.com",
				JwksUri:          "https://fake-discovery/.well-known/issuer.jwks",
				DirectorAdvertiseEndpoints: []string{
					"https://fake-director-1.com",
					"https://fake-director-2.com",
				},
			},
			expectError: false,
		},
		{
			name:                  "Setting Director URL with no Discovery URL falls back to Director Discovery",
			inputFed:              pelican_url.FederationDiscovery{},
			mockMetadataIsFedRoot: false,
			// Need to set external web URL so the tested function doesn't think it hosts
			// its own discovery info
			extWebUrl: "https://my-external-web.com",
			expectedFed: pelican_url.FederationDiscovery{
				// We set the Discovery endpoint to what we expect to learn from
				// the federation root, but we don't set the Director URL because
				// that will get set to the mocked metadata discovery server
				DiscoveryEndpoint: "https://fake-discovery.com",
				RegistryEndpoint:  "https://fake-registry.com",
				BrokerEndpoint:    "https://fake-broker.com",
				JwksUri:           "https://fake-discovery/.well-known/issuer.jwks",
				DirectorAdvertiseEndpoints: []string{
					"https://fake-director-1.com",
					"https://fake-director-2.com",
				},
			},
			expectError: false,
		},
		{
			name: "If a subset of values are set, we discover others but only override unset values",
			inputFed: pelican_url.FederationDiscovery{
				DirectorEndpoint: "https://locally-configured-director.com",
			},
			mockMetadataIsFedRoot: true,
			expectedFed: pelican_url.FederationDiscovery{
				DirectorEndpoint: "https://locally-configured-director.com",
				RegistryEndpoint: "https://fake-registry.com",
				BrokerEndpoint:   "https://fake-broker.com",
				JwksUri:          "https://fake-discovery/.well-known/issuer.jwks",
				DirectorAdvertiseEndpoints: []string{
					"https://fake-director-1.com",
					"https://fake-director-2.com",
				},
			},
			expectError: false,
		},
		{
			name: "Unparsable discovery URL returns error",
			// Trigger discovery from the input discovery URL
			mockMetadataIsFedRoot: false,
			inputFed: pelican_url.FederationDiscovery{
				DiscoveryEndpoint: "https://[::1", // Invalid URL
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ResetConfig()
			t.Cleanup(func() {
				ResetConfig()
			})

			// Set up the mock federation discovery endpoint
			// Since the test case instantiation can't know this URL ahead of time
			// we set the expected value of the fed info whenever no expected discovery
			// endpoint is provided but the test indicates it should use the mock fed root
			// for discovery metadata.
			serverUrl := mockFederationRoot(t)
			if tc.mockMetadataIsFedRoot {
				require.NoError(t, param.Set(param.Federation_DiscoveryUrl.GetName(), serverUrl))
				tc.expectedFed.DiscoveryEndpoint = serverUrl
			} else {
				require.NoError(t, param.Set(param.Federation_DiscoveryUrl.GetName(), ""))
				require.NoError(t, param.Set("Federation.DirectorUrl", serverUrl))
				tc.expectedFed.DirectorEndpoint = serverUrl
			}

			// Set up local configuration (simulates stuff the server would get from config files)
			// Note that federation params other than discovery URL cannot be set with param because
			// they're hidden to force access through `config.GetFederation()`
			if tc.inputFed.DiscoveryEndpoint != "" {
				require.NoError(t, param.Set(param.Federation_DiscoveryUrl.GetName(), tc.inputFed.DiscoveryEndpoint))
			}
			if tc.inputFed.RegistryEndpoint != "" {
				require.NoError(t, param.Set("Federation.RegistryUrl", tc.inputFed.RegistryEndpoint))
			}
			if tc.inputFed.DirectorEndpoint != "" {
				require.NoError(t, param.Set("Federation.DirectorUrl", tc.inputFed.DirectorEndpoint))
			}
			if tc.inputFed.BrokerEndpoint != "" {
				require.NoError(t, param.Set("Federation.BrokerUrl", tc.inputFed.BrokerEndpoint))
			}
			if tc.inputFed.JwksUri != "" {
				require.NoError(t, param.Set("Federation.JwksUrl", tc.inputFed.JwksUri))
			}

			require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), tc.extWebUrl))

			// Run discovery
			ctx := testConfigContext(t)
			result, err := discoverFederationImpl(ctx)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedFed, result)
			}
		})
	}
}
