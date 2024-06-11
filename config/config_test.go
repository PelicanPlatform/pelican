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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/mock"
	"github.com/pelicanplatform/pelican/param"
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
	viper.Set("Transport.MaxIdleConns", 30)
	viper.Set("Transport.IdleConnTimeout", time.Second*90)
	viper.Set("Transport.TLSHandshakeTimeout", time.Second*15)
	viper.Set("Transport.ExpectContinueTimeout", time.Second*1)
	viper.Set("Transport.ResponseHeaderTimeout", time.Second*10)

	viper.Set("Transport.Dialer.Timeout", time.Second*1)
	viper.Set("Transport.Dialer.KeepAlive", time.Second*30)
	viper.Set("TLSSkipVerify", true)
	server.StartTLS()
	defer server.Close()
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestResponseHeaderTimeout(t *testing.T) {
	// Change the viper value of the timeout
	viper.Set("Transport.ResponseHeaderTimeout", time.Millisecond*25)
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

	viper.Set("Transport.ResponseHeaderTimeout", time.Second*10)
}

func TestDialerTimeout(t *testing.T) {
	// Change the viper value of the timeout
	viper.Set("Transport.Dialer.Timeout", time.Millisecond*25)
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

	viper.Set("Transport.Dialer.Timeout", time.Second*10)
}

func TestInitConfig(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
	})
	// Set prefix to OSDF to ensure that config is being set
	testingPreferredPrefix = "OSDF"

	// Create a temp config file to use
	tempCfgFile, err := os.CreateTemp("", "pelican-*.yaml")
	viper.Set("config", tempCfgFile.Name())
	if err != nil {
		t.Fatalf("Failed to make temp file: %v", err)
	}

	InitConfig() // Should set up pelican.yaml, osdf.yaml and defaults.yaml

	// Check if server address is correct by defaults.yaml
	assert.Equal(t, "0.0.0.0", param.Server_WebHost.GetString())
	// Check that Federation Discovery url is correct by osdf.yaml
	assert.Equal(t, "osg-htc.org", param.Federation_DiscoveryUrl.GetString())

	viper.Set("Server.WebHost", "1.1.1.1") // should write to temp config file
	if err := viper.WriteConfigAs(tempCfgFile.Name()); err != nil {
		t.Fatalf("Failed to write to config file: %v", err)
	}
	viper.Reset()
	viper.Set("config", tempCfgFile.Name()) // Set the temp file as the new 'pelican.yaml'
	InitConfig()

	// Check if server address overrides the default
	assert.Equal(t, "1.1.1.1", param.Server_WebHost.GetString())
	viper.Reset()

	//Test if prefix is not set, should not be able to find osdfYaml configuration
	testingPreferredPrefix = ""
	tempCfgFile, err = os.CreateTemp("", "pelican-*.yaml")
	viper.Set("config", tempCfgFile.Name())
	if err != nil {
		t.Fatalf("Failed to make temp file: %v", err)
	}
	InitConfig()
	assert.Equal(t, "", param.Federation_DiscoveryUrl.GetString())
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
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
	})

	t.Run("test-no-continue", func(t *testing.T) {
		err := handleContinuedCfg()
		assert.NoError(t, err)
	})

	t.Run("test-one-dir-no-files", func(t *testing.T) {
		viper.Reset()
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
		viper.Reset()
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
		viper.Reset()
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
		viper.Reset()
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
		viper.Reset()
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

func TestDeprecateLogMessage(t *testing.T) {
	tmpPathPattern := "TestOrigin*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	// Need to set permissions or the xrootd process we spawn won't be able to write PID/UID files
	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	viper.Set("ConfigDir", tmpPath)
	viper.Reset()
	t.Run("expect-deprecated-message-if-namespace-is-set", func(t *testing.T) {
		hook := test.NewGlobal()
		viper.Reset()
		defer viper.Reset()
		// The default value is set to Error, but this is a warning message
		viper.Set("Logging.Level", "Warning")
		viper.Set("Origin.NamespacePrefix", "/a/prefix")
		viper.Set("ConfigDir", tmpPath)

		// NOTE: When we run InitConfig(), which runs handleDeprecatedConfig(), we're making the assumption that our
		// parameters struct is fully built. Since this doesn't happen when we run tests, we need to manually build
		// for any updates to get picked up.
		InitConfig()

		require.Equal(t, 2, len(hook.Entries))
		assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
		assert.Equal(t, "Deprecated configuration key Origin.NamespacePrefix is set. Please migrate to use Origin.FederationPrefix instead", hook.Entries[len(hook.Entries)-2].Message)
		assert.Equal(t, "Will attempt to use the value of Origin.NamespacePrefix as default for Origin.FederationPrefix", hook.LastEntry().Message)
		// If the deprecated key is set to something that we can map to the new key, that mapping should be handled in InitConfig.
		// Since Origin.NamespacePrefix maps to Origin.FederationPrefix, check that it succeeded.
		assert.Equal(t, "/a/prefix", viper.GetString("Origin.FederationPrefix"))
		hook.Reset()
	})
}

func TestEnabledServers(t *testing.T) {
	allServerTypes := []ServerType{OriginType, CacheType, DirectorType, RegistryType}
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
			enabledServers.SetList([]ServerType{server})
			assert.True(t, IsServerEnabled(server))
			assert.Equal(t, []string{server.String()}, GetEnabledServerString(false))
			assert.Equal(t, []string{strings.ToLower(server.String())}, GetEnabledServerString(true))
		}
	})

	t.Run("enable-multiple-servers", func(t *testing.T) {
		enabledServers = 0
		enabledServers.SetList([]ServerType{OriginType, CacheType})
		serverStr := []string{OriginType.String(), CacheType.String()}
		serverStrLower := []string{strings.ToLower(OriginType.String()), strings.ToLower(CacheType.String())}
		sort.Strings(serverStr)
		sort.Strings(serverStrLower)
		assert.True(t, IsServerEnabled(OriginType))
		assert.True(t, IsServerEnabled(CacheType))
		assert.Equal(t, serverStr, GetEnabledServerString(false))
		assert.Equal(t, serverStrLower, GetEnabledServerString(true))
	})

	t.Run("enable-all-servers", func(t *testing.T) {
		enabledServers = 0
		enabledServers.SetList(allServerTypes)
		assert.True(t, IsServerEnabled(OriginType))
		assert.True(t, IsServerEnabled(CacheType))
		assert.True(t, IsServerEnabled(RegistryType))
		assert.True(t, IsServerEnabled(DirectorType))
		assert.Equal(t, allServerStrs, GetEnabledServerString(false))
		assert.Equal(t, allServerStrsLower, GetEnabledServerString(true))
	})

	t.Run("setEnabledServer-only-set-once", func(t *testing.T) {
		enabledServers = 0
		sType := OriginType
		sType.Set(CacheType)
		setEnabledServer(sType)
		assert.True(t, IsServerEnabled(OriginType))
		assert.True(t, IsServerEnabled(CacheType))

		sType.Clear()
		sType.Set(DirectorType)
		sType.Set(RegistryType)
		setEnabledServer(sType)
		assert.True(t, IsServerEnabled(OriginType))
		assert.True(t, IsServerEnabled(CacheType))
		assert.False(t, IsServerEnabled(DirectorType))
		assert.False(t, IsServerEnabled(RegistryType))
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

func TestDiscoverFederation(t *testing.T) {
	ctx := testConfigContext(t)

	viper.Reset()
	// Server to be a "mock" federation
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// make our response:
		response := FederationDiscovery{
			DirectorEndpoint:              "director",
			NamespaceRegistrationEndpoint: "registry",
			JwksUri:                       "jwks",
			BrokerEndpoint:                "broker",
		}

		responseJSON, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, err = w.Write(responseJSON)
		assert.NoError(t, err)
	}))
	defer server.Close()
	transport := GetTransport()
	origClientConfig := transport.TLSClientConfig
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	t.Cleanup(func() {
		transport.TLSClientConfig = origClientConfig
	})

	t.Run("testInvalidDiscoveryUrlWithPath", func(t *testing.T) {
		viper.Reset()
		viper.Set("ConfigDir", t.TempDir())
		viper.Set("Federation.DiscoveryURL", server.URL+"/this/is/some/path")
		InitConfig()
		require.NoError(t, InitClient())
		_, err := GetFederation(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid federation discovery url is set. No path allowed for federation discovery url. Provided url: ",
			"Error returned does not contain the correct error")
		viper.Reset()
	})

	t.Run("testValidDiscoveryUrl", func(t *testing.T) {
		viper.Reset()
		viper.Set("ConfigDir", t.TempDir())
		InitConfig()
		require.NoError(t, InitClient())
		transport := GetTransport()
		transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		viper.Set("Federation.DiscoveryUrl", server.URL)
		fedInfo, err := GetFederation(ctx)
		assert.NoError(t, err)
		// Assert that the metadata matches expectations
		assert.Equal(t, "director", fedInfo.DirectorEndpoint, "Unexpected DirectorEndpoint")
		assert.Equal(t, "registry", fedInfo.NamespaceRegistrationEndpoint, "Unexpected NamespaceRegistrationEndpoint")
		assert.Equal(t, "jwks", fedInfo.JwksUri, "Unexpected JwksUri")
		assert.Equal(t, "broker", fedInfo.BrokerEndpoint, "Unexpected BrokerEndpoint")
		viper.Reset()
	})

	t.Run("testOsgHtcUrl", func(t *testing.T) {
		viper.Reset()
		viper.Set("ConfigDir", t.TempDir())
		InitConfig()
		require.NoError(t, InitClient())
		mock.MockOSDFDiscovery(t, GetTransport())
		viper.Set("Federation.DiscoveryUrl", "osg-htc.org")
		fedInfo, err := GetFederation(ctx)
		assert.NoError(t, err)
		// Assert that the metadata matches expectations
		assert.Equal(t, "https://osdf-director.osg-htc.org", fedInfo.DirectorEndpoint, "Unexpected DirectorEndpoint")
		assert.Equal(t, "https://osdf-registry.osg-htc.org", fedInfo.NamespaceRegistrationEndpoint, "Unexpected NamespaceRegistrationEndpoint")
		assert.Equal(t, "https://osg-htc.org/osdf/public_signing_key.jwks", fedInfo.JwksUri, "Unexpected JwksUri")
		assert.Equal(t, "", fedInfo.BrokerEndpoint, "Unexpected BrokerEndpoint")
		viper.Reset()
	})
}

func TestCheckWatermark(t *testing.T) {
	t.Parallel()

	t.Run("empty-value", func(t *testing.T) {
		ok, num, err := checkWatermark("")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("string-value", func(t *testing.T) {
		ok, num, err := checkWatermark("random")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("integer-greater-than-100", func(t *testing.T) {
		ok, num, err := checkWatermark("101")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("integer-less-than-0", func(t *testing.T) {
		ok, num, err := checkWatermark("-1")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("decimal-fraction-value", func(t *testing.T) {
		ok, num, err := checkWatermark("0.55")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("decimal-int-value", func(t *testing.T) {
		ok, num, err := checkWatermark("15.55")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("int-value", func(t *testing.T) {
		ok, num, err := checkWatermark("55")
		assert.True(t, ok)
		assert.Equal(t, int64(55), num)
		assert.NoError(t, err)
	})

	t.Run("byte-value-no-unit", func(t *testing.T) {
		ok, num, err := checkWatermark("105")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("byte-value-no-value", func(t *testing.T) {
		ok, num, err := checkWatermark("k")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("byte-value-wrong-unit", func(t *testing.T) {
		ok, num, err := checkWatermark("100K") // Only lower case is accepted
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)

		ok, num, err = checkWatermark("100p")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)

		ok, num, err = checkWatermark("100byte")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)

		ok, num, err = checkWatermark("100bits")
		assert.False(t, ok)
		assert.Equal(t, int64(0), num)
		assert.Error(t, err)
	})

	t.Run("byte-value-correct-unit", func(t *testing.T) {
		ok, num, err := checkWatermark("1000k")
		assert.True(t, ok)
		assert.Equal(t, int64(1000*1024), num)
		assert.NoError(t, err)

		ok, num, err = checkWatermark("1000m")
		assert.True(t, ok)
		assert.Equal(t, int64(1000*1024*1024), num)
		assert.NoError(t, err)

		ok, num, err = checkWatermark("1000g")
		assert.True(t, ok)
		assert.Equal(t, int64(1000*1024*1024*1024), num)
		assert.NoError(t, err)

		ok, num, err = checkWatermark("1000t")
		assert.True(t, ok)
		assert.Equal(t, int64(1000*1024*1024*1024*1024), num)
		assert.NoError(t, err)
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
		viper.Reset()
	})

	initConfig := func() {
		viper.Reset()
		tempDir := t.TempDir()
		viper.Set("ConfigDir", tempDir)
	}

	initDirectoryConfig := func() {
		initConfig()
		viper.Set("Director.MinStatResponse", 1)
		viper.Set("Director.MaxStatResponse", 4)
	}

	t.Run("web-url-defaults-to-hostname-port", func(t *testing.T) {
		viper.Reset()
		viper.Set("Server.Hostname", mockHostname)
		viper.Set("Server.WebPort", mockNon443Port)
		err := InitServer(context.Background(), 0)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWNon443Port, param.Server_ExternalWebUrl.GetString())
	})

	t.Run("default-web-url-removes-443-port", func(t *testing.T) {
		viper.Reset()
		viper.Set("Server.Hostname", mockHostname)
		viper.Set("Server.WebPort", mock443Port)
		err := InitServer(context.Background(), 0)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, param.Server_ExternalWebUrl.GetString())
	})

	t.Run("remove-443-port-for-set-web-url", func(t *testing.T) {
		// We respect the URL value set directly by others. Won't remove 443 port
		viper.Reset()
		viper.Set("Server.ExternalWebUrl", mockWebUrlW443Port)
		err := InitServer(context.Background(), 0)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, param.Server_ExternalWebUrl.GetString())
	})

	t.Run("dir-url-default-to-web-url", func(t *testing.T) {
		// We respect the URL value set directly by others. Won't remove 443 port
		initDirectoryConfig()
		// If Server_ExternalWebUrl is not set, Federation_DirectorUrl defaults to https://<hostname>:<non-443-port>
		// In this case, the port is 443, so Federation_DirectorUrl = https://example.com
		viper.Set("Server.Hostname", mockHostname)
		viper.Set("Server.WebPort", mock443Port)
		err := InitServer(ctx, DirectorType)
		require.NoError(t, err)
		fedInfo, err := GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.DirectorEndpoint)

		// If Server_ExternalWebUrl is explicitly set, Federation_DirectorUrl defaults to whatever it is
		// But 443 port is stripped if provided
		initDirectoryConfig()
		viper.Set("Server.ExternalWebUrl", mockWebUrlW443Port)
		err = InitServer(ctx, DirectorType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.DirectorEndpoint)

		initDirectoryConfig()
		viper.Set("Server.ExternalWebUrl", mockWebUrlWoPort)
		viper.Set("Federation.DirectorUrl", "https://example-director.com")
		err = InitServer(ctx, DirectorType)
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
		viper.Set("Server.Hostname", mockHostname)
		viper.Set("Server.WebPort", mock443Port)
		err := InitServer(ctx, RegistryType)
		require.NoError(t, err)
		fedInfo, err := GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.NamespaceRegistrationEndpoint)

		// If Server_ExternalWebUrl is explicitly set, Federation_RegistryUrl defaults to whatever it is
		// But 443 port is stripped if provided
		initConfig()
		viper.Set("Server.ExternalWebUrl", mockWebUrlW443Port)
		err = InitServer(ctx, RegistryType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.NamespaceRegistrationEndpoint)

		initConfig()
		viper.Set("Server.ExternalWebUrl", mockWebUrlWoPort)
		viper.Set("Federation.RegistryUrl", "https://example-registry.com")
		err = InitServer(ctx, RegistryType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://example-registry.com", fedInfo.NamespaceRegistrationEndpoint)
	})

	t.Run("broker-url-default-to-web-url", func(t *testing.T) {
		// We respect the URL value set directly by others. Won't remove 443 port
		initConfig()
		// If Server_ExternalWebUrl is not set, Federation_BrokerUrl defaults to https://<hostname>:<non-443-port>
		// In this case, the port is 443, so Federation_BrokerUrl = https://example.com
		viper.Set("Server.Hostname", mockHostname)
		viper.Set("Server.WebPort", mock443Port)
		err := InitServer(ctx, BrokerType)
		require.NoError(t, err)
		fedInfo, err := GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.BrokerEndpoint)

		// If Server_ExternalWebUrl is explicitly set, Federation_BrokerUrl defaults to whatever it is
		// But 443 port is stripped if provided
		initConfig()
		viper.Set("Server.ExternalWebUrl", mockWebUrlW443Port)
		err = InitServer(ctx, BrokerType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockWebUrlWoPort, fedInfo.BrokerEndpoint)

		initConfig()
		viper.Set("Server.ExternalWebUrl", mockWebUrlWoPort)
		viper.Set("Federation.BrokerUrl", "https://example-registry.com")
		err = InitServer(ctx, BrokerType)
		require.NoError(t, err)
		fedInfo, err = GetFederation(ctx)
		require.NoError(t, err)
		assert.Equal(t, "https://example-registry.com", fedInfo.BrokerEndpoint)
	})
}
func TestDiscoverUrlFederation(t *testing.T) {
	t.Run("TestMetadataDiscoveryTimeout", func(t *testing.T) {
		viper.Set("tlsskipverify", true)
		err := InitClient()
		assert.NoError(t, err)
		// Create a server that sleeps for a longer duration than the timeout
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
		}))
		defer server.Close()

		// Set a short timeout for the test
		timeout := 1 * time.Second

		// Create a context with the timeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Call the function with the server URL and the context
		_, err = DiscoverUrlFederation(ctx, server.URL)

		// Assert that the error is the expected metadata timeout error
		assert.Error(t, err)
		assert.True(t, errors.Is(err, MetadataTimeoutErr))
		viper.Reset()
	})

	t.Run("TestCanceledContext", func(t *testing.T) {
		// Create a server that waits for the context to be canceled
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()

		// Create a context and cancel it immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Call the function with the server URL and the canceled context
		_, err := DiscoverUrlFederation(ctx, server.URL)

		// Assert that the error is the expected context cancel error
		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
	})

	t.Run("TestValidDiscovery", func(t *testing.T) {
		viper.Set("tlsskipverify", true)
		err := InitClient()
		assert.NoError(t, err)
		// Server to be a "mock" federation
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// make our response:
			response := FederationDiscovery{
				DirectorEndpoint:              "director",
				NamespaceRegistrationEndpoint: "registry",
				JwksUri:                       "jwks",
				BrokerEndpoint:                "broker",
			}

			responseJSON, err := json.Marshal(response)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
			_, err = w.Write(responseJSON)
			assert.NoError(t, err)
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		metadata, err := DiscoverUrlFederation(ctx, server.URL)
		assert.NoError(t, err)

		// Assert that the metadata matches expectations
		assert.Equal(t, "director", metadata.DirectorEndpoint, "Unexpected DirectorEndpoint")
		assert.Equal(t, "registry", metadata.NamespaceRegistrationEndpoint, "Unexpected NamespaceRegistrationEndpoint")
		assert.Equal(t, "jwks", metadata.JwksUri, "Unexpected JwksUri")
		assert.Equal(t, "broker", metadata.BrokerEndpoint, "Unexpected BrokerEndpoint")
		viper.Reset()
	})
}
