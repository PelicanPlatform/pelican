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
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/p11proxy"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func setupXrootd(t *testing.T, ctx context.Context, server server_structs.ServerType, egrp *errgroup.Group) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "storage")
	require.NoError(t, os.MkdirAll(storageDir, 0755))
	server_utils.ResetTestState()

	require.NoError(t, param.Set("ConfigDir", tmpDir))
	require.NoError(t, param.Set(param.Xrootd_RunLocation.GetName(), tmpDir))
	require.NoError(t, param.Set(param.Cache_RunLocation.GetName(), tmpDir))
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), tmpDir))
	require.NoError(t, param.Set(param.Origin_StoragePrefix.GetName(), storageDir))
	require.NoError(t, param.Set(param.Origin_FederationPrefix.GetName(), "/"))
	require.NoError(t, param.Set(param.Server_IssuerUrl.GetName(), "https://my-xrootd.com:8444"))

	test_utils.MockFederationRoot(t, nil, nil)

	err := config.InitServer(ctx, server)
	require.NoError(t, err)

	if param.Xrootd_LocalMonitoringPort.GetInt() <= 0 {
		require.NoError(t, SetUpMonitoring(ctx, egrp))
	}

}

func TestXrootDOriginConfig(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})

	tests := []struct {
		name            string
		configKey       string
		configValue     string
		shouldError     bool
		expectedContent string
	}{
		{"TestOriginCmsCorrectConfig", "Logging.Origin.Cms", "debug", false, "cms.trace debug"},
		{"TestOriginCmsIncorrectConfig", "Logging.Origin.Cms", "degub", true, ""},
		{"TestOriginScitokensCorrectConfig", "Logging.Origin.Scitokens", "debug", false, "scitokens.trace debug"},
		{"TestOriginScitokensIncorrectConfig", "Logging.Origin.Scitokens", "degub", true, ""},
		{"TestOriginXrdCorrectConfig", "Logging.Origin.Xrd", "debug", false, "xrd.trace debug"},
		{"TestOriginXrdIncorrectConfig", "Logging.Origin.Xrd", "degub", true, ""},
		{"TestOriginXrootdCorrectConfig", "Logging.Origin.Xrootd", "debug", false, "xrootd.trace debug"},
		{"TestOriginXrootdIncorrectConfig", "Logging.Origin.Xrootd", "degub", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer server_utils.ResetTestState()
			setupXrootd(t, ctx, server_structs.OriginType, egrp)

			if tt.configKey != "" {
				require.NoError(t, param.Set(tt.configKey, tt.configValue))
			}

			configPath, err := ConfigXrootd(ctx, true)
			if tt.shouldError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, configPath)

			file, err := os.Open(configPath)
			assert.NoError(t, err)
			defer file.Close()

			content, err := io.ReadAll(file)
			assert.NoError(t, err)
			if tt.expectedContent != "" {
				assert.Contains(t, string(content), tt.expectedContent)
			}

		})
	}

	// Additional configuration tests
	t.Run("TestOsdfWithXRDHOSTAndPort", func(t *testing.T) {
		defer os.Unsetenv("XRDHOST")
		setupXrootd(t, ctx, server_structs.OriginType, egrp)

		_, err := config.SetPreferredPrefix(config.OsdfPrefix)
		require.NoError(t, err, "Failed to set preferred prefix to OSDF")
		require.NoError(t, param.Set("Server.ExternalWebUrl", "https://my-xrootd.com:8443"))

		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)
		assert.Equal(t, "my-xrootd.com", os.Getenv("XRDHOST"))

		server_utils.ResetTestState()
	})

	t.Run("TestOsdfWithXRDHOSTAndNoPort", func(t *testing.T) {
		defer os.Unsetenv("XRDHOST")
		setupXrootd(t, ctx, server_structs.OriginType, egrp)

		_, err := config.SetPreferredPrefix(config.OsdfPrefix)
		require.NoError(t, err, "Failed to set preferred prefix to OSDF")
		require.NoError(t, param.Set("Server.ExternalWebUrl", "https://my-xrootd.com"))

		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)
		assert.Equal(t, "my-xrootd.com", os.Getenv("XRDHOST"))

		server_utils.ResetTestState()
	})

	t.Run("TestPelicanWithXRDHOST", func(t *testing.T) {
		// We don't expect XRDHOST to be set for Pelican proper. However, if it is set,
		// we must unset it on test failure.
		defer os.Unsetenv("XRDHOST")
		setupXrootd(t, ctx, server_structs.OriginType, egrp)

		_, err := config.SetPreferredPrefix(config.PelicanPrefix)
		require.NoError(t, err, "Failed to set preferred prefix to Pelican")
		require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "https://my-xrootd.com:8443"))

		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)
		_, xrdhostIsSet := os.LookupEnv("XRDHOST")
		assert.False(t, xrdhostIsSet, "XRDHOST should only be set in OSDF mode")

		server_utils.ResetTestState()
	})
}

func TestXrootDCacheConfig(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})

	dirname, err := os.MkdirTemp("", "tmpDir")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(dirname)
	})
	server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_RunLocation.GetName(), dirname))
	require.NoError(t, param.Set("ConfigDir", dirname))
	test_utils.MockFederationRoot(t, nil, nil)

	err = config.InitServer(ctx, server_structs.CacheType)
	require.NoError(t, err)
	require.NoError(t, SetUpMonitoring(ctx, egrp))

	configPath, err := ConfigXrootd(ctx, false)
	require.NoError(t, err)
	assert.NotNil(t, configPath)

	tests := []struct {
		name            string
		configKey       string
		configValue     string
		shouldError     bool
		expectedContent string
	}{
		{"TestCacheThrottlePluginEnabled", "Cache.Concurrency", "10", false, "xrootd.fslib ++ throttle"},
		{"TestCacheThrottlePluginDisabled", "", "", false, ""},
		{"TestCacheOfsCorrectConfig", "Logging.Cache.Ofs", "debug", false, "ofs.trace debug"},
		{"TestCacheOfsIncorrectConfig", "Logging.Cache.Ofs", "degub", true, ""},
		{"TestCachePfcCorrectConfig", "Logging.Cache.Pfc", "debug", false, "pfc.trace debug"},
		{"TestCachePfcIncorrectConfig", "Logging.Cache.Pfc", "degub", true, ""},
		{"TestCachePssCorrectConfig", "Logging.Cache.Pss", "debug", false, "pss.trace on"},
		{"TestCachePssIncorrectConfig", "Logging.Cache.Pss", "degub", true, ""},
		{"TestCachePssSetOptCorrectConfig", "Logging.Cache.PssSetOpt", "debug", false, "pss.setopt DebugLevel 4"},
		{"TestCacheScitokensCorrectConfig", "Logging.Cache.Scitokens", "debug", false, "scitokens.trace debug"},
		{"TestCacheScitokensIncorrectConfig", "Logging.Cache.Scitokens", "degub", true, ""},
		{"TestCacheXrdCorrectConfig", "Logging.Cache.Xrd", "debug", false, "xrd.trace debug"},
		{"TestCacheXrdIncorrectConfig", "Logging.Cache.Xrd", "degub", true, ""},
		{"TestCacheXrootdCorrectConfig", "Logging.Cache.Xrootd", "debug", false, "xrootd.trace debug"},
		{"TestCacheXrootdIncorrectConfig", "Logging.Cache.Xrootd", "degub", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer server_utils.ResetTestState()
			setupXrootd(t, ctx, server_structs.CacheType, egrp)

			if tt.configKey != "" {
				require.NoError(t, param.Set(tt.configKey, tt.configValue))
			}

			configPath, err := ConfigXrootd(ctx, false)
			if tt.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, configPath)

				file, err := os.Open(configPath)
				assert.NoError(t, err)
				defer file.Close()

				content, err := io.ReadAll(file)
				assert.NoError(t, err)
				if tt.expectedContent != "" {
					assert.Contains(t, string(content), tt.expectedContent)
				}
			}
		})
	}

	t.Run("TestNestedDataMetaNamespace", func(t *testing.T) {
		testDir := t.TempDir()
		require.NoError(t, param.Set(param.Cache_StorageLocation.GetName(), testDir))
		namespaceLocation := filepath.Join(testDir, "namespace")
		require.NoError(t, param.Set(param.Cache_NamespaceLocation.GetName(), namespaceLocation))

		cache := &cache.CacheServer{}
		uid := os.Getuid()
		gid := os.Getgid()

		// Data location test
		nestedDataLocation := filepath.Join(namespaceLocation, "data")
		require.NoError(t, param.Set(param.Cache_DataLocations.GetName(), []string{nestedDataLocation}))
		err := CheckCacheXrootdEnv(cache, uid, gid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Please ensure these directories are not nested.")
		// Now set to a valid location so we can hit the meta error in the next part of the test
		require.NoError(t, param.Set(param.Cache_DataLocations.GetName(), []string{filepath.Join(testDir, "data")}))

		// Meta location test
		nestedMetaLocation := filepath.Join(namespaceLocation, "meta")
		require.NoError(t, param.Set(param.Cache_MetaLocations.GetName(), []string{nestedMetaLocation}))
		err = CheckCacheXrootdEnv(cache, uid, gid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Please ensure these directories are not nested.")
	})
}

func TestDurationStrToSecondsHookFuncGenerator(t *testing.T) {
	hook := durationStrToSecondsHookFuncGenerator("XrootdOptions", "authrefreshinterval", param.Xrootd_AuthRefreshInterval.GetName(), nil)

	t.Run("stringWithUnit", func(t *testing.T) {
		data := map[string]any{"authrefreshinterval": "90s"}
		res, err := hook(reflect.TypeOf(data), reflect.TypeOf(XrootdOptions{}), data)
		require.NoError(t, err)
		assert.Equal(t, 90, res.(map[string]any)["authrefreshinterval"])
	})

	t.Run("stringWithoutUnitGetsSeconds", func(t *testing.T) {
		data := map[string]any{"authrefreshinterval": "42"}
		res, err := hook(reflect.TypeOf(data), reflect.TypeOf(XrootdOptions{}), data)
		require.NoError(t, err)
		assert.Equal(t, 42, res.(map[string]any)["authrefreshinterval"])
	})

	t.Run("intValue", func(t *testing.T) {
		data := map[string]any{"authrefreshinterval": 15}
		res, err := hook(reflect.TypeOf(data), reflect.TypeOf(XrootdOptions{}), data)
		require.NoError(t, err)
		assert.Equal(t, 15, res.(map[string]any)["authrefreshinterval"])
	})

	t.Run("floatValueRoundsDownSeconds", func(t *testing.T) {
		data := map[string]any{"authrefreshinterval": float32(2.5)}
		res, err := hook(reflect.TypeOf(data), reflect.TypeOf(XrootdOptions{}), data)
		require.NoError(t, err)
		assert.Equal(t, 2, res.(map[string]any)["authrefreshinterval"])
	})

	t.Run("missingKeyReturnsUnchanged", func(t *testing.T) {
		data := map[string]any{"other": "1m"}
		res, err := hook(reflect.TypeOf(data), reflect.TypeOf(XrootdOptions{}), data)
		require.NoError(t, err)
		assert.Equal(t, data, res)
	})

	t.Run("nonTargetStructSkipsHook", func(t *testing.T) {
		data := map[string]any{"authrefreshinterval": "30s"}
		res, err := hook(reflect.TypeOf(data), reflect.TypeOf(CacheConfig{}), data)
		require.NoError(t, err)
		assert.Equal(t, data, res)
	})

	t.Run("badMapTypeErrors", func(t *testing.T) {
		data := map[string]string{"authrefreshinterval": "30s"}
		_, err := hook(reflect.TypeOf(data), reflect.TypeOf(XrootdOptions{}), data)
		require.Error(t, err)
	})

	t.Run("validationApplied", func(t *testing.T) {
		validation := func(d time.Duration, _ string) time.Duration {
			return d + time.Second
		}
		validationHook := durationStrToSecondsHookFuncGenerator("XrootdOptions", "authrefreshinterval", param.Xrootd_AuthRefreshInterval.GetName(), validation)
		data := map[string]any{"authrefreshinterval": "10s"}
		res, err := validationHook(reflect.TypeOf(data), reflect.TypeOf(XrootdOptions{}), data)
		require.NoError(t, err)
		assert.Equal(t, 11, res.(map[string]any)["authrefreshinterval"])
	})
}

func TestUpdateAuth(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	// t.TempDir() registers its own cleanup; placing these before the
	// cancel/egrp cleanup ensures LIFO ordering removes the dirs AFTER
	// the context is cancelled and the maintenance goroutine has stopped.
	runDirname := t.TempDir()
	configDirname := t.TempDir()

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})

	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Logging_Level.GetName(), "Debug"))
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), runDirname))
	require.NoError(t, param.Set("ConfigDir", configDirname))
	authfileName := filepath.Join(configDirname, "authfile")
	require.NoError(t, param.Set(param.Xrootd_Authfile.GetName(), authfileName))
	scitokensName := filepath.Join(configDirname, "scitokens.cfg")
	require.NoError(t, param.Set(param.Xrootd_ScitokensConfig.GetName(), scitokensName))
	storageDir := filepath.Join(runDirname, "storage")
	require.NoError(t, os.MkdirAll(storageDir, 0755))
	require.NoError(t, param.Set(param.Origin_FederationPrefix.GetName(), "/test"))
	require.NoError(t, param.Set(param.Origin_StoragePrefix.GetName(), storageDir))

	test_utils.MockFederationRoot(t, nil, nil)

	err := config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	scitokensCfgDemo := `
[Issuer DEMO]
issuer = https://demo.scitokens.org
base_path = /test1
default_user = user1
`
	scitokensCfgDemo2 := `
[Issuer DEMO2]
issuer = https://demo2.scitokens.org
base_path = /test2
default_user = user2
`

	authfileFooter := "u * /.well-known lr /test -lr\n"
	authfileDemo := "u testing /test3 lr /test -lr\n"
	authfileDemo2 := `u testing /test4 lr`

	err = os.WriteFile(scitokensName, []byte(scitokensCfgDemo), fs.FileMode(0600))
	require.NoError(t, err)
	err = os.WriteFile(authfileName, []byte(authfileDemo), fs.FileMode(0600))
	require.NoError(t, err)

	server := &origin.OriginServer{}
	err = EmitScitokensConfig(server)
	require.NoError(t, err)

	err = EmitAuthfile(server, false)
	require.NoError(t, err)

	destScitokensName := filepath.Join(param.Origin_RunLocation.GetString(), "scitokens-origin-generated.cfg")
	assert.FileExists(t, destScitokensName)
	destAuthfileName := filepath.Join(param.Origin_RunLocation.GetString(), "authfile-origin-generated")
	assert.FileExists(t, destAuthfileName)

	scitokensContents, err := os.ReadFile(destScitokensName)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(scitokensContents), scitokensCfgDemo))

	authfileContents, err := os.ReadFile(destAuthfileName)
	require.NoError(t, err)
	assert.Equal(t, authfileDemo+authfileFooter, string(authfileContents))

	LaunchXrootdMaintenance(ctx, server, 2*time.Hour)

	err = os.WriteFile(scitokensName+".tmp", []byte(scitokensCfgDemo2), fs.FileMode(0600))
	require.NoError(t, err)
	err = os.Rename(scitokensName+".tmp", scitokensName)
	require.NoError(t, err)

	waitForCopy := func(name, sampleContents string) bool {
		for idx := 0; idx < 10; idx++ {
			time.Sleep(50 * time.Millisecond)
			log.Debug("Re-reading destination file")
			destContents, err := os.ReadFile(name)
			require.NoError(t, err)
			if strings.Contains(string(destContents), sampleContents) {
				return true
			}
			log.Debugln("Destination contents:", string(destContents))
		}
		return false
	}

	assert.True(t, waitForCopy(destScitokensName, scitokensCfgDemo2))

	err = os.WriteFile(authfileName+".tmp", []byte(authfileDemo2), fs.FileMode(0600))
	require.NoError(t, err)
	err = os.Rename(authfileName+".tmp", authfileName)
	require.NoError(t, err)
	assert.True(t, waitForCopy(destAuthfileName, authfileDemo2))
}

func TestCopyCertificates(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	// t.TempDir() registers its own cleanup; placing these before the
	// cancel/egrp cleanup ensures LIFO ordering removes the dirs AFTER
	// the context is cancelled and the maintenance goroutine has stopped.
	runDirname := t.TempDir()
	configDirname := t.TempDir()

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})

	server_utils.ResetTestState()
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "Debug"))
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), runDirname))
	require.NoError(t, param.Set("ConfigDir", configDirname))

	test_utils.MockFederationRoot(t, nil, nil)

	// First, invoke CopyXrootdCertificates directly, ensure it works.
	err := copyXrootdCertificates(&origin.OriginServer{})
	assert.ErrorIs(t, err, errBadKeyPair)

	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)
	err = config.MkdirAll(path.Dir(param.Xrootd_Authfile.GetString()), 0755, -1, -1)
	require.NoError(t, err)
	err = copyXrootdCertificates(&origin.OriginServer{})
	require.NoError(t, err)
	destKeyPairName := runtimeTLSCertPath(false)
	assert.FileExists(t, destKeyPairName)

	keyPairContents, err := os.ReadFile(destKeyPairName)
	require.NoError(t, err)
	certName := param.Server_TLSCertificateChain.GetString()
	firstCertContents, err := os.ReadFile(certName)
	require.NoError(t, err)
	keyName := param.Server_TLSKey.GetString()
	firstKeyContents, err := os.ReadFile(keyName)
	require.NoError(t, err)
	firstKeyPairContents := append(firstCertContents, '\n', '\n')
	firstKeyPairContents = append(firstKeyPairContents, firstKeyContents...)
	assert.True(t, bytes.Equal(firstKeyPairContents, keyPairContents))

	err = os.Rename(certName, certName+".orig")
	require.NoError(t, err)

	err = copyXrootdCertificates(&origin.OriginServer{})
	assert.ErrorIs(t, err, errBadKeyPair)

	err = os.Rename(keyName, keyName+".orig")
	require.NoError(t, err)

	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	err = copyXrootdCertificates(&origin.OriginServer{})
	require.NoError(t, err)

	secondKeyPairContents, err := os.ReadFile(destKeyPairName)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(firstKeyPairContents, secondKeyPairContents))

	originServer := &origin.OriginServer{}
	LaunchXrootdMaintenance(ctx, originServer, 2*time.Hour)

	// Helper function to wait for a copy of the first cert to show up
	// in the destination
	waitForCopy := func() bool {
		for idx := 0; idx < 10; idx++ {
			time.Sleep(50 * time.Millisecond)
			log.Debug("Re-reading destination cert")
			destContents, err := os.ReadFile(destKeyPairName)
			require.NoError(t, err)
			if bytes.Equal(destContents, firstKeyPairContents) {
				return true
			}
		}
		return false
	}

	// The maintenance thread should only copy if there's a valid keypair
	// Thus, if we only copy one, we shouldn't see any changes
	err = os.Rename(certName+".orig", certName)
	require.NoError(t, err)
	log.Debug("Will wait to see if the new certs are not copied")
	assert.False(t, waitForCopy())

	// Now, if we overwrite the key, the maintenance thread should notice
	// and overwrite the destination
	err = os.Rename(keyName+".orig", keyName)
	require.NoError(t, err)
	log.Debug("Will wait to see if the new certs are copied")
	assert.True(t, waitForCopy())
}

func TestCopyCertificatesWithPKCS11(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})

	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	runDir := t.TempDir()
	configDir := t.TempDir()
	require.NoError(t, param.Set(param.Origin_RunLocation.GetName(), runDir))
	require.NoError(t, param.Set("ConfigDir", configDir))

	test_utils.MockFederationRoot(t, nil, nil)

	require.NoError(t, param.Set(param.Server_EnablePKCS11.GetName(), true))
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))

	p11proxy.SetCurrentInfoForTest(p11proxy.Info{Enabled: true, PKCS11URL: "pkcs11:test"})
	t.Cleanup(func() {
		p11proxy.SetCurrentInfoForTest(p11proxy.Info{})
		require.NoError(t, param.Set(param.Server_EnablePKCS11.GetName(), false))
	})

	require.NoError(t, copyXrootdCertificates(&origin.OriginServer{}))

	destPath := runtimeTLSCertPath(false)
	got, err := os.ReadFile(destPath)
	require.NoError(t, err)

	origCert, err := os.ReadFile(param.Server_TLSCertificateChain.GetString())
	require.NoError(t, err)

	assert.Equal(t, origCert, got)
}

func TestAuthIntervalUnmarshal(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	defer server_utils.ResetTestState()
	t.Run("test-minutes-to-seconds", func(t *testing.T) {
		server_utils.ResetTestState()
		var xrdConfig XrootdConfig
		require.NoError(t, param.Set(param.Xrootd_AuthRefreshInterval.GetName(), "5m"))
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(xrootdDecodeHook()))
		assert.NoError(t, err)
		assert.Equal(t, 300, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-hours-to-seconds", func(t *testing.T) {
		server_utils.ResetTestState()
		var xrdConfig XrootdConfig
		require.NoError(t, param.Set(param.Xrootd_AuthRefreshInterval.GetName(), "24h"))
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(xrootdDecodeHook()))
		assert.NoError(t, err)
		assert.Equal(t, 86400, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-seconds-to-seconds", func(t *testing.T) {
		server_utils.ResetTestState()
		var xrdConfig XrootdConfig
		require.NoError(t, param.Set(param.Xrootd_AuthRefreshInterval.GetName(), "100s"))
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(xrootdDecodeHook()))
		assert.NoError(t, err)
		assert.Equal(t, 100, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-less-than-60s", func(t *testing.T) {
		server_utils.ResetTestState()
		var xrdConfig XrootdConfig
		require.NoError(t, param.Set(param.Xrootd_AuthRefreshInterval.GetName(), "10s"))
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(xrootdDecodeHook()))
		assert.NoError(t, err)
		// Should fall back to 5m, or 300s
		assert.Equal(t, 300, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-no-suffix-to-seconds", func(t *testing.T) {
		server_utils.ResetTestState()
		var xrdConfig XrootdConfig
		require.NoError(t, param.Set(param.Xrootd_AuthRefreshInterval.GetName(), "99s"))
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(xrootdDecodeHook()))
		assert.NoError(t, err)
		assert.Equal(t, 99, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-less-than-second", func(t *testing.T) {
		server_utils.ResetTestState()
		var xrdConfig XrootdConfig
		require.NoError(t, param.Set(param.Xrootd_AuthRefreshInterval.GetName(), "0.5s"))
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(xrootdDecodeHook()))
		assert.NoError(t, err)
		assert.Equal(t, 300, xrdConfig.Xrootd.AuthRefreshInterval)
	})

}

func TestGenLoggingConfig(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	testCases := []struct {
		name        string
		pelLogLevel string
		logMap      loggingMap
		input       string
		want        string
		wantErr     bool
	}{
		{
			name:        "EmptyLogMap",
			pelLogLevel: "error",
			logMap:      loggingMap{},
			input:       "Trace",
			want:        "",
			wantErr:     true, // Programmer forgot to set up the log map
		},
		{
			name:        "BadInput",
			pelLogLevel: "error",
			logMap: loggingMap{
				Info:  "bar",
				Error: "foo",
			},
			input:   "badinput", // Bad input configured by user
			wantErr: true,
		},
		{
			name:        "EmptyInput",
			pelLogLevel: "warn",
			logMap: loggingMap{
				Info:  "bar",
				Warn:  "baz",
				Error: "foo",
			},
			want: "baz", // Should pick up "warn" from pel
		},
		{
			name:        "DirectMatch",
			pelLogLevel: "error",
			logMap: loggingMap{
				Info:  "bar",
				Error: "foo",
			},
			input: "info",
			want:  "bar", // No direct match, should drop to next lowest level
		},
		{
			name:        "HandleUppercase",
			pelLogLevel: "error",
			logMap: loggingMap{
				Info:  "bar",
				Error: "foo",
			},
			input: "Info", // Both uppercase and lowercase input should work
			want:  "bar",
		},
		{
			name:        "MapDown",
			pelLogLevel: "error",
			logMap: loggingMap{
				Info:  "bar",
				Error: "foo",
			},
			input: "warn",
			want:  "foo", // No direct match, should drop to next lowest level
		},
		{
			name:        "MapUpIfNoDown",
			pelLogLevel: "error",
			logMap: loggingMap{
				Info:  "bar",
				Error: "foo",
			},
			input: "panic",
			want:  "foo", // There is no next lowest level, get next highest
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			require.NoError(t, param.Set("Logging.Level", tc.pelLogLevel))

			output, err := genLoggingConfig(tc.input, tc.logMap)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, output)
			}
		})
	}
}

func TestAutoShutdownOnStaleAuthfile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	// t.TempDir() registers its own cleanup; placing it before the
	// cancel/egrp cleanup ensures LIFO ordering removes the dir AFTER
	// the context is cancelled and the maintenance goroutine has stopped.
	dir := t.TempDir()

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})

	require.NoError(t, param.Set(param.Logging_Level.GetName(), "Debug"))
	require.NoError(t, param.Set("ConfigDir", dir))
	require.NoError(t, param.Set(param.Cache_RunLocation.GetName(), dir))

	// Start with a valid authfile and scitokens so the first cycles succeed
	validAuthfilePath := filepath.Join(dir, "authfile")
	require.NoError(t, os.WriteFile(validAuthfilePath, []byte("u * /.well-known lr\n"), 0600))
	require.NoError(t, param.Set(param.Xrootd_Authfile.GetName(), validAuthfilePath))

	scitokensPath := filepath.Join(dir, "scitokens.cfg")
	require.NoError(t, os.WriteFile(scitokensPath, []byte(""), 0600))
	require.NoError(t, param.Set(param.Xrootd_ScitokensConfig.GetName(), scitokensPath))

	test_utils.MockFederationRoot(t, nil, nil)

	// Init cache server
	require.NoError(t, config.InitServer(ctx, server_structs.CacheType))

	// Set timeout AFTER InitServer as a string to ensure correct parsing
	require.NoError(t, param.Set(param.Xrootd_ConfigUpdateFailureTimeout.GetName(), "50ms"))
	require.NoError(t, param.Set(param.Xrootd_AutoShutdownEnabled.GetName(), true))

	cacheServer := &cache.CacheServer{}

	// Replace global ShutdownFlag with a test-local buffered channel to avoid interference
	origShutdown := config.ShutdownFlag
	defer func() { config.ShutdownFlag = origShutdown }()
	testShutdown := make(chan any, 1)
	config.ShutdownFlag = testShutdown

	// Launch maintenance with a short ticker
	LaunchXrootdMaintenance(ctx, cacheServer, 100*time.Millisecond)

	// Ensure at least one successful cycle happened (generated file exists)
	emittedAuthfilePath := filepath.Join(dir, "authfile-cache-generated")
	require.Eventually(t, func() bool {
		_, err := os.Stat(emittedAuthfilePath)
		return err == nil
	}, 500*time.Millisecond, 20*time.Millisecond, "expected generated authfile to exist after initial maintenance")

	// Now flip to INVALID authfile path to force failures and staleness
	missingAuthfilePath := filepath.Join(dir, "missing-authfile")
	require.NoError(t, param.Set(param.Xrootd_Authfile.GetName(), missingAuthfilePath))

	// Wait to exceed timeout and then trigger maintenance immediately by touching scitokens
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, os.WriteFile(scitokensPath, []byte("# poke\n"), 0600))

	select {
	case <-testShutdown:
		cancel()
		return
	case <-time.After(3 * time.Second):
		t.Fatal("expected shutdown due to stale Authfile, but none observed within timeout")
	}
}

func TestConfigUpdatesHealthOKWhenFresh(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	dir := t.TempDir() // This also automatically registers its own cleanup (RemoveAll), which should be called after cancel/Wait runs
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, egrp.Wait())
		// ResetTestState must happen after Wait returns so the maintenance
		// goroutine has fully exited; otherwise Cache_RunLocation gets wiped
		// while the goroutine is still emitting files, causing writes to CWD.
		server_utils.ResetTestState()
	})

	require.NoError(t, param.Set(param.Logging_Level.GetName(), "Debug"))
	require.NoError(t, param.Set("ConfigDir", dir))
	require.NoError(t, param.Set(param.Cache_RunLocation.GetName(), dir))
	require.NoError(t, param.Set(param.Xrootd_AutoShutdownEnabled.GetName(), true))
	require.NoError(t, param.Set(param.Xrootd_ConfigUpdateFailureTimeout.GetName(), 1*time.Second))

	// Valid authfile and scitokens inputs so both emissions succeed
	authfilePath := filepath.Join(dir, "authfile")
	require.NoError(t, os.WriteFile(authfilePath, []byte("u * /.well-known lr\n"), 0600))
	require.NoError(t, param.Set(param.Xrootd_Authfile.GetName(), authfilePath))
	scitokensPath := filepath.Join(dir, "scitokens.cfg")
	require.NoError(t, os.WriteFile(scitokensPath, []byte(""), 0600))
	require.NoError(t, param.Set(param.Xrootd_ScitokensConfig.GetName(), scitokensPath))

	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, config.InitServer(ctx, server_structs.CacheType))
	cacheServer := &cache.CacheServer{}

	LaunchXrootdMaintenance(ctx, cacheServer, 20*time.Millisecond)

	// Give the maintenance loop a couple of cycles
	time.Sleep(100 * time.Millisecond)

	status, err := metrics.GetComponentStatus(metrics.OriginCache_ConfigUpdates)
	require.NoError(t, err)
	assert.Equal(t, metrics.StatusOK.String(), status)
}
