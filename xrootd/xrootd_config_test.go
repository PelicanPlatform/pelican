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
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

type xrootdTest struct {
	T   *testing.T
	ctx context.Context
}

func (x *xrootdTest) setup() {
	viper.Reset()
	server_utils.ResetOriginExports()
	dirname, err := os.MkdirTemp("", "tmpDir")
	require.NoError(x.T, err)
	x.T.Cleanup(func() {
		os.RemoveAll(dirname)
	})
	viper.Set("ConfigDir", dirname)
	viper.Set("Xrootd.RunLocation", dirname)
	viper.Set("Cache.RunLocation", dirname)
	viper.Set("Origin.RunLocation", dirname)
	viper.Set("Origin.StoragePrefix", "/")
	viper.Set("Origin.FederationPrefix", "/")
	config.InitConfig()
	var cancel context.CancelFunc
	var egrp *errgroup.Group
	x.ctx, cancel, egrp = test_utils.TestContext(context.Background(), x.T)
	defer func() { require.NoError(x.T, egrp.Wait()) }()
	defer cancel()
}

func TestXrootDOriginConfig(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirname, err := os.MkdirTemp("", "tmpDir")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(dirname)
	})
	viper.Reset()
	server_utils.ResetOriginExports()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()
	viper.Set("Configdir", dirname)
	viper.Set("Origin.RunLocation", dirname)
	viper.Set("Xrootd.RunLocation", dirname)
	viper.Set("Origin.StoragePrefix", "/")
	viper.Set("Origin.FederationPrefix", "/")
	config.InitConfig()
	configPath, err := ConfigXrootd(ctx, true)
	require.NoError(t, err)
	assert.NotNil(t, configPath)

	t.Run("TestOriginCmsCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Origin.Cms", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "cms.trace debug")
		viper.Reset()
	})

	t.Run("TestOriginCmsIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Origin.Cms", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.Error(t, err)
		assert.NotNil(t, configPath)
		viper.Reset()
	})

	t.Run("TestOriginScitokensCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Origin.Scitokens", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "scitokens.trace debug")
		viper.Reset()
	})

	t.Run("TestOriginScitokensIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Origin.Scitokens", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.Error(t, err)
		assert.NotNil(t, configPath)
		viper.Reset()
	})

	t.Run("TestOriginXrdCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Origin.Xrd", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "xrd.trace debug")
		viper.Reset()
	})

	t.Run("TestOriginXrdIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Origin.Xrd", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.Error(t, err)
		assert.NotNil(t, configPath)
		viper.Reset()
	})

	t.Run("TestOriginXrootdCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Origin.Xrootd", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "xrootd.trace debug")
		viper.Reset()
	})

	t.Run("TestOriginXrootdIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Origin.Xrootd", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.Error(t, err)
		assert.NotNil(t, configPath)
		viper.Reset()
	})

	t.Run("TestOsdfWithXRDHOSTAndPort", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		defer os.Unsetenv("XRDHOST")
		xrootd.setup()

		_, err := config.SetPreferredPrefix(config.OsdfPrefix)
		require.NoError(t, err, "Failed to set preferred prefix to OSDF")
		viper.Set("Server.ExternalWebUrl", "https://my-xrootd.com:8443")

		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)
		assert.Equal(t, "my-xrootd.com", os.Getenv("XRDHOST"))

		viper.Reset()
	})

	t.Run("TestOsdfWithXRDHOSTAndNoPort", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		defer os.Unsetenv("XRDHOST")
		xrootd.setup()

		_, err := config.SetPreferredPrefix(config.OsdfPrefix)
		require.NoError(t, err, "Failed to set preferred prefix to OSDF")
		viper.Set("Server.ExternalWebUrl", "https://my-xrootd.com")

		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)
		assert.Equal(t, "my-xrootd.com", os.Getenv("XRDHOST"))

		viper.Reset()
	})

	t.Run("TestPelicanWithXRDHOST", func(t *testing.T) {
		// We don't expect XRDHOST to be set for Pelican proper
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		_, err := config.SetPreferredPrefix(config.PelicanPrefix)
		require.NoError(t, err, "Failed to set preferred prefix to Pelican")
		viper.Set("Server.ExternalWebUrl", "https://my-xrootd.com:8443")

		configPath, err := ConfigXrootd(ctx, true)
		require.NoError(t, err)
		assert.NotNil(t, configPath)
		_, xrdhostIsSet := os.LookupEnv("XRDHOST")
		assert.False(t, xrdhostIsSet, "XRDHOST should only be set in OSDF mode")

		viper.Reset()
	})
}

func TestXrootDCacheConfig(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirname, err := os.MkdirTemp("", "tmpDir")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(dirname)
	})
	viper.Reset()
	server_utils.ResetOriginExports()
	viper.Set("Cache.RunLocation", dirname)
	viper.Set("ConfigDir", dirname)
	config.InitConfig()
	configPath, err := ConfigXrootd(ctx, false)
	require.NoError(t, err)
	assert.NotNil(t, configPath)

	t.Run("TestCacheThrottlePluginEnabled", func(t *testing.T) {
		defer viper.Reset()
		defer server_utils.ResetOriginExports()
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Cache.Concurrency", 10)

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "xrootd.fslib ++ throttle")
		assert.Contains(t, string(content), "throttle.throttle concurrency 10")
	})

	t.Run("TestCacheThrottlePluginDisabled", func(t *testing.T) {
		defer viper.Reset()
		defer server_utils.ResetOriginExports()
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.NotContains(t, string(content), "xrootd.fslib throttle default")
		assert.NotContains(t, string(content), "throttle.throttle concurrency")
	})

	t.Run("TestCacheOfsCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Ofs", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "ofs.trace debug")
		viper.Reset()
	})

	t.Run("TestCacheOfsIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Ofs", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.Error(t, err)
		assert.NotNil(t, configPath)
	})

	t.Run("TestCachePfcCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Pfc", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "pfc.trace debug")
		viper.Reset()
	})

	t.Run("TestCachePfcIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Pfc", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, true)
		require.Error(t, err)
		assert.NotNil(t, configPath)
		viper.Reset()
	})

	t.Run("TestCachePssCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Pss", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "pss.setopt DebugLevel 4")
		viper.Reset()
	})

	t.Run("TestCachePssIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Pss", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.Error(t, err)
		assert.NotNil(t, configPath)
	})

	t.Run("TestCacheScitokensCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Scitokens", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "scitokens.trace debug")
		viper.Reset()
	})

	t.Run("TestCacheScitokensIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Scitokens", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.Error(t, err)
		assert.NotNil(t, configPath)
	})

	t.Run("TestCacheXrdCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Xrd", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "xrd.trace debug")
		viper.Reset()
	})

	t.Run("TestCacheXrdIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Xrd", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.Error(t, err)
		assert.NotNil(t, configPath)
	})

	t.Run("TestCacheXrootdCorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Xrootd", "debug")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.NoError(t, err)
		assert.NotNil(t, configPath)

		// Verify the output
		file, err := os.Open(configPath)
		assert.NoError(t, err)
		defer file.Close()

		content, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Contains(t, string(content), "xrootd.trace debug")
		viper.Reset()
	})

	t.Run("TestCacheXrootdIncorrectConfig", func(t *testing.T) {
		xrootd := xrootdTest{T: t}
		xrootd.setup()

		// Set our config
		viper.Set("Logging.Cache.Xrootd", "degub")

		// Generate the xrootd config
		configPath, err := ConfigXrootd(ctx, false)
		require.Error(t, err)
		assert.NotNil(t, configPath)
	})
}

func TestUpdateAuth(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	runDirname := t.TempDir()
	configDirname := t.TempDir()
	viper.Reset()
	server_utils.ResetOriginExports()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()
	viper.Set("Logging.Level", "Debug")
	viper.Set("Origin.RunLocation", runDirname)
	viper.Set("ConfigDir", configDirname)
	authfileName := filepath.Join(configDirname, "authfile")
	viper.Set("Xrootd.Authfile", authfileName)
	scitokensName := filepath.Join(configDirname, "scitokens.cfg")
	viper.Set("Xrootd.ScitokensConfig", scitokensName)
	viper.Set("Origin.FederationPrefix", "/test")
	viper.Set("Origin.StoragePrefix", "/")
	config.InitConfig()

	err := config.InitServer(ctx, config.OriginType)
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

	authfileFooter := "u * /.well-known lr\n"
	authfileDemo := "u testing /test3 lr\n"
	authfileDemo2 := `u testing /test4 lr`

	err = os.WriteFile(scitokensName, []byte(scitokensCfgDemo), fs.FileMode(0600))
	require.NoError(t, err)
	err = os.WriteFile(authfileName, []byte(authfileDemo), fs.FileMode(0600))
	require.NoError(t, err)

	server := &origin.OriginServer{}
	err = EmitScitokensConfig(server)
	require.NoError(t, err)

	err = EmitAuthfile(server)
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
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	runDirname := t.TempDir()
	configDirname := t.TempDir()
	viper.Reset()
	viper.Set("Logging.Level", "Debug")
	viper.Set("Origin.RunLocation", runDirname)
	viper.Set("ConfigDir", configDirname)
	config.InitConfig()

	// First, invoke CopyXrootdCertificates directly, ensure it works.
	err := CopyXrootdCertificates(&origin.OriginServer{})
	assert.ErrorIs(t, err, errBadKeyPair)

	err = config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	err = config.MkdirAll(path.Dir(param.Xrootd_Authfile.GetString()), 0755, -1, -1)
	require.NoError(t, err)
	err = CopyXrootdCertificates(&origin.OriginServer{})
	require.NoError(t, err)
	destKeyPairName := filepath.Join(param.Origin_RunLocation.GetString(), "copied-tls-creds.crt")
	assert.FileExists(t, destKeyPairName)

	keyPairContents, err := os.ReadFile(destKeyPairName)
	require.NoError(t, err)
	certName := param.Server_TLSCertificate.GetString()
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

	err = CopyXrootdCertificates(&origin.OriginServer{})
	assert.ErrorIs(t, err, errBadKeyPair)

	err = os.Rename(keyName, keyName+".orig")
	require.NoError(t, err)

	err = config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)

	err = CopyXrootdCertificates(&origin.OriginServer{})
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

func TestAuthIntervalUnmarshal(t *testing.T) {
	defer viper.Reset()
	t.Run("test-minutes-to-seconds", func(t *testing.T) {
		viper.Reset()
		var xrdConfig XrootdConfig
		viper.Set("Xrootd.AuthRefreshInterval", "5m")
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(combinedDecodeHookFunc()))
		assert.NoError(t, err)
		assert.Equal(t, 300, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-hours-to-seconds", func(t *testing.T) {
		viper.Reset()
		var xrdConfig XrootdConfig
		viper.Set("Xrootd.AuthRefreshInterval", "24h")
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(combinedDecodeHookFunc()))
		assert.NoError(t, err)
		assert.Equal(t, 86400, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-seconds-to-seconds", func(t *testing.T) {
		viper.Reset()
		var xrdConfig XrootdConfig
		viper.Set("Xrootd.AuthRefreshInterval", "100s")
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(combinedDecodeHookFunc()))
		assert.NoError(t, err)
		assert.Equal(t, 100, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-less-than-60s", func(t *testing.T) {
		viper.Reset()
		var xrdConfig XrootdConfig
		viper.Set("Xrootd.AuthRefreshInterval", "10")
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(combinedDecodeHookFunc()))
		assert.NoError(t, err)
		// Should fall back to 5m, or 300s
		assert.Equal(t, 300, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-no-suffix-to-seconds", func(t *testing.T) {
		viper.Reset()
		var xrdConfig XrootdConfig
		viper.Set("Xrootd.AuthRefreshInterval", "99")
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(combinedDecodeHookFunc()))
		assert.NoError(t, err)
		assert.Equal(t, 99, xrdConfig.Xrootd.AuthRefreshInterval)
	})

	t.Run("test-less-than-second", func(t *testing.T) {
		viper.Reset()
		var xrdConfig XrootdConfig
		viper.Set("Xrootd.AuthRefreshInterval", "0.5s")
		err := viper.Unmarshal(&xrdConfig, viper.DecodeHook(combinedDecodeHookFunc()))
		assert.NoError(t, err)
		assert.Equal(t, 300, xrdConfig.Xrootd.AuthRefreshInterval)
	})

}
