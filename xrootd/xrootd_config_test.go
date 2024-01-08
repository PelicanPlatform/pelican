//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXrootDOriginConfig(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirname := t.TempDir()
	viper.Reset()
	viper.Set("Xrootd.RunLocation", dirname)
	configPath, err := ConfigXrootd(ctx, true)
	require.NoError(t, err)
	assert.NotNil(t, configPath)
}

func TestXrootDCacheConfig(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirname := t.TempDir()
	viper.Reset()
	viper.Set("Xrootd.RunLocation", dirname)
	configPath, err := ConfigXrootd(ctx, false)
	require.NoError(t, err)
	assert.NotNil(t, configPath)
}

func TestUpdateAuth(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	runDirname := t.TempDir()
	configDirname := t.TempDir()
	viper.Reset()
	viper.Set("Logging.Level", "Debug")
	viper.Set("Xrootd.RunLocation", runDirname)
	viper.Set("ConfigDir", configDirname)
	authfileName := filepath.Join(configDirname, "authfile")
	viper.Set("Xrootd.Authfile", authfileName)
	scitokensName := filepath.Join(configDirname, "scitokens.cfg")
	viper.Set("Xrootd.ScitokensConfig", scitokensName)
	viper.Set("Origin.NamespacePrefix", "/test")
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

	server := &origin_ui.OriginServer{}
	err = EmitScitokensConfig(server)
	require.NoError(t, err)

	err = EmitAuthfile(server)
	require.NoError(t, err)

	destScitokensName := filepath.Join(param.Xrootd_RunLocation.GetString(), "scitokens-origin-generated.cfg")
	assert.FileExists(t, destScitokensName)
	destAuthfileName := filepath.Join(param.Xrootd_RunLocation.GetString(), "authfile-origin-generated")
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
	viper.Set("Xrootd.RunLocation", runDirname)
	viper.Set("ConfigDir", configDirname)
	config.InitConfig()

	// First, invoke CopyXrootdCertificates directly, ensure it works.
	err := CopyXrootdCertificates()
	assert.ErrorIs(t, err, errBadKeyPair)

	err = config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	err = config.MkdirAll(path.Dir(param.Xrootd_Authfile.GetString()), 0755, -1, -1)
	require.NoError(t, err)
	err = CopyXrootdCertificates()
	require.NoError(t, err)
	destKeyPairName := filepath.Join(param.Xrootd_RunLocation.GetString(), "copied-tls-creds.crt")
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

	err = CopyXrootdCertificates()
	assert.ErrorIs(t, err, errBadKeyPair)

	err = os.Rename(keyName, keyName+".orig")
	require.NoError(t, err)

	err = config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)

	err = CopyXrootdCertificates()
	require.NoError(t, err)

	secondKeyPairContents, err := os.ReadFile(destKeyPairName)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(firstKeyPairContents, secondKeyPairContents))

	originServer := &origin_ui.OriginServer{}
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
