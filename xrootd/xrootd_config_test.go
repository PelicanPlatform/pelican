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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/sirupsen/logrus"
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

	LaunchXrootdMaintenance(ctx, 2*time.Hour)

	// Helper function to wait for a copy of the first cert to show up
	// in the destination
	waitForCopy := func() bool {
		for idx := 0; idx < 10; idx++ {
			time.Sleep(50 * time.Millisecond)
			logrus.Debug("Re-reading destination cert")
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
	logrus.Debug("Will wait to see if the new certs are not copied")
	assert.False(t, waitForCopy())

	// Now, if we overwrite the key, the maintenance thread should notice
	// and overwrite the destination
	err = os.Rename(keyName+".orig", keyName)
	require.NoError(t, err)
	logrus.Debug("Will wait to see if the new certs are copied")
	assert.True(t, waitForCopy())

}
