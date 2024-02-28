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

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFedServePosixOrigin(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()

	modules := config.ServerType(0)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)

	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	tmpPathPattern := "XRootD-Test_Origin*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	// Need to set permissions or the xrootd process we spawn won't be able to write PID/UID files
	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	viper.Set("ConfigDir", tmpPath)
	viper.Set("Origin.RunLocation", filepath.Join(tmpPath, "xrootd"))
	t.Cleanup(func() {
		if err := os.RemoveAll(tmpPath); err != nil {
			t.Fatal("Failed to clean up temp path")
		}
	})

	// Increase the log level; otherwise, its difficult to debug failures
	viper.Set("Logging.Level", "Debug")
	config.InitConfig()

	viper.Set("Origin.ExportVolume", t.TempDir()+":/test")
	viper.Set("Origin.Mode", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(t.TempDir(), "ns-registry.sqlite"))
	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)
	defer cancel()

	fedCancel, err := launchers.LaunchModules(ctx, modules)

	defer fedCancel()
	if err != nil {
		log.Errorln("Failure in fedServeInternal:", err)
		require.NoError(t, err)
	}

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/.well-known/openid-configuration"
	err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200)
	require.NoError(t, err)

	httpc := http.Client{
		Transport: config.GetTransport(),
	}
	resp, err := httpc.Get(desiredURL)
	require.NoError(t, err)

	assert.Equal(t, resp.StatusCode, http.StatusOK)

	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	expectedResponse := struct {
		JwksUri string `json:"jwks_uri"`
	}{}
	err = json.Unmarshal(responseBody, &expectedResponse)
	require.NoError(t, err)

	assert.NotEmpty(t, expectedResponse.JwksUri)

	cancel()
	fedCancel()
	assert.NoError(t, egrp.Wait())
}
