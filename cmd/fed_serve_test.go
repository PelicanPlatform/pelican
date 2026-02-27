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

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestFedServePosixOrigin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()
	defer director.ResetState()

	server_utils.ResetTestState()

	defer server_utils.ResetTestState()

	modules := server_structs.ServerType(0)
	modules.Set(server_structs.OriginType)
	modules.Set(server_structs.DirectorType)
	modules.Set(server_structs.RegistryType)

	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	// Note: on Mac OS X, this runs extremely close to the path limits as the admin path has a
	// Unix socket in it.  Shortening as much as possible.
	tmpPathPattern := "XrdOrigin*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	// Need to set permissions or the xrootd process we spawn won't be able to write PID/UID files
	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	require.NoError(t, param.Set("ConfigDir", tmpPath))
	// Set RuntimeDir to avoid race conditions with parallel tests using shared /run/pelican
	require.NoError(t, param.Set(param.RuntimeDir.GetName(), tmpPath))
	require.NoError(t, param.Set("Origin.RunLocation", filepath.Join(tmpPath, "xrd")))
	t.Cleanup(func() {
		if err := os.RemoveAll(tmpPath); err != nil {
			t.Fatal("Failed to clean up temp path")
		}
	})

	// Increase the log level; otherwise, its difficult to debug failures
	require.NoError(t, param.Set("Logging.Level", "Debug"))

	require.NoError(t, param.Set("Origin.StoragePrefix", test_utils.GetTmpStoragePrefixDir(t)))
	require.NoError(t, param.Set("Origin.FederationPrefix", "/test"))
	require.NoError(t, param.Set("Origin.StorageType", "posix"))
	require.NoError(t, param.Set("Origin.Port", 0))
	require.NoError(t, param.Set("Server.WebPort", 0))

	// Disable functionality we're not using (and is difficult to make work on Mac)
	require.NoError(t, param.Set("Origin.EnableCmsd", false))
	require.NoError(t, param.Set("Origin.EnableMacaroons", false))
	require.NoError(t, param.Set("Origin.EnableVoms", false))
	require.NoError(t, param.Set("TLSSkipVerify", true))
	require.NoError(t, param.Set("Server.EnableUI", false))
	require.NoError(t, param.Set(param.Server_DbLocation.GetName(), filepath.Join(t.TempDir(), "ns-registry.sqlite")))
	require.NoError(t, param.Set("Registry.RequireOriginApproval", false))
	require.NoError(t, param.Set("Registry.RequireCacheApproval", false))
	require.NoError(t, param.Set("Director.DbLocation", filepath.Join(t.TempDir(), "director.sqlite")))
	require.NoError(t, param.Set(param.Origin_DbLocation.GetName(), filepath.Join(t.TempDir(), "origin.sqlite")))
	require.NoError(t, param.Set(param.Cache_DbLocation.GetName(), filepath.Join(t.TempDir(), "cache.sqlite")))
	// Set up OIDC client configuration for registry OAuth functionality
	oidcClientIDFile := filepath.Join(tmpPath, "oidc-client-id")
	oidcClientSecretFile := filepath.Join(tmpPath, "oidc-client-secret")
	require.NoError(t, os.WriteFile(oidcClientIDFile, []byte("test-client-id"), 0644))
	require.NoError(t, os.WriteFile(oidcClientSecretFile, []byte("test-client-secret"), 0644))
	require.NoError(t, param.Set(param.OIDC_ClientIDFile.GetName(), oidcClientIDFile))
	require.NoError(t, param.Set(param.OIDC_ClientSecretFile.GetName(), oidcClientSecretFile))

	defer cancel()

	_, fedCancel, err := launchers.LaunchModules(ctx, modules)

	defer fedCancel()
	if err != nil {
		log.Errorln("Failure in fedServeInternal:", err)
		require.NoError(t, err)
	}

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/.well-known/openid-configuration"
	err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200, false)
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
