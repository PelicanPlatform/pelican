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

package launcher_utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pelicanplatform/pelican/test_utils"
)

type (
	namespaceEntry struct {
		ID            int    `json:"ID"`
		Prefix        string `json:"Prefix"`
		Pubkey        string `json:"Pubkey"`
		Identity      string `json:"Identity"`
		AdminMetadata string `json:"AdminMetadata"`
	}
)

func TestRegistration(t *testing.T) {
	// Use a temp os directory to better control the deletion of the directory.
	// Fixes issue on Windows where we are trying to delete a file in use so this
	// better waits for the file/process to be shut down before deletion
	tempConfigDir, err := os.MkdirTemp("", "test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempConfigDir)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	viper.Set("ConfigDir", tempConfigDir)

	config.InitConfig()
	viper.Set("Registry.DbLocation", filepath.Join(tempConfigDir, "test.sql"))
	err = config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)

	err = registry.InitializeDB()
	require.NoError(t, err)
	defer func() {
		err := registry.ShutdownRegistryDB()
		assert.NoError(t, err)
	}()

	gin.SetMode(gin.TestMode)
	engine := gin.Default()

	// Ensure we have a issuer key
	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	key, err := privKey.PublicKey()
	require.NoError(t, err)
	assert.NoError(t, jwk.AssignKeyID(key))
	keyId := key.KeyID()
	require.NotEmpty(t, keyId)

	//Configure registry
	registry.RegisterRegistryAPI(engine.Group("/"))

	//Create a test HTTP server that sends requests to gin
	svr := httptest.NewServer(engine)
	defer svr.CloseClientConnections()
	defer svr.Close()

	viper.Set("Federation.RegistryUrl", svr.URL)
	viper.Set("Origin.FederationPrefix", "/test123")

	// Re-run the InitServer to reflect the new RegistryUrl set above
	require.NoError(t, config.InitServer(ctx, config.OriginType))

	// Test registration succeeds
	prefix := param.Origin_FederationPrefix.GetString()
	key, registerURL, isRegistered, err := registerNamespacePrep(ctx, prefix)
	require.NoError(t, err)
	assert.False(t, isRegistered)
	assert.Equal(t, registerURL, svr.URL+"/api/v1.0/registry")
	err = registerNamespaceImpl(key, prefix, registerURL)
	require.NoError(t, err)

	// Test we can query for the new key
	req, err := http.NewRequest("GET", svr.URL+"/api/v1.0/registry", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	// Test new key is the same one we registered.
	entries := []namespaceEntry{}
	err = json.Unmarshal(body, &entries)
	require.NoError(t, err)
	require.Equal(t, len(entries), 1)
	assert.Equal(t, entries[0].Prefix, "/test123")
	keySet, err := jwk.Parse([]byte(entries[0].Pubkey))
	require.NoError(t, err)
	registryKey, isPresent := keySet.LookupKeyID(keyId)
	assert.True(t, isPresent)
	assert.True(t, jwk.Equal(registryKey, key))

	// Test the functionality of the keyIsRegistered function
	keyStatus, err := keyIsRegistered(key, svr.URL+"/api/v1.0/registry", "/test123")
	assert.NoError(t, err)
	require.Equal(t, keyStatus, keyMatch)

	// Generate a new key, test we get mismatch
	privKeyAltRaw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privKeyAlt, err := jwk.FromRaw(privKeyAltRaw)
	require.NoError(t, err)
	keyAlt, err := privKeyAlt.PublicKey()
	require.NoError(t, err)
	assert.NoError(t, jwk.AssignKeyID(keyAlt))
	keyStatus, err = keyIsRegistered(keyAlt, svr.URL+"/api/v1.0/registry", "/test123")
	assert.NoError(t, err)
	assert.Equal(t, keyStatus, keyMismatch)

	// Verify that no key is present for an alternate prefix
	keyStatus, err = keyIsRegistered(key, svr.URL, "test456")
	assert.NoError(t, err)
	assert.Equal(t, keyStatus, noKeyPresent)

	// Redo the namespace prep, ensure that isPresent is true
	prefix = param.Origin_FederationPrefix.GetString()
	_, registerURL, isRegistered, err = registerNamespacePrep(ctx, prefix)
	assert.Equal(t, svr.URL+"/api/v1.0/registry", registerURL)
	assert.NoError(t, err)
	assert.True(t, isRegistered)
}
