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
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestRegistration(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	// Use a temp os directory to better control the deletion of the directory.
	// Fixes issue on Windows where we are trying to delete a file in use so this
	// better waits for the file/process to be shut down before deletion
	tempConfigDir, err := os.MkdirTemp("", "test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempConfigDir)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	viper.Set("ConfigDir", tempConfigDir)
	keysDir := filepath.Join(tempConfigDir, "issuer-keys")
	viper.Set(param.IssuerKeysDirectory.GetName(), keysDir)

	viper.Set("Registry.DbLocation", filepath.Join(tempConfigDir, "test.sql"))
	err = config.InitServer(ctx, server_structs.OriginType)
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
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))

	// Test registration succeeds
	prefix := param.Origin_FederationPrefix.GetString()
	key, registerURL, isRegistered, err := registerNamespacePrep(ctx, prefix)
	require.NoError(t, err)
	assert.False(t, isRegistered)
	assert.Equal(t, registerURL, svr.URL+"/api/v1.0/registry")
	err = registerNamespaceImpl(key, prefix, "mock_site_name", registerURL)
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
	entries := []server_structs.Namespace{}
	err = json.Unmarshal(body, &entries)
	require.NoError(t, err)
	require.Equal(t, len(entries), 1)
	assert.Equal(t, entries[0].Prefix, "/test123")
	keySet, err := jwk.Parse([]byte(entries[0].Pubkey))
	require.NoError(t, err)
	registryKey, isPresent := keySet.LookupKeyID(keyId)
	assert.True(t, isPresent)
	assert.True(t, jwk.Equal(registryKey, key))
	assert.Equal(t, "mock_site_name", entries[0].AdminMetadata.SiteName)

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

	// Redo the namespace prep, ensure that isRegistered is true
	prefix = param.Origin_FederationPrefix.GetString()
	_, registerURL, isRegistered, err = registerNamespacePrep(ctx, prefix)
	assert.True(t, isRegistered)
	assert.Equal(t, svr.URL+"/api/v1.0/registry", registerURL)
	assert.NoError(t, err)
}

func TestMultiKeysRegistration(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	// Use a temp os directory to better control the deletion of the directory.
	// Fixes issue on Windows where we are trying to delete a file in use so this
	// better waits for the file/process to be shut down before deletion
	tempConfigDir, err := os.MkdirTemp("", "test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempConfigDir)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	viper.Set("ConfigDir", tempConfigDir)
	keysDir := filepath.Join(tempConfigDir, "issuer-keys")
	viper.Set(param.IssuerKeysDirectory.GetName(), keysDir)

	viper.Set("Registry.DbLocation", filepath.Join(tempConfigDir, "test.sql"))
	err = config.InitServer(ctx, server_structs.OriginType)
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
	keysMap := config.GetIssuerPrivateKeys()
	require.Equal(t, 1, len(keysMap))

	// Get the key name (so we can delete it later)
	dirEntries, err := os.ReadDir(keysDir)
	require.NoError(t, err)
	require.Equal(t, 1, len(dirEntries))

	// Create a new issuer key and rotate out the old one
	secondKey, err := config.GeneratePEM(keysDir)
	require.NoError(t, err)
	require.NotEqual(t, privKey.KeyID(), secondKey.KeyID())
	keysChange, err := config.RefreshKeys()
	require.True(t, keysChange)
	require.NoError(t, err)
	secondPubKey, err := secondKey.PublicKey()
	require.NoError(t, err)
	activeKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	// Note: late in the development of this work, we switched to
	// having GetIssuerPrivateJWK return the oldest active key
	require.Equal(t, privKey, activeKey)
	keysMap = config.GetIssuerPrivateKeys()
	require.Equal(t, secondKey, keysMap[secondKey.KeyID()])
	require.Equal(t, privKey, keysMap[key.KeyID()])
	require.Equal(t, 2, len(keysMap))
	secondKeyId := secondKey.KeyID()
	require.NotEmpty(t, keyId)

	//Configure registry
	registry.RegisterRegistryAPI(engine.Group("/"))

	//Create a test HTTP server that sends requests to gin
	svr := httptest.NewServer(engine)
	defer svr.CloseClientConnections()
	defer svr.Close()

	viper.Set("Federation.RegistryUrl", svr.URL)
	viper.Set("Origin.FederationPrefix", "/test123")

	// Remove the original key, forcing us to register with the new one
	require.NoError(t, os.Remove(filepath.Join(keysDir, dirEntries[0].Name())))

	// Re-run the InitServer to reflect the new RegistryUrl set above
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))

	// Test registration succeeds
	prefix := param.Origin_FederationPrefix.GetString()
	key, registerURL, isRegistered, err := registerNamespacePrep(ctx, prefix)
	require.NoError(t, err)
	assert.False(t, isRegistered)
	assert.Equal(t, registerURL, svr.URL+"/api/v1.0/registry")
	err = registerNamespaceImpl(key, prefix, "mock_site_name", registerURL)
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
	entries := []server_structs.Namespace{}
	err = json.Unmarshal(body, &entries)
	require.NoError(t, err)
	require.Equal(t, len(entries), 1)
	assert.Equal(t, entries[0].Prefix, "/test123")
	keySet, err := jwk.Parse([]byte(entries[0].Pubkey))
	require.NoError(t, err)
	registryKey, isPresent := keySet.LookupKeyID(secondKeyId)
	require.True(t, isPresent)
	assert.True(t, jwk.Equal(registryKey, secondPubKey))
	assert.Equal(t, "mock_site_name", entries[0].AdminMetadata.SiteName)

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

	// Verify that no key is registered for an alternate prefix
	keyStatus, err = keyIsRegistered(key, svr.URL, "test456")
	assert.NoError(t, err)
	assert.Equal(t, keyStatus, noKeyPresent)

	// Redo the namespace prep, ensure that isRegistered is true
	prefix = param.Origin_FederationPrefix.GetString()
	_, registerURL, isRegistered, err = registerNamespacePrep(ctx, prefix)
	require.NoError(t, err)
	assert.True(t, isRegistered)
	assert.Equal(t, svr.URL+"/api/v1.0/registry", registerURL)
}
