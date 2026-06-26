/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestRegistration(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	// Use a temp os directory to better control the deletion of the directory.
	// Fixes issue on Windows where we are trying to delete a file in use so this
	// better waits for the file/process to be shut down before deletion
	tempConfigDir, err := os.MkdirTemp("", "test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tempConfigDir)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	require.NoError(t, param.ConfigBase.Set(tempConfigDir))
	keysDir := filepath.Join(tempConfigDir, "issuer-keys")
	require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))

	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, param.Registry_DbLocation.Set(""))
	require.NoError(t, param.Server_DbLocation.Set(filepath.Join(tempConfigDir, "test.sql")))
	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	err = database.InitServerDatabase(server_structs.RegistryType)
	require.NoError(t, err)

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

	require.NoError(t, param.Set(param.Federation_RegistryUrl, svr.URL))
	require.NoError(t, param.Origin_FederationPrefix.Set("/test123"))

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
	entries := []server_structs.Registration{}
	err = json.Unmarshal(body, &entries)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
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
	t.Cleanup(test_utils.SetupTestLogging(t))
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
	require.NoError(t, param.ConfigBase.Set(tempConfigDir))

	// MockFederationRoot must be called before setting IssuerKeysDirectory because that
	// function overrides the IssuerKeysDirectory value if not already set. Since we don't
	// rely on the federation keys in this test, it's easier to work around the issue than
	// generate distinct keys for it.
	test_utils.MockFederationRoot(t, nil, nil)

	keysDir := filepath.Join(tempConfigDir, "issuer-keys")
	require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))

	require.NoError(t, param.Registry_DbLocation.Set(""))
	require.NoError(t, param.Server_DbLocation.Set(filepath.Join(tempConfigDir, "test.sql")))
	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	err = database.InitServerDatabase(server_structs.RegistryType)
	require.NoError(t, err)

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

	require.NoError(t, param.Set(param.Federation_RegistryUrl, svr.URL))
	require.NoError(t, param.Origin_FederationPrefix.Set("/test123"))

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
	entries := []server_structs.Registration{}
	err = json.Unmarshal(body, &entries)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
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

// TestRegistrationOldKeyStillInKeyset verifies that when a namespace was registered
// under a key that is still present in the issuer keyset but is no longer the active
// (lexicographically-first) key, registerNamespacePrep treats the namespace as
// already registered instead of failing with "already registered under a different key".
func TestRegistrationOldKeyStillInKeyset(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	tempConfigDir, err := os.MkdirTemp("", "test")
	require.NoError(t, err)
	defer os.RemoveAll(tempConfigDir)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	require.NoError(t, param.ConfigDir.Set(tempConfigDir))

	// MockFederationRoot must be called before setting IssuerKeysDirectory because that
	// function overrides the IssuerKeysDirectory value if not already set.
	test_utils.MockFederationRoot(t, nil, nil)

	keysDir := filepath.Join(tempConfigDir, "issuer-keys")
	require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))

	require.NoError(t, param.Registry_DbLocation.Set(""))
	require.NoError(t, param.Server_DbLocation.Set(filepath.Join(tempConfigDir, "test.sql")))
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))
	require.NoError(t, database.InitServerDatabase(server_structs.RegistryType))

	gin.SetMode(gin.TestMode)
	engine := gin.Default()
	registry.RegisterRegistryAPI(engine.Group("/"))
	svr := httptest.NewServer(engine)
	defer svr.CloseClientConnections()
	defer svr.Close()

	require.NoError(t, param.Set(param.Federation_RegistryUrl, svr.URL))
	require.NoError(t, param.Origin_FederationPrefix.Set("/test123"))
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))

	prefix := param.Origin_FederationPrefix.GetString()

	// Register the namespace under the origin's current (and only) issuer key.
	oldKey, registerURL, isRegistered, err := registerNamespacePrep(ctx, prefix)
	require.NoError(t, err)
	require.False(t, isRegistered)
	require.NoError(t, registerNamespaceImpl(oldKey, prefix, "mock_site_name", registerURL))

	// Add a new key whose filename sorts before the original so it becomes the active
	// key, while keeping the original (registered) key in the keyset.
	newKeyPath := filepath.Join(keysDir, "00_active.pem")
	require.NoError(t, config.GeneratePrivateKey(newKeyPath, elliptic.P256(), false))
	keysChange, err := config.RefreshKeys()
	require.NoError(t, err)
	require.True(t, keysChange)

	// The active key should now differ from the key the namespace was registered under,
	// and both keys should be present in the keyset.
	activeKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	require.NotEqual(t, oldKey.KeyID(), activeKey.KeyID())
	require.Equal(t, 2, len(config.GetIssuerPrivateKeys()))

	// The active key alone does NOT match the registry entry...
	status, err := keyIsRegistered(activeKey, registerURL, prefix)
	require.NoError(t, err)
	require.Equal(t, keyMismatch, status)

	// ...but registerNamespacePrep must still recognize the namespace as ours because
	// the old key remains in the keyset. Before the keyset-wide check this returned a
	// "registered under a different key" error.
	_, _, isRegistered, err = registerNamespacePrep(ctx, prefix)
	require.NoError(t, err)
	require.True(t, isRegistered)
}

// fetchRegistryKids returns the sorted key IDs the registry has recorded for a prefix.
func fetchRegistryKids(t *testing.T, registryUrl, prefix string) []string {
	t.Helper()
	req, err := http.NewRequest("GET", registryUrl+"/api/v1.0/registry", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: config.GetTransport()}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	entries := []server_structs.Registration{}
	require.NoError(t, json.Unmarshal(body, &entries))
	kids := []string{}
	for _, e := range entries {
		if e.Prefix != prefix {
			continue
		}
		keySet, err := jwk.Parse([]byte(e.Pubkey))
		require.NoError(t, err)
		for i := 0; i < keySet.Len(); i++ {
			k, ok := keySet.Key(i)
			require.True(t, ok)
			kids = append(kids, k.KeyID())
		}
	}
	sort.Strings(kids)
	return kids
}

// TestReconcileKeysWhenAlreadyRegistered verifies that when an origin restarts with an
// extra issuer key that was dropped into the issuer-keys directory while it was down, the
// already-registered startup path reconciles the registry so it records the full keyset.
// It also covers the case where the newly-added key is the active (signing) key while the
// already-registered key is only a secondary key in the set.
func TestReconcileKeysWhenAlreadyRegistered(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	tempConfigDir, err := os.MkdirTemp("", "test")
	require.NoError(t, err)
	defer os.RemoveAll(tempConfigDir)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	require.NoError(t, param.ConfigDir.Set(tempConfigDir))

	// MockFederationRoot must be called before setting IssuerKeysDirectory because that
	// function overrides the IssuerKeysDirectory value if not already set.
	test_utils.MockFederationRoot(t, nil, nil)

	keysDir := filepath.Join(tempConfigDir, "issuer-keys")
	require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))

	require.NoError(t, param.Registry_DbLocation.Set(""))
	require.NoError(t, param.Server_DbLocation.Set(filepath.Join(tempConfigDir, "test.sql")))
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))
	require.NoError(t, database.InitServerDatabase(server_structs.RegistryType))

	gin.SetMode(gin.TestMode)
	engine := gin.Default()
	registry.RegisterRegistryAPI(engine.Group("/"))
	svr := httptest.NewServer(engine)
	defer svr.CloseClientConnections()
	defer svr.Close()

	require.NoError(t, param.Set(param.Federation_RegistryUrl, svr.URL))
	require.NoError(t, param.Origin_FederationPrefix.Set("/test123"))
	require.NoError(t, param.Xrootd_Sitename.Set("mock_site_name"))
	require.NoError(t, config.InitServer(ctx, server_structs.OriginType))

	prefix := param.Origin_FederationPrefix.GetString()

	// Register the namespace under the origin's initial (and only) issuer key.
	firstKey, registerURL, isRegistered, err := registerNamespacePrep(ctx, prefix)
	require.NoError(t, err)
	require.False(t, isRegistered)
	require.NoError(t, registerNamespaceImpl(firstKey, prefix, "mock_site_name", registerURL))
	registeredKid := firstKey.KeyID()

	// The registry should currently hold exactly the first key.
	require.Equal(t, []string{registeredKid}, fetchRegistryKids(t, svr.URL, prefix))

	// Simulate a new key dropped into the issuer-keys directory while the origin was down.
	// The "00_" filename sorts first, so it becomes the active/signing key, while the
	// already-registered key becomes a secondary key in the set.
	newKeyPath := filepath.Join(keysDir, "00_active.pem")
	require.NoError(t, config.GeneratePrivateKey(newKeyPath, elliptic.P256(), false))
	keysChange, err := config.RefreshKeys()
	require.NoError(t, err)
	require.True(t, keysChange)
	newKey, err := config.LoadSinglePEM(newKeyPath)
	require.NoError(t, err)
	newKid := newKey.KeyID()

	// The active key is now the new (unregistered) key.
	activeKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	require.Equal(t, newKid, activeKey.KeyID())
	require.NotEqual(t, registeredKid, newKid)

	// "Restart": the namespace is already registered (under firstKey), so the all-keys
	// initial registration is skipped -- the reconcile must push the full keyset instead.
	require.NoError(t, RegisterNamespaceWithRetry(ctx, egrp, prefix))

	// The registry should now record BOTH keys.
	expected := []string{registeredKid, newKid}
	sort.Strings(expected)
	require.Equal(t, expected, fetchRegistryKids(t, svr.URL, prefix))
}
