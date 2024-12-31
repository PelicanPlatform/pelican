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

package registry

import (
	"context"
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
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func registryMockup(ctx context.Context, t *testing.T, testName string) *httptest.Server {
	tDir := t.TempDir()
	issuerTempDir := filepath.Join(tDir, testName)

	ikeyDir := filepath.Join(issuerTempDir, "issuer-keys")
	viper.Set("IssuerKeysDirectory", ikeyDir)
	viper.Set("Registry.DbLocation", filepath.Join(issuerTempDir, "test.sql"))
	viper.Set("Server.WebPort", 8444)
	viper.Set("ConfigDir", tDir)
	config.InitConfig()

	err := config.InitServer(ctx, server_structs.RegistryType)
	require.NoError(t, err)

	setupMockRegistryDB(t)

	gin.SetMode(gin.TestMode)
	engine := gin.Default()

	//Configure registry
	RegisterRegistryAPI(engine.Group("/"))

	//Set up a server to use for testing
	svr := httptest.NewServer(engine)
	viper.Set("Federation.RegistryUrl", svr.URL)
	return svr
}

func getSortedKids(ctx context.Context, jsonStr string) ([]string, error) {
	set, err := jwk.Parse([]byte(jsonStr))
	if err != nil {
		return nil, err
	}
	var kids []string
	keysIter := set.Keys(ctx)
	for keysIter.Next(ctx) {
		key := keysIter.Pair().Value.(jwk.Key)

		kid, ok := key.Get("kid")
		if !ok {
			continue
		}
		kids = append(kids, kid.(string))
	}
	sort.Strings(kids)

	return kids, nil
}

func TestServeNamespaceRegistry(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		func() { require.NoError(t, egrp.Wait()) }()
		cancel()
		config.ResetIssuerJWKPtr()
		config.ResetIssuerPrivateKeys()
		server_utils.ResetTestState()
	})
	server_utils.ResetTestState()

	svr := registryMockup(ctx, t, "serveregistry")
	defer func() {
		err := ShutdownRegistryDB()
		assert.NoError(t, err)
		svr.CloseClientConnections()
		svr.Close()
	}()

	_, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	//Test functionality of registering a namespace (without identity)
	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo/bar", "mock_site_name")
	require.NoError(t, err)
	var privKey2 jwk.Key

	//Test we can list the namespace without an error
	t.Run("Test namespace list", func(t *testing.T) {
		//Set up a buffer to capture stdout
		var stdoutCapture string
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		//List the namespaces
		err = NamespaceList(svr.URL + "/api/v1.0/registry")
		require.NoError(t, err)
		w.Close()
		os.Stdout = oldStdout

		capturedOutput := make([]byte, 1024)
		n, _ := r.Read(capturedOutput)
		stdoutCapture = string(capturedOutput[:n])
		assert.Contains(t, stdoutCapture, `"prefix":"/foo/bar"`)
	})

	t.Run("Test register namespace with sitename", func(t *testing.T) {
		res, err := http.Get(svr.URL + "/api/v1.0/registry/foo/bar")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
		data, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		ns := server_structs.Namespace{}
		err = json.Unmarshal(data, &ns)
		require.NoError(t, err)
		assert.Equal(t, ns.AdminMetadata.SiteName, "mock_site_name")
	})

	t.Run("test-registered-namespace-pubkey-update-with-new-active-key", func(t *testing.T) {
		activeKey, err := config.GetIssuerPrivateJWK()
		require.NoError(t, err)
		require.Equal(t, privKey.KeyID(), activeKey.KeyID())

		// Imitate LaunchIssuerKeysDirRefresh function
		config.UpdatePreviousIssuerPrivateJWK()
		_, err = config.GeneratePEM(param.IssuerKeysDirectory.GetString())
		require.NoError(t, err)
		privKey2, err = config.LoadIssuerPrivateKey(param.IssuerKeysDirectory.GetString())
		require.NoError(t, err)
		err = NamespacesPubKeyUpdate(privKey2, []string{"/foo/bar"}, "mock_site_name", svr.URL+"/api/v1.0/registry/updateNamespacesPubKey")
		require.NoError(t, err)
	})

	t.Run("test-registered-namespace-pubkey-update-with-nonsense-key", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "in_the_middle_of_nowhere")
		privKey3, err := config.GeneratePEM(tempDir)
		require.NoError(t, err)
		err = NamespacesPubKeyUpdate(privKey3, []string{"/foo/bar"}, "mock_site_name", svr.URL+"/api/v1.0/registry/updateNamespacesPubKey")
		require.ErrorContains(t, err, "it doesn't contain any public key matching the existing namespace's public key in db")
	})

	t.Run("test-registered-namespace-pubkey-update-with-imposter-key", func(t *testing.T) {
		privKey4, err := config.GeneratePEMandSetActiveKey(param.IssuerKeysDirectory.GetString())
		require.NoError(t, err)
		config.UpdatePreviousIssuerPrivateJWK()
		// Both active key and previous key are set to privKey4
		err = NamespacesPubKeyUpdate(privKey4, []string{"/foo/bar"}, "mock_site_name", svr.URL+"/api/v1.0/registry/updateNamespacesPubKey")
		require.ErrorContains(t, err, "it fails to pass the proof of possession verification")

		// Revert the active key changes happened in this subtest
		config.SetActiveKey(privKey)
		config.UpdatePreviousIssuerPrivateJWK()
		config.SetActiveKey(privKey2)
	})

	t.Run("Test namespace delete", func(t *testing.T) {
		//Test functionality of namespace delete
		err = NamespaceDelete(svr.URL+"/api/v1.0/registry/foo/bar", "/foo/bar")
		require.NoError(t, err)
		var stdoutCapture string
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		err = NamespaceGet(svr.URL + "/api/v1.0/registry")
		require.NoError(t, err)
		w.Close()
		os.Stdout = oldStdout

		capturedOutput := make([]byte, 1024)
		n, _ := r.Read(capturedOutput)
		stdoutCapture = string(capturedOutput[:n])
		assert.Equal(t, "[]\n", stdoutCapture)
	})
	server_utils.ResetTestState()
}

func TestMultiPubKeysRegisteredOnNamespace(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	server_utils.ResetTestState()
	t.Cleanup(func() {
		func() { require.NoError(t, egrp.Wait()) }()
		cancel()
		config.ResetIssuerJWKPtr()
		config.ResetIssuerPrivateKeys()
		server_utils.ResetTestState()
	})

	tDir := t.TempDir()

	svr := registryMockup(ctx, t, "serveregistry")
	defer func() {
		err := ShutdownRegistryDB()
		assert.NoError(t, err)
		svr.CloseClientConnections()
		svr.Close()
	}()

	config.ResetIssuerJWKPtr()
	config.ResetIssuerPrivateKeys()
	privKeys := config.GetIssuerPrivateKeys()
	require.Len(t, privKeys, 0)

	// Construct a client that has [p1,p2,p3] and p3 is the active private key
	privKey1, err := config.GeneratePEMandSetActiveKey(param.IssuerKeysDirectory.GetString())
	require.NotEmpty(t, privKey1)
	require.NoError(t, err)
	privKey2, err := config.GeneratePEMandSetActiveKey(param.IssuerKeysDirectory.GetString())
	require.NoError(t, err)

	prefix := "/mascot/bucky"
	err = NamespaceRegister(privKey2, svr.URL+"/api/v1.0/registry", "", prefix, "mock_site_name")
	require.NoError(t, err)

	config.UpdatePreviousIssuerPrivateJWK()
	privKey3, err := config.GeneratePEMandSetActiveKey(param.IssuerKeysDirectory.GetString())
	require.NoError(t, err)

	// Construct a public keys JWKS [p2,p4] to save in registry DB, imitating admin manually adding p4
	registryDbJwks := jwk.NewSet()
	pubKey2, err := jwk.PublicKeyOf(privKey2)
	require.NoError(t, err)
	err = registryDbJwks.AddKey(pubKey2)
	require.NoError(t, err)
	privKey4, err := config.GeneratePEM(filepath.Join(tDir, "elsewhere"))
	require.NoError(t, err)
	pubKey4, err := jwk.PublicKeyOf(privKey4)
	require.NoError(t, err)
	err = registryDbJwks.AddKey(pubKey4)
	require.NoError(t, err)
	jwksBytes, err := json.Marshal(registryDbJwks)
	require.NoError(t, err)
	jwksStr := string(jwksBytes)

	// Test functionality of a namespace registered with multi public keys [p2,p4]
	err = setNamespacePubKey(prefix, jwksStr) // set the registered public keys to [p2,p4]
	require.NoError(t, err)
	ns, err := getNamespaceByPrefix(prefix)
	require.NoError(t, err)
	require.Equal(t, jwksStr, ns.Pubkey)

	prevKey := config.GetPreviousIssuerPrivateJWK()
	require.Equal(t, privKey2.KeyID(), prevKey.KeyID())
	privKeys = config.GetIssuerPrivateKeys()
	require.Len(t, privKeys, 3)

	// Client allKeys:[p1,p2,p3] prevKey:p2 activeKey:p3 ---UPDATE--> Registry [p2,p4]
	// => should update Registry to [p3,p4] (rotate out prevKey:p2, rotate in activeKey:p3)
	err = NamespacesPubKeyUpdate(privKey3, []string{prefix}, "mock_site_name", svr.URL+"/api/v1.0/registry/updateNamespacesPubKey")
	require.NoError(t, err)
	ns, err = getNamespaceByPrefix(prefix)
	require.NoError(t, err)

	expectedJwks := jwk.NewSet()
	pubKey3, err := jwk.PublicKeyOf(privKey3)
	require.NoError(t, err)
	err = expectedJwks.AddKey(pubKey3)
	require.NoError(t, err)
	err = expectedJwks.AddKey(pubKey4)
	require.NoError(t, err)
	expectedJwksBytes, err := json.Marshal(expectedJwks)
	require.NoError(t, err)
	expectedJwksStr := string(expectedJwksBytes)

	expectedKids, err := getSortedKids(ctx, expectedJwksStr)
	require.NoError(t, err)
	actualKids, err := getSortedKids(ctx, ns.Pubkey)
	require.NoError(t, err)
	require.Equal(t, expectedKids, actualKids)
}

func TestRegistryKeyChainingOSDF(t *testing.T) {
	server_utils.ResetTestState()

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, egrp.Wait())
		server_utils.ResetTestState()
	})

	_, err := config.SetPreferredPrefix(config.OsdfPrefix)
	assert.NoError(t, err)

	// On by default, but just to make things explicit
	viper.Set("Registry.RequireKeyChaining", true)

	registrySvr := registryMockup(ctx, t, "OSDFkeychaining")
	topoSvr := topologyMockup(t, []string{"/topo/foo"})
	viper.Set("Federation.TopologyNamespaceURL", topoSvr.URL)
	err = migrateTopologyTestTable()
	require.NoError(t, err)
	err = PopulateTopology(ctx)
	require.NoError(t, err)

	defer func() {
		err := ShutdownRegistryDB()
		assert.NoError(t, err)
		registrySvr.CloseClientConnections()
		registrySvr.Close()
		topoSvr.CloseClientConnections()
		topoSvr.Close()
	}()

	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)

	// Start by registering /foo/bar with the default key
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar", "")
	require.NoError(t, err)

	// Perform one test with a subspace and the same key -- should succeed
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/test", "")
	require.NoError(t, err)

	// If the namespace is a subspace from the topology and is registered without the identity
	// we deny it
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/topo/foo/bar", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "A superspace or subspace of this namespace /topo/foo/bar already exists in the OSDF topology: /topo/foo. To register a Pelican equivalence, you need to present your identity.")

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/topo/foo", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "A superspace or subspace of this namespace /topo/foo already exists in the OSDF topology: /topo/foo. To register a Pelican equivalence, you need to present your identity.")

	// Now we create a new key and try to use it to register a super/sub space. These shouldn't succeed
	config.ResetIssuerJWKPtr()
	config.ResetIssuerPrivateKeys()
	tDir2 := t.TempDir()
	viper.Set("IssuerKeysDirectory", tDir2+"/keychaining2")
	viper.Set("ConfigDir", tDir2)
	config.InitConfig()
	err = config.InitServer(ctx, server_structs.RegistryType)
	require.NoError(t, err)

	privKey, err = config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/baz", "")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo", "")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	// Make sure we can register things similar but distinct in prefix and suffix
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/fo", "")
	require.NoError(t, err)
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/barz", "")
	require.NoError(t, err)

	// Now turn off token chaining and retry -- no errors should occur
	viper.Set("Registry.RequireKeyChaining", false)
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/baz", "")
	require.NoError(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo", "")
	require.NoError(t, err)

	// However, topology check should be independent of key chaining check
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/topo", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "A superspace or subspace of this namespace /topo already exists in the OSDF topology: /topo/foo. To register a Pelican equivalence, you need to present your identity.")

	_, err = config.SetPreferredPrefix(config.PelicanPrefix)
	assert.NoError(t, err)
	server_utils.ResetTestState()
}

func TestRegistryKeyChaining(t *testing.T) {
	server_utils.ResetTestState()

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, egrp.Wait())
		server_utils.ResetTestState()
	})

	// On by default, but just to make things explicit
	viper.Set("Registry.RequireKeyChaining", true)

	registrySvr := registryMockup(ctx, t, "keychaining")
	defer func() {
		err := ShutdownRegistryDB()
		assert.NoError(t, err)
		registrySvr.CloseClientConnections()
		registrySvr.Close()
	}()

	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)

	// Start by registering /foo/bar with the default key
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar", "")
	require.NoError(t, err)

	// Perform one test with a subspace and the same key -- should succeed
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/test", "")
	require.NoError(t, err)

	// Now we create a new key and try to use it to register a super/sub space. These shouldn't succeed
	viper.Set("IssuerKeysDirectory", t.TempDir()+"/keychaining2")
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()
	err = config.InitServer(ctx, server_structs.RegistryType)
	require.NoError(t, err)

	privKey, err = config.GetIssuerPrivateJWK()
	require.NoError(t, err)
	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/baz", "")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo", "")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	// Now turn off token chaining and retry -- no errors should occur
	viper.Set("Registry.RequireKeyChaining", false)
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/baz", "")
	require.NoError(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo", "")
	require.NoError(t, err)
}
