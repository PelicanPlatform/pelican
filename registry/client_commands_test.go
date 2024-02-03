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

package registry

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registryMockup(ctx context.Context, t *testing.T, testName string) *httptest.Server {

	issuerTempDir := filepath.Join(t.TempDir(), testName)

	ikey := filepath.Join(issuerTempDir, "issuer.jwk")
	viper.Set("IssuerKey", ikey)
	viper.Set("Registry.DbLocation", filepath.Join(issuerTempDir, "test.sql"))
	viper.Set("Server.WebPort", 8444)
	err := config.InitServer(ctx, config.RegistryType)
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

func TestServeNamespaceRegistry(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()

	svr := registryMockup(ctx, t, "serveregistry")
	defer func() {
		err := ShutdownDB()
		assert.NoError(t, err)
		svr.CloseClientConnections()
		svr.Close()
	}()

	_, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	//Test functionality of registering a namespace (without identity)
	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo/bar")
	require.NoError(t, err)

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
	viper.Reset()
}

func TestRegistryKeyChainingOSDF(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	_ = config.SetPreferredPrefix("OSDF")
	// On by default, but just to make things explicit
	viper.Set("Registry.RequireKeyChaining", true)

	registrySvr := registryMockup(ctx, t, "OSDFkeychaining")
	topoSvr := topologyMockup(t, []string{"/topo/foo"})
	viper.Set("Federation.TopologyNamespaceURL", topoSvr.URL)
	err := PopulateTopology()
	require.NoError(t, err)

	defer func() {
		err := ShutdownDB()
		assert.NoError(t, err)
		registrySvr.CloseClientConnections()
		registrySvr.Close()
		topoSvr.CloseClientConnections()
		topoSvr.Close()
	}()

	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	// Start by registering /foo/bar with the default key
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar")
	require.NoError(t, err)

	// Perform one test with a subspace and the same key -- should succeed
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/test")
	require.NoError(t, err)

	// For now, we simply don't allow further super/sub spacing of namespaces from topo, because how
	// can we validate via a key if there is none?
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/topo/foo/bar")
	require.Error(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/topo")
	require.Error(t, err)

	// Now we create a new key and try to use it to register a super/sub space. These shouldn't succeed
	viper.Set("IssuerKey", t.TempDir()+"/keychaining")
	config.InitConfig()
	err = config.InitServer(ctx, config.RegistryType)
	require.NoError(t, err)

	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err = config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/baz")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	// Make sure we can register things similar but distinct in prefix and suffix
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/fo")
	require.NoError(t, err)
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/barz")
	require.NoError(t, err)

	// Now turn off token chaining and retry -- no errors should occur
	viper.Set("Registry.RequireKeyChaining", false)
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/baz")
	require.NoError(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo")
	require.NoError(t, err)

	// Finally, test with one value for topo
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/topo")
	require.NoError(t, err)

	config.SetPreferredPrefix("pelican")
	viper.Reset()
}

func TestRegistryKeyChaining(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()
	// On by default, but just to make things explicit
	viper.Set("Registry.RequireKeyChaining", true)

	registrySvr := registryMockup(ctx, t, "keychaining")
	defer func() {
		err := ShutdownDB()
		assert.NoError(t, err)
		registrySvr.CloseClientConnections()
		registrySvr.Close()
	}()

	_, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	// Start by registering /foo/bar with the default key
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar")
	require.NoError(t, err)

	// Perform one test with a subspace and the same key -- should succeed
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/test")
	require.NoError(t, err)

	// Now we create a new key and try to use it to register a super/sub space. These shouldn't succeed
	viper.Set("IssuerKey", t.TempDir()+"/keychaining")
	config.InitConfig()
	err = config.InitServer(ctx, config.RegistryType)
	require.NoError(t, err)

	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err = config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/baz")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	// Now turn off token chaining and retry -- no errors should occur
	viper.Set("Registry.RequireKeyChaining", false)
	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo/bar/baz")
	require.NoError(t, err)

	err = NamespaceRegister(privKey, registrySvr.URL+"/api/v1.0/registry", "", "/foo")
	require.NoError(t, err)

	viper.Reset()
}
