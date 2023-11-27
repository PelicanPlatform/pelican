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

package nsregistry

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registryMockup(t *testing.T) *httptest.Server {
	issuerTempDir := t.TempDir()

	ikey := filepath.Join(issuerTempDir, "issuer.jwk")
	viper.Set("IssuerKey", ikey)
	viper.Set("Registry.DbLocation", filepath.Join(issuerTempDir, "test.sql"))
	err := config.InitServer(config.RegistryType)
	require.NoError(t, err)

	err = InitializeDB()
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.Default()

	//Configure registry
	RegisterNamespaceRegistry(engine.Group("/"))

	//Set up a server to use for testing
	svr := httptest.NewServer(engine)
	viper.Set("Federation.NamespaceUrl", svr.URL)
	return svr
}

func TestServeNamespaceRegistry(t *testing.T) {
	viper.Reset()

	svr := registryMockup(t)
	defer func() {
		ShutdownDB()
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

	//Test functionality of namespace get
	t.Run("Test namespace get", func(t *testing.T) {
		//Set up a buffer to capture stdout
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

func TestRegistryKeyChaining(t *testing.T) {
	viper.Reset()
	// On by default, but just to make things explicit
	viper.Set("Registry.RequireKeyChaining", true)
	svr := registryMockup(t)
	defer func() {
		ShutdownDB()
		svr.CloseClientConnections()
		svr.Close()
	}()

	_, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	//Test we register /foo/bar with the default key
	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo/bar")
	require.NoError(t, err)

	// Perform one test with a subspace and the same key -- should succeed
	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo/bar/test")
	require.NoError(t, err)

	// Now we create a new key and try to use it to register a super/sub space. These shouldn't succeed
	viper.Set("IssuerKey", t.TempDir()+"/keychaining")
	_, err = config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	privKey, err = config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo/bar/baz")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo")
	require.ErrorContains(t, err, "Cannot register a namespace that is suffixed or prefixed")

	// Make sure we can register things similar but distinct in prefix and suffix
	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/fo")
	require.NoError(t, err)
	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo/barz")
	require.NoError(t, err)

	// Now turn off token chaining and retry -- no errors should occur
	viper.Set("Registry.RequireKeyChaining", false)
	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo/bar/baz")
	require.NoError(t, err)

	err = NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/foo")
	require.NoError(t, err)

	viper.Reset()
}
