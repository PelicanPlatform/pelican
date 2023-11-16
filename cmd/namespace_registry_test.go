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

package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	nsregistry "github.com/pelicanplatform/pelican/namespace-registry"
	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServeNamespaceRegistry(t *testing.T) {
	issuerTempDir := t.TempDir()

	viper.Reset()
	config.InitConfig()
	ikey := filepath.Join(issuerTempDir, "issuer.jwk")
	viper.Set("IssuerKey", ikey)
	viper.Set("Registry.DbLocation", filepath.Join(issuerTempDir, "test.sql"))
	err := config.InitServer()
	require.NoError(t, err)

	err = nsregistry.InitializeDB()
	require.NoError(t, err)
	defer nsregistry.ShutdownDB()

	gin.SetMode(gin.TestMode)
	engine := gin.Default()

	_, err = config.LoadPublicKey("", ikey)
	require.NoError(t, err)
	privKey, err := config.GetIssuerPrivateJWK()
	require.NoError(t, err)

	//Configure registry
	nsregistry.RegisterNamespaceRegistry(engine.Group("/"))

	//Set up a server to use for testing
	svr := httptest.NewServer(engine)
	defer svr.CloseClientConnections()
	defer svr.Close()

	viper.Set("Federation.NamespaceUrl", svr.URL)
	viper.Set("Origin.NamespacePrefix", "/test")

	//Test functionality of registering a namespace (without identity)
	err = nsregistry.NamespaceRegister(privKey, svr.URL+"/api/v1.0/registry", "", "/test")
	require.NoError(t, err)

	//Test we can list the namespace without an error
	t.Run("Test namespace list", func(t *testing.T) {
		//Set up a buffer to capture stdout
		var stdoutCapture string
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		//List the namespaces
		err = nsregistry.NamespaceList(svr.URL + "/api/v1.0/registry")
		require.NoError(t, err)
		w.Close()
		os.Stdout = oldStdout

		capturedOutput := make([]byte, 1024)
		n, _ := r.Read(capturedOutput)
		stdoutCapture = string(capturedOutput[:n])
		assert.Contains(t, stdoutCapture, `"Prefix":"/test"`)
	})

	//Test functionality of namespace get
	t.Run("Test namespace get", func(t *testing.T) {
		//Set up a buffer to capture stdout
		var stdoutCapture string
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err = nsregistry.NamespaceGet(svr.URL + "/api/v1.0/registry")
		require.NoError(t, err)
		w.Close()
		os.Stdout = oldStdout

		capturedOutput := make([]byte, 1024)
		n, _ := r.Read(capturedOutput)
		stdoutCapture = string(capturedOutput[:n])
		assert.Contains(t, stdoutCapture, `"Prefix":"/test"`)
	})

	t.Run("Test namespace delete", func(t *testing.T) {
		//Test functionality of namespace delete
		err = nsregistry.NamespaceDelete(svr.URL+"/api/v1.0/registry/test", "/test")
		require.NoError(t, err)
		var stdoutCapture string
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		err = nsregistry.NamespaceGet(svr.URL + "/api/v1.0/registry")
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
