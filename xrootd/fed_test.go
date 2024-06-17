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

package xrootd_test

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	//go:embed resources/test-https-origin.yml
	httpsOriginConfig string
)

func TestHttpOriginConfig(t *testing.T) {
	viper.Reset()
	viper.Set("ConfigDir", t.TempDir())
	server_utils.ResetOriginExports()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()

	body := "Hello, World!"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.Path == "/test2/hello_world" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == "GET" && r.URL.Path == "/test2/hello_world" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			_, err := w.Write([]byte(body))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	modules := config.ServerType(0)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)

	viper.Set("Origin.HttpServiceUrl", srv.URL+"/test2")
	viper.Set("Origin.FederationPrefix", "/test")

	config.InitConfig()

	tmpPath := t.TempDir()

	fed := fed_test_utils.NewFedTest(t, httpsOriginConfig)

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	// Create a token file
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Storage_Read.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Storage_Modify.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)
	token, err := tokenConfig.CreateToken()
	assert.NoError(t, err)
	tempToken, err := os.CreateTemp(t.TempDir(), "token")
	assert.NoError(t, err, "Error creating temp token file")
	defer tempToken.Close()
	_, err = tempToken.WriteString(token)
	assert.NoError(t, err, "Error writing to temp token file")

	fedInfo, err := config.GetFederation(fed.Ctx)
	require.NoError(t, err)
	fedUrl, err := url.Parse(fedInfo.DirectorEndpoint)
	require.NoError(t, err)

	// Download the test file
	transferResults, err := client.DoGet(
		fed.Ctx,
		"pelican://"+fedUrl.Host+"/test/hello_world",
		filepath.Join(tmpPath, "hw"),
		false,
		client.WithTokenLocation(tempToken.Name()),
	)
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, transferResults[0].TransferredBytes, int64(len(body)))
	}
}
