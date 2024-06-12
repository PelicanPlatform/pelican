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

package director

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

const (
	mockDirUrlWoPort = "https://example.director.com"
	mockDirUrlWPort  = "https://example.director.com:8444"

	mockRawDirUrlHTTP = "http://example.director.com"
	mockRawDirUrl443  = "https://example.director.com:443"

	mockRegUrlWoPort = "https://example.registry.com"
	mockRegUrlWPort  = "https://example.registry.com:8444"

	mockRawRegUrlHTTP = "http://example.registry.com"
	mockRawRegUrl443  = "https://example.registry.com:443"
)

func TestFederationDiscoveryHandler(t *testing.T) {
	router := gin.Default()
	router.GET("/test", federationDiscoveryHandler)

	tests := []struct {
		name        string
		dirUrl      string
		regUrl      string
		expectedDir string
		expectedReg string
		statusCode  int
	}{
		{
			name:        "reg-dir-without-port",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      mockRegUrlWoPort,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "dir-with-non-443-port",
			dirUrl:      mockDirUrlWPort,
			regUrl:      mockRegUrlWoPort,
			expectedDir: mockDirUrlWPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "dir-with-443-port",
			dirUrl:      mockRawDirUrl443,
			regUrl:      mockRegUrlWoPort,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "dir-with-http",
			dirUrl:      mockRawDirUrlHTTP,
			regUrl:      mockRegUrlWoPort,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "dir-empty",
			dirUrl:      "",
			regUrl:      mockRegUrlWoPort,
			expectedDir: "",
			expectedReg: "",
			statusCode:  500,
		},
		// registry url tests
		{
			name:        "reg-with-non-443-port",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      mockRegUrlWPort,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWPort,
			statusCode:  200,
		},
		{
			name:        "reg-with-443-port",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      mockRawRegUrl443,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "reg-with-http",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      mockRawRegUrlHTTP,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "reg-empty",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      "",
			expectedDir: "",
			expectedReg: "",
			statusCode:  500,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("ConfigDir", t.TempDir())
			viper.Set("Federation.DirectorUrl", tc.dirUrl)
			viper.Set("Federation.RegistryUrl", tc.regUrl)
			config.InitConfig()
			require.NoError(t, config.InitClient())

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)

			require.Equal(t, tc.statusCode, w.Result().StatusCode)
			body, err := io.ReadAll(w.Result().Body)
			require.NoError(t, err)
			dis := config.FederationDiscovery{}
			err = json.Unmarshal(body, &dis)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedDir, dis.DirectorEndpoint)
			assert.Equal(t, tc.expectedReg, dis.NamespaceRegistrationEndpoint)
		})
	}
}

func TestOidcDiscoveryHandler(t *testing.T) {
	router := gin.Default()
	server_utils.RegisterOIDCAPI(router.Group("/test"), true)

	tests := []struct {
		name           string
		dirUrl         string
		expectedIssuer string
		expectedJwks   string
		statusCode     int
	}{
		{
			name:           "dir-without-port",
			dirUrl:         mockDirUrlWoPort,
			expectedIssuer: mockDirUrlWoPort,
			expectedJwks:   mockDirUrlWoPort + directorJWKSPath,
			statusCode:     200,
		},
		{
			name:           "dir-with-443-port",
			dirUrl:         mockRawDirUrl443,
			expectedIssuer: mockDirUrlWoPort,
			expectedJwks:   mockDirUrlWoPort + directorJWKSPath,
			statusCode:     200,
		},
		{
			name:           "dir-with-non-443-port",
			dirUrl:         mockDirUrlWPort,
			expectedIssuer: mockDirUrlWPort,
			expectedJwks:   mockDirUrlWPort + directorJWKSPath,
			statusCode:     200,
		},
		{
			name:           "dir-with-http",
			dirUrl:         mockRawDirUrlHTTP,
			expectedIssuer: mockDirUrlWoPort,
			expectedJwks:   mockDirUrlWoPort + directorJWKSPath,
			statusCode:     200,
		},
		{
			name:           "empty-dir",
			dirUrl:         "",
			expectedIssuer: "",
			expectedJwks:   "",
			statusCode:     500,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("ConfigDir", t.TempDir())
			viper.Set("Federation.DirectorUrl", tc.dirUrl)
			config.InitConfig()
			require.NoError(t, config.InitClient())

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test"+oidcDiscoveryPath, nil)
			router.ServeHTTP(w, req)

			require.Equal(t, tc.statusCode, w.Result().StatusCode)
			body, err := io.ReadAll(w.Result().Body)
			require.NoError(t, err)
			dis := server_structs.OpenIdDiscoveryResponse{}
			err = json.Unmarshal(body, &dis)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedIssuer, dis.Issuer)
			assert.Equal(t, tc.expectedJwks, dis.JwksUri)
		})
	}
}
