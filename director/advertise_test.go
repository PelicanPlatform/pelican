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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

func TestParseServerAd(t *testing.T) {

	server := utils.Server{
		Endpoint: "http://my-endpoint.com",
		Resource: "MY_SERVER",
	}

	osdf_server := utils.Server{
		Endpoint:     "http://my-endpoint.com",
		Resource:     "MY_SERVER",
		AuthEndpoint: "https://my-auth-endpoint.com",
	}

	// Check that we populate all of the fields correctly -- note that lat/long don't get updated
	// until right before the ad is recorded, so we don't check for that here.
	ad := parseServerAd(server, server_structs.OriginType)
	assert.Equal(t, ad.URL.String(), "http://my-endpoint.com")
	assert.Equal(t, ad.WebURL.String(), "")
	assert.Equal(t, ad.Name, "MY_SERVER")
	assert.Equal(t, ad.AuthURL, url.URL{})
	assert.True(t, ad.Type == server_structs.OriginType)

	// A quick check that type is set correctly
	ad = parseServerAd(server, server_structs.CacheType)
	assert.True(t, ad.Type == server_structs.CacheType)

	// A check that the authurl is set correctly for parsing a server ad from topology
	ad = parseServerAd(osdf_server, server_structs.OriginType)
	assert.Equal(t, ad.URL.String(), "http://my-endpoint.com")
	assert.Equal(t, ad.AuthURL.String(), "https://my-auth-endpoint.com")
}

func JSONHandler(w http.ResponseWriter, r *http.Request) {
	jsonResponse := `
	{
		"caches": [
			{
				"auth_endpoint": "https://cache-auth-endpoint.com",
				"endpoint": "http://cache-endpoint.com",
				"resource": "MY_CACHE"
			}
		],
		"namespaces": [
			{
				"caches": [
					{
						"auth_endpoint": "https://cache-auth-endpoint.com",
						"endpoint": "http://cache-endpoint.com",
						"resource": "MY_CACHE"
					}
				],
				"credential_generation": {
					"base_path": "/server",
					"issuer": "https://my-issuer.com",
					"max_scope_depth": 3,
					"strategy": "OAuth2",
					"vault_issuer": null,
					"vault_server": null
				},
				"scitokens": [
					{
						"base_path": ["/server"],
						"issuer": "https://my-issuer.com",
						"restricted_path": []
					}
				],
				"dirlisthost": null,
				"origins": [
					{
						"auth_endpoint": "https://origin1-auth-endpoint.com",
						"endpoint": "http://origin1-endpoint.com",
						"resource": "MY_ORIGIN1"
					}
				],
				"path": "/my/server",
				"readhttps": true,
				"usetokenonread": true,
				"writebackhost": "https://writeback.my-server.com"
			},
			{
				"caches": [
					{
						"auth_endpoint": "https://cache-auth-endpoint.com",
						"endpoint": "http://cache-endpoint.com",
						"resource": "MY_CACHE"
					}
				],
				"credential_generation": null,
				"scitokens": [],
				"dirlisthost": null,
				"origins": [
					{
						"auth_endpoint": "https://origin2-auth-endpoint.com",
						"endpoint": "http://origin2-endpoint.com",
						"resource": "MY_ORIGIN2"
					}
				],
				"path": "/my/server/2",
				"readhttps": true,
				"usetokenonread": false,
				"writebackhost": null
			}
		]
	}
	`

	// Set the Content-Type header to indicate JSON.
	w.Header().Set("Content-Type", "application/json")

	// Write the JSON response to the response body.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jsonResponse))
}
func TestAdvertiseOSDF(t *testing.T) {
	viper.Reset()
	serverAds.DeleteAll()
	topoServer := httptest.NewServer(http.HandlerFunc(JSONHandler))
	defer topoServer.Close()
	viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)

	err := AdvertiseOSDF()
	require.NoError(t, err)

	var foundServer server_structs.ServerAd
	for _, item := range serverAds.Items() {
		if item.Key().URL.Host == "origin1-endpoint.com" {
			foundServer = item.Key()
		}
	}
	require.NotNil(t, foundServer)
	assert.True(t, foundServer.FromTopology)
	nss := serverAds.Get(foundServer)
	require.NotNil(t, nss)
	assert.True(t, nss.Value()[0].FromTopology)

	// Test a few values. If they're correct, it indicates the whole process likely succeeded
	nsAd, oAds, cAds := getAdsForPath("/my/server/path/to/file")
	assert.Equal(t, nsAd.Path, "/my/server")
	assert.Equal(t, nsAd.Generation[0].MaxScopeDepth, uint(3))
	assert.Equal(t, oAds[0].AuthURL.String(), "https://origin1-auth-endpoint.com")
	assert.Equal(t, cAds[0].URL.String(), "http://cache-endpoint.com")

	nsAd, oAds, cAds = getAdsForPath("/my/server/2/path/to/file")
	assert.Equal(t, nsAd.Path, "/my/server/2")
	assert.Equal(t, nsAd.PublicRead, true)
	assert.Equal(t, oAds[0].AuthURL.String(), "https://origin2-auth-endpoint.com")
	assert.Equal(t, cAds[0].URL.String(), "http://cache-endpoint.com")
}
