package director

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestParseServerAd(t *testing.T) {

	server := Server{
		AuthEndpoint: "https://my-auth-endpoint.com",
		Endpoint:     "http://my-endpoint.com",
		Resource:     "MY_SERVER",
	}

	// Check that we populate all of the fields correctly -- note that lat/long don't get updated
	// until right before the ad is recorded, so we don't check for that here.
	ad := parseServerAd(server, OriginType)
	assert.Equal(t, ad.AuthURL.String(), "https://my-auth-endpoint.com")
	assert.Equal(t, ad.URL.String(), "http://my-endpoint.com")
	assert.Equal(t, ad.Name, "MY_SERVER")
	assert.True(t, ad.Type == OriginType)

	// A quick check that type is set correctly
	ad = parseServerAd(server, CacheType)
	assert.True(t, ad.Type == CacheType)
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
	topoServer := httptest.NewServer(http.HandlerFunc(JSONHandler))
	defer topoServer.Close()
	viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)

	err := AdvertiseOSDF()
	if err != nil {
		t.Fatal(err)
	}

	// Test a few values. If they're correct, it indicates the whole process likely succeeded
	nsAd, oAds, cAds := GetAdsForPath("/my/server/path/to/file")
	assert.Equal(t, nsAd.Path, "/my/server")
	assert.Equal(t, nsAd.MaxScopeDepth, uint(3))
	assert.Equal(t, oAds[0].AuthURL.String(), "https://origin1-auth-endpoint.com")
	assert.Equal(t, cAds[0].URL.String(), "http://cache-endpoint.com")

	nsAd, oAds, cAds = GetAdsForPath("/my/server/2/path/to/file")
	assert.Equal(t, nsAd.Path, "/my/server/2")
	assert.Equal(t, nsAd.RequireToken, false)
	assert.Equal(t, oAds[0].AuthURL.String(), "https://origin2-auth-endpoint.com")
	assert.Equal(t, cAds[0].URL.String(), "http://cache-endpoint.com")
}
