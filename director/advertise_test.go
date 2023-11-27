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
	assert.Equal(t, ad.WebURL.String(), "")
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
				"path": "/server",
				"readhttps": true,
				"scitokens": [
					{
						"base_path": [
							"/server"
						],
						"issuer": "https://my-issuer.com",
						"restricted_path": []
					}
				],
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
						"auth_endpoint": "https://origin3-auth-endpoint.com",
						"endpoint": "http://origin3-endpoint.com",
						"resource": "MY_ORIGIN3"
					},
					{
						"auth_endpoint": "https://origin4-auth-endpoint.com",
						"endpoint": "http://origin4-endpoint.com",
						"resource": "MY_ORIGIN4"
					}
				],
				"path": "/orig",
				"scitokens": [
					{
						"base_path": [
							"/p1/path", "/p2"
						],
						"issuer": "https://issuer-sci",
						"restricted_path": ["/p2/open"]
					},
					{
						"base_path": [
							"/p3"
						],
						"issuer": "https://issuer-2-sci",
						"restricted_path": []
					}
				],
				"usetokenonread": true
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
	nsAd, oAds, cAds := GetAdsForPath("/server/path/to/file")
	assert.Equal(t, "/server", nsAd.Path)
	assert.Equal(t, uint(3), nsAd.MaxScopeDepth)
	assert.Equal(t, "https://origin1-auth-endpoint.com", oAds[0].AuthURL.String())
	assert.Equal(t, "http://cache-endpoint.com", cAds[0].URL.String())

	nsAd, oAds, cAds = GetAdsForPath("/my/server/2/path/to/file")
	assert.Equal(t, "/my/server/2", nsAd.Path)
	assert.Equal(t, false, nsAd.RequireToken)
	assert.Equal(t, "https://origin2-auth-endpoint.com", oAds[0].AuthURL.String())
	assert.Equal(t, "http://cache-endpoint.com", cAds[0].URL.String())

	nsAd, oAds, cAds = GetAdsForPath("/p2")
	assert.Equal(t, "/p2", nsAd.Path)
	assert.Equal(t, []string{"/p2/open"}, nsAd.RestrictedPath)
	assert.Equal(t, "https://origin3-auth-endpoint.com", oAds[0].AuthURL.String())
	assert.Equal(t, "http://cache-endpoint.com", cAds[0].URL.String())
	assert.Equal(t, true, nsAd.RequireToken)

	nsAd, _, _ = GetAdsForPath("/p3")
	assert.Equal(t, "/p3", nsAd.Path)
	assert.Equal(t, []string{}, nsAd.RestrictedPath)
}
