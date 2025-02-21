//go:build !windows

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package fed_tests

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

//go:embed resources/both-public.yml
var bothPubNamespaces string

type serverAdUnmarshal struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Queries the cache for a director test file -- this mimics the way the Pelican
// process at the cache behaves, as its responsible for requesting files from its
// own XRootD component
func TestDirectorCacheHealthTest(t *testing.T) {
	// Spin up a federation
	_ = fed_test_utils.NewFedTest(t, bothPubNamespaces)

	ctx := context.Background()
	ctx, _, _ = test_utils.TestContext(ctx, t)
	fedInfo, err := config.GetFederation(ctx)
	require.NoError(t, err, "Failed to get federation service info")

	directorUrlStr := fedInfo.DirectorEndpoint
	directorUrl, err := url.Parse(directorUrlStr)
	require.NoError(t, err, "Failed to parse director URL")

	// There is no cache that will advertise the /pelican/monitoring namespace directly,
	// so we first discover a cache, then ask for the file. To do that, hit the Director's
	// server list endpoint and iterate through the servers until we find a cache.
	listPath, err := url.JoinPath("api", "v1.0", "director_ui", "servers")
	require.NoError(t, err, "Failed to join server list path")
	directorUrl.Path = listPath
	request, err := http.NewRequest("GET", directorUrl.String(), nil)
	require.NoError(t, err, "Failed to create HTTP request against server list path")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Transport: tr}
	resp, err := client.Do(request)
	assert.NoError(t, err, "Failed to get response")
	defer resp.Body.Close()
	require.Equal(t, resp.StatusCode, http.StatusOK, "Failed to get server list from director")
	dirBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read server list body")

	// Unmarshal the body into a slice of dummy server ads. Can't use the actual server_structs.ServerAd
	// struct without a custom unmarshaler (because of string --> url conversion)
	var serverAds []serverAdUnmarshal
	err = json.Unmarshal(dirBody, &serverAds)
	require.NoError(t, err, "Failed to unmarshal server ads")
	var cacheUrlStr string
	found := false
	for _, serverAd := range serverAds {
		if serverAd.Type == server_structs.CacheType.String() {
			cacheUrlStr = serverAd.URL
			found = true
			break
		}
	}
	require.True(t, found, "Failed to find a cache server in the server list")
	cacheUrl, err := url.Parse(cacheUrlStr)
	require.NoError(t, err, "Failed to parse cache URL")

	// Now ask the cache for the director test file. When it gets the request,
	// it'll turn around and ask the director for the file, exactly as it would
	// if the cache's own self-test utility requested the file.
	cachePath, err := url.JoinPath(server_utils.MonitoringBaseNs, "directorTest",
		server_utils.DirectorTest.String()+"-2006-01-02T15:04:10Z.txt")
	require.NoError(t, err, "Failed to join path")

	cacheUrl.Path = cachePath
	request, err = http.NewRequest("GET", cacheUrl.String(), nil)
	require.NoError(t, err, "Failed to create HTTP request against cache")

	resp, err = client.Do(request)
	assert.NoError(t, err, "Failed to get response")
	defer resp.Body.Close()
	cacheBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read cache body")
	assert.Equal(t, resp.StatusCode, http.StatusOK, "Failed to get director test file from cache")
	assert.Contains(t, string(cacheBody), "This object was created by the Pelican director-test functionality")
}

func updateAllowedPrefixesForCache(t *testing.T, dbPath string, cacheHost string, allowedPrefixes []string) {
	// We treat the absence of this custom field differently than its presence
	// and an empty list.
	if len(allowedPrefixes) == 0 {
		return
	}

	db, err := server_utils.InitSQLiteDB(dbPath)
	require.NoError(t, err, "Failed to connect to registry database")
	defer func() {
		_ = server_utils.ShutdownDB(db)
	}()

	var namespace server_structs.Namespace
	result := db.Where("prefix = ?", "/caches/"+cacheHost).First(&namespace)
	require.NoError(t, result.Error, "Failed to find namespace for host %s: %v", cacheHost, result.Error)

	if namespace.CustomFields == nil {
		namespace.CustomFields = make(map[string]interface{})
	}
	namespace.CustomFields["AllowedPrefixes"] = allowedPrefixes

	result = db.Model(&namespace).Updates(server_structs.Namespace{
		CustomFields: namespace.CustomFields,
	})
	require.NoError(t, result.Error, "Failed to update namespace for host %s: %v", cacheHost, result.Error)
	if result.RowsAffected == 0 {
		require.Fail(t, "No rows affected when updating namespace for host %s", cacheHost)
	}
}

// Test that registered services can grab a token from the Director
// using a valid advertise token. For now this only tests Caches because
// we aren't actively using fed tokens in the Origin yet.
func TestDirectorFedTokenCacheAPI(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	testCases := []struct {
		name               string
		allowedPrefixes    []string
		scopeShouldHave    []string
		scopeShouldNotHave []string
	}{
		{
			name:               "AllowFirstNamespace",
			allowedPrefixes:    []string{"/first/namespace"},
			scopeShouldHave:    []string{"storage.read:/first/namespace"},
			scopeShouldNotHave: []string{"/second/namespace"},
		},
		{
			name:               "AllowBothNamespaces",
			allowedPrefixes:    []string{"/first/namespace", "/second/namespace"},
			scopeShouldHave:    []string{"storage.read:/first/namespace", "storage.read:/second/namespace"},
			scopeShouldNotHave: []string{},
		},
		{
			name:               "NoCustomField",
			allowedPrefixes:    []string{},
			scopeShouldHave:    []string{"storage.read:/"}, // Absence of field means no namespace restrictions
			scopeShouldNotHave: []string{},
		},
		{
			name:               "EmptyCustomField",
			allowedPrefixes:    []string{""},
			scopeShouldHave:    []string{}, // Empty field means no read permissions
			scopeShouldNotHave: []string{},
		},
		{
			name:               "GlobNamespace",
			allowedPrefixes:    []string{"*"},
			scopeShouldHave:    []string{"storage.read:/"},
			scopeShouldNotHave: []string{},
		},
		// After some discussion with Sarthak, we decided there's no point in testing
		// the case where the Registry is configured with an invalid namespace -- we
		// make the assumption that namespace info is validated by the Registry before
		// insertion in its database.
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set(param.Director_RegistryQueryInterval.GetName(), "1s")
			_ = fed_test_utils.NewFedTest(t, bothPubNamespaces)

			// All servers running as part of fed-in-a-box will have the same hostname
			// so we can use that fact when injecting allowed prefixes into the registry database
			host := param.Server_Hostname.GetString()
			require.NotEmpty(t, host, "Failed to determine server hostname")

			// Inject our "AllowedPrefixes" data into the registry database under
			// the /caches/<hostname> namespace
			dbLoc := param.Registry_DbLocation.GetString()
			require.NotEmpty(t, dbLoc, "Failed to determine registry database location")
			updateAllowedPrefixesForCache(t, dbLoc, host, tc.allowedPrefixes)

			// Now sleep for 2 seconds so the Director has time to populate the changes
			time.Sleep(2 * time.Second)

			// Grab the service's key and create an advertise token
			ctx := context.Background()
			ctx, _, _ = test_utils.TestContext(ctx, t)
			cache := cache.CacheServer{}
			tokStr, err := server_utils.GetFedTok(ctx, &cache)
			require.NoError(t, err, "Failed to get cache's advertisement token")
			require.NotEmpty(t, tokStr, "Got an empty token")

			tok, err := jwt.ParseInsecure([]byte(tokStr))
			require.NoError(t, err, "Failed to parse token")
			// In this case, the "fed issuer" is the director because we're running as fed-in-a-box.
			// However, that need not be true in general wherever the Director has a configured Federation.DiscoveryUrl.
			fedInfo, err := config.GetFederation(ctx)
			require.NoError(t, err, "Failed to get federation info")
			directorUrlStr := fedInfo.DirectorEndpoint
			assert.Equal(t, directorUrlStr, tok.Issuer())
			var scopes []string
			if rawScopes, exists := tok.Get("scope"); exists {
				if scopeStr, ok := rawScopes.(string); ok {
					scopes = strings.Split(scopeStr, " ")
				}
			}
			assert.ElementsMatch(t, tc.scopeShouldHave, scopes)
		})
	}
}
