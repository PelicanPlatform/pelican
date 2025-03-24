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
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui"
)

type serverAdUnmarshalCustom struct {
	serverAdUnmarshal
	WebURL    string                    `json:"webUrl"`
	Name      string                    `json:"name"`
	Downtimes []server_structs.Downtime `json:"downtimes"`
}

// Verify that the director correctly handles a downtime declared by a cache server
func TestServerDowntimeDirectorForwarding(t *testing.T) {
	server_utils.ResetTestState()
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
		server_utils.ResetTestState()
	})

	// Spin up a federation and get the Director's URL
	viper.Set(param.Server_UIAdminUsers.GetName(), "admin-user")
	viper.Set(param.Server_AdvertisementInterval.GetName(), 1*time.Second) // was 1 minute by default
	_ = fed_test_utils.NewFedTest(t, bothPubNamespaces)
	fedInfo, err := config.GetFederation(ctx)
	require.NoError(t, err, "Failed to get federation service info")

	directorUrlStr := fedInfo.DirectorEndpoint
	directorUrl, err := url.Parse(directorUrlStr)
	require.NoError(t, err, "Failed to parse director URL")

	// Find a cache, then ask for its url. To do that, hit the Director's
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
	require.NoError(t, err, "Failed to get response")
	defer resp.Body.Close()
	require.Equal(t, resp.StatusCode, http.StatusOK, "Failed to get server list from director")
	dirBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read server list body")

	// Unmarshal the body into a slice of dummy server ads. Can't use the actual server_structs.ServerAd
	// struct without a custom unmarshaler (because of string --> url conversion)
	var serverAds []serverAdUnmarshalCustom
	err = json.Unmarshal(dirBody, &serverAds)
	require.NoError(t, err, "Failed to unmarshal server ads")
	var cacheWebUrlStr string
	var cacheServerName string
	found := false
	for _, serverAd := range serverAds {
		if serverAd.Type == server_structs.CacheType.String() {
			cacheWebUrlStr = serverAd.WebURL
			cacheServerName = serverAd.Name
			found = true
			break
		}
	}
	require.True(t, found, "Failed to find a cache server in the server list")
	cacheWebUrl, err := url.Parse(cacheWebUrlStr)
	require.NoError(t, err, "Failed to parse cache URL")

	// originServer := origin.OriginServer{}
	// ads := originServer.GetNamespaceAds()
	// Assemble a downtime creation request to the cache server
	incompleteDowntime := web_ui.DowntimeInput{
		CreatedBy:   "John Doe Jr.",
		Class:       "SCHEDULED",
		Description: "",
		Severity:    "Intermittent Outage (may be up for some of the time)",
		StartTime:   time.Now().UTC().Add(1 * time.Hour).UnixMilli(),
		EndTime:     time.Now().UTC().Add(9 * time.Hour).UnixMilli(),
	}
	body, _ := json.Marshal(incompleteDowntime)
	require.NotEmpty(t, body, "Failed to marshal downtime creation request")

	downtimeCreationPath, err := url.JoinPath("api", "v1.0", "downtime")
	require.NoError(t, err, "Failed to join downtime creation path")
	cacheWebUrl.Path = downtimeCreationPath

	// Create token for admin user in test
	tk := token.NewWLCGToken()
	tk.Issuer = fedInfo.DiscoveryEndpoint
	tk.Subject = "admin-user"
	tk.Lifetime = 5 * time.Minute
	tk.AddAudiences(fedInfo.DiscoveryEndpoint)
	tk.AddScopes(token_scopes.WebUi_Access)
	tok, err := tk.CreateToken()
	require.NoError(t, err)

	downtimeCreationReq, _ := http.NewRequest("POST", cacheWebUrl.String(), bytes.NewBuffer(body))
	downtimeCreationReq.Header.Set("Content-Type", "application/json")
	downtimeCreationReq.Header.Set("Authorization", "Bearer "+tok)
	downtimeCreationReq.AddCookie(&http.Cookie{Name: "login", Value: tok})

	downtimeCreationResp, err := client.Do(downtimeCreationReq)
	require.NoError(t, err, "Failed to get response from downtime creation request")
	defer downtimeCreationResp.Body.Close()
	assert.Equal(t, http.StatusOK, downtimeCreationResp.StatusCode, "Failed to create downtime")
	downtimeCreationRespBody, err := io.ReadAll(downtimeCreationResp.Body)
	require.NoError(t, err, "Failed to read downtime creation response body")
	t.Log("Downtime Creation Response: ", string(downtimeCreationRespBody))

	// Sleep for 2 seconds so the cache server has time to propagate the advertisement
	time.Sleep(2 * time.Second)

	// Now ask the Director if it has the downtime we just set
	getSpecificServerAdPath, err := url.JoinPath("api", "v1.0", "director_ui", "servers", cacheServerName)
	directorUrl.Path = getSpecificServerAdPath
	specificServerAdRequest, err := http.NewRequest("GET", directorUrl.String(), nil)
	require.NoError(t, err, "Failed to create HTTP request against a specific server")

	specificServerAdResp, err := client.Do(specificServerAdRequest)
	require.NoError(t, err, "Failed to get response from specific server request")
	defer specificServerAdResp.Body.Close()
	require.Equal(t, resp.StatusCode, http.StatusOK, "Failed to get the advertisement of a specific server from director")
	adBody, err := io.ReadAll(specificServerAdResp.Body)
	require.NoError(t, err, "Failed to read server ad body")

	// Verify the downtime we just set is in the server ad
	var serverAd serverAdUnmarshalCustom
	err = json.Unmarshal(adBody, &serverAd)
	require.NoError(t, err, "Failed to unmarshal server ad")

	require.Len(t, serverAd.Downtimes, 1, "Downtime not found in server ad")
	require.Equal(t, incompleteDowntime.Severity, serverAd.Downtimes[0].Severity, "Downtime severity mismatch")
	require.Equal(t, incompleteDowntime.CreatedBy, serverAd.Downtimes[0].CreatedBy, "Downtime creator mismatch")
}
