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
	"strings"
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
	viper.Set(param.Director_RegistryQueryInterval.GetName(), 1*time.Second)
	customAdvertisementInterval := 100 * time.Millisecond
	viper.Set(param.Server_AdvertisementInterval.GetName(), customAdvertisementInterval) // was 1 minute by default
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

	// Assemble a downtime creation request to the cache server
	incompleteDowntime := web_ui.DowntimeInput{
		Source:      strings.ToLower(server_structs.CacheType.String()),
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

	// Also create a downtime in the Registry, imitating downtime set by federation admin
	registryUrl, err := url.Parse(fedInfo.RegistryEndpoint)
	require.NoError(t, err, "Failed to parse registry URL")
	registryUrl.Path = downtimeCreationPath

	downtimeByFedAdmin := web_ui.DowntimeInput{
		ServerName:  server_structs.GetCacheNs(cacheServerName), // In Registry downtime table, the server name uses server's registered prefix
		Source:      strings.ToLower(server_structs.RegistryType.String()),
		Class:       "SCHEDULED",
		Description: "This is a test downtime set by federation admin",
		Severity:    "Intermittent Outage (may be up for some of the time)",
		StartTime:   time.Now().UTC().Add(25 * time.Hour).UnixMilli(),
		EndTime:     server_structs.IndefiniteEndTime,
	}
	registryDowntimebody, _ := json.Marshal(downtimeByFedAdmin)
	require.NotEmpty(t, registryDowntimebody, "Failed to marshal registry downtime creation request")
	registryDowntimeCreationReq, _ := http.NewRequest("POST", registryUrl.String(), bytes.NewBuffer(registryDowntimebody))
	registryDowntimeCreationReq.Header.Set("Content-Type", "application/json")
	registryDowntimeCreationReq.AddCookie(&http.Cookie{Name: "login", Value: tok})

	registryDowntimeCreationResp, err := client.Do(registryDowntimeCreationReq)
	require.NoError(t, err, "Failed to get response from registry downtime creation request")
	defer registryDowntimeCreationResp.Body.Close()
	assert.Equal(t, http.StatusOK, registryDowntimeCreationResp.StatusCode, "Failed to create downtime")
	registryDowntimeCreationRespBody, err := io.ReadAll(registryDowntimeCreationResp.Body)
	require.NoError(t, err, "Failed to read downtime creation response body")
	t.Log("Registry Downtime Creation Response: ", string(registryDowntimeCreationRespBody))

	// Now ask the Director for the downtimes we just set
	getServerDowntimesPath, err := url.JoinPath("api", "v1.0", "director_ui", "downtimes")
	require.NoError(t, err, "Failed to join specific server downtime path")
	directorUrl.Path = getServerDowntimesPath
	q := directorUrl.Query()
	q.Set("server", cacheServerName)
	directorUrl.RawQuery = q.Encode()

	// Poll for the downtimes
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(customAdvertisementInterval)
	defer ticker.Stop()

	// A map: serverName → its list of downtimes
	var downtimes []server_structs.Downtime
	var foundExpectedDowntimes bool
LOOP:
	for {
		select {
		case <-timeout:
			t.Fatal("Timed out waiting for downtime propagation")
		case <-ticker.C:
			// Re-fetch the downtimes from the Director
			specificServerDowntimeRequest, err := http.NewRequest("GET", directorUrl.String(), nil)
			require.NoError(t, err, "Failed to create HTTP request against a specific server")
			specificServerDowntimeResp, err := client.Do(specificServerDowntimeRequest)
			require.NoError(t, err, "Failed to get response from specific server request")
			dtBody, err := io.ReadAll(specificServerDowntimeResp.Body)
			require.NoError(t, err, "Failed to read server downtimes body")
			require.Equal(t, http.StatusOK, specificServerDowntimeResp.StatusCode,
				"Expected 200 OK from server downtime endpoint. Got %d. Body: %s",
				specificServerDowntimeResp.StatusCode, string(dtBody))
			specificServerDowntimeResp.Body.Close()
			err = json.Unmarshal(dtBody, &downtimes)
			require.NoError(t, err, "Failed to unmarshal server downtimes")

			// Check if the downtimes present
			if len(downtimes) >= 2 {
				foundExpectedDowntimes = true
				break LOOP // Exit the outer loop if all downtimes are found
			}
		}
	}
	require.True(t, foundExpectedDowntimes, "Downtime not found")

	// Verify the downtime we just set
	t.Log("Downtimes: ", downtimes)
	require.Len(t, downtimes, 2, "Downtimes count mismatch")
	assert.Equal(t, incompleteDowntime.Severity, downtimes[0].Severity, "Downtime severity mismatch")
	assert.Equal(t, server_structs.IndefiniteEndTime, downtimes[1].EndTime, "Downtime end time mismatch")
	require.Equal(t, "admin-user", downtimes[0].CreatedBy, "Downtime creator mismatch")
}
