/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package server_utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// TestDoDiscoveryAddsSyntheticSeedMissingFromPeerResponse verifies that
// when a configured seed URL is successfully contacted but is not mentioned
// in any peer's /directors response, doDiscovery still includes it as
// a synthetic DirectorAd so that clients can still reach it.
func TestDoDiscoveryAddsSyntheticSeedMissingFromPeerResponse(t *testing.T) {
	ResetTestState()
	t.Cleanup(ResetTestState)

	// Director B is online and only reports itself.
	var serverBURL string
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ads := []server_structs.DirectorAd{
			{
				AdvertiseUrl: serverBURL,
				ServerBaseAd: server_structs.ServerBaseAd{
					Name:       "dir-b",
					InstanceID: "inst-b",
					StartTime:  1,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(ads)
	}))
	defer serverB.Close()
	serverBURL = serverB.URL

	// Director A is online but returns an empty list.
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]server_structs.DirectorAd{})
	}))
	defer serverA.Close()
	serverAURL := serverA.URL

	require.NoError(t, param.Server_DirectorUrls.Set([]string{serverAURL, serverBURL}))

	endpoints, err := doDiscovery(context.Background(), false)
	require.NoError(t, err)

	urls := make(map[string]bool, len(endpoints))
	for _, ep := range endpoints {
		urls[ep.AdvertiseUrl] = true
	}
	assert.True(t, urls[serverBURL], "server B (peer-reported) must be in endpoints")
	assert.True(t, urls[serverAURL], "server A (synthetic seed) must be in endpoints even though it didn't report itself")
}

// TestDoDiscoveryNoSyntheticEntryForOfflineSeed verifies that a configured
// seed which is genuinely offline is NOT added as a synthetic entry.
func TestDoDiscoveryNoSyntheticEntryForOfflineSeed(t *testing.T) {
	ResetTestState()
	t.Cleanup(ResetTestState)

	var serverBURL string
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ads := []server_structs.DirectorAd{
			{
				AdvertiseUrl: serverBURL,
				ServerBaseAd: server_structs.ServerBaseAd{
					Name:       "dir-b",
					InstanceID: "inst-b",
					StartTime:  1,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(ads)
	}))
	defer serverB.Close()
	serverBURL = serverB.URL

	// Create and immediately close server A to simulate a refused connection.
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverAURL := serverA.URL
	serverA.Close()

	require.NoError(t, param.Server_DirectorUrls.Set([]string{serverAURL, serverBURL}))

	endpoints, err := doDiscovery(context.Background(), false)
	require.NoError(t, err, "one reachable peer is sufficient; error must not propagate")

	urls := make(map[string]bool, len(endpoints))
	for _, ep := range endpoints {
		urls[ep.AdvertiseUrl] = true
	}
	assert.True(t, urls[serverBURL], "server B (peer-reported) must be in endpoints")
	assert.False(t, urls[serverAURL], "server A (genuinely offline) must NOT be added as a synthetic entry")
}

// TestDoDiscoveryFiltersExpiredPeerEntries verifies that entries returned
// by a peer's /directors response with a past Expiration timestamp are
// excluded from the endpointMap, preventing a stale-state self-sustaining
// loop.
func TestDoDiscoveryFiltersExpiredPeerEntries(t *testing.T) {
	ResetTestState()
	t.Cleanup(ResetTestState)

	expiredTime := time.Now().Add(-1 * time.Minute)
	liveTime := time.Now().Add(15 * time.Minute)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ads := []server_structs.DirectorAd{
			{
				AdvertiseUrl: "http://expired.example.com",
				ServerBaseAd: server_structs.ServerBaseAd{
					Name:       "dir-expired",
					InstanceID: "inst-expired",
					StartTime:  1,
					Expiration: expiredTime,
				},
			},
			{
				AdvertiseUrl: serverURL,
				ServerBaseAd: server_structs.ServerBaseAd{
					Name:       "dir-live",
					InstanceID: "inst-live",
					StartTime:  1,
					Expiration: liveTime,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(ads)
	}))
	defer server.Close()
	serverURL = server.URL

	require.NoError(t, param.Server_DirectorUrls.Set([]string{serverURL}))

	endpoints, err := doDiscovery(context.Background(), false)
	require.NoError(t, err)

	urls := make(map[string]bool, len(endpoints))
	for _, ep := range endpoints {
		urls[ep.AdvertiseUrl] = true
	}
	assert.False(t, urls["http://expired.example.com"],
		"entry with past Expiration must be filtered out")
	assert.True(t, urls[serverURL],
		"entry with future Expiration must be present")
}
