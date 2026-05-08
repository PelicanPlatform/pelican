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

package director

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestForwardService(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	directorNameOnce = sync.Once{}
	directorName = ""
	directorNameError = nil

	require.NoError(t, param.Director_AdvertiseUrl.Set("http://director-ad-url"))
	require.NoError(t, param.Server_ExternalWebUrl.Set("http://external-url"))

	ctx := context.Background()
	ad := &server_structs.OriginAdvertiseV2{
		ServerBaseAd: server_structs.ServerBaseAd{
			Name:         "svc-name",
			InstanceID:   "inst-id",
			StartTime:    12345,
			GenerationID: 1,
			Version:      "v1",
			Expiration:   time.Unix(67890, 0).UTC(),
		},
		DataURL: "http://data-url",
	}

	ch := make(chan *forwardAdInfo, 1)
	dir := &directorInfo{forwardAdChan: ch}

	dir.forwardService(ctx, ad, server_structs.OriginType, nil)

	info := <-ch
	assert.Equal(t, ad.Name, info.key)
	assert.Equal(t, server_structs.OriginType, info.adType)
	assert.Equal(t, ad.Name, info.serverBase.Name)
	assert.Equal(t, ad.InstanceID, info.serverBase.InstanceID)
	assert.Equal(t, ad.StartTime, info.serverBase.StartTime)
	assert.Equal(t, ad.GenerationID, info.serverBase.GenerationID)
	assert.Equal(t, ad.Version, info.serverBase.Version)
	assert.Equal(t, ad.Expiration, info.serverBase.Expiration)

	data, err := io.ReadAll(info.contents)
	require.NoError(t, err)

	var fwd forwardAd
	require.NoError(t, json.Unmarshal(data, &fwd))
	assert.Equal(t, viper.GetString(param.Director_AdvertiseUrl.GetName()), fwd.DirectorAd.AdvertiseUrl)
	assert.Equal(t, server_structs.OriginType.String(), fwd.AdType)
	assert.False(t, fwd.Now.IsZero())
	assert.Equal(t, ad, fwd.ServiceAd)
}

// TestForwardServiceAd tests that we forward the service ad to the correct director
// We have two directors, each with different advertise urls
// We have a service ad that should be only forwarded to the director that is not itself
func TestForwardServiceAd(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	directorAds.DeleteAll()
	t.Cleanup(func() {
		directorAds.DeleteAll()
	})

	require.NoError(t, param.Server_ExternalWebUrl.Set("http://director1.com"))

	ch1 := make(chan *forwardAdInfo, 1)
	dir1 := &directorInfo{
		ad: &server_structs.DirectorAd{
			AdvertiseUrl: "http://director-ad-url-1",
			ServerBaseAd: server_structs.ServerBaseAd{
				Name:         "dir1",
				InstanceID:   "inst-id-1",
				StartTime:    12345,
				GenerationID: 1,
				Version:      "v1",
			},
		},
		forwardAdChan: ch1,
	}

	ch2 := make(chan *forwardAdInfo, 1)
	dir2 := &directorInfo{
		ad: &server_structs.DirectorAd{
			AdvertiseUrl: "http://director-ad-url-2",
			ServerBaseAd: server_structs.ServerBaseAd{
				Name:         "dir2",
				InstanceID:   "inst-id-2",
				StartTime:    12345,
				GenerationID: 1,
				Version:      "v1",
			},
		},
		forwardAdChan: ch2,
	}

	directorAds.Set("dir1", dir1, 15*time.Minute)
	directorAds.Set("dir2", dir2, 15*time.Minute)

	// Build a fake service ad
	svcAd := &server_structs.OriginAdvertiseV2{
		ServerBaseAd: server_structs.ServerBaseAd{
			Name:         "svc-name",
			InstanceID:   "inst-id",
			StartTime:    12345,
			GenerationID: 1,
			Version:      "v1",
			Expiration:   time.Unix(67890, 0).UTC(),
		},
	}

	ctx := context.Background()
	forwardServiceAd(ctx, svcAd, server_structs.OriginType, []string{dir1.ad.Name})

	// We should have received an ad on channel 2 but not channel 1
	select {
	case adInfo := <-ch1:
		assert.Fail(t, "Received an ad on channel 1 but it should have been skipped", adInfo.serverBase)
	default:
	}

	select {
	case adInfo := <-ch2: // We should have received an ad on channel 2
		assert.Equal(t, svcAd.ServerBaseAd, adInfo.serverBase)
	default:
		assert.Fail(t, "Failed to receive an ad on channel 2")
	}
}

// TestForwardServiceAdSeenByPreventsLoop tests that the seenBy list prevents
// infinite forwarding loops with 3+ directors. When a service ad has already
// been seen by directors A and B, it should not be forwarded to either of them.
func TestForwardServiceAdSeenByPreventsLoop(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	directorAds.DeleteAll()
	t.Cleanup(func() {
		directorAds.DeleteAll()
	})

	require.NoError(t, param.Server_ExternalWebUrl.Set("http://director1.com"))

	ch1 := make(chan *forwardAdInfo, 1)
	dir1 := &directorInfo{
		ad: &server_structs.DirectorAd{
			AdvertiseUrl: "http://director-ad-url-1",
			ServerBaseAd: server_structs.ServerBaseAd{
				Name:         "dir1",
				InstanceID:   "inst-id-1",
				StartTime:    12345,
				GenerationID: 1,
				Version:      "v1",
			},
		},
		forwardAdChan: ch1,
	}

	ch2 := make(chan *forwardAdInfo, 1)
	dir2 := &directorInfo{
		ad: &server_structs.DirectorAd{
			AdvertiseUrl: "http://director-ad-url-2",
			ServerBaseAd: server_structs.ServerBaseAd{
				Name:         "dir2",
				InstanceID:   "inst-id-2",
				StartTime:    12345,
				GenerationID: 1,
				Version:      "v1",
			},
		},
		forwardAdChan: ch2,
	}

	ch3 := make(chan *forwardAdInfo, 1)
	dir3 := &directorInfo{
		ad: &server_structs.DirectorAd{
			AdvertiseUrl: "http://director-ad-url-3",
			ServerBaseAd: server_structs.ServerBaseAd{
				Name:         "dir3",
				InstanceID:   "inst-id-3",
				StartTime:    12345,
				GenerationID: 1,
				Version:      "v1",
			},
		},
		forwardAdChan: ch3,
	}

	directorAds.Set("dir1", dir1, 15*time.Minute)
	directorAds.Set("dir2", dir2, 15*time.Minute)
	directorAds.Set("dir3", dir3, 15*time.Minute)

	svcAd := &server_structs.OriginAdvertiseV2{
		ServerBaseAd: server_structs.ServerBaseAd{
			Name:         "svc-name",
			InstanceID:   "inst-id",
			StartTime:    12345,
			GenerationID: 1,
			Version:      "v1",
			Expiration:   time.Unix(67890, 0).UTC(),
		},
	}

	ctx := context.Background()

	// Simulate: dir1 received the ad from the origin and already forwarded.
	// Now dir2 receives the forwarded ad and tries to re-forward.
	// seenBy contains dir1 (the origin's first director) and dir2 (current).
	// Only dir3 should receive the forwarded ad.
	forwardServiceAd(ctx, svcAd, server_structs.OriginType, []string{"dir1", "dir2"})

	select {
	case adInfo := <-ch1:
		assert.Fail(t, "dir1 is in seenBy but received a forwarded ad", adInfo.serverBase)
	default:
	}

	select {
	case adInfo := <-ch2:
		assert.Fail(t, "dir2 is in seenBy but received a forwarded ad", adInfo.serverBase)
	default:
	}

	select {
	case adInfo := <-ch3:
		assert.Equal(t, svcAd.ServerBaseAd, adInfo.serverBase)
	default:
		assert.Fail(t, "dir3 should have received the forwarded ad but did not")
	}
}

// TestForwardServiceAdSimulation exhaustively simulates the forwarding chain
// for 2 through 7 directors, verifying that the seenBy mechanism causes
// convergence with the expected round and message counts.
//
// For N directors in a fully connected topology, a service ad registered at
// one director propagates via flood-forward. Each director adds itself to
// seenBy before re-forwarding, so the process terminates in exactly N rounds
// (the last producing 0 messages) with a predictable total message count:
//
//	Total = Σ_{k=0}^{N-2} (N-1)!/(N-1-k)!
func TestForwardServiceAdSimulation(t *testing.T) {
	// expectedMessages returns the total forwarded messages for n directors.
	expectedMessages := func(n int) int {
		total, hop := 0, 1
		for k := 0; k < n-1; k++ {
			hop *= (n - 1 - k)
			total += hop
		}
		return total
	}

	tests := []struct {
		numDirectors     int
		expectedRounds   int
		expectedMessages int
	}{
		{numDirectors: 2, expectedRounds: 2, expectedMessages: expectedMessages(2)}, // 1
		{numDirectors: 3, expectedRounds: 3, expectedMessages: expectedMessages(3)}, // 4
		{numDirectors: 4, expectedRounds: 4, expectedMessages: expectedMessages(4)}, // 15
		{numDirectors: 5, expectedRounds: 5, expectedMessages: expectedMessages(5)}, // 64
		{numDirectors: 6, expectedRounds: 6, expectedMessages: expectedMessages(6)}, // 325
		{numDirectors: 7, expectedRounds: 7, expectedMessages: expectedMessages(7)}, // 1956
	}

	for _, tc := range tests {
		t.Run("directors="+strconv.Itoa(tc.numDirectors), func(t *testing.T) {
			config.ResetConfig()
			t.Cleanup(config.ResetConfig)
			directorNameOnce = sync.Once{}
			directorNameError = nil
			directorName = ""
			directorNameOnce.Do(func() {})
			t.Cleanup(func() {
				directorNameOnce = sync.Once{}
				directorName = ""
				directorNameError = nil
			})

			directorAds.DeleteAll()
			t.Cleanup(func() {
				directorAds.DeleteAll()
			})

			require.NoError(t, param.Server_ExternalWebUrl.Set("http://test-self.example.com"))

			n := tc.numDirectors
			names := make([]string, n)
			for i := range names {
				names[i] = "dir" + strconv.Itoa(i+1)
			}

			channels := make(map[string]chan *forwardAdInfo, n)
			for _, name := range names {
				ch := make(chan *forwardAdInfo, 1000)
				channels[name] = ch
				info := &directorInfo{
					ad: &server_structs.DirectorAd{
						AdvertiseUrl: "http://" + name + ".example.com",
						ServerBaseAd: server_structs.ServerBaseAd{
							Name:         name,
							InstanceID:   "inst-" + name,
							StartTime:    12345,
							GenerationID: 1,
							Version:      "v1",
						},
					},
					forwardAdChan: ch,
				}
				directorAds.Set(name, info, 15*time.Minute)
			}

			svcAd := &server_structs.OriginAdvertiseV2{
				ServerBaseAd: server_structs.ServerBaseAd{
					Name:         "origin-1",
					InstanceID:   "origin-inst",
					StartTime:    12345,
					GenerationID: 1,
					Version:      "v1",
					Expiration:   time.Unix(67890, 0).UTC(),
				},
			}

			ctx := context.Background()

			type pendingForward struct {
				receiver string
				seenBy   []string
			}

			queue := []pendingForward{{receiver: names[0], seenBy: nil}}
			totalMessages := 0
			received := make(map[string]bool, n)
			round := 0

			for len(queue) > 0 {
				round++
				require.LessOrEqual(t, round, n+1, "forwarding did not terminate")

				for _, pf := range queue {
					directorName = pf.receiver
					forwardServiceAd(ctx, svcAd, server_structs.OriginType, pf.seenBy)
				}

				var nextQueue []pendingForward
				for _, name := range names {
					ch := channels[name]
				drain:
					for {
						select {
						case info := <-ch:
							totalMessages++
							received[name] = true
							data, err := io.ReadAll(info.contents)
							require.NoError(t, err)
							var fwd forwardAd
							require.NoError(t, json.Unmarshal(data, &fwd))
							nextQueue = append(nextQueue, pendingForward{
								receiver: name,
								seenBy:   fwd.SeenBy,
							})
						default:
							break drain
						}
					}
				}
				queue = nextQueue
			}

			assert.Equal(t, tc.expectedRounds, round, "unexpected number of rounds")
			assert.Equal(t, tc.expectedMessages, totalMessages, "unexpected total messages")

			for _, name := range names[1:] {
				assert.True(t, received[name], "director %s never received the ad", name)
			}
		})
	}
}

// TestForwardServiceSeenBySerialized verifies that the seenBy list is included
// in the serialized JSON payload sent to remote directors.
func TestForwardServiceSeenBySerialized(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	directorNameOnce = sync.Once{}
	directorName = ""
	directorNameError = nil

	require.NoError(t, param.Director_AdvertiseUrl.Set("http://director-ad-url"))
	require.NoError(t, param.Server_ExternalWebUrl.Set("http://external-url"))

	ctx := context.Background()
	ad := &server_structs.OriginAdvertiseV2{
		ServerBaseAd: server_structs.ServerBaseAd{
			Name:         "svc-name",
			InstanceID:   "inst-id",
			StartTime:    12345,
			GenerationID: 1,
			Version:      "v1",
			Expiration:   time.Unix(67890, 0).UTC(),
		},
		DataURL: "http://data-url",
	}

	ch := make(chan *forwardAdInfo, 1)
	dir := &directorInfo{forwardAdChan: ch}

	seenBy := []string{"dirA", "dirB"}
	dir.forwardService(ctx, ad, server_structs.OriginType, seenBy)

	info := <-ch
	data, err := io.ReadAll(info.contents)
	require.NoError(t, err)

	var fwd forwardAd
	require.NoError(t, json.Unmarshal(data, &fwd))
	assert.Equal(t, seenBy, fwd.SeenBy)
}
