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
	"bytes"
	"context"
	_ "embed"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/features"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// Geo Override Yaml mockup
//
//go:embed resources/geoip_overrides.yaml
var yamlMockup string

func TestCheckOverrides(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(func() {
		server_utils.ResetTestState()
		geoNetOverrides = nil
	})

	// We'll also check that our logging feature responsibly reports
	// what Pelican is telling the user.
	origOutput := log.StandardLogger().Out
	logOutput := &(bytes.Buffer{})
	log.SetOutput(logOutput)
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetOutput(origOutput)
	})

	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(yamlMockup))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	t.Run("test-no-ipv4-match", func(t *testing.T) {
		// In the event that no override is detected, `checkOverrides` should return a nil override
		addr := net.ParseIP("192.168.0.2")
		coordinate := checkOverrides(addr)
		require.Nil(t, coordinate)
	})

	t.Run("test-no-ipv6-match", func(t *testing.T) {
		addr := net.ParseIP("ABCD::0123")
		coordinate := checkOverrides(addr)
		require.Nil(t, coordinate)
	})

	t.Run("test-log-output", func(t *testing.T) {
		// Check that the log caught our malformed IP and CIDR. We only need to test this once, because it is only logged the very first time.
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride address (192.168.0). Unable to use for GeoIP resolution!")
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride address (10.0.0./24). Unable to use for GeoIP resolution!")
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride address (FD00::000G). Unable to use for GeoIP resolution!")
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride address (FD00::000F/11S). Unable to use for GeoIP resolution!")
	})

	t.Run("test-ipv4-match", func(t *testing.T) {
		// When we match against a regular IPv4, we expect a non-nil coordinate
		expectedCoordinate := Coordinate{
			Lat:  123.4,
			Long: 987.6,
		}

		addr := net.ParseIP("192.168.0.1")
		require.NotNil(t, addr)
		coordinate := checkOverrides(addr)
		require.NotNil(t, coordinate)
		require.Equal(t, expectedCoordinate.Lat, coordinate.Lat)
		require.Equal(t, expectedCoordinate.Long, coordinate.Long)
	})

	t.Run("test-ipv4-CIDR-match", func(t *testing.T) {
		// Same goes for CIDR matches
		expectedCoordinate := Coordinate{
			Lat:  43.073904,
			Long: -89.384859,
		}

		addr := net.ParseIP("10.0.0.136")
		require.NotNil(t, addr)
		coordinate := checkOverrides(addr)
		require.NotNil(t, coordinate)
		require.Equal(t, expectedCoordinate.Lat, coordinate.Lat)
		require.Equal(t, expectedCoordinate.Long, coordinate.Long)
	})

	t.Run("test-ipv6-match", func(t *testing.T) {
		expectedCoordinate := Coordinate{
			Lat:  123.4,
			Long: 987.6,
		}

		addr := net.ParseIP("FC00::0001")
		require.NotNil(t, addr)
		coordinate := checkOverrides(addr)
		require.NotNil(t, coordinate)
		require.Equal(t, expectedCoordinate.Lat, coordinate.Lat)
		require.Equal(t, expectedCoordinate.Long, coordinate.Long)
	})

	t.Run("test-ipv6-CIDR-match", func(t *testing.T) {
		expectedCoordinate := Coordinate{
			Lat:  43.073904,
			Long: -89.384859,
		}

		addr := net.ParseIP("FD00::FA1B")
		assert.NotNil(t, addr)
		coordinate := checkOverrides(addr)
		require.NotNil(t, coordinate)
		require.Equal(t, expectedCoordinate.Lat, coordinate.Lat)
		require.Equal(t, expectedCoordinate.Long, coordinate.Long)
	})
}

func TestSortServerAdsByTopo(t *testing.T) {
	mock1 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: true,
		},
	}
	mock1.ServerAd.Initialize("alpha")
	mock2 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: true,
		},
	}
	mock2.ServerAd.Initialize("bravo")
	mock3 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: true,
		},
	}
	mock3.ServerAd.Initialize("charlie")
	mock4 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
		},
	}
	mock4.ServerAd.Initialize("alpha")
	mock5 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
		},
	}
	mock5.ServerAd.Initialize("bravo")
	mock6 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
		},
	}
	mock6.ServerAd.Initialize("charlie")

	randomList := []*server_structs.Advertisement{&mock6, &mock1, &mock2, &mock4, &mock5, &mock3}
	expectedList := []*server_structs.Advertisement{&mock4, &mock5, &mock6, &mock1, &mock2, &mock3}

	sortedList := sortServerAdsByTopo(randomList)

	assert.EqualValues(t, expectedList, sortedList)
}

// Helper function for adaptive sort that finds the average index of a server in a sorted list
func calcAvgIndex(counts []int) float64 {
	totalAppearances := 0
	weightedSum := 0

	for index, count := range counts {
		weightedSum += index * count
		totalAppearances += count
	}

	if totalAppearances > 0 {
		return float64(weightedSum) / float64(totalAppearances)
	} else {
		return 0.0
	}
}

// Helper func for adaptive sort to check that the calculated avg index is in the expected range
func inRange(min float64, max float64, val float64) bool {
	return val >= min && val <= max
}

func TestSortServerAds(t *testing.T) {
	server_utils.ResetTestState()
	clientIpCache.DeleteAll()
	t.Cleanup(func() {
		server_utils.ResetTestState()
		clientIpCache.DeleteAll()
		geoNetOverrides = nil
	})

	// A random IP that should geo-resolve to roughly the same location as the Madison server
	clientIP := netip.MustParseAddr("128.104.153.60")
	// We need to provide a geo-ip override so that our sorting functions know where this is located
	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(yamlMockup))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	// These are listed in order of increasing distance from the clientIP
	madisonServer := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "madison-cache.org"},
		Latitude:  43.0753,
		Longitude: -89.4114,
	}
	madisonServer.Initialize("madison server")
	sdscServer := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "sdsc-cache.org"},
		Latitude:  32.8761,
		Longitude: -117.2318,
	}
	sdscServer.Initialize("sdsc server")
	bigBenServer := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "bigBen-cache.org"},
		Latitude:  51.5103,
		Longitude: -0.1167,
	}
	bigBenServer.Initialize("bigBen server")
	kremlinServer := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "kremlin-cache.org"},
		Latitude:  55.752121,
		Longitude: 37.617664,
	}
	kremlinServer.Initialize("kremlin server")
	daejeonServer := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "daejeon-cache.org"},
		Latitude:  36.3213,
		Longitude: 127.4200,
	}
	daejeonServer.Initialize("daejeon server")
	mcMurdoServer := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "mcMurdo-cache.org"},
		Latitude:  -77.8500,
		Longitude: 166.6666,
	}
	mcMurdoServer.Initialize("mcMurdo server")
	nullIslandServer := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "null-cache.org"},
		Latitude:  0.0,
		Longitude: 0.0,
	}
	nullIslandServer.Initialize("Null Island Server")

	// Mock servers with same geolocation but different loads
	serverLoad1 := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "server1.org"},
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    0.0,
	}
	serverLoad1.Initialize("load1")

	serverLoad2 := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "server2.org"},
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    10.2,
	}
	serverLoad2.Initialize("load2")

	serverLoad3 := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "server3.org"},
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    14,
	}
	serverLoad3.Initialize("load3")

	serverLoad4 := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "server4.org"},
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    60.3,
	}
	serverLoad4.Initialize("load4")

	serverLoad5NullLoc := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "server5.org"},
		Latitude:  0.0,
		Longitude: 0.0,
		IOLoad:    10.0,
	}
	serverLoad5NullLoc.Initialize("load5NullLoc")

	serverLoad6NullLoc := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "server6.org"},
		Latitude:  0.0,
		Longitude: 0.0,
		IOLoad:    99.0,
	}
	serverLoad6NullLoc.Initialize("load6NullLoc")

	// These are listed in order of increasing distance from the clientIP
	// However, madison server is overloaded and bigBenServer has very high load
	madisonServerHighLoad := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "madison-cache.org"},
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    100.4,
	}
	madisonServerHighLoad.Initialize("madison high load")
	chicagoLowload := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "chicago-cache.org"},
		Latitude:  41.789722,
		Longitude: -87.599724,
		IOLoad:    10,
	}
	chicagoLowload.Initialize("chicago low load")
	bigBenServerHighLoad := server_structs.ServerAd{
		URL:       url.URL{Scheme: "https", Host: "bigben-highload.org"},
		Latitude:  51.5103,
		Longitude: -0.1167,
		IOLoad:    65.7,
	}
	bigBenServerHighLoad.Initialize("big ben high load")

	randAds := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer,
		daejeonServer, mcMurdoServer, nullIslandServer}

	randLoadAds := []server_structs.ServerAd{serverLoad6NullLoc, serverLoad4, serverLoad1, serverLoad3, serverLoad2}

	randDistanceLoadAds := []server_structs.ServerAd{
		madisonServerHighLoad,
		chicagoLowload,
		sdscServer,
		bigBenServerHighLoad,
		kremlinServer,
		daejeonServer,
		mcMurdoServer,
		serverLoad5NullLoc,
		serverLoad6NullLoc,
	}

	// Shuffle so that we don't give the sort function an already-sorted slice!
	rand.Shuffle(len(randAds), func(i, j int) {
		randAds[i], randAds[j] = randAds[j], randAds[i]
	})

	t.Run("test-distance-sort", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "distance")
		rInfo := server_structs.NewRedirectInfoFromIP(clientIP.String())
		expected := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer,
			daejeonServer, mcMurdoServer, nullIslandServer}
		ctx := context.Background()
		ctx = context.WithValue(ctx, ProjectContextKey{}, "pelican-client/1.0.0 project/test")
		sorted, err := sortServerAds(ctx, clientIP, randAds, nil, rInfo)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
		assert.True(t, rInfo.ClientInfo.Resolved)
		assert.Equal(t, rInfo.ClientInfo.Lat, 43.073904)
		assert.Equal(t, rInfo.ClientInfo.Lon, -89.384859)
		assert.Equal(t, rInfo.ClientInfo.IpAddr, "128.104.153.60")
		assert.Equal(t, len(randAds), len(rInfo.ServersInfo))
	})

	t.Run("test-distanceAndLoad-sort-distance-only", func(t *testing.T) {
		// Should return the same ordering as the distance test
		viper.Set("Director.CacheSortMethod", "distanceAndLoad")
		rInfo := server_structs.NewRedirectInfoFromIP(clientIP.String())
		expected := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer,
			daejeonServer, mcMurdoServer, nullIslandServer}
		ctx := context.Background()
		ctx = context.WithValue(ctx, ProjectContextKey{}, "pelican-client/1.0.0 project/test")
		sorted, err := sortServerAds(ctx, clientIP, randAds, nil, rInfo)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
		assert.True(t, rInfo.ClientInfo.Resolved)
		assert.Equal(t, rInfo.ClientInfo.Lat, 43.073904)
		assert.Equal(t, rInfo.ClientInfo.Lon, -89.384859)
		assert.Equal(t, rInfo.ClientInfo.IpAddr, "128.104.153.60")
		assert.Equal(t, len(randAds), len(rInfo.ServersInfo))
	})

	t.Run("test-distanceAndLoad-sort-load-only", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "distanceAndLoad")
		rInfo := server_structs.NewRedirectInfoFromIP(clientIP.String())
		expected := []server_structs.ServerAd{serverLoad1, serverLoad2, serverLoad3, serverLoad4, serverLoad6NullLoc}
		ctx := context.Background()
		ctx = context.WithValue(ctx, ProjectContextKey{}, "pelican-client/1.0.0 project/test")
		sorted, err := sortServerAds(ctx, clientIP, randLoadAds, nil, rInfo)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
		assert.True(t, rInfo.ClientInfo.Resolved)
		assert.Equal(t, rInfo.ClientInfo.Lat, 43.073904)
		assert.Equal(t, rInfo.ClientInfo.Lon, -89.384859)
		assert.Equal(t, rInfo.ClientInfo.IpAddr, "128.104.153.60")
		assert.Equal(t, len(randLoadAds), len(rInfo.ServersInfo))
		// Now that we have load information in the input servers, check
		// that rInfo is receiving the correct values for a few of them
		assert.Equal(t, serverLoad1.IOLoad, rInfo.ServersInfo[serverLoad1.URL.String()].LoadWeight)
		assert.Equal(t, serverLoad2.IOLoad, rInfo.ServersInfo[serverLoad2.URL.String()].LoadWeight)
		assert.Equal(t, serverLoad3.IOLoad, rInfo.ServersInfo[serverLoad3.URL.String()].LoadWeight)
	})

	t.Run("test-distanceAndLoad-sort-distance-and-load", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "distanceAndLoad")
		rInfo := server_structs.NewRedirectInfoFromIP(clientIP.String())
		expected := []server_structs.ServerAd{chicagoLowload, sdscServer, madisonServerHighLoad, kremlinServer,
			daejeonServer, mcMurdoServer, bigBenServerHighLoad, serverLoad5NullLoc, serverLoad6NullLoc}

		ctx := context.Background()
		ctx = context.WithValue(ctx, ProjectContextKey{}, "pelican-client/1.0.0 project/test")
		sorted, err := sortServerAds(ctx, clientIP, randDistanceLoadAds, nil, rInfo)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
		assert.True(t, rInfo.ClientInfo.Resolved)
		assert.Equal(t, rInfo.ClientInfo.Lat, 43.073904)
		assert.Equal(t, rInfo.ClientInfo.Lon, -89.384859)
		assert.Equal(t, rInfo.ClientInfo.IpAddr, "128.104.153.60")
		assert.Equal(t, len(randDistanceLoadAds), len(rInfo.ServersInfo))
		assert.Equal(t, chicagoLowload.IOLoad, rInfo.ServersInfo[chicagoLowload.URL.String()].LoadWeight)
		assert.Equal(t, sdscServer.IOLoad, rInfo.ServersInfo[sdscServer.URL.String()].LoadWeight)
		assert.Equal(t, bigBenServerHighLoad.IOLoad, rInfo.ServersInfo[bigBenServerHighLoad.URL.String()].LoadWeight)
	})

	t.Run("test-adaptive-sort", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "adaptive")
		rInfo := server_structs.NewRedirectInfoFromIP(clientIP.String())

		ctx := context.Background()
		ctx = context.WithValue(ctx, ProjectContextKey{}, "pelican-client/1.0.0 project/test")

		// Set up which servers are known to have the object, and which are known to not have it
		// Servers not in the map are assumed to have an unknown status
		availMap := map[string]bool{}
		availMap[chicagoLowload.URL.String()] = true
		availMap[sdscServer.URL.String()] = true
		availMap[madisonServerHighLoad.URL.String()] = false
		availMap[kremlinServer.URL.String()] = false

		// A map for keeping track of how many times each server appears in a sorted position.
		// This strategy lets us deal with some of the stochastic jiggle in the adaptive sort
		// algorithm by observing trends over many iterations.
		serverSortCounter := make(map[string][]int)
		for _, ad := range randDistanceLoadAds {
			serverSortCounter[ad.Name] = make([]int, serverResLimit)
		}

		// Run the sort 1000 times to get a good idea of how the servers are being sorted
		for range 1000 {
			sorted, err := sortServerAds(ctx, clientIP, randDistanceLoadAds, availMap, rInfo)
			require.NoError(t, err)

			for pos, s := range sorted {
				serverSortCounter[s.Name][pos]++
			}
		}

		// Due to the very stochastic nature of this test, it's difficult to predict which servers will be in the
		// output list, let alone their order. Instead, we notice that chicago and sdsc should have a strong preference
		// for spots 1/2 because they have the object and are (relatively) close to Madison. The rest are much less predictable.
		// Until we've convinced ourselves that we actually like the magic values in adaptive sort, I (Justin H.) don't think
		// we should spend too much time trying to make this test more rigorous.
		// TODO: When we understand adaptive sort better and can make assertions about how these servers should be sorted,
		//       come back and make this test more rigorous
		assert.True(t, inRange(0, 1, calcAvgIndex(serverSortCounter[chicagoLowload.Name])))
		assert.True(t, inRange(0.5, 1.5, calcAvgIndex(serverSortCounter[sdscServer.Name])))
		assert.True(t, rInfo.ClientInfo.Resolved)
		assert.Equal(t, rInfo.ClientInfo.Lat, 43.073904)
		assert.Equal(t, rInfo.ClientInfo.Lon, -89.384859)
		assert.Equal(t, rInfo.ClientInfo.IpAddr, "128.104.153.60")
		assert.Equal(t, len(randDistanceLoadAds), len(rInfo.ServersInfo))
		assert.Equal(t, chicagoLowload.IOLoad, rInfo.ServersInfo[chicagoLowload.URL.String()].LoadWeight)
		assert.Equal(t, sdscServer.IOLoad, rInfo.ServersInfo[sdscServer.URL.String()].LoadWeight)
		assert.Equal(t, bigBenServerHighLoad.IOLoad, rInfo.ServersInfo[bigBenServerHighLoad.URL.String()].LoadWeight)
		assert.Equal(t, "true", rInfo.ServersInfo[chicagoLowload.URL.String()].HasObject)
		assert.Equal(t, "true", rInfo.ServersInfo[sdscServer.URL.String()].HasObject)
		assert.Equal(t, "false", rInfo.ServersInfo[madisonServerHighLoad.URL.String()].HasObject)
		assert.Equal(t, "false", rInfo.ServersInfo[kremlinServer.URL.String()].HasObject)
		assert.Equal(t, "unknown", rInfo.ServersInfo[daejeonServer.URL.String()].HasObject)
		assert.Equal(t, "unknown", rInfo.ServersInfo[mcMurdoServer.URL.String()].HasObject)
	})

	t.Run("test-random-sort", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "random")

		var sorted []server_structs.ServerAd
		var err error

		// We don't expect to get back the sorted slice, but it's possible
		notExpected := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer, daejeonServer,
			mcMurdoServer}

		ctx := context.Background()
		ctx = context.WithValue(ctx, ProjectContextKey{}, "pelican-client/1.0.0 project/test")
		// The probability this test fails the first time due to randomly sorting into ascending distances is (1/6!) = 1/720
		// To mitigate risk of this failing because of that, we'll run the sort 3 times to get a 1/720^3 = 1/373,248,000 chance
		// of failure. If you run thrice and you still get the distance-sorted slice, you might consider buying a powerball ticket
		// (1/292,201,338 chance of winning).
		for range 3 {
			redirectInfo := server_structs.NewRedirectInfoFromIP(clientIP.String())
			sorted, err = sortServerAds(ctx, clientIP, randAds, nil, redirectInfo)
			require.NoError(t, err)

			// If the values are not equal, break the loop
			if !reflect.DeepEqual(notExpected, sorted) {
				break
			}
		}

		assert.NotEqualValues(t, notExpected, sorted)
	})

	t.Run("test-status-weight-sort", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "adaptive")

		// Pin all other factors used in adaptive sorting to isolate the status weight factor.
		sAds := []server_structs.ServerAd{
			{StatusWeight: 0.5, IOLoad: 1.0, Latitude: 32.8761, Longitude: -117.2318},
			{StatusWeight: 0.2, IOLoad: 1.0, Latitude: 32.8761, Longitude: -117.2318},
			{StatusWeight: 0.8, IOLoad: 1.0, Latitude: 32.8761, Longitude: -117.2318},
		}

		ctx := context.Background()
		ctx = context.WithValue(ctx, ProjectContextKey{}, "pelican-client/1.0.0 project/test")
		redirectInfo := server_structs.NewRedirectInfoFromIP(clientIP.String())
		require.NoError(t, err)

		// To get around stochastic jiggle, run the test multiple times and grab average indices
		iters := 1000
		positionCounts := make([][]int, len(sAds))
		for i := range positionCounts {
			positionCounts[i] = make([]int, len(sAds))
		}

		for range iters {
			sorted, err := sortServerAds(ctx, clientIP, sAds, nil, redirectInfo)
			require.NoError(t, err)
			for pos, ad := range sorted {
				if ad.StatusWeight == 0.8 {
					// These indices correspond to the initial ad values
					// and how they should be sorted
					positionCounts[2][pos]++
				} else if ad.StatusWeight == 0.5 {
					positionCounts[0][pos]++
				} else {
					positionCounts[1][pos]++
				}
			}
		}

		// Calculate the average index for each ad
		avgsPos := make([]float64, len(sAds))
		for i, counts := range positionCounts {
			for j, count := range counts {
				avgsPos[i] += float64(j) * float64(count)
			}

			avgsPos[i] /= float64(iters)
		}

		// Now assert the ordering: lower average index means higher position
		assert.Less(t, avgsPos[2], avgsPos[0], "Status weight 0.8 should be sorted higher than 0.5")
		assert.Less(t, avgsPos[0], avgsPos[1], "Status weight 0.5 should be sorted higher than 0.2")
	})
}

func TestSortServerAdsByAvailability(t *testing.T) {
	firstUrl := url.URL{Host: "first.org", Scheme: "https"}
	secondUrl := url.URL{Host: "second.org", Scheme: "https"}
	thirdUrl := url.URL{Host: "third.org", Scheme: "https"}
	fourthUrl := url.URL{Host: "fourth.org", Scheme: "https"}

	firstServer := server_structs.ServerAd{URL: firstUrl}
	secondServer := server_structs.ServerAd{URL: secondUrl}
	thirdServer := server_structs.ServerAd{URL: thirdUrl}
	fourthServer := server_structs.ServerAd{URL: fourthUrl}

	randomOrder := []server_structs.ServerAd{thirdServer, firstServer, fourthServer, secondServer}
	expected := []server_structs.ServerAd{firstServer, secondServer, thirdServer, fourthServer}
	avaiMap := map[string]bool{}
	avaiMap[firstUrl.String()] = true
	avaiMap[secondUrl.String()] = true
	avaiMap[thirdUrl.String()] = false
	avaiMap[fourthUrl.String()] = false

	sortServerAdsByAvailability(randomOrder, avaiMap)
	assert.EqualValues(t, expected, randomOrder)
}

func TestAssignRandBoundedCoord(t *testing.T) {
	// Because of the test's randomness, do it a few times to increase the likelihood of catching errors
	for i := 0; i < 10; i++ {
		// Generate a random bounding box between -200, 200
		lat1 := rand.Float64()*400 - 200
		long1 := rand.Float64()*400 - 200
		lat2 := rand.Float64()*400 - 200
		long2 := rand.Float64()*400 - 200

		// Assign mins and maxes
		minLat, maxLat := math.Min(lat1, lat2), math.Max(lat1, lat2)
		minLong, maxLong := math.Min(long1, long2), math.Max(long1, long2)

		// Assign a random coordinate within the bounding box
		lat, long := assignRandBoundedCoord(minLat, maxLat, minLong, maxLong)
		assert.True(t, lat >= minLat && lat <= maxLat)
		assert.True(t, long >= minLong && long <= maxLong)
	}
}

func TestGetClientLatLong(t *testing.T) {
	// The cache may be populated from previous tests. Wipe it out and start fresh.
	clientIpCache.DeleteAll()
	defer clientIpCache.DeleteAll()
	t.Run("invalid-ip", func(t *testing.T) {
		// Capture the log and check that the correct error is logged
		origOutput := log.StandardLogger().Out
		logOutput := &(bytes.Buffer{})
		log.SetOutput(logOutput)
		log.SetLevel(log.DebugLevel)
		defer func() {
			log.SetOutput(origOutput)
		}()

		clientIp := netip.Addr{}
		assert.False(t, clientIpCache.Has(clientIp))
		rInfo := server_structs.NewRedirectInfoFromIP(clientIp.String())
		coord1, _ := getClientLatLong(clientIp, rInfo)

		assert.True(t, coord1.Lat <= usLatMax && coord1.Lat >= usLatMin)
		assert.True(t, coord1.Long <= usLongMax && coord1.Long >= usLongMin)
		assert.False(t, rInfo.ClientInfo.Resolved)
		assert.False(t, rInfo.ClientInfo.FromTTLCache)
		assert.Contains(t, logOutput.String(), "Unable to sort servers based on client-server distance. Invalid client IP address")
		assert.NotContains(t, logOutput.String(), "Using randomly-assigned lat/long")

		// Get it again to make sure it's coming from the cache
		coord2, _ := getClientLatLong(clientIp, rInfo)
		assert.Equal(t, coord1.Lat, coord2.Lat)
		assert.Equal(t, coord1.Long, coord2.Long)
		assert.False(t, rInfo.ClientInfo.Resolved)
		assert.True(t, rInfo.ClientInfo.FromTTLCache)
		assert.Contains(t, logOutput.String(), "Using randomly-assigned lat/long for unresolved client IP")
		assert.True(t, clientIpCache.Has(clientIp))
	})

	t.Run("valid-ip-no-geoip-match", func(t *testing.T) {
		logOutput := &(bytes.Buffer{})
		origOutput := log.StandardLogger().Out
		log.SetOutput(logOutput)
		log.SetLevel(log.DebugLevel)
		defer func() {
			log.SetOutput(origOutput)
		}()

		clientIp := netip.MustParseAddr("192.168.0.1")
		assert.False(t, clientIpCache.Has(clientIp))
		rInfo := server_structs.NewRedirectInfoFromIP(clientIp.String())
		coord1, _ := getClientLatLong(clientIp, rInfo)

		assert.True(t, coord1.Lat <= usLatMax && coord1.Lat >= usLatMin)
		assert.True(t, coord1.Long <= usLongMax && coord1.Long >= usLongMin)
		assert.False(t, rInfo.ClientInfo.Resolved)
		assert.False(t, rInfo.ClientInfo.FromTTLCache)
		assert.Contains(t, logOutput.String(), "Client IP 192.168.0.1 has been re-assigned a random location in the contiguous US to lat/long")
		assert.NotContains(t, logOutput.String(), "Using randomly-assigned lat/long")

		// Get it again to make sure it's coming from the cache
		coord2, _ := getClientLatLong(clientIp, rInfo)
		assert.Equal(t, coord1.Lat, coord2.Lat)
		assert.Equal(t, coord1.Long, coord2.Long)
		assert.False(t, rInfo.ClientInfo.Resolved)
		assert.True(t, rInfo.ClientInfo.FromTTLCache)
		assert.Contains(t, logOutput.String(), "Using randomly-assigned lat/long for client IP")
		assert.True(t, clientIpCache.Has(clientIp))
	})
}

func hasServerAdWithName(ads []copyAd, name string) bool {
	for _, ad := range ads {
		if ad.ServerAd.Name == name {
			return true
		}
	}
	return false
}

// Test getAdsForPath to make sure various nuanced cases work. Under the hood
// this really tests matchesPrefix, but we test this higher level function to
// avoid having to mess with the cache.
func TestGetAdsForPath(t *testing.T) {
	/*
		FLOW:
			- Set up a few dummy namespaces, origin, and cache ads
			- Record the ads
			- Query for a few paths and make sure the correct ads are returned
	*/
	nsAd1 := server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{PublicReads: false},
		Path: "/chtc",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAd2 := server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{PublicReads: true},
		Path: "/chtc/PUBLIC",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAd3 := server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{PublicReads: true},
		Path: "/chtc/PUBLIC2/",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAdTopo1 := server_structs.NamespaceAdV2{
		Caps:         server_structs.Capabilities{PublicReads: true},
		Path:         "/chtc",
		FromTopology: true,
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAdTopoOnly := server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{PublicReads: false},
		Path: "/foo",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	cacheAd1 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "cache1.wisc.edu",
		},
		Type: server_structs.CacheType.String(),
	}
	cacheAd1.Initialize("cache1")

	cacheAd2 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "cache2.wisc.edu",
		},
		Type: server_structs.CacheType.String(),
	}
	cacheAd2.Initialize("cache2")

	originAd1 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "origin1.wisc.edu",
		},
		Type: server_structs.OriginType.String(),
	}
	originAd1.Initialize("origin1")

	originAd2 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "origin2.wisc.edu",
		},
		Type: server_structs.OriginType.String(),
	}
	originAd2.Initialize("origin2")

	originAdTopo1 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "topology.wisc.edu",
		},
		Type:         server_structs.OriginType.String(),
		FromTopology: true,
	}
	originAdTopo1.Initialize("topology origin 1")

	o1Slice := []server_structs.NamespaceAdV2{nsAd1}
	o2Slice := []server_structs.NamespaceAdV2{nsAd2, nsAd3}
	c1Slice := []server_structs.NamespaceAdV2{nsAd1, nsAd2, nsAdTopoOnly}
	topoSlice := []server_structs.NamespaceAdV2{nsAdTopo1, nsAdTopoOnly}
	recordAd(context.Background(), originAd2, &o2Slice)
	recordAd(context.Background(), originAd1, &o1Slice)
	// Add a server from Topology that serves /chtc namespace
	recordAd(context.Background(), originAdTopo1, &topoSlice)
	recordAd(context.Background(), cacheAd1, &c1Slice)
	recordAd(context.Background(), cacheAd2, &o1Slice)

	testCases := []struct {
		name            string
		inPath          string
		outPath         string
		originNames     []string
		cacheNames      []string
		nsCapsToVerify  server_structs.Capabilities
		fromTopoIndices map[int]bool // should only be instantiated if it's populated
	}{
		{
			name:           "no trailing slash, topo filtered",
			inPath:         "/chtc",
			outPath:        "/chtc",
			originNames:    []string{"origin1"},
			cacheNames:     []string{"cache1", "cache2"},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: false},
		},
		{
			name:            "topology-only namespace gets topo origin",
			inPath:          "/foo",
			outPath:         "/foo",
			originNames:     []string{"topology origin 1"},
			cacheNames:      []string{"cache1"},
			nsCapsToVerify:  server_structs.Capabilities{},
			fromTopoIndices: map[int]bool{0: true},
		},
		{
			name:           "path with trailing slash",
			inPath:         "/chtc/",
			outPath:        "/chtc",
			originNames:    []string{"origin1"},
			cacheNames:     []string{"cache1", "cache2"},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: false},
		},
		{
			name:           "path partially matching public namespace",
			inPath:         "/chtc/PUBLI",
			outPath:        "/chtc",
			originNames:    []string{"origin1"},
			cacheNames:     []string{"cache1", "cache2"},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: false},
		},
		{
			name:           "path matching public namespace",
			inPath:         "/chtc/PUBLIC",
			outPath:        "/chtc/PUBLIC",
			originNames:    []string{"origin2"},
			cacheNames:     []string{"cache1"},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: true},
		},
		{
			name:           "path matching public namespace with trailing slash",
			inPath:         "/chtc/PUBLIC2", // This is stored as /chtc/PUBLIC2/
			outPath:        "/chtc/PUBLIC2",
			originNames:    []string{"origin2"},
			cacheNames:     []string{},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: true},
		},
		{
			name:           "nonexistent path",
			inPath:         "/does/not/exist",
			outPath:        "",
			originNames:    []string{},
			cacheNames:     []string{},
			nsCapsToVerify: server_structs.Capabilities{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get the paths
			oAds, cAds := getAdsForPath(tc.inPath)

			// Assert the correct number of each ad type are returned
			assert.Equal(t, len(tc.originNames), len(oAds))
			assert.Equal(t, len(tc.cacheNames), len(cAds))

			if tc.outPath == "" {
				return
			}

			// Verify origin paths, topology, and capabilities
			for i, oAd := range oAds {
				assert.Equal(t, tc.outPath, oAd.NamespaceAd.Path)
				assert.Equal(t, tc.nsCapsToVerify, oAd.NamespaceAd.Caps)
				if tc.fromTopoIndices != nil {
					if _, ok := tc.fromTopoIndices[i]; ok {
						assert.True(t, oAd.ServerAd.FromTopology)
					}
				} else {
					assert.False(t, oAd.ServerAd.FromTopology)
				}
			}

			// Verify cache paths
			for _, cAd := range cAds {
				assert.Equal(t, tc.outPath, cAd.NamespaceAd.Path)
			}

			// Verify names
			for _, name := range tc.originNames {
				assert.True(t, hasServerAdWithName(oAds, name))
			}
			for _, name := range tc.cacheNames {
				assert.True(t, hasServerAdWithName(cAds, name))
			}
		})
	}
}

func TestAllPredicatesPass(t *testing.T) {
	ctx := &gin.Context{}
	ad := copyAd{
		ServerAd:    server_structs.ServerAd{},
		NamespaceAd: server_structs.NamespaceAdV2{},
	}

	alwaysTrue := func(ctx *gin.Context, ad copyAd) bool { return true }
	alwaysFalse := func(ctx *gin.Context, ad copyAd) bool { return false }

	assert.True(t, allPredicatesPass(ctx, ad, alwaysTrue, alwaysTrue), "All predicates should pass")
	assert.False(t, allPredicatesPass(ctx, ad, alwaysTrue, alwaysFalse), "One predicate fails, so all should fail")
	assert.False(t, allPredicatesPass(ctx, ad, alwaysFalse, alwaysFalse), "All predicates fail")
}

func TestOriginSupportsVerb(t *testing.T) {
	testCases := []struct {
		name           string
		nsCaps         server_structs.Capabilities
		serverCaps     server_structs.Capabilities
		supportedVerbs []string
	}{
		{
			name: "all verbs supported",
			nsCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
			},
			serverCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
			},
			supportedVerbs: []string{
				http.MethodGet,
				http.MethodHead,
				http.MethodPut,
				http.MethodDelete,
				"PROPFIND",
			},
		},
		{
			name:   "server supports all, ns supports none",
			nsCaps: server_structs.Capabilities{},
			serverCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
			},
			supportedVerbs: []string{},
		},
		{
			name: "server supports none, ns supports all",
			nsCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
			},
			serverCaps:     server_structs.Capabilities{},
			supportedVerbs: []string{},
		},
		{
			name: "subset of verbs supported",
			nsCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
			},
			serverCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
			},
			supportedVerbs: []string{
				http.MethodGet,
				http.MethodHead,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := copyAd{
				ServerAd: server_structs.ServerAd{
					Caps: tc.serverCaps,
				},
				NamespaceAd: server_structs.NamespaceAdV2{
					Caps: tc.nsCaps,
				},
			}

			ctx := &gin.Context{}
			for _, verb := range tc.supportedVerbs {
				assert.True(t, originSupportsVerb(verb)(ctx, ad), verb+" should be supported")
			}
			assert.False(t, originSupportsVerb("UNKNOWN")(ctx, ad), "Unknown verb should not be supported")
		})
	}
}

func TestOriginSupportsQuery(t *testing.T) {
	testCases := []struct {
		name       string
		query      string
		nsCaps     server_structs.Capabilities
		serverCaps server_structs.Capabilities
		expected   bool
	}{
		{
			name:  "DirectReads and Listings supported",
			query: pelican_url.QueryDirectRead + "&" + pelican_url.QueryRecursive + "",
			nsCaps: server_structs.Capabilities{
				DirectReads: true,
				Listings:    true,
			},
			serverCaps: server_structs.Capabilities{
				DirectReads: true,
				Listings:    true,
			},
			expected: true,
		},
		{
			name:  "DirectReads not supported by server",
			query: pelican_url.QueryDirectRead + "",
			nsCaps: server_structs.Capabilities{
				DirectReads: true,
			},
			serverCaps: server_structs.Capabilities{
				DirectReads: false,
			},
			expected: false,
		},
		{
			name:  "DirectReads not supported by ns",
			query: pelican_url.QueryDirectRead + "",
			nsCaps: server_structs.Capabilities{
				DirectReads: false,
			},
			serverCaps: server_structs.Capabilities{
				DirectReads: true,
			},
			expected: false,
		},
		{
			name:  "Listings not supported",
			query: pelican_url.QueryRecursive + "",
			nsCaps: server_structs.Capabilities{
				Listings: false,
			},
			serverCaps: server_structs.Capabilities{
				Listings: false,
			},
			expected: false,
		},
		{
			name:  "No query parameters",
			query: "",
			nsCaps: server_structs.Capabilities{
				DirectReads: true,
				Listings:    true,
			},
			serverCaps: server_structs.Capabilities{
				DirectReads: true,
				Listings:    true,
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := copyAd{
				ServerAd: server_structs.ServerAd{
					Caps: tc.serverCaps,
				},
				NamespaceAd: server_structs.NamespaceAdV2{
					Caps: tc.nsCaps,
				},
			}

			ctx := &gin.Context{}
			ctx.Request = &http.Request{
				URL: &url.URL{
					RawQuery: tc.query,
				},
			}

			assert.Equal(t, tc.expected, originSupportsQuery()(ctx, ad))
		})
	}
}

func TestComputeFeaturesUnion(t *testing.T) {
	testCases := []struct {
		name              string
		origins           []copyAd
		expectedFeatNames []string
	}{
		{
			name:              "No origins",
			origins:           []copyAd{},
			expectedFeatNames: []string{},
		},
		{
			name: "One origin",
			origins: []copyAd{
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{features.CacheAuthz.GetName()},
					},
				},
			},
			expectedFeatNames: []string{features.CacheAuthz.GetName()},
		},
		{
			name: "Two origins, both with same feature",
			origins: []copyAd{
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{features.CacheAuthz.GetName()},
					},
				},
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{features.CacheAuthz.GetName()},
					},
				},
			},
			expectedFeatNames: []string{features.CacheAuthz.GetName()},
		},
		{
			name: "Two origins, one with feature",
			origins: []copyAd{
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{features.CacheAuthz.GetName()},
					},
				},
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{},
					},
				},
			},
			expectedFeatNames: []string{features.CacheAuthz.GetName()},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			features := computeFeaturesUnion(tc.origins)
			assert.Len(t, features, len(tc.expectedFeatNames), "There should be %d unique features", len(tc.expectedFeatNames))

			if len(tc.expectedFeatNames) == 0 {
				return
			}

			// convert features to a list of their names
			featNames := make([]string, 0, len(features))
			for _, feat := range features {
				featNames = append(featNames, feat.GetName())
			}

			assert.Equal(t, tc.expectedFeatNames, featNames, "The feature names should match")
		})
	}
}

// Helper func to produce named ads in the following tests
func produceAd(name, adType, vString string) copyAd {
	ad := server_structs.ServerAd{
		ServerBaseAd: server_structs.ServerBaseAd{},
		Type:         adType,
	}
	ad.Initialize(name)
	ad.Version = vString
	copyAd := copyAd{
		ServerAd: ad,
	}
	return copyAd
}

func TestFilterOrigins(t *testing.T) {
	testCases := []struct {
		name          string
		origins       []copyAd
		predicates    []AdPredicate
		expectedNames []string
	}{
		{
			name: "No predicates passes all origins",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates:    []AdPredicate{},
			expectedNames: []string{"origin1", "origin2"},
		},
		{
			name: "Single predicate filters out one origin",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool {
					return ad.ServerAd.Name == "origin1"
				},
			},
			expectedNames: []string{"origin1"},
		},
		{
			name: "Single predicate filters out all origins",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool {
					return false
				},
			},
			expectedNames: []string{},
		},
		{
			name: "Single predicate keeps all origins",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool {
					return true
				},
			},
			expectedNames: []string{"origin1", "origin2"},
		},
		{
			name: "Origins filtered out by different predicates",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool {
					return ad.ServerAd.Name == "origin1"
				},
				func(ctx *gin.Context, ad copyAd) bool {
					return ad.ServerAd.Name == "origin2"
				},
			},
			expectedNames: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}
			origins := filterOrigins(ctx, tc.origins, tc.predicates...)
			assert.Len(t, origins, len(tc.expectedNames), "There should be %d origins", len(tc.expectedNames))

			for _, name := range tc.expectedNames {
				assert.True(t, hasServerAdWithName(origins, name), "Origin %s should be present", name)
			}
		})
	}
}

func TestCacheSupportsFeature(t *testing.T) {
	testCases := []struct {
		name             string
		ad               copyAd
		requiredFeatures []string
		supported        bool
	}{
		{
			name:             "CacheAuthz required and supported",
			ad:               produceAd("", server_structs.CacheType.String(), "v7.16.0"),
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			supported:        true,
		},
		{
			name:             "Unknown server type not marked as supported",
			ad:               produceAd("", "", "v7.16.0"),
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			supported:        false,
		},
		{
			name:             "CacheAuthz required but support unknown",
			ad:               produceAd("", server_structs.CacheType.String(), ""),
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			// Technically unknown, but this predicate only checks true/false
			supported: false,
		},
		{
			name:             "CacheAuthz required but not supported",
			ad:               produceAd("", server_structs.CacheType.String(), "v7.15.999"),
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			supported:        false,
		},
		{
			name:             "CacheAuthz not required but supported",
			ad:               produceAd("", server_structs.CacheType.String(), "v7.16.0"),
			requiredFeatures: []string{},
			supported:        true,
		},
		{
			name:             "CacheAuthz not required and not supported",
			ad:               produceAd("", server_structs.CacheType.String(), "v7.15.999"),
			requiredFeatures: []string{},
			supported:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}
			featureMap := make(map[string]features.Feature, len(tc.requiredFeatures))
			for _, featureName := range tc.requiredFeatures {
				feature, err := features.GetFeature(featureName)
				require.NoError(t, err, "Feature %s should be supported", featureName)
				featureMap[featureName] = feature
			}
			assert.Equal(t, tc.supported, cacheSupportsFeature(featureMap)(ctx, tc.ad))
		})
	}
}

func TestCacheMightSupportFeature(t *testing.T) {
	testCases := []struct {
		name             string
		ad               copyAd
		requiredFeatures []string
		mightSupport     bool
	}{
		{
			name:             "Missing server type means might be supported",
			ad:               produceAd("", "", "v7.16.0"), // unknown server type --> unknown support
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			mightSupport:     true,
		},
		{
			name:             "Missing version means might be supported",
			ad:               produceAd("", server_structs.CacheType.String(), ""), // unknown version --> unknown support
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			mightSupport:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}

			featureMap := make(map[string]features.Feature, len(tc.requiredFeatures))
			for _, featureName := range tc.requiredFeatures {
				feature, err := features.GetFeature(featureName)
				require.NoError(t, err, "Feature %s should be supported", featureName)
				featureMap[featureName] = feature
			}
			assert.Equal(t, tc.mightSupport, cacheMightSupportFeature(featureMap)(ctx, tc.ad))
		})
	}
}

func TestCacheNotFromTopoIfPubReads(t *testing.T) {
	testCases := []struct {
		name        string
		fromTopo    bool
		publicReads bool
		expected    bool
	}{
		{
			name:        "Cache from topology with PublicReads",
			fromTopo:    true,
			publicReads: true,
			expected:    false,
		},
		{
			name:        "Cache not from topology with PublicReads",
			fromTopo:    false,
			publicReads: true,
			expected:    true,
		},
		{
			name:        "Cache from topology without PublicReads",
			fromTopo:    true,
			publicReads: false,
			expected:    true,
		},
		{
			name:        "Cache not from topology without PublicReads",
			fromTopo:    false,
			publicReads: false,
			expected:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := copyAd{
				ServerAd: server_structs.ServerAd{
					FromTopology: tc.fromTopo,
				},
				NamespaceAd: server_structs.NamespaceAdV2{
					Caps: server_structs.Capabilities{
						PublicReads: tc.publicReads,
					},
				},
			}

			ctx := &gin.Context{}
			assert.Equal(t, tc.expected, cacheNotFromTopoIfPubReads()(ctx, ad))
		})
	}
}

func TestFilterCaches(t *testing.T) {
	testCases := []struct {
		name            string
		ads             []copyAd
		commonPred      AdPredicate
		supportedPreds  []AdPredicate
		unknownPreds    []AdPredicate
		expectedSupport []string
		expectedUnknown []string
	}{
		{
			name: "All ads pass common and supported predicates",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
			},
			commonPred: func(ctx *gin.Context, ad copyAd) bool { return true },
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			unknownPreds:    []AdPredicate{},
			expectedSupport: []string{"ad1", "ad2"},
			expectedUnknown: []string{},
		},
		{
			name: "All ads pass common but only some pass supported predicates",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
			},
			commonPred: func(ctx *gin.Context, ad copyAd) bool { return true },
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return ad.ServerAd.Name == "ad1" },
			},
			unknownPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return false },
			},
			expectedSupport: []string{"ad1"},
			expectedUnknown: []string{},
		},
		{
			name: "Ads pass common but only some pass unknown predicates",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
			},
			commonPred: func(ctx *gin.Context, ad copyAd) bool { return true },
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return false },
			},
			unknownPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return ad.ServerAd.Name == "ad2" },
			},
			expectedSupport: []string{},
			expectedUnknown: []string{"ad2"},
		},
		{
			name: "Ads fail common predicate",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
			},
			commonPred: func(ctx *gin.Context, ad copyAd) bool { return false },
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			unknownPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			expectedSupport: []string{},
			expectedUnknown: []string{},
		},
		{
			name: "Ads split between supported and unknown groups",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
				produceAd("ad3", server_structs.CacheType.String(), ""),
			},
			commonPred: func(ctx *gin.Context, ad copyAd) bool { return true },
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return ad.ServerAd.Name == "ad1" },
			},
			unknownPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return ad.ServerAd.Name == "ad2" },
			},
			expectedSupport: []string{"ad1"},
			expectedUnknown: []string{"ad2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}
			supported, unknown := filterCaches(ctx, tc.ads, tc.commonPred, tc.supportedPreds, tc.unknownPreds)

			// Verify supported ads
			assert.Len(t, supported, len(tc.expectedSupport), "Number of supported ads should match")
			for _, name := range tc.expectedSupport {
				assert.True(t, hasServerAdWithName(supported, name), "Supported ad %s should be present", name)
			}

			// Verify unknown ads
			assert.Len(t, unknown, len(tc.expectedUnknown), "Number of unknown ads should match")
			for _, name := range tc.expectedUnknown {
				assert.True(t, hasServerAdWithName(unknown, name), "Unknown ad %s should be present", name)
			}
		})
	}
}
