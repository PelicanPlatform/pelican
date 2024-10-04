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
	"bytes"
	_ "embed"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// Geo Override Yaml mockup
//
//go:embed resources/geoip_overrides.yaml
var yamlMockup string

func TestCheckOverrides(t *testing.T) {
	server_utils.Reset()
	t.Cleanup(func() {
		server_utils.Reset()
		geoIPOverrides = nil
	})

	// We'll also check that our logging feature responsibly reports
	// what Pelican is telling the user.
	logOutput := &(bytes.Buffer{})
	log.SetOutput(logOutput)
	log.SetLevel(log.DebugLevel)

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
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride CIDR address (10.0.0./24): invalid CIDR address: 10.0.0./24."+
			" Unable to use for GeoIP resolution!")
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride address (FD00::000G). Unable to use for GeoIP resolution!")
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride CIDR address (FD00::000F/11S): invalid CIDR address: FD00::000F/11S."+
			" Unable to use for GeoIP resolution!")
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
			Name:         "alpha",
		},
	}
	mock2 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: true,
			Name:         "bravo",
		},
	}
	mock3 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: true,
			Name:         "charlie",
		},
	}
	mock4 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
			Name:         "alpha",
		},
	}
	mock5 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
			Name:         "bravo",
		},
	}
	mock6 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
			Name:         "charlie",
		},
	}

	randomList := []*server_structs.Advertisement{&mock6, &mock1, &mock2, &mock4, &mock5, &mock3}
	expectedList := []*server_structs.Advertisement{&mock4, &mock5, &mock6, &mock1, &mock2, &mock3}

	sortedList := sortServerAdsByTopo(randomList)

	assert.EqualValues(t, expectedList, sortedList)
}

func TestSortServerAds(t *testing.T) {
	server_utils.Reset()
	t.Cleanup(func() {
		server_utils.Reset()
		geoIPOverrides = nil
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
		Name:      "madison server",
		URL:       url.URL{Scheme: "https", Host: "madison-cache.org"},
		Latitude:  43.0753,
		Longitude: -89.4114,
	}
	sdscServer := server_structs.ServerAd{
		Name:      "sdsc server",
		URL:       url.URL{Scheme: "https", Host: "sdsc-cache.org"},
		Latitude:  32.8761,
		Longitude: -117.2318,
	}
	bigBenServer := server_structs.ServerAd{
		Name:      "bigBen server",
		URL:       url.URL{Scheme: "https", Host: "bigBen-cache.org"},
		Latitude:  51.5103,
		Longitude: -0.1167,
	}
	kremlinServer := server_structs.ServerAd{
		Name:      "kremlin server",
		URL:       url.URL{Scheme: "https", Host: "kremlin-cache.org"},
		Latitude:  55.752121,
		Longitude: 37.617664,
	}
	daejeonServer := server_structs.ServerAd{
		Name:      "daejeon server",
		URL:       url.URL{Scheme: "https", Host: "daejeon-cache.org"},
		Latitude:  36.3213,
		Longitude: 127.4200,
	}
	mcMurdoServer := server_structs.ServerAd{
		Name:      "mcMurdo server",
		URL:       url.URL{Scheme: "https", Host: "mcMurdo-cache.org"},
		Latitude:  -77.8500,
		Longitude: 166.6666,
	}
	nullIslandServer := server_structs.ServerAd{
		Name:      "Null Island Server",
		URL:       url.URL{Scheme: "https", Host: "null-cache.org"},
		Latitude:  0.0,
		Longitude: 0.0,
	}

	// Mock servers with same geolocation but different loads
	serverLoad1 := server_structs.ServerAd{
		Name:      "load1",
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    0.0,
	}

	serverLoad2 := server_structs.ServerAd{
		Name:      "load2",
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    10.2,
	}

	serverLoad3 := server_structs.ServerAd{
		Name:      "load3",
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    14,
	}

	serverLoad4 := server_structs.ServerAd{
		Name:      "load4",
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    60.3,
	}

	serverLoad5NullLoc := server_structs.ServerAd{
		Name:      "load5NullLoc",
		Latitude:  0.0,
		Longitude: 0.0,
		IOLoad:    10.0,
	}

	serverLoad6NullLoc := server_structs.ServerAd{
		Name:      "load6NullLoc",
		Latitude:  0.0,
		Longitude: 0.0,
		IOLoad:    99.0,
	}

	// These are listed in order of increasing distance from the clientIP
	// However, madison server is overloaded and bigBenServer has very high load
	madisonServerHighLoad := server_structs.ServerAd{
		Name:      "madison high load",
		URL:       url.URL{Scheme: "https", Host: "madison-cache.org"},
		Latitude:  43.0753,
		Longitude: -89.4114,
		IOLoad:    100.4,
	}
	chicagoLowload := server_structs.ServerAd{
		Name:      "chicago low load",
		URL:       url.URL{Scheme: "https", Host: "chicago-cache.org"},
		Latitude:  41.789722,
		Longitude: -87.599724,
		IOLoad:    10,
	}
	bigBenServerHighLoad := server_structs.ServerAd{
		Name:      "big ben high load",
		Latitude:  51.5103,
		Longitude: -0.1167,
		IOLoad:    65.7,
	}

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
		expected := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer,
			daejeonServer, mcMurdoServer, nullIslandServer}
		sorted, err := sortServerAds(clientIP, randAds, nil)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
	})

	t.Run("test-distanceAndLoad-sort-distance-only", func(t *testing.T) {
		// Should return the same ordering as the distance test
		viper.Set("Director.CacheSortMethod", "distanceAndLoad")
		expected := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer,
			daejeonServer, mcMurdoServer, nullIslandServer}
		sorted, err := sortServerAds(clientIP, randAds, nil)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
	})

	t.Run("test-distanceAndLoad-sort-load-only", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "distanceAndLoad")
		expected := []server_structs.ServerAd{serverLoad1, serverLoad2, serverLoad3, serverLoad4, serverLoad6NullLoc}
		sorted, err := sortServerAds(clientIP, randLoadAds, nil)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
	})

	t.Run("test-distanceAndLoad-sort-distance-and-load", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "distanceAndLoad")
		expected := []server_structs.ServerAd{chicagoLowload, sdscServer, madisonServerHighLoad, kremlinServer,
			daejeonServer, mcMurdoServer, bigBenServerHighLoad, serverLoad5NullLoc, serverLoad6NullLoc}
		sorted, err := sortServerAds(clientIP, randDistanceLoadAds, nil)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
	})

	t.Run("test-random-sort", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "random")

		var sorted []server_structs.ServerAd
		var err error

		// We don't expect to get back the sorted slice, but it's possible
		notExpected := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer, daejeonServer,
			mcMurdoServer}

		// The probability this test fails the first time due to randomly sorting into ascending distances is (1/6!) = 1/720
		// To mitigate risk of this failing because of that, we'll run the sort 3 times to get a 1/720^3 = 1/373,248,000 chance
		// of failure. If you run thrice and you still get the distance-sorted slice, you might consider buying a powerball ticket
		// (1/292,201,338 chance of winning).
		for i := 0; i < 3; i++ {
			sorted, err = sortServerAds(clientIP, randAds, nil)
			require.NoError(t, err)

			// If the values are not equal, break the loop
			if !reflect.DeepEqual(notExpected, sorted) {
				break
			}
		}

		assert.NotEqualValues(t, notExpected, sorted)
	})
}

func TestSortServerAdsByAvailability(t *testing.T) {
	firstUrl := url.URL{Host: "first.org", Scheme: "https"}
	secondUrl := url.URL{Host: "second.org", Scheme: "https"}
	thirdUrl := url.URL{Host: "third.org", Scheme: "https"}
	forthUrl := url.URL{Host: "fourth.org", Scheme: "https"}

	firstServer := server_structs.ServerAd{URL: firstUrl}
	secondServer := server_structs.ServerAd{URL: secondUrl}
	thirdServer := server_structs.ServerAd{URL: thirdUrl}
	forthServer := server_structs.ServerAd{URL: forthUrl}

	randomOrder := []server_structs.ServerAd{thirdServer, firstServer, forthServer, secondServer}
	expected := []server_structs.ServerAd{firstServer, secondServer, thirdServer, forthServer}
	avaiMap := map[string]bool{}
	avaiMap[firstUrl.String()] = true
	avaiMap[secondUrl.String()] = true
	avaiMap[thirdUrl.String()] = false
	avaiMap[forthUrl.String()] = false

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
	t.Run("invalid-ip", func(t *testing.T) {
		// Capture the log and check that the correct error is logged
		logOutput := &(bytes.Buffer{})
		log.SetOutput(logOutput)
		log.SetLevel(log.DebugLevel)

		clientIp := netip.Addr{}
		assert.False(t, clientIpCache.Has(clientIp))
		coord1 := getClientLatLong(clientIp)

		assert.True(t, coord1.Lat <= usLatMax && coord1.Lat >= usLatMin)
		assert.True(t, coord1.Long <= usLongMax && coord1.Long >= usLongMin)
		assert.Contains(t, logOutput.String(), "Unable to sort servers based on client-server distance. Invalid client IP address")
		assert.NotContains(t, logOutput.String(), "Retrieving pre-assigned lat/long")

		// Get it again to make sure it's coming from the cache
		coord2 := getClientLatLong(clientIp)
		assert.Equal(t, coord1.Lat, coord2.Lat)
		assert.Equal(t, coord1.Long, coord2.Long)
		assert.Contains(t, logOutput.String(), "Retrieving pre-assigned lat/long for unresolved client IP")
		assert.True(t, clientIpCache.Has(clientIp))
	})

	t.Run("valid-ip-no-geoip-match", func(t *testing.T) {
		logOutput := &(bytes.Buffer{})
		log.SetOutput(logOutput)
		log.SetLevel(log.DebugLevel)

		clientIp := netip.MustParseAddr("192.168.0.1")
		assert.False(t, clientIpCache.Has(clientIp))
		coord1 := getClientLatLong(clientIp)

		assert.True(t, coord1.Lat <= usLatMax && coord1.Lat >= usLatMin)
		assert.True(t, coord1.Long <= usLongMax && coord1.Long >= usLongMin)
		assert.Contains(t, logOutput.String(), "Client IP 192.168.0.1 has been re-assigned a random location in the contiguous US to lat/long")
		assert.NotContains(t, logOutput.String(), "Retrieving pre-assigned lat/long")

		// Get it again to make sure it's coming from the cache
		coord2 := getClientLatLong(clientIp)
		assert.Equal(t, coord1.Lat, coord2.Lat)
		assert.Equal(t, coord1.Long, coord2.Long)
		assert.Contains(t, logOutput.String(), "Retrieving pre-assigned lat/long for client IP")
		assert.True(t, clientIpCache.Has(clientIp))
	})
}
