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
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

// Geo Override Yaml mockup
//
//go:embed resources/geoip_overrides.yaml
var yamlMockup string

func TestCheckOverrides(t *testing.T) {
	viper.Reset()

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

	viper.Reset()
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

func TestSortServerAdsByIP(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
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
		Latitude:  43.0753,
		Longitude: -89.4114,
	}
	sdscServer := server_structs.ServerAd{
		Latitude:  32.8761,
		Longitude: -117.2318,
	}
	bigBenServer := server_structs.ServerAd{
		Latitude:  51.5103,
		Longitude: -0.1167,
	}
	kremlinServer := server_structs.ServerAd{
		Latitude:  55.752121,
		Longitude: 37.617664,
	}
	daejeonServer := server_structs.ServerAd{
		Latitude:  36.3213,
		Longitude: 127.4200,
	}
	mcMurdoServer := server_structs.ServerAd{
		Latitude:  -77.8500,
		Longitude: 166.6666,
	}

	randAds := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer,
		daejeonServer, mcMurdoServer}
	// Shuffle so that we don't give the sort function an already-sorted slice!
	rand.Shuffle(len(randAds), func(i, j int) {
		randAds[i], randAds[j] = randAds[j], randAds[i]
	})

	t.Run("test-distance-sort", func(t *testing.T) {
		viper.Set("Director.CacheSortMethod", "distance")
		expected := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer,
			daejeonServer, mcMurdoServer}
		sorted, err := sortServerAdsByIP(clientIP, randAds)
		require.NoError(t, err)
		assert.EqualValues(t, expected, sorted)
	})

	t.Run("test-distanceAndLoad-sort", func(t *testing.T) {
		// For now, this test should return the same ordering as the distance test
		viper.Set("Director.CacheSortMethod", "distanceAndLoad")
		expected := []server_structs.ServerAd{madisonServer, sdscServer, bigBenServer, kremlinServer,
			daejeonServer, mcMurdoServer}
		sorted, err := sortServerAdsByIP(clientIP, randAds)
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
			sorted, err = sortServerAdsByIP(clientIP, randAds)
			require.NoError(t, err)

			// If the values are not equal, break the loop
			if !reflect.DeepEqual(notExpected, sorted) {
				break
			}
		}

		assert.NotEqualValues(t, notExpected, sorted)
	})
}
