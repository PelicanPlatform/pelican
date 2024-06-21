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
	"archive/tar"
	"cmp"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

const (
	maxMindURL string = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz"
)

var (
	maxMindReader atomic.Pointer[geoip2.Reader]
)

type (
	SwapMap struct {
		Weight float64
		Index  int
	}

	SwapMaps []SwapMap
)

type Coordinate struct {
	Lat  float64 `mapstructure:"lat"`
	Long float64 `mapstructure:"long"`
}

type GeoIPOverride struct {
	IP         string     `mapstructure:"IP"`
	Coordinate Coordinate `mapstructure:"Coordinate"`
}

var invalidOverrideLogOnce = map[string]bool{}
var geoIPOverrides []GeoIPOverride

func (me SwapMaps) Len() int {
	return len(me)
}

func (me SwapMaps) Less(left, right int) bool {
	return me[left].Weight < me[right].Weight
}

func (me SwapMaps) Swap(left, right int) {
	me[left], me[right] = me[right], me[left]
}

// Check for any pre-configured IP-to-lat/long overrides. If the passed address
// matches an override IP (either directly or via CIDR masking), then we use the
// configured lat/long from the override instead of relying on MaxMind.
// NOTE: We don't return an error because if checkOverrides encounters an issue,
// we still have GeoIP to fall back on.
func checkOverrides(addr net.IP) (coordinate *Coordinate) {
	// Unmarshal the values, but only the first time we run through this block
	if geoIPOverrides == nil {
		err := param.GeoIPOverrides.Unmarshal(&geoIPOverrides)
		if err != nil {
			log.Warningf("Error while unmarshaling GeoIP Overrides: %v", err)
		}
	}

	for _, geoIPOverride := range geoIPOverrides {
		// Check for regular IP addresses before CIDR
		overrideIP := net.ParseIP(geoIPOverride.IP)
		if overrideIP == nil {
			// The IP is malformed
			if !invalidOverrideLogOnce[geoIPOverride.IP] && !strings.Contains(geoIPOverride.IP, "/") {
				// Don't return here, because we have more to check.
				// Do provide a notice to the user, however.
				log.Warningf("Failed to parse configured GeoIPOverride address (%s). Unable to use for GeoIP resolution!", geoIPOverride.IP)
				invalidOverrideLogOnce[geoIPOverride.IP] = true
			}
		}
		if overrideIP.Equal(addr) {
			return &geoIPOverride.Coordinate
		}

		// Alternatively, we can match by CIDR blocks
		if strings.Contains(geoIPOverride.IP, "/") {
			_, ipNet, err := net.ParseCIDR(geoIPOverride.IP)
			if err != nil {
				if !invalidOverrideLogOnce[geoIPOverride.IP] {
					// Same reason as above for not returning.
					log.Warningf("Failed to parse configured GeoIPOverride CIDR address (%s): %v. Unable to use for GeoIP resolution!", geoIPOverride.IP, err)
					invalidOverrideLogOnce[geoIPOverride.IP] = true
				}
				continue
			}
			if ipNet.Contains(addr) {
				return &geoIPOverride.Coordinate
			}
		}
	}

	return nil
}

func getLatLong(addr netip.Addr) (lat float64, long float64, err error) {
	ip := net.IP(addr.AsSlice())
	override := checkOverrides(ip)
	if override != nil {
		log.Infof("Overriding Geolocation of detected IP (%s) to lat:long %f:%f based on configured overrides", ip.String(), (override.Lat), override.Long)
		return override.Lat, override.Long, nil
	}

	reader := maxMindReader.Load()
	if reader == nil {
		err = errors.New("No GeoIP database is available")
		return
	}
	record, err := reader.City(ip)
	if err != nil {
		return
	}
	lat = record.Location.Latitude
	long = record.Location.Longitude

	if lat == 0 && long == 0 {
		log.Infof("GeoIP Resolution of the address %s resulted in the nul lat/long.", ip.String())
	}
	return
}

func getClientLatLong(addr netip.Addr) (coord Coordinate, ok bool) {
	var err error
	coord.Lat, coord.Long, err = getLatLong(addr)
	ok = (err == nil && !(coord.Lat == 0 && coord.Long == 0))
	if err != nil {
		log.Warningf("failed to resolve lat/long for address %s: %v", addr, err)
	}
	return
}

// Sort serverAds based on the IP address of the client with shorter distance between
// server IP and client having higher priority
func sortServerAdsByIP(addr netip.Addr, ads []server_structs.ServerAd) ([]server_structs.ServerAd, error) {
	// Each entry in weights will map a priority to an index in the original ads slice.
	// A larger weight is a higher priority.
	weights := make(SwapMaps, len(ads))
	sortMethod := param.Director_CacheSortMethod.GetString()

	// For each ad, we apply the configured sort method to determine a priority weight.
	for idx, ad := range ads {
		switch sortMethod {
		case "distance":
			clientCoord, ok := getClientLatLong(addr)
			if !ok {
				// Unable to compute distances for this server; just do random distances.
				// Below we sort weights in descending order, so we assign negative value here,
				// causing them to always be at the end of the sorted list.
				weights[idx] = SwapMap{0 - rand.Float64(), idx}
			} else {
				weights[idx] = SwapMap{distanceWeight(clientCoord, ad),
					idx}
			}
		case "distanceAndLoad":
			clientCoord, ok := getClientLatLong(addr)
			if !ok {
				weights[idx] = SwapMap{0 - rand.Float64(), idx}
			} else {
				// Each server ad will have a load value that we can use for sorting
				weights[idx] = SwapMap{distanceAndLoadWeight(clientCoord, ad),
					idx}
			}
		case "random":
			weights[idx] = SwapMap{rand.Float64(), idx}
		default:
			return nil, errors.Errorf("Invalid sort method '%s' set in Director.CacheSortMethod. Valid methods are 'distance',"+
				"'distanceAndLoad', and 'random.'", param.Director_CacheSortMethod.GetString())
		}
	}

	// Larger weight = higher priority, so we reverse the sort (which would otherwise default to ascending)
	sort.Sort(sort.Reverse(weights))
	resultAds := make([]server_structs.ServerAd, len(ads))
	for idx, weight := range weights {
		resultAds[idx] = ads[weight.Index]
	}
	return resultAds, nil
}

// Sort a list of ServerAds with the following rule:
//   - if a ServerAds has FromTopology = true, then it will be moved to the end of the list
//   - if two ServerAds has the SAME FromTopology value (both true or false), then break tie them by name
//
// TODO: remove the return statement as slices.SortStableFunc sorts the slice in-place
func sortServerAdsByTopo(ads []*server_structs.Advertisement) []*server_structs.Advertisement {
	slices.SortStableFunc(ads, func(a, b *server_structs.Advertisement) int {
		if a.FromTopology && !b.FromTopology {
			return 1
		} else if !a.FromTopology && b.FromTopology {
			return -1
		} else {
			return cmp.Compare(a.Name, b.Name)
		}
	})
	return ads
}

func sortServerAdsByAvailability(ads []server_structs.ServerAd, avaiMap map[string]bool) {
	slices.SortStableFunc(ads, func(a, b server_structs.ServerAd) int {
		if avaiMap[a.URL.String()] && !avaiMap[b.URL.String()] {
			return 1
		} else if !avaiMap[a.URL.String()] && avaiMap[b.URL.String()] {
			return -1
		} else {
			// Preserve original ordering
			return 0
		}
	})
}

func downloadDB(localFile string) error {
	err := os.MkdirAll(filepath.Dir(localFile), 0755)
	if err != nil {
		return err
	}

	var licenseKey string
	keyFile := param.Director_MaxMindKeyFile.GetString()
	keyFromEnv := viper.GetString("MAXMINDKEY")
	if keyFile != "" {
		contents, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		licenseKey = strings.TrimSpace(string(contents))
	} else if keyFromEnv != "" {
		licenseKey = keyFromEnv
	} else {
		return errors.New("A MaxMind key file must be specified in the config (Director.MaxMindKeyFile), in the environment (PELICAN_DIRECTOR_MAXMINDKEYFILE), or the key must be provided via the environment variable PELICAN_MAXMINDKEY)")
	}

	url := fmt.Sprintf(maxMindURL, licenseKey)
	localDir := filepath.Dir(localFile)
	fileHandle, err := os.CreateTemp(localDir, filepath.Base(localFile)+".tmp")
	if err != nil {
		return err
	}
	defer fileHandle.Close()
	resp, err := http.Get(url)
	if err != nil {
		os.Remove(fileHandle.Name())
		return err
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	foundDB := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		baseName := path.Base(hdr.Name)
		if baseName != "GeoLite2-City.mmdb" {
			continue
		}
		if _, err = io.Copy(fileHandle, tr); err != nil {
			os.Remove(fileHandle.Name())
			return err
		}
		foundDB = true
		break
	}
	if !foundDB {
		return errors.New("GeoIP database not found in downloaded resource")
	}
	if err = os.Rename(fileHandle.Name(), localFile); err != nil {
		return err
	}
	return nil
}

func periodicMaxMindReload(ctx context.Context) {
	// The MaxMindDB updates Tuesday/Thursday. While a free API key
	// does get 1000 downloads a month, we might still want to change
	// this eventually to guarantee we only update on those days...

	// Update once every other day
	ticker := time.NewTicker(48 * time.Hour)
	for {
		select {
		case <-ticker.C:
			localFile := param.Director_GeoIPLocation.GetString()
			if err := downloadDB(localFile); err != nil {
				log.Warningln("Failed to download GeoIP database:", err)
			} else {
				localReader, err := geoip2.Open(localFile)
				if err != nil {
					log.Warningln("Failed to re-open GeoIP database:", err)
				} else {
					maxMindReader.Store(localReader)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func InitializeDB(ctx context.Context) {
	go periodicMaxMindReload(ctx)
	localFile := param.Director_GeoIPLocation.GetString()
	localReader, err := geoip2.Open(localFile)
	if err != nil {
		log.Warningln("Local GeoIP database file not present; will attempt a download.", err)
		err = downloadDB(localFile)
		if err != nil {
			log.Errorln("Failed to download GeoIP database!  Will not be available:", err)
			return
		}
		localReader, err = geoip2.Open(localFile)
		if err != nil {
			log.Errorln("Failed to reopen GeoIP database!  Will not be available:", err)
			return
		}
	}
	maxMindReader.Store(localReader)
}
