/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	maxMindURL string = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz"
)

var (
	maxMindReader atomic.Pointer[geoip2.Reader]
)

type (
	SwapMap struct {
		Distance float64
		Index    int
	}

	SwapMaps []SwapMap
)

func (me SwapMaps) Len() int {
	return len(me)
}

func (me SwapMaps) Less(left, right int) bool {
	return me[left].Distance < me[right].Distance
}

func (me SwapMaps) Swap(left, right int) {
	me[left], me[right] = me[right], me[left]
}

func GetLatLong(addr netip.Addr) (lat float64, long float64, err error) {
	ip := net.IP(addr.AsSlice())
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
	return
}

func SortServers(addr netip.Addr, ads []ServerAd) ([]ServerAd, error) {
	distances := make(SwapMaps, len(ads))
	lat, long, err := GetLatLong(addr)
	isInvalid := err != nil
	for idx, ad := range ads {
		if isInvalid || (ad.Latitude == 0 && ad.Longitude == 0) {
			// Unable to compute distances for this server; just do random distances.
			// Note that valid distances are between 0 and 1, hence (1 + random) is always
			// going to be sorted after valid distances.
			distances[idx] = SwapMap{1 + rand.Float64(), idx}
		} else {
			distances[idx] = SwapMap{distanceOnSphere(lat, long, ad.Latitude, ad.Longitude),
				idx}
		}
	}
	sort.Sort(distances)
	resultAds := make([]ServerAd, len(ads))
	for idx, distance := range distances {
		resultAds[idx] = ads[distance.Index]
	}
	return resultAds, nil
}

func DownloadDB(localFile string) error {
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

func PeriodicMaxMindReload() {
	// The MaxMindDB updates Tuesday/Thursday. While a free API key
	// does get 1000 downloads a month, we might still want to change
	// this eventually to guarantee we only update on those days...
	for {
		// Update once every other day
		time.Sleep(time.Hour * 48)
		localFile := param.Director_GeoIPLocation.GetString()
		if err := DownloadDB(localFile); err != nil {
			log.Warningln("Failed to download GeoIP database:", err)
		} else {
			localReader, err := geoip2.Open(localFile)
			if err != nil {
				log.Warningln("Failed to re-open GeoIP database:", err)
			} else {
				maxMindReader.Store(localReader)
			}
		}
	}
}

func InitializeDB() {
	go PeriodicMaxMindReload()
	localFile := param.Director_GeoIPLocation.GetString()
	localReader, err := geoip2.Open(localFile)
	if err != nil {
		log.Warningln("Local GeoIP database file not present; will attempt a download.", err)
		err = DownloadDB(localFile)
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
