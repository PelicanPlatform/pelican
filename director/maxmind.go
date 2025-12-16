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
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang/v2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

type (
	maxmindError struct {
		Kind    MaxMindErrorKind
		Message string
	}

	MaxMindErrorKind int
)

const (
	maxMindURL string = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz"

	MaxMindDBError MaxMindErrorKind = iota
	MaxMindQueryError
	MaxMindNullLatLonError
	MaxMindLargeAccuracyError
)

var (
	maxMindReader atomic.Pointer[geoip2.Reader]
)

func (e maxmindError) Error() string {
	return e.Message
}

func downloadDB(localFile string) error {
	err := os.MkdirAll(filepath.Dir(localFile), 0755)
	if err != nil {
		return err
	}

	var licenseKey string
	keyFile := param.Director_MaxMindKeyFile.GetString()
	if keyFile == "" {
		return errors.Errorf("A MaxMind API key file must be specified in the config (%s)", param.Director_MaxMindKeyFile.GetName())
	}

	contents, err := os.ReadFile(keyFile)
	if err != nil {
		return errors.Wrapf(err, "unable to read MaxMind license key file %q", keyFile)
	}

	licenseKey = strings.TrimSpace(string(contents))

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
	defer ticker.Stop()
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

func InitializeGeoIPDB(ctx context.Context) {
	go periodicMaxMindReload(ctx)
	localFile := param.Director_GeoIPLocation.GetString()
	localReader, err := geoip2.Open(localFile)
	if err != nil {
		log.Infoln("Local GeoIP database file not present; will attempt a download.", err)
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

// Given an IP address, query MaxMind for a coordinate.
//
// Null coordinates (0,0) and suspiciously large accuracy radii (>=900 km) are
// treated as errors, and the returned coordinate will have all-zero values.
// This is declared as a package-level variable so it can be overridden for unit testing
// where managing a real database is inconvenient.
var getMaxMindCoordinate = func(addr netip.Addr) (coord server_structs.Coordinate, err error) {
	coord.Source = server_structs.CoordinateSourceMaxMind

	reader := maxMindReader.Load()
	if reader == nil {
		err = maxmindError{Kind: MaxMindDBError, Message: "No MaxMind GeoIP database is available"}
		return
	}
	record, err := reader.City(addr)
	if err != nil {
		err = maxmindError{Kind: MaxMindQueryError, Message: fmt.Sprintf("failed to retrieve GeoIP data from the MaxMind database: %v", err)}
		return
	} else if record == nil || record.Location.Latitude == nil || record.Location.Longitude == nil {
		err = maxmindError{Kind: MaxMindQueryError, Message: fmt.Sprintf("no GeoIP data was returned from the MaxMind database for the address %s", addr.String())}
		return
	}

	lat := *record.Location.Latitude
	long := *record.Location.Longitude
	accuracyRadius := record.Location.AccuracyRadius

	// If the lat/long results are null before we've nulled them because of a large accuracy radius,
	// something else is probably breaking (why didn't maxmind generate an error on reading the record?)
	// Sometimes this comes from private IP ranges, so we handle it explicitly.
	if lat == 0 && long == 0 {
		err = maxmindError{Kind: MaxMindNullLatLonError, Message: fmt.Sprintf("GeoIP resolution of the address %s resulted in the null lat/long, but no error was provided by MaxMind", addr.String())}
		// These values in the return struct are already implicitly 0, but it's nice to see them explicitly
		coord.Lat = 0
		coord.Long = 0
		coord.AccuracyRadius = 0
		return
	}

	// MaxMind provides an accuracy radius in kilometers. When it actually has no clue how to resolve a valid, public
	// IP, it sets the radius to 1000. If we get a radius of 900 or more (probably even much less than this...), we
	// should be very suspicious of the data and treat this as a failure
	if accuracyRadius >= 900 {
		err = maxmindError{Kind: MaxMindLargeAccuracyError, Message: fmt.Sprintf("GeoIP resolution of the address %s resulted in a suspiciously large accuracy radius of %d km", addr.String(), accuracyRadius)}
		coord.Lat = 0
		coord.Long = 0
		coord.AccuracyRadius = 0
		return
	}

	coord.Lat = lat
	coord.Long = long
	coord.AccuracyRadius = accuracyRadius
	return
}
