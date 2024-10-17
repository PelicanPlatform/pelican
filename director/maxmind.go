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
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

const (
	maxMindURL string = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz"
)

var (
	maxMindReader atomic.Pointer[geoip2.Reader]
)

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
