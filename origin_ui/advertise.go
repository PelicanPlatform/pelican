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

package origin_ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func PeriodicAdvertiseOrigin() error {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		err := AdvertiseOrigin()
		if err != nil {
			log.Warningln("Origin advertise failed:", err)
		}
		for {
			<-ticker.C
			err := AdvertiseOrigin()
			if err != nil {
				log.Warningln("Origin advertise failed:", err)
			}
		}
	}()

	return nil
}

func AdvertiseOrigin() error {
	name := param.Xrootd_Sitename.GetString()
	if name == "" {
		return errors.New("Origin name isn't set")
	}

	// TODO: waiting on a different branch to merge origin URL generation
	// The checkdefaults func that runs before the origin is served checks for and
	// parses the originUrl, so it should be safe to just grab it as a string here.
	originUrl := viper.GetString("OriginUrl")

	// Here we instantiate the namespaceAd slice, but we still need to define the namespace
	namespaceUrl, err := url.Parse(param.Federation_NamespaceUrl.GetString())
	if err != nil {
		return errors.Wrap(err, "Bad NamespaceUrl")
	}
	if namespaceUrl.String() == "" {
		return errors.New("No NamespaceUrl is set")
	}

	prefix := param.Origin_NamespacePrefix.GetString()

	// TODO: Need to figure out where to get some of these values
	// 		 so that they aren't hardcoded...
	nsAd := director.NamespaceAd{
		RequireToken:  true,
		Path:          prefix,
		Issuer:        *namespaceUrl,
		MaxScopeDepth: 3,
		Strategy:      "OAuth2",
		BasePath:      "/",
	}
	ad := director.OriginAdvertise{
		Name:       name,
		URL:        originUrl,
		Namespaces: []director.NamespaceAd{nsAd},
	}

	body, err := json.Marshal(ad)
	if err != nil {
		return errors.Wrap(err, "Failed to generate JSON description of origin")
	}

	directorUrlStr := param.Federation_DirectorUrl.GetString()
	if directorUrlStr == "" {
		return errors.New("Director endpoint URL is not known")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return errors.Wrap(err, "Failed to parse Federation.DirectorURL")
	}
	directorUrl.Path = "/api/v1.0/director/registerOrigin"

	token, err := director.CreateAdvertiseToken(prefix)
	if err != nil {
		return errors.Wrap(err, "Failed to generate advertise token")
	}

	req, err := http.NewRequest("POST", directorUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrap(err, "Failed to create POST request for director registration")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// We should switch this over to use the common transport, but for that to happen
	// that function needs to be exported from pelican
	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for director registration")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return fmt.Errorf("Error response %v from director registration: %v", resp.StatusCode, resp.Status)
	}

	return nil
}
