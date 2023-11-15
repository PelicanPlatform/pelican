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
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type directorResponse struct {
	Error string `json:"error"`
}

func PeriodicAdvertiseOrigin() error {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		err := AdvertiseOrigin()
		if err != nil {
			log.Warningln("Origin advertise failed:", err)
			if err = metrics.SetComponentHealthStatus("federation", "critical", "Error advertising origin to federation"); err != nil {
				log.Warningln("Failed to update internal component health status:", err)
			}
		} else if err = metrics.SetComponentHealthStatus("federation", "ok", ""); err != nil {
			log.Warningln("Failed to update internal component health status:", err)
		}

		for {
			<-ticker.C
			err := AdvertiseOrigin()
			if err != nil {
				log.Warningln("Origin advertise failed:", err)
				if err = metrics.SetComponentHealthStatus("federation", "critical", "Error advertising origin to federation"); err != nil {
					log.Warningln("Failed to update internal component health status:", err)
				}
			} else if err = metrics.SetComponentHealthStatus("federation", "ok", ""); err != nil {
				log.Warningln("Failed to update internal component health status:", err)
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

	originUrl := param.Origin_Url.GetString()
	originWebUrl := param.Server_ExternalAddress.GetString()

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
		WebURL:     originWebUrl,
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
	userAgent := "pelican-origin/" + client.ObjectClientOptions.Version
	req.Header.Set("User-Agent", userAgent)

	// We should switch this over to use the common transport, but for that to happen
	// that function needs to be exported from pelican
	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for director registration")
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode > 299 {
		var respErr directorResponse
		if unmarshalErr := json.Unmarshal(body, &respErr); unmarshalErr != nil { // Error creating json
			return errors.Wrapf(unmarshalErr, "Could not unmarshall the director's response, which responded %v from director registration: %v", resp.StatusCode, resp.Status)
		}
		return errors.Errorf("Error during director registration: %v\n", respErr.Error)
	}

	return nil
}
