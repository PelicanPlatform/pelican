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

package server_ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type directorResponse struct {
	Error string `json:"error"`
}

func PeriodicAdvertise(server server_utils.XRootDServer) error {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		err := Advertise(server)
		if err != nil {
			log.Warningln(fmt.Sprintf("%s advertise failed:", server.GetServerType()), err)
			metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, fmt.Sprintf("Error advertising %s to federation", server.GetServerType()))
		} else {
			metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusOK, "")
		}

		for {
			<-ticker.C
			err := Advertise(server)
			if err != nil {
				log.Warningln(fmt.Sprintf("%s advertise failed:", server.GetServerType()), err)
				metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusCritical, fmt.Sprintf("Error advertising %s to federation", server.GetServerType()))
			} else {
				metrics.SetComponentHealthStatus(metrics.OriginCache_Federation, metrics.StatusOK, "")
			}
		}
	}()

	return nil
}

func Advertise(server server_utils.XRootDServer) error {
	name := param.Xrootd_Sitename.GetString()
	if name == "" {
		return errors.New(fmt.Sprintf("%s name isn't set", server.GetServerType()))
	}

	originUrl := param.Origin_Url.GetString()
	originWebUrl := param.Server_ExternalWebUrl.GetString()

	ad, err := server.CreateAdvertisement(name, originUrl, originWebUrl)
	if err != nil {
		return err
	}

	body, err := json.Marshal(ad)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Failed to generate JSON description of %s", server.GetServerType()))
	}

	directorUrlStr := param.Federation_DirectorUrl.GetString()
	if directorUrlStr == "" {
		return errors.New("Director endpoint URL is not known")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return errors.Wrap(err, "Failed to parse Federation.DirectorURL")
	}

	directorUrl.Path = "/api/v1.0/director/register" + server.GetServerType().String()

	prefix := param.Origin_NamespacePrefix.GetString()

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
	userAgent := "pelican-" + strings.ToLower(server.GetServerType().String()) + "/" + client.ObjectClientOptions.Version
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
		if resp.StatusCode == http.StatusForbidden {
			return errors.Errorf("Error during director advertisement: Cache has not been approved by administrator.")
		}
		return errors.Errorf("Error during director registration: %v\n", respErr.Error)
	}

	return nil
}
