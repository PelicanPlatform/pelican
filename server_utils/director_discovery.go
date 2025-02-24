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

package server_utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Utilities for determining the set of known directors and their advertisement endpoints

var (
	directorEndpoints atomic.Pointer[[]server_structs.DirectorAd]
)

// Query all known directors & metadata, return a list of unique director ads
func doDiscovery(ctx context.Context, isDirector bool) (endpoints []server_structs.DirectorAd, err error) {
	endpointMap := make(map[string]server_structs.DirectorAd)

	// First, add in all the statically-defined endpoints
	var fed pelican_url.FederationDiscovery
	endpointsTemp := make(map[string]bool)
	if fed, err = config.GetFederation(ctx); err == nil {
		endpointsTemp[fed.DirectorEndpoint] = true
		for _, info := range fed.DirectorAdvertiseEndpoints {
			endpointsTemp[info] = true
		}
	} else {
		log.Warningln("Failed to determine federation information:", err)
	}
	for _, endpoint := range param.Server_DirectorURLs.GetStringSlice() {
		if _, err := url.Parse(endpoint); err != nil {
			log.Errorln("Ignoring URL", endpoint, "specified in Server.DirectorURLs due to parsing error:", err)
			continue
		}
		endpointsTemp[endpoint] = true
	}
	if isDirector {
		endpointsTemp[param.Server_ExternalWebUrl.GetString()] = true
		// Bootstrap my own ad, even if nothing else is discovered.
		if servers := directorEndpoints.Load(); servers == nil {
			servers := make([]server_structs.DirectorAd, 1)
			if name, err := GetServiceName(ctx, server_structs.DirectorType); err == nil {
				servers[0] = server_structs.DirectorAd{
					AdvertiseUrl: param.Server_ExternalWebUrl.GetString(),
				}
				servers[0].Initialize(name)
				directorEndpoints.CompareAndSwap(nil, &servers)
			}
		}
	}

	// For each statically-defined endpoint, query it for all its known directors
	var lastError error = nil
	for endpoint := range endpointsTemp {
		var directorUrl *url.URL
		directorUrl, err = url.Parse(endpoint)
		if err != nil {
			lastError = err
			continue
		}
		directorUrl.Path, _ = url.JoinPath(directorUrl.Path, "api", "v1.0", "director", "directors")

		client := &http.Client{Transport: config.GetTransport()}
		directorInfo, err := client.Get(directorUrl.String())
		if err != nil {
			lastError = errors.Wrapf(err, "failed to contact director at %s", directorUrl.String())
			continue
		}
		defer directorInfo.Body.Close()

		if directorInfo.StatusCode != http.StatusOK {
			lastError = errors.Errorf("director at %s responded to 'list directors' API with status code %d", directorUrl.String(), directorInfo.StatusCode)
			log.Warningln("Remote director responded with a failure:", lastError)
			continue
		}

		var directorResponse []server_structs.DirectorAd
		if lastError = json.NewDecoder(directorInfo.Body).Decode(&directorResponse); lastError != nil {
			log.Warningln("Failed to decode response from director:", lastError)
			continue
		}
		for _, directorEndpoint := range directorResponse {
			existingAd := endpointMap[directorEndpoint.AdvertiseUrl]
			if after := directorEndpoint.After(existingAd); existingAd.Name == "" || after == server_structs.AdAfterTrue || after == server_structs.AdAfterUnknown {
				endpointMap[directorEndpoint.AdvertiseUrl] = directorEndpoint
			}
		}
	}
	if lastError != nil {
		err = lastError
	}

	endpoints = make([]server_structs.DirectorAd, 0, len(endpointMap))
	for _, ad := range endpointMap {
		endpoints = append(endpoints, ad)
	}
	return
}

// Return a list of known director ads
func GetDirectorAds() []server_structs.DirectorAd {
	servers := directorEndpoints.Load()
	if servers == nil {
		return make([]server_structs.DirectorAd, 0)
	}
	return *servers
}

// Launch goroutine that periodically discovers all the known directors in a federation.
func LaunchPeriodicDirectorDiscovery(ctx context.Context, isDirector bool) error {
	egrp := ctx.Value(config.EgrpKey).(*errgroup.Group)
	servers, err := doDiscovery(ctx, isDirector)
	if err != nil {
		log.Warningln("Failed to discover available director endpoints:", err)
	} else {
		directorEndpoints.Store(&servers)
	}
	if len(servers) == 0 {
		log.Warningln("No director advertisement endpoints discovered!")
	} else if log.IsLevelEnabled(log.InfoLevel) {
		endpoints := servers[0].AdvertiseUrl
		for _, ad := range servers[1:] {
			endpoints += ", " + ad.AdvertiseUrl
		}
		log.Infoln("Will advertise to director endpoints:", endpoints)
	}

	ticker := time.NewTicker(1 * time.Minute)
	egrp.Go(func() error {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if servers, err := doDiscovery(ctx, isDirector); err != nil {
					log.Warningln("Failed to discover available director endpoints:", err)
					select {
					case <-ctx.Done():
						log.Infoln("Periodic director advertise loop has been terminated")
						return nil
					default:
						break
					}
				} else {
					directorEndpoints.Store(&servers)
				}

			case <-ctx.Done():
				log.Infoln("Periodic advertisement loop has been terminated")
				return nil
			}
		}
	})

	return nil
}
