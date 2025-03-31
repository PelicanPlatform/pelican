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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

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
// If no director ads are found, default back to the federation director endpoint
// If that endpoint doesn't exist, then all the errors encountered during the director
// ad discovery will be returned
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
	for _, endpoint := range param.Server_DirectorUrls.GetStringSlice() {
		if _, err := url.Parse(endpoint); err != nil {
			log.Errorln("Ignoring URL", endpoint, "specified in", param.Server_DirectorUrls.GetName(), "due to parsing error:", err)
			continue
		}
		endpointsTemp[endpoint] = true
	}
	if isDirector {
		adUrl := param.Director_AdvertiseUrl.GetString()
		if adUrl == "" {
			adUrl = param.Server_ExternalWebUrl.GetString()
			log.Debugln("Server will advertise to itself using the external web URL", adUrl)
		} else {
			log.Debugln("Server will advertise to itself using the configured advertise URL", adUrl)
		}
		endpoint, err := url.Parse(adUrl)
		if err == nil && endpoint.Port() != "0" {
			endpointsTemp[adUrl] = true
			// Bootstrap my own ad, even if nothing else is discovered.
			if servers := directorEndpoints.Load(); servers == nil {
				servers := make([]server_structs.DirectorAd, 1)
				if name, err := GetServiceName(ctx, server_structs.DirectorType); err == nil {
					servers[0] = server_structs.DirectorAd{
						AdvertiseUrl: adUrl,
					}
					servers[0].Initialize(name)
					directorEndpoints.CompareAndSwap(nil, &servers)
				}
			}
		} else if err != nil {
			log.Errorln("Ignoring URL", adUrl, "specified in", param.Director_AdvertiseUrl.GetName(), "due to parsing error:", err)
		} else {
			log.Warningln("Ignoring URL", adUrl, "specified in", param.Director_AdvertiseUrl.GetName(), "as the port is set to 0")
		}
	}

	// For each statically-defined endpoint, query it for all its known directors
	var allErrors error = nil
	for endpoint := range endpointsTemp {
		var directorUrl *url.URL
		directorUrl, err = url.Parse(endpoint)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}
		directorUrl.Path, _ = url.JoinPath(directorUrl.Path, "api", "v1.0", "director", "directors")

		client := &http.Client{Transport: config.GetTransport()}
		directorInfo, err := client.Get(directorUrl.String())
		if err != nil {
			newError := fmt.Errorf("failed to contact director at %s: %w", directorUrl.String(), err)
			allErrors = errors.Join(allErrors, newError)
			continue
		}
		defer directorInfo.Body.Close()

		if directorInfo.StatusCode != http.StatusOK {
			newError := fmt.Errorf("director at %s responded to 'list directors' API with status code %d", directorUrl.String(), directorInfo.StatusCode)
			allErrors = errors.Join(allErrors, newError)
			log.Warningln("Remote director responded with a failure:", newError)
			continue
		}

		var directorResponse []server_structs.DirectorAd
		if err = json.NewDecoder(directorInfo.Body).Decode(&directorResponse); err != nil {
			log.Warningln("Failed to decode response from director:", err)
			allErrors = errors.Join(allErrors, err)
			continue
		}
		for _, directorEndpoint := range directorResponse {
			existingAd := endpointMap[directorEndpoint.AdvertiseUrl]
			if directorEndpoint.Name == "" {
				continue
			}
			if after := directorEndpoint.After(existingAd); existingAd.Name == "" || after == server_structs.AdAfterTrue || after == server_structs.AdAfterUnknown {
				endpointMap[directorEndpoint.AdvertiseUrl] = directorEndpoint
			}
		}
	}

	// No endpoints were found and the federation director endpoint is nil
	if len(endpointMap) == 0 && fed.DirectorEndpoint == "" {
		newError := errors.New("failed to find director endpoint")
		err = errors.Join(newError, allErrors)
	} else if len(endpointMap) == 0 { // Fall back to director endpoint
		endpoints = []server_structs.DirectorAd{
			{
				AdvertiseUrl: fed.DirectorEndpoint,
			},
		}
	} else { // ad discovery succeeded, so use that
		endpoints = make([]server_structs.DirectorAd, 0, len(endpointMap))
		for _, ad := range endpointMap {
			endpoints = append(endpoints, ad)
		}
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

	advertiseInterval := param.Server_AdvertisementInterval.GetDuration()
	if advertiseInterval > param.Server_AdLifetime.GetDuration()/3 {
		newInterval := param.Server_AdLifetime.GetDuration() / 3
		log.Warningln("The periodic director discovery interval", advertiseInterval.String(), "is set to below 1/3 of the ad lifetime.  Decreasing it to", newInterval.String())
		advertiseInterval = newInterval
	}

	ticker := time.NewTicker(advertiseInterval)
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
