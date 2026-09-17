/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"sort"
	"sync"
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

type (
	ContextKey string
)

var (
	directorEndpoints atomic.Pointer[[]server_structs.DirectorAd]
)

func init() {
	// Register pelican_url's ResetState function with our test reset mechanism
	RegisterPelicanUrlReset(pelican_url.ResetState)
}

const (
	// Context value key; used to store a second context that will
	// indicate the director discovery should stop.
	//
	// Meant mostly for unit tests; director discovery is essential
	// functionality.
	DirectorDiscoveryShutdownKey ContextKey = "discovery_shutdown"
)

// directorQueryTimeout bounds a single "list directors" request made
// during director discovery.
//
// Chosen to be comfortably shorter than Transport.DialerTimeout (10s by
// default) because discovery runs on the startup path: the cost of
// waiting is a server that has not finished starting, while the cost of
// giving up early is one skipped director for one round of a loop that
// repeats on Server.AdvertisementInterval. A director too slow to list
// its peers within a few seconds is not one we should be holding up
// every server in the federation for.
const directorQueryTimeout = 3 * time.Second

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
				if metadata, err := GetServerMetadata(ctx, server_structs.DirectorType); err == nil {
					servers[0] = server_structs.DirectorAd{
						AdvertiseUrl: adUrl,
					}
					servers[0].Initialize(metadata.Name)
					directorEndpoints.CompareAndSwap(nil, &servers)
				}
			}
		} else if err != nil {
			log.Errorln("Ignoring URL", adUrl, "specified in", param.Director_AdvertiseUrl.GetName(), "due to parsing error:", err)
		} else {
			log.Warningln("Ignoring URL", adUrl, "specified in", param.Director_AdvertiseUrl.GetName(), "as the port is set to 0")
		}
	}

	// Query every statically-defined endpoint for the directors IT knows
	// about, CONCURRENTLY and with a bounded per-query timeout.
	//
	// Both of those matter, and neither is a micro-optimisation. This
	// function is called synchronously from LaunchPeriodicDirectorDiscovery,
	// which is called synchronously from launchers.LaunchModules — so
	// every second spent here is a second before the server finishes
	// starting and, for a local cache, before its socket exists at all.
	//
	// Serially, N endpoints cost the SUM of their latencies, and an
	// endpoint that is simply unreachable costs a full dial timeout
	// (Transport.DialerTimeout, 10s by default) on its own. A federation
	// only has to advertise one dead director for every server in it to
	// take ten extra seconds to start — which is exactly what happened
	// when the OSDF's discovery document listed a director that had
	// stopped accepting connections: `pelican serve --module localcache`
	// stopped reaching its listener inside the six seconds the CI
	// integration test allows, on every branch at once.
	//
	// The explicit client timeout is the other half. The shared transport
	// bounds the DIAL, but nothing bounded the request as a whole, so an
	// endpoint that accepted a connection and then went quiet would block
	// startup indefinitely. Discovery is a best-effort, periodically
	// repeated operation: a director too slow to answer within the
	// timeout is simply skipped this round, and the ticker tries again.
	var allErrors error = nil
	contacted := make(map[string]bool)
	type queryResult struct {
		endpoint string
		ads      []server_structs.DirectorAd
		err      error
	}
	results := make([]queryResult, 0, len(endpointsTemp))
	var resultsMu sync.Mutex
	var wg sync.WaitGroup
	for endpoint := range endpointsTemp {
		directorUrl, parseErr := url.Parse(endpoint)
		if parseErr != nil {
			allErrors = errors.Join(allErrors, parseErr)
			continue
		}
		directorUrl.Path, _ = url.JoinPath(directorUrl.Path, "api", "v1.0", "director", "directors")

		wg.Add(1)
		go func(endpoint string, directorUrl *url.URL) {
			defer wg.Done()
			res := queryResult{endpoint: endpoint}
			defer func() {
				resultsMu.Lock()
				results = append(results, res)
				resultsMu.Unlock()
			}()

			queryCtx, cancel := context.WithTimeout(ctx, directorQueryTimeout)
			defer cancel()
			req, reqErr := http.NewRequestWithContext(queryCtx, http.MethodGet, directorUrl.String(), nil)
			if reqErr != nil {
				res.err = reqErr
				return
			}
			client := &http.Client{Transport: config.GetTransport()}
			directorInfo, getErr := client.Do(req)
			if getErr != nil {
				res.err = fmt.Errorf("failed to contact director at %s: %w", directorUrl.String(), getErr)
				return
			}
			defer directorInfo.Body.Close()

			if directorInfo.StatusCode != http.StatusOK {
				res.err = fmt.Errorf("director at %s responded to 'list directors' API with status code %d", directorUrl.String(), directorInfo.StatusCode)
				log.Warningln("Remote director responded with a failure:", res.err)
				return
			}
			if decodeErr := json.NewDecoder(directorInfo.Body).Decode(&res.ads); decodeErr != nil {
				log.Warningln("Failed to decode response from director:", decodeErr)
				res.err = decodeErr
				return
			}
		}(endpoint, directorUrl)
	}
	wg.Wait()

	// Merge in a deterministic order. The precedence rule below depends
	// on the order ads are visited, so sorting by endpoint keeps the
	// outcome reproducible now that the queries themselves race.
	sort.Slice(results, func(i, j int) bool { return results[i].endpoint < results[j].endpoint })
	now := time.Now()
	for _, res := range results {
		if res.err != nil {
			allErrors = errors.Join(allErrors, res.err)
			continue
		}
		contacted[res.endpoint] = true
		for _, directorEndpoint := range res.ads {
			existingAd := endpointMap[directorEndpoint.AdvertiseUrl]
			if directorEndpoint.Name == "" {
				continue
			}
			if !directorEndpoint.Expiration.IsZero() && now.After(directorEndpoint.Expiration) {
				continue
			}
			if after := directorEndpoint.After(existingAd); existingAd.Name == "" || after == server_structs.AdAfterTrue || after == server_structs.AdAfterUnknown {
				endpointMap[directorEndpoint.AdvertiseUrl] = directorEndpoint
			}
		}
	}

	// Ensure every seed we successfully contacted but that no peer
	// reported is kept in endpointMap as a synthetic entry. A seed may
	// legitimately omit its own URL from its /directors response
	// (e.g., it is an older director that still relies on getting its
	// own ad back from a peer).
	for endpoint := range contacted {
		if _, ok := endpointMap[endpoint]; !ok {
			endpointMap[endpoint] = server_structs.DirectorAd{AdvertiseUrl: endpoint}
		}
	}

	// No endpoints were found and the federation director endpoint is nil
	if len(endpointMap) == 0 && fed.DirectorEndpoint == "" {
		newError := errors.New("failed to find director endpoint")
		err = errors.Join(newError, allErrors)
	} else if len(endpointMap) == 0 { // Fall back to director endpoint
		err = nil
		endpoints = []server_structs.DirectorAd{
			{
				AdvertiseUrl: fed.DirectorEndpoint,
			},
		}
	} else { // ad discovery succeeded, so use that
		err = nil
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

	shutdownAny := ctx.Value(DirectorDiscoveryShutdownKey)
	var shutdownChannel <-chan struct{} = nil
	if shutdownCtx, ok := shutdownAny.(context.Context); ok {
		shutdownChannel = shutdownCtx.Done()
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
						log.Infoln("Periodic director discovery loop has been terminated")
						return nil
					default:
						break
					}
				} else {
					directorEndpoints.Store(&servers)
				}
			case <-shutdownChannel:
				log.Infoln("Periodic director discovery loop has been shutdown by command")
				return nil
			case <-ctx.Done():
				log.Infoln("Periodic director discovery loop has been terminated")
				return nil
			}
		}
	})

	return nil
}
