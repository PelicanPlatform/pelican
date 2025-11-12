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

package cache

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	CacheServer struct {
		server_structs.NamespaceHolder
		namespaceFilter map[string]struct{}
		pids            []int
	}
)

// Can use this mechanism to override the minimum for the sake of tests
var MinFedTokenTickerRate = 1 * time.Minute

func (server *CacheServer) CreateAdvertisement(name, id, originUrl, originWebUrl string, downtimes []server_structs.Downtime) (*server_structs.OriginAdvertiseV2, error) {
	registryPrefix := server_structs.GetCacheNs(param.Xrootd_Sitename.GetString())

	// Get the overall health status as reported by the cache.
	status := metrics.GetHealthStatus().OverallStatus

	ad := server_structs.OriginAdvertiseV2{
		ServerID:       id,
		RegistryPrefix: registryPrefix,
		DataURL:        originUrl,
		WebURL:         originWebUrl,
		Namespaces:     server.GetNamespaceAds(),
		Status:         status,
		Downtimes:      downtimes,
	}
	ad.Initialize(name)

	return &ad, nil
}

func (server *CacheServer) SetPids(pids []int) {
	server.pids = make([]int, len(pids))
	copy(server.pids, pids)
}

func (server *CacheServer) GetPids() (pids []int) {
	pids = make([]int, len(server.pids))
	copy(pids, server.pids)
	return
}

func (server *CacheServer) SetFilters() {
	/*
	* Converts the list of permitted namespaces to a set and stores it for the serve
	* This is based on the assumption that the cache server could potentially be filtering once
	* every minute, so to save speed, we use a map to an empty struct to allow for O(1) lookup time
	 */
	server.namespaceFilter = make(map[string]struct{})
	nsList := param.Cache_PermittedNamespaces.GetStringSlice()
	// Ensure that each permitted namespace starts with a "/"
	for _, ns := range nsList {
		if !strings.HasPrefix(ns, "/") {
			ns = "/" + ns
		}
		server.namespaceFilter[ns] = struct{}{}
	}
}

func (server *CacheServer) filterAdsBasedOnNamespace(nsAds []server_structs.NamespaceAdV2) []server_structs.NamespaceAdV2 {
	/*
	* Filters out ads based on the namespaces listed in server.NamespaceFilter
	* Note that this does a few checks for trailing and non-trailing "/" as it's assumed that the namespaces
	* from the director and the ones provided might differ.
	 */
	filteredAds := []server_structs.NamespaceAdV2{}
	if len(server.namespaceFilter) > 0 {
		for _, ad := range nsAds {
			ns := ad.Path
			sentinel := true
			//If the final character isn't a '/', add it to the string
			if !strings.HasSuffix(ns, "/") {
				ns = ns + "/"
			}
			for sentinel {
				_, exists := server.namespaceFilter[ns]
				if exists {
					filteredAds = append(filteredAds, ad)
					break
				}

				splitIndex := strings.LastIndex(ns, "/")

				//If ns isn't the root the start of the path, either remove the trailing /
				//or check one director higher
				if splitIndex != -1 && splitIndex != 0 {
					if splitIndex != len(ns)-1 {
						ns = ns[:splitIndex+1]
					} else {
						ns = ns[:splitIndex]
					}
				} else {
					sentinel = false
				}
			}
		}
	}
	return filteredAds
}

func (server *CacheServer) GetNamespaceAdsFromDirector() error {
	// Get the endpoint of the director
	var respNS []server_structs.NamespaceAdV2

	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return err
	}
	if fedInfo.DirectorEndpoint == "" {
		return errors.New("No director specified; give the federation name (-f)")
	}

	directorEndpointURL, err := url.Parse(fedInfo.DirectorEndpoint)
	if err != nil {
		return errors.Wrap(err, "Unable to parse director url")
	}

	// Create the listNamespaces url
	directorNSListEndpointURL, err := url.JoinPath(directorEndpointURL.String(), "api", "v2.0", "director", "listNamespaces")
	if err != nil {
		return err
	}

	// Attempt to get data from the 2.0 endpoint, if that returns a 404 error, then attempt to get data
	// from the 1.0 endpoint and convert from V1 to V2
	tr := config.GetTransport()
	respData, err := utils.MakeRequest(context.Background(), tr, directorNSListEndpointURL, "GET", nil, nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			directorNSListEndpointURL, err = url.JoinPath(fedInfo.DirectorEndpoint, "api", "v1.0", "director", "listNamespaces")
			if err != nil {
				return err
			}
			respData, err = utils.MakeRequest(context.Background(), tr, directorNSListEndpointURL, "GET", nil, nil)
			var respNSV1 []server_structs.NamespaceAdV1
			if err != nil {
				return errors.Wrap(err, "Failed to make request")
			} else {
				if jsonErr := json.Unmarshal(respData, &respNSV1); jsonErr == nil { // Error creating json
					return errors.Wrapf(err, "Failed to make request: %v", err)
				}
				respNS = server_structs.ConvertNamespaceAdsV1ToV2(respNSV1, nil)
			}
		} else {
			return errors.Wrap(err, "Failed to make request")
		}
	} else {
		err = json.Unmarshal(respData, &respNS)
		if err != nil {
			return errors.Wrapf(err, "Failed to marshal response in to JSON: %v", err)
		}
	}

	if len(server.namespaceFilter) > 0 {
		respNS = server.filterAdsBasedOnNamespace(respNS)
	}

	server.SetNamespaceAds(respNS)

	return nil
}

func (server *CacheServer) GetServerType() server_structs.ServerType {
	return server_structs.CacheType
}

func (server *CacheServer) GetAdTokCfg(directorUrl string) (adTokCfg server_structs.AdTokCfg, err error) {

	var directorAudience string
	directorAudience, err = token.GetWLCGAudience(directorUrl)
	if err != nil {
		err = errors.Wrap(err, "failed to determine correct token audience for director")
		return
	}

	adTokCfg.Audience = directorAudience
	adTokCfg.Subject = param.Cache_Url.GetString()
	issuer, err := config.GetServerIssuerURL()
	if err != nil {
		err = errors.Wrap(err, "unable to determine server's issuer URL, needed for server advertising token")
		return
	}
	adTokCfg.Issuer = issuer

	return
}

func (server *CacheServer) GetFedTokLocation() string {
	return param.Cache_FedTokenLocation.GetString()
}

// Given a token, calculate the lifetime of the token
func calcTokLifetime(tok string) (time.Duration, error) {
	// I think verificationless parsing is fine here, because we already assume a strong
	// trust relationship with the Director, and if its been compromised, we have bigger problems.
	parsedTok, err := jwt.ParseInsecure([]byte(tok))
	if err != nil {
		return 0, err
	}
	return parsedTok.Expiration().Sub(parsedTok.IssuedAt()), nil
}

// validateTickerRate is the circuit breaker that prevents the ticker
// from firing too often. It also handles logging errors/warnings related
// to the token lifetime and the refresh rate.
func validateTickerRate(tickerRate time.Duration, tokLifetime time.Duration) time.Duration {
	validated := tickerRate

	if validated < MinFedTokenTickerRate {
		log.Warningf("Deduced federation token refresh period is less than minimum of %.3fm; setting to %.3fm",
			MinFedTokenTickerRate.Minutes(), MinFedTokenTickerRate.Minutes())
		validated = MinFedTokenTickerRate
	}

	// Unfortunately we can't do anything here about the Director sending
	// such short lived tokens unless we're willing to forgo the circuit
	// breaker.
	if validated > tokLifetime {
		log.Errorf("Deduced federation token refresh period exceeds token lifetime. Tokens will expire before refresh")
	}

	log.Debugf("Federation token refresh rate set to %.3fm", validated.Minutes())

	return validated
}

// getTickerRate calculates the rate at which the federation token should be refreshed
// by looking at the token lifetime and setting the ticker to 1/3 of that lifetime.
// If the token lifetime cannot be determined, the ticker is set to 1/3 of the default with
// a minimum of 1 minute.
func getTickerRate(tok string) time.Duration {
	var tickerRate time.Duration
	tokenLifetime, err := calcTokLifetime(tok)
	if err != nil {
		tokenLifetime = param.Director_FedTokenLifetime.GetDuration()
		log.Errorf("Failed to calculate lifetime of federation token: %v.", err)
	}
	tickerRate = tokenLifetime / 3
	return validateTickerRate(tickerRate, tokenLifetime)
}

func LaunchFedTokManager(ctx context.Context, egrp *errgroup.Group, cache server_structs.XRootDServer) {
	// Do our initial token fetch+set, then turn things over to the ticker
	tok, err := server_utils.CreateFedTok(ctx, cache)
	if err != nil {
		log.Errorf("Failed to get a federation token: %v", err)
	}

	// We want to fire the ticker at 1/3 the period of the token lifetime, or 1/3 the default
	// lifetime for the token if we can't otherwise determine it. In most cases, the two values
	// will be the same unless some fed administrator thinks they know better! This 1/3 period approach
	// gives us a bit of buffer in the event the Director is down for a short period of time.
	tickerRate := getTickerRate(tok)

	// Set the token in the cache
	err = server_utils.SetFedTok(ctx, cache, tok)
	if err != nil {
		log.Errorf("Failed to set the federation token: %v", err)
	}

	// TODO: Figure out what to do if the Director starts issuing tokens with a different
	// lifetime --> we can adjust ticker period dynamically, but what's the sensible thing to do?
	fedTokTicker := time.NewTicker(tickerRate)
	egrp.Go(func() error {
		defer fedTokTicker.Stop()
		for {
			select {
			case <-fedTokTicker.C:
				// Time to ask the Director for a new token
				log.Debugln("Refreshing federation token")
				tok, err := server_utils.CreateFedTok(ctx, cache)
				if err != nil {
					log.Errorf("Failed to get a federation token: %v", err)
					continue
				}
				log.Traceln("Successfully received new federation token")

				// Once again, parse the token, use it to set the next ticker fire
				// while also building in a circuit breaker to set a min ticker rate
				newTickerRate := getTickerRate(tok)
				if newTickerRate != tickerRate {
					fedTokTicker.Reset(newTickerRate)
					tickerRate = newTickerRate
				}

				// Set the token in the cache
				err = server_utils.SetFedTok(ctx, cache, tok)
				if err != nil {
					log.Errorf("Failed to write the federation token: %v", err)
				}
				log.Traceln("Successfully wrote new federation token to disk")
			case <-ctx.Done():
				return nil
			}
		}
	})
}
