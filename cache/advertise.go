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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	CacheServer struct {
		server_structs.NamespaceHolder
		namespaceFilter map[string]struct{}
		pids            []int
	}
)

func (server *CacheServer) CreateAdvertisement(name, originUrl, originWebUrl string) (*server_structs.OriginAdvertiseV2, error) {
	registryPrefix := server_structs.GetCacheNS(param.Xrootd_Sitename.GetString())
	ad := server_structs.OriginAdvertiseV2{
		Name:           name,
		RegistryPrefix: registryPrefix,
		DataURL:        originUrl,
		WebURL:         originWebUrl,
		Namespaces:     server.GetNamespaceAds(),
		Version:        config.GetVersion(),
	}

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

func (server *CacheServer) GetAdTokCfg(ctx context.Context) (adTokCfg server_structs.AdTokCfg, err error) {
	fInfo, err := config.GetFederation(ctx)
	if err != nil {
		err = errors.Wrap(err, "failed to get federation info")
		return
	}
	directorUrl := fInfo.DirectorEndpoint
	if directorUrl == "" {
		err = errors.New("unable to determine Director's URL")
		return
	}
	adTokCfg.Audience = directorUrl
	adTokCfg.Subject = param.Cache_Url.GetString()
	adTokCfg.Issuer = param.Server_IssuerUrl.GetString()

	return
}

func (server *CacheServer) GetFedTokLocation() string {
	return param.Cache_FedTokenLocation.GetString()
}

func LaunchFedTokManager(ctx context.Context, egrp *errgroup.Group, cache server_structs.XRootDServer) {
	// Do our initial token fetch+set, then turn things over to the ticker
	tok, err := server_utils.GetFedTok(ctx, cache)
	if err != nil {
		log.Errorf("Failed to get a federation token: %v", err)
	}

	// Set the token in the cache
	err = server_utils.SetFedTok(ctx, cache, tok)
	if err != nil {
		log.Errorf("Failed to set the federation token: %v", err)
	}

	// Fire the ticker every at 1/3 the period of token lifetime. This gives us a bit
	// of buffer in the event the Director is down for a short period of time.
	fedTokTicker := time.NewTicker(param.Director_FedTokenLifetime.GetDuration() / 3)
	egrp.Go(func() error {
		defer fedTokTicker.Stop()
		for {
			select {
			case <-fedTokTicker.C:
				// Time to ask the Director for a new token
				log.Debugln("Refreshing federation token")
				tok, err := server_utils.GetFedTok(ctx, cache)
				if err != nil {
					log.Errorf("Failed to get a federation token: %v", err)
					continue
				}

				// Set the token in the cache
				err = server_utils.SetFedTok(ctx, cache, tok)
				if err != nil {
					log.Errorf("Failed to write the federation token: %v", err)
				}
			case <-ctx.Done():
				return nil
			}
		}
	})
}
