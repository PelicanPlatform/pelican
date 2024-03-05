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

package cache_ui

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type (
	CacheServer struct {
		server_utils.NamespaceHolder
		namespaceFilter map[string]struct{}
	}
)

func (server *CacheServer) CreateAdvertisement(name string, originUrl string, originWebUrl string) (common.OriginAdvertiseV2, error) {
	ad := common.OriginAdvertiseV2{
		Name:       name,
		DataURL:    originUrl,
		WebURL:     originWebUrl,
		Namespaces: server.GetNamespaceAds(),
	}

	return ad, nil
}

func (server *CacheServer) SetFilters() {
	server.namespaceFilter = make(map[string]struct{})
	if viper.IsSet("Cache.AcceptedNamespaces") {
		nsList := param.Cache_AcceptedNamespaces.GetStringSlice()
		for _, ns := range nsList {
			server.namespaceFilter[ns] = struct{}{}
		}
	}
}

func (server *CacheServer) filterAdsBasedOnNamespace(nsAds []common.NamespaceAdV2) []common.NamespaceAdV2 {
	filteredAds := []common.NamespaceAdV2{}
	if len(server.namespaceFilter) > 0 {
		for _, ad := range nsAds {
			ns := ad.Path
			sentinel := true
			for sentinel {
				_, exists := server.namespaceFilter[ns]
				if exists {
					filteredAds = append(filteredAds, ad)
					break
				}

				splitIndex := strings.LastIndex(ns, "/")
				if splitIndex != -1 && splitIndex != 0 {
					ns = ns[:splitIndex]
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
	var respNS []common.NamespaceAdV2

	directorEndpoint := param.Federation_DirectorUrl.GetString()
	if directorEndpoint == "" {
		return errors.New("No director specified; give the federation name (-f)")
	}

	directorEndpointURL, err := url.Parse(directorEndpoint)
	if err != nil {
		return errors.Wrap(err, "Unable to parse director url")
	}

	if err != nil {
		return errors.Wrapf(err, "Failed to get DirectorURL from config: %v", err)
	}

	// Create the listNamespaces url
	directorNSListEndpointURL, err := url.JoinPath(directorEndpointURL.String(), "api", "v2.0", "director", "listNamespaces")
	if err != nil {
		return err
	}

	// Attempt to get data from the 2.0 endpoint, if that returns a 404 error, then attempt to get data
	// from the 1.0 endpoint and convert from V1 to V2

	respData, err := utils.MakeRequest(directorNSListEndpointURL, "GET", nil, nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			directorNSListEndpointURL, err = url.JoinPath(directorEndpoint, "api", "v1.0", "director", "listNamespaces")
			if err != nil {
				return err
			}
			respData, err = utils.MakeRequest(directorNSListEndpointURL, "GET", nil, nil)
			var respNSV1 []common.NamespaceAdV1
			if err != nil {
				return errors.Wrap(err, "Failed to make request")
			} else {
				if jsonErr := json.Unmarshal(respData, &respNSV1); jsonErr == nil { // Error creating json
					return errors.Wrapf(err, "Failed to make request: %v", err)
				}
				respNS = director.ConvertNamespaceAdsV1ToV2(respNSV1, nil)
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

	if viper.IsSet("Cache.AcceptedNamespaces") {
		respNS = server.filterAdsBasedOnNamespace(respNS)
	}

	server.SetNamespaceAds(respNS)

	return nil
}

func (server *CacheServer) GetServerType() config.ServerType {
	return config.CacheType
}
