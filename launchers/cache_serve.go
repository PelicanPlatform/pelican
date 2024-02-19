//go:build !windows

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

package launchers

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/cache_ui"
	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/xrootd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

func getNSAdsFromDirector() ([]common.NamespaceAdV2, error) {
	// Get the endpoint of the director
	var respNS []common.NamespaceAdV2

	directorEndpoint := param.Federation_DirectorUrl.GetString()
	if directorEndpoint == "" {
		return nil, errors.New("No director specified; give the federation name (-f)")
	}

	directorEndpointURL, err := url.Parse(directorEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse director url")
	}

	if err != nil {
		return respNS, errors.Wrapf(err, "Failed to get DirectorURL from config: %v", err)
	}

	// Create the listNamespaces url
	directorNSListEndpointURL, err := url.JoinPath(directorEndpointURL.String(), "api", "v2.0", "director", "listNamespaces")
	if err != nil {
		return respNS, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", "https://70fa1e4d6777:8444/api/v2.0/director/listNamespaces", nil)
	if err != nil {
		return respNS, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return respNS, err
	}
	defer resp.Body.Close()

	// Attempt to get data from the 2.0 endpoint, if that returns a 404 error, then attempt to get data
	// from the 1.0 endpoint and convert from V1 to V2

	respData, err := utils.MakeRequest(directorNSListEndpointURL, "GET", nil, nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			directorNSListEndpointURL, err = url.JoinPath(directorEndpoint, "api", "v1.0", "director", "listNamespaces")
			if err != nil {
				return respNS, err
			}
			respData, err = utils.MakeRequest(directorNSListEndpointURL, "GET", nil, nil)
			var respNSV1 []common.NamespaceAdV1
			if err != nil {
				return respNS, errors.Wrap(err, "Failed to make request")
			} else {
				if jsonErr := json.Unmarshal(respData, &respNSV1); jsonErr == nil { // Error creating json
					return respNS, errors.Wrapf(err, "Failed to make request: %v", err)
				}
				respNS = director.ConvertNamespaceAdsV1ToV2(respNSV1, nil)
			}
		} else {
			return respNS, errors.Wrap(err, "Failed to make request")
		}
	} else {
		err = json.Unmarshal(respData, &respNS)
		if err != nil {
			return respNS, errors.Wrapf(err, "Failed to marshal response in to JSON: %v", err)
		}
	}

	return respNS, nil
}

func CacheServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) (server_utils.XRootDServer, error) {

	err := xrootd.SetUpMonitoring(ctx, egrp)
	if err != nil {
		return nil, err
	}

	cacheServer := &cache_ui.CacheServer{}
	err = cacheServer.GetNamespaceAdsFromDirector()
	if err != nil {
		return nil, err
	}
	err = server_ui.CheckDefaults(cacheServer)
	if err != nil {
		return nil, err
	}

	cachePrefix := "/caches/" + param.Xrootd_Sitename.GetString()

	viper.Set("Cache.NamespacePrefix", cachePrefix)

	broker.RegisterBrokerCallback(ctx, engine.Group("/"))
	broker.LaunchNamespaceKeyMaintenance(ctx, egrp)
	configPath, err := xrootd.ConfigXrootd(ctx, false)
	if err != nil {
		return nil, err
	}

	xrootd.LaunchXrootdMaintenance(ctx, cacheServer, 2*time.Minute)

	log.Info("Launching cache")
	launchers, err := xrootd.ConfigureLaunchers(false, configPath, false, true)
	if err != nil {
		return nil, err
	}

	if err = daemon.LaunchDaemons(ctx, launchers, egrp); err != nil {
		return nil, err
	}

	return cacheServer, nil
}

// Finish configuration of the cache server.
func CacheServeFinish(ctx context.Context, egrp *errgroup.Group) error {
	return server_ui.RegisterNamespaceWithRetry(ctx, egrp, param.Cache_NamespacePrefix.GetString())
}
