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

package main

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/pelicanplatform/pelican/cache_ui"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pelicanplatform/pelican/xrootd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

func getNSAdsFromDirector() ([]director.NamespaceAd, error) {
	// Get the endpoint of the director
	var respNS []director.NamespaceAd
	directorEndpoint, err := getDirectorEndpoint()
	if err != nil {
		return respNS, errors.Wrapf(err, "Failed to get DirectorURL from config: %v", err)
	}

	// Create the listNamespaces url
	directorNSListEndpointURL, err := url.JoinPath(directorEndpoint, "api", "v1.0", "director", "listNamespaces")
	if err != nil {
		return respNS, err
	}

	respData, err := utils.MakeRequest(directorNSListEndpointURL, "GET", nil, nil)
	if err != nil {
		if jsonErr := json.Unmarshal(respData, &respNS); jsonErr == nil { // Error creating json
			return respNS, errors.Wrapf(err, "Failed to make request: %v", err)
		}
		return respNS, errors.Wrap(err, "Failed to make request")
	}

	err = json.Unmarshal(respData, &respNS)
	if err != nil {
		return respNS, errors.Wrapf(err, "Failed to marshal response in to JSON: %v", err)
	}

	return respNS, nil
}

func serveCache(cmd *cobra.Command, _ []string) error {
	err := serveCacheInternal(cmd.Context())
	if err != nil {
		return err
	}

	return nil
}

func serveCacheInternal(cmdCtx context.Context) error {
	// Use this context for any goroutines that needs to react to server shutdown
	err := config.InitServer(cmdCtx, config.CacheType)
	cobra.CheckErr(err)

	egrp, ok := cmdCtx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}

	err = xrootd.SetUpMonitoring(cmdCtx, egrp)
	if err != nil {
		return err
	}

	nsAds, err := getNSAdsFromDirector()
	if err != nil {
		return err
	}

	cacheServer := &cache_ui.CacheServer{}
	cacheServer.SetNamespaceAds(nsAds)
	err = server_ui.CheckDefaults(cacheServer)
	if err != nil {
		return err
	}

	cachePrefix := "/caches/" + param.Xrootd_Sitename.GetString()

	viper.Set("Origin.NamespacePrefix", cachePrefix)

	if err = server_ui.RegisterNamespaceWithRetry(cmdCtx, egrp); err != nil {
		return err
	}

	if err = server_ui.LaunchPeriodicAdvertise(cmdCtx, egrp, []server_utils.XRootDServer{cacheServer}); err != nil {
		return err
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	// Set up necessary APIs to support Web UI, including auth and metrics
	if err := web_ui.ConfigureServerWebAPI(cmdCtx, engine, egrp); err != nil {
		return err
	}

	egrp.Go(func() error {
		if err := web_ui.RunEngine(cmdCtx, engine, egrp); err != nil {
			log.Panicln("Failure when running the web engine:", err)
			return err
		} else {
			return err
		}
	})
	if param.Server_EnableUI.GetBool() {
		if err = web_ui.ConfigureEmbeddedPrometheus(cmdCtx, engine); err != nil {
			return errors.Wrap(err, "Failed to configure embedded prometheus instance")
		}

		if err = web_ui.InitServerWebLogin(cmdCtx); err != nil {
			return err
		}
	}

	configPath, err := xrootd.ConfigXrootd(cmdCtx, false)
	if err != nil {
		return err
	}

	xrootd.LaunchXrootdMaintenance(cmdCtx, cacheServer, 2*time.Minute)

	log.Info("Launching cache")
	launchers, err := xrootd.ConfigureLaunchers(false, configPath, false)
	if err != nil {
		return err
	}

	if err = daemon.LaunchDaemons(cmdCtx, launchers, egrp); err != nil {
		return err
	}

	return nil
}
