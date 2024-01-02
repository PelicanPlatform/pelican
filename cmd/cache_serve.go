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

func serveCacheInternal(ctx context.Context) error {
	// Use this context for any goroutines that needs to react to server shutdown
	shutdownCtx, shutdownCancel := context.WithCancel(ctx)
	// Use this wait group to ensure the goroutines can finish before the server exits/shutdown
	egrp, ctx := errgroup.WithContext(shutdownCtx)

	// This anonymous function ensures we cancel any context and wait for those goroutines to
	// finish their cleanup work before the server exits
	defer func() {
		shutdownCancel()
		if err := egrp.Wait(); err != nil {
			log.Errorln("Failure when cleaning up cache:", err)
		}
		if err := config.CleanupTempResources(); err != nil {
			log.Errorln("Failure when cleaning up temp directories:", err)
		}
	}()

	err := xrootd.SetUpMonitoring(ctx, egrp)
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

	if err = server_ui.RegisterNamespaceWithRetry(ctx, egrp); err != nil {
		return err
	}

	if err = server_ui.LaunchPeriodicAdvertise(ctx, egrp, []server_utils.XRootDServer{cacheServer}); err != nil {
		return err
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	// Set up necessary APIs to support Web UI, including auth and metrics
	if err := web_ui.ConfigureServerWebAPI(ctx, engine, egrp); err != nil {
		return err
	}

	go func() {
		if err := web_ui.RunEngine(ctx, engine, egrp); err != nil {
			log.Panicln("Failure when running the web engine:", err)
		}
		shutdownCancel()
	}()
	if param.Server_EnableUI.GetBool() {
		if err = web_ui.InitServerWebLogin(ctx); err != nil {
			return err
		}
	}

	configPath, err := xrootd.ConfigXrootd(ctx, false)
	if err != nil {
		return err
	}

	xrootd.LaunchXrootdMaintenance(ctx, 2*time.Minute)

	log.Info("Launching cache")
	launchers, err := xrootd.ConfigureLaunchers(false, configPath, false)
	if err != nil {
		return err
	}

	if err = daemon.LaunchDaemons(ctx, launchers, egrp); err != nil {
		return err
	}

	log.Info("Clean shutdown of the cache")
	return nil
}
