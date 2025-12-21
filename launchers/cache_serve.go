//go:build !windows

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

package launchers

import (
	"context"
	_ "embed"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/lotman"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pelicanplatform/pelican/xrootd"
)

func CacheServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, modules server_structs.ServerType) (server_structs.XRootDServer, error) {
	err := xrootd.SetUpMonitoring(ctx, egrp)
	if err != nil {
		return nil, err
	}

	if err := cache.CheckCacheSentinelLocation(); err != nil {
		return nil, err
	}

	if err := database.InitServerDatabase(server_structs.CacheType); err != nil {
		return nil, err
	}

	cache.RegisterCacheAPI(engine, ctx, egrp)

	cacheServer := &cache.CacheServer{}
	err = cacheServer.GetNamespaceAdsFromDirector()
	cacheServer.SetFilters()
	if err != nil {
		return nil, err
	}
	err = launcher_utils.CheckDefaults(cacheServer)
	if err != nil {
		return nil, err
	}

	// Initialize PKCS#11 helper after the defaults are set up
	initPKCS11(ctx, modules)

	// Register Lotman
	if param.Cache_EnableLotman.GetBool() {
		// Register the web endpoints
		if param.Lotman_EnableAPI.GetBool() {
			log.Debugln("Registering Lotman API")
			lotman.RegisterLotman(ctx, engine.Group("/", web_ui.ServerHeaderMiddleware))
		}

		// Until https://github.com/PelicanPlatform/lotman/issues/24 is closed, we can only really logic over
		// top-level prefixes because enumerating all object "directories" under a given federation prefix is
		// infeasible, but is currently the only way to nest namespaces in Lotman such that a sub namespace
		// can be associated with a top-level prefix.
		// To that end, we need to filter out any nested namespaces from the cache server's namespace ads.
		uniqueTopPrefixes := server_utils.FilterTopLevelPrefixes(cacheServer.GetNamespaceAds())

		// Bind the c library funcs to Go, instantiate lots, set up the Lotman database, etc
		if success := lotman.InitLotman(uniqueTopPrefixes); !success {
			return nil, errors.New("Failed to initialize lotman")
		}
	}

	// Don't perform Broker operations for site-local caches.
	if !param.Cache_EnableSiteLocalMode.GetBool() {
		broker.InitializeBrokerClient(ctx, egrp, engine)
	}
	configPath, err := xrootd.ConfigXrootd(ctx, false)
	if err != nil {
		return nil, err
	}

	xrootd.LaunchXrootdMaintenance(ctx, cacheServer, 2*time.Minute)

	// Site-local caches aren't part of the federation, so they don't expect
	// Director tests or federation tokens.
	if !param.Cache_EnableSiteLocalMode.GetBool() {
		cache.LaunchDirectorTestFileCleanup(ctx)
		cache.LaunchFedTokManager(ctx, egrp, cacheServer)
	}

	concLimit := param.Cache_Concurrency.GetInt()
	if concLimit > 0 {
		server_utils.LaunchConcurrencyMonitoring(ctx, egrp, cacheServer.GetServerType())
	}

	if param.Cache_SelfTest.GetBool() {
		err = xrootd.InitSelfTestDir()
		if err != nil {
			return nil, err
		}

		xrootd.PeriodicSelfTest(ctx, egrp, false)
	}

	// Director and origin also registers this metadata URL; avoid registering twice.
	if !modules.IsEnabled(server_structs.DirectorType) && !modules.IsEnabled(server_structs.OriginType) {
		server_utils.RegisterOIDCAPI(engine.Group("/", web_ui.ServerHeaderMiddleware), false)
	}

	log.Info("Launching cache")
	useCMSD := false
	privileged := false
	launchers, err := xrootd.ConfigureLaunchers(privileged, configPath, useCMSD, true)
	if err != nil {
		return nil, err
	}

	portStartCallback := func(port int) {
		if err := param.Set(param.Cache_Port.GetName(), port); err != nil {
			log.WithError(err).Warnf("Failed to set %s to %d", param.Cache_Port.GetName(), port)
		}
		if cacheUrl, err := url.Parse(param.Cache_Url.GetString()); err == nil {
			host := cacheUrl.Hostname()
			if host == "" {
				host = param.Server_Hostname.GetString()
			}
			currentPort := cacheUrl.Port()
			if currentPort == "" || currentPort == "0" {
				cacheUrl.Host = net.JoinHostPort(host, strconv.Itoa(port))
				if err := param.Set(param.Cache_Url.GetName(), cacheUrl.String()); err != nil {
					log.WithError(err).Warnf("Failed to set %s to %s", param.Cache_Url.GetName(), cacheUrl.String())
				} else {
					log.Debugf("Resetting %s to %s", param.Cache_Url.GetName(), cacheUrl.String())
				}
			}
		}
		log.Infoln("Cache startup complete on port", port)
	}

	// Store restart information before launching
	xrootd.StoreRestartInfo(launchers, egrp, portStartCallback, true, useCMSD, privileged)

	pids, err := xrootd.LaunchDaemons(ctx, launchers, egrp, portStartCallback)
	if err != nil {
		return nil, err
	}
	cacheServer.SetPids(pids)

	if param.Cache_EnableEvictionMonitoring.GetBool() {
		metrics.LaunchXrootdCacheEvictionMonitoring(ctx, egrp)
	}

	metrics.LaunchXrdCurlStatsMonitoring(ctx, egrp)

	return cacheServer, nil
}

// Finish configuration of the cache server.
func CacheServeFinish(ctx context.Context, egrp *errgroup.Group, cacheServer server_structs.XRootDServer) error {
	if param.Cache_EnableSiteLocalMode.GetBool() {
		log.Debugf("Skipping Cache registration because site-local mode is enabled (see %s)", param.Cache_EnableSiteLocalMode.GetName())
		return nil
	}

	log.Debug("Register Cache")
	metrics.SetComponentHealthStatus(metrics.OriginCache_Registry, metrics.StatusWarning, "Start to register namespaces for the cache server")
	if err := launcher_utils.RegisterNamespaceWithRetry(ctx, egrp, server_structs.GetCacheNs(param.Xrootd_Sitename.GetString())); err != nil {
		return err
	}
	log.Debug("Cache is registered")
	return nil
}
