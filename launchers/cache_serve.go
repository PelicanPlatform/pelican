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
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/lotman"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/xrootd"
)

func CacheServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, modules config.ServerType) (server_structs.XRootDServer, error) {
	err := xrootd.SetUpMonitoring(ctx, egrp)
	if err != nil {
		return nil, err
	}

	if err := cache.CheckCacheSentinelLocation(); err != nil {
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

	// Register Lotman
	if param.Cache_EnableLotman.GetBool() {
		// Register the web endpoints
		if param.Lotman_EnableAPI.GetBool() {
			log.Debugln("Registering Lotman API")
			lotman.RegisterLotman(ctx, engine.Group("/"))
		}
		// Bind the c library funcs to Go
		if success := lotman.InitLotman(); !success {
			return nil, errors.New("Failed to initialize lotman")
		}
	}

	broker.RegisterBrokerCallback(ctx, engine.Group("/"))
	broker.LaunchNamespaceKeyMaintenance(ctx, egrp)
	configPath, err := xrootd.ConfigXrootd(ctx, false)
	if err != nil {
		return nil, err
	}

	xrootd.LaunchXrootdMaintenance(ctx, cacheServer, 2*time.Minute)

	cache.LaunchDirectorTestFileCleanup(ctx)

	if param.Cache_SelfTest.GetBool() {
		err = cache.InitSelfTestDir()
		if err != nil {
			return nil, err
		}

		cache.PeriodicCacheSelfTest(ctx, egrp)
	}

	// Director and origin also registers this metadata URL; avoid registering twice.
	if !modules.IsEnabled(config.DirectorType) && !modules.IsEnabled(config.OriginType) {
		server_utils.RegisterOIDCAPI(engine.Group("/"), false)
	}

	log.Info("Launching cache")
	launchers, err := xrootd.ConfigureLaunchers(false, configPath, false, true)
	if err != nil {
		return nil, err
	}

	portStartCallback := func(port int) {
		viper.Set("Cache.Port", port)
		if cacheUrl, err := url.Parse(param.Origin_Url.GetString()); err == nil {
			cacheUrl.Host = cacheUrl.Hostname() + ":" + strconv.Itoa(port)
			viper.Set("Cache.Url", cacheUrl.String())
			log.Debugln("Resetting Cache.Url to", cacheUrl.String())
		}
		log.Infoln("Cache startup complete on port", port)
	}

	pids, err := xrootd.LaunchDaemons(ctx, launchers, egrp, portStartCallback)
	if err != nil {
		return nil, err
	}
	cacheServer.SetPids(pids)
	return cacheServer, nil
}

// Finish configuration of the cache server.
func CacheServeFinish(ctx context.Context, egrp *errgroup.Group, cacheServer server_structs.XRootDServer) error {
	log.Debug("Register Cache")
	metrics.SetComponentHealthStatus(metrics.OriginCache_Registry, metrics.StatusWarning, "Start to register namespaces for the cache server")
	if err := launcher_utils.RegisterNamespaceWithRetry(ctx, egrp, server_structs.GetCacheNS(param.Xrootd_Sitename.GetString())); err != nil {
		return err
	}
	log.Debug("Cache is registered")
	return nil
}
