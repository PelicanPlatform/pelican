//go:build darwin || (linux && ppc64le)

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
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/lotman"
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
		server_utils.RegisterOIDCAPI(engine)
	}

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
	return launcher_utils.RegisterNamespaceWithRetry(ctx, egrp, "/caches/"+param.Xrootd_Sitename.GetString())
}
