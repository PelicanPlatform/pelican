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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/cache_ui"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/xrootd"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

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
