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
	"fmt"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
)

func DirectorServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) error {

	log.Info("Initializing Director GeoIP database...")
	director.InitializeDB(ctx)

	director.ConfigFilterdServers()

	director.LaunchTTLCache(ctx, egrp)

	director.LaunchMapMetrics(ctx, egrp)

	director.ConfigFilterdServers()

	director.LaunchServerIOQuery(ctx, egrp)

	if config.GetPreferredPrefix() == config.OsdfPrefix {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusWarning, "Start requesting from topology, status unknown")
		log.Info("Generating/advertising server ads from OSG topology service...")

		// Get the ads from topology, populate the cache, and keep the cache
		// updated with fresh info
		if err := director.AdvertiseOSDF(ctx); err != nil {
			return err
		}
		go director.PeriodicCacheReload(ctx)
	}

	// Configure the shortcut middleware to either redirect to a cache
	// or to an origin
	defaultResponse := param.Director_DefaultResponse.GetString()
	if !(defaultResponse == "cache" || defaultResponse == "origin") {
		return fmt.Errorf("the director's default response must either be set to 'cache' or 'origin',"+
			" but you provided %q. Was there a typo?", defaultResponse)
	}
	log.Debugf("The director will redirect to %ss by default", defaultResponse)
	if param.Director_SupportContactUrl.IsSet() {
		_, err := url.Parse(param.Director_SupportContactUrl.GetString())
		if err != nil {
			return errors.Wrap(err, "invalid URL for Director.SupportContactUrl")
		}
	}
	rootGroup := engine.Group("/")
	director.RegisterDirectorOIDCAPI(rootGroup)
	director.RegisterDirectorWebAPI(rootGroup)
	engine.Use(director.ShortcutMiddleware(defaultResponse))
	director.RegisterDirectorAPI(ctx, rootGroup)

	return nil
}
