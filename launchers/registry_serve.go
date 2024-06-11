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

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
)

func RegistryServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) error {
	log.Info("Initializing the namespace registry's database...")

	// Initialize the registry's sqlite database
	err := registry.InitializeDB()
	if err != nil {
		return errors.Wrap(err, "Unable to initialize the namespace registry database")
	}

	if param.Server_EnableUI.GetBool() {
		registry.InitOptionsCache(ctx, egrp)

		if err = registry.InitCustomRegistrationFields(); err != nil {
			return err
		}

		if err := registry.InitInstConfig(ctx, egrp); err != nil {
			return err
		}
	}

	if config.GetPreferredPrefix() == config.OsdfPrefix {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusWarning, "Start requesting from topology, status unknown")
		log.Info("Populating registry with namespaces from OSG topology service...")
		if err := registry.PopulateTopology(ctx); err != nil {
			panic(errors.Wrap(err, "Unable to populate topology table"))
		}

		// Checks topology for updates every 10 minutes
		go registry.PeriodicTopologyReload(ctx)
	}

	rootRouterGroup := engine.Group("/")
	// Register routes for server/Pelican client facing APIs
	registry.RegisterRegistryAPI(rootRouterGroup)
	// Register routes for APIs to registry Web UI
	if err := registry.RegisterRegistryWebAPI(rootRouterGroup); err != nil {
		return err
	}

	egrp.Go(func() error {
		<-ctx.Done()
		return registry.ShutdownRegistryDB()
	})

	return nil
}
