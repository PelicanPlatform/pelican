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
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pelicanplatform/pelican/web_ui"
)

func serveRegistry(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	err := serveRegistryInternal(ctx)
	if err != nil {
		return err
	}

	return nil
}

func serveRegistryInternal(ctx context.Context) error {
	log.Info("Initializing the namespace registry's database...")
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	defer shutdownCancel()

	// Initialize the registry's sqlite database
	err := registry.InitializeDB()
	if err != nil {
		return errors.Wrap(err, "Unable to initialize the namespace registry database")
	}

	if config.GetPreferredPrefix() == "OSDF" {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusWarning, "Start requesting from topology, status unknown")
		log.Info("Populating registry with namespaces from OSG topology service...")
		if err := registry.PopulateTopology(); err != nil {
			panic(errors.Wrap(err, "Unable to populate topology table"))
		}

		// Checks topology for updates every 10 minutes
		go registry.PeriodicTopologyReload()
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	if param.Server_EnableUI.GetBool() {
		// Set up necessary APIs to support Web UI, including auth and metrics
		if err := web_ui.ConfigureServerWebAPI(engine); err != nil {
			return err
		}

		if err := web_ui.ConfigOAuthClientAPIs(engine); err != nil {
			return err
		}
	}

	rootRouterGroup := engine.Group("/")
	// Call out to registry to establish routes for the gin engine
	registry.RegisterRegistryRoutes(rootRouterGroup)
	registry.RegisterRegistryWebAPI(rootRouterGroup)
	log.Info("Starting web engine...")

	// Might need to play around with this setting more to handle
	// more complicated routing scenarios where we can't just use
	// a wildcard. It removes duplicate / from the resource.
	//engine.RemoveExtraSlash = true
	go func() {
		if err := web_ui.RunEngine(shutdownCtx, engine); err != nil {
			log.Panicln("Failure when running the web engine:", err)
		}
		shutdownCancel()
	}()

	if param.Server_EnableUI.GetBool() {
		log.Info("Starting web engine...")
		go web_ui.InitServerWebLogin()
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigs
	_ = sig
	shutdownCancel()

	return nil
}
