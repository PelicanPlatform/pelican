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
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/namespace_registry"
	"github.com/pelicanplatform/pelican/web_ui"
)

func serveNamespaceRegistry( /*cmd*/ *cobra.Command /*args*/, []string) error {
	log.Info("Initializing the namespace registry's database...")

	// Initialize the registry's sqlite database
	err := nsregistry.InitializeDB()
	if err != nil {
		return errors.Wrap(err, "Unable to initialize the namespace registry database")
	}

	if config.GetPreferredPrefix() == "OSDF" {
		log.Info("Populating registry with namespaces from OSG topology service...")
		if err := nsregistry.PopulateTopology(); err != nil {
			panic(errors.Wrap(err, "Unable to populate topology table"))
		}

		// Checks topology for updates every 10 minutes
		go nsregistry.PeriodicTopologyReload()
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	if err := web_ui.ConfigureServerWebAPI(engine, false); err != nil {
		return err
	}
	rootRouterGroup := engine.Group("/")
	// Call out to nsregistry to establish routes for the gin engine
	nsregistry.RegisterNamespaceRegistry(rootRouterGroup)
	nsregistry.RegisterNamespacesRegistryWebAPI(rootRouterGroup)
	log.Info("Starting web engine...")

	// Might need to play around with this setting more to handle
	// more complicated routing scenarios where we can't just use
	// a wildcard. It removes duplicate / from the resource.
	//engine.RemoveExtraSlash = true
	go web_ui.RunEngine(engine)

	go web_ui.InitServerWebLogin()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigs
	_ = sig

	return nil
}
