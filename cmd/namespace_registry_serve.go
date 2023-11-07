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
	"crypto/elliptic"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	nsregistry "github.com/pelicanplatform/pelican/namespace-registry"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func serveNamespaceRegistry( /*cmd*/ *cobra.Command /*args*/, []string) error {
	log.Info("Initializing the namespace registry's database...")

	// Initialize the registry's sqlite database
	err := nsregistry.InitializeDB()
	if err != nil {
		return errors.Wrap(err, "Unable to initialize the namespace registry database")
	}

	// The registry needs its own private key. If one doesn't exist, this will generate it
	issuerKeyFile := param.IssuerKey.GetString()
	err = config.GeneratePrivateKey(issuerKeyFile, elliptic.P256())
	if err != nil {
		return errors.Wrap(err, "Failed to generate registry private key")
	}

	if err := config.GenerateCert(); err != nil {
		return err
	}
	if err != nil {
		return errors.Wrap(err, "Failed to generate TLS certificate")
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	if err := web_ui.ConfigureMetrics(engine, false); err != nil {
		return err
	}

	// Call out to nsregistry to establish routes for the gin engine
	nsregistry.RegisterNamespaceRegistry(engine.Group("/"))
	log.Info("Starting web engine...")

	// Might need to play around with this setting more to handle
	// more complicated routing scenarios where we can't just use
	// a wildcard. It removes duplicate / from the resource.
	//engine.RemoveExtraSlash = true
	go web_ui.RunEngine(engine)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigs
	_ = sig

	return nil
}
