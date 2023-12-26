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
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func serveDirector( /*cmd*/ *cobra.Command /*args*/, []string) error {
	// Use this context for any goroutines that needs to react to server shutdown
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	// Use this wait group to ensure the goroutines can finish before the server exits/shutdown
	var wg sync.WaitGroup

	// This anonymous function ensures we cancel any context and wait for those goroutines to
	// finish their cleanup work before the server exits
	defer func() {
		shutdownCancel()
		wg.Wait()
	}()

	log.Info("Initializing Director GeoIP database...")
	director.InitializeDB()

	if config.GetPreferredPrefix() == "OSDF" {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusWarning, "Start requesting from topology, status unknown")
		log.Info("Generating/advertising server ads from OSG topology service...")

		// Get the ads from topology, populate the cache, and keep the cache
		// updated with fresh info
		if err := director.AdvertiseOSDF(); err != nil {
			panic(err)
		}
	}
	go director.PeriodicCacheReload()

	director.ConfigTTLCache(shutdownCtx, &wg)
	wg.Add(1) // Add to wait group after ConfigTTLCache finishes to avoid deadlock

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	// We configure Prometheus differently for director than for the rest servers,
	// although in the future we probably want to pass the server type to the
	// metric config function just because each server may have different config
	if err := web_ui.ConfigureServerWebAPI(engine); err != nil {
		return err
	}

	// Configure the shortcut middleware to either redirect to a cache
	// or to an origin
	defaultResponse := param.Director_DefaultResponse.GetString()
	if !(defaultResponse == "cache" || defaultResponse == "origin") {
		return fmt.Errorf("The director's default response must either be set to 'cache' or 'origin',"+
			" but you provided %q. Was there a typo?", defaultResponse)
	}
	log.Debugf("The director will redirect to %ss by default", defaultResponse)
	rootGroup := engine.Group("/")
	director.RegisterDirectorAuth(rootGroup)
	director.RegisterDirectorWebAPI(rootGroup)
	engine.Use(director.ShortcutMiddleware(defaultResponse))
	director.RegisterDirector(rootGroup)

	log.Info("Starting web engine...")
	go web_ui.RunEngine(engine)

	go web_ui.InitServerWebLogin()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigs
	_ = sig

	return nil
}
