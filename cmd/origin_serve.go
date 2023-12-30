//go:build !windows

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
	_ "embed"
	"sync"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pelicanplatform/pelican/xrootd"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func serveOrigin( /*cmd*/ *cobra.Command /*args*/, []string) error {
	// Use this context for any goroutines that needs to react to server shutdown
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	// Use this wait group to ensure the goroutines can finish before the server exits/shutdown
	var wg sync.WaitGroup

	// This anonymous function ensures we cancel any context and wait for those goroutines to
	// finish their cleanup work before the server exits
	defer func() {
		shutdownCancel()
		wg.Wait()
		config.CleanupTempResources()
	}()

	err := xrootd.SetUpMonitoring(shutdownCtx, &wg)
	if err != nil {
		return err
	}
	wg.Add(1) // Add to wg afterward to ensure no error causes deadlock

	originServer := &origin_ui.OriginServer{}
	err = server_ui.CheckDefaults(originServer)
	if err != nil {
		return err
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	if param.Origin_EnableUI.GetBool() {
		// Set up necessary APIs to support Web UI, including auth and metrics
		if err := web_ui.ConfigureServerWebAPI(engine); err != nil {
			return err
		}
	}

	// Set up the APIs unrelated to UI, which only contains director-based health test reporting endpoint for now
	if err = origin_ui.ConfigureOriginAPI(engine, shutdownCtx, &wg); err != nil {
		return err
	}
	wg.Add(1)

	// In posix mode, we rely on xrootd to export keys. When we run the origin with
	// different backends, we instead export the keys via the Pelican process
	if param.Origin_Mode.GetString() != "posix" {
		if err = origin_ui.ConfigIssJWKS(engine.Group("/.well-known")); err != nil {
			return err
		}
	}

	if err = server_ui.RegisterNamespaceWithRetry(); err != nil {
		return err
	}
	if err = server_ui.PeriodicAdvertise(originServer); err != nil {
		return err
	}
	if param.Origin_EnableIssuer.GetBool() {
		if err = oa4mp.ConfigureOA4MPProxy(engine); err != nil {
			return err
		}
	}

	go web_ui.RunEngine(engine)

	if param.Origin_EnableUI.GetBool() {
		go web_ui.InitServerWebLogin()
	}

	configPath, err := xrootd.ConfigXrootd(true)
	if err != nil {
		return err
	}

	if param.Origin_SelfTest.GetBool() {
		go origin_ui.PeriodicSelfTest()
	}

	xrootd.LaunchXrootdMaintenance(shutdownCtx, 2*time.Minute)

	privileged := param.Origin_Multiuser.GetBool()
	launchers, err := xrootd.ConfigureLaunchers(privileged, configPath, param.Origin_EnableCmsd.GetBool())
	if err != nil {
		return err
	}

	if param.Origin_EnableIssuer.GetBool() {
		oa4mp_launcher, err := oa4mp.ConfigureOA4MP()
		if err != nil {
			return err
		}
		launchers = append(launchers, oa4mp_launcher)
	}

	ctx := context.Background()
	if err = daemon.LaunchDaemons(ctx, launchers); err != nil {
		return err
	}
	log.Info("Clean shutdown of the origin")
	return nil
}
