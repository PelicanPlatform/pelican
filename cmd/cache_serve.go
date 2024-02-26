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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/cache_ui"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pelicanplatform/pelican/xrootd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

func serveCache(cmd *cobra.Command, _ []string) error {
	cancel, err := serveCacheInternal(cmd.Context())
	if err != nil {
		cancel()
		return err
	}

	return nil
}

func serveCacheInternal(cmdCtx context.Context) (context.CancelFunc, error) {
	// Use this context for any goroutines that needs to react to server shutdown
	ctx, shutdownCancel := context.WithCancel(cmdCtx)

	err := config.InitServer(ctx, config.CacheType)
	cobra.CheckErr(err)

	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}

	// Added the same logic from launcher.go as we currently launch cache separately from other services
	egrp.Go(func() error {
		log.Debug("Will shutdown process on signal")
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		select {
		case sig := <-sigs:
			log.Warningf("Received signal %v; will shutdown process", sig)
			shutdownCancel()
			return launchers.ErrExitOnSignal
		case <-config.RestartFlag:
			log.Warningf("Received restart request; will restart the process")
			shutdownCancel()
			return launchers.ErrRestart
		case <-ctx.Done():
			return nil
		}
	})

	err = xrootd.SetUpMonitoring(ctx, egrp)
	if err != nil {
		return shutdownCancel, err
	}

	if err != nil {
		return shutdownCancel, err
	}

	cacheServer := &cache_ui.CacheServer{}
	err = cacheServer.GetNamespaceAdsFromDirector()
	if err != nil {
		return shutdownCancel, err
	}
	err = server_ui.CheckDefaults(cacheServer)
	if err != nil {
		return shutdownCancel, err
	}

	cachePrefix := "/caches/" + param.Xrootd_Sitename.GetString()

	viper.Set("Origin.NamespacePrefix", cachePrefix)

	if err = server_ui.RegisterNamespaceWithRetry(ctx, egrp); err != nil {
		return shutdownCancel, err
	}

	if err = server_ui.LaunchPeriodicAdvertise(ctx, egrp, []server_utils.XRootDServer{cacheServer}); err != nil {
		return shutdownCancel, err
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return shutdownCancel, err
	}

	// Set up necessary APIs to support Web UI, including auth and metrics
	if err := web_ui.ConfigureServerWebAPI(ctx, engine, egrp); err != nil {
		return shutdownCancel, err
	}

	egrp.Go(func() (err error) {
		if err = web_ui.RunEngine(ctx, engine, egrp); err != nil {
			log.Errorln("Failure when running the web engine:", err)
		}
		return
	})
	if param.Server_EnableUI.GetBool() {
		if err = web_ui.ConfigureEmbeddedPrometheus(ctx, engine); err != nil {
			return shutdownCancel, errors.Wrap(err, "Failed to configure embedded prometheus instance")
		}

		if err = web_ui.InitServerWebLogin(ctx); err != nil {
			return shutdownCancel, err
		}
	}
	broker.RegisterBrokerCallback(ctx, engine.Group("/"))
	broker.LaunchNamespaceKeyMaintenance(ctx, egrp)

	configPath, err := xrootd.ConfigXrootd(ctx, false)
	if err != nil {
		return shutdownCancel, err
	}

	if err = cache_ui.LaunchRequestListener(ctx, egrp); err != nil {
		return shutdownCancel, err
	}

	xrootd.LaunchXrootdMaintenance(ctx, cacheServer, 2*time.Minute)

	log.Info("Launching cache")
	launchers, err := xrootd.ConfigureLaunchers(false, configPath, false, true)
	if err != nil {
		return shutdownCancel, err
	}

	if err = daemon.LaunchDaemons(ctx, launchers, egrp); err != nil {
		return shutdownCancel, err
	}

	return shutdownCancel, nil
}
