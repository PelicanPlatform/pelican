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
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

func LaunchModules(ctx context.Context, modules config.ServerType) (context.CancelFunc, error) {
	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}

	ctx, shutdownCancel := context.WithCancel(ctx)

	egrp.Go(func() error {
		log.Debug("Will shutdown process on signal")
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		select {
		case sig := <-sigs:
			log.Debugf("Received signal %v; will shutdown process", sig)
			shutdownCancel()
			return errors.New("Federation process has been cancelled")
		case <-ctx.Done():
			return nil
		}
	})

	engine, err := web_ui.GetEngine()
	if err != nil {
		return shutdownCancel, err
	}

	if err = config.InitServer(ctx, modules); err != nil {
		return shutdownCancel, errors.Wrap(err, "Failure when configuring the server")
	}

	if param.Server_EnableUI.GetBool() {
		// Set up necessary APIs to support Web UI, including auth and metrics
		if err := web_ui.ConfigureServerWebAPI(ctx, engine, egrp); err != nil {
			return shutdownCancel, err
		}
	}

	if modules.IsEnabled(config.RegistryType) {

		viper.Set("Federation.RegistryURL", param.Server_ExternalWebUrl.GetString())

		if err = RegistryServe(ctx, engine, egrp); err != nil {
			return shutdownCancel, err
		}
	}

	if modules.IsEnabled(config.DirectorType) {

		viper.Set("Director.DefaultResponse", "cache")

		viper.Set("Federation.DirectorURL", param.Server_ExternalWebUrl.GetString())

		if err = DirectorServe(ctx, engine, egrp); err != nil {
			return shutdownCancel, err
		}
	}

	servers := make([]server_utils.XRootDServer, 0)
	if modules.IsEnabled(config.OriginType) {
		if param.Origin_Mode.GetString() != "posix" {
			return shutdownCancel, errors.Errorf("Origin Mode must be set to posix, S3 is not currently supported.")
		}

		if param.Origin_ExportVolume.GetString() == "" {
			return shutdownCancel, errors.Errorf("Origin.ExportVolume must be set in the parameters.yaml file.")
		}

		server, err := OriginServe(ctx, engine, egrp)
		if err != nil {
			return shutdownCancel, err
		}
		servers = append(servers, server)

		err = server_utils.WaitUntilWorking(ctx, "GET", param.Origin_Url.GetString()+"/.well-known/openid-configuration", "Origin", http.StatusOK)
		if err != nil {
			return shutdownCancel, err
		}

		log.Debug("Finishing origin server configuration")
	}

	log.Info("Starting web engine...")
	egrp.Go(func() error {
		if err := web_ui.RunEngine(ctx, engine, egrp); err != nil {
			log.Errorln("Failure when running the web engine:", err)
			shutdownCancel()
			return err
		}
		log.Info("Web engine has shutdown")
		shutdownCancel()
		return nil
	})

	if err = server_utils.WaitUntilWorking(ctx, "GET", param.Server_ExternalWebUrl.GetString()+"/view", "Web UI", http.StatusOK); err != nil {
		log.Errorln("Web engine startup appears to have failed:", err)
	}

	if modules.IsEnabled(config.OriginType) {
		if err = OriginServeFinish(ctx, egrp); err != nil {
			return shutdownCancel, err
		}
	}

	// Include cache here just in case, although we currently don't use launcher to launch cache
	if modules.IsEnabled(config.OriginType) || modules.IsEnabled(config.CacheType) {
		log.Debug("Launching periodic advertise")
		if err := server_ui.LaunchPeriodicAdvertise(ctx, egrp, servers); err != nil {
			return shutdownCancel, err
		}
	}

	if param.Server_EnableUI.GetBool() {
		if err = web_ui.ConfigureEmbeddedPrometheus(ctx, engine); err != nil {
			return shutdownCancel, errors.Wrap(err, "Failed to configure embedded prometheus instance")
		}

		log.Info("Starting web login...")
		egrp.Go(func() error { return web_ui.InitServerWebLogin(ctx) })
	}

	return shutdownCancel, nil
}
