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
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/file_cache"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_ui"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

var (
	ErrExitOnSignal error = errors.New("Exit program on signal")
	ErrRestart      error = errors.New("Restart program")
)

func LaunchModules(ctx context.Context, modules config.ServerType) (context.CancelFunc, error) {
	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}

	ctx, shutdownCancel := context.WithCancel(ctx)

	egrp.Go(func() error {
		_ = config.RestartFlag
		log.Debug("Will shutdown process on signal")
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		select {
		case sig := <-sigs:
			log.Warningf("Received signal %v; will shutdown process", sig)
			shutdownCancel()
			return ErrExitOnSignal
		case <-config.RestartFlag:
			log.Warningf("Received restart request; will restart the process")
			shutdownCancel()
			return ErrRestart
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

	// Set up necessary APIs to support Web UI, including auth and metrics
	if err := web_ui.ConfigureServerWebAPI(ctx, engine, egrp); err != nil {
		return shutdownCancel, err
	}

	if modules.IsEnabled(config.RegistryType) {

		viper.Set("Federation.RegistryURL", param.Server_ExternalWebUrl.GetString())

		if err = RegistryServe(ctx, engine, egrp); err != nil {
			return shutdownCancel, err
		}
	}

	if modules.IsEnabled(config.BrokerType) {
		viper.Set("Federation.BrokerURL", param.Server_ExternalWebUrl.GetString())

		rootGroup := engine.Group("/")
		broker.RegisterBroker(ctx, rootGroup)
		broker.LaunchNamespaceKeyMaintenance(ctx, egrp)
	}

	if modules.IsEnabled(config.DirectorType) {

		viper.Set("Director.DefaultResponse", "cache")

		viper.Set("Federation.DirectorURL", param.Server_ExternalWebUrl.GetString())

		if err = DirectorServe(ctx, engine, egrp); err != nil {
			return shutdownCancel, err
		}
	}

	// Start listening on the socket.  If `Server.WebPort` is 0, then a random port will be
	// selected and we'll update the configuration accordingly.  This needs to be done before
	// the XRootD configuration is written as the Server.WebPort is incorporated into the issuer URL.
	addr := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return shutdownCancel, err
	}
	lnReference := ln
	defer func() {
		if lnReference != nil {
			lnReference.Close()
		}
	}()
	config.UpdateConfigFromListener(ln)

	servers := make([]server_utils.XRootDServer, 0)

	if modules.IsEnabled(config.OriginType) {
		mode := param.Origin_Mode.GetString()
		switch mode {
		case "posix":
			if param.Origin_ExportVolume.GetString() == "" && (param.Xrootd_Mount.GetString() == "" || param.Origin_NamespacePrefix.GetString() == "") {
				return shutdownCancel, errors.Errorf(`
	Export information was not provided.
	Add the command line flag:

		-v /mnt/foo:/bar

	to export the directory /mnt/foo to the namespace prefix /bar in the data federation. Alternatively, specify Origin.ExportVolume in the parameters.yaml file:

		Origin:
			ExportVolume: /mnt/foo:/bar

	Or, specify Xrootd.Mount and Origin.NamespacePrefix in the parameters.yaml file:

		Xrootd:
			Mount: /mnt/foo
		Origin:
			NamespacePrefix: /bar`)
			}
		case "s3":
			if param.Origin_S3Region.GetString() == "" || param.Origin_S3ServiceName.GetString() == "" ||
				param.Origin_S3ServiceUrl.GetString() == "" {
				return shutdownCancel, errors.Errorf("The S3 origin is missing configuration options to run properly." +
					" You must specify a region, a service name and a service URL via the command line or via" +
					" your configuration file.")
			}
		default:
			return shutdownCancel, errors.Errorf("Currently-supported origin modes include posix and s3.")
		}

		server, err := OriginServe(ctx, engine, egrp, modules)
		if err != nil {
			return shutdownCancel, err
		}
		servers = append(servers, server)

		// Ordering: `LaunchBrokerListener` depends on the "right" value of Origin.NamespacePrefix
		// which is possibly not set until `OriginServe` is called.
		if param.Origin_EnableBroker.GetBool() {
			if err = origin_ui.LaunchBrokerListener(ctx, egrp); err != nil {
				return shutdownCancel, err
			}
		}
	}

	if modules.IsEnabled(config.LocalCacheType) {
		log.Debugln("Starting local cache listener")
		if err := simple_cache.LaunchListener(ctx, egrp); err != nil {
			log.Errorln("Failure when starting the local cache listener:", err)
			return shutdownCancel, err
		}
	}

	log.Info("Starting web engine...")
	lnReference = nil
	egrp.Go(func() error {
		if err := web_ui.RunEngineRoutineWithListener(ctx, engine, egrp, true, ln); err != nil {
			log.Errorln("Failure when running the web engine:", err)
			return err
		}
		log.Info("Web engine has shutdown")
		shutdownCancel()
		return nil
	})

	if err = server_utils.WaitUntilWorking(ctx, "GET", param.Server_ExternalWebUrl.GetString()+"/api/v1.0/health", "Web UI", http.StatusOK); err != nil {
		log.Errorln("Web engine startup appears to have failed:", err)
		return shutdownCancel, err
	}

	if modules.IsEnabled(config.OriginType) {
		log.Debug("Finishing origin server configuration")
		if err = OriginServeFinish(ctx, egrp); err != nil {
			return shutdownCancel, err
		}
	}

	// Origin needs to advertise once before the cache starts
	if modules.IsEnabled(config.CacheType) && modules.IsEnabled(config.OriginType) {
		log.Debug("Advertise Origin")
		if err = server_ui.Advertise(ctx, servers); err != nil {
			return shutdownCancel, err
		}
		desiredURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/director/origin" + param.Origin_NamespacePrefix.GetString()
		if err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 307); err != nil {
			log.Errorln("Origin does not seem to have advertised correctly:", err)
			return shutdownCancel, err
		}
	}

	if modules.IsEnabled(config.CacheType) {
		// Give five seconds for the origin to finish advertising to the director
		desiredURL := param.Server_ExternalWebUrl.GetString() + "/.well-known/openid-configuration"
		if err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200); err != nil {
			log.Errorln("Director does not seem to be working:", err)
			return shutdownCancel, err
		}
		server, err := CacheServe(ctx, engine, egrp)
		if err != nil {
			return shutdownCancel, err
		}

		servers = append(servers, server)
	}

	if modules.IsEnabled(config.OriginType) || modules.IsEnabled(config.CacheType) {
		log.Debug("Launching periodic advertise")
		if err := server_ui.LaunchPeriodicAdvertise(ctx, egrp, servers); err != nil {
			return shutdownCancel, err
		}
	}

	if modules.IsEnabled(config.CacheType) {
		log.Debug("Finishing cache server configuration")
		if err = CacheServeFinish(ctx, egrp); err != nil {
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
