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
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
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

	// Register OIDC endpoint
	if param.Server_EnableUI.GetBool() {
		if modules.IsEnabled(config.RegistryType) ||
			modules.IsEnabled(config.OriginType) ||
			modules.IsEnabled(config.CacheType) {
			err := web_ui.ConfigOAuthClientAPIs(engine)
			if err != nil {
				return shutdownCancel, err
			}
		}
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

		mode := param.Origin_StorageType.GetString()
		originExports, err := common.GetOriginExports()
		if err != nil {
			return shutdownCancel, err
		}

		switch mode {
		case "posix":
			if len(*originExports) == 0 {
				return shutdownCancel, errors.Errorf(`
	Export information was not provided.
	To specify exports via the command line, use:

				-v /mnt/foo:/bar -v /mnt/test:/baz

	to export the directories /mnt/foo and /mnt/test under the namespace prefixes /bar and /baz, respectively.

	Alternatively, specify Origin.Exports in the parameters.yaml file:

	Origin:
		Exports:
		- StoragePrefix: /mnt/foo
		  FederationPrefix: /bar
		  Capabilities: ["PublicReads", "Writes", "Listings"]
		- StoragePrefix: /mnt/test
		  FederationPrefix: /baz
		  Capabilities: ["Writes"]

	to export the directories /mnt/foo and /mnt/test under the namespace prefixes /bar and /baz, respectively (with listed permissions).
	`)
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

		// Ordering: `LaunchBrokerListener` depends on the "right" value of Origin.FederationPrefix
		// which is possibly not set until `OriginServe` is called.
		// NOTE: Until the Broker supports multi-export origins, we've made the assumption that there
		// is only one namespace prefix available here and that it lives in Origin.FederationPrefix
		if param.Origin_EnableBroker.GetBool() {
			if err = origin_ui.LaunchBrokerListener(ctx, egrp); err != nil {
				return shutdownCancel, err
			}
		}
	}

	var lc *local_cache.LocalCache
	if modules.IsEnabled(config.LocalCacheType) {
		// Create and register the cache routines before the web interface is up
		lc, err = local_cache.NewLocalCache(ctx, egrp, local_cache.WithDeferConfig(true))
		if err != nil {
			return shutdownCancel, err
		}
		rootGroup := engine.Group("/")
		lc.Register(ctx, rootGroup)
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

		// We may have arbitrarily many exports, so we should make sure they're all advertised before
		// starting the cache up. This guarantees that when the cache starts, it is immediately aware
		// of the namespaces and doesn't have to wait an entire cycle to learn about them from the director

		// To check all of the advertisements, we'll launch a WaitUntilWorking concurrently for each of them.
		originExports, err := common.GetOriginExports()
		if err != nil {
			return shutdownCancel, err
		}
		errCh := make(chan error, len(*originExports))
		var wg sync.WaitGroup
		wg.Add(len(*originExports))
		// NOTE: A previous version of this functionality (in the days of assuming only one export) used
		// use param.Server_ExternalWebUrl as the endpoint to check. Justin thinks the assumption here
		// was that it only made sense to serve an origin and a cache at the same time if a local director
		// was being fired up, but that may be a pigeonhole. The new assumption here is that we're religious
		// about setting Federation.DirectorUrl.
		directorUrl, err := url.Parse(param.Federation_DirectorUrl.GetString())
		if err != nil {
			return shutdownCancel, errors.Wrap(err, "Failed to parse director URL when checking origin advertisements before cache launch")
		}
		for _, export := range *originExports {
			go func(prefix string) {
				defer wg.Done()
				// Probably no need to incur another err check since we already checked the director URL.
				urlToCheck, _ := url.Parse(directorUrl.String())
				urlToCheck.Path, err = url.JoinPath("/api/v1.0/director/origin", prefix)
				if err != nil {
					errCh <- errors.Wrapf(err, "Failed to join path %s for origin advertisement check", prefix)
					return
				}
				if err = server_utils.WaitUntilWorking(ctx, "GET", urlToCheck.String(), "director", 307); err != nil {
					errCh <- errors.Wrapf(err, "The prefix %s does not seem to have advertised correctly", prefix)
				}

			}(export.FederationPrefix)

		}
		wg.Wait()

		close(errCh)
		errFound := false
		for err := range errCh {
			if err != nil {
				log.Errorln("No result from waiting for prefix advertisement:", err)
				errFound = true
			}

		}
		if errFound {
			return shutdownCancel, errors.New("Failed to advertise all origin exports before cache launch")
		}
	}

	if modules.IsEnabled(config.CacheType) {
		// Give five seconds for the origin to finish advertising to the director
		desiredURL := param.Federation_DirectorUrl.GetString() + "/.well-known/openid-configuration"
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

	if modules.IsEnabled(config.LocalCacheType) {
		log.Debugln("Starting local cache listener at", param.LocalCache_Socket.GetString())
		if err := lc.Config(egrp); err != nil {
			log.Warning("Failure when configuring the local cache; cache may incorrectly generate 403 errors until reconfiguration runs")
		}
		if err := lc.LaunchListener(ctx, egrp); err != nil {
			log.Errorln("Failure when starting the local cache listener:", err)
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
