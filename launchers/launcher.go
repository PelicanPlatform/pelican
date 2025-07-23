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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

var (
	ErrExitOnSignal error = errors.New("Exit program on signal")
	ErrRestart      error = errors.New("Restart program")

	// oncePrometheus is used to ensure that the embedded prometheus instance is only configured once,
	// even when LaunchModules is called multiple times in test scenarios.
	oncePrometheus sync.Once
)

func LaunchModules(ctx context.Context, modules server_structs.ServerType) (servers []server_structs.XRootDServer, shutdownCancel context.CancelFunc, err error) {
	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}

	ctx, shutdownCancel = context.WithCancel(ctx)

	config.LogPelicanVersion()

	var engine *gin.Engine
	engine, err = web_ui.GetEngine()
	if err != nil {
		return
	}

	if err = config.InitServer(ctx, modules); err != nil {
		err = errors.Wrap(err, "Failure when configuring the server")
		return
	}

	// Print Pelican config at server start if it's in debug or info level
	if log.GetLevel() >= log.InfoLevel {
		if err = config.PrintConfig(); err != nil {
			return
		}
	}

	// Set up necessary APIs to support Web UI, including auth and metrics
	if err = web_ui.ConfigureServerWebAPI(ctx, engine, egrp); err != nil {
		return
	}

	// Register OIDC endpoint
	if param.Server_EnableUI.GetBool() {
		// Warn if Prometheus is disabled, but Web UI is enabled. Metrics via Web UI will not be available.
		if !param.Monitoring_EnablePrometheus.GetBool() {
			log.Warn("Prometheus is disabled, but Web UI is enabled. Metrics via Web UI will not be available.")
		}
		if modules.IsEnabled(server_structs.RegistryType) ||
			(modules.IsEnabled(server_structs.OriginType) && param.Origin_EnableOIDC.GetBool()) ||
			(modules.IsEnabled(server_structs.CacheType) && param.Cache_EnableOIDC.GetBool()) ||
			(modules.IsEnabled(server_structs.DirectorType) && param.Director_EnableOIDC.GetBool()) {
			if err = web_ui.ConfigOAuthClientAPIs(engine); err != nil {
				return
			}
		}
	}

	if modules.IsEnabled(server_structs.RegistryType) {
		// Federation.RegistryUrl defaults to Server.ExternalUrl in InitServer()
		if err = RegistryServe(ctx, engine, egrp); err != nil {
			return
		}
	}

	if modules.IsEnabled(server_structs.BrokerType) {
		rootGroup := engine.Group("/", web_ui.ServerHeaderMiddleware)
		broker.RegisterBroker(ctx, rootGroup)
		broker.LaunchNamespaceKeyMaintenance(ctx, egrp)
	}

	if modules.IsEnabled(server_structs.DirectorType) {
		// Director.DefaultResponse defaults to "cache" through default.yaml
		// Federation.DirectorUrl defaults to Server.ExternalUrl in InitServer()
		// Duplicated set are removed
		if err = DirectorServe(ctx, engine, egrp); err != nil {
			return
		}
	}

	// Start listening on the socket.  If `Server.WebPort` is 0, then a random port will be
	// selected and we'll update the configuration accordingly.  This needs to be done before
	// the XRootD configuration is written as the Server.WebPort is incorporated into the issuer URL.
	addr := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return
	}
	lnReference := ln
	defer func() {
		if lnReference != nil {
			lnReference.Close()
		}
	}()
	config.UpdateConfigFromListener(ln)

	servers = make([]server_structs.XRootDServer, 0)

	if modules.IsEnabled(server_structs.OriginType) {

		var server server_structs.XRootDServer
		server, err = OriginServe(ctx, engine, egrp, modules)
		if err != nil {
			return
		}
		servers = append(servers, server)

		var originExports []server_utils.OriginExport
		originExports, err = server_utils.GetOriginExports()
		if err != nil {
			return
		}

		ok, err = server_utils.CheckOriginSentinelLocations(originExports)
		if err != nil && !ok {
			return
		}
	}

	var lc *local_cache.LocalCache
	if modules.IsEnabled(server_structs.LocalCacheType) {
		// Create and register the cache routines before the web interface is up
		lc, err = local_cache.NewLocalCache(ctx, egrp, local_cache.WithDeferConfig(true))
		if err != nil {
			return
		}
		rootGroup := engine.Group("/", web_ui.ServerHeaderMiddleware)
		lc.Register(ctx, rootGroup)
	}

	// Start a routine to periodically refresh the private key directory
	// This ensures that new or updated private keys are automatically loaded and registered
	launcher_utils.LaunchIssuerKeysDirRefresh(ctx, egrp, modules)

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

	healthCheckUrl := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	if err = server_utils.WaitUntilWorking(ctx, "GET", healthCheckUrl, "Web UI", http.StatusOK, true); err != nil {
		log.Errorln("Web engine check failed: ", err)
		return
	}

	// Launch director discovery.  This is done after the director modules are done
	// (since they may provide some of the response information) and before the origin/cache
	// are started (since we may forward ads based on discovered directors)
	if err = server_utils.LaunchPeriodicDirectorDiscovery(ctx, modules.IsEnabled(server_structs.DirectorType)); err != nil {
		return
	}
	if modules.IsEnabled(server_structs.DirectorType) {
		director.LaunchPeriodicAdvertise(ctx)
	}

	if param.Origin_EnableIssuer.GetBool() {
		oa4mpHealthCheckUrl := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/issuer/.well-known/openid-configuration"
		if err = server_utils.WaitUntilWorking(ctx, "GET", oa4mpHealthCheckUrl, "Issuer", http.StatusOK, true); err != nil {
			log.Errorln("Failed to startup issuer component: ", err)
			return
		}
	}

	if modules.IsEnabled(server_structs.OriginType) {
		log.Debug("Finishing origin server configuration")
		if err = OriginServeFinish(ctx, egrp); err != nil {
			return
		}
	}

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return
	}

	// Launch the broker listener.  Needs the federation information to determine the broker endpoint.
	if fedInfo.BrokerEndpoint != "" {
		if modules.IsEnabled(server_structs.OriginType) && param.Origin_EnableBroker.GetBool() {
			if err = origin.LaunchBrokerListener(ctx, egrp, engine); err != nil {
				return
			}
		}
	}

	// Origin needs to advertise once before the cache starts
	if modules.IsEnabled(server_structs.CacheType) && modules.IsEnabled(server_structs.OriginType) {
		log.Debug("Advertise Origin and Cache to the Director")
		if err = launcher_utils.Advertise(ctx, servers); err != nil {
			err = errors.Wrap(err, "failed to do initial advertisement to the director")
			return
		}

		// We may have arbitrarily many exports, so we should make sure they're all advertised before
		// starting the cache up. This guarantees that when the cache starts, it is immediately aware
		// of the namespaces and doesn't have to wait an entire cycle to learn about them from the director

		// To check all of the advertisements, we'll launch a WaitUntilWorking concurrently for each of them.
		var originExports []server_utils.OriginExport
		originExports, err = server_utils.GetOriginExports()
		if err != nil {
			return
		}
		errCh := make(chan error, len(originExports))
		var wg sync.WaitGroup
		wg.Add(len(originExports))
		// NOTE: A previous version of this functionality (in the days of assuming only one export) used
		// use param.Server_ExternalWebUrl as the endpoint to check. Justin thinks the assumption here
		// was that it only made sense to serve an origin and a cache at the same time if a local director
		// was being fired up, but that may be a pigeonhole. The new assumption here is that we're religious
		// about setting Federation.DirectorUrl.
		var directorUrl *url.URL
		directorUrl, err = url.Parse(fedInfo.DirectorEndpoint)
		if err != nil {
			err = errors.Wrap(err, "Failed to parse director URL when checking origin advertisements before cache launch")
			return
		}
		for _, export := range originExports {
			go func(prefix string) {
				defer wg.Done()
				// Probably no need to incur another err check since we already checked the director URL.
				urlToCheck, _ := url.Parse(directorUrl.String())
				urlToCheck.Path, err = url.JoinPath("/api/v1.0/director/origin", prefix)
				// Skip stat check. Otherwise it will return 404
				query := urlToCheck.Query()
				query.Add("skipstat", "")
				urlToCheck.RawQuery = query.Encode()
				if err != nil {
					errCh <- errors.Wrapf(err, "Failed to join path %s for origin advertisement check", prefix)
					return
				}
				if err = server_utils.WaitUntilWorking(ctx, "GET", urlToCheck.String(), "director", 307, false); err != nil {
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
			err = errors.New("Failed to advertise all origin exports before cache launch")
			return
		}
	}

	var cacheServer server_structs.XRootDServer
	if modules.IsEnabled(server_structs.CacheType) {
		// Give five seconds for the origin to finish advertising to the director
		desiredURL := fedInfo.DirectorEndpoint + "/.well-known/openid-configuration"
		if err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200, false); err != nil {
			log.Errorln("Director does not seem to be working:", err)
			return
		}
		cacheServer, err = CacheServe(ctx, engine, egrp, modules)
		if err != nil {
			return
		}

		servers = append(servers, cacheServer)
	}

	if modules.IsEnabled(server_structs.CacheType) {
		log.Debug("Finishing cache server configuration")
		if err = CacheServeFinish(ctx, egrp, cacheServer); err != nil {
			return
		}
	}

	// Launch the broker listener.  Needs the federation information to determine the broker endpoint.
	if fedInfo.BrokerEndpoint != "" && !(modules.IsEnabled(server_structs.OriginType) && param.Origin_EnableBroker.GetBool()) && modules.IsEnabled(server_structs.CacheType) && param.Cache_EnableBroker.GetBool() {
		// Note we unconditionally launch the broker listener for the cache if there
		// is one available.  This is to reduce the need for the cache to have a second
		// incoming TCP connection to function.
		if err = cache.LaunchBrokerListener(ctx, egrp, engine); err != nil {
			return
		}
	}

	// If we are a director, we will potentially contact other
	// services with the broker, so we need to set up the broker dialer
	if modules.IsEnabled(server_structs.DirectorType) {
		fmt.Println("Setting up broker dialer for director")
		brokerDialer := broker.NewBrokerDialer(ctx, egrp)
		config.SetTransportDialer(brokerDialer.DialContext)
		director.SetBrokerDialer(brokerDialer)
	}

	// Now that we've launched XRootD (which should drop their privileges to the xrootd user), we can drop our own
	if config.IsRootExecution() && param.Server_DropPrivileges.GetBool() {
		if err = dropPrivileges(); err != nil {
			return
		}
	}

	if modules.IsEnabled(server_structs.OriginType) || modules.IsEnabled(server_structs.CacheType) {
		log.Debug("Launching periodic advertise of origin/cache server to the director")
		if err = launcher_utils.LaunchPeriodicAdvertise(ctx, egrp, servers); err != nil {
			return
		}
	}

	if modules.IsEnabled(server_structs.LocalCacheType) {
		log.Debugln("Starting local cache listener at", param.LocalCache_Socket.GetString())
		if err := lc.Config(egrp); err != nil {
			log.Warning("Failure when configuring the local cache; cache may incorrectly generate 403 errors until reconfiguration runs")
		}
		if err = lc.LaunchListener(ctx, egrp); err != nil {
			log.Errorln("Failure when starting the local cache listener:", err)
			return
		}

	}

	if param.Monitoring_EnablePrometheus.GetBool() {
		metrics.SetComponentHealthStatus(metrics.Prometheus, metrics.StatusWarning, "Prometheus not started")
		// Due to federation tests / fed-in-a-box, we need to configure the embedded prometheus instance only once
		// and not for each server. This is why we use a sync.Once here.
		oncePrometheus.Do(func() {
			err = web_ui.ConfigureEmbeddedPrometheus(ctx, engine)
		})
		if err != nil {
			err = errors.Wrap(err, "Failed to configure embedded prometheus instance")
			metrics.SetComponentHealthStatus(metrics.Prometheus, metrics.StatusCritical, err.Error())
			return
		}
		metrics.SetComponentHealthStatus(metrics.Prometheus, metrics.StatusOK, "Prometheus started")

		log.Info("Starting web login...")
		egrp.Go(func() error { return web_ui.InitServerWebLogin(ctx) })
	}

	egrp.Go(func() error {
		_ = config.RestartFlag
		log.Debug("Will shutdown process on signal")
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		select {
		case sig := <-sigs:
			log.Warningf("Received signal %v; will shutdown process", sig)
			// Graceful shutdown if received SIGTERM
			if sig == syscall.SIGTERM {
				handleGracefulShutdown(ctx, modules, servers)
			}
			shutdownCancel()
			return ErrExitOnSignal
		case <-config.RestartFlag:
			log.Warningf("Received restart request; will restart the process")
			handleGracefulShutdown(ctx, modules, servers)
			shutdownCancel()
			return ErrRestart
		case <-ctx.Done():
			return nil
		}
	})

	return
}

func handleGracefulShutdown(ctx context.Context, modules server_structs.ServerType, servers []server_structs.XRootDServer) {
	if modules.IsEnabled(server_structs.OriginType) || modules.IsEnabled(server_structs.CacheType) {
		log.Warnf("Waiting %s for in-flight transfers before shutting down", param.Xrootd_ShutdownTimeout.GetDuration().String())

		// Set component's health status, so the ad could pick up the shutdown flag (`Status`: `shutting down`)
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusShuttingDown, "The server is shutting down")
		// When the server is up again, the ShuttingDown status will be cleared

		if advErr := launcher_utils.Advertise(ctx, servers); advErr != nil {
			log.Errorf("Failed to advertise before shutdown: %v", advErr)
		}
		time.Sleep(param.Xrootd_ShutdownTimeout.GetDuration())
		log.Warn("Shutdown grace period elapsed; proceeding with shutdown and discarding incomplete transfers")
	}
}
