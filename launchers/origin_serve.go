//go:build !windows

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
	_ "embed"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/origin_serve"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/ssh_posixv2"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pelicanplatform/pelican/xrootd"
)

func OriginServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, modules server_structs.ServerType) (server_structs.XRootDServer, error) {
	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize origin exports")
	}

	// Determine if we should use XRootD or native HTTP server
	storageType := param.Origin_StorageType.GetString()
	useXRootD := storageType != string(server_structs.OriginStoragePosixv2) && storageType != string(server_structs.OriginStorageSSH)

	if useXRootD {
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusWarning, "XRootD is initializing")
		metrics.SetComponentHealthStatus(metrics.OriginCache_CMSD, metrics.StatusWarning, "CMSD is initializing")

		err = xrootd.SetUpMonitoring(ctx, egrp)
		if err != nil {
			return nil, err
		}
	} else {
		log.Info("Initializing POSIXv2 origin backend")
	}

	originServer := &origin.OriginServer{}
	err = launcher_utils.CheckDefaults(originServer)
	if err != nil {
		return nil, err
	}

	// Initialize PKCS#11 helper after the defaults are set up
	initPKCS11(ctx, modules)

	if err := database.InitServerDatabase(server_structs.OriginType); err != nil {
		return nil, errors.Wrap(err, "failed to initialize server sqlite database")
	}

	origin.ConfigOriginTTLCache(ctx, egrp)

	if param.Origin_StorageType.GetString() == string(server_structs.OriginStorageGlobus) {
		if err := origin.InitGlobusBackend(originExports); err != nil {
			return nil, errors.Wrap(err, "failed to initialize Globus backend")
		}
		origin.LaunchGlobusTokenRefresh(ctx, egrp)
	}

	concLimit := param.Origin_Concurrency.GetInt()
	if concLimit > 0 {
		server_utils.LaunchConcurrencyMonitoring(ctx, egrp, originServer.GetServerType())
	}

	// Set up the APIs unrelated to UI, which only contains director-based health test reporting endpoint for now
	if err = origin.RegisterOriginAPI(engine, ctx, egrp); err != nil {
		return nil, err
	}

	// Set up the APIs for the origin UI
	if err = origin.RegisterOriginWebAPI(engine); err != nil {
		return nil, err
	}

	// Director also registers this metadata URL; avoid registering twice.
	if !modules.IsEnabled(server_structs.DirectorType) {
		server_utils.RegisterOIDCAPI(engine.Group("/", web_ui.ServerHeaderMiddleware), false)
	}

	// OA4MP is not XRootD specific - configure if enabled
	if param.Origin_EnableIssuer.GetBool() {
		if err = oa4mp.ConfigureOA4MPProxy(engine); err != nil {
			return nil, err
		}
	}

	// Handle XRootD-specific initialization
	if useXRootD {
		configPath, err := xrootd.ConfigXrootd(ctx, true)
		if err != nil {
			return nil, err
		}

		if param.Origin_SelfTest.GetBool() {
			xrootd.PeriodicSelfTest(ctx, egrp, true)
		}

		privileged := param.Origin_Multiuser.GetBool()
		useCMSD := param.Origin_EnableCmsd.GetBool()
		launchers, err := xrootd.ConfigureLaunchers(privileged, configPath, useCMSD, false)
		if err != nil {
			return nil, err
		}

		if param.Origin_EnableIssuer.GetBool() {
			oa4mp_launcher, err := oa4mp.ConfigureOA4MP()
			if err != nil {
				return nil, err
			}
			launchers = append(launchers, oa4mp_launcher)
		}

		portStartCallback := func(port int) {
			if err := param.Set("Origin.Port", port); err != nil {
				log.WithError(err).Warnf("Failed to set Origin.Port to %d", port)
			}
			if originUrl, err := url.Parse(param.Origin_Url.GetString()); err == nil {
				originUrl.Host = originUrl.Hostname() + ":" + strconv.Itoa(port)
				if err := param.Set("Origin.Url", originUrl.String()); err != nil {
					log.WithError(err).Warnf("Failed to set Origin.Url to %s", originUrl.String())
				}
				log.Debugln("Resetting Origin.Url to", originUrl.String())
			}
			log.Infoln("Origin startup complete on port", port)
		}

		pids, err := xrootd.LaunchDaemons(ctx, launchers, egrp, portStartCallback)
		if err != nil {
			return nil, err
		}
		originServer.SetPids(pids)

		// Store restart information after PIDs are known
		xrootd.StoreRestartInfo(launchers, pids, egrp, portStartCallback, false, useCMSD, privileged)

		// Register callback for xrootd logging configuration changes
		// This must be done after LaunchDaemons so the server has PIDs
		xrootd.RegisterXrootdLoggingCallback()

		// LaunchOriginDaemons may edit the viper config; these launched goroutines are purposely
		// delayed until after the viper config is done.
		xrootd.LaunchXrootdMaintenance(ctx, originServer, 2*time.Minute)
	}
	// POSIXv2-specific initialization is deferred to OriginServeFinish()

	// Launch origin file test maintenance (not XRootD specific)
	origin.LaunchOriginFileTestMaintenance(ctx)
	origin.LaunchDiskUsageCalculator(ctx, egrp)

	return originServer, nil
}

// Finish configuration of the origin server.  To be invoked after the web UI components
// have been launched.
func OriginServeFinish(ctx context.Context, egrp *errgroup.Group, engine *gin.Engine, modules server_structs.ServerType) error {
	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return err
	}

	// Handle POSIXv2 and SSH-specific initialization now that the web server is running
	storageType := param.Origin_StorageType.GetString()
	useXRootD := storageType != string(server_structs.OriginStoragePosixv2) && storageType != string(server_structs.OriginStorageSSH)
	if !useXRootD {
		// For SSH backend, initialize the SSH connection before setting up handlers
		if storageType == string(server_structs.OriginStorageSSH) {
			// Register WebSocket handlers for keyboard-interactive auth
			ssh_posixv2.RegisterWebSocketHandler(engine, ctx, egrp)

			// Initialize the SSH backend (creates helper broker and starts connection manager)
			if err := ssh_posixv2.InitializeBackend(ctx, egrp, originExports); err != nil {
				return errors.Wrap(err, "failed to initialize SSH backend")
			}
			log.Info("SSH backend initialized")
		}

		if err := origin_serve.InitAuthConfig(ctx, egrp, originExports); err != nil {
			return errors.Wrap(err, "failed to initialize origin_serve auth config")
		}

		if err := origin_serve.InitializeHandlers(originExports); err != nil {
			return errors.Wrap(err, "failed to initialize origin_serve handlers")
		}

		directorEnabled := modules.IsEnabled(server_structs.DirectorType)
		if err := origin_serve.RegisterHandlers(engine, directorEnabled); err != nil {
			return errors.Wrap(err, "failed to register origin_serve handlers")
		}

		// For POSIXv2, the origin serves files directly via the web server, not XRootD.
		// Update Origin.Url to use the external web URL which is now set to the correct port.
		externalWebUrl := param.Server_ExternalWebUrl.GetString()
		if err := param.Set("Origin.Url", externalWebUrl); err != nil {
			log.WithError(err).Warnf("Failed to set Origin.Url to %s", externalWebUrl)
		}
		log.Debugf("Set Origin.Url to %s for POSIXv2 origin", externalWebUrl)

		log.Info("POSIXv2 origin backend initialized successfully")
	}

	metrics.SetComponentHealthStatus(metrics.OriginCache_Registry, metrics.StatusWarning, "Start to register namespaces for the origin server")
	log.Debug("Register Origin")
	extUrlStr := param.Server_ExternalWebUrl.GetString()
	extUrl, _ := url.Parse(extUrlStr)
	// Only use hostname:port
	if err := launcher_utils.RegisterNamespaceWithRetry(ctx, egrp, server_structs.GetOriginNs(extUrl.Host)); err != nil {
		return err
	}
	log.Debug("Origin is registered")
	for _, export := range originExports {
		if err := launcher_utils.RegisterNamespaceWithRetry(ctx, egrp, export.FederationPrefix); err != nil {
			return err
		}
	}

	egrp.Go(func() error {
		<-ctx.Done()
		return database.ShutdownDB()
	})

	return nil
}
