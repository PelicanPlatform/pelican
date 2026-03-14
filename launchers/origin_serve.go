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

	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/oa4mp"
	issuer "github.com/pelicanplatform/pelican/oauth2/issuer"
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

	// Configure the issuer (OA4MP proxy or embedded fosite) if enabled
	if param.Origin_EnableIssuer.GetBool() {
		issuerMode := param.Origin_IssuerMode.GetString()
		switch issuerMode {
		case "embedded", "":
			if err := configureEmbeddedIssuer(ctx, egrp, engine); err != nil {
				return nil, errors.Wrap(err, "failed to configure embedded OIDC issuer")
			}
		case "oa4mp":
			if err = oa4mp.ConfigureOA4MPProxy(engine); err != nil {
				return nil, err
			}
		default:
			return nil, errors.Errorf("unsupported Origin.IssuerMode %q; valid values are \"embedded\" and \"oa4mp\"", issuerMode)
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

		if param.Origin_EnableIssuer.GetBool() && param.Origin_IssuerMode.GetString() == "oa4mp" {
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
			// Register WebSocket handlers for keyboard-interactive auth with admin authentication
			ssh_posixv2.RegisterWebSocketHandler(engine, ctx, egrp, web_ui.AuthHandler, web_ui.AdminAuthHandler)

			// Initialize the SSH backend (creates helper broker and starts connection manager).
			// In tunnel mode the origin dials the helper through SSH channels;
			// in broker mode the helper polls and calls back with reversed connections.
			if err := ssh_posixv2.InitializeBackend(ctx, egrp, originExports); err != nil {
				return errors.Wrap(err, "failed to initialize SSH backend")
			}
			log.Info("SSH backend initialized")
		}

		// Launch the OA4MP token issuer daemon for non-XRootD backends.
		// For XRootD backends, it is launched alongside XRootD via xrootd.LaunchDaemons.
		if param.Origin_EnableIssuer.GetBool() && param.Origin_IssuerMode.GetString() == "oa4mp" {
			oa4mpLauncher, err := oa4mp.ConfigureOA4MP()
			if err != nil {
				return errors.Wrap(err, "failed to configure OA4MP for non-XRootD backend")
			}
			if _, err := daemon.LaunchDaemons(ctx, []daemon.Launcher{oa4mpLauncher}, egrp); err != nil {
				return errors.Wrap(err, "failed to launch OA4MP daemon for non-XRootD backend")
			}
			log.Info("OA4MP token issuer daemon launched for non-XRootD backend")
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

// configureEmbeddedIssuer initializes the fosite-based embedded OIDC issuer,
// compiles authorization rules, and registers routes on the Gin engine.
//
// A separate OIDCProvider is created for each origin export that requires
// authentication (non-public reads or writes).  Each provider uses the
// export's FederationPrefix as the namespace so that clients and tokens are
// scoped per-namespace.
func configureEmbeddedIssuer(ctx context.Context, egrp *errgroup.Group, engine *gin.Engine) error {
	// Compile Issuer.AuthorizationTemplates as the global fallback for
	// any namespace that does not have per-namespace rules.
	if err := oa4mp.InitAuthzRules(); err != nil {
		return errors.Wrap(err, "failed to compile issuer authorization templates")
	}

	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return errors.Wrap(err, "failed to get origin exports for embedded issuer")
	}

	gracePeriod := param.Issuer_RefreshTokenGracePeriod.GetDuration()
	if gracePeriod == 0 {
		gracePeriod = 5 * time.Minute
	}

	registry := issuer.NewProviderRegistry()

	for _, export := range originExports {
		// Only create an issuer for exports that need authentication
		if export.Capabilities.PublicReads && !export.Capabilities.Writes {
			continue
		}

		namespace := export.FederationPrefix
		issuerURL := issuer.IssuerURLForNamespace(namespace)

		provider, err := issuer.NewOIDCProvider(database.ServerDatabase, issuerURL, gracePeriod, namespace)
		if err != nil {
			return errors.Wrapf(err, "failed to create embedded OIDC provider for namespace %s", namespace)
		}

		registry.Register(namespace, provider)

		// If the export defines its own AuthorizationTemplates, compile
		// them and attach to this provider so they override the global
		// rules for this namespace.
		if len(export.AuthorizationTemplates) > 0 {
			rules, err := oa4mp.CompileAuthzTemplates(export.AuthorizationTemplates)
			if err != nil {
				return errors.Wrapf(err, "failed to compile per-export authorization templates for namespace %s", namespace)
			}
			provider.SetAuthzRules(rules)
		}

		// Seed the pre-allocated public client for browser-based flows (PKCE).
		publicClientID := param.Issuer_PublicClientID.GetString()
		if publicClientID != "" {
			redirectURIs := param.Issuer_RedirectUris.GetStringSlice()
			if err := provider.EnsurePublicClient(ctx, publicClientID, redirectURIs); err != nil {
				return errors.Wrapf(err, "failed to seed public client %q for namespace %s", publicClientID, namespace)
			}
		}

		// Start background cleanup for each provider
		unusedTimeout := param.Issuer_DynamicClientUnusedTimeout.GetDuration()
		if unusedTimeout == 0 {
			unusedTimeout = 1 * time.Hour
		}
		staleTimeout := param.Issuer_DynamicClientStaleTimeout.GetDuration()
		if staleTimeout == 0 {
			staleTimeout = 336 * time.Hour // 2 weeks
		}
		provider.StartCleanup(ctx, egrp, unusedTimeout, staleTimeout)

		log.Infof("Embedded OIDC issuer configured for namespace %s", namespace)
	}

	if registry.First() == nil {
		log.Info("Embedded OIDC issuer: no exports require authentication; no issuers registered")
		return nil
	}

	// Apply a non-aborting middleware to the issuer route group so that
	// handlers which inspect ctx.GetString("User") (e.g., device-verify)
	// will see the identity extracted from the login cookie.  Unlike
	// AuthHandler, this middleware never aborts—it lets the handler decide
	// how to react to an unauthenticated request.
	issuer.RegisterRoutesWithMiddleware(engine, registry, func(ctx *gin.Context) {
		user, userId, groups, _ := web_ui.GetUserGroups(ctx)
		if user != "" {
			ctx.Set("User", user)
			if userId != "" {
				ctx.Set("UserId", userId)
			}
			if len(groups) > 0 {
				ctx.Set("Groups", groups)
			}
		}
		ctx.Next()
	})

	// Register admin client-management endpoints behind full admin auth.
	// Admin routes are handled by the same namespace-dispatched routes.
	issuer.RegisterAdminRoutes(engine, registry, web_ui.AuthHandler, web_ui.AdminAuthHandler)

	log.Info("Embedded OIDC issuer configured successfully")
	return nil
}
